// Package plextrac reads a PlexTrac instance's content library (WriteupsDB)
// so findings can be matched to the company's own write-ups. It only reads:
// nothing is created or changed in PlexTrac.
package plextrac

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/config"
)

// Endpoints, from PlexTrac's API (and its Postman collection).
const (
	pathAuthenticate = "/api/v1/authenticate"
	pathMFA          = "/api/v1/authenticate/mfa"
	pathRepositories = "/api/v2/repositories/getAllWriteupsRepositories"
	pathWriteups     = "/api/v1/template/list"
	pathWriteup      = "/api/v1/template/" // + id
)

// TokenLifetime is how long a PlexTrac session lasts when the token doesn't say.
const TokenLifetime = 15 * time.Minute

// ErrSessionExpired means `hiccup plextrac login` is needed.
var ErrSessionExpired = errors.New("plextrac: no current session (hiccup plextrac login)")

func dir() string { return filepath.Join(config.Home(), "plextrac") }

func tokenPath() string { return filepath.Join(dir(), "token.json") }

// Session is a signed-in PlexTrac session.
type Session struct {
	URL      string    `json:"url"`
	Token    string    `json:"token"`
	TenantID any       `json:"tenant_id,omitempty"`
	Expires  time.Time `json:"expires"`
	// BareToken: the instance wants the token without "Bearer ".
	BareToken bool `json:"bare_token,omitempty"`
}

// Valid reports whether the session has at least a minute left.
func (s *Session) Valid() bool {
	return s != nil && s.Token != "" && time.Until(s.Expires) > time.Minute
}

func (s *Session) Save() error {
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(tokenPath(), b, 0o600)
}

// LoadSession returns the saved session for url, or ErrSessionExpired.
func LoadSession(url string) (*Session, error) {
	b, err := os.ReadFile(tokenPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrSessionExpired
	} else if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if !s.Valid() || strings.TrimRight(s.URL, "/") != strings.TrimRight(url, "/") {
		return nil, ErrSessionExpired
	}
	return &s, nil
}

// Logout deletes the saved session.
func Logout() error {
	err := os.Remove(tokenPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Client talks to one PlexTrac instance.
type Client struct {
	URL  string
	HTTP *http.Client
	// Token is the session token; empty before Login.
	Token string
	// bareToken: PlexTrac's docs say "Authorization: Bearer <token>", but its
	// own scripts send the bare token; after a 401 with Bearer we use that.
	bareToken bool
}

func New(url string) (*Client, error) {
	url = strings.TrimRight(url, "/")
	if url == "" {
		return nil, errors.New(`no PlexTrac URL: set "plextrac": {"url": "https://<instance>.plextrac.com"} in config or HICCUP_PLEXTRAC_URL`)
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = "https://" + url
	}
	return &Client{URL: url, HTTP: &http.Client{Timeout: 60 * time.Second}}, nil
}

// do sends a JSON request; out may be nil.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = b
	}
	send := func() (*http.Response, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, c.URL+path, bytes.NewReader(payload))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/json")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Token != "" {
			if c.bareToken {
				req.Header.Set("Authorization", c.Token)
			} else {
				req.Header.Set("Authorization", "Bearer "+c.Token)
			}
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("plextrac: %w", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp, data, nil
	}
	resp, data, err := send()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && c.Token != "" && !c.bareToken {
		c.bareToken = true
		if resp, data, err = send(); err != nil {
			return err
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized && c.Token != "":
		return ErrSessionExpired
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("plextrac: rate limited (sign-in allows 10 attempts a minute); wait and retry")
	case resp.StatusCode/100 != 2:
		var e struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if msg == "" {
			msg = e.Error
		}
		if msg == "" {
			msg = strings.TrimSpace(string(data))
			if len(msg) > 200 {
				msg = msg[:200] + "..."
			}
		}
		return fmt.Errorf("plextrac: %s %s: %s: %s", method, path, resp.Status, msg)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("plextrac: %s %s: unexpected response: %w", method, path, err)
		}
	}
	return nil
}

type authResponse struct {
	Status     string `json:"status"`
	Token      string `json:"token"`
	TenantID   any    `json:"tenant_id"`
	MFAEnabled bool   `json:"mfa_enabled"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

// Login signs in with a username and password, asking mfa for the 6-digit
// code when the account has multi-factor authentication.
func (c *Client) Login(ctx context.Context, username, password string, mfa func() (string, error)) (*Session, error) {
	var r authResponse
	if err := c.do(ctx, "POST", pathAuthenticate, map[string]string{"username": username, "password": password}, &r); err != nil {
		return nil, err
	}
	if r.Status != "success" && r.Token == "" && !r.MFAEnabled {
		return nil, errors.New("plextrac: sign-in failed (check the username and password)")
	}
	if r.MFAEnabled {
		if mfa == nil {
			return nil, errors.New("plextrac: this account needs an MFA code; sign in from a terminal")
		}
		otp, err := mfa()
		if err != nil {
			return nil, err
		}
		var m authResponse
		if err := c.do(ctx, "POST", pathMFA, map[string]string{"code": r.Code, "token": strings.TrimSpace(otp)}, &m); err != nil {
			return nil, err
		}
		if m.Token == "" {
			return nil, errors.New("plextrac: MFA code rejected")
		}
		if m.TenantID == nil {
			m.TenantID = r.TenantID
		}
		r = m
	}
	if r.Token == "" {
		return nil, errors.New("plextrac: sign-in returned no token")
	}
	c.Token = r.Token
	return &Session{URL: c.URL, Token: r.Token, TenantID: r.TenantID, Expires: tokenExpiry(r.Token)}, nil
}

// Resume uses a saved session.
func (c *Client) Resume(s *Session) {
	c.Token, c.bareToken = s.Token, s.BareToken
}

// Current records how the client authenticates in s, for saving.
func (c *Client) Current(s *Session) *Session {
	s.BareToken = c.bareToken
	return s
}

// tokenExpiry reads the JWT's exp claim, falling back to TokenLifetime.
func tokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims struct {
				Exp float64 `json:"exp"`
			}
			if json.Unmarshal(b, &claims) == nil && claims.Exp > 0 {
				return time.Unix(int64(claims.Exp), 0)
			}
		}
	}
	return time.Now().Add(TokenLifetime)
}
