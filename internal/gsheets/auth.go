// Package gsheets writes the auth matrix to a Google Sheet.
package gsheets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/infinite-omicron/hiccup/internal/config"
)

// Scope lets hiccup read and write spreadsheets only.
const Scope = "https://www.googleapis.com/auth/spreadsheets"

func dir() string { return filepath.Join(config.Home(), "google") }

func tokenPath() string { return filepath.Join(dir(), "token.json") }

// CredentialsPath is $HICCUP_GOOGLE_CREDENTIALS or ~/.hiccup/google/credentials.json:
// a service account key, or an OAuth client of type "Desktop app".
func CredentialsPath() string {
	if p := os.Getenv("HICCUP_GOOGLE_CREDENTIALS"); p != "" {
		return p
	}
	return filepath.Join(dir(), "credentials.json")
}

// Client returns an HTTP client authorized for Scope, from (in order) a
// service account key or an OAuth client plus the token saved by Login, or
// Google Application Default Credentials.
func Client(ctx context.Context) (*http.Client, error) {
	b, err := os.ReadFile(CredentialsPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		creds, err := google.FindDefaultCredentials(ctx, Scope)
		if err != nil {
			return nil, fmt.Errorf("no Google credentials: put a service account key or a Desktop OAuth client at %s (then run `hiccup google login` for an OAuth client), or set up Application Default Credentials: %w", CredentialsPath(), err)
		}
		return oauth2.NewClient(ctx, creds.TokenSource), nil
	case err != nil:
		return nil, err
	}
	var kind struct {
		Type string          `json:"type"`
		App  json.RawMessage `json:"installed"`
	}
	if err := json.Unmarshal(b, &kind); err != nil {
		return nil, fmt.Errorf("%s: %w", CredentialsPath(), err)
	}
	if kind.Type == "service_account" {
		jwt, err := google.JWTConfigFromJSON(b, Scope)
		if err != nil {
			return nil, err
		}
		return jwt.Client(ctx), nil
	}
	conf, err := google.ConfigFromJSON(b, Scope)
	if err != nil {
		return nil, fmt.Errorf("%s: want a service account key or a Desktop OAuth client: %w", CredentialsPath(), err)
	}
	tb, err := os.ReadFile(tokenPath())
	if err != nil {
		return nil, fmt.Errorf("not signed in to Google: run `hiccup google login`")
	}
	var tok oauth2.Token
	if err := json.Unmarshal(tb, &tok); err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, &savingSource{base: conf.TokenSource(ctx, &tok), last: tok.AccessToken}), nil
}

// savingSource persists refreshed tokens so the next run reuses them.
type savingSource struct {
	base oauth2.TokenSource
	last string
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	t, err := s.base.Token()
	if err == nil && t.AccessToken != s.last {
		s.last = t.AccessToken
		_ = saveToken(t)
	}
	return t, err
}

func saveToken(t *oauth2.Token) error {
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return os.WriteFile(tokenPath(), b, 0o600)
}

// Login runs the OAuth consent flow for a Desktop OAuth client with a
// loopback redirect and PKCE, and saves the token. announce receives the URL
// to open (hiccup also tries to open it in the default browser).
func Login(ctx context.Context, announce func(url string)) error {
	b, err := os.ReadFile(CredentialsPath())
	if err != nil {
		return fmt.Errorf("Google OAuth client: %w (create a \"Desktop app\" OAuth client in Google Cloud and save its JSON there)", err)
	}
	conf, err := google.ConfigFromJSON(b, Scope)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	conf.RedirectURL = "http://" + ln.Addr().String() + "/"
	verifier, state := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("prompt", "consent"))

	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("state") != state:
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		case q.Get("error") != "":
			fmt.Fprintln(w, "hiccup: Google sign-in failed; you can close this tab.")
			got <- result{err: fmt.Errorf("google: %s", q.Get("error"))}
		default:
			fmt.Fprintln(w, "hiccup: signed in to Google; you can close this tab.")
			got <- result{code: q.Get("code")}
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	announce(authURL)
	openBrowser(authURL)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-got:
		if r.err != nil {
			return r.err
		}
		tok, err := conf.Exchange(ctx, r.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return err
		}
		return saveToken(tok)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
