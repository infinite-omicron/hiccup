// Package session stores per-account sessions (cookies and headers) and
// injects them into raw HTTP requests.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/config"
)

type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

type Session struct {
	Site       string            `json:"site"`
	Account    string            `json:"account"`
	Cookies    []Cookie          `json:"cookies,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	CapturedAt time.Time         `json:"captured_at"`
}

// Anonymous is the empty session used for accounts without credentials.
func Anonymous(site, account string) *Session { return &Session{Site: site, Account: account} }

func Path(site, account string) string {
	return filepath.Join(config.Home(), "sessions", site, account+".json")
}

func Load(site, account string) (*Session, error) {
	b, err := os.ReadFile(Path(site, account))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no session for %s/%s (run: hiccup login %s %s)", site, account, site, account)
	}
	if err != nil {
		return nil, err
	}
	var s Session
	return &s, json.Unmarshal(b, &s)
}

func (s *Session) Save() error {
	p := Path(s.Site, s.Account)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// Empty reports whether the session carries no credentials.
func (s *Session) Empty() bool { return len(s.Cookies) == 0 && len(s.Headers) == 0 }

// Apply rewrites a raw HTTP request so it carries only this session's
// credentials: the Cookie header, Authorization and the site's configured
// session headers are removed, then this session's cookies (those matching
// host) and headers are added.
func (s *Session) Apply(raw []byte, host string, strip []string) []byte {
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	drop := map[string]bool{"cookie": true, "authorization": true}
	for _, h := range strip {
		drop[strings.ToLower(h)] = true
	}
	for h := range s.Headers {
		drop[strings.ToLower(h)] = true
	}
	out := []string{lines[0]}
	for _, l := range lines[1:] {
		name, _, _ := strings.Cut(l, ":")
		if !drop[strings.ToLower(strings.TrimSpace(name))] {
			out = append(out, l)
		}
	}
	var pairs []string
	for _, c := range s.Cookies {
		if domainMatch(host, c.Domain) {
			pairs = append(pairs, c.Name+"="+c.Value)
		}
	}
	if len(pairs) > 0 {
		out = append(out, "Cookie: "+strings.Join(pairs, "; "))
	}
	for k, v := range s.Headers {
		out = append(out, k+": "+v)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n\r\n" + body)
}

// domainMatch implements cookie domain matching (RFC 6265 5.1.3) loosely:
// an empty domain matches any host.
func domainMatch(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(strings.TrimPrefix(domain, "."))
	return domain == "" || host == domain || strings.HasSuffix(host, "."+domain)
}

// HeaderValue returns a header's value from a raw HTTP request.
func HeaderValue(raw []byte, name string) (string, bool) {
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n")[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}
