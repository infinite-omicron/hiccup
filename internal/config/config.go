// Package config loads ~/.hiccup/config.json and applies HICCUP_* environment overrides.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	Backend string           `json:"backend,omitempty"`
	Burp    Burp             `json:"burp"`
	Sites   map[string]*Site `json:"sites,omitempty"`
}

type Burp struct {
	URL   string   `json:"url,omitempty"`
	Token string   `json:"token,omitempty"`
	Jar   string   `json:"jar,omitempty"`
	BApps []string `json:"bapps,omitempty"`
}

type Site struct {
	BaseURL   string           `json:"base_url"`
	Scope     []string         `json:"scope,omitempty"`
	Throttle  *Throttle        `json:"throttle,omitempty"`
	UserAgent *UserAgent       `json:"user_agent,omitempty"`
	Login     *Login           `json:"login,omitempty"`
	Session   *Session         `json:"session,omitempty"`
	Roles     map[string]*Role `json:"roles,omitempty"`
}

type Throttle struct {
	RPS            float64  `json:"rps"`
	Burst          int      `json:"burst,omitempty"`
	JitterMS       [2]int   `json:"jitter_ms,omitempty"`
	MaxConcurrency int      `json:"max_concurrency,omitempty"`
	Backoff        *Backoff `json:"backoff,omitempty"`
}

type Backoff struct {
	OnStatus        []int `json:"on_status,omitempty"`
	HonorRetryAfter bool  `json:"honor_retry_after"`
	MaxS            int   `json:"max_s,omitempty"`
}

type UserAgent struct {
	Value string `json:"value"`
	Scope string `json:"scope,omitempty"` // "browser" (default) or "all"
}

type Login struct {
	URL      string        `json:"url"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	Submit   string        `json:"submit"`
	Success  *LoginSuccess `json:"success,omitempty"`
}

type LoginSuccess struct {
	URLContains string `json:"url_contains,omitempty"`
	Selector    string `json:"selector,omitempty"`
}

type Session struct {
	Cookies []string `json:"cookies,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

type Role struct {
	Level    int        `json:"level"`
	Accounts []*Account `json:"accounts"`
}

type Account struct {
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	// Password is plaintext, "env:VAR", or "keychain:service/account".
	Password string `json:"password,omitempty"`
}

// Home is $HICCUP_HOME or ~/.hiccup.
func Home() string {
	if h := os.Getenv("HICCUP_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hiccup"
	}
	return filepath.Join(home, ".hiccup")
}

// Path is $HICCUP_CONFIG or <Home>/config.json.
func Path() string {
	if p := os.Getenv("HICCUP_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(Home(), "config.json")
}

// RuntimePath is the file the Burp extension writes on load with its URL and token.
func RuntimePath() string { return filepath.Join(Home(), "burp.json") }

// Load reads the config file; a missing file is an empty config. Environment
// overrides and the extension's runtime file are applied by the accessors
// (BackendName, BurpEndpoint, Site.EffectiveThrottle, Site.EffectiveUserAgent)
// so that Save never persists them.
func Load() (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(Path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", Path(), err)
		}
	}
	if c.Sites == nil {
		c.Sites = map[string]*Site{}
	}
	return c, nil
}

// BackendName is $HICCUP_BACKEND, the config's backend, or "burp".
func (c *Config) BackendName() string {
	if v := os.Getenv("HICCUP_BACKEND"); v != "" {
		return v
	}
	if c.Backend != "" {
		return c.Backend
	}
	return "burp"
}

// BurpEndpoint layers, lowest first: config.json, the extension's runtime file
// (its token changes every time the extension loads), then HICCUP_BURP_URL and
// HICCUP_BURP_TOKEN.
func (c *Config) BurpEndpoint() (url, token string) {
	url, token = c.Burp.URL, c.Burp.Token
	if rb, err := os.ReadFile(RuntimePath()); err == nil {
		var rt struct{ URL, Token string }
		if json.Unmarshal(rb, &rt) == nil {
			if rt.URL != "" {
				url = rt.URL
			}
			if rt.Token != "" {
				token = rt.Token
			}
		}
	}
	if v := os.Getenv("HICCUP_BURP_URL"); v != "" {
		url = v
	}
	if v := os.Getenv("HICCUP_BURP_TOKEN"); v != "" {
		token = v
	}
	if url == "" {
		url = "http://127.0.0.1:8099"
	}
	return url, token
}

// EffectiveThrottle is the site's throttle with HICCUP_THROTTLE_RPS applied.
func (s *Site) EffectiveThrottle() (*Throttle, error) {
	v := os.Getenv("HICCUP_THROTTLE_RPS")
	if v == "" {
		return s.Throttle, nil
	}
	rps, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil, fmt.Errorf("HICCUP_THROTTLE_RPS: %w", err)
	}
	t := Throttle{}
	if s.Throttle != nil {
		t = *s.Throttle
	}
	t.RPS = rps
	return &t, nil
}

// EffectiveUserAgent is the site's User-Agent with HICCUP_USER_AGENT applied.
func (s *Site) EffectiveUserAgent() *UserAgent {
	v := os.Getenv("HICCUP_USER_AGENT")
	if v == "" {
		return s.UserAgent
	}
	ua := UserAgent{Scope: "browser"}
	if s.UserAgent != nil {
		ua = *s.UserAgent
	}
	ua.Value = v
	return &ua
}

// Save writes the config atomically with owner-only permissions.
func (c *Config) Save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Site returns the named site, or the one named by HICCUP_SITE, or the only site.
func (c *Config) Site(name string) (string, *Site, error) {
	if name == "" {
		name = os.Getenv("HICCUP_SITE")
	}
	if name == "" && len(c.Sites) == 1 {
		for n := range c.Sites {
			name = n
		}
	}
	if name == "" {
		return "", nil, errors.New("no site given (use --site or HICCUP_SITE)")
	}
	s, ok := c.Sites[name]
	if !ok {
		return "", nil, fmt.Errorf("unknown site %q in %s", name, Path())
	}
	return name, s, nil
}

// SiteNames returns site names in sorted order.
func (c *Config) SiteNames() []string {
	names := make([]string, 0, len(c.Sites))
	for n := range c.Sites {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Hosts returns the hostnames covered by a site (base URL plus scope entries).
func (s *Site) Hosts() []string {
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range append([]string{s.BaseURL}, s.Scope...) {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// FindAccount looks an account up by name across all roles.
func (s *Site) FindAccount(name string) (role string, r *Role, a *Account, ok bool) {
	for rn, r := range s.Roles {
		for _, a := range r.Accounts {
			if a.Name == name {
				return rn, r, a, true
			}
		}
	}
	return "", nil, nil, false
}

// Example is written by `hiccup config init`.
func Example() *Config {
	return &Config{
		Backend: "burp",
		Burp:    Burp{URL: "http://127.0.0.1:8099", BApps: []string{}},
		Sites: map[string]*Site{
			"example": {
				BaseURL: "https://app.example.test",
				Scope:   []string{"https://app.example.test/"},
				Throttle: &Throttle{RPS: 1, Burst: 1, JitterMS: [2]int{300, 1500}, MaxConcurrency: 1,
					Backoff: &Backoff{OnStatus: []int{429, 503}, HonorRetryAfter: true, MaxS: 120}},
				Login: &Login{URL: "/login", Username: "#email", Password: "#password",
					Submit: "button[type=submit]", Success: &LoginSuccess{URLContains: "/dashboard"}},
				Session: &Session{Cookies: []string{"session"}, Headers: []string{"Authorization"}},
				Roles: map[string]*Role{
					"admin": {Level: 100, Accounts: []*Account{{Name: "admin1", Username: "admin1@example.test", Password: "changeme"}}},
					"user": {Level: 10, Accounts: []*Account{
						{Name: "user1", Username: "user1@example.test", Password: "env:HICCUP_EXAMPLE_USER1_PW"},
						{Name: "user2", Username: "user2@example.test", Password: "keychain:hiccup/example/user2"}}},
					"anonymous": {Level: 0, Accounts: []*Account{{Name: "anon"}}},
				},
			},
		},
	}
}
