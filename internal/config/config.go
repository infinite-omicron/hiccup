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
	Proxy  string  `json:"proxy,omitempty"` // burp, zap or mitmproxy
	Burp   Burp    `json:"burp"`
	Zap    *Zap    `json:"zap,omitempty"`
	Mitm   *Mitm   `json:"mitm,omitempty"`
	Matrix *Matrix `json:"matrix,omitempty"`
	// Microsoft is the Entra app registration used to sync to OneDrive/SharePoint.
	Microsoft *Microsoft `json:"microsoft,omitempty"`
	// PlexTrac is the instance hiccup pulls company write-ups from.
	PlexTrac *PlexTrac        `json:"plextrac,omitempty"`
	Sites    map[string]*Site `json:"sites,omitempty"`
}

// PlexTrac locates a PlexTrac instance and the account hiccup signs in with.
type PlexTrac struct {
	URL      string `json:"url,omitempty"`      // e.g. https://acme.plextrac.com
	Username string `json:"username,omitempty"` // the account's email
	Password string `json:"password,omitempty"` // plaintext, env:VAR or keychain:service/account; empty prompts
	// Repositories limits syncing to these WriteupsDB repositories (names or IDs); empty syncs all.
	Repositories []string `json:"repositories,omitempty"`
	// Map is the finding -> write-up mapping file, relative to ~/.hiccup/plextrac/.
	Map string `json:"map,omitempty"`
}

// PlexTracSettings returns the PlexTrac settings with HICCUP_PLEXTRAC_URL,
// HICCUP_PLEXTRAC_USERNAME, HICCUP_PLEXTRAC_PASSWORD and HICCUP_PLEXTRAC_MAP applied.
func (c *Config) PlexTracSettings() PlexTrac {
	var p PlexTrac
	if c.PlexTrac != nil {
		p = *c.PlexTrac
	}
	for env, dst := range map[string]*string{
		"HICCUP_PLEXTRAC_URL": &p.URL, "HICCUP_PLEXTRAC_USERNAME": &p.Username,
		"HICCUP_PLEXTRAC_PASSWORD": &p.Password, "HICCUP_PLEXTRAC_MAP": &p.Map,
	} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	return p
}

// Microsoft identifies the Entra ID (Azure AD) app registration for Microsoft 365.
type Microsoft struct {
	Tenant   string `json:"tenant,omitempty"`    // "organizations" (default), a tenant ID or a domain
	ClientID string `json:"client_id,omitempty"` // public client with "Allow public client flows"
}

// MicrosoftSettings returns the Microsoft app registration, with
// HICCUP_M365_TENANT and HICCUP_M365_CLIENT_ID applied.
func (c *Config) MicrosoftSettings() (tenant, clientID string) {
	if c.Microsoft != nil {
		tenant, clientID = c.Microsoft.Tenant, c.Microsoft.ClientID
	}
	if v := os.Getenv("HICCUP_M365_TENANT"); v != "" {
		tenant = v
	}
	if v := os.Getenv("HICCUP_M365_CLIENT_ID"); v != "" {
		clientID = v
	}
	return tenant, clientID
}

// Zap locates a running ZAP (proxy "zap").
type Zap struct {
	URL    string `json:"url,omitempty"`     // API, default http://127.0.0.1:8090
	APIKey string `json:"api_key,omitempty"` // plaintext, env:VAR or keychain:service/account
	Proxy  string `json:"proxy,omitempty"`   // proxy listener, default the API's host:port
}

// Mitm configures mitmproxy started by `hiccup mitm start` (proxy "mitmproxy").
type Mitm struct {
	Proxy   string   `json:"proxy,omitempty"`    // listen address, default 127.0.0.1:8082
	APIPort int      `json:"api_port,omitempty"` // hiccup addon API port, default 8097
	Bin     string   `json:"bin,omitempty"`      // mitmdump binary, default from PATH
	Args    []string `json:"args,omitempty"`     // extra mitmdump arguments
}

// ZapEndpoint is the ZAP API URL, API key reference and proxy, with HICCUP_ZAP_URL
// and HICCUP_ZAP_API_KEY applied.
func (c *Config) ZapEndpoint() (url, keyRef, proxy string) {
	if c.Zap != nil {
		url, keyRef, proxy = c.Zap.URL, c.Zap.APIKey, c.Zap.Proxy
	}
	if v := os.Getenv("HICCUP_ZAP_URL"); v != "" {
		url = v
	}
	if v := os.Getenv("HICCUP_ZAP_API_KEY"); v != "" {
		keyRef = v
	}
	if url == "" {
		url = "http://127.0.0.1:8090"
	}
	return url, keyRef, proxy
}

// MitmSettings returns the mitmproxy settings with defaults filled in.
func (c *Config) MitmSettings() Mitm {
	m := Mitm{}
	if c.Mitm != nil {
		m = *c.Mitm
	}
	if m.Proxy == "" {
		m.Proxy = "127.0.0.1:8082"
	}
	if m.APIPort == 0 {
		m.APIPort = 8097
	}
	if m.Bin == "" {
		m.Bin = "mitmdump"
	}
	return m
}

// Matrix says where `hiccup matrix export --xlsx` takes its layout from.
type Matrix struct {
	Template string `json:"template,omitempty"` // e.g. ~/.hiccup/Checklist.xltx
	Sheet    string `json:"sheet,omitempty"`    // default "Auth Matrix"
	// M365 is where every export also uploads the workbook: "onedrive:/path/" or
	// a OneDrive/SharePoint folder URL. "{site}" is replaced by the site name.
	M365 string `json:"m365,omitempty"`
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
	// NavSelector finds the links `matrix record` clicks; default "nav a, [role=navigation] a, [role=menu] a, aside a".
	NavSelector string `json:"nav_selector,omitempty"`
	// Exclude are URL regexes never recorded or replayed (logout is always excluded).
	Exclude []string `json:"exclude,omitempty"`
	// ListenerBase is the first proxy listener port for per-account browsers
	// (--parallel): accounts get ListenerBase, ListenerBase+1, ... (default 8181).
	ListenerBase int `json:"listener_base,omitempty"`
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
	// ProxyPort pins this account's proxy listener for --parallel.
	ProxyPort int `json:"proxy_port,omitempty"`
}

// DefaultListenerBase is the first per-account listener port.
const DefaultListenerBase = 8181

// CDPOffset is added to an account's listener port to get its browser's CDP port.
const CDPOffset = 1000

// AccountPorts assigns each account a proxy listener port for --parallel: its
// own proxy_port, or the next free port from listener_base, in the order of
// Accounts (highest level first, then by name).
func (s *Site) AccountPorts() map[string]int {
	base := s.ListenerBase
	if base == 0 {
		base = DefaultListenerBase
	}
	out := map[string]int{}
	used := map[int]bool{}
	for _, r := range s.Accounts() {
		if p := r.Account.ProxyPort; p != 0 {
			out[r.Account.Name] = p
			used[p] = true
		}
	}
	next := base
	for _, r := range s.Accounts() {
		if _, ok := out[r.Account.Name]; ok {
			continue
		}
		for used[next] {
			next++
		}
		out[r.Account.Name] = next
		used[next] = true
	}
	return out
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
// (ProxyName, BurpEndpoint, Site.EffectiveThrottle, Site.EffectiveUserAgent)
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

// ProxyName is $HICCUP_PROXY, the config's proxy, or "burp".
func (c *Config) ProxyName() string {
	if v := os.Getenv("HICCUP_PROXY"); v != "" {
		return v
	}
	if c.Proxy != "" {
		return c.Proxy
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

// AccountRef is an account with its role, for iterating a site's accounts.
type AccountRef struct {
	Role    string
	Level   int
	Account *Account
}

// Accounts lists a site's accounts, highest level first, then by name.
func (s *Site) Accounts() []AccountRef {
	var out []AccountRef
	for rn, r := range s.Roles {
		for _, a := range r.Accounts {
			out = append(out, AccountRef{Role: rn, Level: r.Level, Account: a})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level > out[j].Level
		}
		return out[i].Account.Name < out[j].Account.Name
	})
	return out
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
		Proxy: "burp",
		Burp:  Burp{URL: "http://127.0.0.1:8099", BApps: []string{}},
		Sites: map[string]*Site{
			"example": {
				BaseURL: "https://app.example.test",
				Scope:   []string{"https://app.example.test/"},
				Throttle: &Throttle{RPS: 1, Burst: 1, JitterMS: [2]int{300, 1500}, MaxConcurrency: 1,
					Backoff: &Backoff{OnStatus: []int{429, 503}, HonorRetryAfter: true, MaxS: 120}},
				Login: &Login{URL: "/login", Username: "#email", Password: "#password",
					Submit: "button[type=submit]", Success: &LoginSuccess{URLContains: "/dashboard"}},
				Session:     &Session{Cookies: []string{"session"}, Headers: []string{"Authorization"}},
				NavSelector: "nav a",
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
