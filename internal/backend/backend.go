// Package backend defines what hiccup needs from an intercepting proxy. Burp is
// the first implementation; ZAP and mitmproxy can follow behind the same interface.
package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
)

type Backend interface {
	Health(ctx context.Context) (map[string]any, error)

	BrowserLaunch(ctx context.Context, opts BrowserOptions) (*BrowserStatus, error)
	BrowserStatus(ctx context.Context) (*BrowserStatus, error)
	BrowserStop(ctx context.Context) (*BrowserStatus, error)

	Intercept(ctx context.Context) (bool, error)
	SetIntercept(ctx context.Context, enabled bool) (bool, error)

	History(ctx context.Context, q HistoryQuery) ([]Summary, error)
	HistoryItem(ctx context.Context, id int) (*Exchange, error)
	SiteMap(ctx context.Context, prefix string, full bool) ([]Exchange, error)

	Send(ctx context.Context, reqs []Request) ([]Exchange, error)
	SendToRepeater(ctx context.Context, r Request, tab string) error
	SendToIntruder(ctx context.Context, r Request, tab string) error
	Scan(ctx context.Context, mode string, urls []string) error

	Issues(ctx context.Context, prefix string) ([]Issue, error)
	AddIssues(ctx context.Context, issues []Issue) (int, error)

	Scope(ctx context.Context, urls []string, exclude bool) error
	InScope(ctx context.Context, url string) (bool, error)

	Throttle(ctx context.Context) ([]ThrottleRule, error)
	SetThrottle(ctx context.Context, rules []ThrottleRule) ([]ThrottleRule, error)
	ClearThrottle(ctx context.Context) error
	UserAgent(ctx context.Context) (*UserAgent, error)
	SetUserAgent(ctx context.Context, ua UserAgent) error

	// InstallExtensions loads extension files. Burp may reload every extension
	// (the hiccup one too), so callers must reconnect when Reloading is true.
	InstallExtensions(ctx context.Context, exts []Extension) (*InstallResult, error)

	// UserOptions exports Burp user options (optionally only the given paths,
	// e.g. "user_options.extender.python"); SetUserOptions imports a fragment.
	UserOptions(ctx context.Context, paths ...string) (json.RawMessage, error)
	SetUserOptions(ctx context.Context, fragment json.RawMessage) error

	Shutdown(ctx context.Context) error
}

type BrowserOptions struct {
	URL      string `json:"url,omitempty"`
	Port     int    `json:"port,omitempty"`
	UA       string `json:"ua,omitempty"`
	Headless bool   `json:"headless,omitempty"`
	Binary   string `json:"binary,omitempty"`
	// KeepIntercept leaves Proxy intercept on; by default launch turns it off
	// because intercepted requests hang automation.
	KeepIntercept bool `json:"keep_intercept,omitempty"`
}

type BrowserStatus struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid,omitempty"`
	CDP     string `json:"cdp,omitempty"`   // http://127.0.0.1:<port>
	WS      string `json:"ws,omitempty"`    // browser websocket URL
	Token   string `json:"token,omitempty"` // Burp's Chromium wants it in x-burp-authorization on /json/*
}

type HistoryQuery struct {
	Contains string
	Since    int // only items with id > Since; -1 for all
	Limit    int
	InScope  bool
}

// Summary is one proxy history row without bodies.
type Summary struct {
	ID     int    `json:"id"`
	Time   string `json:"time,omitempty"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status *int   `json:"status"`
	Length *int   `json:"length,omitempty"`
	MIME   string `json:"mime,omitempty"`
}

// Request is either URL-based (URL, Method, Headers, Body) or raw (Raw + URL or Host/Port/HTTPS).
type Request struct {
	URL     string      `json:"url,omitempty"`
	Method  string      `json:"method,omitempty"`
	Headers [][2]string `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	BodyB64 string      `json:"body_b64,omitempty"`
	RawB64  string      `json:"raw_b64,omitempty"`
	Host    string      `json:"host,omitempty"`
	Port    int         `json:"port,omitempty"`
	HTTPS   *bool       `json:"https,omitempty"`
}

// Exchange is a full request/response pair.
type Exchange struct {
	ID              int         `json:"id,omitempty"`
	Time            string      `json:"time,omitempty"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Status          *int        `json:"status"`
	Length          *int        `json:"length,omitempty"`
	ElapsedMS       *int64      `json:"elapsed_ms,omitempty"`
	ResponseHeaders [][2]string `json:"response_headers,omitempty"`
	RequestB64      string      `json:"request_b64,omitempty"`
	ResponseB64     string      `json:"response_b64,omitempty"`
}

func (e *Exchange) Request() []byte  { return decode(e.RequestB64) }
func (e *Exchange) Response() []byte { return decode(e.ResponseB64) }

func decode(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

type Issue struct {
	Name                  string     `json:"name"`
	URL                   string     `json:"url"`
	Severity              string     `json:"severity"`   // HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE
	Confidence            string     `json:"confidence"` // CERTAIN, FIRM, TENTATIVE
	Detail                string     `json:"detail,omitempty"`
	Remediation           string     `json:"remediation,omitempty"`
	Background            string     `json:"background,omitempty"`
	RemediationBackground string     `json:"remediation_background,omitempty"`
	Evidence              []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	URL         string `json:"url,omitempty"`
	RequestB64  string `json:"request_b64"`
	ResponseB64 string `json:"response_b64,omitempty"`
}

type ThrottleRule struct {
	Host     string  `json:"host"`
	RPS      float64 `json:"rps"`
	Burst    int     `json:"burst,omitempty"`
	JitterMS [2]int  `json:"jitter_ms"`
	Backoff  struct {
		OnStatus        []int `json:"on_status,omitempty"`
		HonorRetryAfter bool  `json:"honor_retry_after"`
		MaxS            int   `json:"max_s,omitempty"`
	} `json:"backoff"`
}

type Extension struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"` // java, python, ruby
	Name string `json:"name,omitempty"`
}

type InstallResult struct {
	Added     []string `json:"added"`
	Already   []string `json:"already"`
	Reloading bool     `json:"reloading"`
}

type UserAgent struct {
	UA    string `json:"ua"`
	Scope string `json:"scope,omitempty"`
	// ClientHints are rewritten alongside User-Agent so Sec-CH-UA* stays consistent.
	ClientHints map[string]string `json:"client_hints,omitempty"`
}
