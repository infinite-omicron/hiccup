// Package burp talks to the hiccup-burp extension's REST API.
package burp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/backend"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

var _ backend.Backend = (*Client)(nil)

func New(baseURL, token string) *Client {
	// No timeout: throttled sends can legitimately block for a long time. Callers use ctx.
	return &Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{Transport: &http.Transport{Proxy: nil}}}
}

// APIError is a non-2xx response from the extension.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("burp: %d: %s", e.Status, e.Message) }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the hiccup Burp extension at %s (is Burp running with hiccup-burp.jar loaded?): %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct{ Error string }
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = string(data)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var m map[string]any
	return m, c.do(ctx, "GET", "/health", nil, nil, &m)
}

func (c *Client) BrowserLaunch(ctx context.Context, o backend.BrowserOptions) (*backend.BrowserStatus, error) {
	var s backend.BrowserStatus
	if err := c.do(ctx, "POST", "/browser/launch", nil, o, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) BrowserStatus(ctx context.Context) (*backend.BrowserStatus, error) {
	var s backend.BrowserStatus
	return &s, c.do(ctx, "GET", "/browser", nil, nil, &s)
}

func (c *Client) BrowserStop(ctx context.Context) (*backend.BrowserStatus, error) {
	var s backend.BrowserStatus
	return &s, c.do(ctx, "POST", "/browser/stop", nil, nil, &s)
}

func (c *Client) Intercept(ctx context.Context) (bool, error) {
	var r struct{ Enabled bool }
	return r.Enabled, c.do(ctx, "GET", "/proxy/intercept", nil, nil, &r)
}

func (c *Client) SetIntercept(ctx context.Context, enabled bool) (bool, error) {
	var r struct{ Enabled bool }
	return r.Enabled, c.do(ctx, "POST", "/proxy/intercept", nil, map[string]bool{"enabled": enabled}, &r)
}

func (c *Client) History(ctx context.Context, h backend.HistoryQuery) ([]backend.Summary, error) {
	q := url.Values{}
	if h.Contains != "" {
		q.Set("contains", h.Contains)
	}
	if h.Since >= 0 {
		q.Set("since", strconv.Itoa(h.Since))
	}
	if h.Limit > 0 {
		q.Set("limit", strconv.Itoa(h.Limit))
	}
	if h.InScope {
		q.Set("in_scope", "true")
	}
	var out []backend.Summary
	return out, c.do(ctx, "GET", "/proxy/history", q, nil, &out)
}

func (c *Client) HistoryItem(ctx context.Context, id int) (*backend.Exchange, error) {
	var e backend.Exchange
	if err := c.do(ctx, "GET", "/proxy/history/"+strconv.Itoa(id), nil, nil, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (c *Client) SiteMap(ctx context.Context, prefix string, full bool) ([]backend.Exchange, error) {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if full {
		q.Set("full", "true")
	}
	var out []backend.Exchange
	return out, c.do(ctx, "GET", "/sitemap", q, nil, &out)
}

func (c *Client) Send(ctx context.Context, reqs []backend.Request) ([]backend.Exchange, error) {
	var out []backend.Exchange
	return out, c.do(ctx, "POST", "/http/send", nil, map[string]any{"requests": reqs}, &out)
}

func (c *Client) SendToRepeater(ctx context.Context, r backend.Request, tab string) error {
	return c.do(ctx, "POST", "/repeater", nil, withTab(r, tab), nil)
}

func (c *Client) SendToIntruder(ctx context.Context, r backend.Request, tab string) error {
	return c.do(ctx, "POST", "/intruder", nil, withTab(r, tab), nil)
}

func withTab(r backend.Request, tab string) map[string]any {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if tab != "" {
		m["tab"] = tab
	}
	return m
}

func (c *Client) Scan(ctx context.Context, mode string, urls []string) error {
	return c.do(ctx, "POST", "/scan", nil, map[string]any{"mode": mode, "urls": urls}, nil)
}

func (c *Client) Issues(ctx context.Context, prefix string) ([]backend.Issue, error) {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	var out []backend.Issue
	return out, c.do(ctx, "GET", "/issues", q, nil, &out)
}

func (c *Client) AddIssues(ctx context.Context, issues []backend.Issue) (int, error) {
	var r struct{ Added int }
	return r.Added, c.do(ctx, "POST", "/issues", nil, issues, &r)
}

func (c *Client) Scope(ctx context.Context, urls []string, exclude bool) error {
	return c.do(ctx, "POST", "/scope", nil, map[string]any{"urls": urls, "exclude": exclude}, nil)
}

func (c *Client) InScope(ctx context.Context, u string) (bool, error) {
	var r struct {
		InScope bool `json:"in_scope"`
	}
	return r.InScope, c.do(ctx, "GET", "/scope", url.Values{"url": {u}}, nil, &r)
}

func (c *Client) Throttle(ctx context.Context) ([]backend.ThrottleRule, error) {
	var out []backend.ThrottleRule
	return out, c.do(ctx, "GET", "/throttle", nil, nil, &out)
}

func (c *Client) SetThrottle(ctx context.Context, rules []backend.ThrottleRule) ([]backend.ThrottleRule, error) {
	var out []backend.ThrottleRule
	return out, c.do(ctx, "POST", "/throttle", nil, rules, &out)
}

func (c *Client) ClearThrottle(ctx context.Context) error {
	return c.do(ctx, "DELETE", "/throttle", nil, nil, nil)
}

func (c *Client) UserAgent(ctx context.Context) (*backend.UserAgent, error) {
	var ua backend.UserAgent
	if err := c.do(ctx, "GET", "/useragent", nil, nil, &ua); err != nil {
		return nil, err
	}
	return &ua, nil
}

func (c *Client) SetUserAgent(ctx context.Context, ua backend.UserAgent) error {
	return c.do(ctx, "POST", "/useragent", nil, ua, nil)
}

func (c *Client) InstallExtensions(ctx context.Context, exts []backend.Extension) (*backend.InstallResult, error) {
	var r backend.InstallResult
	if err := c.do(ctx, "POST", "/extensions/install", nil, map[string]any{"extensions": exts}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) UserOptions(ctx context.Context, paths ...string) (json.RawMessage, error) {
	q := url.Values{}
	if len(paths) > 0 {
		q.Set("paths", strings.Join(paths, ","))
	}
	var out json.RawMessage
	return out, c.do(ctx, "GET", "/options/user", q, nil, &out)
}

func (c *Client) SetUserOptions(ctx context.Context, fragment json.RawMessage) error {
	return c.do(ctx, "POST", "/options/user", nil, fragment, nil)
}

func (c *Client) Shutdown(ctx context.Context) error {
	return c.do(ctx, "POST", "/shutdown", nil, nil, nil)
}

// WaitReady polls /health until the extension answers or ctx ends.
func (c *Client) WaitReady(ctx context.Context) error {
	for {
		if _, err := c.Health(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
