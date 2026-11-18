// Package zap drives OWASP ZAP through its REST API. ZAP has no browser of its
// own, so the browser is launched locally and proxied through ZAP.
package zap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/browser"
)

// Context is the ZAP context hiccup uses as its scope.
const Context = "hiccup"

// rulePrefix marks the rate-limit and replacer rules hiccup owns.
const rulePrefix = "hiccup "

type Client struct {
	BaseURL string // ZAP API, e.g. http://127.0.0.1:8090
	APIKey  string
	Proxy   string // ZAP's proxy listener; usually the same host:port as the API
	HTTP    *http.Client
	browser *browser.Launcher
}

var _ backend.Backend = (*Client)(nil)

func New(baseURL, apiKey, proxy string) *Client {
	if proxy == "" {
		if u, err := url.Parse(baseURL); err == nil {
			proxy = u.Host
		}
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, Proxy: proxy,
		HTTP:    &http.Client{Transport: &http.Transport{Proxy: nil}},
		browser: &browser.Launcher{Name: "zap", Proxy: proxy}}
}

func unsupported(what string) error { return fmt.Errorf("ZAP: %s: %w", what, backend.ErrUnsupported) }

// call runs /JSON/<component>/<kind>/<name>/ with params (POSTed as a form, so
// long raw requests fit) and decodes the JSON answer into out.
func (c *Client) call(ctx context.Context, component, kind, name string, params url.Values, out any) error {
	u := fmt.Sprintf("%s/JSON/%s/%s/%s/", c.BaseURL, component, kind, name)
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-ZAP-API-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach ZAP at %s (is it running with the API enabled?): %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		var e struct{ Code, Message string }
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("ZAP %s/%s/%s: %s %s", component, kind, name, e.Code, e.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var v struct{ Version string }
	if err := c.call(ctx, "core", "view", "version", nil, &v); err != nil {
		return nil, err
	}
	m := map[string]any{"name": "ZAP", "version": "ZAP " + v.Version, "edition": "ZAP", "proxy": c.Proxy}
	if on, err := c.Intercept(ctx); err == nil {
		m["intercept"] = on
	}
	return m, nil
}

// ---- browser ----

func (c *Client) BrowserLaunch(ctx context.Context, o backend.BrowserOptions) (*backend.BrowserStatus, error) {
	if !o.KeepIntercept {
		_, _ = c.SetIntercept(ctx, false)
	}
	return c.browser.Launch(ctx, o)
}

func (c *Client) BrowserStatus(ctx context.Context) (*backend.BrowserStatus, error) {
	return c.browser.Status(ctx)
}

func (c *Client) BrowserStop(ctx context.Context) (*backend.BrowserStatus, error) {
	return c.browser.Stop(ctx)
}

func (c *Client) Intercept(ctx context.Context) (bool, error) {
	var r struct {
		IsBreakAll string `json:"isBreakAll"`
	}
	err := c.call(ctx, "break", "view", "isBreakAll", nil, &r)
	return r.IsBreakAll == "true", err
}

func (c *Client) SetIntercept(ctx context.Context, enabled bool) (bool, error) {
	err := c.call(ctx, "break", "action", "break", url.Values{"type": {"http-all"}, "state": {strconv.FormatBool(enabled)}}, nil)
	return enabled, err
}

// ---- history ----

// message is ZAP's JSON form of an HTTP message.
type message struct {
	ID             string `json:"id"`
	Timestamp      string `json:"timestamp"`
	RequestHeader  string `json:"requestHeader"`
	RequestBody    string `json:"requestBody"`
	ResponseHeader string `json:"responseHeader"`
	ResponseBody   string `json:"responseBody"`
}

func (m *message) id() int { n, _ := strconv.Atoi(m.ID); return n }

// methodURL reads the request line; ZAP keeps absolute URLs there.
func (m *message) methodURL() (string, string) {
	line, _, _ := strings.Cut(m.RequestHeader, "\r\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return "", ""
	}
	return f[0], f[1]
}

func (m *message) status() *int {
	f := strings.Fields(m.ResponseHeader)
	if len(f) < 2 {
		return nil
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return nil
	}
	return &n
}

func headerValue(head, name string) string {
	for _, l := range strings.Split(head, "\r\n")[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// mime maps Content-Type to the Burp-style names the matrix filter understands.
func mime(head string) string {
	ct := strings.ToLower(headerValue(head, "Content-Type"))
	switch {
	case ct == "":
		return ""
	case strings.HasPrefix(ct, "image/"):
		return "IMAGE"
	case strings.HasPrefix(ct, "font/"):
		return "FONT"
	case strings.HasPrefix(ct, "text/css"):
		return "CSS"
	case strings.Contains(ct, "javascript"):
		return "SCRIPT"
	case strings.Contains(ct, "json"):
		return "JSON"
	case strings.Contains(ct, "html"):
		return "HTML"
	}
	return strings.ToUpper(strings.TrimSpace(strings.Split(ct, ";")[0]))
}

func (m *message) summary() backend.Summary {
	method, u := m.methodURL()
	s := backend.Summary{ID: m.id(), Method: method, URL: u, Status: m.status(), MIME: mime(m.ResponseHeader)}
	if ms, err := strconv.ParseInt(m.Timestamp, 10, 64); err == nil {
		s.Time = time.UnixMilli(ms).Format(time.RFC3339)
	}
	if m.ResponseHeader != "" {
		n := len(m.ResponseHeader) + len(m.ResponseBody)
		s.Length = &n
	}
	return s
}

// raw turns a message into an exchange. The request line is made
// origin-form (path only) so it looks like what was sent on the wire.
func (m *message) exchange() *backend.Exchange {
	s := m.summary()
	reqHead := m.RequestHeader
	if line, rest, ok := strings.Cut(reqHead, "\r\n"); ok {
		f := strings.Fields(line)
		if len(f) == 3 {
			if u, err := url.Parse(f[1]); err == nil && u.IsAbs() {
				f[1] = u.RequestURI()
			}
			reqHead = strings.Join(f, " ") + "\r\n" + rest
		}
	}
	e := &backend.Exchange{ID: s.ID, Time: s.Time, Method: s.Method, URL: s.URL, Status: s.Status, Length: s.Length,
		RequestB64: base64.StdEncoding.EncodeToString([]byte(reqHead + m.RequestBody))}
	if m.ResponseHeader != "" {
		e.ResponseB64 = base64.StdEncoding.EncodeToString([]byte(m.ResponseHeader + m.ResponseBody))
		for _, l := range strings.Split(m.ResponseHeader, "\r\n")[1:] {
			if k, v, ok := strings.Cut(l, ":"); ok {
				e.ResponseHeaders = append(e.ResponseHeaders, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
			}
		}
	}
	return e
}

func (c *Client) messages(ctx context.Context, baseURL string) ([]message, error) {
	var r struct{ Messages []message }
	p := url.Values{}
	if baseURL != "" {
		p.Set("baseurl", baseURL)
	}
	if err := c.call(ctx, "core", "view", "messages", p, &r); err != nil {
		return nil, err
	}
	sort.Slice(r.Messages, func(i, j int) bool { return r.Messages[i].id() < r.Messages[j].id() })
	return r.Messages, nil
}

func (c *Client) History(ctx context.Context, q backend.HistoryQuery) ([]backend.Summary, error) {
	msgs, err := c.messages(ctx, "")
	if err != nil {
		return nil, err
	}
	var scope []*regexp.Regexp
	if q.InScope {
		if scope, err = c.scopeRegexps(ctx); err != nil {
			return nil, err
		}
	}
	var out []backend.Summary
	for i := range msgs {
		s := msgs[i].summary()
		if s.ID <= q.Since || (q.Contains != "" && !strings.Contains(s.URL, q.Contains)) || (q.InScope && !matchAny(scope, s.URL)) {
			continue
		}
		out = append(out, s)
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[len(out)-q.Limit:]
	}
	return out, nil
}

func (c *Client) HistoryItem(ctx context.Context, id int) (*backend.Exchange, error) {
	var r struct{ Message message }
	if err := c.call(ctx, "core", "view", "message", url.Values{"id": {strconv.Itoa(id)}}, &r); err != nil {
		return nil, err
	}
	return r.Message.exchange(), nil
}

func (c *Client) SiteMap(ctx context.Context, prefix string, full bool) ([]backend.Exchange, error) {
	msgs, err := c.messages(ctx, prefix)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []backend.Exchange
	for i := len(msgs) - 1; i >= 0; i-- {
		e := msgs[i].exchange()
		if seen[e.Method+" "+e.URL] {
			continue
		}
		seen[e.Method+" "+e.URL] = true
		if !full {
			e = &backend.Exchange{Method: e.Method, URL: e.URL, Status: e.Status}
		}
		out = append(out, *e)
	}
	return out, nil
}

// ---- sending ----

// rawRequest builds the raw request ZAP's sendRequest wants: absolute URL in the request line.
func rawRequest(r backend.Request) (string, error) {
	if r.RawB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(r.RawB64)
		if err != nil {
			return "", err
		}
		head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
		line, rest, _ := strings.Cut(head, "\r\n")
		f := strings.Fields(line)
		if len(f) != 3 {
			return "", fmt.Errorf("bad request line %q", line)
		}
		if !strings.Contains(f[1], "://") {
			origin := ""
			switch {
			case r.Host != "":
				scheme, port := "https", r.Port
				if r.HTTPS != nil && !*r.HTTPS {
					scheme = "http"
				}
				origin = scheme + "://" + r.Host
				if port != 0 && !(scheme == "https" && port == 443) && !(scheme == "http" && port == 80) {
					origin += ":" + strconv.Itoa(port)
				}
			case r.URL != "":
				u, err := url.Parse(r.URL)
				if err != nil {
					return "", err
				}
				origin = u.Scheme + "://" + u.Host
			default:
				return "", fmt.Errorf("raw request needs a host or url")
			}
			f[1] = origin + f[1]
		}
		return strings.Join(f, " ") + "\r\n" + rest + "\r\n\r\n" + body, nil
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	body := r.Body
	if r.BodyB64 != "" {
		b, err := base64.StdEncoding.DecodeString(r.BodyB64)
		if err != nil {
			return "", err
		}
		body = string(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, u.String(), u.Host)
	for _, h := range r.Headers {
		if !strings.EqualFold(h[0], "Host") {
			fmt.Fprintf(&sb, "%s: %s\r\n", h[0], h[1])
		}
	}
	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("\r\n" + body)
	return sb.String(), nil
}

func (c *Client) Send(ctx context.Context, reqs []backend.Request) ([]backend.Exchange, error) {
	out := make([]backend.Exchange, 0, len(reqs))
	for _, r := range reqs {
		raw, err := rawRequest(r)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		var res struct {
			SendRequest []message `json:"sendRequest"`
		}
		if err := c.call(ctx, "core", "action", "sendRequest", url.Values{"request": {raw}, "followRedirects": {"false"}}, &res); err != nil {
			return nil, err
		}
		if len(res.SendRequest) == 0 {
			return nil, fmt.Errorf("ZAP sendRequest returned no message")
		}
		e := res.SendRequest[0].exchange()
		ms := time.Since(start).Milliseconds()
		e.ElapsedMS = &ms
		out = append(out, *e)
	}
	return out, nil
}

func (c *Client) SendToRepeater(context.Context, backend.Request, string) error {
	return unsupported("Repeater (use hiccup send, or ZAP's Requester in the desktop UI)")
}

func (c *Client) SendToIntruder(context.Context, backend.Request, string) error {
	return unsupported("Intruder (use ZAP's Fuzzer in the desktop UI)")
}

func (c *Client) Scan(ctx context.Context, mode string, urls []string) error {
	for _, u := range urls {
		var err error
		switch mode {
		case "crawl":
			err = c.call(ctx, "spider", "action", "scan", url.Values{"url": {u}}, nil)
		case "audit":
			err = c.call(ctx, "ascan", "action", "scan", url.Values{"url": {u}, "recurse": {"true"}}, nil)
		case "passive":
			// ZAP scans everything it proxies passively; nothing to start.
		default:
			return fmt.Errorf("unknown scan mode %q", mode)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- issues (ZAP alerts) ----

var riskNames = map[string]string{"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFORMATION"}
var riskIDs = map[string]string{"HIGH": "3", "MEDIUM": "2", "LOW": "1", "INFORMATION": "0", "FALSE_POSITIVE": "0"}
var confidenceNames = map[string]string{"Confirmed": "CERTAIN", "High": "CERTAIN", "Medium": "FIRM", "Low": "TENTATIVE", "False Positive": "TENTATIVE"}
var confidenceIDs = map[string]string{"CERTAIN": "3", "FIRM": "2", "TENTATIVE": "1"}

func (c *Client) Issues(ctx context.Context, prefix string) ([]backend.Issue, error) {
	var r struct {
		Alerts []struct {
			Name, Alert, Risk, Confidence, URL, Description, Solution string
		} `json:"alerts"`
	}
	p := url.Values{}
	if prefix != "" {
		p.Set("baseurl", prefix)
	}
	if err := c.call(ctx, "alert", "view", "alerts", p, &r); err != nil {
		return nil, err
	}
	out := make([]backend.Issue, 0, len(r.Alerts))
	for _, a := range r.Alerts {
		name := a.Name
		if name == "" {
			name = a.Alert
		}
		out = append(out, backend.Issue{Name: name, URL: a.URL, Severity: riskNames[a.Risk], Confidence: confidenceNames[a.Confidence],
			Detail: a.Description, Remediation: a.Solution})
	}
	return out, nil
}

var tagRe = regexp.MustCompile(`<[^>]+>`)

func plain(s string) string {
	s = strings.NewReplacer("</p>", "\n", "<br>", "\n", "</li>", "\n", "<li>", "- ").Replace(s)
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, "")))
}

// messageFor finds (or creates, with a GET through ZAP) a history message for
// u, because ZAP alerts must hang off a message.
func (c *Client) messageFor(ctx context.Context, u string) (string, error) {
	msgs, err := c.messages(ctx, u)
	if err != nil {
		return "", err
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if _, mu := msgs[i].methodURL(); mu == u {
			return msgs[i].ID, nil
		}
	}
	if len(msgs) > 0 {
		return msgs[len(msgs)-1].ID, nil
	}
	ex, err := c.Send(ctx, []backend.Request{{URL: u}})
	if err != nil {
		return "", err
	}
	return strconv.Itoa(ex[0].ID), nil
}

func (c *Client) AddIssues(ctx context.Context, issues []backend.Issue) (int, error) {
	for i, is := range issues {
		id, err := c.messageFor(ctx, is.URL)
		if err != nil {
			return i, fmt.Errorf("%s: %w", is.URL, err)
		}
		other := ""
		if len(is.Evidence) > 0 {
			other = fmt.Sprintf("%d request/response pair(s) attached by hiccup; see hiccup's export for the raw evidence.", len(is.Evidence))
		}
		conf := confidenceIDs[is.Confidence]
		if conf == "" {
			conf = "2"
		}
		if is.Severity == "FALSE_POSITIVE" {
			conf = "0"
		}
		risk := riskIDs[is.Severity]
		if risk == "" {
			risk = "0"
		}
		p := url.Values{
			"messageId": {id}, "name": {is.Name}, "riskId": {risk}, "confidenceId": {conf},
			"description": {plain(is.Detail)}, "solution": {plain(is.Remediation)}, "otherInfo": {other},
			"param": {""}, "attack": {""}, "references": {""}, "evidence": {""}, "cweId": {"0"}, "wascId": {"0"},
		}
		if err := c.call(ctx, "alert", "action", "addAlert", p, nil); err != nil {
			return i, err
		}
	}
	return len(issues), nil
}

// ---- scope (a ZAP context) ----

func (c *Client) Scope(ctx context.Context, urls []string, exclude bool) error {
	if err := c.call(ctx, "context", "action", "newContext", url.Values{"contextName": {Context}}, nil); err != nil &&
		!strings.Contains(err.Error(), "already_exists") && !strings.Contains(strings.ToLower(err.Error()), "already exist") {
		return err
	}
	if err := c.call(ctx, "context", "action", "setContextInScope", url.Values{"contextName": {Context}, "booleanInScope": {"true"}}, nil); err != nil {
		return err
	}
	action := "includeInContext"
	if exclude {
		action = "excludeFromContext"
	}
	for _, u := range urls {
		if err := c.call(ctx, "context", "action", action, url.Values{"contextName": {Context}, "regex": {"^" + regexp.QuoteMeta(u) + ".*"}}, nil); err != nil {
			return err
		}
	}
	return nil
}

// stringList decodes ZAP list views, which are either JSON arrays or "[a, b]" strings.
func stringList(raw json.RawMessage) []string {
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "["), "]")
	for _, p := range strings.Split(s, ", ") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, p)
		}
	}
	return list
}

func (c *Client) scopeRegexps(ctx context.Context) ([]*regexp.Regexp, error) {
	var r struct {
		IncludeRegexs json.RawMessage `json:"includeRegexs"`
	}
	if err := c.call(ctx, "context", "view", "includeRegexs", url.Values{"contextName": {Context}}, &r); err != nil {
		if strings.Contains(err.Error(), "context_not_found") {
			return nil, nil
		}
		return nil, err
	}
	var out []*regexp.Regexp
	for _, s := range stringList(r.IncludeRegexs) {
		if re, err := regexp.Compile(s); err == nil {
			out = append(out, re)
		}
	}
	return out, nil
}

func matchAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (c *Client) InScope(ctx context.Context, u string) (bool, error) {
	res, err := c.scopeRegexps(ctx)
	return matchAny(res, u), err
}

// ---- throttle (network add-on rate limit rules) ----

type rateRule struct {
	Description       string `json:"description"`
	Enabled           any    `json:"enabled"`
	MatchString       string `json:"matchString"`
	RequestsPerSecond any    `json:"requestsPerSecond"`
}

func (c *Client) rateRules(ctx context.Context) ([]rateRule, error) {
	var r struct {
		Rules []rateRule `json:"rateLimitRules"`
	}
	err := c.call(ctx, "network", "view", "getRateLimitRules", nil, &r)
	return r.Rules, err
}

func (c *Client) Throttle(ctx context.Context) ([]backend.ThrottleRule, error) {
	rules, err := c.rateRules(ctx)
	if err != nil {
		return nil, err
	}
	var out []backend.ThrottleRule
	for _, r := range rules {
		if !strings.HasPrefix(r.Description, rulePrefix) {
			continue
		}
		rps, _ := strconv.ParseFloat(fmt.Sprint(r.RequestsPerSecond), 64)
		out = append(out, backend.ThrottleRule{Host: r.MatchString, RPS: rps, Burst: 1})
	}
	return out, nil
}

// SetThrottle maps rules onto ZAP rate limits. ZAP takes whole requests per
// second (so rates under 1 become 1) and has no jitter or 429 backoff.
func (c *Client) SetThrottle(ctx context.Context, rules []backend.ThrottleRule) ([]backend.ThrottleRule, error) {
	for _, r := range rules {
		host := strings.TrimPrefix(strings.ToLower(r.Host), "*.")
		desc := rulePrefix + host
		_ = c.call(ctx, "network", "action", "removeRateLimitRule", url.Values{"description": {desc}}, nil)
		if r.RPS <= 0 {
			continue
		}
		p := url.Values{
			"description": {desc}, "enabled": {"true"}, "matchRegex": {"false"}, "matchString": {host},
			"requestsPerSecond": {strconv.Itoa(max(1, int(math.Round(r.RPS))))}, "groupBy": {"host"},
		}
		if err := c.call(ctx, "network", "action", "addRateLimitRule", p, nil); err != nil {
			return nil, err
		}
	}
	return c.Throttle(ctx)
}

func (c *Client) ClearThrottle(ctx context.Context) error {
	rules, err := c.rateRules(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if strings.HasPrefix(r.Description, rulePrefix) {
			if err := c.call(ctx, "network", "action", "removeRateLimitRule", url.Values{"description": {r.Description}}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- User-Agent: ZAP's default UA for its own requests, Replacer rules for proxied ones ----

func (c *Client) UserAgent(ctx context.Context) (*backend.UserAgent, error) {
	var r struct {
		Rules []struct{ Description, Replacement, MatchString string } `json:"rules"`
	}
	if err := c.call(ctx, "replacer", "view", "rules", nil, &r); err != nil {
		return nil, err
	}
	ua := &backend.UserAgent{Scope: "all", ClientHints: map[string]string{}}
	for _, rule := range r.Rules {
		switch {
		case rule.Description == rulePrefix+"User-Agent":
			ua.UA = rule.Replacement
		case strings.HasPrefix(rule.Description, rulePrefix+"Sec-CH-UA"):
			ua.ClientHints[rule.MatchString] = rule.Replacement
		}
	}
	return ua, nil
}

func (c *Client) SetUserAgent(ctx context.Context, ua backend.UserAgent) error {
	if err := c.call(ctx, "network", "action", "setDefaultUserAgent", url.Values{"userAgent": {ua.UA}}, nil); err != nil {
		return err
	}
	headers := map[string]string{"User-Agent": ua.UA}
	for k, v := range ua.ClientHints {
		headers[k] = v
	}
	for h, v := range headers {
		desc := rulePrefix + h
		_ = c.call(ctx, "replacer", "action", "removeRule", url.Values{"description": {desc}}, nil)
		if ua.UA == "" {
			continue
		}
		// An empty replacement removes the header (Firefox-style UAs send no client hints).
		p := url.Values{"description": {desc}, "enabled": {"true"}, "matchType": {"REQ_HEADER"},
			"matchRegex": {"false"}, "matchString": {h}, "replacement": {v}}
		if err := c.call(ctx, "replacer", "action", "addRule", p, nil); err != nil {
			return err
		}
	}
	return nil
}

// ---- not applicable ----

func (c *Client) InstallExtensions(context.Context, []backend.Extension) (*backend.InstallResult, error) {
	return nil, unsupported("loading Burp extensions (install ZAP add-ons from the Marketplace instead)")
}

func (c *Client) UserOptions(context.Context, ...string) (json.RawMessage, error) {
	return nil, unsupported("Burp user options")
}

func (c *Client) SetUserOptions(context.Context, json.RawMessage) error {
	return unsupported("Burp user options")
}

func (c *Client) Shutdown(ctx context.Context) error {
	return c.call(ctx, "core", "action", "shutdown", nil, nil)
}
