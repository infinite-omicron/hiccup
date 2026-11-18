package zap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/infinite-omicron/hiccup/internal/backend"
)

// fakeZAP records API calls and answers the few views the client reads.
type fakeZAP struct {
	mu    sync.Mutex
	calls []string
	forms []url.Values
}

func (f *fakeZAP) handler(t *testing.T) http.Handler {
	msg := func(id, line, status, body string) map[string]string {
		return map[string]string{
			"id": id, "timestamp": "1794971624000",
			"requestHeader":  line + " HTTP/1.1\r\nHost: a.test\r\nCookie: s=1\r\n\r\n",
			"responseHeader": "HTTP/1.1 " + status + " OK\r\nContent-Type: text/html\r\n\r\n", "responseBody": body,
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ZAP-API-Key") != "k" {
			http.Error(w, `{"code":"bad_api_key","message":"Bad API key"}`, 400)
			return
		}
		_ = r.ParseForm()
		f.mu.Lock()
		f.calls = append(f.calls, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/JSON/"), "/"))
		f.forms = append(f.forms, r.PostForm)
		f.mu.Unlock()
		var out any = map[string]string{"Result": "OK"}
		switch strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/JSON/"), "/") {
		case "core/view/version":
			out = map[string]string{"version": "2.17.0"}
		case "break/view/isBreakAll":
			out = map[string]string{"isBreakAll": "false"}
		case "core/view/messages":
			msgs := []any{msg("2", "GET https://a.test/docs/2", "200", "two"), msg("1", "GET https://a.test/", "200", "home")}
			if r.PostForm.Get("baseurl") == "https://new.test/" {
				msgs = nil
			}
			out = map[string]any{"messages": msgs}
		case "core/view/message":
			out = map[string]any{"message": msg(r.PostForm.Get("id"), "POST https://a.test/x?y=1", "403", "no")}
		case "core/action/sendRequest":
			line, _, _ := strings.Cut(r.PostForm.Get("request"), "\r\n")
			out = map[string]any{"sendRequest": []any{msg("9", line, "200", "sent")}}
		case "context/view/includeRegexs":
			out = map[string]string{"includeRegexs": `[^https://a\.test/.*]`}
		case "network/view/getRateLimitRules":
			out = map[string]any{"rateLimitRules": []any{
				map[string]any{"description": "hiccup a.test", "matchString": "a.test", "requestsPerSecond": 1, "enabled": true},
				map[string]any{"description": "someone else's", "matchString": "b.test", "requestsPerSecond": 5, "enabled": true},
			}}
		case "replacer/view/rules":
			out = map[string]any{"rules": []any{map[string]string{"description": "hiccup User-Agent", "matchString": "User-Agent", "replacement": "UA/1"}}}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

func (f *fakeZAP) form(call string) url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if c == call {
			return f.forms[i]
		}
	}
	return nil
}

func setup(t *testing.T) (*Client, *fakeZAP) {
	f := &fakeZAP{}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return New(srv.URL, "k", "127.0.0.1:8090"), f
}

func TestHealthHistoryItem(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	h, err := c.Health(ctx)
	if err != nil || h["version"] != "ZAP 2.17.0" || h["intercept"] != false {
		t.Fatalf("health: %v %v", h, err)
	}
	rows, err := c.History(ctx, backend.HistoryQuery{Since: 1, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != 2 || rows[0].URL != "https://a.test/docs/2" || *rows[0].Status != 200 || rows[0].MIME != "HTML" {
		t.Fatalf("history: %+v %v", rows, err)
	}
	e, err := c.HistoryItem(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if req := string(e.Request()); !strings.HasPrefix(req, "POST /x?y=1 HTTP/1.1\r\nHost: a.test") {
		t.Errorf("request line should be origin-form: %q", req)
	}
	if e.Method != "POST" || *e.Status != 403 {
		t.Errorf("item: %+v", e)
	}
	if _, err := New(c.BaseURL, "wrong", "").Health(ctx); err == nil || !strings.Contains(err.Error(), "Bad API key") {
		t.Errorf("bad key: %v", err)
	}
}

func TestSendMakesRequestLineAbsolute(t *testing.T) {
	c, f := setup(t)
	https := true
	raw := "GET /a?b=1 HTTP/1.1\r\nHost: a.test\r\nCookie: s=2\r\n\r\n"
	ex, err := c.Send(context.Background(), []backend.Request{
		{RawB64: b64(raw), Host: "a.test", Port: 8443, HTTPS: &https},
		{URL: "http://a.test/form", Method: "POST", Body: "q=1", Headers: [][2]string{{"X-A", "1"}}},
	})
	if err != nil || len(ex) != 2 || ex[0].ElapsedMS == nil {
		t.Fatalf("send: %+v %v", ex, err)
	}
	f.mu.Lock()
	first, second := f.forms[0].Get("request"), f.forms[1].Get("request")
	f.mu.Unlock()
	if !strings.HasPrefix(first, "GET https://a.test:8443/a?b=1 HTTP/1.1\r\nHost: a.test\r\nCookie: s=2") {
		t.Errorf("raw: %q", first)
	}
	if !strings.Contains(second, "POST http://a.test/form HTTP/1.1\r\nHost: a.test\r\nX-A: 1\r\nContent-Length: 3\r\n\r\nq=1") {
		t.Errorf("url form: %q", second)
	}
}

func TestAddIssues(t *testing.T) {
	c, f := setup(t)
	n, err := c.AddIssues(context.Background(), []backend.Issue{
		{Name: "IDOR", URL: "https://a.test/docs/2", Severity: "HIGH", Confidence: "TENTATIVE", Detail: "<p>user2 read <b>doc</b> &amp; more</p>"},
		{Name: "New", URL: "https://new.test/", Severity: "LOW"}, // no history yet: a GET creates a message
	})
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	a := f.form("alert/action/addAlert")
	if a.Get("messageId") != "2" || a.Get("riskId") != "3" || a.Get("confidenceId") != "1" || a.Get("description") != "user2 read doc & more" {
		t.Errorf("addAlert: %v", a)
	}
	if f.form("core/action/sendRequest") == nil {
		t.Error("an issue on a URL without history should create a message")
	}
}

func TestScopeThrottleUA(t *testing.T) {
	c, f := setup(t)
	ctx := context.Background()
	if err := c.Scope(ctx, []string{"https://a.test/"}, false); err != nil {
		t.Fatal(err)
	}
	if got := f.form("context/action/includeInContext").Get("regex"); got != `^https://a\.test/.*` {
		t.Errorf("regex %q", got)
	}
	if in, _ := c.InScope(ctx, "https://a.test/x"); !in {
		t.Error("in scope")
	}
	if in, _ := c.InScope(ctx, "https://b.test/"); in {
		t.Error("out of scope")
	}

	rules, err := c.SetThrottle(ctx, []backend.ThrottleRule{{Host: "*.a.test", RPS: 0.5}})
	if err != nil || len(rules) != 1 || rules[0].Host != "a.test" {
		t.Fatalf("throttle: %+v %v", rules, err)
	}
	add := f.form("network/action/addRateLimitRule")
	if add.Get("matchString") != "a.test" || add.Get("requestsPerSecond") != "1" || add.Get("description") != "hiccup a.test" {
		t.Errorf("rate rule: %v", add)
	}

	if err := c.SetUserAgent(ctx, backend.UserAgent{UA: "UA/2", ClientHints: map[string]string{"Sec-CH-UA": ""}}); err != nil {
		t.Fatal(err)
	}
	if f.form("network/action/setDefaultUserAgent").Get("userAgent") != "UA/2" {
		t.Error("default UA not set")
	}
	f.mu.Lock()
	var replacements []string
	for i, call := range f.calls {
		if call == "replacer/action/addRule" {
			replacements = append(replacements, f.forms[i].Get("matchString")+"="+f.forms[i].Get("replacement"))
		}
	}
	f.mu.Unlock()
	if strings.Join(replacements, ",") != "Sec-CH-UA=,User-Agent=UA/2" && strings.Join(replacements, ",") != "User-Agent=UA/2,Sec-CH-UA=" {
		t.Errorf("replacer rules: %v", replacements)
	}
	if ua, _ := c.UserAgent(ctx); ua.UA != "UA/1" {
		t.Errorf("UA view: %+v", ua)
	}
}

func TestUnsupported(t *testing.T) {
	c, _ := setup(t)
	if err := c.SendToRepeater(context.Background(), backend.Request{}, ""); !errors.Is(err, backend.ErrUnsupported) {
		t.Errorf("repeater: %v", err)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
