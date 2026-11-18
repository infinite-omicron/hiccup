package session

import (
	"strings"
	"testing"
)

func TestApply(t *testing.T) {
	raw := []byte("GET /documents/1 HTTP/1.1\r\nHost: app.test\r\nCookie: session=admin\r\nAuthorization: Bearer admin\r\nX-CSRF: a\r\nAccept: */*\r\n\r\nbody")
	s := &Session{
		Cookies: []Cookie{{Name: "session", Value: "u1", Domain: ".app.test"}, {Name: "other", Value: "x", Domain: "elsewhere.test"}},
		Headers: map[string]string{"X-CSRF": "u1-token"},
	}
	got := string(s.Apply(raw, "app.test", nil))
	want := "GET /documents/1 HTTP/1.1\r\nHost: app.test\r\nAccept: */*\r\nCookie: session=u1\r\nX-CSRF: u1-token\r\n\r\nbody"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	anon := string(Anonymous("s", "anon").Apply(raw, "app.test", []string{"X-CSRF"}))
	if strings.Contains(anon, "Cookie") || strings.Contains(anon, "Authorization") || strings.Contains(anon, "X-CSRF") {
		t.Errorf("anonymous request still has credentials: %q", anon)
	}
}

func TestHeaderValue(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: a\r\nauthorization: Bearer t\r\n\r\n")
	if v, ok := HeaderValue(raw, "Authorization"); !ok || v != "Bearer t" {
		t.Errorf("got %q %v", v, ok)
	}
	if _, ok := HeaderValue(raw, "X-Missing"); ok {
		t.Error("missing header found")
	}
}

func TestDomainMatch(t *testing.T) {
	for _, c := range []struct {
		host, domain string
		want         bool
	}{
		{"app.test", "", true}, {"app.test", "app.test", true}, {"a.app.test", ".app.test", true},
		{"evilapp.test", "app.test", false}, {"app.test", "other.test", false},
	} {
		if got := domainMatch(c.host, c.domain); got != c.want {
			t.Errorf("domainMatch(%q, %q) = %v", c.host, c.domain, got)
		}
	}
}
