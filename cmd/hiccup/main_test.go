package main

import (
	"encoding/base64"
	"os"
	"slices"
	"testing"

	"github.com/infinite-omicron/hiccup/internal/config"
)

func TestParseRange(t *testing.T) {
	for in, want := range map[string][2]int{"0": {0, 0}, "500": {500, 500}, "500-2000": {500, 2000}, " 1 - 2 ": {1, 2}} {
		got, err := parseRange(in)
		if err != nil || got != want {
			t.Errorf("parseRange(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "x", "5-1", "1-x"} {
		if _, err := parseRange(bad); err == nil {
			t.Errorf("parseRange(%q) should fail", bad)
		}
	}
}

func TestNormalizeRaw(t *testing.T) {
	got := string(normalizeRaw([]byte("POST /x HTTP/1.1\nHost: a\n\nbody\nline2")))
	if want := "POST /x HTTP/1.1\r\nHost: a\r\n\r\nbody\nline2"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := string(normalizeRaw([]byte("GET / HTTP/1.1\nHost: a\n"))); got != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Errorf("no body: got %q", got)
	}
	crlf := "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
	if got := string(normalizeRaw([]byte(crlf))); got != crlf {
		t.Errorf("CRLF input changed: %q", got)
	}
}

func TestNucleiRate(t *testing.T) {
	cases := map[float64][]string{
		2:    {"-rl", "2", "-rld", "1s"},
		0.5:  {"-rl", "1", "-rld", "2s"},
		0.25: {"-rl", "1", "-rld", "4s"},
	}
	for rps, want := range cases {
		if got := nucleiRate(rps); !slices.Equal(got, want) {
			t.Errorf("nucleiRate(%v) = %v, want %v", rps, got, want)
		}
	}
}

func TestRequestFlags(t *testing.T) {
	f := requestFlags{url: "https://a.test/x", headers: []string{"X-A: 1", "Cookie: s=2"}, data: "q=1"}
	r, err := f.build()
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Body != "q=1" || len(r.Headers) != 2 || r.Headers[1] != [2]string{"Cookie", "s=2"} {
		t.Errorf("unexpected request: %+v", r)
	}
	if _, err := (&requestFlags{url: "https://a.test", headers: []string{"bad"}}).build(); err == nil {
		t.Error("header without colon should fail")
	}
	if _, err := (&requestFlags{}).build(); err == nil {
		t.Error("missing --url should fail")
	}
}

func TestRequestFlagsRaw(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/req.txt"
	if err := os.WriteFile(path, []byte("GET / HTTP/1.1\nHost: a\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := (&requestFlags{raw: path, host: "a.test", plainHTTP: true}).build()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(r.RawB64)
	if string(raw) != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" || r.Host != "a.test" || r.HTTPS == nil || *r.HTTPS {
		t.Errorf("unexpected raw request: %+v (%q)", r, raw)
	}
	if _, err := (&requestFlags{raw: path}).build(); err == nil {
		t.Error("--raw without a target should fail")
	}
}

func TestThrottleRules(t *testing.T) {
	s := &config.Site{
		BaseURL:  "https://app.example.test",
		Scope:    []string{"https://api.example.test/v1/", "https://app.example.test/admin"},
		Throttle: &config.Throttle{RPS: 0.5, JitterMS: [2]int{100, 200}, Backoff: &config.Backoff{OnStatus: []int{429}, MaxS: 30}},
	}
	rules := throttleRules(s.Hosts(), s.Throttle)
	if len(rules) != 2 || rules[0].Host != "app.example.test" || rules[1].Host != "api.example.test" {
		t.Fatalf("rules: %+v", rules)
	}
	if r := rules[0]; r.RPS != 0.5 || r.JitterMS != [2]int{100, 200} || !slices.Equal(r.Backoff.OnStatus, []int{429}) || r.Backoff.MaxS != 30 {
		t.Errorf("rule: %+v", r)
	}
	if throttleRules([]string{"x.test"}, nil) != nil {
		t.Error("no throttle config should give no rules")
	}
}
