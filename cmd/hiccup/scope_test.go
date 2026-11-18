package main

import (
	"slices"
	"strings"
	"testing"
)

func TestScopeURLs(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		// Issue #10: a bare host is accepted and means both schemes.
		{[]string{"infinite-omicron.com"}, []string{"https://infinite-omicron.com/", "http://infinite-omicron.com/"}},
		{[]string{"https://infinite-omicron.com"}, []string{"https://infinite-omicron.com/"}},
		{[]string{"http://a.test/app/"}, []string{"http://a.test/app/"}},
		{[]string{"a.test/app"}, []string{"https://a.test/app", "http://a.test/app"}},
		{[]string{"a.test:8443"}, []string{"https://a.test:8443/", "http://a.test:8443/"}},
		{[]string{"a.test:443"}, []string{"https://a.test:443/"}},
		{[]string{"a.test:80"}, []string{"http://a.test:80/"}},
		{[]string{"127.0.0.1:18081"}, []string{"https://127.0.0.1:18081/", "http://127.0.0.1:18081/"}},
		{[]string{"[::1]:8080"}, []string{"https://[::1]:8080/", "http://[::1]:8080/"}},
		{[]string{"a.test", "https://a.test"}, []string{"https://a.test/", "http://a.test/"}}, // deduplicated
	}
	for _, c := range cases {
		got, err := scopeURLs(c.in)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("scopeURLs(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for in, want := range map[string]string{
		"*.example.com": "wildcards",
		"https://":      "not a valid URL",
		"/just/a/path":  "no host",
		"":              "no host or URL",
	} {
		if _, err := scopeURLs([]string{in}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("scopeURLs(%q) error = %v, want it to mention %q", in, err, want)
		}
	}
}
