package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// scopeURLs turns scope arguments into the URL prefixes every proxy accepts.
//
//   - A bare host (example.com, example.com:8443, example.com/app) means both
//     https:// and http://, unless the port is 443 or 80.
//   - A URL keeps its scheme; one without a path gets "/", so prefix matching
//     (mitmproxy) can't also match example.com.evil.net.
//   - Wildcards are rejected: Burp's API only takes URL prefixes.
func scopeURLs(args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if strings.Contains(arg, "*") {
			return nil, fmt.Errorf("%q: wildcards aren't supported; Burp's scope API takes URL prefixes, so add each host (e.g. app.example.com)", arg)
		}
		schemes := []string{"https", "http"}
		raw := arg
		if strings.Contains(arg, "://") {
			u, err := url.Parse(arg)
			if err != nil || u.Host == "" {
				return nil, fmt.Errorf("%q is not a valid URL", arg)
			}
			schemes, raw = []string{u.Scheme}, strings.TrimPrefix(arg, u.Scheme+"://")
		}
		hostport, path, _ := strings.Cut(raw, "/")
		if hostport == "" {
			return nil, fmt.Errorf("%q has no host", arg)
		}
		if _, port, err := net.SplitHostPort(hostport); err == nil && len(schemes) == 2 {
			switch port {
			case "443":
				schemes = []string{"https"}
			case "80":
				schemes = []string{"http"}
			}
		}
		for _, s := range schemes {
			u, err := url.Parse(s + "://" + hostport + "/" + path)
			if err != nil || u.Hostname() == "" {
				return nil, fmt.Errorf("%q is not a valid host or URL", arg)
			}
			add(u.String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no host or URL given")
	}
	return out, nil
}
