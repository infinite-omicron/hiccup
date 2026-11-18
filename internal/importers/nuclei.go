// Package importers turns other tools' findings into backend issues.
package importers

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/infinite-omicron/hiccup/internal/backend"
)

// nucleiResult is the subset of `nuclei -jsonl` output we use.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation"`
		Reference   []string `json:"reference"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	CurlCommand      string   `json:"curl-command"`
}

// NucleiSeverity maps nuclei severities to Burp's (Burp has no "critical").
func NucleiSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFORMATION"
	}
}

// Nuclei reads JSONL from r. Lines that aren't results (blank, banners) are skipped.
func Nuclei(r io.Reader) ([]backend.Issue, error) {
	var issues []backend.Issue
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var res nucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if res.TemplateID == "" {
			continue
		}
		issues = append(issues, nucleiIssue(res))
	}
	return issues, sc.Err()
}

func nucleiIssue(r nucleiResult) backend.Issue {
	target := issueURL(r.MatchedAt, r.Host)
	name := r.Info.Name
	if name == "" {
		name = r.TemplateID
	}
	if r.MatcherName != "" {
		name += " (" + r.MatcherName + ")"
	}

	var d strings.Builder
	fmt.Fprintf(&d, "<p>Reported by <b>nuclei</b> template <code>%s</code> (%s severity).</p>",
		html.EscapeString(r.TemplateID), html.EscapeString(strings.ToLower(r.Info.Severity)))
	if r.Info.Description != "" {
		fmt.Fprintf(&d, "<p>%s</p>", html.EscapeString(r.Info.Description))
	}
	fmt.Fprintf(&d, "<p>Matched at: <code>%s</code></p>", html.EscapeString(r.MatchedAt))
	if len(r.ExtractedResults) > 0 {
		d.WriteString("<p>Extracted:</p><ul>")
		for _, x := range r.ExtractedResults {
			fmt.Fprintf(&d, "<li><code>%s</code></li>", html.EscapeString(x))
		}
		d.WriteString("</ul>")
	}
	if len(r.Info.Reference) > 0 {
		d.WriteString("<p>References:</p><ul>")
		for _, ref := range r.Info.Reference {
			fmt.Fprintf(&d, "<li>%s</li>", html.EscapeString(ref))
		}
		d.WriteString("</ul>")
	}
	if r.CurlCommand != "" {
		fmt.Fprintf(&d, "<p>Reproduce:</p><pre>%s</pre>", html.EscapeString(r.CurlCommand))
	}

	is := backend.Issue{
		Name:        "[nuclei] " + name,
		URL:         target,
		Severity:    NucleiSeverity(r.Info.Severity),
		Confidence:  "FIRM",
		Detail:      d.String(),
		Remediation: html.EscapeString(r.Info.Remediation),
	}
	if r.Request != "" && strings.HasPrefix(target, "http") {
		ev := backend.Evidence{URL: target, RequestB64: b64(crlf(r.Request))}
		if r.Response != "" {
			ev.ResponseB64 = b64(crlf(r.Response))
		}
		is.Evidence = []backend.Evidence{ev}
	}
	return is
}

// issueURL makes an http(s) URL from nuclei's matched-at, which may be a bare
// host:port for network, DNS or SSL templates.
func issueURL(matchedAt, host string) string {
	for _, s := range []string{matchedAt, host} {
		if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			return s
		}
	}
	s := matchedAt
	if s == "" {
		s = host
	}
	if h, port, err := net.SplitHostPort(s); err == nil {
		switch port {
		case "443":
			return "https://" + h + "/"
		case "80":
			return "http://" + h + "/"
		default:
			return "https://" + net.JoinHostPort(h, port) + "/"
		}
	}
	return "https://" + strings.TrimSuffix(s, "/") + "/"
}

// crlf normalizes the head of an HTTP message to CRLF line endings.
func crlf(msg string) string {
	if strings.Contains(msg, "\r\n") {
		return msg
	}
	head, body, found := strings.Cut(msg, "\n\n")
	head = strings.ReplaceAll(head, "\n", "\r\n")
	if !found {
		return head + "\r\n\r\n"
	}
	return head + "\r\n\r\n" + body
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
