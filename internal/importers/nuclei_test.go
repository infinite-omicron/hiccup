package importers

import (
	"encoding/base64"
	"strings"
	"testing"
)

const sample = `[INF] banner line that is not JSON
{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info"},"type":"http","host":"https://example.com","matched-at":"https://example.com/","matcher-name":"nginx","request":"GET / HTTP/1.1\nHost: example.com\n\n","response":"HTTP/1.1 200 OK\nServer: nginx\n\nhello"}
{"template-id":"CVE-2021-0000","info":{"name":"Bad Thing","severity":"critical","description":"desc <b>","remediation":"patch","reference":["https://ref"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/admin","extracted-results":["secret"]}
{"template-id":"weak-cipher-suites","info":{"name":"Weak Ciphers","severity":"low"},"type":"ssl","host":"example.com","matched-at":"example.com:443"}

`

func TestNuclei(t *testing.T) {
	issues, err := Nuclei(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 3 {
		t.Fatalf("got %d issues, want 3", len(issues))
	}

	tech := issues[0]
	if tech.Name != "[nuclei] Wappalyzer Technology Detection (nginx)" || tech.Severity != "INFORMATION" {
		t.Errorf("tech: %+v", tech)
	}
	if len(tech.Evidence) != 1 {
		t.Fatalf("tech evidence: %+v", tech.Evidence)
	}
	req, _ := base64.StdEncoding.DecodeString(tech.Evidence[0].RequestB64)
	if string(req) != "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" {
		t.Errorf("request not CRLF-normalized: %q", req)
	}

	cve := issues[1]
	if cve.Severity != "HIGH" || cve.URL != "https://example.com/admin" || cve.Evidence != nil {
		t.Errorf("cve: %+v", cve)
	}
	if !strings.Contains(cve.Detail, "desc &lt;b&gt;") || !strings.Contains(cve.Detail, "<code>secret</code>") {
		t.Errorf("detail not escaped or missing extracted results: %s", cve.Detail)
	}

	if ssl := issues[2]; ssl.URL != "https://example.com/" || ssl.Severity != "LOW" {
		t.Errorf("ssl: %+v", ssl)
	}
}

func TestIssueURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.test/x": "https://a.test/x",
		"a.test:80":        "http://a.test/",
		"a.test:8443":      "https://a.test:8443/",
		"a.test":           "https://a.test/",
	} {
		if got := issueURL(in, ""); got != want {
			t.Errorf("issueURL(%q) = %q, want %q", in, got, want)
		}
	}
}
