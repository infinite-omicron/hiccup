package plextrac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakePlexTrac serves the read endpoints hiccup uses. bare makes it accept
// only the token without "Bearer ".
func fakePlexTrac(t *testing.T, mfa, bare bool) *httptest.Server {
	t.Helper()
	exp := time.Now().Add(15 * time.Minute).Unix()
	jwt := "e30." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp))) + ".sig"
	authed := func(r *http.Request) bool {
		h := r.Header.Get("Authorization")
		if bare {
			return h == jwt
		}
		return h == "Bearer "+jwt
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/authenticate", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["username"] != "tester@example.com" || in["password"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"status":"error","message":"Unauthorized"}`)
			return
		}
		if mfa {
			fmt.Fprint(w, `{"status":"success","tenant_id":7,"mfa_enabled":true,"code":"challenge-1"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","tenant_id":7,"token":%q}`, jwt)
	})
	mux.HandleFunc("POST /api/v1/authenticate/mfa", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["code"] != "challenge-1" || in["token"] != "123456" {
			fmt.Fprint(w, `{"status":"error"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","token":%q}`, jwt)
	})
	mux.HandleFunc("POST /api/v2/repositories/getAllWriteupsRepositories", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data":[{"repositoryId":"r1","name":"Acme WriteupsDB","writeupsCount":3},
			{"repositoryId":"r2","name":"Default Repository","writeupsCount":1},
			{"repositoryId":"r3","name":"Old","isDeleted":true}]}`)
	})
	mux.HandleFunc("GET /api/v1/template/list", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `[
		 {"id":"template_1","doc_id":1,"title":"HSTS Not Enforced","severity":"Low","repositoryId":"r1",
		  "description":"<p>The application does not send <b>Strict-Transport-Security</b>.</p>",
		  "recommendations":"<ul><li>Send the header</li><li>Preload</li></ul>","references":"<a href=\"https://owasp.org/x\">OWASP</a>",
		  "tags":["tls"],"fields":{"f1":{"label":"Impact","value":"Downgrade"},"scores":{"label":"x","value":{}}},
		  "common_identifiers":{"CWE":[{"name":"CWE-319"}]}},
		 {"id":"template_2","doc_id":2,"title":"Weak SSL/TLS Ciphers Supported","severity":"Low","repositoryId":"r1","tags":"tls, ciphers"},
		 {"id":"template_3","doc_id":3,"title":"Broken Access Control - Vertical Privilege Escalation","severity":"High","repositoryId":"r1"},
		 {"id":"template_4","doc_id":4,"title":"Generic Default","repositoryId":"r2"},
		 {"id":"template_5","doc_id":5,"title":"Deleted One","repositoryId":"r1","isDeleted":true}
		]`)
	})
	return httptest.NewServer(mux)
}

func TestLoginWithMFAAndSync(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	srv := fakePlexTrac(t, true, false)
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	s, err := c.Login(context.Background(), "tester@example.com", "pw", func() (string, error) { asked = true; return "123456", nil })
	if err != nil || !asked || !s.Valid() {
		t.Fatalf("login: %v asked=%v session=%+v", err, asked, s)
	}
	if time.Until(s.Expires) < 14*time.Minute {
		t.Errorf("expiry not read from the token: %v", s.Expires)
	}
	if err := c.Current(s).Save(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(os.Getenv("HICCUP_HOME"), "plextrac", "token.json")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode: %v", fi)
	}
	if _, err := LoadSession(srv.URL); err != nil {
		t.Errorf("load session: %v", err)
	}
	if _, err := LoadSession("https://other.example.com"); err != ErrSessionExpired {
		t.Errorf("session for another instance should not load: %v", err)
	}

	lib, err := c.Sync(context.Background(), []string{"acme writeupsdb"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lib.Writeups) != 3 || lib.Writeups[0].Repository != "Acme WriteupsDB" {
		t.Fatalf("sync: %d write-ups %+v", len(lib.Writeups), lib.Writeups)
	}
	hsts := lib.Find("template_1")
	if hsts == nil || hsts.Fields["Impact"] != "Downgrade" || len(hsts.CWE) != 1 || hsts.Fields["x"] != "" {
		t.Errorf("fields: %+v", hsts)
	}
	if w := lib.Find("weak ssl/tls ciphers supported"); w == nil || len(w.Tags) != 2 {
		t.Errorf("find by title / string tags: %+v", w)
	}
	if _, err := c.Sync(context.Background(), []string{"nope"}); err == nil || !strings.Contains(err.Error(), "Acme WriteupsDB") {
		t.Errorf("unknown repository: %v", err)
	}
	all, _ := c.Sync(context.Background(), nil)
	if len(all.Writeups) != 4 {
		t.Errorf("all repositories: %d", len(all.Writeups))
	}
}

func TestLoginErrors(t *testing.T) {
	srv := fakePlexTrac(t, true, false)
	defer srv.Close()
	c, _ := New(srv.URL)
	if _, err := c.Login(context.Background(), "tester@example.com", "bad", nil); err == nil {
		t.Error("bad password accepted")
	}
	if _, err := c.Login(context.Background(), "tester@example.com", "pw", nil); err == nil || !strings.Contains(err.Error(), "MFA") {
		t.Errorf("MFA without a prompt: %v", err)
	}
	if _, err := c.Login(context.Background(), "tester@example.com", "pw", func() (string, error) { return "000000", nil }); err == nil {
		t.Error("wrong MFA code accepted")
	}
	if _, err := New(""); err == nil {
		t.Error("empty URL accepted")
	}
}

func TestBareTokenFallback(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	srv := fakePlexTrac(t, false, true)
	defer srv.Close()
	c, _ := New(srv.URL)
	s, err := c.Login(context.Background(), "tester@example.com", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Repositories(context.Background()); err != nil {
		t.Fatalf("fallback to bare token: %v", err)
	}
	if !c.Current(s).BareToken {
		t.Error("bare token not remembered")
	}
	c2, _ := New(srv.URL)
	c2.Token = "wrong"
	if _, err := c2.Repositories(context.Background()); err != ErrSessionExpired {
		t.Errorf("bad token: %v", err)
	}
}

func testLibrary() *Library {
	return &Library{Writeups: []Writeup{
		{ID: "template_1", Title: "HSTS Not Enforced"},
		{ID: "template_2", Title: "Weak SSL/TLS Ciphers Supported"},
		{ID: "template_3", Title: "Broken Access Control - Vertical Privilege Escalation"},
		{ID: "template_4", Title: "Content Security Policy Weaknesses"},
		{ID: "template_5", Title: "Clickjacking"},
	}}
}

func TestMatch(t *testing.T) {
	lib := testLibrary()
	m := Mapping{"vertical": "Broken Access Control - Vertical Privilege Escalation", "Gone": "template_99"}
	got := lib.MatchAll([]Finding{
		{Name: "Potential Vertical Privilege Escalation", Aliases: []string{"vertical"}},
		{Name: "Strict transport security not enforced"},
		{Name: "weak ssl/tls ciphers supported"},
		{Name: "Content security policy: allows untrusted script execution"},
		{Name: "Robots.txt file"},
		{Name: "Gone"},
		{Name: "Frameable response (potential Clickjacking)"},
	}, m)
	want := []struct{ how, id string }{
		{"mapped", "template_3"}, {"exact", "template_1"}, {"exact", "template_2"},
		{"fuzzy", "template_4"}, {"unmatched", ""}, {"unmatched", ""}, {"fuzzy", "template_5"},
	}
	for i, w := range want {
		id := ""
		if got[i].Writeup != nil {
			id = got[i].Writeup.ID
		}
		if got[i].How != w.how || id != w.id {
			t.Errorf("%q: got %s %s (score %.2f, %+v), want %s %s", got[i].Finding.Name, got[i].How, id, got[i].Score, got[i].Suggestions, w.how, w.id)
		}
	}
	if got[5].Problem == "" {
		t.Error("stale mapping not reported")
	}
	if len(got[4].Suggestions) > 3 {
		t.Error("too many suggestions")
	}
}

func TestMappingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HICCUP_HOME", home)
	if p := MappingPath("acme.json"); p != filepath.Join(home, "plextrac", "acme.json") {
		t.Errorf("relative: %s", p)
	}
	if p := MappingPath(""); filepath.Base(p) != "mapping.json" {
		t.Errorf("default: %s", p)
	}
	if p := MappingPath("/tmp/x.json"); p != "/tmp/x.json" {
		t.Errorf("absolute: %s", p)
	}
	if h, err := os.UserHomeDir(); err == nil {
		if p := MappingPath("~/m.json"); p != filepath.Join(h, "m.json") {
			t.Errorf("tilde: %s", p)
		}
	}
	p := MappingPath("acme.json")
	m, err := LoadMapping(p)
	if err != nil || len(m) != 0 {
		t.Fatalf("missing file: %v %v", m, err)
	}
	m["Robots.txt file"] = "template_9"
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	back, _ := LoadMapping(p)
	if v, ok := back.lookup("robots.TXT  file"); !ok || v != "template_9" {
		t.Errorf("lookup ignoring case/spacing: %v %v", v, ok)
	}
}

func TestText(t *testing.T) {
	in := `<p>Use <b>HSTS</b> &amp; <code>preload</code>.</p><ul><li>One</li><li>Two</li></ul><p>See <a href="https://example.com/a">the guide</a> or <a href="https://example.com/b">https://example.com/b</a>.<br>Done&nbsp;now</p>`
	want := "Use **HSTS** & `preload`.\n\n- One\n- Two\n\nSee [the guide](https://example.com/a) or https://example.com/b.\nDone now"
	if got := Text(in); got != want {
		t.Errorf("Text:\n%q\nwant\n%q", got, want)
	}
	if got := Text("plain &lt;text&gt;"); got != "plain <text>" {
		t.Errorf("plain: %q", got)
	}
	w := &Writeup{ID: "template_1", Title: "HSTS Not Enforced", Severity: "Low", Description: "<p>D</p>", Fields: map[string]string{"Impact": "I"}}
	md := w.Markdown()
	for _, s := range []string{"# HSTS Not Enforced", "**Severity:** Low", "## Description\n\nD", "## Impact\n\nI"} {
		if !strings.Contains(md, s) {
			t.Errorf("markdown missing %q:\n%s", s, md)
		}
	}
}

func TestSearch(t *testing.T) {
	lib := testLibrary()
	if got := lib.Search([]string{"tls", "weak"}, ""); len(got) != 1 || got[0].ID != "template_2" {
		t.Errorf("search: %+v", got)
	}
}
