package authmatrix

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/session"
)

func TestTemplate(t *testing.T) {
	cases := []struct {
		in, want string
		ref      bool
	}{
		{"https://a.test/documents/42", "/documents/${document_id}", true},
		{"https://a.test/upload/report.pdf", "/upload/${upload_name}", true},
		{"https://a.test/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/files", "/users/${user_id}/files", true},
		{"https://a.test/categories/7", "/categories/${category_id}", true},
		{"https://a.test/admin/users", "/admin/users", false},
		{"https://a.test/", "/", false},
		{"https://a.test/search?q=shoes&page=2", "/search?page=${page}&q=${q}", true},
		{"https://a.test/app.js", "/app.js", false},
	}
	for _, c := range cases {
		got, ref := Template(c.in)
		if got != c.want || ref != c.ref {
			t.Errorf("Template(%q) = %q, %v; want %q, %v", c.in, got, ref, c.want, c.ref)
		}
	}
}

func intp(i int) *int { return &i }

func TestBuild(t *testing.T) {
	items := []proxy.Summary{
		{ID: 1, Method: "GET", URL: "http://a.test/login"}, // before first mark
		{ID: 3, Method: "GET", URL: "http://a.test/dashboard", Status: intp(200)},
		{ID: 4, Method: "GET", URL: "http://a.test/static/app.js"}, // static
		{ID: 5, Method: "GET", URL: "http://a.test/logo", MIME: "IMAGE_PNG"},
		{ID: 6, Method: "GET", URL: "http://other.test/x"}, // out of scope
		{ID: 8, Method: "GET", URL: "http://a.test/documents/1"},
		{ID: 9, Method: "GET", URL: "http://a.test/documents/2"}, // same template, dropped
		{ID: 10, Method: "GET", URL: "http://a.test/logout"},     // excluded
		{ID: 11, Method: "POST", URL: "http://a.test/documents/1"},
	}
	marks := []Mark{{"Dashboard", 2}, {"My Document", 7}}
	acts := Build(items, marks, Filter{Hosts: []string{"a.test"}, Exclude: []*regexp.Regexp{DefaultExclude}})
	if len(acts) != 2 || acts[0].Name != "Dashboard" || len(acts[0].Requests) != 1 {
		t.Fatalf("actions: %+v", acts)
	}
	doc := acts[1]
	if len(doc.Requests) != 2 || doc.Requests[0].Key() != "GET /documents/${document_id}" || doc.Requests[1].Method != "POST" {
		t.Errorf("document action: %+v", doc)
	}
}

func obs(status int, loc, body string) Observation {
	return Observation{Status: status, Location: loc, Body: []byte(body)}
}

func TestClassify(t *testing.T) {
	owner := obs(200, "", "<h1>Document</h1><p>user1 quarterly report</p><p>owner user1</p>")
	cases := []struct {
		o    Observation
		want string
	}{
		{obs(403, "", "no"), Denied},
		{obs(302, "/login", ""), Denied},
		{obs(302, "/elsewhere", ""), Differs},
		{obs(404, "", ""), Denied},
		{obs(500, "", ""), Error},
		{obs(200, "", `<form><input type="password"></form>`), Denied},
		{obs(200, "", "<h1>Document</h1><p>user1 quarterly report</p><p>owner user1</p>"), Allowed},
		{obs(200, "", "<h1>Welcome</h1><p>totally different page here</p>"), Differs},
	}
	for i, c := range cases {
		if got, why := Classify(c.o, owner, "/login"); got != c.want {
			t.Errorf("case %d: %s (%s), want %s", i, got, why, c.want)
		}
	}
	o := Observe([]byte("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"))
	if o.Status != 302 || o.Location != "/login" {
		t.Errorf("Observe: %+v", o)
	}
}

func TestExpectAndFinding(t *testing.T) {
	admin := Account{Name: "admin1", Role: "admin", Level: 100}
	u1 := Account{Name: "user1", Role: "user", Level: 10}
	u2 := Account{Name: "user2", Role: "user", Level: 10}
	anon := Account{Name: "anon", Role: "anonymous", Anonymous: true}
	adminPage := RecordedRequest{Method: "GET", Template: "/admin/users"}
	sharedPage := RecordedRequest{Method: "GET", Template: "/documents"}
	doc := RecordedRequest{Method: "GET", Template: "/documents/${document_id}", ObjectRef: true}
	known := map[string]int{adminPage.Key(): 100, sharedPage.Key(): 10}

	check := func(a, rec Account, r RecordedRequest, o Overrides, wantAllow bool, verdict, wantFinding string) {
		t.Helper()
		allow, why := Expect(a, rec, "act", r, known, o)
		if allow != wantAllow {
			t.Errorf("%s replaying %s's %s: allow=%v (%s), want %v", a.Name, rec.Name, r.Key(), allow, why, wantAllow)
		}
		if f := Finding(a, rec, allow, verdict); f != wantFinding {
			t.Errorf("%s replaying %s's %s (%s): finding %q, want %q", a.Name, rec.Name, r.Key(), verdict, f, wantFinding)
		}
	}
	check(admin, admin, adminPage, nil, true, Allowed, "")
	check(u1, admin, adminPage, nil, false, Allowed, "vertical")
	check(u1, admin, adminPage, nil, false, Denied, "")
	check(u1, admin, sharedPage, nil, true, Allowed, "") // a user recorded it too
	check(anon, admin, sharedPage, nil, false, Allowed, "forceful-browsing")
	check(u2, u1, doc, nil, false, Allowed, "horizontal") // IDOR
	check(admin, u1, doc, nil, true, Allowed, "")         // admins may read users' objects
	check(u1, admin, adminPage, nil, false, Differs, "review")
	check(u1, admin, adminPage, Overrides{"act": {"user": "allow"}}, true, Allowed, "")
	check(u2, u1, doc, Overrides{"*": {"user2": "allow"}}, true, Allowed, "")
}

// fakeProxy serves canned responses keyed by the Cookie header.
type fakeProxy struct {
	proxy.Proxy
	history map[int]string
	respond func(raw string) string
}

func (f *fakeProxy) HistoryItem(_ context.Context, id int) (*proxy.Exchange, error) {
	return &proxy.Exchange{ID: id, RequestB64: base64.StdEncoding.EncodeToString([]byte(f.history[id]))}, nil
}

func (f *fakeProxy) Send(_ context.Context, reqs []proxy.Request) ([]proxy.Exchange, error) {
	out := make([]proxy.Exchange, len(reqs))
	for i, r := range reqs {
		raw, _ := base64.StdEncoding.DecodeString(r.RawB64)
		out[i] = proxy.Exchange{RequestB64: r.RawB64, ResponseB64: base64.StdEncoding.EncodeToString([]byte(f.respond(string(raw))))}
	}
	return out, nil
}

func TestRunAndExport(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	page := func(body string) string { return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body }
	f := &fakeProxy{
		history: map[int]string{
			1: "GET /admin/users HTTP/1.1\r\nHost: a.test\r\nCookie: s=admin\r\n\r\n",
			2: "GET /documents/1 HTTP/1.1\r\nHost: a.test\r\nCookie: s=u1\r\n\r\n",
			3: "POST /documents/1/delete HTTP/1.1\r\nHost: a.test\r\nCookie: s=u1\r\n\r\n",
		},
		respond: func(raw string) string {
			who := ""
			if _, c, ok := strings.Cut(raw, "Cookie: s="); ok {
				who, _, _ = strings.Cut(c, "\r\n")
			}
			switch {
			case who == "":
				return "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
			case strings.HasPrefix(raw, "GET /admin/users"): // bug: any logged-in user
				return page("<ul><li>admin1</li><li>user1</li><li>user2</li></ul>")
			default: // bug: no ownership check on documents
				return page("<p>user1 quarterly report</p>")
			}
		},
	}
	accts := []Account{{"admin1", "admin", 100, false}, {"user1", "user", 10, false}, {"user2", "user", 10, false}, {"anon", "anonymous", 0, true}}
	sess := func(name, v string) *session.Session {
		return &session.Session{Account: name, Cookies: []session.Cookie{{Name: "s", Value: v}}}
	}
	m, err := Run(context.Background(), f, RunOptions{
		Site:     "t",
		Accounts: accts,
		Sessions: map[string]*session.Session{"admin1": sess("admin1", "admin"), "user1": sess("user1", "u1"), "user2": sess("user2", "u2")},
		Recordings: []*Recording{
			{Account: "admin1", Role: "admin", Level: 100, Actions: []Action{{Name: "Users", Requests: []RecordedRequest{{ID: 1, Method: "GET", URL: "http://a.test/admin/users", Template: "/admin/users"}}}}},
			{Account: "user1", Role: "user", Level: 10, Actions: []Action{{Name: "My Document", Requests: []RecordedRequest{
				{ID: 2, Method: "GET", URL: "http://a.test/documents/1", Template: "/documents/${document_id}", ObjectRef: true},
				{ID: 3, Method: "POST", URL: "http://a.test/documents/1/delete", Template: "/documents/${document_id}/delete", ObjectRef: true},
			}}}},
		},
		LoginPath:   "/login",
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, fr := range m.Findings(true) {
		got[fr.Cell.Account+" "+fr.Request.Key()] = fr.Cell.Finding
	}
	want := map[string]string{
		"user1 GET /admin/users":              "vertical",
		"user2 GET /admin/users":              "vertical",
		"user2 GET /documents/${document_id}": "horizontal",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("findings %v\nwant     %v", got, want)
	}
	for _, c := range m.Actions[1].Requests[1].Cells {
		if c.Verdict != Skipped {
			t.Errorf("POST should be skipped without --unsafe: %+v", c)
		}
	}
	if issues := m.Issues(); len(issues) != 3 || len(issues[0].Evidence) != 2 {
		t.Errorf("issues: %d (%+v)", len(issues), issues)
	}

	// xlsx into a workbook laid out like the Checklist "Auth Matrix" tab.
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "Checklist.xlsx")
	wb := excelize.NewFile()
	_, _ = wb.NewSheet("Check List")
	_ = wb.SetSheetName("Sheet1", "Auth Matrix")
	_ = wb.SetCellValue("Auth Matrix", "B1", "Action:")
	_ = wb.SetCellValue("Auth Matrix", "C2", "Exp?")
	_ = wb.SetCellValue("Auth Matrix", "D2", "Actual")
	_ = wb.SetCellValue("Auth Matrix", "A3", "Account")
	if err := wb.SaveAs(tmpl); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.xlsx")
	if err := m.WriteXLSX(out, XLSXOptions{Template: tmpl}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("workbook mode: %v %v", fi.Mode().Perm(), err)
	}
	x, err := excelize.OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	cell := func(c string) string { v, _ := x.GetCellValue("Auth Matrix", c); return v }
	// Block 1 (Users): rows 1-7; a blank row 8; block 2 (My Document) from row 9.
	for c, want := range map[string]string{
		"B1": "Action:", "C1": "Users", "C2": "Exp?", "D2": "Actual", "A3": "Account",
		"A4": "admin1", "A5": "user1", "A7": "anon", "A8": "",
		"B9": "Action:", "C9": "My Document", "A11": "Account", "A12": "admin1",
		"E1": "", "E5": "",
	} {
		if got := cell(c); got != want {
			t.Errorf("%s = %q, want %q", c, got, want)
		}
	}
	if d5 := cell("D5"); !strings.Contains(d5, "VERTICAL") || !strings.HasPrefix(cell("C5"), "deny: GET /admin/users") {
		t.Errorf("user1 × Users: C5=%q D5=%q", cell("C5"), d5)
	}
	if sheets := x.GetSheetList(); len(sheets) != 2 {
		t.Errorf("other sheets of the template should be kept: %v", sheets)
	}

	var csvBuf bytes.Buffer
	if err := m.WriteCSV(&csvBuf); err != nil || strings.Count(csvBuf.String(), "\n") != 1+3*4 {
		t.Errorf("csv rows: %d %v", strings.Count(csvBuf.String(), "\n"), err)
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct{ parent, child, want []string }{
		{nil, []string{"Content", "Scheduled content"}, []string{"Content", "Scheduled content"}},
		{[]string{"Content"}, []string{"Scheduled content"}, []string{"Content", "Scheduled content"}},
		{[]string{"Content"}, []string{"Content", "Scheduled content"}, []string{"Content", "Scheduled content"}},
		{[]string{"Manage", "Content"}, []string{"Manage", "Content", "Comments"}, []string{"Manage", "Content", "Comments"}},
		{[]string{"Flush all caches"}, []string{"flush all caches", "Flush CSS and JavaScript"}, []string{"Flush all caches", "Flush CSS and JavaScript"}},
		{[]string{"Documents"}, []string{"Admin", "Users"}, []string{"Documents", "Admin", "Users"}},
	}
	for _, c := range cases {
		if got := JoinPath(c.parent, c.child); !slices.Equal(got, c.want) {
			t.Errorf("JoinPath(%q, %q) = %q, want %q", c.parent, c.child, got, c.want)
		}
	}
	if got := ActionName([]string{"Content", "Scheduled content"}); got != "Content -> Scheduled content" {
		t.Errorf("ActionName = %q", got)
	}
}
