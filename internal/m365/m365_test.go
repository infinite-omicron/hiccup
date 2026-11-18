package m365

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareID(t *testing.T) {
	u := "https://contoso.sharepoint.com/sites/Pentest/Shared Documents/acme"
	id := shareID(u)
	if !strings.HasPrefix(id, "u!") || strings.ContainsAny(id, "=+/") {
		t.Fatalf("share id %q", id)
	}
	dec, err := base64.RawURLEncoding.DecodeString(id[2:])
	if err != nil || string(dec) != u {
		t.Errorf("round trip: %q %v", dec, err)
	}
}

func TestUpload(t *testing.T) {
	var puts []string
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/shares/"):
			dec, _ := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/shares/u!"), "/driveItem"))
			if strings.HasSuffix(string(dec), ".xlsx") {
				io.WriteString(w, `{"id":"FILE1","name":"matrix.xlsx","parentReference":{"driveId":"b!drive"}}`)
			} else {
				io.WriteString(w, `{"id":"FOLDER1","name":"acme","folder":{"childCount":3},"parentReference":{"driveId":"b!drive"}}`)
			}
		case r.Method == "PUT":
			b, _ := io.ReadAll(r.Body)
			puts = append(puts, r.URL.EscapedPath())
			bodies = append(bodies, string(b))
			if r.Header.Get("Content-Type") != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
				t.Errorf("content type %q", r.Header.Get("Content-Type"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "acme-auth-matrix.xlsx", "webUrl": "https://contoso.sharepoint.com/x", "size": len(b)})
		default:
			http.Error(w, `{"error":{"code":"itemNotFound","message":"nope"}}`, 404)
		}
	}))
	defer srv.Close()
	GraphURL = srv.URL

	local := filepath.Join(t.TempDir(), "acme-auth-matrix.xlsx")
	if err := os.WriteFile(local, []byte("xlsx-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, target := range []string{
		"onedrive:/Pentests/Acme Corp/matrix.xlsx",
		"onedrive:/Pentests/",
		"https://contoso.sharepoint.com/sites/Pentest/Shared%20Documents/acme",
		"https://contoso.sharepoint.com/sites/Pentest/Shared%20Documents/acme/matrix.xlsx",
	} {
		item, err := Upload(ctx, srv.Client(), local, target)
		if err != nil || item.WebURL == "" {
			t.Fatalf("%s: %+v %v", target, item, err)
		}
	}
	want := []string{
		"/me/drive/root:/Pentests/Acme%20Corp/matrix.xlsx:/content",
		"/me/drive/root:/Pentests/acme-auth-matrix.xlsx:/content",
		"/drives/b%21drive/items/FOLDER1:/acme-auth-matrix.xlsx:/content",
		"/drives/b%21drive/items/FILE1/content",
	}
	for i := range want {
		if puts[i] != want[i] || bodies[i] != "xlsx-bytes" {
			t.Errorf("put %d: %s (%q), want %s", i, puts[i], bodies[i], want[i])
		}
	}
	if _, err := Upload(ctx, srv.Client(), local, "sharepoint://nope"); err == nil {
		t.Error("bad target should fail")
	}
}

func TestClientNeedsSettingsAndLogin(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	if _, err := Client(context.Background(), Settings{}); err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Errorf("missing client id: %v", err)
	}
	if _, err := Client(context.Background(), Settings{ClientID: "x"}); err == nil || !strings.Contains(err.Error(), "m365 login") {
		t.Errorf("missing token: %v", err)
	}
}

// TestLoginAndClient runs the device-code flow against a fake identity
// platform (pending once, then a token) and uses the saved token on Graph.
func TestLoginAndClient(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/contoso.test/oauth2/v2.0/devicecode":
			if r.Form.Get("client_id") != "app-id" || !strings.Contains(r.Form.Get("scope"), "Files.ReadWrite.All") {
				t.Errorf("devicecode form: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"device_code":"DEV","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","interval":1,"expires_in":60}`)
		case "/contoso.test/oauth2/v2.0/token":
			w.Header().Set("Content-Type", "application/json")
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "DEV" {
				t.Errorf("token form: %v", r.Form)
			}
			if polls++; polls == 1 {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"authorization_pending"}`)
				return
			}
			io.WriteString(w, `{"access_token":"AT","refresh_token":"RT","token_type":"Bearer","expires_in":3600}`)
		case "/me":
			if r.Header.Get("Authorization") != "Bearer AT" {
				http.Error(w, `{"error":{"code":"InvalidAuthenticationToken","message":"no"}}`, 401)
				return
			}
			io.WriteString(w, `{"displayName":"Lucas","userPrincipalName":"lucas@contoso.test"}`)
		case "/me/drive":
			io.WriteString(w, `{"webUrl":"https://contoso-my.sharepoint.com/personal/lucas"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	Authority, GraphURL = srv.URL, srv.URL

	s := Settings{Tenant: "contoso.test", ClientID: "app-id"}
	var shown string
	if err := Login(context.Background(), s, func(u, code string) { shown = u + " " + code }); err != nil {
		t.Fatal(err)
	}
	if shown != "https://microsoft.com/devicelogin ABCD-EFGH" || polls != 2 {
		t.Errorf("shown %q after %d polls", shown, polls)
	}
	if fi, err := os.Stat(tokenPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	c, err := Client(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	me, err := Me(context.Background(), c)
	if err != nil || me["user"] != "lucas@contoso.test" || me["onedrive"] == "" {
		t.Fatalf("me: %v %v", me, err)
	}
	if err := Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := Client(context.Background(), s); err == nil {
		t.Error("client should fail after logout")
	}
}
