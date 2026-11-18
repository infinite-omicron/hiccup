package bapp

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const uuid = "f9bbac8c4acf4aefa4d7dc92a991af2f"

func bappZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func store(t *testing.T, archive []byte) *httptest.Server {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bappstore":
			fmt.Fprintf(w, `<a href="/bappstore/%s">Autorize</a><a href="/bappstore/0123456789abcdef0123456789abcdef">Auth Analyzer</a><a href="/bappstore/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">Active Scan&#x2B;&#x2B;</a>`, uuid)
		case "/bappstore/" + uuid:
			fmt.Fprintf(w, `<a id="DownloadedLink" href="https://portswigger.net/bappstore/bapps/download/%s/36">Download BApp</a>`, uuid)
		case "/bappstore/bapps/download/" + uuid + "/36":
			hits++
			if hits > 1 {
				t.Error("archive downloaded twice")
			}
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	StoreURL = srv.URL + "/bappstore"
	return srv
}

func TestIndexFindDownload(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	store(t, bappZip(t, map[string]string{
		"BappManifest.bmf": "Uuid: " + uuid + "\nExtensionType: 2\nName: Autorize\nSerialVersion: 36\nProOnly: False\nEntryPoint: Autorize.py\n",
		"Autorize.py":      "# entry",
		"gui/tab.py":       "# module",
	}))
	ctx := context.Background()
	entries, err := Index(ctx, false)
	if err != nil || len(entries) != 3 || entries[0].Name != "Active Scan++" {
		t.Fatalf("index: %v %v", entries, err)
	}
	if _, err := Find(entries, "aut"); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("ambiguous name should fail: %v", err)
	}
	e, err := Find(entries, "autorize")
	if err != nil || e.UUID != uuid {
		t.Fatalf("find: %v %v", e, err)
	}
	d, err := Download(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if d.Type() != "python" || d.Name != "Autorize" || filepath.Base(d.Entry) != "Autorize.py" || d.ProOnly {
		t.Errorf("downloaded: %+v", d)
	}
	if _, err := os.Stat(filepath.Join(d.Dir, "gui", "tab.py")); err != nil {
		t.Error("package files not extracted")
	}
	if _, err := Download(ctx, e); err != nil { // cached: no second archive fetch
		t.Fatal(err)
	}
}

func TestUnzipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.bapp")
	if err := os.WriteFile(archive, bappZip(t, map[string]string{"../../escape.txt": "x"}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unzip(archive, filepath.Join(dir, "out")); err == nil {
		t.Error("zip slip entry should be rejected")
	}
}

func TestMavenJar(t *testing.T) {
	t.Setenv("HICCUP_HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/org/python/jython-standalone/maven-metadata.xml":
			fmt.Fprint(w, "<metadata><versioning><release>2.7.5rc1</release><versions><version>2.7.10</version><version>2.7.4</version><version>2.7.5rc1</version><version>3.0.0-SNAPSHOT</version></versions></versioning></metadata>")
		case "/org/python/jython-standalone/2.7.10/jython-standalone-2.7.10.jar":
			fmt.Fprint(w, "jar")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	MavenURL = srv.URL
	p, err := MavenJar(context.Background(), "org.python", "jython-standalone", "jython")
	if err != nil || filepath.Base(p) != "jython-standalone-2.7.10.jar" {
		t.Fatalf("%s %v", p, err)
	}
}
