package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLayers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HICCUP_HOME", home)
	t.Setenv("HICCUP_CONFIG", "")
	t.Setenv("HICCUP_BURP_URL", "")
	t.Setenv("HICCUP_BURP_TOKEN", "")
	t.Setenv("HICCUP_SITE", "")
	t.Setenv("HICCUP_USER_AGENT", "ua-from-env")
	t.Setenv("HICCUP_THROTTLE_RPS", "0.5")

	write(t, filepath.Join(home, "config.json"), `{"burp":{"url":"http://127.0.0.1:1","token":"stale"},
		"sites":{"a":{"base_url":"https://a.test","scope":["https://api.a.test/","https://a.test/x"]}}}`)
	write(t, filepath.Join(home, "burp.json"), `{"url":"http://127.0.0.1:8099","token":"fresh"}`)

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if url, token := c.BurpEndpoint(); c.BackendName() != "burp" || url != "http://127.0.0.1:8099" || token != "fresh" {
		t.Errorf("runtime file should win: %s %s", url, token)
	}
	name, s, err := c.Site("")
	if err != nil || name != "a" {
		t.Fatalf("only site should be the default: %q %v", name, err)
	}
	if th, err := s.EffectiveThrottle(); err != nil || th.RPS != 0.5 || s.EffectiveUserAgent().Value != "ua-from-env" {
		t.Errorf("env overrides not applied: %+v %v", th, err)
	}
	if s.Throttle != nil || s.UserAgent != nil {
		t.Error("env overrides must not leak into the saved config")
	}
	if h := s.Hosts(); len(h) != 2 || h[0] != "a.test" || h[1] != "api.a.test" {
		t.Errorf("hosts: %v", h)
	}

	t.Setenv("HICCUP_BURP_TOKEN", "from-env")
	if _, token := c.BurpEndpoint(); token != "from-env" {
		t.Errorf("env token should win: %q", token)
	}
}

func TestSaveKeepsRuntimeOutAndIsPrivate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HICCUP_HOME", home)
	t.Setenv("HICCUP_CONFIG", "")
	t.Setenv("HICCUP_USER_AGENT", "ua-from-env")
	write(t, filepath.Join(home, "burp.json"), `{"url":"http://127.0.0.1:8099","token":"runtime-token"}`)
	if err := Example().Save(); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"runtime-token", "ua-from-env"} {
		if strings.Contains(string(b), leaked) {
			t.Errorf("%q leaked into the saved config", leaked)
		}
	}
	if fi, _ := os.Stat(Path()); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("config mode %v is not private", fi.Mode().Perm())
	}
}

func TestSiteErrors(t *testing.T) {
	t.Setenv("HICCUP_SITE", "")
	c := &Config{Sites: map[string]*Site{"a": {}, "b": {}}}
	if _, _, err := c.Site(""); err == nil {
		t.Error("ambiguous site should fail")
	}
	if _, _, err := c.Site("zzz"); err == nil {
		t.Error("unknown site should fail")
	}
	t.Setenv("HICCUP_SITE", "b")
	if n, _, err := c.Site(""); err != nil || n != "b" {
		t.Errorf("HICCUP_SITE: %q %v", n, err)
	}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
