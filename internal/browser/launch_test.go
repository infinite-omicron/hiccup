package browser

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinite-omicron/hiccup/internal/proxy"
)

func TestLaunchersRejectPerAccountListeners(t *testing.T) {
	l := &Launchers{Prefix: "mitm", Proxy: "127.0.0.1:8082"}
	if _, err := l.Launch(context.Background(), proxy.BrowserOptions{Name: "user1", ProxyPort: 8182}); !errors.Is(err, proxy.ErrUnsupported) {
		t.Errorf("want ErrUnsupported, got %v", err)
	}
	if n := l.launcher("user1").Name; n != "mitm-user1" {
		t.Errorf("launcher name %q", n)
	}
	if n := l.launcher("").Name; n != "mitm" {
		t.Errorf("default launcher name %q", n)
	}
}

func TestDisablePasswordManager(t *testing.T) {
	profile := t.TempDir()
	prefs := filepath.Join(profile, "Default", "Preferences")
	_ = os.MkdirAll(filepath.Dir(prefs), 0o700)
	_ = os.WriteFile(prefs, []byte(`{"profile":{"name":"Person 1"},"other":1}`), 0o600)
	if err := DisablePasswordManager(profile); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	b, _ := os.ReadFile(prefs)
	_ = json.Unmarshal(b, &got)
	prof := got["profile"].(map[string]any)
	if got["credentials_enable_service"] != false || prof["password_manager_leak_detection"] != false ||
		prof["password_manager_enabled"] != false || prof["name"] != "Person 1" || got["other"] != float64(1) {
		t.Errorf("prefs: %v", got)
	}
}
