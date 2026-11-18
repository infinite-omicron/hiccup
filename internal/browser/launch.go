package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
)

// Launcher starts a local Chromium-family browser proxied through a proxy
// that has no browser of its own (ZAP, mitmproxy). State lives in
// $HICCUP_HOME/browser-<name>.json so later CLI runs can find the browser.
type Launcher struct {
	Name  string // proxy name, keeps profiles and state apart
	Proxy string // host:port of the proxy's listener
}

type launchState struct {
	PID   int    `json:"pid"`
	CDP   string `json:"cdp"`
	WS    string `json:"ws"`
	Token string `json:"token,omitempty"`
}

func (l *Launcher) statePath() string {
	return filepath.Join(config.Home(), "browser-"+l.Name+".json")
}

var devtoolsRe = regexp.MustCompile(`DevTools listening on (ws://\S+)(?: with token (\S+))?`)

// FindChrome returns the first installed Chromium-family browser: $HICCUP_BROWSER,
// then Chrome, Chromium, Edge and Brave in their usual places.
func FindChrome() (string, error) {
	if p := os.Getenv("HICCUP_BROWSER"); p != "" {
		return p, nil
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		for _, app := range []string{"Google Chrome", "Chromium", "Microsoft Edge", "Brave Browser"} {
			candidates = append(candidates, filepath.Join("/Applications", app+".app", "Contents", "MacOS", app))
			if h, err := os.UserHomeDir(); err == nil {
				candidates = append(candidates, filepath.Join(h, "Applications", app+".app", "Contents", "MacOS", app))
			}
		}
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(base, "Chromium", "Application", "chrome.exe"),
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"))
		}
	default:
		for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
			if p, err := exec.LookPath(n); err == nil {
				candidates = append(candidates, p)
			}
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("no Chrome, Chromium, Edge or Brave found (set HICCUP_BROWSER or pass --binary)")
}

func (l *Launcher) Launch(ctx context.Context, o proxy.BrowserOptions) (*proxy.BrowserStatus, error) {
	if st, _ := l.Status(ctx); st != nil && st.Running {
		return st, nil
	}
	bin := o.Binary
	if bin == "" {
		var err error
		if bin, err = FindChrome(); err != nil {
			return nil, err
		}
	}
	port := o.Port
	if port == 0 {
		port = 9222
	}
	profile := filepath.Join(config.Home(), "browser-profile-"+l.Name)
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return nil, err
	}
	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-debugging-address=127.0.0.1",
		"--remote-allow-origins=*",
		"--user-data-dir=" + profile,
		"--proxy-server=http://" + l.Proxy,
		"--proxy-bypass-list=<-loopback>",
		"--ignore-certificate-errors",
		"--no-first-run", "--no-default-browser-check",
		"--disable-background-networking", "--disable-component-update", "--disable-sync",
	}
	if o.UA != "" {
		args = append(args, "--user-agent="+o.UA)
	}
	if o.Headless {
		args = append(args, "--headless=new")
	}
	url := o.URL
	if url == "" {
		url = "about:blank"
	}
	args = append(args, url)

	logPath := filepath.Join(config.Home(), "browser-"+l.Name+".log")
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	// The DevTools line gives the websocket URL (and a token for Burp's Chromium build).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(logPath); len(b) > 0 {
			if m := devtoolsRe.FindSubmatch(b); m != nil {
				st := launchState{PID: pid, CDP: fmt.Sprintf("http://127.0.0.1:%d", port), WS: string(m[1]), Token: string(m[2])}
				if err := writeState(l.statePath(), st); err != nil {
					return nil, err
				}
				return &proxy.BrowserStatus{Running: true, PID: pid, CDP: st.CDP, WS: st.WS, Token: st.Token}, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("browser started (pid %d) but never reported its DevTools address; see %s", pid, logPath)
}

func (l *Launcher) Status(_ context.Context) (*proxy.BrowserStatus, error) {
	var st launchState
	b, err := os.ReadFile(l.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return &proxy.BrowserStatus{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if !alive(st.PID) {
		_ = os.Remove(l.statePath())
		return &proxy.BrowserStatus{}, nil
	}
	return &proxy.BrowserStatus{Running: true, PID: st.PID, CDP: st.CDP, WS: st.WS, Token: st.Token}, nil
}

func (l *Launcher) Stop(ctx context.Context) (*proxy.BrowserStatus, error) {
	st, err := l.Status(ctx)
	if err != nil {
		return nil, err
	}
	if st.Running {
		kill(st.PID)
	}
	_ = os.Remove(l.statePath())
	return &proxy.BrowserStatus{}, nil
}

func writeState(path string, st launchState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
