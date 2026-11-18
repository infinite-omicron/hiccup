// Package mitm drives mitmproxy through the hiccup addon (hiccup_mitm.py),
// which serves the same REST API as the Burp extension. mitmproxy has no
// browser of its own, so the browser is launched locally.
package mitm

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/proxy/burp"
)

//go:embed hiccup_mitm.py
var Addon []byte

// AddonPath writes the embedded addon to $HICCUP_HOME/mitm/hiccup_mitm.py and returns its path.
func AddonPath() (string, error) {
	p := filepath.Join(config.Home(), "mitm", "hiccup_mitm.py")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, Addon, 0o600)
}

// RuntimePath is where the addon writes its URL and token.
func RuntimePath() string { return filepath.Join(config.Home(), "mitm.json") }

type Client struct {
	*burp.Client
	browser *browser.Launcher
}

var _ proxy.Proxy = (*Client)(nil)

// New connects to the addon's API; listener is mitmproxy's proxy address.
func New(url, token, listener string) *Client {
	return &Client{Client: burp.New(url, token), browser: &browser.Launcher{Name: "mitm", Proxy: listener}}
}

func (c *Client) BrowserLaunch(ctx context.Context, o proxy.BrowserOptions) (*proxy.BrowserStatus, error) {
	return c.browser.Launch(ctx, o)
}

func (c *Client) BrowserStatus(ctx context.Context) (*proxy.BrowserStatus, error) {
	return c.browser.Status(ctx)
}

func (c *Client) BrowserStop(ctx context.Context) (*proxy.BrowserStatus, error) {
	return c.browser.Stop(ctx)
}
