// Package mitm drives mitmproxy through the hiccup addon (hiccup_mitm.py),
// which serves the same REST API as the Burp extension. mitmproxy has no
// browser of its own, so the browser is launched locally.
package mitm

import (
	"context"
	_ "embed"
	"fmt"
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
	browsers *browser.Launchers
}

var _ proxy.Proxy = (*Client)(nil)

// New connects to the addon's API; listener is mitmproxy's proxy address.
func New(url, token, listener string) *Client {
	return &Client{Client: burp.New(url, token), browsers: &browser.Launchers{Prefix: "mitm", Proxy: listener}}
}

func (c *Client) BrowserLaunch(ctx context.Context, o proxy.BrowserOptions) (*proxy.BrowserStatus, error) {
	return c.browsers.Launch(ctx, o)
}

func (c *Client) BrowserStatus(ctx context.Context, name string) (*proxy.BrowserStatus, error) {
	return c.browsers.Status(ctx, name)
}

func (c *Client) BrowserStop(ctx context.Context, name string) (*proxy.BrowserStatus, error) {
	return c.browsers.Stop(ctx, name)
}

func (c *Client) Browsers(ctx context.Context) ([]proxy.BrowserStatus, error) { return c.browsers.All(ctx) }

func (c *Client) Listeners(context.Context) ([]proxy.Listener, error) {
	return nil, fmt.Errorf("mitmproxy: per-account listeners: %w", proxy.ErrUnsupported)
}

func (c *Client) AddListeners(context.Context, []int) ([]proxy.Listener, error) {
	return nil, fmt.Errorf("mitmproxy: per-account listeners: %w", proxy.ErrUnsupported)
}

func (c *Client) RemoveListeners(context.Context, []int) ([]proxy.Listener, error) {
	return nil, fmt.Errorf("mitmproxy: per-account listeners: %w", proxy.ErrUnsupported)
}
