// Package browser drives the Burp-launched Chromium over CDP.
package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// Session is a CDP attachment to one page target.
type Session struct {
	Ctx context.Context
	// root is the browser-level connection; contextID the tab's browser
	// context ("" for the default one). Both survive the tab being swapped.
	root      context.Context
	contextID cdp.BrowserContextID
	// cancels run in reverse on Close: re-attachments first, then the original
	// tab (which disposes an isolated browser context), then the connection.
	cancels []func()
}

// Close detaches from the tab, leaving the tab and the browser open, except
// for an isolated tab, which is closed with its browser context.
func (s *Session) Close() {
	for i := len(s.cancels) - 1; i >= 0; i-- {
		s.cancels[i]()
	}
}

// reattach finds the page in this session's browser context again after the
// browser detached it (for example when a navigation swaps the page's
// target, or its window was closed) and continues on it.
func (s *Session) reattach() error {
	targets, err := chromedp.Targets(s.root)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.Type != "page" || (s.contextID != "" && t.BrowserContextID != s.contextID) {
			continue
		}
		tab, cancel := chromedp.NewContext(s.root, chromedp.WithTargetID(t.TargetID), chromedp.WithDetachOnCancel())
		if err := chromedp.Do(tab); err != nil {
			cancel()
			continue
		}
		s.Ctx = tab
		s.cancels = append(s.cancels, cancel)
		return nil
	}
	return errors.New("no page left in the browser context (was its window closed?)")
}

// AuthHeader is the header Burp's Chromium build checks on its DevTools HTTP endpoints.
const AuthHeader = "x-burp-authorization"

// Endpoint locates a browser's DevTools. WS is preferred; HTTP is used to look
// the websocket URL up when WS is empty.
type Endpoint struct {
	HTTP  string
	WS    string
	Token string
}

// AttachOptions choose the tab a Session drives.
type AttachOptions struct {
	// NewTab opens a new tab instead of attaching to the first page tab.
	NewTab bool
	// Isolated opens a new tab in a fresh browser context (its own cookies and
	// storage), disposed when the Session closes. Use it to log several
	// accounts in without them sharing a session.
	Isolated bool
}

// Attach connects to the browser and attaches to the first page tab, or opens
// a new tab per opts. Closing the Session detaches and leaves the tab open,
// except for an isolated tab, which is closed with its browser context.
func Attach(ctx context.Context, ep Endpoint, opts AttachOptions) (*Session, error) {
	h := http.Header{}
	if ep.Token != "" {
		h.Set(AuthHeader, ep.Token)
	}
	cdpURL, ropts := ep.HTTP, []remote.Option{remote.WithDialHTTPHeader(h)}
	if ep.WS != "" {
		cdpURL, ropts = ep.WS, append(ropts, remote.NoModifyURL)
	}
	alloc, cancelAlloc := remote.NewAllocator(ctx, cdpURL, ropts...)
	root, cancelRoot := chromedp.NewContext(alloc)
	cancel := func() { cancelRoot(); cancelAlloc() }

	targets, err := chromedp.Targets(root)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("cdp %s: %w", cdpURL, err)
	}
	var tabOpts []chromedp.ContextOption
	switch {
	case opts.Isolated:
		tabOpts = append(tabOpts, chromedp.WithNewBrowserContext())
	default:
		tabOpts = append(tabOpts, chromedp.WithDetachOnCancel())
	}
	if !opts.NewTab && !opts.Isolated {
		for _, t := range targets {
			if t.Type == "page" {
				tabOpts = append(tabOpts, chromedp.WithTargetID(t.TargetID))
				break
			}
		}
	}
	tab, cancelTab := chromedp.NewContext(root, tabOpts...)
	if err := chromedp.Do(tab); err != nil {
		cancelTab()
		cancel()
		return nil, err
	}
	s := &Session{Ctx: tab, root: root, cancels: []func(){cancel, cancelTab}}
	if c := chromedp.FromContext(tab); c != nil {
		s.contextID = c.BrowserContextID
	}
	return s, nil
}

// OverrideUA applies a UA plus matching client-hint metadata to this tab, so
// navigator.userAgent, navigator.userAgentData and Sec-CH-UA* agree. The
// override lasts while this session is attached.
func (s *Session) OverrideUA(ua string) error {
	if ua == "" {
		return nil
	}
	p := emulation.SetUserAgentOverrideParams{UserAgent: ua}
	if md := Metadata(ua); md != nil {
		p.UserAgentMetadata = md
		p.Platform = navigatorPlatform(md.Platform)
	}
	_, err := chromedp.Call(s.Ctx, emulation.SetUserAgentOverride, p)
	return err
}

func (s *Session) Navigate(url string, timeout time.Duration) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(s.Ctx, timeout)
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Navigate(url), chromedp.WaitReady(chromedp.CSS("body"))); err != nil {
		return nil, err
	}
	return s.Info()
}

func (s *Session) Eval(js string) (json.RawMessage, error) {
	return chromedp.Run(s.Ctx, chromedp.Evaluate[json.RawMessage](js, chromedp.EvalAwaitPromise))
}

func (s *Session) Screenshot(quality int) ([]byte, error) {
	return chromedp.Run(s.Ctx, chromedp.FullScreenshot(quality))
}

func (s *Session) HTML() (string, error) {
	return chromedp.Run(s.Ctx, chromedp.OuterHTML(chromedp.CSS("html")))
}

func (s *Session) Info() (map[string]string, error) {
	loc, err := chromedp.Run(s.Ctx, chromedp.Location())
	if err != nil {
		return nil, err
	}
	title, err := chromedp.Run(s.Ctx, chromedp.Title())
	return map[string]string{"url": loc, "title": title}, err
}
