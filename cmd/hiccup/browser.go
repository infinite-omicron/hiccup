package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/browser"
)

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check the backend connection and push site throttles/User-Agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			h, err := b.Health(cmd.Context())
			if err != nil {
				return err
			}
			applied, err := a.applySites(cmd.Context(), b)
			if err != nil {
				return err
			}
			br, err := b.BrowserStatus(cmd.Context())
			if err != nil {
				return err
			}
			return a.print(map[string]any{"backend": a.cfg.Backend, "health": h, "browser": br, "applied": applied})
		},
	}
}

func (a *app) browserCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "browser", Short: "Launch and drive Burp's browser over CDP"}

	var opts backend.BrowserOptions
	launch := &cobra.Command{
		Use:   "launch [url]",
		Short: "Start Burp's bundled Chromium with a CDP port, proxied through Burp",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				opts.URL = args[0]
			}
			if _, err := a.applySites(cmd.Context(), b); err != nil {
				return err
			}
			if opts.UA == "" {
				opts.UA = a.siteUA()
			} else if err := b.SetUserAgent(cmd.Context(), uaSetting(opts.UA, "browser")); err != nil {
				return err
			}
			st, err := b.BrowserLaunch(cmd.Context(), opts)
			if err != nil {
				return err
			}
			return a.print(st)
		},
	}
	launch.Flags().IntVar(&opts.Port, "port", 9222, "CDP port")
	launch.Flags().StringVar(&opts.UA, "ua", "", "User-Agent override (default: the site's user_agent)")
	launch.Flags().BoolVar(&opts.Headless, "headless", false, "run headless")
	launch.Flags().StringVar(&opts.Binary, "binary", "", "Chromium binary (default: Burp's bundled browser)")
	launch.Flags().BoolVar(&opts.KeepIntercept, "keep-intercept", false, "leave Proxy intercept on (requests will wait for you to forward them)")

	stop := &cobra.Command{
		Use: "stop", Short: "Stop the launched browser", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			st, err := b.BrowserStop(cmd.Context())
			if err != nil {
				return err
			}
			return a.print(st)
		},
	}

	cdp := &cobra.Command{
		Use:   "cdp",
		Short: "Print the CDP endpoint, websocket URL and auth token",
		Long: "Burp's Chromium build requires the token in an x-burp-authorization header on its\n" +
			"/json/* endpoints. Playwright can connect to the websocket URL directly; for clients that\n" +
			"can't send headers (Selenium debuggerAddress), run `hiccup browser relay`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ep, err := a.cdp(cmd)
			if err != nil {
				return err
			}
			return a.print(map[string]string{"cdp": ep.HTTP, "ws": ep.WS, "token": ep.Token, "header": browser.AuthHeader})
		},
	}

	var relayAddr string
	relay := &cobra.Command{
		Use:   "relay",
		Short: "Serve the CDP HTTP endpoint without auth (adds x-burp-authorization) for Selenium/Playwright",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ep, err := a.cdp(cmd)
			if err != nil {
				return err
			}
			return browser.Relay(cmd.Context(), relayAddr, ep, func(addr string) {
				_ = a.print(map[string]string{"relay": "http://" + addr, "upstream": ep.HTTP,
					"selenium":   "options.debugger_address = \"" + addr + "\"",
					"playwright": "chromium.connect_over_cdp(\"http://" + addr + "\")"})
			})
		},
	}
	relay.Flags().StringVar(&relayAddr, "listen", "127.0.0.1:9223", "address to listen on (keep it on loopback)")

	var newTab bool
	var timeout time.Duration
	nav := &cobra.Command{
		Use: "nav <url>", Short: "Navigate the current tab and wait for the page to load", Args: cobra.ExactArgs(1),
		RunE: a.withTab(&newTab, func(s *browser.Session, args []string) (any, error) {
			return s.Navigate(args[0], timeout)
		}),
	}
	nav.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "page load timeout")

	eval := &cobra.Command{
		Use: "eval <js>", Short: "Evaluate JavaScript in the current tab (promises are awaited)", Args: cobra.ExactArgs(1),
		RunE: a.withTab(&newTab, func(s *browser.Session, args []string) (any, error) {
			return s.Eval(args[0])
		}),
	}

	var quality int
	shot := &cobra.Command{
		Use: "screenshot <out.png>", Short: "Full-page screenshot of the current tab", Args: cobra.ExactArgs(1),
		RunE: a.withTab(&newTab, func(s *browser.Session, args []string) (any, error) {
			buf, err := s.Screenshot(quality)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(args[0], buf, 0o644); err != nil {
				return nil, err
			}
			return map[string]any{"path": args[0], "bytes": len(buf)}, nil
		}),
	}
	shot.Flags().IntVar(&quality, "quality", 100, "100 = PNG, lower = JPEG quality")

	html := &cobra.Command{
		Use: "html", Short: "Print the current tab's DOM as HTML", Args: cobra.NoArgs,
		RunE: a.withTab(&newTab, func(s *browser.Session, _ []string) (any, error) {
			h, err := s.HTML()
			if err != nil {
				return nil, err
			}
			fmt.Print(h)
			return nil, nil
		}),
	}

	info := &cobra.Command{
		Use: "info", Short: "Print the current tab's URL and title", Args: cobra.NoArgs,
		RunE: a.withTab(&newTab, func(s *browser.Session, _ []string) (any, error) {
			return s.Info()
		}),
	}

	for _, c := range []*cobra.Command{nav, eval, shot, html, info} {
		c.Flags().BoolVar(&newTab, "new-tab", false, "open a new tab instead of using the current one")
	}
	cmd.AddCommand(launch, stop, cdp, relay, nav, eval, shot, html, info)
	return cmd
}

// cdp returns the DevTools endpoint of the browser the backend launched, or
// of any browser given by HICCUP_CDP_URL (http:// or ws://) and HICCUP_CDP_TOKEN.
func (a *app) cdp(cmd *cobra.Command) (browser.Endpoint, error) {
	if v := os.Getenv("HICCUP_CDP_URL"); v != "" {
		ep := browser.Endpoint{HTTP: v, Token: os.Getenv("HICCUP_CDP_TOKEN")}
		if strings.HasPrefix(v, "ws") {
			ep.HTTP, ep.WS = "", v
		}
		return ep, nil
	}
	b, err := a.be()
	if err != nil {
		return browser.Endpoint{}, err
	}
	st, err := b.BrowserStatus(cmd.Context())
	if err != nil {
		return browser.Endpoint{}, err
	}
	if !st.Running {
		return browser.Endpoint{}, fmt.Errorf("browser is not running (hiccup browser launch)")
	}
	return browser.Endpoint{HTTP: st.CDP, WS: st.WS, Token: st.Token}, nil
}

// tabUA is the UA a tab session should present: the site's, else the one the
// backend holds (e.g. from `browser launch --ua`).
func (a *app) tabUA(cmd *cobra.Command) string {
	if ua := a.siteUA(); ua != "" {
		return ua
	}
	if os.Getenv("HICCUP_CDP_URL") != "" {
		return ""
	}
	if b, err := a.be(); err == nil {
		if ua, err := b.UserAgent(cmd.Context()); err == nil {
			return ua.UA
		}
	}
	return ""
}

// withTab attaches to the browser, applies the site UA to the tab, runs fn and prints its result.
func (a *app) withTab(newTab *bool, fn func(*browser.Session, []string) (any, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ep, err := a.cdp(cmd)
		if err != nil {
			return err
		}
		s, err := browser.Attach(cmd.Context(), ep, browser.AttachOptions{NewTab: *newTab})
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.OverrideUA(a.tabUA(cmd)); err != nil {
			return err
		}
		out, err := fn(s, args)
		if err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		return a.print(out)
	}
}
