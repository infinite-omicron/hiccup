package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
)

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check the proxy connection and push site throttles/User-Agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.proxyClient()
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
			br, err := b.BrowserStatus(cmd.Context(), "")
			if err != nil {
				return err
			}
			out := map[string]any{"proxy": a.cfg.ProxyName(), "health": h, "browser": br, "applied": applied}
			if all, err := b.Browsers(cmd.Context()); err == nil && len(all) > 0 {
				out["browsers"] = all
			}
			return a.print(out)
		},
	}
}

func (a *app) browserCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "browser", Short: "Launch and drive Burp's browser over CDP (Chrome DevTools Protocol)",
		Long: "--as <account> uses that account's own browser, on its own Burp proxy listener (see\n" +
			"docs/auth-matrix.md, parallel accounts). Without it, commands use the default browser."}
	cmd.PersistentFlags().StringVar(&a.browserAs, "as", "", "use this account's own browser and proxy listener")

	var opts proxy.BrowserOptions
	var all bool
	launch := &cobra.Command{
		Use:   "launch [url]",
		Short: "Start Burp's bundled Chromium with a CDP port, proxied through Burp",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
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
			accounts := []string{}
			switch {
			case all:
				_, s, err := a.cfg.Site(a.site)
				if err != nil {
					return err
				}
				for _, r := range s.Accounts() {
					accounts = append(accounts, r.Account.Name)
				}
			case a.browserAs != "":
				accounts = append(accounts, a.browserAs)
			default:
				st, err := b.BrowserLaunch(cmd.Context(), opts)
				if err != nil {
					return err
				}
				return a.print(st)
			}
			var out []*proxy.BrowserStatus
			for _, acct := range accounts {
				o := opts
				st, err := a.launchAccountBrowser(cmd, b, acct, o, cmd.Flags().Changed("port"))
				if err != nil {
					return fmt.Errorf("%s: %w", acct, err)
				}
				out = append(out, st)
			}
			if len(out) == 1 {
				return a.print(out[0])
			}
			return a.print(out, "name", "proxy", "cdp", "running")
		},
	}
	launch.Flags().BoolVar(&all, "all", false, "launch a browser for every account of the site, each on its own listener")
	launch.Flags().IntVar(&opts.Port, "port", 9222, "CDP port")
	launch.Flags().StringVar(&opts.UA, "ua", "", "User-Agent override (default: the site's user_agent)")
	launch.Flags().BoolVar(&opts.Headless, "headless", false, "run headless")
	launch.Flags().StringVar(&opts.Binary, "binary", "", "Chromium binary (default: Burp's bundled browser)")
	launch.Flags().BoolVar(&opts.KeepIntercept, "keep-intercept", false, "leave Proxy intercept on (requests will wait for you to forward them)")

	var stopAll bool
	stop := &cobra.Command{
		Use: "stop", Short: "Stop the launched browser (--as one account's, --all every browser)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if !stopAll {
				st, err := b.BrowserStop(cmd.Context(), a.browserAs)
				if err != nil {
					return err
				}
				return a.print(st)
			}
			running, err := b.Browsers(cmd.Context())
			if err != nil {
				return err
			}
			stopped := []string{}
			for _, st := range running {
				if _, err := b.BrowserStop(cmd.Context(), st.Name); err != nil {
					return err
				}
				stopped = append(stopped, st.Name)
			}
			return a.print(map[string]any{"stopped": stopped})
		},
	}
	stop.Flags().BoolVar(&stopAll, "all", false, "stop every browser hiccup launched")

	list := &cobra.Command{
		Use: "list", Short: "List the running browsers", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			all, err := b.Browsers(cmd.Context())
			if err != nil {
				return err
			}
			return a.print(all, "name", "proxy", "cdp", "pid")
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
	cmd.AddCommand(launch, stop, list, cdp, relay, nav, eval, shot, html, info)
	return cmd
}

// cdp returns the DevTools endpoint of the browser the proxy launched, or
// of any browser given by HICCUP_CDP_URL (http:// or ws://) and HICCUP_CDP_TOKEN.
func (a *app) cdp(cmd *cobra.Command) (browser.Endpoint, error) { return a.cdpFor(cmd, a.browserAs) }

// cdpFor returns the DevTools endpoint of a named browser ("" is the default one).
func (a *app) cdpFor(cmd *cobra.Command, name string) (browser.Endpoint, error) {
	if v := os.Getenv("HICCUP_CDP_URL"); v != "" {
		ep := browser.Endpoint{HTTP: v, Token: os.Getenv("HICCUP_CDP_TOKEN")}
		if strings.HasPrefix(v, "ws") {
			ep.HTTP, ep.WS = "", v
		}
		return ep, nil
	}
	b, err := a.proxyClient()
	if err != nil {
		return browser.Endpoint{}, err
	}
	st, err := b.BrowserStatus(cmd.Context(), name)
	if err != nil {
		return browser.Endpoint{}, err
	}
	if !st.Running {
		if name != "" {
			return browser.Endpoint{}, fmt.Errorf("%s's browser is not running (hiccup browser launch --as %s)", name, name)
		}
		return browser.Endpoint{}, fmt.Errorf("browser is not running (hiccup browser launch)")
	}
	return browser.Endpoint{HTTP: st.CDP, WS: st.WS, Token: st.Token}, nil
}

// tabUA is the UA a tab session should present: the site's, else the one the
// proxy holds (e.g. from `browser launch --ua`).
func (a *app) tabUA(cmd *cobra.Command) string {
	if ua := a.siteUA(); ua != "" {
		return ua
	}
	if os.Getenv("HICCUP_CDP_URL") != "" {
		return ""
	}
	if b, err := a.proxyClient(); err == nil {
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

// launchAccountBrowser starts an account's own browser on its own proxy
// listener (adding the listener first), so its traffic is attributable.
// The CDP port is the listener port + config.CDPOffset unless portSet.
func (a *app) launchAccountBrowser(cmd *cobra.Command, b proxy.Proxy, account string, o proxy.BrowserOptions, portSet bool) (*proxy.BrowserStatus, error) {
	_, s, err := a.cfg.Site(a.site)
	if err != nil {
		return nil, err
	}
	if _, _, _, ok := s.FindAccount(account); !ok {
		return nil, fmt.Errorf("no account %q in the site", account)
	}
	port := s.AccountPorts()[account]
	if _, err := b.AddListeners(cmd.Context(), []int{port}); err != nil {
		return nil, err
	}
	o.Name, o.ProxyPort = account, port
	if !portSet {
		o.Port = port + config.CDPOffset
	}
	return b.BrowserLaunch(cmd.Context(), o)
}
