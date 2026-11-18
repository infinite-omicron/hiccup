package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/secrets"
	"github.com/infinite-omicron/hiccup/internal/session"
)

func (a *app) loginCmd() *cobra.Command {
	var manual, all, parallel, headless bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "login [account...]",
		Short: "Log accounts in through Burp's browser and save their sessions",
		Long: "Runs the site's login recipe in a fresh browser context per account (so sessions never mix),\n" +
			"then saves cookies and session headers to ~/.hiccup/sessions/<site>/<account>.json.\n" +
			"With --manual, or when the recipe fails in a terminal, you log in yourself in Burp's browser.\n\n" +
			"With --parallel (Burp), each account gets its own browser on its own Burp proxy listener and\n" +
			"they log in at the same time; the browsers stay open so you can keep testing as each user.",
		RunE: func(cmd *cobra.Command, args []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			refs := s.Accounts()
			if !all {
				if len(args) == 0 {
					return fmt.Errorf("name accounts to log in, or use --all")
				}
				refs = slices.DeleteFunc(refs, func(r config.AccountRef) bool { return !slices.Contains(args, r.Account.Name) })
				if len(refs) != len(args) {
					return fmt.Errorf("unknown account in %v for site %s (see hiccup creds list)", args, site)
				}
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if _, err := a.applySites(cmd.Context(), b); err != nil {
				return err
			}
			row := func(r config.AccountRef, sess *session.Session) map[string]any {
				return map[string]any{"account": r.Account.Name, "cookies": len(sess.Cookies),
					"headers": len(sess.Headers), "session": session.Path(site, r.Account.Name)}
			}
			var out []map[string]any
			if !parallel {
				for _, r := range refs {
					sess, err := a.login(cmd, b, site, s, r.Account, loginOptions{manual: manual, timeout: timeout})
					if err != nil {
						return fmt.Errorf("%s: %w", r.Account.Name, err)
					}
					out = append(out, row(r, sess))
				}
				return a.print(out, "account", "cookies", "headers", "session")
			}

			// --parallel: one browser and proxy listener per account.
			ports := s.AccountPorts()
			opts := func(r config.AccountRef) loginOptions {
				o := loginOptions{manual: manual, timeout: timeout, listener: ports[r.Account.Name]}
				if r.Account.Username != "" {
					o.browser = r.Account.Name
				}
				return o
			}
			for _, r := range refs {
				if r.Account.Username == "" {
					continue // anonymous: nothing to log in
				}
				if _, err := a.launchAccountBrowser(cmd, b, r.Account.Name, proxy.BrowserOptions{UA: a.siteUA(), Headless: headless}, false); err != nil {
					return fmt.Errorf("%s: %w", r.Account.Name, err)
				}
			}
			out = make([]map[string]any, len(refs))
			errs := make([]error, len(refs))
			if manual {
				// One terminal for everyone: confirm each login in turn.
				for i, r := range refs {
					sess, err := a.login(cmd, b, site, s, r.Account, opts(r))
					if errs[i] = err; err == nil {
						out[i] = row(r, sess)
					}
				}
			} else {
				var wg sync.WaitGroup
				for i, r := range refs {
					wg.Go(func() {
						sess, err := a.login(cmd, b, site, s, r.Account, opts(r))
						if errs[i] = err; err == nil {
							out[i] = row(r, sess)
						}
					})
				}
				wg.Wait()
			}
			for i, err := range errs {
				if err != nil {
					return fmt.Errorf("%s: %w", refs[i].Account.Name, err)
				}
			}
			return a.print(out, "account", "cookies", "headers", "session")
		},
	}
	cmd.Flags().BoolVar(&manual, "manual", false, "log in yourself in Burp's browser instead of running the recipe")
	cmd.Flags().BoolVar(&all, "all", false, "log in every account of the site")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "time allowed for each login (manual: 5x this)")
	cmd.Flags().BoolVar(&parallel, "parallel", false, "give each account its own browser and Burp proxy listener, and log them in at once")
	cmd.Flags().BoolVar(&headless, "headless", false, "--parallel: run the account browsers without windows")
	return cmd
}

type loginOptions struct {
	manual  bool // the user logs in by hand in the visible tab
	visible bool // run the recipe in the visible tab instead of a fresh browser context
	// browser is the account's own browser (--parallel); its tab is used
	// directly, since the whole browser belongs to the account.
	browser string
	// listener is the account's proxy listener: session headers are read only
	// from requests that came through it.
	listener int
	timeout  time.Duration
	// keep, when non-nil, receives the logged-in tab instead of it being
	// closed, so `matrix record` can keep browsing as that account.
	keep **browser.Session
}

// login logs one account in and saves its session.
func (a *app) login(cmd *cobra.Command, b proxy.Proxy, site string, s *config.Site, acct *config.Account, o loginOptions) (*session.Session, error) {
	manual, timeout, keep := o.manual, o.timeout, o.keep
	if acct.Username == "" {
		sess := session.Anonymous(site, acct.Name)
		sess.CapturedAt = time.Now().UTC()
		if keep != nil {
			tab, err := a.attachTo(cmd, o.browser, browser.AttachOptions{Isolated: !o.visible && o.browser == ""})
			if err != nil {
				return nil, err
			}
			*keep = tab
		}
		return sess, sess.Save()
	}
	password, err := secrets.Resolve(acct.Password)
	if err != nil {
		return nil, err
	}
	startID, err := latestID(cmd.Context(), b)
	if err != nil {
		return nil, err
	}

	var tab *browser.Session
	if !manual && s.Login != nil {
		tab, err = a.attachTo(cmd, o.browser, browser.AttachOptions{Isolated: !o.visible && o.browser == ""})
		if err != nil {
			return nil, err
		}
		err = tab.Login(recipe(s, acct.Username, password), timeout)
		if err != nil {
			tab.Close()
			tab = nil
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return nil, err
			}
			fmt.Fprintf(os.Stderr, "hiccup: login recipe failed (%v); falling back to manual login\n", err)
		}
	}
	if tab == nil {
		if tab, err = a.manualLogin(cmd, s, acct, o.browser, 5*timeout); err != nil {
			return nil, err
		}
	}
	sess, err := capture(cmd.Context(), b, tab, site, s, acct.Name, startID, o.listener)
	if err == nil {
		err = sess.Save()
	}
	if keep != nil && err == nil {
		*keep = tab
	} else {
		tab.Close()
	}
	return sess, err
}

func (a *app) attach(cmd *cobra.Command, o browser.AttachOptions) (*browser.Session, error) {
	return a.attachTo(cmd, a.browserAs, o)
}

// attachTo attaches to a named browser ("" is the default one).
func (a *app) attachTo(cmd *cobra.Command, name string, o browser.AttachOptions) (*browser.Session, error) {
	ep, err := a.cdpFor(cmd, name)
	if err != nil {
		return nil, err
	}
	tab, err := browser.Attach(cmd.Context(), ep, o)
	if err != nil {
		return nil, err
	}
	if err := tab.OverrideUA(a.tabUA(cmd)); err != nil {
		tab.Close()
		return nil, err
	}
	return tab, nil
}

func recipe(s *config.Site, user, password string) browser.LoginRecipe {
	r := browser.LoginRecipe{
		URL:         resolve(s.BaseURL, s.Login.URL),
		UsernameSel: s.Login.Username,
		PasswordSel: s.Login.Password,
		SubmitSel:   s.Login.Submit,
		Username:    user,
		Password:    password,
	}
	if s.Login.Success != nil {
		r.SuccessURL, r.SuccessSelector = s.Login.Success.URLContains, s.Login.Success.Selector
	}
	return r
}

// manualLogin opens the login page in the visible tab and waits for the user.
func (a *app) manualLogin(cmd *cobra.Command, s *config.Site, acct *config.Account, browserName string, timeout time.Duration) (*browser.Session, error) {
	tab, err := a.attachTo(cmd, browserName, browser.AttachOptions{})
	if err != nil {
		return nil, err
	}
	loginURL := s.BaseURL
	if s.Login != nil && s.Login.URL != "" {
		loginURL = resolve(s.BaseURL, s.Login.URL)
	}
	if _, err := tab.Navigate(loginURL, 30*time.Second); err != nil {
		tab.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	var urlContains, selector string
	if s.Login != nil && s.Login.Success != nil {
		urlContains, selector = s.Login.Success.URLContains, s.Login.Success.Selector
	}
	fmt.Fprintf(os.Stderr, "hiccup: log in as %s (%s) in Burp's browser", acct.Name, acct.Username)
	entered := make(chan struct{})
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	if interactive && urlContains == "" && selector == "" {
		// Without a success check, any navigation would count as logged in
		// (an SSO redirect, an MFA page), so only the user can say when.
		fmt.Fprintln(os.Stderr, ", then press Enter")
		done := make(chan struct{})
		go func() {
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			close(done)
		}()
		select {
		case <-done:
			return tab, nil
		case <-ctx.Done():
			tab.Close()
			return nil, fmt.Errorf("manual login: %w", ctx.Err())
		}
	}
	if interactive {
		fmt.Fprint(os.Stderr, ", then press Enter")
		go func() {
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			close(entered)
			cancel()
		}()
	}
	fmt.Fprintln(os.Stderr)
	err = tab.WaitLoggedIn(ctx, urlContains, selector)
	select {
	case <-entered:
		err = nil // the user says they are logged in
	default:
	}
	if err != nil {
		tab.Close()
		return nil, fmt.Errorf("manual login: %w", err)
	}
	return tab, nil
}

// capture reads the session from the tab's cookies and, for configured
// session headers (e.g. Authorization), from proxy history since startID.
func capture(ctx context.Context, b proxy.Proxy, tab *browser.Session, site string, s *config.Site, account string, startID, listener int) (*session.Session, error) {
	urls := []string{s.BaseURL}
	urls = append(urls, s.Scope...)
	cookies, err := tab.Cookies(urls...)
	if err != nil {
		return nil, err
	}
	sess := &session.Session{Site: site, Account: account, CapturedAt: time.Now().UTC(), Headers: map[string]string{}}
	var keep, headers []string
	if s.Session != nil {
		keep, headers = s.Session.Cookies, s.Session.Headers
	}
	for _, c := range cookies {
		if len(keep) == 0 || slices.Contains(keep, c.Name) {
			sess.Cookies = append(sess.Cookies, session.Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
		}
	}
	if len(headers) > 0 {
		items, err := b.History(ctx, proxy.HistoryQuery{Since: startID, Limit: 50, Listener: listener})
		if err != nil {
			return nil, err
		}
		hosts := s.Hosts()
		for i := len(items) - 1; i >= 0 && len(sess.Headers) < len(headers); i-- {
			u, err := url.Parse(items[i].URL)
			if err != nil || !slices.Contains(hosts, strings.ToLower(u.Hostname())) {
				continue
			}
			ex, err := b.HistoryItem(ctx, items[i].ID)
			if err != nil {
				return nil, err
			}
			for _, h := range headers {
				if _, done := sess.Headers[h]; done {
					continue
				}
				if v, ok := session.HeaderValue(ex.Request(), h); ok {
					sess.Headers[h] = v
				}
			}
		}
	}
	if sess.Empty() {
		return nil, fmt.Errorf("logged in, but no session cookies or headers were found (check the site's \"session\" config)")
	}
	return sess, nil
}

// latestID is the id of the newest proxy history item, or 0.
func latestID(ctx context.Context, b proxy.Proxy) (int, error) {
	items, err := b.History(ctx, proxy.HistoryQuery{Since: -1, Limit: 1})
	if err != nil || len(items) == 0 {
		return 0, err
	}
	return items[0].ID, nil
}

func resolve(base, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return bu.ResolveReference(ru).String()
}
