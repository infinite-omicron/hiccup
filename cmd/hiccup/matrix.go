package main

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/infinite-omicron/hiccup/internal/authmatrix"
	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/gsheets"
	"github.com/infinite-omicron/hiccup/internal/m365"
	"github.com/infinite-omicron/hiccup/internal/opener"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/session"
)

const defaultNavSelector = "nav a, [role=navigation] a, [role=menu] a, [role=menubar] a, [role=tablist] a, aside a"

func (a *app) matrixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Auth matrix: record actions per account, replay as every account, find privilege escalation",
		Long: "1. hiccup matrix record --as admin1     (and optionally --as user1 for lower roles)\n" +
			"2. hiccup login --all                   (fresh sessions for every account)\n" +
			"3. hiccup matrix run                    (replays recorded requests as each account)\n" +
			"4. hiccup matrix export --xlsx out.xlsx --burp-issues",
	}
	cmd.AddCommand(a.matrixMapCmd(), a.matrixRecordCmd(), a.matrixMarkCmd(), a.matrixStopCmd(), a.matrixRunCmd(), a.matrixShowCmd(), a.matrixExportCmd())
	return cmd
}

func (a *app) filter(s *config.Site) (authmatrix.Filter, error) {
	f := authmatrix.Filter{Hosts: s.Hosts(), Exclude: []*regexp.Regexp{authmatrix.DefaultExclude}}
	if s.Login != nil && s.Login.URL != "" {
		f.Exclude = append(f.Exclude, regexp.MustCompile(regexp.QuoteMeta(resolve(s.BaseURL, s.Login.URL))))
	}
	for _, e := range s.Exclude {
		re, err := regexp.Compile(e)
		if err != nil {
			return f, fmt.Errorf("exclude %q: %w", e, err)
		}
		f.Exclude = append(f.Exclude, re)
	}
	return f, nil
}

func (a *app) matrixMapCmd() *cobra.Command {
	var as, selector string
	var depth, maxLinks int
	var timeout, settle time.Duration
	cmd := &cobra.Command{
		Use:   "map --as <account>",
		Short: "Show the site's nav as menu paths, as an account sees it, without recording",
		Long: "Logs in as the account and reads the nav from the browser, including submenus. With the\n" +
			"default --depth 1 it only reads the landing page; --depth 2 or more also opens each link to\n" +
			"find the nav that appears there (which follows GET links, like recording does).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			_, _, acct, ok := s.FindAccount(as)
			if !ok {
				return fmt.Errorf("no account %q in site %s", as, site)
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if _, err := a.applySites(cmd.Context(), b); err != nil {
				return err
			}
			f, err := a.filter(s)
			if err != nil {
				return err
			}
			var tab *browser.Session
			if _, err := a.login(cmd, b, site, s, acct, loginOptions{timeout: timeout, keep: &tab}); err != nil {
				return err
			}
			defer tab.Close()
			if selector == "" {
				selector = s.NavSelector
			}
			if selector == "" {
				selector = defaultNavSelector
			}
			links, err := a.crawlNav(cmd, tab, s, crawlOptions{selector: selector, depth: depth, maxLinks: maxLinks,
				filter: f, timeout: timeout, settle: settle, visit: depth > 1})
			if err != nil {
				return err
			}
			type row struct {
				Action string   `json:"action"`
				Path   []string `json:"path"`
				URL    string   `json:"url"`
			}
			rows := []row{}
			for _, l := range links {
				rows = append(rows, row{authmatrix.ActionName(l.Path), l.Path, l.Href})
			}
			return a.print(rows, "action", "url")
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "account to map the nav as (required)")
	cmd.Flags().StringVar(&selector, "selector", "", "CSS selector for nav links (default: site nav_selector or common nav containers)")
	cmd.Flags().IntVar(&depth, "depth", 1, "1 reads the landing page only; 2 or more also opens each link")
	cmd.Flags().IntVar(&maxLinks, "max-links", 100, "maximum nav links")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "login and page load timeout")
	cmd.Flags().DurationVar(&settle, "settle", time.Second, "wait after each page load")
	_ = cmd.MarkFlagRequired("as")
	return cmd
}

func (a *app) matrixRecordCmd() *cobra.Command {
	var as []string
	var all, manual, parallel, headless bool
	var o recordOptions
	cmd := &cobra.Command{
		Use:   "record --as <account>[,<account>...]",
		Short: "Log in as an account and record the requests each nav action makes",
		Long: "Auto mode logs in (fresh browser context), maps the site's nav from the browser, including\n" +
			"submenus, and opens every link. Each action is named after its menu path, e.g.\n" +
			"\"Content -> Scheduled content\". With --depth 2 or more it also follows nav links that appear\n" +
			"on those pages. Preview the paths with `hiccup matrix map`. GET links that do something\n" +
			"(e.g. flush caches) are followed too: add them to the site's exclude list to skip them.\n\n" +
			"Manual mode logs in and lets you browse; run `hiccup matrix mark \"<action>\"` before each\n" +
			"action and `hiccup matrix stop` at the end.\n\n" +
			"With --parallel (Burp), each account gets its own browser on its own Burp proxy listener and\n" +
			"they record at the same time; each recording only takes requests from its account's listener.\n" +
			"With --manual --parallel you browse every account's window yourself, marking actions with\n" +
			"`hiccup matrix mark --as <account> \"<action>\"`, and finish with `hiccup matrix stop --all`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			var accounts []*config.Account
			if all {
				for _, r := range s.Accounts() {
					accounts = append(accounts, r.Account)
				}
			}
			for _, name := range as {
				_, _, acct, ok := s.FindAccount(name)
				if !ok {
					return fmt.Errorf("no account %q in site %s", name, site)
				}
				accounts = append(accounts, acct)
			}
			switch {
			case len(accounts) == 0:
				return fmt.Errorf("name an account with --as (or several, or --all)")
			case len(accounts) > 1 && !parallel:
				return fmt.Errorf("recording several accounts at once needs --parallel")
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if _, err := a.applySites(cmd.Context(), b); err != nil {
				return err
			}
			if o.filter, err = a.filter(s); err != nil {
				return err
			}
			if o.selector == "" {
				o.selector = s.NavSelector
			}
			if o.selector == "" {
				o.selector = defaultNavSelector
			}
			o.manual, o.parallel, o.headless = manual, parallel, headless
			if !parallel {
				res, err := a.recordAccount(cmd, b, site, s, accounts[0], o)
				if err != nil {
					return err
				}
				return a.printRecording(res, false)
			}
			results := make([]*recordResult, len(accounts))
			errs := make([]error, len(accounts))
			if manual {
				for i, acct := range accounts { // one terminal: log in each in turn
					results[i], errs[i] = a.recordAccount(cmd, b, site, s, acct, o)
				}
			} else {
				var wg sync.WaitGroup
				for i, acct := range accounts {
					wg.Go(func() { results[i], errs[i] = a.recordAccount(cmd, b, site, s, acct, o) })
				}
				wg.Wait()
			}
			for i, err := range errs {
				if err != nil {
					return fmt.Errorf("%s: %w", accounts[i].Name, err)
				}
			}
			if manual {
				fmt.Fprintf(os.Stderr, "hiccup: recording %d accounts, each in its own browser window. Run `hiccup matrix mark --as <account> \"<action>\"` before each action and `hiccup matrix stop --all` when done.\n", len(accounts))
			}
			var rows []recordRow
			for _, r := range results {
				rows = append(rows, r.rows...)
			}
			return a.printRecording(&recordResult{rows: rows, states: collectStates(results)}, true)
		},
	}
	cmd.Flags().StringSliceVar(&as, "as", nil, "account(s) to record as; several need --parallel")
	cmd.Flags().BoolVar(&all, "all", false, "record every account of the site (needs --parallel)")
	cmd.Flags().BoolVar(&manual, "manual", false, "browse yourself and mark actions")
	cmd.Flags().BoolVar(&parallel, "parallel", false, "give each account its own browser and Burp proxy listener, and record them at once")
	cmd.Flags().BoolVar(&headless, "headless", false, "--parallel: run the account browsers without windows")
	cmd.Flags().StringVar(&o.selector, "selector", "", "CSS selector for nav links (default: site nav_selector or common nav containers)")
	cmd.Flags().DurationVar(&o.settle, "settle", time.Second, "wait after each page load for background requests")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 60*time.Second, "login and page load timeout")
	cmd.Flags().IntVar(&o.maxLinks, "max-links", 100, "maximum nav links to follow")
	cmd.Flags().IntVar(&o.depth, "depth", 2, "1 follows the landing page's nav; 2 also follows nav links that appear on those pages (tabs, section menus); and so on")
	cmd.MarkFlagsMutuallyExclusive("as", "all")
	return cmd
}

type recordOptions struct {
	selector                   string
	depth, maxLinks            int
	settle, timeout            time.Duration
	filter                     authmatrix.Filter
	manual, parallel, headless bool
}

type recordRow struct {
	Account  string `json:"account"`
	Action   string `json:"action"`
	Requests int    `json:"requests"`
	Example  string `json:"example"`
}

type recordResult struct {
	rows   []recordRow
	states []*authmatrix.State // manual mode: recordings in progress
}

func collectStates(results []*recordResult) []*authmatrix.State {
	var out []*authmatrix.State
	for _, r := range results {
		out = append(out, r.states...)
	}
	return out
}

func (a *app) printRecording(r *recordResult, withAccount bool) error {
	if len(r.states) > 0 {
		if len(r.states) == 1 {
			return a.print(r.states[0])
		}
		return a.print(r.states, "account", "listener_port", "start_id")
	}
	if withAccount {
		return a.print(r.rows, "account", "action", "requests", "example")
	}
	return a.print(r.rows, "action", "requests", "example")
}

// recordAccount records one account. With o.parallel it uses the account's
// own browser and proxy listener; otherwise a fresh browser context (auto) or
// the visible tab (manual).
func (a *app) recordAccount(cmd *cobra.Command, b proxy.Proxy, site string, s *config.Site, acct *config.Account, o recordOptions) (*recordResult, error) {
	role, r, _, _ := s.FindAccount(acct.Name)
	lo := loginOptions{timeout: o.timeout, visible: o.manual}
	label := ""
	if o.parallel {
		port := s.AccountPorts()[acct.Name]
		if _, err := a.launchAccountBrowser(cmd, b, acct.Name, proxy.BrowserOptions{UA: a.siteUA(), Headless: o.headless}, false); err != nil {
			return nil, err
		}
		lo.browser, lo.listener, label = acct.Name, port, acct.Name+" "
	}

	if o.manual {
		if _, err := a.login(cmd, b, site, s, acct, lo); err != nil {
			return nil, err
		}
		id, err := latestID(cmd.Context(), b)
		if err != nil {
			return nil, err
		}
		st := &authmatrix.State{Site: site, Account: acct.Name, StartID: id, ListenerPort: lo.listener,
			Marks: []authmatrix.Mark{{Action: "Landing", FromID: id}}}
		if err := authmatrix.SaveState(st); err != nil {
			return nil, err
		}
		if !o.parallel {
			fmt.Fprintf(os.Stderr, "hiccup: recording as %s. Browse in Burp's browser; run `hiccup matrix mark \"<action>\"` before each action and `hiccup matrix stop` when done.\n", acct.Name)
		}
		return &recordResult{states: []*authmatrix.State{st}}, nil
	}

	var tab *browser.Session
	lo.keep = &tab
	if _, err := a.login(cmd, b, site, s, acct, lo); err != nil {
		return nil, err
	}
	defer tab.Close()
	startID, err := latestID(cmd.Context(), b)
	if err != nil {
		return nil, err
	}
	marks := []authmatrix.Mark{{Action: "Home", FromID: startID}}
	_, err = a.crawlNav(cmd, tab, s, crawlOptions{selector: o.selector, depth: o.depth, maxLinks: o.maxLinks, filter: o.filter,
		timeout: o.timeout, settle: o.settle, visit: true, label: label,
		before: func(path []string) error {
			id, err := latestID(cmd.Context(), b)
			if err != nil {
				return err
			}
			marks = append(marks, authmatrix.Mark{Action: authmatrix.ActionName(path), FromID: id})
			return nil
		}})
	if err != nil {
		return nil, err
	}
	return a.finishRecording(cmd, b, site, role, r.Level, acct.Name, startID, lo.listener, marks, o.filter)
}

// excluded reports whether a link matches the site's exclude patterns (logout is always excluded).
func excluded(l browser.Link, f authmatrix.Filter) bool {
	for _, re := range f.Exclude {
		if re.MatchString(l.Href) || re.MatchString(l.Text) || re.MatchString(authmatrix.ActionName(l.Path)) {
			return true
		}
	}
	return false
}

type crawlOptions struct {
	selector        string
	depth, maxLinks int
	filter          authmatrix.Filter
	timeout, settle time.Duration
	// visit opens every link; without it only the landing page's nav is read.
	visit bool
	// before runs just before each link is opened, with its menu path.
	before func(path []string) error
	// label prefixes progress lines (the account, when recording in parallel).
	label string
}

// crawlNav maps the site's nav breadth-first from the base URL. Links found
// on a page that weren't seen before (its tabs or section menu) are named
// under that page's path. It returns every link it found, in order.
func (a *app) crawlNav(cmd *cobra.Command, tab *browser.Session, s *config.Site, o crawlOptions) ([]browser.Link, error) {
	type item struct {
		browser.Link
		depth int
	}
	if _, err := tab.Navigate(s.BaseURL, o.timeout); err != nil {
		return nil, err
	}
	pause(s, o.settle)
	seen := map[string]bool{}
	var queue []item
	enqueue := func(parent []string, links []browser.Link, depth int) {
		for _, l := range links {
			if seen[l.Href] || excluded(l, o.filter) || len(queue) >= o.maxLinks {
				continue
			}
			seen[l.Href] = true
			l.Path = authmatrix.JoinPath(parent, l.Path)
			queue = append(queue, item{l, depth})
		}
	}
	links, err := tab.Links(o.selector)
	if err != nil {
		return nil, err
	}
	enqueue(nil, links, 1)
	for i := 0; o.visit && i < len(queue); i++ {
		it := queue[i]
		if o.before != nil {
			if err := o.before(it.Path); err != nil {
				return nil, err
			}
		}
		fmt.Fprintf(os.Stderr, "hiccup: [%s%d/%d] %s -> %s\n", o.label, i+1, len(queue), authmatrix.ActionName(it.Path), it.Href)
		if _, err := tab.Navigate(it.Href, o.timeout); err != nil {
			fmt.Fprintf(os.Stderr, "hiccup:   %v\n", err)
			continue
		}
		pause(s, o.settle)
		if it.depth < o.depth {
			more, err := tab.Links(o.selector)
			if err != nil {
				return nil, err
			}
			enqueue(it.Path, more, it.depth+1)
		}
	}
	out := make([]browser.Link, len(queue))
	for i, it := range queue {
		out[i] = it.Link
	}
	return out, nil
}

// pause waits settle plus the site's throttle jitter, so crawling looks human-paced.
func pause(s *config.Site, settle time.Duration) {
	d := settle
	if t, err := s.EffectiveThrottle(); err == nil && t != nil && t.JitterMS[1] > 0 {
		lo, hi := t.JitterMS[0], max(t.JitterMS[0], t.JitterMS[1])
		d += time.Duration(lo+rand.IntN(hi-lo+1)) * time.Millisecond
	}
	time.Sleep(d)
}

// finishRecording turns proxy history since startID into the account's
// recording. With listener > 0 only requests from that listener count.
func (a *app) finishRecording(cmd *cobra.Command, b proxy.Proxy, site, role string, level int, account string, startID, listener int, marks []authmatrix.Mark, f authmatrix.Filter) (*recordResult, error) {
	items, err := b.History(cmd.Context(), proxy.HistoryQuery{Since: startID, Limit: 100000, Listener: listener})
	if err != nil {
		return nil, err
	}
	rec := &authmatrix.Recording{Site: site, Account: account, Role: role, Level: level, Created: time.Now().UTC(),
		Actions: authmatrix.Build(items, marks, f)}
	if err := authmatrix.SaveRecording(rec); err != nil {
		return nil, err
	}
	res := &recordResult{}
	for _, act := range rec.Actions {
		res.rows = append(res.rows, recordRow{account, act.Name, len(act.Requests), act.Requests[0].Key()})
	}
	return res, nil
}

func (a *app) matrixMarkCmd() *cobra.Command {
	var as string
	cmd := &cobra.Command{
		Use:   "mark <action>",
		Short: "Manual recording: requests from now on belong to this action (--as when several accounts record)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			site, _, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			st, err := authmatrix.LoadState(site, as)
			if err != nil {
				return err
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			id, err := latestID(cmd.Context(), b)
			if err != nil {
				return err
			}
			st.Marks = append(st.Marks, authmatrix.Mark{Action: args[0], FromID: id})
			if err := authmatrix.SaveState(st); err != nil {
				return err
			}
			return a.print(map[string]any{"account": st.Account, "action": args[0], "from_id": id})
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "the account whose recording to mark")
	return cmd
}

func (a *app) matrixStopCmd() *cobra.Command {
	var as string
	var all bool
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Manual recording: finish and save the recording (--as one account, --all every one)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			var states []*authmatrix.State
			if all {
				if states, err = authmatrix.States(site); err != nil {
					return err
				}
				if len(states) == 0 {
					return fmt.Errorf("no recordings in progress for %s", site)
				}
			} else {
				st, err := authmatrix.LoadState(site, as)
				if err != nil {
					return err
				}
				states = []*authmatrix.State{st}
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			f, err := a.filter(s)
			if err != nil {
				return err
			}
			var rows []recordRow
			for _, st := range states {
				role, r, _, ok := s.FindAccount(st.Account)
				if !ok {
					return fmt.Errorf("account %q is no longer in the config", st.Account)
				}
				res, err := a.finishRecording(cmd, b, site, role, r.Level, st.Account, st.StartID, st.ListenerPort, st.Marks, f)
				if err != nil {
					return err
				}
				if err := authmatrix.ClearState(st); err != nil {
					return err
				}
				rows = append(rows, res.rows...)
			}
			return a.printRecording(&recordResult{rows: rows}, len(states) > 1)
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "the account whose recording to finish")
	cmd.Flags().BoolVar(&all, "all", false, "finish every recording in progress")
	cmd.MarkFlagsMutuallyExclusive("as", "all")
	return cmd
}

func (a *app) matrixRunCmd() *cobra.Command {
	var unsafe bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Replay every recorded request as every account and classify the results",
		Long: "Uses the saved sessions (hiccup login --all). Only GET/HEAD/OPTIONS are replayed unless\n" +
			"--unsafe: replaying POST/PUT/DELETE as other users changes data on the target.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			recs, err := authmatrix.LoadRecordings(site)
			if err != nil {
				return err
			}
			if len(recs) == 0 {
				return fmt.Errorf("no recordings for %s (hiccup matrix record --as <account>)", site)
			}
			opts := authmatrix.RunOptions{Site: site, Recordings: recs, Unsafe: unsafe, Sessions: map[string]*session.Session{}}
			for _, ref := range s.Accounts() {
				acct := ref.Account
				opts.Accounts = append(opts.Accounts, authmatrix.Account{Name: acct.Name, Role: ref.Role, Level: ref.Level, Anonymous: acct.Username == ""})
				if acct.Username == "" {
					continue
				}
				sess, err := session.Load(site, acct.Name)
				if err != nil {
					return err
				}
				opts.Sessions[acct.Name] = sess
			}
			if s.Session != nil {
				opts.StripHeader = s.Session.Headers
			}
			if s.Login != nil {
				opts.LoginPath = s.Login.URL
			}
			if opts.Overrides, err = authmatrix.LoadOverrides(site); err != nil {
				return err
			}
			if t, err := s.EffectiveThrottle(); err == nil && t != nil {
				opts.Concurrency = t.MaxConcurrency
			}
			if term.IsTerminal(int(os.Stderr.Fd())) {
				opts.Progress = func(done, total int) { fmt.Fprintf(os.Stderr, "\rhiccup: replayed %d/%d requests", done, total) }
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if _, err := a.applySites(cmd.Context(), b); err != nil {
				return err
			}
			m, err := authmatrix.Run(cmd.Context(), b, opts)
			if opts.Progress != nil {
				fmt.Fprintln(os.Stderr)
			}
			if err != nil {
				return err
			}
			if err := m.Save(); err != nil {
				return err
			}
			warnStaleSessions(m)
			return a.print(findingRows(m, true), "finding", "account", "action", "request", "status", "reason")
		},
	}
	cmd.Flags().BoolVar(&unsafe, "unsafe", false, "also replay state-changing methods (POST, PUT, PATCH, DELETE)")
	return cmd
}

// warnStaleSessions flags owners whose own replay was denied: their session has likely expired.
func warnStaleSessions(m *authmatrix.Matrix) {
	stale := map[string]bool{}
	for _, act := range m.Actions {
		for _, r := range act.Requests {
			for _, c := range r.Cells {
				if c.Account == r.Recorder && c.Verdict == authmatrix.Denied {
					stale[c.Account] = true
				}
			}
		}
	}
	for acct := range stale {
		fmt.Fprintf(os.Stderr, "hiccup: warning: %s was denied its own recorded requests; its session may have expired (hiccup login %s)\n", acct, acct)
	}
}

type findingRow struct {
	Finding string `json:"finding"`
	Account string `json:"account"`
	Action  string `json:"action"`
	Request string `json:"request"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Reason  string `json:"reason"`
}

func findingRows(m *authmatrix.Matrix, review bool) []findingRow {
	rows := []findingRow{}
	for _, f := range m.Findings(review) {
		rows = append(rows, findingRow{f.Cell.Finding, f.Cell.Account, f.Action, f.Request.Key(), f.Request.URL, f.Cell.Status, f.Cell.Reason})
	}
	return rows
}

func (a *app) matrixShowCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the last run's findings (or every cell with --all)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, _, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			m, err := authmatrix.LoadMatrix(site)
			if err != nil {
				return err
			}
			if !all {
				return a.print(findingRows(m, true), "finding", "account", "action", "request", "status", "reason")
			}
			type cellRow struct {
				Action   string `json:"action"`
				Request  string `json:"request"`
				Account  string `json:"account"`
				Expected string `json:"expected"`
				Verdict  string `json:"verdict"`
				Status   int    `json:"status"`
				Finding  string `json:"finding"`
			}
			var rows []cellRow
			for _, act := range m.Actions {
				for _, r := range act.Requests {
					for _, c := range r.Cells {
						rows = append(rows, cellRow{act.Name, r.Key(), c.Account, c.Expected, c.Verdict, c.Status, c.Finding})
					}
				}
			}
			return a.print(rows, "action", "request", "account", "expected", "verdict", "status", "finding")
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "every cell, not only findings")
	return cmd
}

func (a *app) matrixExportCmd() *cobra.Command {
	var xlsx, csvPath, jsonPath, template, sheet, sheets, m365Target string
	var burpIssues, full, open, noOpen bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the last run to Excel (your Checklist template), Microsoft 365, Google Sheets, csv, json or Burp issues",
		Long: `With no output flags, writes <site>-auth-matrix.xlsx in the current directory and opens it in
Excel when run in an interactive terminal (--open and --no-open override that). --m365 also
uploads the workbook to OneDrive or SharePoint, replacing the previous copy (see hiccup m365).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, _, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			m, err := authmatrix.LoadMatrix(site)
			if err != nil {
				return err
			}
			if m365Target == "" && a.cfg.Matrix != nil {
				m365Target = strings.ReplaceAll(a.cfg.Matrix.M365, "{site}", site)
			}
			others := csvPath != "" || jsonPath != "" || sheets != "" || burpIssues
			out := map[string]any{}
			if xlsx == "" && (m365Target != "" || !others) {
				// The workbook is the default output, and it is what --m365 uploads.
				xlsx = site + "-auth-matrix.xlsx"
				// An app that already has it open would keep showing the old copy
				// (opening it again only brings that window forward), so write a new one.
				if opener.InUse(xlsx) {
					xlsx = fmt.Sprintf("%s-auth-matrix-%s.xlsx", site, time.Now().Format("20060102-150405"))
					out["note"] = site + "-auth-matrix.xlsx is open in another app, so this export was written to a new file"
				}
			} else if xlsx != "" && opener.InUse(xlsx) {
				out["note"] = xlsx + " is open in another app; reload it there (File -> Reload) to see this export"
			}
			if sheet == "" && a.cfg.Matrix != nil {
				sheet = a.cfg.Matrix.Sheet
			}
			if xlsx != "" {
				if template == "" && a.cfg.Matrix != nil {
					template = expandHome(a.cfg.Matrix.Template)
				}
				if err := m.WriteXLSX(xlsx, authmatrix.XLSXOptions{Template: template, Sheet: sheet}); err != nil {
					return err
				}
				out["xlsx"] = xlsx
			}
			if m365Target != "" {
				tenant, clientID := a.cfg.MicrosoftSettings()
				client, err := m365.Client(cmd.Context(), m365.Settings{Tenant: tenant, ClientID: clientID})
				if err != nil {
					return err
				}
				item, err := m365.Upload(cmd.Context(), client, xlsx, m365Target)
				if err != nil {
					return err
				}
				out["m365"] = item.WebURL
			}
			if csvPath != "" {
				if err := writeWith(csvPath, m.WriteCSV); err != nil {
					return err
				}
				out["csv"] = csvPath
			}
			if jsonPath != "" {
				if err := writeWith(jsonPath, func(w io.Writer) error { return m.WriteJSON(w, full) }); err != nil {
					return err
				}
				out["json"] = jsonPath
			}
			if sheets != "" {
				client, err := gsheets.Client(cmd.Context())
				if err != nil {
					return err
				}
				link, err := gsheets.Write(cmd.Context(), client, sheets, sheet, m)
				if err != nil {
					return err
				}
				out["sheets"] = link
			}
			if burpIssues {
				b, err := a.proxyClient()
				if err != nil {
					return err
				}
				n, err := addIssues(cmd, b, m.Issues())
				if err != nil {
					return err
				}
				out["burp_issues"] = n
			}
			// Open the workbook for a person at a terminal, never for scripts or agents.
			interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
			if xlsx != "" && !noOpen && (open || interactive) {
				if err := opener.Open(xlsx); err != nil {
					return err
				}
				out["opened"] = true
			}
			return a.print(out)
		},
	}
	cmd.Flags().StringVar(&xlsx, "xlsx", "", "workbook to write (default <site>-auth-matrix.xlsx when no other output is chosen)")
	cmd.Flags().StringVar(&template, "template", "", "workbook to fill (default: config matrix.template), e.g. Checklist.xltx")
	cmd.Flags().StringVar(&sheet, "sheet", "", `tab to fill in the workbook or Google Sheet (default "Auth Matrix")`)
	cmd.Flags().BoolVar(&open, "open", false, "open the workbook in Excel even when not in an interactive terminal")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "don't open the workbook")
	cmd.Flags().StringVar(&m365Target, "m365", "", "also upload the workbook to OneDrive/SharePoint: onedrive:/path/ or a folder URL (default: config matrix.m365)")
	cmd.Flags().StringVar(&sheets, "sheets", "", "Google Sheet ID or URL to fill (see hiccup google)")
	cmd.Flags().StringVar(&csvPath, "csv", "", "write a csv with one row per account and request")
	cmd.Flags().StringVar(&jsonPath, "json", "", "write the matrix as json")
	cmd.Flags().BoolVar(&full, "full", false, "json: include base64 requests and responses")
	cmd.Flags().BoolVar(&burpIssues, "burp-issues", false, "add each finding to Burp as an issue (Burp Pro)")
	cmd.MarkFlagsMutuallyExclusive("open", "no-open")
	return cmd
}

func writeWith(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
