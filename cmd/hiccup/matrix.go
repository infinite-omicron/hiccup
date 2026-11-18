package main

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"regexp"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/infinite-omicron/hiccup/internal/authmatrix"
	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/gsheets"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/session"
)

const defaultNavSelector = "nav a, [role=navigation] a, [role=menu] a, aside a"

func (a *app) matrixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Auth matrix: record actions per account, replay as every account, find privilege escalation",
		Long: "1. hiccup matrix record --as admin1     (and optionally --as user1 for lower roles)\n" +
			"2. hiccup login --all                   (fresh sessions for every account)\n" +
			"3. hiccup matrix run                    (replays recorded requests as each account)\n" +
			"4. hiccup matrix export --xlsx out.xlsx --burp-issues",
	}
	cmd.AddCommand(a.matrixRecordCmd(), a.matrixMarkCmd(), a.matrixStopCmd(), a.matrixRunCmd(), a.matrixShowCmd(), a.matrixExportCmd())
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

func (a *app) matrixRecordCmd() *cobra.Command {
	var as, selector string
	var manual bool
	var settle, timeout time.Duration
	var maxLinks int
	cmd := &cobra.Command{
		Use:   "record --as <account>",
		Short: "Log in as an account and record the requests each nav action makes",
		Long: "Auto mode logs in (fresh browser context), opens the base URL, and clicks every nav link,\n" +
			"naming each action after the link text. Manual mode logs in and lets you browse; run\n" +
			"`hiccup matrix mark \"<action>\"` before each action and `hiccup matrix stop` at the end.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			role, r, acct, ok := s.FindAccount(as)
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

			if manual {
				// Log in in the visible tab: that is where the user will browse.
				if _, err := a.login(cmd, b, site, s, acct, loginOptions{visible: true, timeout: timeout}); err != nil {
					return err
				}
				id, err := latestID(cmd.Context(), b)
				if err != nil {
					return err
				}
				st := &authmatrix.State{Site: site, Account: acct.Name, StartID: id, Marks: []authmatrix.Mark{{Action: "Landing", FromID: id}}}
				if err := authmatrix.SaveState(st); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "hiccup: recording as %s. Browse in Burp's browser; run `hiccup matrix mark \"<action>\"` before each action and `hiccup matrix stop` when done.\n", acct.Name)
				return a.print(st)
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
			startID, err := latestID(cmd.Context(), b)
			if err != nil {
				return err
			}
			marks := []authmatrix.Mark{{Action: "Home", FromID: startID}}
			if _, err := tab.Navigate(s.BaseURL, timeout); err != nil {
				return err
			}
			pause(s, settle)
			links, err := tab.Links(selector)
			if err != nil {
				return err
			}
			links = keepLinks(links, f, maxLinks)
			for i, l := range links {
				id, err := latestID(cmd.Context(), b)
				if err != nil {
					return err
				}
				marks = append(marks, authmatrix.Mark{Action: l.Text, FromID: id})
				fmt.Fprintf(os.Stderr, "hiccup: [%d/%d] %s → %s\n", i+1, len(links), l.Text, l.Href)
				if _, err := tab.Navigate(l.Href, timeout); err != nil {
					fmt.Fprintf(os.Stderr, "hiccup:   %v\n", err)
				}
				pause(s, settle)
			}
			return a.finishRecording(cmd, b, site, role, r.Level, acct.Name, startID, marks, f)
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "account to record as (required)")
	cmd.Flags().BoolVar(&manual, "manual", false, "browse yourself and mark actions")
	cmd.Flags().StringVar(&selector, "selector", "", "CSS selector for nav links (default: site nav_selector or common nav containers)")
	cmd.Flags().DurationVar(&settle, "settle", time.Second, "wait after each page load for background requests")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "login and page load timeout")
	cmd.Flags().IntVar(&maxLinks, "max-links", 50, "maximum nav links to follow")
	_ = cmd.MarkFlagRequired("as")
	return cmd
}

// keepLinks drops links that must not be visited (logout, excluded) and caps the count.
func keepLinks(links []browser.Link, f authmatrix.Filter, limit int) []browser.Link {
	var out []browser.Link
	for _, l := range links {
		skip := false
		for _, re := range f.Exclude {
			if re.MatchString(l.Href) || re.MatchString(l.Text) {
				skip = true
			}
		}
		if !skip && len(out) < limit {
			out = append(out, l)
		}
	}
	return out
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

func (a *app) finishRecording(cmd *cobra.Command, b proxy.Proxy, site, role string, level int, account string, startID int, marks []authmatrix.Mark, f authmatrix.Filter) error {
	items, err := b.History(cmd.Context(), proxy.HistoryQuery{Since: startID, Limit: 100000})
	if err != nil {
		return err
	}
	rec := &authmatrix.Recording{Site: site, Account: account, Role: role, Level: level, Created: time.Now().UTC(),
		Actions: authmatrix.Build(items, marks, f)}
	if err := authmatrix.SaveRecording(rec); err != nil {
		return err
	}
	type row struct {
		Action   string `json:"action"`
		Requests int    `json:"requests"`
		Example  string `json:"example"`
	}
	var rows []row
	for _, act := range rec.Actions {
		rows = append(rows, row{act.Name, len(act.Requests), act.Requests[0].Key()})
	}
	return a.print(rows, "action", "requests", "example")
}

func (a *app) matrixMarkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mark <action>",
		Short: "Manual recording: requests from now on belong to this action",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			site, _, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			st, err := authmatrix.LoadState(site)
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
			return a.print(map[string]any{"action": args[0], "from_id": id})
		},
	}
}

func (a *app) matrixStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Manual recording: finish and save the recording",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			site, s, err := a.cfg.Site(a.site)
			if err != nil {
				return err
			}
			st, err := authmatrix.LoadState(site)
			if err != nil {
				return err
			}
			role, r, _, ok := s.FindAccount(st.Account)
			if !ok {
				return fmt.Errorf("account %q is no longer in the config", st.Account)
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			f, err := a.filter(s)
			if err != nil {
				return err
			}
			if err := a.finishRecording(cmd, b, site, role, r.Level, st.Account, st.StartID, st.Marks, f); err != nil {
				return err
			}
			return authmatrix.ClearState(site)
		},
	}
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
	var xlsx, csvPath, jsonPath, template, sheet, sheets string
	var burpIssues, full bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the last run to xlsx (your Checklist template), Google Sheets, csv, json and/or Burp issues",
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
			out := map[string]any{}
			if xlsx != "" {
				if template == "" && a.cfg.Matrix != nil {
					template = expandHome(a.cfg.Matrix.Template)
				}
				if sheet == "" && a.cfg.Matrix != nil {
					sheet = a.cfg.Matrix.Sheet
				}
				if err := m.WriteXLSX(xlsx, authmatrix.XLSXOptions{Template: template, Sheet: sheet}); err != nil {
					return err
				}
				out["xlsx"] = xlsx
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
				if sheet == "" && a.cfg.Matrix != nil {
					sheet = a.cfg.Matrix.Sheet
				}
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
			if len(out) == 0 {
				return fmt.Errorf("choose at least one of --xlsx, --sheets, --csv, --json, --burp-issues")
			}
			return a.print(out)
		},
	}
	cmd.Flags().StringVar(&xlsx, "xlsx", "", "write an xlsx workbook")
	cmd.Flags().StringVar(&template, "template", "", "workbook to fill (default: config matrix.template), e.g. Checklist.xltx")
	cmd.Flags().StringVar(&sheet, "sheet", "", `tab to fill in --xlsx/--sheets (default "Auth Matrix")`)
	cmd.Flags().StringVar(&sheets, "sheets", "", "Google Sheet ID or URL to fill (see hiccup google)")
	cmd.Flags().StringVar(&csvPath, "csv", "", "write a csv with one row per account and request")
	cmd.Flags().StringVar(&jsonPath, "json", "", "write the matrix as json")
	cmd.Flags().BoolVar(&full, "full", false, "json: include base64 requests and responses")
	cmd.Flags().BoolVar(&burpIssues, "burp-issues", false, "add each finding to Burp as an issue (Burp Pro)")
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
