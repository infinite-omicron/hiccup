package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/infinite-omicron/hiccup/internal/authmatrix"
	"github.com/infinite-omicron/hiccup/internal/plextrac"
	"github.com/infinite-omicron/hiccup/internal/secrets"
)

func (a *app) plextracCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plextrac",
		Short: "Pull your company's write-ups from PlexTrac's WriteupsDB and match them to findings",
		Long: `Read-only: hiccup never creates or changes anything in PlexTrac.

Set "plextrac": {"url": "https://<instance>.plextrac.com", "username": "...", "map": "<file>.json"}
in config (password: plaintext, env:VAR, keychain:... or empty to be asked). Sign in with
` + "`hiccup plextrac login`" + ` (asks for the MFA code), then ` + "`hiccup plextrac sync`" + ` copies the
write-ups to ~/.hiccup/plextrac/writeups.json, so searching and matching work offline.
The mapping file (finding -> write-up ID or title) is kept apart from config, in
~/.hiccup/plextrac/ unless "map" is an absolute or ~ path.`,
	}
	cmd.AddCommand(a.plextracLoginCmd(), a.plextracLogoutCmd(), a.plextracSyncCmd(), a.plextracWriteupsCmd(),
		a.plextracShowCmd(), a.plextracMatchCmd(), a.plextracMapCmd())
	return cmd
}

func (a *app) plextracClient() (*plextrac.Client, error) {
	return plextrac.New(a.cfg.PlexTracSettings().URL)
}

// plextracSession resumes the saved session for the configured instance.
func (a *app) plextracSession() (*plextrac.Client, *plextrac.Session, error) {
	c, err := a.plextracClient()
	if err != nil {
		return nil, nil, err
	}
	s, err := plextrac.LoadSession(c.URL)
	if err != nil {
		return nil, nil, err
	}
	c.Resume(s)
	return c, s, nil
}

func (a *app) plextracLoginCmd() *cobra.Command {
	var save bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to PlexTrac (asks for the password if not configured, and the MFA code)",
		Long: "Sessions last about 15 minutes; run `hiccup plextrac sync` while signed in.\n" +
			"--save-password stores the password in the OS keychain and points config at it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.plextracLogin(cmd.Context(), save)
			if err != nil {
				return err
			}
			return a.print(map[string]any{"ok": true, "url": s.URL, "expires": s.Expires})
		},
	}
	cmd.Flags().BoolVar(&save, "save-password", false, "store the password in the OS keychain and reference it from config")
	return cmd
}

func (a *app) plextracLogin(ctx context.Context, save bool) (*plextrac.Session, error) {
	p := a.cfg.PlexTracSettings()
	c, err := plextrac.New(p.URL)
	if err != nil {
		return nil, err
	}
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	user := p.Username
	if user == "" {
		if !interactive {
			return nil, errors.New(`no PlexTrac username: set "plextrac": {"username": "..."} or HICCUP_PLEXTRAC_USERNAME`)
		}
		fmt.Fprint(os.Stderr, "PlexTrac username: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		user = strings.TrimSpace(line)
	}
	password, err := secrets.Resolve(p.Password)
	if err != nil {
		return nil, err
	}
	typed := false
	if password == "" {
		if !interactive {
			return nil, errors.New("no PlexTrac password: set plextrac.password (env:, keychain:) or sign in from a terminal")
		}
		if password, err = readPassword(false); err != nil {
			return nil, err
		}
		typed = true
	}
	var mfa func() (string, error)
	if interactive {
		mfa = func() (string, error) {
			fmt.Fprint(os.Stderr, "PlexTrac MFA code: ")
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			return strings.TrimSpace(line), err
		}
	}
	s, err := c.Login(ctx, user, password, mfa)
	if err != nil {
		return nil, err
	}
	if err := c.Current(s).Save(); err != nil {
		return nil, err
	}
	if save && typed {
		ref, err := secrets.Store("plextrac/"+user, password)
		if err != nil {
			return nil, err
		}
		if a.cfg.PlexTrac == nil {
			a.cfg.PlexTrac = &p
		}
		a.cfg.PlexTrac.Username, a.cfg.PlexTrac.Password = user, ref
		if err := a.cfg.Save(); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "hiccup: password stored in the keychain (%s)\n", ref)
	}
	return s, nil
}

func (a *app) plextracLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "logout", Short: "Forget the PlexTrac session (synced write-ups are kept)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := plextrac.Logout(); err != nil {
				return err
			}
			return a.print(map[string]bool{"ok": true})
		},
	}
}

func (a *app) plextracSyncCmd() *cobra.Command {
	var repos []string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Copy the write-ups from PlexTrac (default: the repositories in config, else all)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, s, err := a.plextracSession()
			if errors.Is(err, plextrac.ErrSessionExpired) && term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintln(os.Stderr, "hiccup: signing in to PlexTrac")
				if _, err = a.plextracLogin(cmd.Context(), false); err != nil {
					return err
				}
				c, s, err = a.plextracSession()
			}
			if err != nil {
				return err
			}
			if len(repos) == 0 {
				repos = a.cfg.PlexTracSettings().Repositories
			}
			lib, err := c.Sync(cmd.Context(), repos)
			if err != nil {
				return err
			}
			if err := lib.Save(); err != nil {
				return err
			}
			_ = c.Current(s).Save()
			var rows []map[string]any
			for _, r := range lib.Repositories {
				n := 0
				for _, w := range lib.Writeups {
					if w.RepositoryID == r.ID {
						n++
					}
				}
				rows = append(rows, map[string]any{"repository": r.Name, "id": r.ID, "writeups": n})
			}
			return a.print(rows, "repository", "writeups", "id")
		},
	}
	cmd.Flags().StringSliceVar(&repos, "repository", nil, "only these repositories (names or IDs)")
	return cmd
}

func (a *app) plextracWriteupsCmd() *cobra.Command {
	var repo string
	cmd := &cobra.Command{
		Use:   "writeups [term...]",
		Short: "Search the synced write-ups (title, tags and description contain every term)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lib, err := plextrac.LoadLibrary()
			if err != nil {
				return err
			}
			var rows []map[string]any
			for _, w := range lib.Search(args, repo) {
				rows = append(rows, map[string]any{"id": w.ID, "title": w.Title, "severity": w.Severity, "repository": w.Repository})
			}
			return a.print(rows, "id", "severity", "title", "repository")
		},
	}
	cmd.Flags().StringVar(&repo, "repository", "", "only this repository (name or ID)")
	return cmd
}

func (a *app) plextracShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id|title>",
		Short: "Print a write-up (Markdown; --format json for the raw fields)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lib, err := plextrac.LoadLibrary()
			if err != nil {
				return err
			}
			ref := strings.Join(args, " ")
			w := lib.Find(ref)
			if w == nil {
				if hits := lib.Search(args, ""); len(hits) == 1 {
					w = &hits[0]
				} else if len(hits) > 1 {
					return fmt.Errorf("%d write-ups match %q; use an ID (hiccup plextrac writeups %s)", len(hits), ref, ref)
				}
			}
			if w == nil {
				return fmt.Errorf("no write-up %q (hiccup plextrac writeups)", ref)
			}
			if f := cmd.Flag("format"); f != nil && f.Changed && a.format == "json" {
				return a.print(w)
			}
			fmt.Print(w.Markdown())
			return nil
		},
	}
}

func (a *app) plextracMatchCmd() *cobra.Command {
	var burp, matrix, siteOnly, show bool
	var names []string
	cmd := &cobra.Command{
		Use:   "match",
		Short: "Match findings to write-ups: Burp issues, the auth matrix, or --name",
		Long: "Each finding is matched by the mapping file first, then by an exact title, then by the\n" +
			"closest title (score 0-1; below 0.5 it's unmatched, with suggestions). Teach it with\n" +
			"`hiccup plextrac map <finding> <write-up>`. Burp issues marked false positive are skipped.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !burp && !matrix && len(names) == 0 {
				return errors.New("choose what to match: --burp, --matrix and/or --name")
			}
			lib, err := plextrac.LoadLibrary()
			if err != nil {
				return err
			}
			mapping, err := plextrac.LoadMapping(plextrac.MappingPath(a.cfg.PlexTracSettings().Map))
			if err != nil {
				return err
			}
			var findings []plextrac.Finding
			for _, n := range names {
				findings = append(findings, plextrac.Finding{Name: n, Source: "name"})
			}
			if burp {
				f, err := a.burpFindings(cmd.Context(), siteOnly)
				if err != nil {
					return err
				}
				findings = append(findings, f...)
			}
			if matrix {
				f, err := a.matrixFindings()
				if err != nil {
					return err
				}
				findings = append(findings, f...)
			}
			matches := lib.MatchAll(findings, mapping)
			if show {
				for _, m := range matches {
					fmt.Printf("\n---\n> %s (%s", m.Finding.Name, m.How)
					if m.How == "fuzzy" {
						fmt.Printf(" %.2f", m.Score)
					}
					fmt.Println(")")
					if m.Writeup != nil {
						fmt.Print(m.Writeup.Markdown())
					} else {
						fmt.Println("\nNo write-up matched." + suggestionText(m))
					}
				}
				return nil
			}
			var rows []map[string]any
			for _, m := range matches {
				row := map[string]any{"finding": m.Finding.Name, "source": m.Finding.Source, "how": m.How, "score": m.Score}
				if m.Writeup != nil {
					row["writeup"], row["id"] = m.Writeup.Title, m.Writeup.ID
				} else {
					row["writeup"] = strings.TrimPrefix(suggestionText(m), " ")
				}
				if m.Problem != "" {
					row["problem"] = m.Problem
				}
				if a.format == "json" {
					row["suggestions"] = m.Suggestions
				}
				rows = append(rows, row)
			}
			return a.print(rows, "finding", "how", "score", "writeup", "id", "source")
		},
	}
	cmd.Flags().BoolVar(&burp, "burp", false, "Burp's issues (not marked false positive)")
	cmd.Flags().BoolVar(&siteOnly, "site-only", false, "--burp: only issues on the site's base_url host")
	cmd.Flags().BoolVar(&matrix, "matrix", false, "the last auth matrix run's finding types")
	cmd.Flags().StringArrayVar(&names, "name", nil, "a finding title to match (repeatable)")
	cmd.Flags().BoolVar(&show, "show", false, "print each matched write-up in full")
	return cmd
}

func suggestionText(m plextrac.Match) string {
	if len(m.Suggestions) == 0 {
		return ""
	}
	var s []string
	for _, x := range m.Suggestions {
		s = append(s, fmt.Sprintf("%s (%.2f)", x.Title, x.Score))
	}
	return " closest: " + strings.Join(s, "; ")
}

// burpFindings groups Burp's issues by name, skipping false positives.
func (a *app) burpFindings(ctx context.Context, siteOnly bool) ([]plextrac.Finding, error) {
	b, err := a.proxyClient()
	if err != nil {
		return nil, err
	}
	issues, err := b.Issues(ctx, "")
	if err != nil {
		return nil, err
	}
	var hostRe *regexp.Regexp
	if siteOnly {
		_, s, err := a.cfg.Site(a.site)
		if err != nil {
			return nil, err
		}
		host := strings.TrimPrefix(strings.TrimPrefix(s.BaseURL, "https://"), "http://")
		host = strings.SplitN(host, "/", 2)[0]
		hostRe = regexp.MustCompile(`(?i)^https?://` + regexp.QuoteMeta(host) + `(:\d+)?(/|$)`)
	}
	counts := map[string]int{}
	for _, i := range issues {
		if strings.EqualFold(i.Severity, "FALSE_POSITIVE") || (hostRe != nil && !hostRe.MatchString(i.URL)) {
			continue
		}
		counts[i.Name]++
	}
	var out []plextrac.Finding
	for n, c := range counts {
		out = append(out, plextrac.Finding{Name: n, Source: "burp", Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// matrixFindings lists the finding types in the last auth matrix run.
func (a *app) matrixFindings() ([]plextrac.Finding, error) {
	site, _, err := a.cfg.Site(a.site)
	if err != nil {
		return nil, err
	}
	m, err := authmatrix.LoadMatrix(site)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, act := range m.Actions {
		for _, r := range act.Requests {
			for _, c := range r.Cells {
				if c.Finding != "" {
					counts[c.Finding]++
				}
			}
		}
	}
	var out []plextrac.Finding
	for code, c := range counts {
		out = append(out, plextrac.Finding{Name: authmatrix.FindingLabel(code), Aliases: []string{code}, Source: "matrix", Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (a *app) plextracMapCmd() *cobra.Command {
	var list bool
	var remove string
	cmd := &cobra.Command{
		Use:   "map [<finding> <write-up id or title>]",
		Short: "Map a finding name to a write-up, in the mapping file (--list, --remove)",
		Long: "Finding names are Burp issue names, auth matrix codes (vertical, horizontal,\n" +
			"forceful-browsing, review) or their labels. The file is the config's plextrac.map\n" +
			"(relative to ~/.hiccup/plextrac/; default mapping.json).",
		Args: cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := plextrac.MappingPath(a.cfg.PlexTracSettings().Map)
			m, err := plextrac.LoadMapping(path)
			if err != nil {
				return err
			}
			switch {
			case remove != "":
				if _, ok := m[remove]; !ok {
					return fmt.Errorf("%q isn't in %s", remove, path)
				}
				delete(m, remove)
			case len(args) == 2:
				ref := args[1]
				if lib, err := plextrac.LoadLibrary(); err == nil {
					w := lib.Find(ref)
					if w == nil {
						return fmt.Errorf("no synced write-up %q (hiccup plextrac writeups)", ref)
					}
					ref = w.ID
				}
				m[args[0]] = ref
			case list || len(args) == 0:
				var rows []map[string]string
				for _, k := range sortedMapKeys(m) {
					rows = append(rows, map[string]string{"finding": k, "writeup": m[k]})
				}
				return a.print(rows, "finding", "writeup")
			default:
				return errors.New("usage: hiccup plextrac map <finding> <write-up id or title>")
			}
			if err := m.Save(path); err != nil {
				return err
			}
			return a.print(map[string]any{"file": path, "entries": len(m)})
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list the mapping")
	cmd.Flags().StringVar(&remove, "remove", "", "remove this finding from the mapping")
	return cmd
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
