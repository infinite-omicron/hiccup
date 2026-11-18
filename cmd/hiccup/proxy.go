package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/proxy"
)

func (a *app) historyCmd() *cobra.Command {
	var q proxy.HistoryQuery
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List proxy history (newest last)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			rows, err := b.History(cmd.Context(), q)
			if err != nil {
				return err
			}
			return a.print(rows, "id", "method", "status", "length", "url")
		},
	}
	cmd.Flags().StringVar(&q.Contains, "contains", "", "only URLs containing this text")
	cmd.Flags().IntVar(&q.Since, "since", -1, "only items with id greater than this")
	cmd.Flags().IntVar(&q.Limit, "limit", 100, "maximum items (most recent)")
	cmd.Flags().BoolVar(&q.InScope, "in-scope", false, "only in-scope items")

	var raw bool
	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Show one proxy history item with request and response",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			e, err := b.HistoryItem(cmd.Context(), id)
			if err != nil {
				return err
			}
			if raw {
				os.Stdout.Write(e.Request())
				fmt.Println()
				fmt.Println()
				os.Stdout.Write(e.Response())
				return nil
			}
			return a.print(e)
		},
	}
	get.Flags().BoolVar(&raw, "raw", false, "print raw HTTP request and response instead of JSON")
	cmd.AddCommand(get)
	return cmd
}

func (a *app) interceptCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "intercept [on|off]",
		Short:     "Show or set Burp Proxy intercept",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			var on bool
			switch {
			case len(args) == 0:
				on, err = b.Intercept(cmd.Context())
			case args[0] == "on" || args[0] == "off":
				on, err = b.SetIntercept(cmd.Context(), args[0] == "on")
			default:
				return fmt.Errorf("want on or off, got %q", args[0])
			}
			if err != nil {
				return err
			}
			return a.print(map[string]bool{"enabled": on})
		},
	}
}

func (a *app) sitemapCmd() *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "sitemap [prefix]",
		Short: "List site map entries, optionally under a URL prefix",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}
			rows, err := b.SiteMap(cmd.Context(), prefix, full)
			if err != nil {
				return err
			}
			return a.print(rows, "method", "status", "url")
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "include base64 request/response")
	return cmd
}

// requestFlags builds a proxy.Request from curl-like flags or a raw HTTP file.
type requestFlags struct {
	url, method, data, dataFile, raw, host string
	headers                                []string
	port                                   int
	plainHTTP                              bool
}

func (f *requestFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.url, "url", "u", "", "target URL")
	cmd.Flags().StringVarP(&f.method, "method", "X", "", "HTTP method (default GET, or POST with -d)")
	cmd.Flags().StringArrayVarP(&f.headers, "header", "H", nil, `header "Name: value" (repeatable)`)
	cmd.Flags().StringVarP(&f.data, "data", "d", "", "request body")
	cmd.Flags().StringVar(&f.dataFile, "data-file", "", "read request body from file (- for stdin)")
	cmd.Flags().StringVar(&f.raw, "raw", "", "raw HTTP request file (- for stdin); target from --url or --host")
	cmd.Flags().StringVar(&f.host, "host", "", "target host for --raw")
	cmd.Flags().IntVar(&f.port, "port", 0, "target port for --raw (default 443, or 80 with --http)")
	cmd.Flags().BoolVar(&f.plainHTTP, "http", false, "use plain HTTP for --raw with --host")
}

func readArg(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func (f *requestFlags) build() (proxy.Request, error) {
	var r proxy.Request
	if f.raw != "" {
		b, err := readArg(f.raw)
		if err != nil {
			return r, err
		}
		r.RawB64 = base64.StdEncoding.EncodeToString(normalizeRaw(b))
		switch {
		case f.host != "":
			https := !f.plainHTTP
			r.Host, r.Port, r.HTTPS = f.host, f.port, &https
		case f.url != "":
			r.URL = f.url
		default:
			return r, fmt.Errorf("--raw needs --url or --host")
		}
		return r, nil
	}
	if f.url == "" {
		return r, fmt.Errorf("--url is required")
	}
	r.URL, r.Method = f.url, f.method
	for _, h := range f.headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return r, fmt.Errorf("bad header %q (want \"Name: value\")", h)
		}
		r.Headers = append(r.Headers, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
	}
	if f.dataFile != "" {
		b, err := readArg(f.dataFile)
		if err != nil {
			return r, err
		}
		r.BodyB64 = base64.StdEncoding.EncodeToString(b)
	} else {
		r.Body = f.data
	}
	if (r.Body != "" || r.BodyB64 != "") && r.Method == "" {
		r.Method = "POST"
	}
	return r, nil
}

// normalizeRaw converts a hand-written request's head to CRLF line endings.
func normalizeRaw(b []byte) []byte {
	s := string(b)
	if strings.Contains(s, "\r\n") {
		return b
	}
	head, body, found := strings.Cut(s, "\n\n")
	head = strings.ReplaceAll(strings.TrimRight(head, "\n"), "\n", "\r\n")
	if !found {
		return []byte(head + "\r\n\r\n")
	}
	return []byte(head + "\r\n\r\n" + body)
}

func (a *app) sendCmd() *cobra.Command {
	var f requestFlags
	var raw bool
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send a request through Burp (throttled, visible in Logger)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := f.build()
			if err != nil {
				return err
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			out, err := b.Send(cmd.Context(), []proxy.Request{r})
			if err != nil {
				return err
			}
			if raw && len(out) == 1 {
				_, err := os.Stdout.Write(out[0].Response())
				return err
			}
			if len(out) == 1 {
				return a.print(out[0], "status", "length", "elapsed_ms", "url")
			}
			return a.print(out, "status", "length", "elapsed_ms", "url")
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&raw, "raw-response", false, "print only the raw HTTP response")
	return cmd
}

// toolCmd builds `hiccup repeater` / `hiccup intruder`.
func (a *app) toolCmd(tool string) *cobra.Command {
	var f requestFlags
	var tab string
	cmd := &cobra.Command{
		Use:   tool,
		Short: "Send a request to Burp " + strings.ToUpper(tool[:1]) + tool[1:],
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := f.build()
			if err != nil {
				return err
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if tool == "repeater" {
				err = b.SendToRepeater(cmd.Context(), r, tab)
			} else {
				err = b.SendToIntruder(cmd.Context(), r, tab)
			}
			if err != nil {
				return err
			}
			return a.print(map[string]any{"ok": true, "tool": tool})
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&tab, "tab", "", "tab name")
	return cmd
}

func (a *app) scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "scan <crawl|audit|passive> <url>...",
		Short:     "Start a Burp Pro crawl or audit (exit 3 on Community)",
		Args:      cobra.MinimumNArgs(2),
		ValidArgs: []string{"crawl", "audit", "passive"},
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if err := b.Scan(cmd.Context(), args[0], args[1:]); err != nil {
				return err
			}
			return a.print(map[string]any{"ok": true, "mode": args[0], "urls": args[1:]})
		},
	}
}

func (a *app) scopeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scope", Short: "Manage Burp target scope"}
	add := &cobra.Command{
		Use: "add [host|url...]", Short: "Include hosts or URLs in scope (default: the site's scope); a bare host means https and http",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.scopeChange(cmd, args, false)
		},
	}
	exclude := &cobra.Command{
		Use: "exclude <host|url>...", Short: "Exclude hosts or URLs from scope", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.scopeChange(cmd, args, true)
		},
	}
	check := &cobra.Command{
		Use: "check <host|url>", Short: "Is a URL in scope? (a bare host checks https)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			urls, err := scopeURLs(args)
			if err != nil {
				return err
			}
			// A bare host checks its https URL.
			in, err := b.InScope(cmd.Context(), urls[0])
			if err != nil {
				return err
			}
			return a.print(map[string]any{"url": urls[0], "in_scope": in})
		},
	}
	cmd.AddCommand(add, exclude, check)
	return cmd
}

func (a *app) scopeChange(cmd *cobra.Command, urls []string, exclude bool) error {
	if len(urls) == 0 {
		_, s, err := a.cfg.Site(a.site)
		if err != nil {
			return err
		}
		urls = s.Scope
		if len(urls) == 0 {
			urls = []string{s.BaseURL}
		}
	}
	urls, err := scopeURLs(urls)
	if err != nil {
		return err
	}
	b, err := a.proxyClient()
	if err != nil {
		return err
	}
	if err := b.Scope(cmd.Context(), urls, exclude); err != nil {
		return err
	}
	return a.print(map[string]any{"ok": true, "urls": urls, "exclude": exclude})
}

func (a *app) issuesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "issues", Short: "List or add Burp issues"}
	list := &cobra.Command{
		Use: "list [prefix]", Short: "List issues, optionally under a URL prefix", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}
			issues, err := b.Issues(cmd.Context(), prefix)
			if err != nil {
				return err
			}
			return a.print(issues, "severity", "confidence", "name", "url")
		},
	}

	var is proxy.Issue
	var fromFile string
	add := &cobra.Command{
		Use:   "add",
		Short: "Add an issue (flags) or issues (--file JSON array or object, - for stdin)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var issues []proxy.Issue
			if fromFile != "" {
				data, err := readArg(fromFile)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(data, &issues); err != nil {
					var one proxy.Issue
					if err2 := json.Unmarshal(data, &one); err2 != nil {
						return fmt.Errorf("--file: %w", err)
					}
					issues = []proxy.Issue{one}
				}
			} else {
				if is.Name == "" || is.URL == "" {
					return fmt.Errorf("--name and --url are required")
				}
				is.Severity, is.Confidence = strings.ToUpper(is.Severity), strings.ToUpper(is.Confidence)
				issues = []proxy.Issue{is}
			}
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			n, err := addIssues(cmd, b, issues)
			if err != nil {
				return err
			}
			return a.print(map[string]any{"added": n})
		},
	}
	add.Flags().StringVar(&is.Name, "name", "", "issue name")
	add.Flags().StringVar(&is.URL, "url", "", "affected URL")
	add.Flags().StringVar(&is.Severity, "severity", "INFORMATION", "HIGH, MEDIUM, LOW, INFORMATION")
	add.Flags().StringVar(&is.Confidence, "confidence", "FIRM", "CERTAIN, FIRM, TENTATIVE")
	add.Flags().StringVar(&is.Detail, "detail", "", "detail (HTML allowed)")
	add.Flags().StringVar(&is.Remediation, "remediation", "", "remediation (HTML allowed)")
	add.Flags().StringVar(&fromFile, "file", "", "JSON issue(s) to add")
	cmd.AddCommand(list, add)
	return cmd
}

// addIssues posts issues in batches so huge imports don't build one giant request.
func addIssues(cmd *cobra.Command, b proxy.Proxy, issues []proxy.Issue) (int, error) {
	const batch = 50
	total := 0
	for i := 0; i < len(issues); i += batch {
		n, err := b.AddIssues(cmd.Context(), issues[i:min(i+batch, len(issues))])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
