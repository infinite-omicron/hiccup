// Command hiccup drives an intercepting proxy (Burp first) from scripts and agents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/proxy/burp"
	"github.com/infinite-omicron/hiccup/internal/proxy/mitm"
	"github.com/infinite-omicron/hiccup/internal/proxy/zap"
	"github.com/infinite-omicron/hiccup/internal/secrets"
)

var version = "dev"

// app holds global flags and lazily-built state shared by subcommands.
type app struct {
	format  string
	site    string
	burpURL string
	token   string
	cfg     *config.Config
	proxy   proxy.Proxy
}

func main() {
	a := &app{}
	root := &cobra.Command{
		Use:           "hiccup",
		Short:         "Drive Burp, ZAP or mitmproxy from scripts and agents",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			a.cfg = cfg
			return nil
		},
	}
	root.PersistentFlags().StringVar(&a.format, "format", "json", "output format: json or table")
	root.PersistentFlags().StringVar(&a.site, "site", "", "site from config (default: $HICCUP_SITE, or the only site)")
	root.PersistentFlags().StringVar(&a.burpURL, "burp-url", "", "hiccup extension URL (default: from ~/.hiccup/burp.json)")
	root.PersistentFlags().StringVar(&a.token, "token", "", "hiccup extension token (default: from ~/.hiccup/burp.json)")

	root.AddCommand(
		a.statusCmd(),
		a.browserCmd(),
		a.historyCmd(),
		a.interceptCmd(),
		a.sitemapCmd(),
		a.sendCmd(), a.toolCmd("repeater"), a.toolCmd("intruder"),
		a.scanCmd(),
		a.scopeCmd(),
		a.issuesCmd(),
		a.throttleCmd(),
		a.uaCmd(),
		a.importCmd(),
		a.runCmd(),
		a.configCmd(),
		a.credsCmd(),
		a.loginCmd(),
		a.matrixCmd(),
		a.burpCmd(),
		a.bappCmd(),
		a.mitmCmd(),
		a.googleCmd(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := root.ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hiccup:", err)
		if errors.Is(err, proxy.ErrUnsupported) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

// proxyClient connects to the configured proxy (burp, zap or mitmproxy).
func (a *app) proxyClient() (proxy.Proxy, error) {
	if a.proxy != nil {
		return a.proxy, nil
	}
	switch name := a.cfg.ProxyName(); name {
	case "burp":
		url, token := a.cfg.BurpEndpoint()
		if a.burpURL != "" {
			url = a.burpURL
		}
		if a.token != "" {
			token = a.token
		}
		if token == "" {
			return nil, fmt.Errorf("no Burp token: load hiccup-burp.jar in Burp (it writes %s) or set HICCUP_BURP_TOKEN", config.RuntimePath())
		}
		a.proxy = burp.New(url, token)
	case "zap":
		u, keyRef, listener := a.cfg.ZapEndpoint()
		key, err := secrets.Resolve(keyRef)
		if err != nil {
			return nil, fmt.Errorf("ZAP API key: %w", err)
		}
		a.proxy = zap.New(u, key, listener)
	case "mitmproxy", "mitm":
		u, token, err := mitmRuntime()
		if err != nil {
			return nil, err
		}
		a.proxy = mitm.New(u, token, a.cfg.MitmSettings().Proxy)
	default:
		return nil, fmt.Errorf("unknown proxy %q (burp, zap or mitmproxy)", name)
	}
	return a.proxy, nil
}

// print writes v as indented JSON, or as a table of the given columns when --format table.
func (a *app) print(v any, cols ...string) error {
	if a.format == "table" && len(cols) > 0 {
		return printTable(v, cols)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func printTable(v any, cols []string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		var one map[string]any
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		rows = []map[string]any{one}
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, strings.ToUpper(strings.Join(cols, "\t")))
	for _, r := range rows {
		vals := make([]string, len(cols))
		for i, c := range cols {
			if x, ok := r[c]; ok && x != nil {
				vals[i] = fmt.Sprint(x)
			}
		}
		fmt.Fprintln(w, strings.Join(vals, "\t"))
	}
	return w.Flush()
}
