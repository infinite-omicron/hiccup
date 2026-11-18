package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/config"
)

func (a *app) throttleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "throttle", Short: "Per-host rate limits enforced inside Burp for every tool"}

	list := &cobra.Command{
		Use: "list", Short: "Show active throttle rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			rules, err := b.Throttle(cmd.Context())
			if err != nil {
				return err
			}
			return a.print(rules, "host", "rps", "burst", "jitter_ms")
		},
	}

	apply := &cobra.Command{
		Use: "apply", Short: "Push every site's throttle (and the selected site's User-Agent) from config", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			out, err := a.applySites(cmd.Context(), b)
			if err != nil {
				return err
			}
			return a.print(out)
		},
	}

	var rps float64
	var burst int
	var jitter string
	var save bool
	set := &cobra.Command{
		Use:   "set [site|host]",
		Short: "Set a rate limit for a site (all its hosts) or a single host (*.example.com for subdomains)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jit, err := parseRange(jitter)
			if err != nil {
				return err
			}
			t := &config.Throttle{RPS: rps, Burst: burst, JitterMS: jit}
			target := a.site
			if len(args) == 1 {
				target = args[0]
			}
			var rules []backend.ThrottleRule
			if _, s, err := a.cfg.Site(target); err == nil {
				t.Backoff, t.MaxConcurrency = keepBackoff(s.Throttle)
				s.Throttle = t
				rules = throttleRules(s.Hosts(), t)
				if save {
					if err := a.cfg.Save(); err != nil {
						return err
					}
				}
			} else if target != "" {
				// A bare host, or "*.example.com" for subdomains.
				rules = throttleRules([]string{strings.ToLower(target)}, t)
			} else {
				return err
			}
			b, err := a.be()
			if err != nil {
				return err
			}
			out, err := b.SetThrottle(cmd.Context(), rules)
			if err != nil {
				return err
			}
			return a.print(out, "host", "rps", "burst", "jitter_ms")
		},
	}
	set.Flags().Float64Var(&rps, "rps", 1, "requests per second (0 removes the limit)")
	set.Flags().IntVar(&burst, "burst", 1, "requests allowed back-to-back")
	set.Flags().StringVar(&jitter, "jitter", "0", "extra random delay in ms, e.g. 500-2000")
	set.Flags().BoolVar(&save, "save", false, "also save to the site's config")

	off := &cobra.Command{
		Use: "off", Short: "Remove all throttle rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.be()
			if err != nil {
				return err
			}
			if err := b.ClearThrottle(cmd.Context()); err != nil {
				return err
			}
			return a.print([]backend.ThrottleRule{})
		},
	}
	cmd.AddCommand(list, apply, set, off)
	return cmd
}

func keepBackoff(t *config.Throttle) (*config.Backoff, int) {
	if t == nil {
		return nil, 0
	}
	return t.Backoff, t.MaxConcurrency
}

// parseRange parses "500-2000" or "500" into [min, max].
func parseRange(s string) ([2]int, error) {
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return [2]int{}, fmt.Errorf("bad range %q", s)
	}
	b := a
	if found {
		if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a {
			return [2]int{}, fmt.Errorf("bad range %q", s)
		}
	}
	return [2]int{a, b}, nil
}

func (a *app) uaCmd() *cobra.Command {
	var scope string
	var save bool
	cmd := &cobra.Command{
		Use:   "ua [user-agent]",
		Short: "Set the User-Agent (and matching Sec-CH-UA hints); no argument shows the site's",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ua := a.siteUA()
			if len(args) == 1 {
				ua = args[0]
			}
			if ua == "" {
				return fmt.Errorf("no User-Agent given and the site has none configured")
			}
			if save {
				_, s, err := a.cfg.Site(a.site)
				if err != nil {
					return err
				}
				s.UserAgent = &config.UserAgent{Value: ua, Scope: scope}
				if err := a.cfg.Save(); err != nil {
					return err
				}
			}
			b, err := a.be()
			if err != nil {
				return err
			}
			setting := uaSetting(ua, scope)
			if err := b.SetUserAgent(cmd.Context(), setting); err != nil {
				return err
			}
			return a.print(setting)
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "browser", `"browser" (proxied traffic) or "all" (every Burp tool)`)
	cmd.Flags().BoolVar(&save, "save", false, "also save to the site's config")
	return cmd
}
