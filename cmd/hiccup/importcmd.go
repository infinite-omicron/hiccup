package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/importers"
)

func (a *app) importCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "import", Short: "Import other tools' findings as Burp issues"}
	var dry bool
	nuclei := &cobra.Command{
		Use:   "nuclei [file|-]",
		Short: "Import `nuclei -jsonl` output (default: stdin)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var r io.Reader = os.Stdin
			if len(args) == 1 && args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			return a.importNuclei(cmd, r, dry)
		},
	}
	nuclei.Flags().BoolVar(&dry, "dry-run", false, "print the issues instead of adding them")
	cmd.AddCommand(nuclei)
	return cmd
}

func (a *app) importNuclei(cmd *cobra.Command, r io.Reader, dry bool) error {
	issues, err := importers.Nuclei(r)
	if err != nil {
		return err
	}
	if dry {
		return a.print(issues, "severity", "name", "url")
	}
	b, err := a.be()
	if err != nil {
		return err
	}
	n, err := addIssues(cmd, b, issues)
	if err != nil {
		return err
	}
	return a.print(map[string]any{"tool": "nuclei", "added": n})
}

func (a *app) runCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "run", Short: "Run an external tool through Burp with the site's throttle and User-Agent"}
	var noProxy, noImport bool
	nuclei := &cobra.Command{
		Use:   "nuclei [nuclei flags...]",
		Short: "Run nuclei through Burp's proxy, then import its findings",
		Long: "Adds -proxy (Burp's listener), rate limits from the site's throttle, a User-Agent header,\n" +
			"a longer -timeout (requests may wait in Burp's throttle) and -jsonl output, then imports results.\n" +
			"Example: hiccup run nuclei -- -u https://app.example.test -tags exposure",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runNuclei(cmd, args, noProxy, noImport)
		},
	}
	nuclei.Flags().BoolVar(&noProxy, "no-proxy", false, "don't route nuclei through Burp")
	nuclei.Flags().BoolVar(&noImport, "no-import", false, "don't import results into Burp")
	cmd.AddCommand(nuclei)
	return cmd
}

func (a *app) runNuclei(cmd *cobra.Command, args []string, noProxy, noImport bool) error {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return fmt.Errorf("nuclei not found in PATH (brew install nuclei)")
	}
	b, err := a.be()
	if err != nil {
		return err
	}
	if _, err := a.applySites(cmd.Context(), b); err != nil {
		return err
	}

	out, err := os.CreateTemp("", "hiccup-nuclei-*.jsonl")
	if err != nil {
		return err
	}
	out.Close()
	defer os.Remove(out.Name())

	extra := []string{"-jsonl", "-o", out.Name(), "-duc"}
	has := func(flags ...string) bool {
		return slices.ContainsFunc(args, func(s string) bool { return slices.Contains(flags, s) })
	}
	if !noProxy && !has("-p", "-proxy") {
		h, err := b.Health(cmd.Context())
		if err != nil {
			return err
		}
		if p, _ := h["proxy"].(string); p != "" {
			extra = append(extra, "-proxy", "http://"+p)
		}
	}
	if _, s, err := a.cfg.Site(a.site); err == nil {
		t, err := s.EffectiveThrottle()
		if err != nil {
			return err
		}
		if t != nil && t.RPS > 0 && !has("-rl", "-rate-limit") {
			extra = append(extra, nucleiRate(t.RPS)...)
			if !has("-c", "-concurrency") {
				extra = append(extra, "-c", "1", "-bs", "1")
			}
			if !has("-timeout") {
				// Requests may wait in Burp's throttle before they are sent.
				extra = append(extra, "-timeout", strconv.Itoa(max(30, int(math.Ceil(10/t.RPS)))))
			}
		}
		if ua := s.EffectiveUserAgent(); ua != nil && ua.Value != "" {
			extra = append(extra, "-H", "User-Agent: "+ua.Value)
		}
	}

	full := append(slices.Clone(args), extra...)
	fmt.Fprintf(os.Stderr, "hiccup: %s %s\n", filepath.Base(bin), strings.Join(full, " "))
	c := exec.CommandContext(cmd.Context(), bin, full...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stderr, os.Stderr
	start := time.Now()
	runErr := c.Run()
	fmt.Fprintf(os.Stderr, "hiccup: nuclei finished in %s\n", time.Since(start).Round(time.Second))

	if noImport {
		return runErr
	}
	f, err := os.Open(out.Name())
	if err != nil {
		return err
	}
	defer f.Close()
	if err := a.importNuclei(cmd, f, false); err != nil {
		return err
	}
	return runErr
}

// nucleiRate expresses rps as nuclei's -rl count per -rld duration.
func nucleiRate(rps float64) []string {
	if rps >= 1 {
		return []string{"-rl", strconv.Itoa(int(rps)), "-rld", "1s"}
	}
	return []string{"-rl", "1", "-rld", (time.Duration(float64(time.Second) / rps)).Round(time.Millisecond).String()}
}
