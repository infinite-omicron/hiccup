package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/bapp"
)

func (a *app) bappCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "bapp", Short: "Find and install extensions from PortSwigger's BApp Store"}
	var refresh bool
	search := &cobra.Command{
		Use: "search [text]", Short: "Search the BApp Store by name", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := bapp.Index(cmd.Context(), refresh)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				entries = bapp.Search(entries, args[0])
			}
			return a.print(entries, "name", "uuid")
		},
	}
	search.Flags().BoolVar(&refresh, "refresh", false, "refetch the store index (cached for a day)")

	var save bool
	install := &cobra.Command{
		Use:   "install [name|uuid...]",
		Short: "Download BApps and load them into the running Burp (default: config burp.bapps)",
		Long: "Downloads each BApp to ~/.hiccup/bapps, unpacks it and loads its entry point. Python and Ruby\n" +
			"BApps need Jython/JRuby: if Burp has none configured, hiccup downloads it from Maven Central.\n" +
			"Pro-only BApps are skipped on Burp Community.",
		RunE: func(cmd *cobra.Command, args []string) error {
			names := args
			if len(names) == 0 {
				names = a.cfg.Burp.BApps
			}
			if len(names) == 0 {
				return fmt.Errorf("name BApps to install, or list them in config burp.bapps")
			}
			b, err := a.be()
			if err != nil {
				return err
			}
			rows, err := a.installBApps(cmd, b, names, save)
			if err != nil {
				return err
			}
			return a.print(rows, "name", "version", "type", "status")
		},
	}
	install.Flags().BoolVar(&save, "save", false, "also add the BApps to config burp.bapps")
	cmd.AddCommand(search, install)
	return cmd
}

type bappRow struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Status  string `json:"status"` // installed, already, skipped: ...
	Entry   string `json:"entry,omitempty"`
}

// installBApps downloads the named BApps and loads them in one batch, so Burp
// reloads its extensions only once.
func (a *app) installBApps(cmd *cobra.Command, b backend.Backend, names []string, save bool) ([]bappRow, error) {
	ctx := cmd.Context()
	h, err := b.Health(ctx)
	if err != nil {
		return nil, err
	}
	pro := h["edition"] == "PROFESSIONAL"
	entries, err := bapp.Index(ctx, false)
	if err != nil {
		return nil, err
	}
	var rows []bappRow
	var exts []backend.Extension
	needs := map[string]bool{}
	for _, n := range names {
		e, err := bapp.Find(entries, n)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "hiccup: downloading %s\n", e.Name)
		d, err := bapp.Download(ctx, e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name, err)
		}
		row := bappRow{Name: d.Name, UUID: d.UUID, Version: d.ScreenVersion, Type: d.Type(), Entry: d.Entry}
		if d.ProOnly && !pro {
			row.Status = "skipped: requires Burp Suite Professional"
			rows = append(rows, row)
			continue
		}
		needs[d.Type()] = true
		exts = append(exts, backend.Extension{Path: d.Entry, Type: d.Type(), Name: d.Name})
		rows = append(rows, row)
	}
	if needs["python"] {
		if err := a.ensureRuntime(cmd, b, "python", "location_of_jython_standalone_jar_file", "org.python", "jython-standalone", "jython"); err != nil {
			return nil, err
		}
	}
	if needs["ruby"] {
		if err := a.ensureRuntime(cmd, b, "ruby", "location_of_jruby_jar_file", "org.jruby", "jruby-complete", "jruby"); err != nil {
			return nil, err
		}
	}
	if len(exts) > 0 {
		r, err := a.installAndWait(cmd, b, exts, 2*time.Minute)
		if err != nil {
			return nil, err
		}
		status := map[string]string{}
		for _, p := range r.Added {
			status[p] = "installed"
		}
		for _, p := range r.Already {
			status[p] = "already installed"
		}
		for i := range rows {
			if s, ok := status[rows[i].Entry]; ok {
				rows[i].Status = s
			}
		}
	}
	if save {
		for _, r := range rows {
			if !slices.Contains(a.cfg.Burp.BApps, r.Name) {
				a.cfg.Burp.BApps = append(a.cfg.Burp.BApps, r.Name)
			}
		}
		if err := a.cfg.Save(); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// ensureRuntime points Burp at a Jython or JRuby jar, downloading one from
// Maven Central when Burp has none configured (or the configured file is gone).
func (a *app) ensureRuntime(cmd *cobra.Command, b backend.Backend, lang, key, group, artifact, sub string) error {
	raw, err := b.UserOptions(cmd.Context(), "user_options.extender."+lang)
	if err != nil {
		return err
	}
	var opts struct {
		UserOptions struct {
			Extender map[string]map[string]any `json:"extender"`
		} `json:"user_options"`
	}
	if err := json.Unmarshal(raw, &opts); err != nil {
		return err
	}
	section := opts.UserOptions.Extender[lang]
	if section == nil {
		section = map[string]any{}
	}
	if p, _ := section[key].(string); p != "" {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "hiccup: downloading %s:%s for %s extensions\n", group, artifact, lang)
	jar, err := bapp.MavenJar(cmd.Context(), group, artifact, sub)
	if err != nil {
		return err
	}
	section[key] = jar
	frag, err := json.Marshal(map[string]any{"user_options": map[string]any{"extender": map[string]any{lang: section}}})
	if err != nil {
		return err
	}
	return b.SetUserOptions(cmd.Context(), frag)
}
