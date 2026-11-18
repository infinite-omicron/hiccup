package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/secrets"
)

func (a *app) configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Manage ~/.hiccup/config.json"}
	path := &cobra.Command{
		Use: "path", Short: "Print the config file path", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return a.print(map[string]string{"config": config.Path(), "runtime": config.RuntimePath()})
		},
	}
	var force bool
	initCmd := &cobra.Command{
		Use: "init", Short: "Write an example config (0600)", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if _, err := os.Stat(config.Path()); err == nil && !force {
				return fmt.Errorf("%s exists (use --force to overwrite)", config.Path())
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := config.Example().Save(); err != nil {
				return err
			}
			return a.print(map[string]string{"written": config.Path()})
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	show := &cobra.Command{
		Use: "show", Short: "Print the effective config with plaintext passwords redacted", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c := *a.cfg
			c.Burp.Token = redact(c.Burp.Token)
			sites := map[string]*config.Site{}
			for n, s := range a.cfg.Sites {
				cp := *s
				cp.Roles = map[string]*config.Role{}
				for rn, r := range s.Roles {
					rc := &config.Role{Level: r.Level}
					for _, acct := range r.Accounts {
						ac := *acct
						if secrets.Kind(ac.Password) == "plain" {
							ac.Password = redact(ac.Password)
						}
						rc.Accounts = append(rc.Accounts, &ac)
					}
					cp.Roles[rn] = rc
				}
				sites[n] = &cp
			}
			c.Sites = sites
			return a.print(c)
		},
	}
	cmd.AddCommand(path, initCmd, show)
	return cmd
}

func redact(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

func (a *app) credsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "creds", Short: "Per-site test accounts and where their passwords live"}
	list := &cobra.Command{
		Use: "list [site]", Short: "List accounts by role (never prints secrets)", Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := a.site
			if len(args) == 1 {
				name = args[0]
			}
			site, s, err := a.cfg.Site(name)
			if err != nil {
				return err
			}
			type row struct {
				Site     string `json:"site"`
				Role     string `json:"role"`
				Level    int    `json:"level"`
				Account  string `json:"account"`
				Username string `json:"username,omitempty"`
				Password string `json:"password"`
				Resolves bool   `json:"resolves"`
			}
			var rows []row
			for rn, r := range s.Roles {
				for _, acct := range r.Accounts {
					_, err := secrets.Resolve(acct.Password)
					rows = append(rows, row{site, rn, r.Level, acct.Name, acct.Username, secrets.Kind(acct.Password), err == nil})
				}
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Level != rows[j].Level {
					return rows[i].Level > rows[j].Level
				}
				return rows[i].Account < rows[j].Account
			})
			return a.print(rows, "role", "level", "account", "username", "password", "resolves")
		},
	}

	var stdin bool
	set := &cobra.Command{
		Use:   "set <site> <account>",
		Short: "Store an account's password in the OS keychain and reference it from config",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			site, s, err := a.cfg.Site(args[0])
			if err != nil {
				return err
			}
			_, _, acct, ok := s.FindAccount(args[1])
			if !ok {
				return fmt.Errorf("no account %q in site %q", args[1], site)
			}
			pw, err := readPassword(stdin)
			if err != nil {
				return err
			}
			ref, err := secrets.Store(site+"/"+acct.Name, pw)
			if err != nil {
				return err
			}
			acct.Password = ref
			if err := a.cfg.Save(); err != nil {
				return err
			}
			return a.print(map[string]string{"site": site, "account": acct.Name, "password": ref})
		},
	}
	set.Flags().BoolVar(&stdin, "password-stdin", false, "read the password from stdin")
	cmd.AddCommand(list, set)
	return cmd
}

func readPassword(stdin bool) (string, error) {
	if !stdin && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
