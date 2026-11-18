package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/gsheets"
)

func (a *app) googleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "google",
		Short: "Google Sheets access for `matrix export --sheets`",
		Long: "Credentials, in order:\n" +
			"  - a service account key at " + gsheets.CredentialsPath() + " (share the sheet with its email), or\n" +
			"  - a \"Desktop app\" OAuth client there, plus `hiccup google login` once, or\n" +
			"  - Google Application Default Credentials with the spreadsheets scope.\n" +
			"$HICCUP_GOOGLE_CREDENTIALS overrides the credentials path. Access is limited to spreadsheets.",
	}
	login := &cobra.Command{
		Use: "login", Short: "Sign in with your OAuth client (opens a browser)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := gsheets.Login(cmd.Context(), func(url string) {
				fmt.Fprintf(os.Stderr, "hiccup: open this URL to sign in to Google:\n%s\n", url)
			})
			if err != nil {
				return err
			}
			return a.print(map[string]any{"ok": true})
		},
	}
	status := &cobra.Command{
		Use: "status", Short: "Check that Google credentials are usable", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := gsheets.Client(cmd.Context()); err != nil {
				return err
			}
			return a.print(map[string]any{"ok": true, "credentials": gsheets.CredentialsPath()})
		},
	}
	cmd.AddCommand(login, status)
	return cmd
}
