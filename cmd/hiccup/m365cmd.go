package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/m365"
)

func (a *app) m365Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "m365",
		Short: "Microsoft 365 sign-in for syncing the auth matrix workbook to OneDrive/SharePoint",
		Long: `Uses an Entra ID app registration of your own: a public client with "Allow public client
flows" enabled and the delegated Microsoft Graph permission Files.ReadWrite.All. Set
"microsoft": {"client_id": "...", "tenant": "..."} in config, or HICCUP_M365_CLIENT_ID and
HICCUP_M365_TENANT. The token is stored in ~/.hiccup/microsoft/ (0600).`,
	}
	settings := func() m365.Settings {
		tenant, clientID := a.cfg.MicrosoftSettings()
		return m365.Settings{Tenant: tenant, ClientID: clientID}
	}
	login := &cobra.Command{
		Use: "login", Short: "Sign in with a device code (works over SSH and on headless machines)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := m365.Login(cmd.Context(), settings(), func(verificationURL, code string) {
				fmt.Fprintf(os.Stderr, "hiccup: to sign in, open %s and enter the code %s\n", verificationURL, code)
			})
			if err != nil {
				return err
			}
			return a.print(map[string]bool{"ok": true})
		},
	}
	status := &cobra.Command{
		Use: "status", Short: "Check that hiccup can reach Microsoft Graph as you", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := m365.Client(cmd.Context(), settings())
			if err != nil {
				return err
			}
			me, err := m365.Me(cmd.Context(), client)
			if err != nil {
				return err
			}
			return a.print(me)
		},
	}
	logout := &cobra.Command{
		Use: "logout", Short: "Delete the saved Microsoft token", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := m365.Logout(); err != nil {
				return err
			}
			return a.print(map[string]bool{"ok": true})
		},
	}
	cmd.AddCommand(login, status, logout)
	return cmd
}
