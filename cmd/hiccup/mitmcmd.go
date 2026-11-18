package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy/burp"
	"github.com/infinite-omicron/hiccup/internal/proxy/mitm"
)

// mitmRuntime reads the URL and token the hiccup mitmproxy addon wrote.
func mitmRuntime() (string, string, error) {
	b, err := os.ReadFile(mitm.RuntimePath())
	if err != nil {
		return "", "", fmt.Errorf("mitmproxy with the hiccup addon isn't running (hiccup mitm start): %w", err)
	}
	var rt struct{ URL, Token string }
	if err := json.Unmarshal(b, &rt); err != nil {
		return "", "", err
	}
	return rt.URL, rt.Token, nil
}

func (a *app) mitmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mitm",
		Short: "Run mitmproxy with the hiccup addon (proxy \"mitmproxy\")",
		Long: "Starts mitmdump with hiccup's addon, which serves the same REST API as the Burp extension.\n" +
			"Select it with \"proxy\": \"mitmproxy\" in config or HICCUP_PROXY=mitmproxy.",
	}
	var wait time.Duration
	start := &cobra.Command{
		Use: "start", Short: "Start mitmdump with the hiccup addon and wait for its API", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := a.cfg.MitmSettings()
			if u, token, err := mitmRuntime(); err == nil {
				hctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
				_, herr := burp.New(u, token).Health(hctx)
				cancel()
				if herr == nil {
					return a.print(map[string]any{"already_running": true, "url": u, "proxy": m.Proxy})
				}
			}
			bin, err := exec.LookPath(m.Bin)
			if err != nil {
				return fmt.Errorf("mitmdump not found (brew install mitmproxy, or set mitm.bin): %w", err)
			}
			addon, err := mitm.AddonPath()
			if err != nil {
				return err
			}
			host, port, ok := strings.Cut(m.Proxy, ":")
			if !ok {
				return fmt.Errorf("mitm.proxy %q: want host:port", m.Proxy)
			}
			args := append([]string{"-s", addon, "--listen-host", host, "--listen-port", port,
				"--set", "hiccup_api_port=" + strconv.Itoa(m.APIPort), "--set", "hiccup_home=" + config.Home(),
				"--set", "ssl_insecure=true"}, m.Args...)
			_ = os.Remove(mitm.RuntimePath())
			logPath := filepath.Join(config.Home(), "mitm.log")
			logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer logf.Close()
			c := exec.Command(bin, args...)
			c.Stdout, c.Stderr = logf, logf
			detach(c)
			if err := c.Start(); err != nil {
				return err
			}
			pid := c.Process.Pid
			_ = c.Process.Release()
			ctx, cancel := context.WithTimeout(cmd.Context(), wait)
			defer cancel()
			for {
				if u, token, err := mitmRuntime(); err == nil {
					if _, err := burp.New(u, token).Health(ctx); err == nil {
						return a.print(map[string]any{"pid": pid, "url": u, "proxy": m.Proxy, "log": logPath})
					}
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("mitmdump started (pid %d) but the hiccup addon did not come up; see %s", pid, logPath)
				case <-time.After(300 * time.Millisecond):
				}
			}
		},
	}
	start.Flags().DurationVar(&wait, "wait", 30*time.Second, "how long to wait for the addon's API")

	stop := &cobra.Command{
		Use: "stop", Short: "Shut mitmproxy down", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, token, err := mitmRuntime()
			if err != nil {
				return err
			}
			if err := burp.New(u, token).Shutdown(cmd.Context()); err != nil {
				return err
			}
			return a.print(map[string]bool{"ok": true})
		},
	}
	cmd.AddCommand(start, stop)
	return cmd
}
