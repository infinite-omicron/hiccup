package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
	"github.com/infinite-omicron/hiccup/internal/proxy/burp"
)

func (a *app) burpCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "burp", Short: "Start Burp with hiccup loaded, and install extensions"}

	var jar, install, javaBin string
	var headless, acceptEULA, noBApps, preload bool
	var wait time.Duration
	var extraArgs []string
	start := &cobra.Command{
		Use:   "start",
		Short: "Launch Burp with hiccup-burp.jar preloaded (via --user-config-file) and wait for the API",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if url, token := a.cfg.BurpEndpoint(); token != "" {
				hctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
				h, err := burp.New(url, token).Health(hctx)
				cancel()
				if err == nil {
					out := map[string]any{"already_running": true, "url": url, "health": h}
					if !noBApps && len(a.cfg.Burp.BApps) > 0 {
						b, err := a.proxyClient()
						if err != nil {
							return err
						}
						if out["bapps"], err = a.installBApps(cmd, b, a.cfg.Burp.BApps, false); err != nil {
							return err
						}
					}
					return a.print(out)
				}
			}
			if jar == "" {
				jar = a.cfg.Burp.Jar
			}
			if jar == "" {
				jar = filepath.Join(config.Home(), "hiccup-burp.jar")
			}
			jar = expandHome(jar)
			if _, err := os.Stat(jar); err != nil {
				return fmt.Errorf("extension jar: %w (build it with `make jar` and copy to %s, or pass --jar)", err, jar)
			}
			java, burpJar, err := findBurp(install)
			if err != nil {
				return err
			}
			if javaBin != "" {
				java = javaBin
			}
			// A user config file's extension list replaces Burp's in-memory list.
			// Headless Burp never saves user settings, so that is harmless there;
			// a GUI Burp might save it over the user's own extensions, so only
			// preload when asked to.
			var userCfg string
			if headless || preload {
				if !headless {
					fmt.Fprintln(os.Stderr, "hiccup: warning: --preload may replace the extensions saved in your Burp settings")
				}
				if userCfg, err = writeUserConfig(jar); err != nil {
					return err
				}
			}
			// The old runtime file belongs to a previous Burp; wait for the new one.
			_ = os.Remove(config.RuntimePath())

			// Mirrors the JVM options of Burp's own install4j launcher.
			args := []string{
				"--add-opens", "java.base/java.lang=ALL-UNNAMED",
				"--add-opens", "java.base/javax.crypto=ALL-UNNAMED",
				"--add-opens", "java.desktop/javax.swing=ALL-UNNAMED",
				"--add-opens", "java.desktop/java.awt=ALL-UNNAMED",
				"--add-opens", "java.desktop/java.awt.color=ALL-UNNAMED",
				"--add-opens", "jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
				"-Djna.boot.library.path=" + filepath.Join(filepath.Dir(burpJar), "native"),
				"-Djna.noclasspath=true", "-Djna.nounpack=true",
			}
			if headless {
				args = append(args, "-Djava.awt.headless=true")
			}
			args = append(args, "-cp", burpJar, "burp.StartBurp")
			if userCfg != "" {
				args = append(args, "--user-config-file="+userCfg)
			}
			args = append(args, extraArgs...)
			logPath := filepath.Join(config.Home(), "burp.log")
			logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer logf.Close()
			c := exec.Command(java, args...)
			c.Stdout, c.Stderr = logf, logf
			stdin, err := c.StdinPipe()
			if err != nil {
				return err
			}
			detach(c)
			if err := c.Start(); err != nil {
				return err
			}
			pid := c.Process.Pid
			_ = c.Process.Release()

			ctx, cancel := context.WithTimeout(cmd.Context(), wait)
			defer cancel()
			go answerPrompts(ctx, logPath, stdin, acceptEULA)
			cfg, err := waitRuntime(ctx, "")
			if err != nil {
				hint := ""
				if b, _ := os.ReadFile(logPath); strings.Contains(string(b), "Do you accept the license agreement") {
					hint = "; Burp is waiting for its EULA to be accepted: run it once yourself, or pass --accept-eula"
				} else if userCfg == "" {
					hint = fmt.Sprintf("; if hiccup isn't loaded in this Burp yet, add it once: Extensions → Installed → Add → Java → %s (Burp reloads it on every start)", jar)
				}
				return fmt.Errorf("burp started (pid %d) but the hiccup API did not come up: %w (see %s)%s", pid, err, logPath, hint)
			}
			url, _ := cfg.BurpEndpoint()
			out := map[string]any{"pid": pid, "url": url, "log": logPath, "headless": headless}
			if !noBApps && len(a.cfg.Burp.BApps) > 0 {
				b, err := a.proxyClient()
				if err != nil {
					return err
				}
				rows, err := a.installBApps(cmd, b, a.cfg.Burp.BApps, false)
				if err != nil {
					return fmt.Errorf("burp is running, but installing BApps failed: %w", err)
				}
				out["bapps"] = rows
			}
			return a.print(out)
		},
	}
	start.Flags().StringVar(&jar, "jar", "", "hiccup-burp.jar (default: config burp.jar or ~/.hiccup/hiccup-burp.jar)")
	start.Flags().StringVar(&install, "install-dir", "", "Burp install directory or burpsuite*.jar (default: auto-detect)")
	start.Flags().BoolVar(&headless, "headless", false, "run Burp without a GUI")
	start.Flags().BoolVar(&acceptEULA, "accept-eula", false, "headless only: answer Burp's EULA prompt with yes (you are accepting PortSwigger's licence)")
	start.Flags().StringVar(&javaBin, "java", "", "Java 21+ binary (default: Burp's bundled JRE)")
	start.Flags().BoolVar(&noBApps, "no-bapps", false, "don't install the BApps listed in config burp.bapps")
	start.Flags().BoolVar(&preload, "preload", false, "GUI: load hiccup via --user-config-file (may replace your saved extension list; headless always does this)")
	start.Flags().DurationVar(&wait, "wait", 3*time.Minute, "how long to wait for the API")
	start.Flags().StringArrayVar(&extraArgs, "burp-arg", nil, "extra Burp argument, e.g. --burp-arg=--project-file=x.burp (repeatable)")

	var typ, name string
	var reloadWait time.Duration
	installExt := &cobra.Command{
		Use:   "install-ext <file>...",
		Short: "Load extension jar/py/rb files into the running Burp",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			var exts []proxy.Extension
			for _, f := range args {
				abs, err := filepath.Abs(expandHome(f))
				if err != nil {
					return err
				}
				if _, err := os.Stat(abs); err != nil {
					return err
				}
				exts = append(exts, proxy.Extension{Path: abs, Type: typ, Name: name})
			}
			r, err := a.installAndWait(cmd, b, exts, reloadWait)
			if err != nil {
				return err
			}
			return a.print(r)
		},
	}
	installExt.Flags().StringVar(&typ, "type", "", "java, python or ruby (default: from the file extension)")
	installExt.Flags().StringVar(&name, "name", "", "display name")
	installExt.Flags().DurationVar(&reloadWait, "wait", time.Minute, "how long to wait for hiccup to reload")

	stop := &cobra.Command{
		Use: "stop", Short: "Shut Burp down cleanly", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.proxyClient()
			if err != nil {
				return err
			}
			if err := b.Shutdown(cmd.Context()); err != nil {
				return err
			}
			return a.print(map[string]bool{"ok": true})
		},
	}

	cmd.AddCommand(start, stop, installExt)
	return cmd
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, rest)
		}
	}
	return p
}

// findBurp returns the bundled java and the Burp jar for an install.
func findBurp(hint string) (java, jar string, err error) {
	var dirs []string
	if hint != "" {
		if strings.HasSuffix(hint, ".jar") {
			dirs = append(dirs, filepath.Dir(hint))
		} else {
			dirs = append(dirs, hint, filepath.Join(hint, "Contents", "Resources"))
		}
	} else {
		home, _ := os.UserHomeDir()
		switch runtime.GOOS {
		case "darwin":
			for _, app := range []string{"Burp Suite.app", "Burp Suite Professional.app", "Burp Suite Community Edition.app"} {
				dirs = append(dirs, filepath.Join("/Applications", app, "Contents", "Resources"),
					filepath.Join(home, "Applications", app, "Contents", "Resources"))
			}
		case "windows":
			for _, base := range []string{os.Getenv("ProgramFiles"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs")} {
				dirs = append(dirs, filepath.Join(base, "BurpSuitePro"), filepath.Join(base, "BurpSuiteCommunity"))
			}
		default:
			dirs = append(dirs, filepath.Join(home, "BurpSuitePro"), filepath.Join(home, "BurpSuiteCommunity"),
				"/opt/BurpSuitePro", "/opt/BurpSuiteCommunity")
		}
	}
	for _, d := range dirs {
		jars, _ := filepath.Glob(filepath.Join(d, "app", "burpsuite*.jar"))
		more, _ := filepath.Glob(filepath.Join(d, "burpsuite*.jar"))
		jars = append(jars, more...)
		if hint != "" && strings.HasSuffix(hint, ".jar") {
			jars = []string{hint}
		}
		if len(jars) == 0 {
			continue
		}
		exe := "java"
		if runtime.GOOS == "windows" {
			exe = "java.exe"
		}
		for _, j := range []string{
			filepath.Join(d, "jre.bundle", "Contents", "Home", "bin", exe),
			filepath.Join(d, "jre", "bin", exe),
		} {
			if _, err := os.Stat(j); err == nil {
				return j, jars[0], nil
			}
		}
		if j, err := exec.LookPath(exe); err == nil {
			return j, jars[0], nil // needs Java 21+
		}
	}
	return "", "", fmt.Errorf("Burp install not found (pass --install-dir)")
}

// writeUserConfig writes a Burp user-options file that loads the hiccup extension.
func writeUserConfig(jar string) (string, error) {
	cfg := map[string]any{
		"user_options": map[string]any{
			"extender": map[string]any{
				"extensions": []map[string]any{{
					"errors":         "ui",
					"extension_file": jar,
					"extension_type": "java",
					"loaded":         true,
					"name":           "hiccup",
					"output":         "ui",
				}},
			},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(config.Home(), "burp-user-config.json")
	if err := os.MkdirAll(config.Home(), 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o600)
}

// installAndWait loads extensions and, when Burp reloads them all (hiccup
// included), waits for hiccup to come back and reconnects.
func (a *app) installAndWait(cmd *cobra.Command, b proxy.Proxy, exts []proxy.Extension, wait time.Duration) (*proxy.InstallResult, error) {
	_, oldToken := a.cfg.BurpEndpoint()
	r, err := b.InstallExtensions(cmd.Context(), exts)
	if err != nil {
		return nil, err
	}
	if r.Reloading {
		ctx, cancel := context.WithTimeout(cmd.Context(), wait)
		defer cancel()
		if _, err := waitRuntime(ctx, oldToken); err != nil {
			return r, fmt.Errorf("extensions added, but hiccup did not come back after Burp reloaded extensions: %w", err)
		}
		a.proxy = nil // the token changed; reconnect on next use
	}
	return r, nil
}

// answerPrompts watches Burp's log for its headless start-up prompts and
// answers them: the EULA only when the user passed --accept-eula, and the
// licence key prompt with Enter (Community, or the already-stored Pro licence).
func answerPrompts(ctx context.Context, logPath string, stdin io.WriteCloser, acceptEULA bool) {
	defer stdin.Close()
	prompts := []struct {
		text, answer string
		allowed      bool
	}{
		{"Do you accept the license agreement", "y\n", acceptEULA},
		{"press Enter to use the Community Edition", "\n", true},
	}
	answered := make([]bool, len(prompts))
	for {
		if b, err := os.ReadFile(logPath); err == nil {
			for i, p := range prompts {
				if !answered[i] && p.allowed && strings.Contains(string(b), p.text) {
					answered[i] = true
					_, _ = io.WriteString(stdin, p.answer)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// waitRuntime waits for the extension to write a runtime file (with a token
// other than oldToken) and answer /health.
func waitRuntime(ctx context.Context, oldToken string) (*config.Config, error) {
	for {
		cfg, err := config.Load()
		if err != nil {
			return nil, err
		}
		if url, token := cfg.BurpEndpoint(); token != "" && token != oldToken {
			c := burp.New(url, token)
			hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, herr := c.Health(hctx)
			cancel()
			if herr == nil {
				return cfg, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
