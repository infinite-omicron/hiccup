# hiccup

Drive Burp Suite from scripts and agents (Claude Code, agy, shell).

- **`hiccup-burp.jar`**: a small Burp extension (Montoya API). It exposes Burp through a token-protected REST API on `127.0.0.1:8099` and contains no logic of its own.
- **`hiccup`**: a single Go binary for macOS, Linux and Windows. It holds all the logic: config, credentials, browser automation over CDP, per-host throttling and User-Agent control, and importers such as Nuclei.

Output is JSON by default, so agents can parse it; add `--format table` for a human-readable table. See [docs/proposal.md](docs/proposal.md) for the full design. Phase 1 (this code) covers the extension, the core CLI, the browser, throttling and the Nuclei import. The auth matrix, login recipes and the ZAP/mitmproxy backends come later.

## Build

Requires Go 1.27+, Gradle and a JDK 17+.

```sh
make            # dist/hiccup-burp.jar and dist/hiccup
make dist       # also cross-compiles hiccup for darwin/linux/windows × amd64/arm64
make install    # copies the jar to ~/.hiccup/ where `hiccup burp start` finds it
make test
```

## Start Burp with hiccup loaded

Load the jar yourself from Extensions → Installed → Add → Java → `dist/hiccup-burp.jar`, or let hiccup launch Burp with the extension preloaded:

```sh
hiccup burp start                       # GUI
hiccup burp start --headless            # no GUI
```

On load, the extension writes its URL and a fresh token to `~/.hiccup/burp.json` (mode 0600). Every `hiccup` command reads that file, so no setup is needed.

Notes from testing on macOS with Burp Community 2026.11:

- **EULA**: headless Burp asks you on stdin to accept its EULA. hiccup only answers yes if you pass `--accept-eula`, which means *you* accept PortSwigger's licence. It always answers the licence-key prompt with Enter (Community, or your stored Pro licence).
- **Gatekeeper**: a freshly installed Burp (`brew install --cask burp-suite`) is quarantined until you open it once from Finder. Until then its bundled JRE is killed on launch. Open Burp once, or pass `--java` with a Java 21+ binary.

## Browser automation

```sh
hiccup browser launch https://target.test     # Burp's bundled Chromium, proxied through Burp, CDP on :9222
hiccup browser nav https://target.test/login
hiccup browser eval 'document.title'
hiccup browser screenshot shot.png
hiccup browser html > page.html
hiccup browser cdp                            # CDP endpoint, websocket URL and token
```

What `browser launch` does:

- It runs the same Chromium binary that ships with Burp, with `--proxy-server` pointed at Burp's first proxy listener, so all browser traffic shows up in Proxy history.
- It turns **Proxy intercept off**, because intercepted requests would hang automation. Pass `--keep-intercept` to leave it on. `hiccup intercept on|off` toggles it.
- Burp's Chromium build protects its DevTools HTTP endpoints (`/json/*`) with an `x-burp-authorization` token that it prints at start-up. The extension captures that token for you.
  - **Playwright**: `chromium.connect_over_cdp(ws_url)` using the `ws` from `hiccup browser cdp`.
  - **Selenium**, or any client that can't send headers: run `hiccup browser relay` and point the client at `127.0.0.1:9223` (`options.debugger_address = "127.0.0.1:9223"`).

## Throttling and User-Agent

The extension registers one HTTP handler that sees every Burp tool: Proxy (including the browser), Repeater, Intruder, Scanner and extensions.

- **Throttle**: a per-host limit (requests/second plus random jitter). On 429 or 503 it pauses that host for `Retry-After` seconds, or backs off exponentially. Whatever sends the traffic, the site never sees more than the limit.
- **User-Agent**: the browser is launched with `--user-agent`. Every CDP session applies `Emulation.setUserAgentOverride` with matching client-hint metadata, and Burp rewrites the `Sec-CH-UA*` headers to match. That way `navigator.userAgent`, `navigator.userAgentData` and the request headers stay consistent, since a mismatch is a common bot-detection signal. With `scope: "all"` the User-Agent is also rewritten on Repeater, Intruder, Scanner and extension requests.

```sh
hiccup throttle set acme --rps 0.5 --jitter 500-2000 --save   # a site's hosts (or a host, or *.example.com)
hiccup throttle list
hiccup throttle off
hiccup ua "Mozilla/5.0 (...) Chrome/150.0.0.0 Safari/537.36" --scope all --save
```

`hiccup status`, `browser launch` and `run nuclei` push every site's throttle from config automatically.

## Burp tools

```sh
hiccup history --contains /api --in-scope --format table
hiccup history get 42 --raw
hiccup sitemap https://target.test/
hiccup send -u https://target.test/api -H 'Authorization: Bearer x' -d '{"a":1}'
hiccup send --raw req.txt --host target.test            # raw HTTP from a file or stdin (-)
hiccup repeater -u https://target.test/admin --tab admin
hiccup intruder --raw req.txt --host target.test
hiccup scope add                                        # the site's scope from config
hiccup scan audit https://target.test/                  # Burp Pro only (exit code 3 otherwise)
hiccup issues list
hiccup issues add --name "IDOR on /docs" --url https://target.test/docs/1 --severity high
hiccup burp install-ext ./ext.jar                       # loads into the running Burp
```

## Nuclei → Burp issues

```sh
hiccup run nuclei -- -u https://target.test -tags exposure   # through Burp's proxy, with the site's throttle and User-Agent
nuclei -u https://target.test -jsonl | hiccup import nuclei -
hiccup import nuclei results.jsonl --dry-run
```

Nuclei severities map to Burp's as follows: critical and high become High, medium becomes Medium, low becomes Low, info becomes Information. Each request/response is attached as evidence. **Burp Community silently discards issues that extensions add**, so issue import needs Burp Professional. On Community, hiccup reports exit code 3 instead of pretending the import succeeded.

## Config: `~/.hiccup/config.json`

`hiccup config init` writes an example (mode 0600), and `hiccup config show` prints it with passwords redacted. Passwords can be:

- plaintext (the default)
- `env:VAR`
- `keychain:service/account` (macOS Keychain, Windows Credential Manager or Linux Secret Service)

`hiccup creds set <site> <account>` stores a password in the keychain and updates the config to point at it. `hiccup creds list` shows where each password lives and whether it resolves, but never the secret itself.

| Variable | Meaning |
|---|---|
| `HICCUP_HOME` | state directory (default `~/.hiccup`) |
| `HICCUP_CONFIG` | config file (default `$HICCUP_HOME/config.json`) |
| `HICCUP_SITE` | default site |
| `HICCUP_BACKEND` | `burp` (ZAP and mitmproxy later) |
| `HICCUP_BURP_URL`, `HICCUP_BURP_TOKEN` | override the extension endpoint |
| `HICCUP_BURP_PORT` | port the extension listens on (read by Burp's process) |
| `HICCUP_USER_AGENT`, `HICCUP_THROTTLE_RPS` | per-run overrides; never written to config |
| `HICCUP_CDP_URL`, `HICCUP_CDP_TOKEN` | drive any Chromium instead of the launched one |

## API security

The extension's API:

- listens only on `127.0.0.1`
- requires the bearer token from `burp.json`
- rejects requests that carry an `Origin` header, to block browser CSRF
- rejects requests whose `Host` isn't the loopback address, to block DNS rebinding
