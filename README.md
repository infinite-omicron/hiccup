# hiccup

Drive Burp Suite, OWASP ZAP or mitmproxy from scripts and agents (Claude Code, agy, shell).

- **`hiccup-burp.jar`**: a small Burp extension (Montoya API). It exposes Burp through a token-protected REST API on `127.0.0.1:8099` and contains no logic of its own.
- **`hiccup`**: a single Go binary for macOS, Linux and Windows. It holds all the logic: config, credentials, browser automation over CDP, per-host throttling and User-Agent control, and importers such as Nuclei.

Output is JSON by default, so agents can parse it; add `--format table` for a human-readable table. See [docs/proposal.md](docs/proposal.md) for the full design. Done so far:

- Phase 1: the extension, the core CLI, the browser, throttling and the Nuclei import.
- Phase 2: login recipes, per-account sessions and the auth matrix.
- Phase 3: installing BApp Store extensions and the Google Sheets export.
- Phase 4: ZAP and mitmproxy support.

## Build

Requires Go 1.27+ and a JDK 17+ (the Gradle wrapper fetches Gradle).

```sh
make            # dist/hiccup-burp.jar and dist/hiccup
make dist       # also cross-compiles hiccup for darwin/linux/windows × amd64/arm64
make install    # copies the jar to ~/.hiccup/ where `hiccup burp start` finds it
make test
```

Install with Homebrew on macOS or Linux:

```sh
brew install --cask infinite-omicron/tap/hiccup
```

Prebuilt binaries and the jar are also attached to each [GitHub Release](https://github.com/infinite-omicron/hiccup/releases), with `checksums.txt` (SHA-256).

## Releases and contributing

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org): `<type>(<scope>): <description>`, with types such as `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci` and `chore`. CI rejects pushes and PRs whose commits don't match.
- **Releases** follow [SemVer](https://semver.org) and are cut by [release-please](https://github.com/googleapis/release-please). It keeps a release PR open with the next version and `CHANGELOG.md`, computed from the commits:
  - `fix` → patch
  - `feat` → minor
  - `!` or a `BREAKING CHANGE:` footer → major (minor while the version is still 0.x)
- **Publishing**: merging the release PR tags `vX.Y.Z` and publishes the GitHub Release. The Release workflow then attaches:
  - `hiccup_X.Y.Z_<os>_<arch>` archives for macOS, Linux and Windows (amd64 and arm64)
  - `hiccup-burp_X.Y.Z.jar`
  - `checksums.txt`
- **Rebuilding assets**: to redo them for an existing tag, run the Release workflow by hand with that tag.
- **Provenance**: every asset gets a signed build provenance attestation (`gh attestation verify <file> -R infinite-omicron/hiccup`) and is listed on the organization's [linked artifacts](https://github.com/orgs/infinite-omicron/artifacts) page.
- **Homebrew**: the Release workflow then writes `Casks/hiccup.rb` in [infinite-omicron/homebrew-tap](https://github.com/infinite-omicron/homebrew-tap) for stable releases. It needs a `HOMEBREW_TAP_DEPLOY_KEY` secret: the private half of a deploy key with write access on that repo (or a `HOMEBREW_TAP_TOKEN` fine-grained token with *Contents: read and write*).
- **Locally**, `make release VERSION=v1.2.3` produces the same assets in `dist/release/`.

## Start Burp with hiccup loaded

Load the jar yourself from Extensions → Installed → Add → Java → `dist/hiccup-burp.jar`, or let hiccup launch Burp with the extension preloaded:

```sh
hiccup burp start --headless            # no GUI; hiccup is preloaded
hiccup burp start                       # GUI; add hiccup-burp.jar once in Extensions, Burp reloads it on every start
hiccup burp stop                        # clean shutdown
```

In headless mode, hiccup is loaded through `--user-config-file`. A config file's extension list *replaces* Burp's, so a GUI Burp doesn't get that treatment by default: it could save the replaced list over your own extensions. Use `--preload` to opt in anyway. Headless Burp never saves user settings, so preloading there is harmless.

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

## BApp Store extensions

```sh
hiccup bapp search logger
hiccup bapp install "Logger++" Autorize --save   # --save adds them to config burp.bapps
hiccup bapp install                               # everything in config burp.bapps
```

What `bapp install` does:

- Downloads each BApp into `~/.hiccup/bapps/<uuid>/<serial>/`, unpacks it (rejecting paths that escape the folder), and loads its entry point into the running Burp in one batch. Burp reloads all extensions once, hiccup included, and the CLI waits for hiccup to come back.
- A newer version of a BApp replaces the older one.
- Pro-only BApps are skipped on Community.
- Python BApps run on Jython, and Ruby ones on JRuby. If Burp has neither configured, hiccup downloads the newest stable `jython-standalone` or `jruby-complete` from Maven Central and points Burp at it.
- `hiccup burp start` installs the BApps listed in `burp.bapps` (skip that with `--no-bapps`).

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

## Logins and sessions

Each site lists its roles (with a privilege `level`) and accounts. An account without a `username` is anonymous. The `login` recipe fills a form:

```json
"login": {"url": "/login", "username": "#email", "password": "#password",
          "submit": "button[type=submit]", "success": {"url_contains": "/dashboard"}},
"session": {"cookies": ["session"], "headers": ["Authorization"]}
```

```sh
hiccup login --all           # every account, each in a fresh browser context
hiccup login user1 --manual  # you log in yourself in Burp's browser, then press Enter
```

hiccup saves each account's session cookies to `~/.hiccup/sessions/<site>/<account>.json`, along with any configured headers (such as an `Authorization` token, read from proxy history after login). If a recipe fails in a terminal, hiccup falls back to manual login.

## Auth matrix (horizontal and vertical privilege escalation)

```sh
hiccup matrix record --as admin1          # log in, click every nav link; one action per link
hiccup matrix record --as user1           # recording lower roles too improves the expectations
hiccup login --all                        # fresh sessions for every account
hiccup matrix run                         # replay every recorded request as every account
hiccup matrix show --format table
hiccup matrix export --xlsx matrix.xlsx --csv matrix.csv --burp-issues
```

For actions that the nav links don't cover, record by hand:

```sh
hiccup matrix record --as admin1 --manual   # logs in in the visible tab
hiccup matrix mark "Create Document"        # requests from now on belong to this action
hiccup matrix stop
```

How it works:

- **Recording**: requests are grouped into actions, and object references in paths are turned into templates (`/documents/42` → `/documents/${document_id}`). Static files, out-of-scope hosts, login and logout are dropped.
- **Replay**: each request is sent through Burp, and so throttled, once per account. hiccup removes `Cookie`, `Authorization` and the configured session headers, then injects that account's session. Only GET, HEAD and OPTIONS are replayed unless you pass `--unsafe`, because replaying POST, PUT or DELETE as other users changes data.
- **Classification**:
  - **Denied**: 401 or 403, a redirect to login, a 404 the owner doesn't get, or a login page.
  - **Allowed**: a 2xx that looks like the owner's response.
  - **Differs**: a 2xx that doesn't look like the owner's response; flagged as `review` for you to check.
- **Expected access**:
  - The recorder is always allowed.
  - A reference to someone's object (`/documents/${document_id}`) is allowed only for accounts at a higher level.
  - Any other request is allowed for accounts at the recorder's level or above, or for any account at or above the level of someone who recorded it themselves.
  - You can override any of these in `~/.hiccup/sites/<site>/expectations.json`, e.g. `{"Reports": {"user": "allow"}, "*": {"auditor": "deny"}}`.
- **Findings**: `vertical` when a lower level got access, `horizontal` when the same level reached another account's object (IDOR), and `forceful-browsing` when the anonymous account got access.
- **Google Sheets**: `--sheets <spreadsheet ID or URL>` fills the same layout in a Google Sheet tab, creating the tab if it's missing. See `hiccup google --help` for credentials:
  - a service-account key (share the sheet with its email), or
  - a "Desktop app" OAuth client plus `hiccup google login` once, or
  - Application Default Credentials.

  The scope is limited to spreadsheets, and the token is stored mode 0600 in `~/.hiccup/google/`.
- **xlsx export**: fills the *Auth Matrix* tab of your checklist template. One column pair (`Exp?` / `Actual`) per action, one row per account, and finding cells highlighted red (amber for `review`). The rest of the workbook is kept. Set `"matrix": {"template": "~/.hiccup/Checklist.xltx"}` in config, or pass `--template`.

`testdata/authapp/app.py` is a small multi-role app with one bug of each kind. hiccup reports exactly those bugs against it, and no false positives on the routes that are properly protected.

## Other proxies: ZAP and mitmproxy

Pick the proxy with `"proxy"` in config or `HICCUP_PROXY` (`burp`, `zap` or `mitmproxy`). The same commands work on all three, except where a tool has no equivalent.

**mitmproxy**: `hiccup mitm start` runs `mitmdump` with hiccup's addon (embedded in the binary). The addon serves the same REST API as the Burp extension, with the same token, `Host` and `Origin` protections. It keeps proxy history in memory and enforces throttling (including jitter and 429/503 backoff) and the User-Agent rewrite in its request hook.

```json
"proxy": "mitmproxy",
"mitm": {"proxy": "127.0.0.1:8082", "api_port": 8097}
```

```sh
hiccup mitm start
hiccup browser launch https://target.test   # local Chrome/Chromium/Edge/Brave, proxied through mitmproxy
hiccup mitm stop
```

**ZAP**: start ZAP with its API enabled (for example `zap.sh -daemon -port 8090 -config api.key=…`), then:

```json
"proxy": "zap",
"zap": {"url": "http://127.0.0.1:8090", "api_key": "keychain:hiccup/zap"}
```

| hiccup | Burp | ZAP | mitmproxy |
|---|---|---|---|
| history, sitemap, send | ✓ | messages, `sendRequest` | ✓ (send goes through the proxy) |
| browser | Burp's Chromium | local Chrome-family browser | local Chrome-family browser |
| throttle | per host, jitter, backoff | network add-on rate limits (whole req/s, no jitter or backoff) | per host, jitter, backoff |
| User-Agent + client hints | ✓ | default UA + Replacer rules | ✓ |
| scope | target scope | `hiccup` context | prefixes in the addon |
| issues | Pro only | alerts (attached to a history message) | stored by the addon (`$HICCUP_HOME/mitm-issues.json`) |
| scan | Pro: crawl/audit | spider / active scan | — |
| intercept | ✓ | break | — (mitmdump has none) |
| Repeater, Intruder, extensions, BApps | ✓ | — | — |

Unsupported operations exit with code 3. The auth matrix, logins, the Nuclei import and the exports work with every proxy. mitmproxy support was tested end-to-end against `testdata/authapp`, with the same findings as Burp. ZAP support is built from ZAP 2.17's API definitions and tested against a mock of that API.

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
| `HICCUP_PROXY` | `burp`, `zap` or `mitmproxy` |
| `HICCUP_ZAP_URL`, `HICCUP_ZAP_API_KEY` | ZAP API endpoint and key (plaintext, `env:` or `keychain:`) |
| `HICCUP_BROWSER` | Chrome-family browser when the proxy is ZAP or mitmproxy |
| `HICCUP_BURP_URL`, `HICCUP_BURP_TOKEN` | override the extension endpoint |
| `HICCUP_BURP_PORT` | port the extension listens on (read by Burp's process) |
| `HICCUP_USER_AGENT`, `HICCUP_THROTTLE_RPS` | per-run overrides; never written to config |
| `HICCUP_CDP_URL`, `HICCUP_CDP_TOKEN` | drive any Chromium instead of the launched one |
| `HICCUP_GOOGLE_CREDENTIALS` | Google credentials JSON (default `$HICCUP_HOME/google/credentials.json`) |

## API security

The extension's API:

- listens only on `127.0.0.1`
- requires the bearer token from `burp.json`
- rejects requests that carry an `Origin` header, to block browser CSRF
- rejects requests whose `Host` isn't the loopback address, to block DNS rebinding
