# hiccup: a scriptable pentest driver for Burp (later ZAP and mitmproxy)

## Context
You want agents (Claude Code, agy) and scripts to drive Burp: run its browser, use its tools, push open-source scanner findings (Nuclei, etc.) into Burp as issues, and generate the **Auth Matrix** from your `Checklist.xltx` template automatically, using several test credentials per role. It has two parts:
1. **`hiccup-burp.jar`**: the smallest Montoya extension that can expose Burp through an authenticated REST API on localhost. It contains no logic.
2. **`hiccup`**: a single Go binary for macOS, Windows and Linux that holds all the logic, including config, credentials, browser automation over CDP, importers and the auth matrix. Proxy access goes through a `Backend` interface, so ZAP or mitmproxy can be added later without changing commands.

The extension follows PortSwigger's [creating extensions docs](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating):
- Java 21 or lower; I'll build with `--release 17` using the local JDK 17
- Gradle Kotlin DSL, same as the starter project
- `compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")`, the latest release
- An entry class that implements `BurpExtension`

Local tools:
- Go 1.27 and Gradle are installed.
- For testing, install Burp Community with `brew install --cask burp-suite` and Nuclei with `brew install nuclei`. Community has no scanner, so `/scan` returns 501 there.

### Your Auth Matrix layout (from the "Auth Matrix" tab in `Checklist.xltx`)
- `B1` = "Action:". Starting at column C, each action takes a pair of columns, with the action name in row 1 and `Exp?` / `Actual` in row 2.
- `A3` = "Account". Each account gets a row from row 4 down.
- Example cell content:

  | Account | Action | Exp? | Actual |
  |---|---|---|---|
  | admin1 | Create Document (first nav item) | `POST /upload/${document_name}` | `GET /upload/${document_name}` |

  Exp? is the request or outcome the role is expected to get, and Actual is what hiccup observed.

## Repo layout: `~/hiccup/` (git init, conventional commits, no co-author trailer)
```
extension/                        # hiccup-burp.jar
  settings.gradle.kts, build.gradle.kts   # montoya compileOnly, gson shaded
  src/main/java/hiccup/Extension.java     # starts/stops the server, token, unload handler
  src/main/java/hiccup/Api.java           # routes + handlers (JDK HttpServer)
  src/main/java/hiccup/Browser.java       # launches Burp's bundled Chromium with CDP
cmd/hiccup/main.go                # cobra root + subcommands
internal/config/                  # ~/.hiccup/config.json load/save, HICCUP_* env overrides
internal/secrets/                 # plain | env:VAR | keychain:service/account  (zalando/go-keyring)
internal/backend/                 # Backend interface; burp/ implementation (zap/, mitm/ later)
internal/browser/                 # chromedp over CDP: nav, eval, screenshot, login recipes, nav crawl
internal/importers/nuclei.go      # nuclei JSONL → issues
internal/authmatrix/              # record, replay, classify, export (xlsx/csv/json/sheets/burp)
internal/bapp/                    # BApp Store download + install
Makefile                          # jar + 6 cross-compiled binaries → dist/
```

## Extension API (bound to 127.0.0.1 only, bearer token required, requests with an `Origin` header get a 403)
- **Start-up**: on load, the extension writes its `{url, token}` into the `burp` section of `~/.hiccup/config.json`, or into `~/.hiccup/burp.json` so it never rewrites your config. The file is mode 0600.
- **Unload**: stops the server, kills the browser it launched, and removes the runtime file.

| Endpoint | Montoya call |
|---|---|
| `GET /health` | version and edition |
| `POST /browser/launch`, `POST /browser/stop`, `GET /browser` | starts Burp's bundled Chromium (`burpbrowser/<ver>`) with `--remote-debugging-port`, `--proxy-server=<Burp listener>`, a separate profile dir and `--ignore-certificate-errors`. Returns the CDP URL |
| `GET /proxy/history?contains=&since=&limit=`, `GET /proxy/history/{id}` | `proxy().history()` |
| `GET /sitemap?prefix=` | `siteMap().requestResponses` |
| `POST /http/send` (single request or batch) | `http().sendRequest` |
| `POST /repeater`, `POST /intruder` | `sendToRepeater` / `sendToIntruder` |
| `POST /scan` | Pro only: `scanner().startCrawl` / `startAudit` |
| `GET /issues`, `POST /issues` (single or array) | `siteMap().issues` / `siteMap().add(AuditIssue.auditIssue(..))` |
| `GET /scope`, `POST /scope` | `scope().isInScope` / `includeInScope` |
| `GET /throttle`, `POST /throttle` `{host, rps, burst, jitter_ms, backoff}` | the extension's `registerHttpHandler` handler (see Throttling) |
| `POST /useragent` `{ua, scope:"browser"\|"all"}` | stores the UA; `all` also rewrites `User-Agent` in the HttpHandler |
| `POST /extensions/install` `{path, type}` | `burpSuite().importUserOptionsFromJson(..)` with an `extender.extensions` entry. **Needs a live check against Burp**. If Burp doesn't load the extension that way, the fallback is `hiccup burp start`, which writes a user-config file and launches Burp with `--user-config-file` |

## `~/.hiccup/config.json`
```json
{
  "proxy": "burp",
  "burp": { "url": "http://127.0.0.1:8099", "token": "…", "jar": "~/.hiccup/hiccup-burp.jar",
            "bapps": ["Autorize", "JWT Editor", "Logger++"] },
  "sites": {
    "acme": {
      "base_url": "https://app.acme.test",
      "throttle": { "rps": 1.0, "burst": 1, "jitter_ms": [300, 1500], "max_concurrency": 1,
                    "backoff": { "on_status": [429, 503], "honor_retry_after": true, "max_s": 120 } },
      "user_agent": { "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
                      "scope": "all" },
      "scope": ["https://app.acme.test/"],
      "login": { "url": "/login", "username": "#email", "password": "#password",
                 "submit": "button[type=submit]", "success": { "url_contains": "/dashboard" } },
      "session": { "cookies": ["session"], "headers": ["Authorization"] },
      "roles": {
        "admin": { "level": 100, "accounts": [
          { "name": "admin1", "username": "admin1@acme.test", "password": "plaintext-ok" } ] },
        "user": { "level": 10, "accounts": [
          { "name": "user1", "username": "u1@acme.test", "password": "env:HICCUP_ACME_USER1_PW" },
          { "name": "user2", "username": "u2@acme.test", "password": "keychain:hiccup/acme-user2" } ] },
        "anonymous": { "level": 0, "accounts": [ { "name": "anon" } ] }
      }
    }
  }
}
```
- **Secrets**: plaintext is the default. A value can also be `env:VAR` or `keychain:service/account`. Use `hiccup creds set acme user2` to store a password in the OS keychain.
- **Environment variables** (all `HICCUP_`-prefixed): `HICCUP_CONFIG`, `HICCUP_PROXY`, `HICCUP_BURP_URL`, `HICCUP_BURP_TOKEN`, `HICCUP_SITE`, `HICCUP_USER_AGENT`, `HICCUP_THROTTLE_RPS`.
- The config file is written with mode 0600.

## CLI (JSON on stdout by default, `--format table` for people)
- `hiccup status` · `hiccup burp start` · `hiccup burp install-ext [--all | name…]`. That last command looks up each BApp by name in the BApp Store, downloads it to `~/.hiccup/bapps/`, and loads it via `/extensions/install`. It also installs `hiccup-burp.jar` itself when you run `hiccup burp start`.
- `hiccup browser launch|stop|cdp|nav|eval|screenshot|html`
- `hiccup history`, `hiccup sitemap`, `hiccup send`, `hiccup repeater`, `hiccup intruder`, `hiccup scan`, `hiccup scope add`, `hiccup issues list|add`
- `hiccup import nuclei [file|-]`, then other tools later behind the same importer interface. Severity maps critical/high→HIGH, medium→MEDIUM, low→LOW, info→INFORMATION. The request and response go in as evidence.
- `hiccup creds list|set|test <site> [account]`. `test` runs a login and reports success or failure.
- `hiccup login <site> <account> [--manual]`:
  - The **recipe** runs over CDP in a fresh browser context, so sessions stay isolated.
  - `--manual` waits until you've logged in by hand in the Burp browser.
  - Either way, it captures the session (cookies via `Network.getAllCookies` plus the configured headers from the latest proxy history entry) to `~/.hiccup/sessions/<site>/<account>.json`. If the recipe fails, it falls back to `--manual`.

## Throttling and User-Agent (to avoid tripping bot detection)
- **Enforced inside Burp.** The extension registers one `HttpHandler`. It covers every Burp tool (Proxy, which includes the browser, plus Repeater, Intruder, Scanner and the extension's own requests).
  - **Rate limit**: in `handleHttpRequestToBeSent`, a per-host token bucket blocks each request until a token is free, then adds a random jitter. Requests to `localhost` are never blocked.
  - **Backoff**: `handleHttpResponseReceived` watches for 429 or 503. When one arrives, it pauses that host's bucket for the `Retry-After` time, or with exponential backoff up to `max_s`.
  - **Result**: whatever sends traffic (hiccup, you in the browser, an agent, Repeater), the site never sees more than the configured rate.
  - **Setup**: `hiccup` pushes each site's `throttle` setting to `/throttle` on `status`, `login`, `browser launch` and `matrix *`. You can also set it directly: `hiccup throttle set acme --rps 0.5 --jitter 500-2000`, `hiccup throttle off`.
- **Client-side pacing in hiccup** keeps queues short instead of piling requests up against the Burp limit:
  - Replay runs with `max_concurrency` workers.
  - Auto-crawl waits `jitter_ms` between nav clicks and form submits.
  - When hiccup wraps an external tool, it passes the matching limits: `hiccup run nuclei …` adds `-rl <rps> -c 1 -H "User-Agent: …"` and sends the tool through Burp's proxy (`-proxy`) so the HttpHandler throttles it too.
- **User-Agent override**:
  - **Browser**: `--user-agent=<ua>` at launch, plus `Emulation.setUserAgentOverride` with matching `userAgentMetadata` on every CDP target. This keeps the `Sec-CH-UA*` client hints and `navigator.userAgentData` consistent with the UA string, because a mismatch is a common bot-detection signal.
  - **`scope:"all"`**: the HttpHandler also rewrites `User-Agent` on requests from the other Burp tools.
  - **CLI**: `hiccup browser launch --ua "<ua>"`, or the per-site config with `HICCUP_USER_AGENT` as an override.

## Auth matrix (`hiccup matrix …`)
1. **Record**: `hiccup matrix record <site> --as admin1`.
   - Logs in as the most privileged account.
   - In **auto** mode, clicks each nav or menu item over CDP (`nav a, [role=menu] a, aside a`, can be overridden per site), then fills and submits forms with a dry-run toggle.
   - In **manual** mode, you browse yourself and run `hiccup matrix mark "<action>"` between steps.
   - Every request in scope from proxy history is tagged with the current action name (the nav item text). Static assets are dropped. Paths are templated: numbers, UUIDs and hashes become `${param}` named from the path segment, giving entries like `POST /upload/${document_name}`.
2. **Replay**: for each action's requests and each account, including `anon`:
   - Remove the `Cookie` and `Authorization` headers, inject that account's saved session, and send through `/http/send`, so everything shows up in Burp.
   - Run horizontal checks between accounts of the same role (user1 ↔ user2). Each one's own object IDs come from its own recording pass, which is optional (`--as user1`).
3. **Classify** each cell as allowed or denied:
   - Status class, redirect to login, and the size and structure of the body compared with the owner's response and the anonymous response.
   - **Exp?** comes from the role level and the account recorded for the action: if your level is at least the recorder's level, you're expected to be allowed. You can override this per action in `~/.hiccup/sites/<site>/expectations.json`.
   - **Actual** is the observed result as `METHOD /path → status (allowed/denied)`.
   - A mismatch where access was allowed but shouldn't be is flagged:
     - **Vertical** privilege escalation when a lower level gets access.
     - **Horizontal** privilege escalation when the same role reaches another account's object.
     - **Forceful browsing** when `anon` gets access.
4. **Export**: `hiccup matrix export <site> --xlsx out.xlsx --csv --json --sheets <id> --burp-issues`
   - **xlsx**: fills the Auth Matrix tab of your `Checklist.xltx` with excelize, using the cell layout above. The template path is set in config.
   - **sheets**: Google Sheets API with OAuth stored under `~/.hiccup/google/`.
   - **burp-issues**: one issue per flagged cell, with both request/response pairs as evidence.

## Phases
1. Extension and core CLI: config, secrets, backend, browser, history/send/issues, Nuclei import.
2. Login recipes and sessions, then the auth matrix and its exports.
3. BApp install and the Google Sheets export.
4. Later: `internal/backend/zap` (ZAP REST API) and `internal/backend/mitm` (a mitmproxy addon script that exposes the same endpoints).

## Verification
- `make` builds the jar and six binaries. `go test ./...` covers the Nuclei mapping, path templating, the classifier using fixture responses, and an xlsx export round-trip against `Checklist.xltx`.
- Run `brew install --cask burp-suite nuclei` and load the jar in Burp Community. Then check:
  - `hiccup status` works.
  - `hiccup browser launch https://example.com` opens the browser, and the request appears in Proxy history.
  - `nuclei -u http://testphp.vulnweb.com -jsonl | hiccup import nuclei -` makes the issues appear in Target → Issues.
- **Auth matrix end-to-end**: run a local multi-role test app, e.g. OWASP Juice Shop in Docker with admin and customer accounts. Then `hiccup login`, `hiccup matrix record`, and `hiccup matrix export --xlsx` should produce a filled Auth Matrix tab with known vertical and horizontal IDOR cases flagged.
- **Throttle**: set `rps=1` and send 10 requests through `hiccup send` against a local server that logs timestamps. They should arrive about 1 second apart, plus jitter. A 429 with `Retry-After: 5` from the server should pause the host for 5 seconds.
- **UA**: launch with `--ua X`, then check that `navigator.userAgent`, the `User-Agent` header in Proxy history, and the `Sec-CH-UA` header all match.
- A request without the token gets a 401. After unloading the extension, the browser exits and the runtime file is removed.
