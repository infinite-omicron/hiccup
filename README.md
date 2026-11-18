# hiccup

Drive Burp Suite, OWASP ZAP or mitmproxy from scripts and agents (Claude Code, agy, shell).

- **`hiccup-burp.jar`**: a small Burp extension that exposes Burp through a token-protected REST API on `127.0.0.1`. It contains no logic of its own.
- **`hiccup`**: a single Go binary for macOS, Linux and Windows. It holds all the logic:
  - config and credentials
  - browser automation over CDP (Chrome DevTools Protocol)
  - per-host throttling and User-Agent control
  - an auth matrix for privilege-escalation testing
  - importers such as Nuclei

Output is JSON by default, so agents can parse it; add `--format table` for a human-readable table.

## Install

```sh
brew install --cask infinite-omicron/tap/hiccup
```

Or download a build for macOS, Linux or Windows from [GitHub Releases](https://github.com/infinite-omicron/hiccup/releases). Then load `hiccup-burp.jar` into Burp (Extensions -> Installed -> Add -> Java).

## Quick start

```sh
hiccup status                                   # finds the extension through ~/.hiccup/burp.json
hiccup config init                              # example config with a site, roles and accounts
hiccup browser launch https://target.test       # Burp's Chromium, proxied through Burp
hiccup history --format table
hiccup login --all && hiccup matrix record --as admin1 && hiccup matrix run
hiccup matrix export                            # opens the auth matrix in Excel
```

## Documentation

| Page | Covers |
|---|---|
| [Getting started](docs/getting-started.md) | installing, loading the extension, first commands, exit codes |
| [Burp](docs/burp.md) | starting Burp, Burp tools, BApp Store extensions |
| [Browser automation](docs/browser.md) | CDP, Playwright and Selenium, the relay |
| [Throttling and User-Agent](docs/throttling.md) | rate limits, back-off, consistent client hints |
| [Auth matrix](docs/auth-matrix.md) | logins, sessions, horizontal and vertical privilege escalation, Excel, Microsoft 365 and Google Sheets exports |
| [Nuclei](docs/nuclei.md) | running Nuclei through the proxy, importing findings |
| [Proxies](docs/proxies.md) | ZAP and mitmproxy, and what maps to what |
| [Ports](docs/ports.md) | every port hiccup uses and how to change it |
| [Configuration](docs/configuration.md) | config file, credentials, environment variables |
| [Security](docs/security.md) | the local API's protections, credentials, releases |
| [Contributing](docs/contributing.md) | building, commits, CI and releases |
| [Design proposal](docs/proposal.md) | the original design |
