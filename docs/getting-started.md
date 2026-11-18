# Getting started

## Install

**Homebrew** (macOS and Linux, arm64 and amd64):

```sh
brew install --cask infinite-omicron/tap/hiccup
```

This installs the `hiccup` binary and `hiccup-burp.jar` side by side. `hiccup burp start` finds the jar there.

**GitHub Releases**: each [release](https://github.com/infinite-omicron/hiccup/releases) has:

- `hiccup_X.Y.Z_<os>_<arch>` archives for macOS, Linux and Windows. Each holds the binary, the jar and the README.
- `hiccup-burp_X.Y.Z.jar` on its own.
- `checksums.txt` (SHA-256).

Every file has a signed build provenance attestation:

```sh
gh attestation verify hiccup_X.Y.Z_linux_amd64.tar.gz -R infinite-omicron/hiccup
```

**From source**: see [contributing.md](contributing.md).

## Load the extension into Burp

Pick one:

- **In Burp:** Extensions -> Installed -> Add, set Extension type to *Java*, and choose `hiccup-burp.jar`. Burp reloads it on every start from then on.
- **Let hiccup start Burp:** see [burp.md](burp.md#starting-and-stopping-burp).

On load, the extension writes its URL and a fresh token to `~/.hiccup/burp.json` (mode 0600). Every `hiccup` command reads that file, so there's nothing to configure. It listens on `127.0.0.1:8099`; see [ports.md](ports.md).

## First commands

```sh
hiccup status                                   # is the extension reachable? which Burp?
hiccup config init                              # writes an example ~/.hiccup/config.json
hiccup browser launch https://target.test       # Burp's Chromium, proxied through Burp
hiccup history --format table                   # what the browser just did
```

Output is JSON by default, so scripts and agents can parse it. Add `--format table` to read it yourself. Commands exit with:

- **0:** success
- **1:** an error
- **3:** the current proxy doesn't support the operation (for example, scanning on Burp Community)

## Next

- [configuration.md](configuration.md): sites, accounts, credentials and environment variables
- [browser.md](browser.md): driving the browser, Playwright and Selenium
- [auth-matrix.md](auth-matrix.md): testing horizontal and vertical privilege escalation
