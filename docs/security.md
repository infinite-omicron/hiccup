# Security

## The local API

The Burp extension and the mitmproxy addon each serve hiccup's REST API. Both:

- listen only on `127.0.0.1`; see [ports.md](ports.md)
- require the bearer token from `~/.hiccup/burp.json` or `mitm.json`, which is regenerated every time they load and written mode 0600
- compare the token in constant time
- reject requests that carry an `Origin` header, to block cross-site requests from web pages in any browser (CSRF)
- reject requests whose `Host` isn't the loopback address, to block DNS rebinding

The Burp extension's HTTP server also:

- only accepts `Content-Length` bodies (chunked bodies get 411)
- caps the request head at 64 KB and the body at 64 MB
- times out idle connections after 30 seconds

## The browser

The automated browser exposes CDP (Chrome DevTools Protocol) on `127.0.0.1` only. Anything that can reach that port can control the browser. Burp's Chromium build adds a token check on its `/json/*` endpoints; `hiccup browser relay` removes that check for Selenium, so only run the relay while you need it.

## Credentials

Passwords can live in the OS keychain or in environment variables instead of the config file; see [configuration.md](configuration.md#credentials). `hiccup creds list` and `hiccup config show` never print secrets.

## Replaying requests

The auth matrix only replays GET, HEAD and OPTIONS unless you pass `--unsafe`. Replaying state-changing requests as other users modifies data on the target.

## Releases

Every release asset has a signed build provenance attestation and is listed on the organization's [linked artifacts](https://github.com/orgs/infinite-omicron/artifacts) page:

```sh
gh attestation verify <file> -R infinite-omicron/hiccup
```

The macOS binaries are not notarized, so the Homebrew cask clears the quarantine flag on install.
