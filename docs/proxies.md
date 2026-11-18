# Proxies: Burp, ZAP and mitmproxy

Pick the proxy with `"proxy"` in config or `HICCUP_PROXY`: `burp` (the default), `zap` or `mitmproxy`. The same commands work on all three, except where a tool has no equivalent; those exit with code 3.

## mitmproxy

`hiccup mitm start` runs `mitmdump` with hiccup's addon, which is embedded in the `hiccup` binary.

- **API:** the addon serves the same REST API as the Burp extension, with the same token, `Host` and `Origin` protections.
- **History:** kept in memory.
- **In the request hook:** throttling (with jitter and 429/503 back-off) and the User-Agent rewrite.

```json
"proxy": "mitmproxy",
"mitm": {"proxy": "127.0.0.1:8082", "api_port": 8097}
```

```sh
hiccup mitm start
hiccup browser launch https://target.test   # local Chrome/Chromium/Edge/Brave, proxied through mitmproxy
hiccup mitm stop
```

`mitm.bin` picks the `mitmdump` binary, and `mitm.args` adds arguments to it.

## ZAP

Start ZAP with its API enabled, for example:

```sh
zap.sh -daemon -port 8090 -config api.key=<key>
```

Then point hiccup at it:

```json
"proxy": "zap",
"zap": {"url": "http://127.0.0.1:8090", "api_key": "keychain:hiccup/zap"}
```

`HICCUP_ZAP_URL` and `HICCUP_ZAP_API_KEY` override these. The key can be plaintext, `env:` or `keychain:`; see [configuration.md](configuration.md).

## What maps to what

| hiccup | Burp | ZAP | mitmproxy |
|---|---|---|---|
| history, sitemap, send | ✓ | messages, `sendRequest` | ✓ (send goes through the proxy) |
| browser | Burp's Chromium | local Chrome-family browser | local Chrome-family browser |
| throttle | per host, jitter, back-off | network add-on rate limits (whole requests/s, no jitter or back-off) | per host, jitter, back-off |
| User-Agent + client hints | ✓ | default UA + Replacer rules | ✓ |
| scope | target scope | a `hiccup` context | URL prefixes in the addon |
| issues | Pro only | alerts (attached to a history message) | stored by the addon (`$HICCUP_HOME/mitm-issues.json`) |
| scan | Pro: crawl/audit | spider / active scan | — |
| intercept | ✓ | break | — (mitmdump has none) |
| Repeater, Intruder, extensions, BApps | ✓ | — | — |

The auth matrix, logins, the Nuclei import and the exports work with every proxy.

**Testing status:**

- **mitmproxy:** tested end to end against `testdata/authapp`, with the same findings as Burp.
- **ZAP:** built from ZAP 2.17's API definitions and tested against a mock of that API. It hasn't been run against a live ZAP yet.

For the port each piece uses, see [ports.md](ports.md).
