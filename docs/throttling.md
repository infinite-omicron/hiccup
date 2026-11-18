# Throttling and User-Agent

These keep automated testing from tripping a site's rate limits or bot detection.

## Throttling

The Burp extension registers one HTTP handler that sees every Burp tool: Proxy (including the browser), Repeater, Intruder, Scanner and extensions. Whatever sends the traffic, the site never sees more than the limit.

- **Rate:** a per-host limit in requests per second, plus optional random jitter between requests.
- **Back-off:** on 429 or 503, that host is paused for the `Retry-After` seconds, or with exponential back-off when there's no header. The pause is capped by `max_s`.

```sh
hiccup throttle set acme --rps 0.5 --jitter 500-2000 --save   # all of a site's hosts (or one host, or *.example.com)
hiccup throttle list
hiccup throttle off
```

The same settings in config:

```json
"throttle": {"rps": 1.0, "burst": 1, "jitter_ms": [300, 1500], "max_concurrency": 1,
             "backoff": {"on_status": [429, 503], "honor_retry_after": true, "max_s": 120}}
```

`hiccup status`, `browser launch`, `login`, `matrix` and `run nuclei` push every site's throttle from config automatically. hiccup also paces itself:

- **Auth matrix replay:** uses at most `max_concurrency` workers.
- **Recording:** waits the jitter between clicks.
- **`hiccup run nuclei`:** passes matching `-rl`/`-rld` limits to Nuclei.

With ZAP, the throttle becomes ZAP's own rate-limit rules, which only take whole requests per second and have no jitter or back-off. See [proxies.md](proxies.md).

## User-Agent

```sh
hiccup ua "Mozilla/5.0 (...) Chrome/150.0.0.0 Safari/537.36" --scope all --save
```

hiccup keeps the User-Agent and the client hints consistent, because a mismatch is a common bot-detection signal:

- the browser is launched with `--user-agent`
- every CDP session applies `Emulation.setUserAgentOverride` with matching client-hint metadata, so `navigator.userAgent` and `navigator.userAgentData` agree
- the proxy rewrites the `Sec-CH-UA*` request headers to match. For a non-Chromium User-Agent (Firefox, Safari), it removes them, as those browsers don't send them.

With `"scope": "browser"` (the default), only proxied browser traffic is rewritten. With `"scope": "all"`, Repeater, Intruder, Scanner and extension requests get the User-Agent too.

The per-run overrides `HICCUP_USER_AGENT` and `HICCUP_THROTTLE_RPS` are never written to config.
