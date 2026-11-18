# Ports

Every network port hiccup uses, what listens on it, and how to change it. Everything hiccup opens itself listens on the loopback address (`127.0.0.1`) only.

| Port | What listens | Default set by | Change it with |
|---|---|---|---|
| **8099** | hiccup's REST API inside Burp (the `hiccup-burp.jar` extension) | the extension | `HICCUP_BURP_PORT` in Burp's environment (`hiccup burp start` passes yours through) |
| **8080** | Burp's proxy listener | Burp | Burp -> Proxy -> Proxy settings. hiccup uses Burp's first running listener |
| **9222** | the browser's CDP (Chrome DevTools Protocol) endpoint | `hiccup browser launch` | `hiccup browser launch --port <n>` |
| **9223** | `hiccup browser relay`: the CDP endpoint without Burp's auth header, for Selenium | `hiccup browser relay` | `hiccup browser relay --listen 127.0.0.1:<n>` |
| **8082** | mitmproxy's proxy listener | `hiccup mitm start` | `"mitm": {"proxy": "127.0.0.1:<n>"}` in config |
| **8097** | hiccup's REST API inside mitmproxy (the addon) | `hiccup mitm start` | `"mitm": {"api_port": <n>}` in config |
| **8090** | ZAP's API and proxy (ZAP serves both on one port) | hiccup's ZAP default | start ZAP with `-port <n>` and set `"zap": {"url": "http://127.0.0.1:<n>"}` or `HICCUP_ZAP_URL` |
| random | one-time callback during `hiccup google login` | the OS picks a free port | none (closed as soon as you've signed in) |
| **18081** | `testdata/authapp/app.py`, the test app for the auth matrix | the test app | `python3 testdata/authapp/app.py <port>` |

## Why these numbers

- **8099** and **8097** sit next to Burp's 8080 without colliding with it or with each other. That way Burp and mitmproxy can run at the same time.
- **8082** keeps mitmproxy off Burp's 8080; mitmproxy itself defaults to 8080 too.
- **8090** because ZAP's own default is also 8080. Start ZAP with `-port 8090`, or point hiccup at whatever port you chose.
- **9222** is Chrome's conventional CDP port, and **9223** is the next one up.

## Finding the ports at runtime

You rarely need these numbers. On load, the Burp extension writes its URL and a fresh token to `~/.hiccup/burp.json`, and the mitmproxy addon writes `~/.hiccup/mitm.json`. Every `hiccup` command reads those files. To see the live values:

```sh
hiccup status              # the proxy's listener ("proxy") and the browser's CDP URL
hiccup browser cdp         # CDP endpoint, websocket URL and Burp's CDP token
```

## Clashes

If a port is taken, the component that wants it fails to start and says so:

- **8099:** the extension logs `cannot listen on 127.0.0.1:8099` in its Errors tab. This happens when two Burps load hiccup at once, for example your GUI Burp plus a headless one from `hiccup burp start`. Give the second one its own port, e.g. `HICCUP_BURP_PORT=8199 hiccup burp start --headless`, and use a separate `HICCUP_HOME` so the two `burp.json` files don't overwrite each other.
- **9222:** the browser can't open its CDP port, so `hiccup browser launch` returns no websocket URL, or (with ZAP and mitmproxy) says the browser never reported its DevTools address. Pass `--port`.
