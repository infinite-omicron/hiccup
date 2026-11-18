# Browser automation

hiccup drives a Chromium-family browser through CDP, the **Chrome DevTools Protocol**. That's the protocol Chrome's developer tools, Playwright and Puppeteer use to control the browser: navigate, run JavaScript, take screenshots, read cookies. The browser's traffic goes through the proxy, so everything it does shows up in history.

```sh
hiccup browser launch https://target.test     # start the browser, proxied, CDP on 127.0.0.1:9222
hiccup browser nav https://target.test/login
hiccup browser eval 'document.title'          # promises are awaited
hiccup browser screenshot shot.png            # full page; --quality <100 for JPEG
hiccup browser html > page.html
hiccup browser info                           # current URL and title
hiccup browser cdp                            # CDP endpoint, websocket URL and token
hiccup browser stop
```

`nav`, `eval`, `screenshot`, `html` and `info` act on the current tab; `--new-tab` opens one instead.

## Which browser

- **Burp:** the Chromium build that ships with Burp, started by the extension.
- **ZAP and mitmproxy:** neither ships a browser, so hiccup starts a local Chrome, Chromium, Edge or Brave. Set `HICCUP_BROWSER` to choose one.
- **Your own Chromium:** to drive one you started yourself, set `HICCUP_CDP_URL` (and `HICCUP_CDP_TOKEN` if it needs one).

`browser launch`:

- points `--proxy-server` at the proxy's listener and ignores certificate errors, so HTTPS works through the proxy's CA
- uses its own profile under `~/.hiccup/`, separate from your normal browser and from Burp's
- with `--headless`, runs without a window
- turns Burp's **Proxy intercept off**, because intercepted requests would hang automation. Pass `--keep-intercept` to leave it on; `hiccup intercept on|off` toggles it.

## Playwright and Selenium

Burp's Chromium build protects its CDP HTTP endpoints (`/json/*`) with an `x-burp-authorization` token that it prints at start-up. The extension captures that token for you.

- **Playwright:** connect to the websocket URL directly; it needs no token:

  ```python
  ws = json.loads(subprocess.check_output(["hiccup", "browser", "cdp"]))["ws"]
  browser = playwright.chromium.connect_over_cdp(ws)
  ```

- **Selenium, or any client that can't send headers:** run the relay. It serves the CDP endpoint on `127.0.0.1:9223` and adds the token:

  ```sh
  hiccup browser relay
  ```

  ```python
  options.debugger_address = "127.0.0.1:9223"
  ```

## User-Agent

`browser launch --ua "<UA>"` (or the site's `user_agent` in config) sets the browser's User-Agent. hiccup also keeps the client hints consistent with it; see [throttling.md](throttling.md#user-agent).
