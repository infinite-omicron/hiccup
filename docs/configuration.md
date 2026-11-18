# Configuration

hiccup reads `~/.hiccup/config.json`.

- `hiccup config init` writes an example, mode 0600.
- `hiccup config show` prints the effective config with plaintext passwords redacted.
- `hiccup config path` shows where the files are.

## Sites, roles and accounts

```json
{
  "proxy": "burp",
  "burp": { "bapps": ["Logger++"] },
  "matrix": { "template": "~/.hiccup/Checklist.xltx" },
  "sites": {
    "acme": {
      "base_url": "https://app.acme.test",
      "scope": ["https://app.acme.test/"],
      "throttle": { "rps": 1.0, "jitter_ms": [300, 1500] },
      "user_agent": { "value": "Mozilla/5.0 (...) Chrome/150.0.0.0 Safari/537.36", "scope": "all" },
      "login": { "url": "/login", "username": "#email", "password": "#password",
                 "submit": "button[type=submit]", "success": { "url_contains": "/dashboard" } },
      "session": { "cookies": ["session"], "headers": ["Authorization"] },
      "nav_selector": "nav a, [role=tablist] a",
      "listener_base": 8181,
      "exclude": ["/admin/flush"],
      "roles": {
        "admin": { "level": 100, "accounts": [
          { "name": "admin1", "username": "admin1@acme.test", "password": "plaintext-ok" } ] },
        "user": { "level": 10, "accounts": [
          { "name": "user1", "username": "u1@acme.test", "password": "env:HICCUP_ACME_USER1_PW" },
          { "name": "user2", "username": "u2@acme.test", "password": "keychain:hiccup/acme/user2" } ] },
        "anonymous": { "level": 0, "accounts": [ { "name": "anon" } ] }
      }
    }
  }
}
```

**Picking a site:** commands use `--site`, else `HICCUP_SITE`, else the only site in the config.

**Topic pages:**

- **Throttle and User-Agent:** [throttling.md](throttling.md)
- **Login and session:** [auth-matrix.md](auth-matrix.md#logins-and-sessions)
- **`proxy`, `zap` and `mitm`:** [proxies.md](proxies.md)

## Microsoft 365

Syncing the auth matrix workbook to OneDrive or SharePoint (`matrix export --m365`) signs in through an Entra ID (Azure AD) app registration in your tenant. Register one once:

1. Entra admin center -> App registrations -> New registration. Supported account types: this organizational directory.
2. Authentication -> *Allow public client flows* -> Yes (the device-code flow needs it). No redirect URI or client secret is needed.
3. API permissions -> Microsoft Graph -> Delegated -> `Files.ReadWrite.All`. Users can usually consent to this themselves; your tenant may require an admin to grant it.

Then:

```json
"microsoft": { "client_id": "<application (client) ID>", "tenant": "<tenant ID or contoso.com>" },
"matrix": { "m365": "onedrive:/Pentests/{site}/" }
```

```sh
hiccup m365 login     # prints a code to enter at microsoft.com/devicelogin
hiccup m365 status    # who you're signed in as, and your OneDrive URL
hiccup m365 logout
```

`tenant` defaults to `organizations` (any work or school account). The token is stored in `~/.hiccup/microsoft/token.json` (0600) and refreshed automatically.

## Credentials

A password can be:

- **plaintext:** the default
- **`env:VAR`:** read from an environment variable
- **`keychain:service/account`:** read from the macOS Keychain, Windows Credential Manager or Linux Secret Service

```sh
hiccup creds set acme user2     # prompts, stores in the keychain, points the config at it
hiccup creds list               # where each password lives and whether it resolves; never the secret
```

The ZAP API key in `zap.api_key` accepts the same forms.

## Environment variables

| Variable | Meaning |
|---|---|
| `HICCUP_HOME` | state directory (default `~/.hiccup`) |
| `HICCUP_CONFIG` | config file (default `$HICCUP_HOME/config.json`) |
| `HICCUP_SITE` | default site |
| `HICCUP_PROXY` | `burp`, `zap` or `mitmproxy` |
| `HICCUP_BURP_URL`, `HICCUP_BURP_TOKEN` | override the extension endpoint |
| `HICCUP_BURP_PORT` | port the extension listens on (read by Burp's process) |
| `HICCUP_ZAP_URL`, `HICCUP_ZAP_API_KEY` | ZAP API endpoint and key |
| `HICCUP_BROWSER` | Chrome-family browser when the proxy is ZAP or mitmproxy |
| `HICCUP_CDP_URL`, `HICCUP_CDP_TOKEN` | drive any Chromium over CDP (Chrome DevTools Protocol) instead of the launched one |
| `HICCUP_USER_AGENT`, `HICCUP_THROTTLE_RPS` | per-run overrides; never written to config |
| `HICCUP_GOOGLE_CREDENTIALS` | Google credentials JSON (default `$HICCUP_HOME/google/credentials.json`) |
| `HICCUP_M365_CLIENT_ID`, `HICCUP_M365_TENANT` | the Entra ID app registration for Microsoft 365 sync |

## What lives in `~/.hiccup`

| Path | Contents |
|---|---|
| `config.json` | your config (0600) |
| `burp.json`, `mitm.json` | the running extension's or addon's URL and token, rewritten on every load (0600) |
| `sessions/<site>/<account>.json` | saved sessions (0600) |
| `sites/<site>/` | auth matrix recordings, results and `expectations.json` |
| `bapps/` | downloaded BApps; `jython/` and `jruby/` runtimes |
| `google/` | Google credentials and token (0600) |
| `microsoft/` | Microsoft 365 token (0600) |
| `browser-profile*` | the automated browser's profiles |
| `*.log` | Burp, mitmproxy and browser logs from the last start |
