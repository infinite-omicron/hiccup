# Auth matrix: horizontal and vertical privilege escalation

The auth matrix records what each account can do in the app, replays every request as every other account, and reports where access control is missing.

## Logins and sessions

Each site in config lists its roles, each with a privilege `level`, and the role's accounts. An account without a `username` is anonymous. The `login` recipe fills a form:

```json
"login": {"url": "/login", "username": "#email", "password": "#password",
          "submit": "button[type=submit]", "success": {"url_contains": "/dashboard"}},
"session": {"cookies": ["session"], "headers": ["Authorization"]}
```

```sh
hiccup login --all           # every account, each in a fresh browser context
hiccup login user1 --manual  # you log in yourself in the browser, then press Enter
```

hiccup saves each account's session to `~/.hiccup/sessions/<site>/<account>.json`:

- **Cookies:** the session cookies, or only the ones listed under `session.cookies`.
- **Headers:** the headers listed under `session.headers`, such as an `Authorization` token, read from proxy history after login.

Each account logs in in its own browser context, so sessions never mix. If a recipe fails in a terminal, hiccup falls back to manual login.

## Recording, replaying and exporting

```sh
hiccup matrix map --as admin1             # preview: the site's nav as menu paths
hiccup matrix record --as admin1          # log in and open every nav link; one action per menu path
hiccup matrix record --as user1           # recording lower roles too improves the expectations
hiccup login --all                        # fresh sessions for every account
hiccup matrix run                         # replay every recorded request as every account
hiccup matrix show --format table         # findings (--all for every cell)
hiccup matrix export                      # acme-auth-matrix.xlsx, opened in Excel
```

For actions that the nav links don't cover, record by hand:

```sh
hiccup matrix record --as admin1 --manual   # logs in in the visible tab
hiccup matrix mark "Create Document"        # requests from now on belong to this action
hiccup matrix stop
```

## Mapping the nav

`hiccup matrix map --as <account>` logs in and reads the site's navigation from the browser, as that account sees it. Each link gets its **menu path**, which becomes the action's name:

```
Content -> Scheduled content
Admin -> Flush all caches -> Flush CSS and JavaScript
Help -> About
Content -> Documents -> Shared        (a tab on the Documents page, found at --depth 2)
```

- **Submenus:** paths come from the menus around each link: nested lists (`<li>` inside `<li>`), `<details>`/`<summary>` menus, and buttons that open a menu with `aria-controls`. Links in submenus that only appear on hover are found too.
- **Depth:**
  - `map` reads only the landing page by default.
  - `record` uses `--depth 2`: after opening each link, it also follows nav links that are new on that page, such as tabs or a section's own menu, and names them under that page's path.
  - Use `--depth 3` or more for deeper sites. `--max-links` caps the total.
- **Which links:** the default selector covers `nav`, `[role=navigation]`, `[role=menu]`, `[role=menubar]`, `[role=tablist]` and `aside`. Set the site's `nav_selector` to use your own, or pass `--selector`.

**Links that do something:** recording (and `map --depth 2` or more) opens every link with a GET request. Some admin menus run an action on GET, for example Drupal's *Flush all caches*. To skip one, add a regex for its URL or menu path to the site's `exclude` list, e.g. `"exclude": ["/admin/flush", "Flush all caches"]`. Logout is always skipped.

## How it works

- **Recording:**
  - Requests are grouped into actions, named after the link's menu path (e.g. `Content -> Scheduled content`) or your marks.
  - Object references in paths become templates: `/documents/42` -> `/documents/${document_id}`.
  - Static files, out-of-scope hosts, login and logout are dropped. Add more with the site's `exclude` regexes; `nav_selector` chooses which links are clicked.
- **Replay:**
  - Each request is sent through the proxy, and so throttled, once per account.
  - hiccup removes `Cookie`, `Authorization` and the configured session headers, then injects that account's session.
  - Only GET, HEAD and OPTIONS are replayed unless you pass `--unsafe`, because replaying POST, PUT or DELETE as other users changes data.
- **Classification:**
  - **Denied:** 401 or 403, a redirect to login, a 404 the owner doesn't get, or a login page.
  - **Allowed:** a 2xx that looks like the owner's response.
  - **Differs:** a 2xx that doesn't look like the owner's response. It's flagged as `review` for you to check.
- **Expected access:**
  - The recorder is always allowed.
  - A reference to someone's object (`/documents/${document_id}`) is allowed only for accounts at a higher level.
  - Any other request is allowed for accounts at the recorder's level or above, or for any account at or above the level of someone who recorded it themselves.
  - Override any of these in `~/.hiccup/sites/<site>/expectations.json`, e.g. `{"Reports": {"user": "allow"}, "*": {"auditor": "deny"}}`.
- **Findings:** the classification is a heuristic, so workbooks and Burp issues word findings as *potential* issues to confirm by hand. JSON, CSV and `matrix run` use the short codes.

  | Code | Wording | When |
  |---|---|---|
  | `vertical` | Potential vertical privilege escalation | a lower level got access |
  | `horizontal` | Potential horizontal privilege escalation (IDOR) | the same level reached another account's object |
  | `forceful-browsing` | Potential unauthenticated access (forceful browsing) | the anonymous account got access |
  | `review` | Needs review | a 2xx that doesn't look like the owner's response |

If an owner is denied its own recorded requests, `matrix run` warns that its session has probably expired.

## Exports

- **Excel (the default):** `hiccup matrix export` with no output flags writes `<site>-auth-matrix.xlsx` in the current directory and opens it in Microsoft Excel. Without Excel, it opens in your default app for `.xlsx` files, such as Numbers or LibreOffice.
  - **Opening:** only happens in an interactive terminal, never for scripts or agents. `--open` forces it and `--no-open` skips it. `--xlsx <file>` picks another file name.
  - **Already open:** opening a document that's already open only brings its existing window forward, so the app would keep showing the old copy. If Excel or LibreOffice has the default workbook open, the export writes a timestamped copy instead (`<site>-auth-matrix-20261118-124546.xlsx`) and opens that. A file you name with `--xlsx` is overwritten as asked, with a note to reload it in the app.
  - **Layout:** the workbook fills the *Auth Matrix* tab of your checklist template in columns A-D, with one block per action stacked top to bottom:

    | | A | B | C | D |
    |---|---|---|---|---|
    | 1 | | Action: | **Home** | |
    | 2 | | | Exp? | Actual |
    | 3 | Account | | | |
    | 4 | admin1 | | allow: GET /dashboard | GET /dashboard -> 200 allowed |
    | ... | one row per account, then a blank row and the next action (Dashboard, ...) | | | |

    Each block copies the header styles of the template's first block (`B1`, `C1`, `C2`, `D2`, `A3`). Finding cells are highlighted red, and `review` cells amber. The rest of the workbook is kept, and the sheet prints landscape, one page wide.
  - **Template:** set `"matrix": {"template": "~/.hiccup/Checklist.xltx"}` in config, or pass `--template`.
- **Microsoft 365 (OneDrive or SharePoint):** `--m365 <target>` also uploads the workbook, replacing the previous copy, so the team sees the latest matrix in Excel for the web or the desktop app. To sync on every export, set `"matrix": {"m365": "<target>"}` in config; `{site}` in the target is replaced by the site name. Targets:
  - `onedrive:/Pentests/{site}/`: a folder in your OneDrive (the file keeps its name), or `onedrive:/Pentests/matrix.xlsx` for a fixed name
  - a OneDrive or SharePoint **folder URL** copied from the browser, e.g. `https://contoso.sharepoint.com/sites/Pentest/Shared Documents/acme`
  - a **file URL**: that file's content is replaced

  Sign in once with `hiccup m365 login`, a device code you enter at microsoft.com/devicelogin. It uses an Entra ID app registration of your own; see [configuration.md](configuration.md#microsoft-365).
- **Google Sheets:** `--sheets <spreadsheet ID or URL>` fills the same layout in a Google Sheet tab, creating the tab if it's missing. Credentials, in order (see `hiccup google --help`):
  1. a service-account key (share the sheet with its email)
  2. a "Desktop app" OAuth client plus `hiccup google login` once
  3. Application Default Credentials

  The scope is limited to spreadsheets, and the token is stored mode 0600 in `~/.hiccup/google/`.
- **csv** and **json:** one row (or object) per account and request. `--full` adds the base64 requests and responses to the JSON.
- **Burp issues:** `--burp-issues` adds one issue per finding, with the owner's and the other account's request/response as evidence. Needs Burp Professional.

## Test app

`testdata/authapp/app.py` is a small multi-role app with one bug of each kind (horizontal, vertical, unauthenticated). Its nav has hover submenus, an ARIA menu button and page tabs, so `matrix map` should show the paths listed above. hiccup reports exactly those bugs against it, and no false positives on the routes that are properly protected.

```sh
python3 testdata/authapp/app.py      # http://127.0.0.1:18081; accounts admin1, user1, user2 (password "pw")
```
