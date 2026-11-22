# PlexTrac write-ups

hiccup can pull your company's write-ups from PlexTrac's content library (WriteupsDB) and match them to the findings you're triaging: Burp issues and the auth matrix. For each finding you get the write-up your company already uses, with its description, recommendations and references, ready to review or paste.

hiccup only **reads** from PlexTrac. It never creates, changes or deletes anything there.

## Setup

```json
"plextrac": {
  "url": "https://acme.plextrac.com",
  "username": "tester@example.com",
  "password": "keychain:hiccup/plextrac/tester@example.com",
  "repositories": ["Acme WriteupsDB"],
  "map": "acme.json"
}
```

- **`password`:** plaintext, `env:VAR` or `keychain:...`, like other hiccup credentials (see [configuration.md](configuration.md#credentials)). Leave it empty to be asked at sign-in. `hiccup plextrac login --save-password` stores what you type in the OS keychain and points the config at it.
- **`repositories`:** which WriteupsDB repositories to sync, by name or ID. Leave it out to sync every repository your account can read.
- **`map`:** the file that maps finding names to write-ups (see [Mapping](#mapping)). It's a separate file, so each company's mapping stays out of the config and can be shared with the team. A relative name is in `~/.hiccup/plextrac/`; absolute and `~/...` paths work too. The default is `mapping.json`.

Environment overrides: `HICCUP_PLEXTRAC_URL`, `HICCUP_PLEXTRAC_USERNAME`, `HICCUP_PLEXTRAC_PASSWORD`, `HICCUP_PLEXTRAC_MAP`.

## Signing in and syncing

```sh
hiccup plextrac login      # password (if not configured), then your 6-digit MFA code
hiccup plextrac sync       # copies the write-ups to ~/.hiccup/plextrac/writeups.json
hiccup plextrac logout     # forgets the session; synced write-ups are kept
```

- **Sessions:** a PlexTrac session lasts about 15 minutes, so sync right after signing in. `sync` signs in by itself when run in a terminal without a current session.
- **Rate limit:** PlexTrac allows 10 sign-in attempts a minute.
- **Offline use:** searching, showing and matching only use the synced copy, so they work without a session. Sync again when the library changes.

## Searching and reading

```sh
hiccup plextrac writeups tls                        # write-ups whose title, tags or description contain "tls"
hiccup plextrac writeups --repository "Acme WriteupsDB" --format table
hiccup plextrac show "HSTS Not Enforced"            # by title or ID, as Markdown
hiccup plextrac show template_123 --format json     # the raw fields
```

## Matching findings

```sh
hiccup plextrac match --burp --site-only --format table   # Burp issues on the site's host (false positives skipped)
hiccup plextrac match --matrix --format table             # the last auth matrix run's finding types
hiccup plextrac match --name "Strict transport security not enforced"
hiccup plextrac match --burp --site-only --show           # print each matched write-up in full
```

Each finding is matched in this order:
1. **`mapped`:** the mapping file names a write-up for it.
2. **`exact`:** a write-up has the same title, ignoring case, punctuation and common synonyms (`HSTS` = `Strict Transport Security`, `SSL` = `TLS`, `CSP` = `Content Security Policy`).
3. **`fuzzy`:** the closest title, scored 0-1. 0.5 or more is a match.
4. **`unmatched`:** nothing close enough. The three closest titles are listed as suggestions.

## Mapping

Teach hiccup which write-up your company uses for each finding:

```sh
hiccup plextrac map "Strict transport security not enforced" "HSTS Not Enforced"
hiccup plextrac map vertical "Broken Access Control - Vertical Privilege Escalation"
hiccup plextrac map --list
hiccup plextrac map --remove "Robots.txt file"
```

- **Finding names:** Burp issue names as Burp shows them, or auth matrix codes (`vertical`, `horizontal`, `forceful-browsing`, `review`) and their labels (`Potential Vertical Privilege Escalation`).
- **Write-ups:** the write-up is saved by ID, so renaming it in PlexTrac doesn't break the mapping.
- **The file:**

  ```json
  {
    "Strict transport security not enforced": "template_101",
    "vertical": "template_204"
  }
  ```

  A mapping to a write-up that's no longer in the synced library is reported as a problem in `match`.

## Files

| Path | Contents |
|---|---|
| `~/.hiccup/plextrac/token.json` | the current session (0600) |
| `~/.hiccup/plextrac/writeups.json` | the synced write-ups (0600) |
| `~/.hiccup/plextrac/<map>` | your finding -> write-up mapping (0600) |
