# Burp

## Starting and stopping Burp

```sh
hiccup burp start --headless            # no GUI; hiccup is preloaded
hiccup burp start                       # GUI; add hiccup-burp.jar once in Extensions, Burp reloads it on every start
hiccup burp stop                        # clean shutdown
```

`burp start` finds Burp's install and its bundled Java runtime, starts Burp, and waits until the hiccup API answers. If hiccup is already running in a Burp, it reports that instead of starting a second one.

- **Headless mode:** hiccup is loaded through Burp's `--user-config-file`. That file's extension list *replaces* Burp's own, which is harmless here because headless Burp never saves user settings.
- **GUI mode:** the GUI does save settings, so it doesn't get this treatment by default; the replaced list could be saved over your own extensions. Use `--preload` to opt in anyway.

**Finding the jar:** `burp start` uses, in order:

1. `--jar <path>`
2. `burp.jar` in config
3. `~/.hiccup/hiccup-burp.jar`
4. the jar next to the `hiccup` binary (release archives and Homebrew)

**Other flags:**

- `--java <path>`: use another Java 21+ runtime instead of Burp's bundled one.
- `--install-dir <path>`: point at a Burp install that isn't in the usual place.
- `--burp-arg <arg>`: pass extra arguments to Burp (repeatable), e.g. `--burp-arg=--project-file=x.burp`.
- `--no-bapps`: don't install the BApps listed in config.

Notes from testing on macOS with Burp Community 2026.11:

- **EULA:** headless Burp asks on stdin to accept its EULA. hiccup only answers yes if you pass `--accept-eula`, which means *you* accept PortSwigger's licence. It always answers the licence-key prompt with Enter (Community, or your stored Pro licence).
- **Gatekeeper:** a freshly installed Burp (`brew install --cask burp-suite`) is quarantined until you open it once from Finder. Until then, macOS kills its bundled Java runtime on launch. Open Burp once, or pass `--java` with a Java 21+ binary.
- **Bundled runtime:** Burp's bundled Java runtime is trimmed. It lacks, for example, `jdk.httpserver`. CI checks that the extension only needs modules Burp ships (see [contributing.md](contributing.md)).

## Burp tools

```sh
hiccup history --contains /api --in-scope --format table
hiccup history get 42 --raw
hiccup sitemap https://target.test/
hiccup send -u https://target.test/api -H 'Authorization: Bearer x' -d '{"a":1}'
hiccup send --raw req.txt --host target.test            # raw HTTP from a file or stdin (-)
hiccup repeater -u https://target.test/admin --tab admin
hiccup intruder --raw req.txt --host target.test
hiccup intercept off                                    # or on; no argument shows the state
hiccup scope add                                        # the site's scope from config
hiccup scope add target.test                            # a bare host means https:// and http://
hiccup scan audit https://target.test/                  # Burp Pro only (exit code 3 otherwise)
hiccup issues list
hiccup issues add --name "IDOR on /docs" --url https://target.test/docs/1 --severity high
hiccup burp install-ext ./ext.jar                       # loads into the running Burp
hiccup burp listeners                                   # proxy listeners; --add-site / --remove (hiccup's only)
```

Scope takes hosts or URLs. A bare host (`target.test`, `target.test:8443`) adds both `https://` and `http://`; a URL keeps its scheme. Burp's scope API only takes URL prefixes, so wildcards like `*.target.test` are rejected: add each host instead.

`hiccup send` goes through Burp, so it is throttled and appears in Burp's Logger, but not in Proxy history.

**Burp Community silently discards issues that extensions add.** `issues add`, the Nuclei import and the auth matrix's `--burp-issues` therefore need Burp Professional. On Community they exit with code 3 instead of pretending to succeed.

## BApp Store extensions

```sh
hiccup bapp search logger
hiccup bapp install "Logger++" Autorize --save   # --save adds them to config burp.bapps
hiccup bapp install                               # everything in config burp.bapps
```

What `bapp install` does:

- **Download and load:** it downloads each BApp into `~/.hiccup/bapps/<uuid>/<serial>/` and unpacks it, rejecting paths that escape the folder. It then loads all the entry points into the running Burp in one batch. Burp reloads every extension once, hiccup included, and the CLI waits for hiccup to come back.
- **Upgrades:** a newer version of a BApp replaces the older one.
- **Pro-only BApps:** skipped on Community.
- **Python and Ruby BApps:** Python ones run on Jython and Ruby ones on JRuby. If Burp has neither configured, hiccup downloads the newest stable `jython-standalone` or `jruby-complete` from Maven Central and points Burp at it.
- **On start:** `hiccup burp start` installs the BApps listed in `burp.bapps`; skip that with `--no-bapps`.
