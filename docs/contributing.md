# Contributing

## Build

Requires Go 1.27+ and a JDK 17+ (the Gradle wrapper fetches Gradle).

```sh
make                          # dist/hiccup-burp.jar and dist/hiccup
make dist                     # also cross-compiles hiccup for darwin/linux/windows x amd64/arm64
make install                  # copies the jar to ~/.hiccup/ where `hiccup burp start` finds it
make test
make release VERSION=v1.2.3   # the release assets, in dist/release/
```

## Layout

| Path | What |
|---|---|
| `extension/` | `hiccup-burp.jar`: the Burp extension (Java, Montoya API) |
| `cmd/hiccup/` | the CLI |
| `internal/proxy/` | the `Proxy` interface, with `burp/`, `zap/` and `mitm/` implementations (`mitm/` embeds the mitmproxy addon) |
| `internal/browser/` | CDP (Chrome DevTools Protocol) automation, the local browser launcher, the relay |
| `internal/authmatrix/` | recording, replay, classification and exports for the auth matrix |
| `internal/{config,secrets,session,bapp,gsheets,importers}/` | config, credentials, sessions, BApp Store, Google Sheets, Nuclei |
| `testdata/authapp/` | a multi-role test app with known access-control bugs |
| `docs/proposal.md` | the original design proposal |

## Commits and pull requests

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org): `<type>(<scope>): <description>`, with types such as `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci` and `chore`. CI rejects pull requests whose commits don't match.
- **`main` is protected:** changes go through a pull request, and must pass CI:
  - the commit check
  - `go vet` and `go test`
  - a build of the jar and all binaries
  - a check that the jar only needs Java modules that Burp's bundled runtime includes

## Releases

Releases follow [SemVer](https://semver.org) and are cut by [release-please](https://github.com/googleapis/release-please). It keeps a release PR open with the next version and `CHANGELOG.md`, computed from the commits:

- `fix` -> patch
- `feat` -> minor
- `!` or a `BREAKING CHANGE:` footer -> major (minor while the version is still 0.x)

Merging the release PR tags `vX.Y.Z` and publishes the GitHub Release. The Release workflow then:

- attaches the `hiccup_X.Y.Z_<os>_<arch>` archives, `hiccup-burp_X.Y.Z.jar` and `checksums.txt`
- signs a build provenance attestation for every file and lists them on the organization's [linked artifacts](https://github.com/orgs/infinite-omicron/artifacts) page
- for stable releases, writes `Casks/hiccup.rb` in [infinite-omicron/homebrew-tap](https://github.com/infinite-omicron/homebrew-tap), using the `HOMEBREW_TAP_DEPLOY_KEY` secret (a deploy key with write access on that repo)

To rebuild the assets for an existing tag, run the Release workflow by hand with that tag:

```sh
gh workflow run release.yml -f tag=vX.Y.Z
```
