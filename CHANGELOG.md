# Changelog

## [0.2.0](https://github.com/infinite-omicron/hiccup/compare/v0.1.0...v0.2.0) (2026-11-18)


### Features

* **bapp:** install extensions from the BApp Store ([3ec4459](https://github.com/infinite-omicron/hiccup/commit/3ec4459b285940c85f7cd83958e7f67c0bbeef0c))
* **browser:** launch a local chrome-family browser for proxies without one ([eed02b1](https://github.com/infinite-omicron/hiccup/commit/eed02b12e6a4f58b0d6bb612b8a6ceac312dc5aa))
* **burp:** find hiccup-burp.jar next to the hiccup binary ([efe26ee](https://github.com/infinite-omicron/hiccup/commit/efe26ee2b2d435a4ee4f33b4f3a3629fc88490f1))
* **cli:** add hiccup cli for driving burp from scripts and agents ([9ceb6e6](https://github.com/infinite-omicron/hiccup/commit/9ceb6e6e2a766e7a37f852e16c33d72e08344240))
* **cli:** select burp, zap or mitmproxy as the backend ([7209a1a](https://github.com/infinite-omicron/hiccup/commit/7209a1a7334d16ba7d76eb0f54f138ffab5743f4))
* **extension:** add hiccup-burp montoya extension exposing a local rest api ([b7d429d](https://github.com/infinite-omicron/hiccup/commit/b7d429dc96287b6d99fea89294007cd1a83ffa19))
* **extension:** report the extension version in health ([83fcddc](https://github.com/infinite-omicron/hiccup/commit/83fcddc873cd0e9fb8d7dfa272317a4af9a4fc8c))
* **login:** add login recipes and per-account session capture ([f2cd552](https://github.com/infinite-omicron/hiccup/commit/f2cd552a8bec1d9fee0b5ea53dd4cb5573f8751b))
* **matrix:** add auth matrix for horizontal and vertical privilege escalation ([1ca62f9](https://github.com/infinite-omicron/hiccup/commit/1ca62f9b30a33682ddc3dfd6e9b6f366a024faa1))
* **matrix:** export the auth matrix to google sheets ([66a1618](https://github.com/infinite-omicron/hiccup/commit/66a1618752df138fcbfb57995f6a32a2298278d1))
* **mitm:** add mitmproxy backend ([273d8cb](https://github.com/infinite-omicron/hiccup/commit/273d8cb14516e18ba132da84a3603f27408b48f0))
* **zap:** add zap backend ([ef6191d](https://github.com/infinite-omicron/hiccup/commit/ef6191d849e808cb73035332eca1a5d64a5f523d))


### Bug Fixes

* **burp:** only preload hiccup via user config in headless mode ([05e6b68](https://github.com/infinite-omicron/hiccup/commit/05e6b68bf7afcfb30121648ae909c5495ff8a73f))


### Refactoring

* **matrix:** build the auth matrix grid once for every export ([e3b6e68](https://github.com/infinite-omicron/hiccup/commit/e3b6e689b850b1b5a1c07246e951d947bb272b16))
* rename HICCUP_BACKEND to HICCUP_PROXY and config backend to proxy ([7f7f56a](https://github.com/infinite-omicron/hiccup/commit/7f7f56a1c21c38a180c92090d25322fb3623bd74))
* rename the backend package to proxy ([8d83b7e](https://github.com/infinite-omicron/hiccup/commit/8d83b7e599a033a6ab0c2d1e5a90e9ed4408355e))


### Documentation

* add hiccup design proposal ([43ee3df](https://github.com/infinite-omicron/hiccup/commit/43ee3df554f6f9f977a386da454b791da0710b1d))
* add readme with usage and burp quirks found in testing ([12793ab](https://github.com/infinite-omicron/hiccup/commit/12793ab45bd3d73bc9c9bd7de11cf7de74b2a16a))
* document bapp installs, burp start/stop and sheets export ([3d3a0d0](https://github.com/infinite-omicron/hiccup/commit/3d3a0d080935b0c0fda58f6500af62254bdef9f0))
* document logins and the auth matrix ([549b75d](https://github.com/infinite-omicron/hiccup/commit/549b75dd607bb05fc4e6cbbf67adabdf3c52c68f))
* document releases and commit conventions ([486e12d](https://github.com/infinite-omicron/hiccup/commit/486e12d8dd05558eb31f28d63bc1e42b08ae2a31))
* document the zap and mitmproxy backends ([fdc58dc](https://github.com/infinite-omicron/hiccup/commit/fdc58dcfb54f270787cc9b2cb930513e16b8cf77))

## 0.1.0 (2026-11-18)


### Features

* **bapp:** install extensions from the BApp Store ([3ec4459](https://github.com/infinite-omicron/hiccup/commit/3ec4459b285940c85f7cd83958e7f67c0bbeef0c))
* **browser:** launch a local chrome-family browser for proxies without one ([eed02b1](https://github.com/infinite-omicron/hiccup/commit/eed02b12e6a4f58b0d6bb612b8a6ceac312dc5aa))
* **burp:** find hiccup-burp.jar next to the hiccup binary ([efe26ee](https://github.com/infinite-omicron/hiccup/commit/efe26ee2b2d435a4ee4f33b4f3a3629fc88490f1))
* **cli:** add hiccup cli for driving burp from scripts and agents ([9ceb6e6](https://github.com/infinite-omicron/hiccup/commit/9ceb6e6e2a766e7a37f852e16c33d72e08344240))
* **cli:** select burp, zap or mitmproxy as the backend ([7209a1a](https://github.com/infinite-omicron/hiccup/commit/7209a1a7334d16ba7d76eb0f54f138ffab5743f4))
* **extension:** add hiccup-burp montoya extension exposing a local rest api ([b7d429d](https://github.com/infinite-omicron/hiccup/commit/b7d429dc96287b6d99fea89294007cd1a83ffa19))
* **extension:** report the extension version in health ([83fcddc](https://github.com/infinite-omicron/hiccup/commit/83fcddc873cd0e9fb8d7dfa272317a4af9a4fc8c))
* **login:** add login recipes and per-account session capture ([f2cd552](https://github.com/infinite-omicron/hiccup/commit/f2cd552a8bec1d9fee0b5ea53dd4cb5573f8751b))
* **matrix:** add auth matrix for horizontal and vertical privilege escalation ([1ca62f9](https://github.com/infinite-omicron/hiccup/commit/1ca62f9b30a33682ddc3dfd6e9b6f366a024faa1))
* **matrix:** export the auth matrix to google sheets ([66a1618](https://github.com/infinite-omicron/hiccup/commit/66a1618752df138fcbfb57995f6a32a2298278d1))
* **mitm:** add mitmproxy backend ([273d8cb](https://github.com/infinite-omicron/hiccup/commit/273d8cb14516e18ba132da84a3603f27408b48f0))
* **zap:** add zap backend ([ef6191d](https://github.com/infinite-omicron/hiccup/commit/ef6191d849e808cb73035332eca1a5d64a5f523d))


### Bug Fixes

* **burp:** only preload hiccup via user config in headless mode ([05e6b68](https://github.com/infinite-omicron/hiccup/commit/05e6b68bf7afcfb30121648ae909c5495ff8a73f))


### Refactoring

* **matrix:** build the auth matrix grid once for every export ([e3b6e68](https://github.com/infinite-omicron/hiccup/commit/e3b6e689b850b1b5a1c07246e951d947bb272b16))
* rename HICCUP_BACKEND to HICCUP_PROXY and config backend to proxy ([7f7f56a](https://github.com/infinite-omicron/hiccup/commit/7f7f56a1c21c38a180c92090d25322fb3623bd74))
* rename the backend package to proxy ([8d83b7e](https://github.com/infinite-omicron/hiccup/commit/8d83b7e599a033a6ab0c2d1e5a90e9ed4408355e))


### Documentation

* add hiccup design proposal ([43ee3df](https://github.com/infinite-omicron/hiccup/commit/43ee3df554f6f9f977a386da454b791da0710b1d))
* add readme with usage and burp quirks found in testing ([12793ab](https://github.com/infinite-omicron/hiccup/commit/12793ab45bd3d73bc9c9bd7de11cf7de74b2a16a))
* document bapp installs, burp start/stop and sheets export ([3d3a0d0](https://github.com/infinite-omicron/hiccup/commit/3d3a0d080935b0c0fda58f6500af62254bdef9f0))
* document logins and the auth matrix ([549b75d](https://github.com/infinite-omicron/hiccup/commit/549b75dd607bb05fc4e6cbbf67adabdf3c52c68f))
* document releases and commit conventions ([486e12d](https://github.com/infinite-omicron/hiccup/commit/486e12d8dd05558eb31f28d63bc1e42b08ae2a31))
* document the zap and mitmproxy backends ([fdc58dc](https://github.com/infinite-omicron/hiccup/commit/fdc58dcfb54f270787cc9b2cb930513e16b8cf77))
