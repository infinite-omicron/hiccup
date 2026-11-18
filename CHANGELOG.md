# Changelog

## [0.2.0](https://github.com/infinite-omicron/hiccup/compare/v0.1.0...v0.2.0) (2026-11-18)


### Features

* **matrix:** color account rows by whether expected and actual match ([44a11db](https://github.com/infinite-omicron/hiccup/commit/44a11db9e2788c5483f7ba63a488a1484168ff44))
* **matrix:** export to excel by default and open the workbook ([e98fbab](https://github.com/infinite-omicron/hiccup/commit/e98fbab42ff329396c19a2d412958edeb2d8365b))
* **matrix:** log in and record accounts in parallel ([19d642a](https://github.com/infinite-omicron/hiccup/commit/19d642ae30309c399c007595d1260972b3201e68))
* **matrix:** map the site's nav as menu paths and crawl it by depth ([c23366a](https://github.com/infinite-omicron/hiccup/commit/c23366a002f181f3792ce701ae2b3d4a7a1327d7))
* **matrix:** show finding labels after the result ([ab8380a](https://github.com/infinite-omicron/hiccup/commit/ab8380a9d69f7545da39ec73b1a4e84a71907b9b))
* **matrix:** sync the auth matrix workbook to onedrive and sharepoint ([84481ec](https://github.com/infinite-omicron/hiccup/commit/84481ec993af90b0359433651234e3e579ed497a))
* **matrix:** word findings as potential privilege escalation ([7657a98](https://github.com/infinite-omicron/hiccup/commit/7657a984761c51239cef05e23d95cbd1ffbbbdc4))
* **proxy:** per-account browsers and proxy listeners ([2d0a2f4](https://github.com/infinite-omicron/hiccup/commit/2d0a2f47a258209ff2ae5ff618a8b10e27e23349))


### Bug Fixes

* **extension:** serve the API without jdk.httpserver ([659812b](https://github.com/infinite-omicron/hiccup/commit/659812b1325eda4dcebf50a43f4c2eaf0a42c69b)), closes [#7](https://github.com/infinite-omicron/hiccup/issues/7)
* **login:** recover when the browser detaches the page mid-login ([584d0e2](https://github.com/infinite-omicron/hiccup/commit/584d0e2a73995837f7622a8e182de2a17c0d2a9e))
* **login:** suggest valid syntax when an account has no session ([7102a36](https://github.com/infinite-omicron/hiccup/commit/7102a36581b282145c2d97338f2ef838366e7137))
* **matrix:** open a fresh workbook when the old one is still open ([ee7fadb](https://github.com/infinite-omicron/hiccup/commit/ee7fadb9da57bc4cc5b6d506247c31ef8a903d26))
* **matrix:** stack actions vertically in columns A-D ([318283b](https://github.com/infinite-omicron/hiccup/commit/318283b3d3b41eb5bcdc6034fa37f96668903535))
* **matrix:** wait for the opener to hand the workbook to the app ([2e9b2f4](https://github.com/infinite-omicron/hiccup/commit/2e9b2f494e503cf667d64acc4a3603b684a6213b))
* **matrix:** write the auth matrix workbook owner-only ([5cab745](https://github.com/infinite-omicron/hiccup/commit/5cab745a1e851f288c30b5ab0ee1cac6f122f85e))
* **scope:** accept bare hostnames in scope commands ([ebbf86d](https://github.com/infinite-omicron/hiccup/commit/ebbf86de519109bcdd1fead8965b8bd3e746fe74)), closes [#10](https://github.com/infinite-omicron/hiccup/issues/10)


### Documentation

* document bare-host scope and running two burps with hiccup ([677047a](https://github.com/infinite-omicron/hiccup/commit/677047aea24e98f54aee490f32b03daf311113b4))
* document nav mapping, depth and excluding action links ([6bda753](https://github.com/infinite-omicron/hiccup/commit/6bda7532487cee0c6cb20334c0373f7368736e5a))
* document parallel accounts, per-account ports and the password manager ([e300eae](https://github.com/infinite-omicron/hiccup/commit/e300eae050d1ac8020b8f358c257635fa0fc3105))
* document the excel default and microsoft 365 sync ([acd792a](https://github.com/infinite-omicron/hiccup/commit/acd792aab32b4879e07c766dfd15a1e9f3eb884b))
* move usage docs out of the readme into docs/ ([8018b16](https://github.com/infinite-omicron/hiccup/commit/8018b160c9446079203413b0e774fe6f701db08d))

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
