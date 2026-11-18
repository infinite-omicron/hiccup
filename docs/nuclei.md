# Nuclei findings as issues

```sh
hiccup run nuclei -- -u https://target.test -tags exposure   # through the proxy, with the site's throttle and User-Agent
nuclei -u https://target.test -jsonl | hiccup import nuclei -
hiccup import nuclei results.jsonl --dry-run                  # print the issues instead of adding them
```

`hiccup run nuclei` adds the following to Nuclei's arguments, unless you set them yourself:

- `-proxy` with the proxy's listener, so the requests show up in history and go through the throttle
- `-rl`/`-rld`, `-c 1 -bs 1` and a longer `-timeout`, from the site's throttle
- `-H "User-Agent: ..."` with the site's User-Agent
- `-jsonl -o <tmp>`, so the results can be imported afterwards (`--no-import` skips that)

Everything after `--` goes to Nuclei unchanged.

**Severities:**

| Nuclei | Burp |
|---|---|
| critical, high | High |
| medium | Medium |
| low | Low |
| info | Information |

Each finding's request and response are attached as evidence when Nuclei recorded them. Network, DNS and SSL findings get an `https://host/` URL.

**Burp Community silently discards issues that extensions add**, so importing into Burp needs Burp Professional. On Community, hiccup exits with code 3 instead of pretending the import succeeded. With ZAP the findings become alerts, and with mitmproxy they're stored by the addon; see [proxies.md](proxies.md).
