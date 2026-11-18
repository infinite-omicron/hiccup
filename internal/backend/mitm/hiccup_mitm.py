"""hiccup addon for mitmproxy: serves the same REST API as the hiccup Burp
extension, so the hiccup CLI can drive mitmproxy.

Run: mitmdump -s hiccup_mitm.py --set hiccup_api_port=8097

Like the Burp extension, it listens on 127.0.0.1 only, requires the bearer
token it writes to $HICCUP_HOME/mitm.json, and rejects requests that carry an
Origin header or a non-loopback Host header. Endpoints mitmproxy has no
equivalent for (Repeater, Intruder, scanning, extensions) answer 501.
"""

import asyncio
import base64
import hmac
import http.client as httpclient
import http.server as httpserver
import json
import os
import random
import re
import secrets
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from mitmproxy import ctx, http, version

MAX_FLOWS = 50000


def home() -> Path:
    h = os.environ.get("HICCUP_HOME") or ctx.options.hiccup_home
    return Path(h) if h else Path.home() / ".hiccup"


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def raw_request(req: http.Request) -> bytes:
    head = f"{req.method} {req.path} {req.http_version}\r\n"
    for k, v in req.headers.fields:
        head += f"{k.decode('latin1')}: {v.decode('latin1')}\r\n"
    return head.encode("latin1") + b"\r\n" + (req.raw_content or b"")


def raw_response(resp: http.Response) -> bytes:
    head = f"{resp.http_version} {resp.status_code} {resp.reason}\r\n"
    for k, v in resp.headers.fields:
        head += f"{k.decode('latin1')}: {v.decode('latin1')}\r\n"
    return head.encode("latin1") + b"\r\n" + (resp.raw_content or b"")


class Bucket:
    """GCRA limiter with jitter and 429/503 backoff, like the Burp extension's."""

    def __init__(self, rule):
        self.rule = rule
        self.next_slot = time.monotonic()
        self.paused_until = 0.0
        self.strikes = 0
        self.lock = threading.Lock()

    def reserve(self) -> float:
        r = self.rule
        with self.lock:
            now = time.monotonic()
            interval = 1.0 / r["rps"]
            earliest = now - max(0, r.get("burst", 1) - 1) * interval
            slot = max(self.next_slot, earliest, self.paused_until)
            lo, hi = (r.get("jitter_ms") or [0, 0])[:2]
            self.next_slot = slot + interval + random.uniform(lo, max(lo, hi)) / 1000
            return max(0.0, slot - now)

    def observe(self, status, retry_after):
        b = self.rule.get("backoff") or {}
        with self.lock:
            if status not in (b.get("on_status") or [429, 503]):
                self.strikes = 0
                return
            self.strikes += 1
            max_s = b.get("max_s") or 120
            secs = min(max_s, 2 ** min(self.strikes, 16))
            if b.get("honor_retry_after", True) and retry_after and retry_after.strip().isdigit():
                secs = min(max_s, int(retry_after))
            self.paused_until = max(self.paused_until, time.monotonic() + secs)


class Hiccup:
    def __init__(self):
        self.lock = threading.Lock()
        self.flows = []  # dicts, oldest first
        self.next_id = 1
        self.buckets = {}
        self.ua = None
        self.ua_scope = "browser"
        self.hints = {}
        self.scope = []
        self.issues = []
        self.server = None
        self.token = secrets.token_hex(32)

    # ---- mitmproxy hooks ----

    def load(self, loader):
        loader.add_option("hiccup_api_port", int, 8097, "Port of the hiccup REST API (127.0.0.1).")
        loader.add_option("hiccup_home", str, "", "hiccup state directory (default $HICCUP_HOME or ~/.hiccup).")

    def running(self):
        port = ctx.options.hiccup_api_port
        handler = self._handler_class()
        self.server = httpserver.ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, name="hiccup-api", daemon=True).start()
        self.port = port
        self.issues_path = home() / "mitm-issues.json"
        try:
            self.issues = json.loads(self.issues_path.read_text())
        except (OSError, ValueError):
            self.issues = []
        rt = home() / "mitm.json"
        rt.parent.mkdir(parents=True, exist_ok=True)
        tmp = rt.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"url": f"http://127.0.0.1:{port}", "token": self.token, "pid": os.getpid()}, f)
        os.replace(tmp, rt)
        ctx.log.info(f"hiccup API listening on http://127.0.0.1:{port} (token in {rt})")

    def done(self):
        if self.server:
            self.server.shutdown()
        try:
            (home() / "mitm.json").unlink()
        except OSError:
            pass

    def _bucket(self, host):
        host = host.lower()
        if host in self.buckets:
            return self.buckets[host]
        parts = host.split(".")
        for i in range(1, len(parts)):
            b = self.buckets.get("*." + ".".join(parts[i:]))
            if b:
                return b
        return None

    async def request(self, flow: http.HTTPFlow):
        b = self._bucket(flow.request.pretty_host)
        if b:
            wait = b.reserve()
            if wait > 0:
                await asyncio.sleep(wait)
        # mitmproxy can't tell tools apart, so both scopes rewrite all proxied traffic.
        if self.ua:
            if "User-Agent" in flow.request.headers:
                flow.request.headers["User-Agent"] = self.ua
            for k, v in self.hints.items():
                if k in flow.request.headers:
                    if v:
                        flow.request.headers[k] = v
                    else:
                        del flow.request.headers[k]

    def response(self, flow: http.HTTPFlow):
        b = self._bucket(flow.request.pretty_host)
        if b:
            b.observe(flow.response.status_code, flow.response.headers.get("Retry-After"))
        self._record(flow)

    def error(self, flow: http.HTTPFlow):
        self._record(flow)

    def _record(self, flow):
        req, resp = flow.request, flow.response
        with self.lock:
            item = {
                "id": self.next_id,
                "time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(req.timestamp_start)),
                "method": req.method,
                "url": req.pretty_url,
                "status": resp.status_code if resp else None,
                "length": len(raw_response(resp)) if resp else None,
                "mime": mime(resp),
                "request": raw_request(req),
                "response": raw_response(resp) if resp else None,
                "response_headers": [[k, v] for k, v in resp.headers.items(multi=True)] if resp else [],
            }
            self.next_id += 1
            self.flows.append(item)
            del self.flows[:-MAX_FLOWS]

    # ---- API ----

    def _handler_class(self):
        addon = self

        class Handler(httpserver.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                status, out = 200, None
                try:
                    addon.guard(self)
                    n = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(n) if n else b""
                    body = json.loads(raw) if raw.strip() else {}
                    u = urlsplit(self.path)
                    q = {k: v[0] for k, v in parse_qs(u.query).items()}
                    out = addon.route(self.command, u.path, q, body)
                except HttpError as e:
                    status, out = e.status, {"error": str(e)}
                except (ValueError, KeyError, TypeError) as e:
                    status, out = 400, {"error": f"bad request: {e}"}
                except Exception as e:  # noqa: BLE001 - report, don't crash the proxy
                    status, out = 500, {"error": repr(e)}
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _go

        return Handler

    def guard(self, h):
        if h.headers.get("Origin"):
            raise HttpError(403, "browser requests are not allowed")
        if h.headers.get("Host") not in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            raise HttpError(403, "bad Host header")
        got = (h.headers.get("Authorization") or "").encode()
        if not hmac.compare_digest(got, f"Bearer {self.token}".encode()):
            raise HttpError(401, "missing or bad bearer token")

    def route(self, method, path, q, body):
        key = f"{method} {path}"
        if method == "GET" and path.startswith("/proxy/history/"):
            return self.history_item(int(path.rsplit("/", 1)[1]))
        routes = {
            "GET /health": lambda: {
                "name": "mitmproxy", "version": f"mitmproxy {version.VERSION}", "edition": "MITMPROXY",
                "extension": "hiccup", "proxy": f"{ctx.options.listen_host or '127.0.0.1'}:{ctx.options.listen_port or 8080}",
                "intercept": False,
            },
            "GET /proxy/history": lambda: self.history(q),
            "GET /proxy/intercept": lambda: {"enabled": False},
            "POST /proxy/intercept": lambda: self.set_intercept(body),
            "GET /sitemap": lambda: self.sitemap(q),
            "POST /http/send": lambda: [self.send(r) for r in body["requests"]] if "requests" in body else self.send(body),
            "GET /issues": lambda: [{k: v for k, v in i.items() if k != "evidence"} for i in self.issues
                                    if not q.get("prefix") or i["url"].startswith(q["prefix"])],
            "POST /issues": lambda: self.add_issues(body),
            "GET /scope": lambda: {"url": q["url"], "in_scope": self.in_scope(q["url"])},
            "POST /scope": lambda: self.set_scope(body),
            "GET /throttle": lambda: [b.rule for b in self.buckets.values()],
            "POST /throttle": lambda: self.set_throttle(body),
            "DELETE /throttle": lambda: (self.buckets.clear(), [])[1],
            "GET /useragent": lambda: {"ua": self.ua, "scope": self.ua_scope, "client_hints": self.hints},
            "POST /useragent": lambda: self.set_ua(body),
            "POST /shutdown": lambda: (threading.Timer(0.3, ctx.master.shutdown).start(), {"ok": True})[1],
        }
        if key in routes:
            return routes[key]()
        if key in ("POST /repeater", "POST /intruder", "POST /scan", "POST /extensions/install",
                   "GET /options/user", "POST /options/user", "GET /options/project",
                   "GET /browser", "POST /browser/launch", "POST /browser/stop"):
            raise HttpError(501, f"mitmproxy has no equivalent for {path}")
        raise HttpError(404, f"no route for {key}")

    def summary(self, f):
        return {k: f[k] for k in ("id", "time", "method", "url", "status", "length", "mime")}

    def history(self, q):
        since, limit = int(q.get("since", -1)), int(q.get("limit", 100))
        contains, in_scope = q.get("contains"), q.get("in_scope") == "true"
        with self.lock:
            rows = [f for f in self.flows if f["id"] > since and (not contains or contains in f["url"])
                    and (not in_scope or self.in_scope(f["url"]))]
        return [self.summary(f) for f in rows[-limit:]]

    def exchange(self, f):
        out = {"method": f["method"], "url": f["url"], "status": f["status"], "length": f["length"],
               "request_b64": base64.b64encode(f["request"]).decode()}
        if f["response"] is not None:
            out["response_b64"] = base64.b64encode(f["response"]).decode()
            out["response_headers"] = f["response_headers"]
        return out

    def history_item(self, id_):
        with self.lock:
            for f in self.flows:
                if f["id"] == id_:
                    return {**self.exchange(f), "id": f["id"], "time": f["time"]}
        raise HttpError(404, f"no proxy history item {id_}")

    def sitemap(self, q):
        prefix, full = q.get("prefix", ""), q.get("full") == "true"
        seen, out = set(), []
        with self.lock:
            for f in reversed(self.flows):
                k = (f["method"], f["url"])
                if f["url"].startswith(prefix) and k not in seen:
                    seen.add(k)
                    out.append(self.exchange(f) if full else {"method": f["method"], "url": f["url"], "status": f["status"]})
        return out

    def set_intercept(self, body):
        if body.get("enabled"):
            raise HttpError(501, "mitmdump has no interactive intercept (use mitmweb)")
        return {"enabled": False}

    def in_scope(self, url):
        return any(url.startswith(p) for p in self.scope)

    def set_scope(self, body):
        urls = body["urls"]
        if body.get("exclude"):
            self.scope = [p for p in self.scope if p not in urls]
        else:
            self.scope += [u for u in urls if u not in self.scope]
        return {"ok": True, "urls": urls}

    def set_throttle(self, body):
        for r in body if isinstance(body, list) else [body]:
            host = r["host"].lower()
            if r.get("rps", 0) <= 0:
                self.buckets.pop(host, None)
            else:
                r["host"] = host
                self.buckets[host] = Bucket(r)
        return [b.rule for b in self.buckets.values()]

    def set_ua(self, body):
        self.ua = body.get("ua") or None
        self.ua_scope = body.get("scope") or "browser"
        self.hints = body.get("client_hints") or {}
        return {"ua": self.ua, "scope": self.ua_scope, "client_hints": self.hints}

    def add_issues(self, body):
        items = body if isinstance(body, list) else [body]
        for i in items:
            if not i.get("name") or not i.get("url"):
                raise HttpError(400, 'issues need "name" and "url"')
            self.issues.append({k: i.get(k) for k in ("name", "url", "severity", "confidence", "detail", "remediation", "evidence")})
        tmp = self.issues_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.issues))
        os.replace(tmp, self.issues_path)
        return {"added": len(items)}

    def send(self, r):
        """Sends a request through this proxy, so it is throttled and recorded."""
        method, target, headers, body, scheme, host, port = parse_send(r)
        proxy_host = ctx.options.listen_host or "127.0.0.1"
        proxy_port = ctx.options.listen_port or 8080
        start = time.monotonic()
        if scheme == "https":
            insecure = ssl.create_default_context()
            insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE  # mitmproxy re-signs TLS
            conn = httpclient.HTTPSConnection(proxy_host, proxy_port, timeout=300, context=insecure)
            conn.set_tunnel(host, port)
            path = target
        else:
            conn = httpclient.HTTPConnection(proxy_host, proxy_port, timeout=300)
            path = f"http://{host}:{port}{target}"
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in headers:
            if k.lower() not in ("content-length", "proxy-connection", "connection"):
                conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        reason = resp.reason or ""
        head = f"HTTP/1.1 {resp.status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in resp.getheaders())
        raw_resp = head.encode("latin1") + b"\r\n" + data
        req_head = f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
        return {"method": method, "url": f"{scheme}://{host}:{port}{target}", "status": resp.status,
                "length": len(raw_resp), "elapsed_ms": int((time.monotonic() - start) * 1000),
                "response_headers": [[k, v] for k, v in resp.getheaders()],
                "request_b64": base64.b64encode(req_head.encode("latin1") + b"\r\n" + body).decode(),
                "response_b64": base64.b64encode(raw_resp).decode()}


def mime(resp):
    if not resp:
        return None
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    for prefix, name in (("image/", "IMAGE"), ("font/", "FONT"), ("text/css", "CSS"), ("audio/", "SOUND"), ("video/", "VIDEO")):
        if ct.startswith(prefix):
            return name
    if "javascript" in ct:
        return "SCRIPT"
    if "json" in ct:
        return "JSON"
    if "html" in ct:
        return "HTML"
    return ct.upper() or None


def parse_send(r):
    """Accepts the Burp extension's request shapes: {url, method, headers, body|body_b64} or {raw|raw_b64, url | host, port, https}."""
    if "raw" in r or "raw_b64" in r:
        raw = base64.b64decode(r["raw_b64"]) if "raw_b64" in r else r["raw"].encode("latin1")
        head, _, body = raw.partition(b"\r\n\r\n")
        if b"\r\n" not in head and b"\n\n" in raw:
            head, _, body = raw.partition(b"\n\n")
        lines = re.split(rb"\r?\n", head)
        method, target = lines[0].decode("latin1").split(" ")[:2]
        headers = [tuple(x.strip() for x in l.decode("latin1").split(":", 1)) for l in lines[1:] if b":" in l]
        if "host" in r:
            scheme = "https" if r.get("https", True) else "http"
            host, port = r["host"], r.get("port") or (443 if scheme == "https" else 80)
        else:
            u = urlsplit(r["url"])
            scheme, host = u.scheme, u.hostname
            port = u.port or (443 if scheme == "https" else 80)
        return method, target, headers, body, scheme, host, port
    u = urlsplit(r["url"])
    scheme, host = u.scheme, u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    hdrs = r.get("headers") or []
    headers = list(hdrs.items()) if isinstance(hdrs, dict) else [tuple(h) for h in hdrs]
    if not any(k.lower() == "host" for k, _ in headers):
        headers.insert(0, ("Host", u.netloc))
    body = base64.b64decode(r["body_b64"]) if r.get("body_b64") else (r.get("body") or "").encode()
    return (r.get("method") or "GET").upper(), target, headers, body, scheme, host, port


addons = [Hiccup()]
