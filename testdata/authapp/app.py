#!/usr/bin/env python3
"""A tiny multi-role web app with known access-control bugs, for testing
`hiccup matrix`. Stdlib only. Run: python3 app.py [port]

Accounts (password "pw" for all): admin1 (admin), user1 and user2 (user).

Known bugs:
  - /documents/<id>   any logged-in user can read any document (horizontal)
  - /admin/users      any logged-in user can list users (vertical)
  - /api/export       no authentication at all (forceful browsing)
Correctly protected: /admin (admin only), /documents (logged in), /dashboard.
"""
import html
import http.server
import json
import secrets
import sys
from urllib.parse import parse_qs

USERS = {
    "admin1@test": {"name": "admin1", "role": "admin", "password": "pw"},
    "user1@test": {"name": "user1", "role": "user", "password": "pw"},
    "user2@test": {"name": "user2", "role": "user", "password": "pw"},
}
DOCS = {1: ("user1", "user1 quarterly report"), 2: ("user2", "user2 medical notes"), 3: ("admin1", "admin1 salaries")}
SESSIONS = {}


def page(title, body, user=None):
    nav = ""
    if user:
        own = next(i for i, (o, _) in DOCS.items() if o == user["name"])
        links = [("/dashboard", "Dashboard"), ("/documents", "Documents"), (f"/documents/{own}", "My Document"),
                 ("/api/export", "Export")]
        if user["role"] == "admin":
            links += [("/admin", "Admin"), ("/admin/users", "Users")]
        links.append(("/logout", "Log out"))
        nav = "<nav>" + " ".join(f'<a href="{h}">{t}</a>' for h, t in links) + "</nav>"
    return f"<!doctype html><html><head><title>{html.escape(title)}</title></head><body>{nav}<h1>{html.escape(title)}</h1>{body}</body></html>"


class App(http.server.BaseHTTPRequestHandler):
    def user(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session" and v in SESSIONS:
                return SESSIONS[v]
        return None

    def send(self, status, body, ctype="text/html", headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to, headers=()):
        self.send(302, "", headers=[("Location", to), *headers])

    def do_GET(self):
        u, path = self.user(), self.path.split("?")[0]
        if path == "/":
            return self.redirect("/dashboard" if u else "/login")
        if path == "/login":
            form = ('<form method="post" action="/login"><input id="email" name="email">'
                    '<input id="password" name="password" type="password"><button type="submit">Sign in</button></form>')
            return self.send(200, page("Sign in", form))
        if path == "/logout":
            return self.redirect("/login", [("Set-Cookie", "session=; Max-Age=0")])
        if path == "/api/export":  # BUG: no auth check
            return self.send(200, json.dumps({"users": sorted(v["name"] for v in USERS.values())}), "application/json")
        if not u:
            return self.redirect("/login")
        if path == "/dashboard":
            return self.send(200, page("Dashboard", f"<p>Welcome {u['name']} ({u['role']})</p>", u))
        if path == "/documents":
            mine = [f'<li><a href="/documents/{i}">{t}</a></li>' for i, (o, t) in DOCS.items() if o == u["name"]]
            return self.send(200, page("Documents", "<ul>" + "".join(mine) + "</ul>", u))
        if path.startswith("/documents/"):
            try:
                owner, text = DOCS[int(path.rsplit("/", 1)[1])]
            except (ValueError, KeyError):
                return self.send(404, page("Not found", ""))
            # BUG: no ownership check
            return self.send(200, page("Document", f"<p>{html.escape(text)}</p><p>owner: {owner}</p>", u))
        if path == "/admin":
            if u["role"] != "admin":
                return self.send(403, page("Forbidden", "<p>admins only</p>", u))
            return self.send(200, page("Admin", "<p>admin console</p>", u))
        if path == "/admin/users":  # BUG: missing role check
            rows = "".join(f"<li>{v['name']} ({v['role']})</li>" for v in USERS.values())
            return self.send(200, page("Users", f"<ul>{rows}</ul>", u))
        return self.send(404, page("Not found", "", u))

    def do_POST(self):
        if self.path == "/login":
            n = int(self.headers.get("Content-Length") or 0)
            q = parse_qs(self.rfile.read(n).decode())
            email, pw = q.get("email", [""])[0], q.get("password", [""])[0]
            acct = USERS.get(email)
            if not acct or acct["password"] != pw:
                return self.send(200, page("Sign in", "<p>bad credentials</p>"))
            sid = secrets.token_hex(16)
            SESSIONS[sid] = acct
            return self.redirect("/dashboard", [("Set-Cookie", f"session={sid}; Path=/; HttpOnly")])
        self.send(404, "")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18081
    http.server.ThreadingHTTPServer(("127.0.0.1", port), App).serve_forever()
