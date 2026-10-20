"""Defect 6 / BUG-0533 (AU-SESS403, CC-SESS-0029): a forbidden answer is never, by
itself, a lost session.

`session.detect.detect_logout` read every 401 and 403 as a session loss, and
`SessionManager.observe` then marked the session invalid, so the next `prepare` logged
in again. A low-privilege identity denied an admin route, a WAF block on a quote or a
CSRF refusal each cost one login and changed the session in the middle of the run.

These tests run on real loopback apps through the real `SessionManager` (its default
requests fetcher, no browser), the real `core.http.HttpClient` seam and
`SeamProbeSender`. Credentials are in memory (`tests.test_credentials.FakeBackend`, D12).

Each test asserts the layer it guards, with counts taken by the server or by a listener:
- **logins**: the server counts successful logins;
- **invalidations**: an FR-SESS-16 logout listener counts them;
- **checks**: the server counts health GETs, i.e. requests to the app's stable protected
  resource that carry the session and are not the login fetcher's (browser headers);
- **sessions**: the server's own record of the session each probe carried.

The app modes (`_App`) are the shapes the design must tell apart:
- `redirect`: PHP-like, every page redirects to the login;
- `none`: no protected resource;
- `static`: `/` always redirects to `/login`;
- `presence`: `/` reacts to any cookie;
- `forbid`: a lost session gets 403;
- `basic`: HTTP Basic;
- `json`: a JSON/bearer login;
- `rotate` / `rotate_all`: a rotating session id.

Every new-API keyword (`clock`, `sleep`, the bounds) is passed only when
`SessionManager` accepts it, so every test also runs against today's code.

A test marked ``_BUG_0533`` fails on the base (15a8a27 + 7ebf48a). It is a strict
xfail until CC-SESS-0029 lands and removes the marker. Every test passes with the
revision-2 prototype patched in
(`docs/components/03-session-manager/au-sess403-prototype/`, ``-p proto_plugin``).
Every test also fails against its named revert (``REVERT=<name>``; `run_reverts.sh`;
DRAFT-AU-SESS403 §6).

``python3 -m tests.test_session_forbidden_answers`` prints the measurement table the
draft cites."""

from __future__ import annotations

import ast
import base64
import inspect
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import HttpClient, Request
from fuzzlab.core.net import require_loopback
from fuzzlab.session import detect
from fuzzlab.session.manager import SessionAuthError, SessionManager
from fuzzlab.session.state import SessionState
from fuzzlab.tools.probesender import SeamProbeSender
from tests.test_credentials import FakeBackend

HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parents[1]
#: identity -> (username, password, role)
ACCOUNTS = {"user": ("alice", "pw-alice-0533", "user"),
            "admin": ("root", "pw-root-0533", "admin")}
#: Probes per scenario.
N = 10

_BUG_0533 = pytest.mark.xfail(
    strict=True, reason="BUG-0533: a forbidden or unconfirmed answer logs the session in "
                        "again (defect 6); CC-SESS-0029 removes this marker")

#: The stable protected resource each mode's login should record (None: none can be).
RESOURCE = {"redirect": "/", "static": "/dashboard", "presence": "/home.php",
            "forbid": "/", "basic": "/", "rotate": "/", "rotate_all": "/",
            "none": None, "json": None}


def _login_page(token: str, action: str = "/login.php") -> bytes:
    return (f"<html><body><form method='post' action='{action}'>"
            f"<input type='hidden' name='user_token' value='{token}'>"
            "<input type='text' name='username'>"
            "<input type='password' name='password'>"
            "<input type='submit' name='Login' value='Login'>"
            "</form></body></html>").encode()


_JSON_SHELL = (b"<html><body><form id='f'><input name='email'>"
               b"<input type='password' name='password'><button>Sign in</button></form>"
               b"<script>document.getElementById('f').onsubmit = function (e) {"
               b" e.preventDefault(); fetch('/api/login', {method: 'POST', headers: "
               b"{'Content-Type': 'application/json'}, body: JSON.stringify({email: "
               b"this.email.value, password: this.password.value})}); };</script>"
               b"</body></html>")

_SETTINGS = (b"<html><body><h1>Settings</h1><form method='post' action='/settings.php'>"
             b"<input type='password' name='new_password'><input type='submit'>"
             b"</form></body></html>")


class _App:
    """A loopback app in one of the modes above (see the module docstring and
    `_route`). Each request is recorded when it arrives as ``(method, path, SID,
    browser_headers, carries_authorization)``.

    Controls for the health GETs (a GET of the mode's resource that carries the
    session, sent without the login fetcher's browser headers):
    - ``health_status``: answer every health GET with this status.
    - ``health_queue``: statuses for the next health GETs, one each (None: answer
      normally); used before ``health_status``.
    - ``health_redirect``: answer every health GET with a 302 to this URL.
    - ``hold_health``: ``(arrived, release, status)``; the next health GET sets
      ``arrived``, waits for ``release``, then answers ``status`` (None: normally).
    - ``hold_health_until``: the next health GET waits, bounded, until this callable
      returns True.
    - ``rotate_health``: a live health GET rotates the session id.
    - ``offorigin_login``: `/` sends an anonymous visitor to this login URL on another
      origin (an IdP).

    Other controls:
    - ``referer_bound``: a request that carries a live session and a ``Referer`` ends
      that session, as a session bound to a header does.
    - ``round_size``: ``/sync403.php`` and ``/api/r<n>`` hold each request until a
      round has arrived."""

    def __init__(self, *, mode: str = "redirect", round_size: int = 1):
        assert mode in RESOURCE, mode
        self.mode = mode
        self.login_path = "/login" if mode == "static" else "/login.php"
        self.resource_path = RESOURCE[mode]
        self._lock = threading.Lock()
        self.sessions: dict[str, str | None] = {}     # SID -> identity (None: anonymous)
        self.csrf: dict[str, str] = {}
        self.tokens: set[str] = set()
        self.bearers: dict[str, str] = {}
        self.basic_expired = False
        self.logins = 0
        self.requests: list[tuple[str, str, str | None, bool, bool]] = []
        self.slow_arrived = threading.Event()
        self.slow_release = threading.Event()
        self.round = threading.Barrier(round_size) if round_size > 1 else None
        self.health_status: int | None = None
        self.health_queue: list = []
        self.health_redirect: str | None = None
        self.hold_health: tuple | None = None
        self.hold_health_until = None
        self.rotate_health = False
        self.referer_bound = False
        self.offorigin_login: str | None = None
        self.server = self._serve()
        self.base = f"http://{HOST}:{self.server.server_address[1]}/"

    # -- controls ---------------------------------------------------------------------
    def close(self) -> None:
        self.slow_release.set()
        if self.hold_health is not None:
            self.hold_health[1].set()
        self.server.shutdown()
        self.server.server_close()

    def expire_all(self) -> None:
        """The server ends every logged-in session (an expiry)."""
        with self._lock:
            for sid in [s for s, who in self.sessions.items() if who]:
                del self.sessions[sid]
            self.bearers.clear()
            self.basic_expired = True

    def issue_session(self, identity: str) -> str:
        """A fresh logged-in SID, made server-side (for an adopted session)."""
        sid = "sess-" + secrets.token_hex(16)
        with self._lock:
            self.sessions[sid] = identity
            self.csrf[sid] = secrets.token_hex(8)
        return sid

    def sids(self, path: str) -> set:
        with self._lock:
            return {sid for _m, p, sid, _b, _a in self.requests if p == path}

    def health_gets(self) -> int:
        """Health GETs the server received (the whole log)."""
        with self._lock:
            return sum(1 for m, p, sid, browser, auth in self.requests
                       if m == "GET" and p == self.resource_path and not browser
                       and (sid is not None or auth))

    def count(self) -> int:
        with self._lock:
            return len(self.requests)

    # -- the server -------------------------------------------------------------------
    def _serve(self) -> ThreadingHTTPServer:
        require_loopback(HOST)                     # PA-0130: a loopback listener only
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "SID":
                        return value
                return None

            def _send(self, status, body=b"", headers=(), ctype="text/html"):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _form(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if "json" in (self.headers.get("Content-Type") or ""):
                    try:
                        doc = json.loads(raw or b"{}")
                        return doc if isinstance(doc, dict) else {}
                    except ValueError:
                        return {}
                return dict(parse_qsl(raw.decode(), keep_blank_values=True))

            def _who(self, sid, auth):
                with app._lock:
                    if app.mode == "json":
                        token = auth[7:] if auth.startswith("Bearer ") else ""
                        return app.bearers.get(token)
                    if app.mode == "basic":
                        for ident, (user, pw, _r) in ACCOUNTS.items():
                            good = "Basic " + base64.b64encode(
                                f"{user}:{pw}".encode()).decode()
                            if auth == good and not app.basic_expired:
                                return ident
                        return None
                    return app.sessions.get(sid) if sid else None

            def _health(self, path, sid, auth, browser):
                """A health GET's controls; returns True when it has answered."""
                if not (path == app.resource_path and not browser and (sid or auth)):
                    return False
                hold, app.hold_health = app.hold_health, None
                if hold is not None:
                    arrived, release, status = hold
                    arrived.set()
                    release.wait(10)
                    if status is not None:
                        self._send(status, b"<h1>held</h1>")
                        return True
                until, app.hold_health_until = app.hold_health_until, None
                if until is not None:
                    import time
                    for _ in range(200):
                        if until():
                            break
                        time.sleep(0.05)
                status = app.health_queue.pop(0) if app.health_queue else app.health_status
                if status is not None:
                    self._send(status, b"<h1>unavailable</h1>", [("Retry-After", "1")])
                    return True
                if app.health_redirect is not None:
                    self._send(302, b"", [("Location", app.health_redirect)])
                    return True
                return False

            def _route(self, method):
                parts = urlsplit(self.path)
                path, sid = parts.path, self._sid()
                auth = self.headers.get("Authorization") or ""
                browser = (self.headers.get("User-Agent") or "").startswith("Mozilla")
                with app._lock:
                    app.requests.append((method, path, sid, browser, bool(auth)))
                    known = sid in app.sessions
                form = self._form()
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                who = self._who(sid, auth)
                if who and app.referer_bound and self.headers.get("Referer"):
                    with app._lock:                    # a session bound to a header
                        app.sessions.pop(sid, None)
                    who = None
                if method == "GET" and self._health(path, sid, auth, browser):
                    return None
                role = ACCOUNTS[who][2] if who else None
                login = [("Location", app.login_path)]
                if app.mode == "basic":
                    return self._basic(path, who, auth)
                if app.mode == "json":
                    return self._json(method, path, who, form)
                if path == app.login_path and method == "GET":
                    if who and app.mode == "static":
                        return self._send(302, b"", [("Location", "/dashboard")])
                    extra = []
                    if not known:                       # PHP's session_start()
                        anon = "anon-" + secrets.token_hex(12)
                        with app._lock:
                            app.sessions[anon] = None
                        extra = [("Set-Cookie", f"SID={anon}; Path=/; HttpOnly")]
                    token = secrets.token_hex(8)
                    with app._lock:
                        app.tokens.add(token)
                    return self._send(200, _login_page(token, app.login_path), extra)
                if path == app.login_path:
                    return self._login(sid, form)
                if path == "/":
                    return self._root(sid, who)
                if path == "/products.php":
                    return self._send(429, b"<h1>Too Many Requests</h1>",
                                      [("Retry-After", "1")])
                if path == "/slow.php":
                    app.slow_arrived.set()
                    app.slow_release.wait(10)
                    who = self._who(sid, auth)             # judged when it answers
                if who is None:
                    if path.startswith("/api/"):
                        return self._send(401, b'{"error":"unauthenticated"}',
                                          ctype="application/json")
                    if app.mode == "forbid":
                        return self._send(403, b"<h1>Forbidden</h1>")
                    if path == "/profile.php":            # BUG-0113: the form in place
                        return self._send(200, _login_page(secrets.token_hex(8),
                                                           app.login_path))
                    return self._send(302, b"", login)
                rotated = []
                if app.mode == "rotate_all" and method == "GET":
                    rotated = self._rotate(sid)
                if path in ("/home.php", "/slow.php"):
                    return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>".encode(),
                                      rotated)
                if path == "/dashboard":
                    return self._send(200, f"<h1>Dashboard {ACCOUNTS[who][0]}</h1>".encode())
                if path == "/profile.php":
                    return self._send(200, f"<h1>Profile {ACCOUNTS[who][0]}</h1>".encode())
                if path == "/admin.php":
                    return self._send(200, b"<h1>Admin</h1>") if role == "admin" else \
                        self._send(403, b"<h1>403 Forbidden</h1>")
                if path == "/search.php":
                    if "'" in query.get("q", ""):
                        return self._send(403, b"<h1>Request blocked (rule 942100)</h1>")
                    return self._send(200, b"<ul><li>result</li></ul>")
                if path == "/comment.php":
                    with app._lock:
                        good = app.csrf.get(sid)
                    if form.get("csrf") != good:
                        return self._send(403, b"<h1>CSRF token mismatch</h1>")
                    return self._send(200, b"<p>saved</p>")
                if path == "/api/me":
                    return self._send(200, b'{"me":"alice"}', ctype="application/json")
                if path == "/api/reports" or path.startswith("/api/r"):
                    if app.round is not None and path.startswith("/api/r") and \
                            path != "/api/reports":
                        self._wait_round()
                    return self._send(200, b'{"reports":[]}', ctype="application/json") \
                        if role == "admin" else \
                        self._send(401, b'{"error":"insufficient scope"}',
                                   ctype="application/json")
                if path == "/manager.php":
                    return self._send(200, b"<h1>Manager</h1>") if role == "admin" else \
                        self._send(302, b"", [("Location",
                                               f"{app.login_path}?next=/manager.php")])
                if path in ("/account/password.php", "/account/profile.php"):
                    if form.get("current_password") != ACCOUNTS[who][1]:
                        return self._send(401, b"<p>current password is wrong</p>")
                    return self._send(200, b"<p>changed</p>")
                if path == "/csrf.php":                   # DVWA's password change
                    return self._send(200, b"<p>Password Changed.</p>")
                if path == "/bounce.php":                 # it ends the session
                    with app._lock:
                        app.sessions.pop(sid, None)
                    return self._send(302, b"", login)
                if path == "/sync403.php":
                    self._wait_round()
                    return self._send(403, b"<h1>403 Forbidden</h1>")
                return self._send(404, b"not found")

            def _wait_round(self):
                if app.round is not None:
                    try:
                        app.round.wait(10)
                    except threading.BrokenBarrierError:
                        pass

            def _rotate(self, sid):
                new = "sess-" + secrets.token_hex(16)
                with app._lock:
                    who = app.sessions.pop(sid, None)
                    app.sessions[new] = who
                    app.csrf[new] = app.csrf.pop(sid, "")
                return [("Set-Cookie", f"SID={new}; Path=/; HttpOnly")]

            def _root(self, sid, who):
                if app.mode == "static":
                    return self._send(302, b"", [("Location", "/login")])
                if app.mode == "presence":
                    return self._send(200, b"<h1>Welcome back</h1>") if sid else \
                        self._send(302, b"", [("Location", "/login.php")])
                if app.mode == "forbid":
                    return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>".encode()) \
                        if who else self._send(403, b"<h1>Forbidden</h1>")
                if app.mode == "none":
                    return self._send(200, b"<h1>Home</h1>")
                if who is None and app.offorigin_login:     # an IdP's login, elsewhere
                    return self._send(302, b"", [("Location", app.offorigin_login)])
                if app.mode == "rotate" and who:
                    rotated = self._rotate(sid) if app.rotate_health and \
                        not (self.headers.get("User-Agent") or "").startswith("Mozilla") \
                        else []
                    return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>".encode(),
                                      rotated)
                return self._send(302, b"", [("Location",
                                              "/home.php" if who else "/login.php")])

            def _login(self, sid, form):
                ident = next((i for i, (u, p, _r) in ACCOUNTS.items()
                              if u == form.get("username") and p == form.get("password")),
                             None)
                with app._lock:
                    issued = form.get("user_token") in app.tokens
                if ident is None or not issued:
                    return self._send(200, _login_page(secrets.token_hex(8),
                                                       app.login_path))
                new = "sess-" + secrets.token_hex(16)
                with app._lock:
                    app.sessions.pop(sid, None)            # the session id is regenerated
                    app.sessions[new] = ident
                    app.csrf[new] = secrets.token_hex(8)
                    app.logins += 1
                cookie = ("Set-Cookie", f"SID={new}; Path=/; HttpOnly")
                if app.mode == "none":
                    return self._send(200, b"<p>welcome</p>", [cookie])
                landing = {"static": "/dashboard", "forbid": "/"}.get(app.mode, "/home.php")
                return self._send(302, b"", [("Location", landing), cookie])

            def _basic(self, path, who, auth):
                challenge = [("WWW-Authenticate", 'Basic realm="lab"')]
                if not auth:
                    with app._lock:
                        app.basic_expired = False         # re-challenged: a fresh start
                    return self._send(401, b"auth", challenge)
                if who is None:
                    return self._send(401, b"auth", challenge)
                if path == "/":
                    return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>".encode())
                if path == "/settings.php":
                    return self._send(200, _SETTINGS)
                if path == "/api/me":
                    return self._send(200, b'{"me":"alice"}', ctype="application/json")
                return self._send(404, b"not found")

            def _json(self, method, path, who, form):
                if path == "/" and method == "GET":
                    return self._send(200, _JSON_SHELL)
                if path == "/api/login" and method == "POST":
                    ident = next((i for i, (u, p, _r) in ACCOUNTS.items()
                                  if u == form.get("email") and p == form.get("password")),
                                 None)
                    if ident is None:
                        return self._send(401, b'{"error":"wrong"}', ctype="application/json")
                    token = "eyJ" + secrets.token_hex(24)
                    with app._lock:
                        app.bearers[token] = ident
                        app.logins += 1
                    return self._send(200, json.dumps({"token": token}).encode(),
                                      ctype="application/json")
                if who is None:
                    return self._send(401, b'{"error":"unauthenticated"}',
                                      ctype="application/json")
                if path == "/api/me":
                    return self._send(200, b'{"me":"alice"}', ctype="application/json")
                if path == "/api/reports":
                    return self._send(401, b'{"error":"insufficient scope"}',
                                      ctype="application/json")
                return self._send(404, b"not found")

            def do_GET(self):  # noqa: N802 - http.server API
                self._route("GET")

            def do_POST(self):  # noqa: N802 - http.server API
                self._route("POST")

            def log_message(self, *args):
                pass

        class _Server(ThreadingHTTPServer):
            daemon_threads = True

        server = _Server((HOST, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


class FakeClock:
    """The manager's clock and sleep (FR-SESS-23's injectable pair): frozen until
    ``sleep`` advances it; every sleep is recorded."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def _creds() -> CredentialStore:
    store = CredentialStore(backend=FakeBackend())
    for identity, (username, password, _role) in ACCOUNTS.items():
        store.set(HOST, identity, username, password)
    return store


def _manager(**kw):
    """The real manager with its default requests fetcher (no browser), and the list a
    logout listener appends each valid -> invalid transition to (FR-SESS-16). Only the
    keywords this `SessionManager` accepts are passed (today's has none of revision 2's)."""
    params = inspect.signature(SessionManager.__init__).parameters
    mgr = SessionManager(_creds(), scope_hosts=[HOST], browser_login=False,
                         **{k: v for k, v in kw.items() if k in params})
    losses: list[str] = []
    mgr.add_logout_listener(lambda origin, identity: losses.append(identity))
    return mgr, losses


def _fake(**bounds):
    clock = FakeClock()
    return clock, dict(clock=clock, sleep=clock.sleep, **bounds)


def _client(mgr) -> HttpClient:
    return HttpClient(RequestBudget(10_000), [HOST], session=mgr)


def _logged_in(app: _App, **kw):
    """``(mgr, losses, client)``: logged in from the operator's base (FR-SESS-15), as every
    session-using CLI does, so a re-login never derives its base from a probe URL."""
    mgr, losses = _manager(**kw)
    mgr.ensure(HOST, "user", app.base, operator=True)
    return mgr, losses, _client(mgr)


def _sender(app: _App, mgr, identity: str = "user") -> SeamProbeSender:
    return SeamProbeSender(_client(mgr), identity, manager=mgr, base_url=app.base)


def _get(client, app, path, identity="user"):
    req = Request("GET", app.base + path.lstrip("/"), identity=identity)
    return client.send(req), req


def _report(mgr) -> dict:
    report = getattr(mgr, "health_report", None)
    return report().get(f"{HOST}/user", {}) if report else {}


#: One probe of each scenario, as the oracle's seam sends it: ``(path, send)``.
SCENARIOS = {
    "admin-403": ("/admin.php", lambda s, b: s.send(b + "admin.php", "id", "1")),
    "waf-403": ("/search.php", lambda s, b: s.send(b + "search.php?q=a", "q", "a'")),
    "csrf-403": ("/comment.php", lambda s, b: s.send(
        b + "comment.php", "comment", "hi", method="POST", location="body",
        entries=(("comment", "hi"), ("csrf", "")))),
    "throttle-429": ("/products.php", lambda s, b: s.send(b + "products.php", "id", "1")),
    "scope-401": ("/api/reports", lambda s, b: s.send(b + "api/reports", "id", "1")),
    "privilege-login-redirect": ("/manager.php", lambda s, b: s.send(
        b + "manager.php", "id", "1")),
    "password-401": ("/account/password.php", lambda s, b: s.send(
        b + "account/password.php", "current_password", "wrong", method="POST",
        location="body", entries=(("current_password", "wrong"),
                                  ("new_password", "n3w-pass-0533")))),
    "name-only-401": ("/account/profile.php", lambda s, b: s.send(
        b + "account/profile.php", "display_name", "x", method="POST", location="body",
        entries=(("display_name", "x"), ("current_password", "wrong")))),
}


def run_scenario(name: str, n: int = N, *, mode: str = "redirect") -> dict:
    """``n`` probes of scenario ``name`` by the low-privilege identity, on a frozen
    fake clock."""
    path, send = SCENARIOS[name]
    app = _App(mode=mode)
    try:
        _clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        statuses = [send(sender, app.base).status for _ in range(n)]
        return {"probes": n, "logins": app.logins, "invalidations": len(losses),
                "sessions": len(app.sids(path)), "checks": app.health_gets(),
                "statuses": sorted(set(statuses))}
    finally:
        app.close()


def run_expiry(mode: str = "redirect", path: str = "home.php", **bounds) -> dict:
    """A real expiry in the middle of a run: a login, an expiry, then three sends."""
    app = _App(mode=mode)
    try:
        clock, kw = _fake(**bounds)
        mgr, losses = _manager(**kw)
        mgr.ensure(HOST, "user", app.base, operator=True)         # the operator's base
        client = _client(mgr)
        first = _get(client, app, path)[0].status
        app.expire_all()
        after = []
        for _ in range(3):
            try:
                after.append(_get(client, app, path)[0].status)
            except SessionAuthError as exc:
                after.append(type(exc).__name__)
        return {"logins": mgr.login_attempts() if mode == "basic" else app.logins,
                "invalidations": len(losses), "checks": app.health_gets(),
                "statuses": [first] + after, "sleeps": len(clock.sleeps)}
    finally:
        app.close()


def run_stale_answer(mode: str = "redirect") -> dict:
    """A late answer from an earlier session: ``/slow.php`` is sent on session 1 and
    held; the server expires session 1; the loss is seen and session 2 logs in; then
    session 1's late redirect to the login page arrives; then one more send."""
    app = _App(mode=mode)
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")                       # login 1
        late = threading.Thread(target=_get, args=(client, app, "slow.php"), daemon=True)
        late.start()
        assert app.slow_arrived.wait(10)                    # in flight on session 1
        app.expire_all()                                    # the server ends session 1
        _get(client, app, "home.php")                       # the loss is seen
        _get(client, app, "home.php")                       # login 2
        app.slow_release.set()                              # session 1's answer arrives
        late.join(10)
        _get(client, app, "home.php")
        return {"logins": app.logins, "invalidations": len(losses),
                "checks": app.health_gets()}
    finally:
        app.close()


def run_concurrent_rounds(rounds: int, width: int = 6, *, mode: str = "redirect") -> dict:
    """``rounds`` rounds of ``width`` concurrent 403s. The server holds each round until
    all of it has arrived, so every send of a round is prepared before any answer."""
    app = _App(mode=mode, round_size=width)
    try:
        _clock, kw = _fake()
        mgr, losses = _manager(**kw)
        client = _client(mgr)
        per_round = []
        for _ in range(rounds):
            before = app.logins
            threads = [threading.Thread(target=_get, args=(client, app, "sync403.php"),
                                        daemon=True) for _ in range(width)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            per_round.append(app.logins - before)
        return {"logins": app.logins, "logins_per_round": per_round,
                "invalidations": len(losses), "checks": app.health_gets()}
    finally:
        app.close()


def run_protected_resource(mode: str) -> dict:
    """After a login on ``mode``: the stable protected resource and refusal status the
    session recorded."""
    app = _App(mode=mode)
    try:
        mgr, _losses = _manager()
        state = mgr.ensure(HOST, "user", app.base, operator=True)
        url = state.protected_probe
        return {"recorded": url.replace(app.base, "/") if url else None,
                "refusal_status": getattr(state, "probe_refusal_status", None),
                "kind": state.kind}
    finally:
        app.close()


# --- T1-T8: each layer of the decision ------------------------------------------------

@_BUG_0533
@pytest.mark.parametrize("mode", ["redirect", "none"])
@pytest.mark.parametrize("name", ["admin-403", "waf-403", "csrf-403"])
def test_a_forbidden_answer_never_logs_in_and_checks_at_most_once(name, mode):
    """T1 (M2). A 403 is a policy block (SP-56).
    - With a resource it triggers the cached health check: at most one per window.
    - With none it triggers nothing.
    - Never a login, never an invalidation, one session throughout.
    Reverts: `403` (the `none` mode logs in 10 times), `nocache` (10 checks)."""
    got = run_scenario(name, mode=mode)
    assert got["statuses"] == [403], got
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got
    assert got["checks"] == (1 if RESOURCE[mode] else 0), got


@pytest.mark.parametrize("mode", ["redirect", "none"])
def test_a_throttled_answer_never_triggers_anything(mode):
    """T2. A 429 is never a signal: no check, no login. Revert: `throttle`."""
    got = run_scenario("throttle-429", mode=mode)
    assert got["statuses"] == [429], got
    assert (got["logins"], got["invalidations"], got["checks"]) == (1, 0, 0), got


@_BUG_0533
@pytest.mark.parametrize("name", ["scope-401", "privilege-login-redirect"])
def test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in(name):
    """T3. A credentialed 401 or login redirect is a suspected loss. One health check
    finds the session live, the cache covers the other nine, and nothing logs in.
    Reverts: `noconfirm` (10 logins), `nocache` (10 checks)."""
    got = run_scenario(name)
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got
    assert got["checks"] == 1, got


@_BUG_0533
@pytest.mark.parametrize("mode", ["redirect", "none"])
@pytest.mark.parametrize("name", ["password-401", "name-only-401"])
def test_a_credential_submissions_answer_is_checked_never_an_unconfirmed_loss(name, mode):
    """T4 (M3, PA-0529(3)). A credential submission's own 401 is checked when a resource
    is known and never counts as an unconfirmed loss. `name-only-401` is a submission
    only through its field name (`request_entry_names`).
    Reverts: `nosubmission` (`none`: 10 logins), `submission_ignored` (`redirect`: no
    check), `noentrynames` (`none`, name-only: 10 logins)."""
    got = run_scenario(name, mode=mode)
    assert got["statuses"] == [401], got
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got
    assert got["checks"] == (1 if RESOURCE[mode] else 0), got


def test_a_password_change_point_still_recovers_a_real_expiry():
    """T4b (M3). DVWA's `password_new` / `password_conf` point is a credential
    submission. A real expiry seen on it is still confirmed and recovered with exactly
    one login. Revert: `submission_ignored` (never recovered)."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        url = app.base + "csrf.php?password_new=x&password_conf=x&Change=Change"
        first = sender.send(url, "password_new", "n3w").status
        app.expire_all()
        after = [sender.send(url, "password_new", "n3w").status for _ in range(3)]
        assert [first] + after == [200, 302, 200, 200], (first, after)
        assert (app.logins, len(losses)) == (2, 1)
    finally:
        app.close()


def test_a_real_expiry_is_recovered_with_one_login_and_one_check():
    """T5 (a pin). A real expiry is invalidated once, confirmed by at most one check, and
    recovered with exactly one more login. Revert: `redirect_live` (never recovered)."""
    got = run_expiry()
    assert got["statuses"] == [200, 302, 200, 200], got
    assert (got["logins"], got["invalidations"]) == (2, 1), got
    assert got["checks"] <= 1, got


@_BUG_0533
@pytest.mark.parametrize("mode", ["redirect", "none"])
def test_a_late_answer_from_an_earlier_session_is_ignored(mode):
    """T6 (the generation bound). Session 1's late answer says nothing about session 2:
    no check, no invalidation, no login.
    Revert: `nogen` (`none`: a third login; `redirect`: a second check)."""
    got = run_stale_answer(mode)
    assert (got["logins"], got["invalidations"]) == (2, 1), got
    assert got["checks"] == (1 if RESOURCE[mode] else 0), got


def test_the_single_flight_lock_stops_simultaneous_duplicate_logins():
    """T7 (a pin; the audit's claim, measured). Six concurrent first sends cost one
    login."""
    got = run_concurrent_rounds(1, mode="none")
    assert got["logins_per_round"] == [1], got


@_BUG_0533
@pytest.mark.parametrize("mode", ["redirect", "none"])
def test_concurrent_forbidden_rounds_never_log_in_again(mode):
    """T8. The lock does not stop sequential churn: each round of concurrent 403s costs
    one more login today. With the fix it costs none: one check in all (with a resource)
    or none. Revert: `403` (`none`: 4 logins)."""
    got = run_concurrent_rounds(4, mode=mode)
    assert (got["logins"], got["invalidations"]) == (1, 0), got
    assert got["checks"] == (1 if RESOURCE[mode] else 0), got


# --- T9: the stable protected resource (M4, M5) ---------------------------------------

@pytest.mark.parametrize("mode,refusal", [
    pytest.param("redirect", None, marks=_BUG_0533),
    pytest.param("static", None, marks=_BUG_0533),
    pytest.param("presence", None, marks=_BUG_0533),
    pytest.param("forbid", 403, marks=_BUG_0533),
    pytest.param("basic", None, marks=_BUG_0533),
    ("none", None),
])
def test_each_login_records_the_resource_its_answers_prove(mode, refusal):
    """T9. The credentialed answer must be LIVE on the walk that stops at a login
    redirect. The anonymous and the corrupted answers must agree as a refusal.
    - `static`: `/` always redirects to `/login`, so the resource is `/dashboard`.
    - `presence`: `/` answers any cookie, so the resource is `/home.php`.
    - `forbid`: refuses with 403, and that status is recorded.
    - `none`: no resource can be proved.

    A JSON/bearer login records none either (`json`, measured by `measure()`): its
    base is its login page, an auth endpoint, and it has no landing, so no revert can
    make it a candidate.

    Reverts: `rule2verify` (static), `nocorrupt` (presence), `norefusal` (forbid),
    `publicbase` (none)."""
    got = run_protected_resource(mode)
    assert got["recorded"] == RESOURCE[mode], got
    assert got["refusal_status"] == refusal, got


# --- true-positive pins: a real loss is still recovered with exactly one login -------

def test_a_401_expiry_on_an_api_route_is_recovered_with_one_login():
    """TP1. Revert: `redirect_live` (never recovered)."""
    got = run_expiry(path="api/me")
    assert got["statuses"] == [200, 401, 200, 200], got
    assert (got["logins"], got["invalidations"]) == (2, 1), got


def test_an_in_place_login_form_expiry_is_recovered_with_one_login():
    """TP2 (BUG-0113's shape): the page answers 200 with this session's login form.
    Revert: `content_rule_off` (never recovered)."""
    got = run_expiry(path="profile.php")
    assert got["statuses"] == [200, 200, 200, 200], got
    assert (got["logins"], got["invalidations"]) == (2, 1), got


def test_a_basic_expiry_is_recovered_and_a_password_page_is_never_a_signal():
    """TP3 (Basic keeps BUG-0113's exception: its page content is never read).
    - Ten probes of a settings page that shows a password field cause no check.
    - A real expiry is recovered with one login.

    Revert: `basic_content` (the settings page triggers checks)."""
    app = _App(mode="basic")
    try:
        _clock, kw = _fake()
        mgr, losses = _manager(**kw)
        client = _client(mgr)
        assert [_get(client, app, "settings.php")[0].status for _ in range(10)] == [200] * 10
        assert app.health_gets() == 0
        app.expire_all()
        got = [_get(client, app, "api/me")[0].status for _ in range(3)]
        assert got == [401, 200, 200], got
        assert (mgr.login_attempts(), len(losses)) == (2, 1)
    finally:
        app.close()


def test_an_app_that_ends_sessions_with_403_is_recovered_with_one_login():
    """TP4 (M2, M5). The session ends with a 403. The policy block triggers the check;
    the resource answers its recorded refusal status, so the session is LOST (not
    INCONCLUSIVE). Reverts: `norefusal` (an unknown session), `policy_nocheck` (never
    recovered)."""
    got = run_expiry(mode="forbid", max_pause_s=60.0)
    assert got["statuses"] == [200, 403, 200, 200], got
    assert (got["logins"], got["invalidations"], got["sleeps"]) == (2, 1, 0), got


def test_a_page_that_answers_any_cookie_never_hides_a_real_expiry():
    """TP5 (M4b, the corrupted arm). `/` answers any SID with 200, so it cannot be the
    resource. A real expiry is still recovered with one login. Revert: `nocorrupt` (`/`
    is recorded and reads LIVE for a dead session: never recovered)."""
    got = run_expiry(mode="presence")
    assert got["statuses"] == [200, 302, 200, 200], got
    assert (got["logins"], got["invalidations"]) == (2, 1), got


@_BUG_0533
def test_a_static_redirect_base_neither_churns_nor_misses_an_expiry():
    """TP6 (M4a). On the `static` app, ten scope 401s cost one check and no login, and a
    real expiry is recovered with one login. Revert: `rule2verify` (`/` is recorded,
    every check stops at `/login` and reads LOST: 10 logins)."""
    got = run_scenario("scope-401", mode="static")
    assert (got["logins"], got["invalidations"], got["checks"]) == (1, 0, 1), got
    exp = run_expiry(mode="static", path="dashboard")
    assert exp["statuses"] == [200, 302, 200, 200], exp
    assert (exp["logins"], exp["invalidations"]) == (2, 1), exp


@_BUG_0533
def test_an_inconclusive_check_pauses_and_never_changes_the_identity():
    """T12 (FR-SESS-23's pause). The check of a suspicion answers 503, which is
    inconclusive.
    - Nothing changes: no invalidation, no login, no listener.
    - The next send waits the 5 s pause out, checks again (live), and goes out on the
      same session.

    Reverts: `inconclusive_lost` (a logout and a login), `inconclusive_live` (no
    wait)."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.health_queue = [503, None]
        _get(client, app, "api/reports")                          # inconclusive: paused
        assert (losses, app.logins, clock.sleeps) == ([], 1, [])
        assert _get(client, app, "home.php")[0].status == 200
        assert (losses, app.logins, clock.sleeps) == ([], 1, [5.0])
        assert len(app.sids("/home.php")) == 1 and app.health_gets() == 2
    finally:
        app.close()


@_BUG_0533
def test_a_live_verdict_is_cached_for_its_window_its_generation_and_its_url():
    """T14 (M6). A live verdict covers later signals of the same generation and URL key
    within `health_ttl_s` (30 s), and nothing else:
    - another URL is checked;
    - the same URL after the window is checked;
    - the same URL on the next generation is checked.

    Reverts: `nocache`, `cache_nourl`, `cache_nogen`."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        checks = []
        for path in ("api/reports", "api/reports", "admin.php"):
            _get(client, app, path)
            checks.append(app.health_gets())
        clock.t += 31.0
        _get(client, app, "api/reports")
        checks.append(app.health_gets())
        app.expire_all()
        _get(client, app, "home.php")                             # a loss: one check
        _get(client, app, "home.php")                             # re-login: generation 2
        clock.t -= 31.0                                           # inside the window again
        _get(client, app, "api/reports")
        checks.append(app.health_gets())
        assert checks == [1, 1, 2, 3, 5], checks
    finally:
        app.close()


def test_an_expiry_that_redirects_to_another_origins_login_is_lost_at_its_hop():
    """FR-SESS-23's walk. Once the session ends, the resource redirects to an IdP's login
    on another origin. The check stops at that hop and reads the session LOST; it never
    fetches the other origin. A pin: on the base, every 401 is a loss. Revert: `nostop`
    (the walk refuses the hop and raises)."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.offorigin_login = "http://127.0.0.1:1/login"
        app.expire_all()
        assert _get(client, app, "api/me")[0].status == 401
        assert losses == ["user"]
    finally:
        app.close()


# --- M6, M7: the cache, the breakers, single flight, compare-and-set ------------------

@_BUG_0533
def test_n_concurrent_signals_make_one_health_get():
    """M7. Six concurrent 401s on six URLs. The resource answers only after all six
    signals are seen, so the one verdict covers them all: one GET, recorded before the
    lock is released. Revert: `noflight` (six GETs)."""
    app = _App(round_size=6)
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.hold_health_until = lambda: _report(mgr).get("suspected", 0) >= 6
        threads = [threading.Thread(target=_get, args=(client, app, f"api/r{i}"),
                                    daemon=True) for i in range(1, 7)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        assert (app.health_gets(), app.logins, len(losses)) == (1, 1, 0)
    finally:
        app.close()


@_BUG_0533
def test_a_pause_found_for_an_older_generation_never_pauses_the_new_one():
    """M7 (the compare-and-set on the generation).
    1. A check of session 1 is in flight.
    2. Session 2 is adopted meanwhile.
    3. The check then answers 503, which is inconclusive for session 1.
    4. The next send on session 2 neither waits nor rechecks.

    Revert: `nocas` (it waits)."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")                                # login: session 1
        arrived, release = threading.Event(), threading.Event()
        app.hold_health = (arrived, release, 503)
        first = threading.Thread(target=_get, args=(client, app, "api/reports"),
                                 daemon=True)
        first.start()
        assert arrived.wait(10)                                      # session 1's check
        old = mgr._state[(HOST, "user")]
        mgr.adopt(SessionState(HOST, "user", kind="cookie",
                               cookies={"SID": app.issue_session("user")},
                               origins=frozenset(old.origins), login_url=old.login_url))
        release.set()
        first.join(10)
        resp, _req = _get(client, app, "home.php")
        assert resp.status == 200 and clock.sleeps == []
    finally:
        app.close()


def test_a_header_probe_bypasses_a_warm_cache_and_trips_the_breaker_on_its_own_send():
    """T18 (M6).
    1. A scope 401 warms the cache for `/api/reports`.
    2. A `Referer` header probe of that URL ends the session server-side. It carries a
       header the session does not own, so it bypasses the cache.
    3. Its check finds the session lost, and the header breaker trips in that same send.

    Revert: `foreign` (the cache answers LIVE and nothing trips). It passes on the base
    (a pin): there, every 401 is a loss."""
    app = _App()
    app.referer_bound = True
    try:
        _clock, kw = _fake()
        mgr, _losses = _manager(**kw)
        sender = _sender(app, mgr)
        sender.send(app.base + "api/reports", "id", "1")              # warm: checked live
        sender.send(app.base + "api/reports", "Referer", "x", location="header")
        assert (sender.header_stop_reason or "").startswith(
            "session bound to a probed header (Referer"), sender.header_stop_reason
    finally:
        app.close()


@_BUG_0533
def test_listeners_hear_only_a_lost_session_and_a_pause_recheck_has_no_culprit():
    """T17 (FR-SESS-16, M6). The listener is never told for a 403, a live suspicion, a
    cached repeat or an inconclusive check. A loss found by a pause re-check has no
    culprit send, so it is not told either. A loss observed on a send is told once.
    Revert: `notify_pause` (told twice)."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        _get(client, app, "admin.php")                           # 403: a live check
        _get(client, app, "api/reports")                         # 401: a live check
        _get(client, app, "api/reports")                         # cached
        app.health_status = 503
        _get(client, app, "api/r1")                              # inconclusive: paused
        app.health_status = None
        app.expire_all()
        assert _get(client, app, "home.php")[0].status == 200    # re-check: lost, re-login
        assert losses == []
        app.expire_all()
        _get(client, app, "home.php")                            # a loss on this send
        assert losses == ["user"]
    finally:
        app.close()


@_BUG_0533
def test_the_health_and_login_locks_never_deadlock():
    """T24. A confirmed loss is checked under the health lock. The login takes the
    health lock inside the login lock (a new generation ends the old pause). So the
    loss must never re-log in while the health lock is held. Revert:
    `relogin_under_health_lock` (health -> login -> health: the observing send never
    returns)."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.expire_all()
        t = threading.Thread(target=_get, args=(client, app, "home.php"), daemon=True)
        t.start()
        t.join(15)
        assert not t.is_alive(), "the observing send deadlocked"
        assert app.health_gets() == 1
    finally:
        app.close()


# --- M8, M9, M10: unknown health, verify_live, the re-login budget ---------------------

@_BUG_0533
def test_an_unknown_session_is_sticky_and_costs_nothing_after():
    """T13 (M8). The resource answers 503.
    - The suspicion pauses the identity.
    - The next send waits, rechecks, and after `max_pause_s` raises
      `SessionHealthUnknown`.
    - Every later send raises at once: the clock does not move and nothing reaches the
      server.

    Revert: `nosticky` (the third send goes out)."""
    app = _App()
    try:
        clock, kw = _fake(max_pause_s=60.0)
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        sender.send(app.base + "home.php", "id", "1")
        app.health_status = 503
        sender.send(app.base + "api/reports", "id", "1")          # suspected: paused
        with pytest.raises(SessionAuthError):
            sender.send(app.base + "home.php", "id", "1")         # waits, then unknown
        assert sum(clock.sleeps) >= 60.0 and losses == [] and app.logins == 1
        t0, n0 = clock.t, app.count()
        with pytest.raises(SessionAuthError):
            sender.send(app.base + "home.php", "id", "1")
        assert (clock.t, app.count()) == (t0, n0)
    finally:
        app.close()


@_BUG_0533
def test_the_runs_pause_budget_ends_a_second_pause_early():
    """T13b (M8). The first pause resolves after 15 s. The second would last its whole
    40 s bound, but the run's 50 s budget ends it first. Revert: `nobudget` (55 s
    slept)."""
    app = _App()
    try:
        clock, kw = _fake(max_pause_s=40.0, pause_budget_s=50.0)
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.health_queue = [503, 503, None]
        _get(client, app, "api/reports")                          # pause 1
        # pause 1: a 5 s wait, a 503 re-check, a 10 s wait, then a live re-check
        assert _get(client, app, "home.php")[0].status == 200
        assert sum(clock.sleeps) == 15.0, clock.sleeps
        app.health_status = 503
        _get(client, app, "api/r1")                               # pause 2
        with pytest.raises(SessionAuthError):
            _get(client, app, "home.php")
        assert sum(clock.sleeps) <= 50.0, clock.sleeps
    finally:
        app.close()


@_BUG_0533
@pytest.mark.parametrize("max_pause_s,last", [(100.0, "raises"), (300.0, 200)])
def test_relogins_draw_on_a_refilling_budget(max_pause_s, last):
    """T15 (M10). Every probe of `/bounce.php` ends the session, and a confirmed loss
    follows each one. A burst of 2 re-logins is free. The next re-login waits for a
    token (120 s): beyond the pause bound it raises; within it, it logs in. Revert:
    `nobucket` (the fourth probe logs in at once)."""
    app = _App()
    try:
        clock, kw = _fake(relogin_burst=2, relogin_refill_s=120.0, max_pause_s=max_pause_s)
        mgr, _losses = _manager(**kw)
        sender = _sender(app, mgr)
        for _ in range(3):
            sender.send(app.base + "bounce.php", "id", "1")
        assert app.logins == 3 and clock.sleeps == []
        if last == "raises":
            with pytest.raises(SessionAuthError):
                sender.send(app.base + "bounce.php", "id", "1")
            assert app.logins == 3
        else:
            sender.send(app.base + "bounce.php", "id", "1")
            assert app.logins == 4 and clock.sleeps == [120.0]
    finally:
        app.close()


@_BUG_0533
def test_credential_posts_are_counted_and_the_json_control_too():
    """M10. Each account's credential POSTs are counted. A JSON login's wrong-password
    control is counted too, apart: the lockout residual's numbers. Revert: `nocount`."""
    app = _App(mode="json")
    try:
        mgr, _losses = _manager()
        mgr.ensure(HOST, "user", app.base, operator=True)
        assert mgr.health_report()["credential_posts"] == {"control": 1, "submitted": 1}
    finally:
        app.close()


@_BUG_0533
def test_verify_live_waits_out_an_unknown_and_then_reads_live():
    """T21 (M9). The resource answers 503. `verify_live` waits out the bounded pause and
    checks again. Still inconclusive, it keeps today's answer (live), changes nothing,
    and never goes sticky. Revert: `verifylive_false`."""
    app = _App()
    try:
        clock, kw = _fake(max_pause_s=60.0)
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.health_status = 503
        assert mgr.verify_live(HOST, "user", app.base) is True
        assert app.health_gets() >= 2 and sum(clock.sleeps) >= 5.0
        app.health_status = None
        assert _get(client, app, "home.php")[0].status == 200 and app.logins == 1
    finally:
        app.close()


def test_verify_live_never_reads_the_cache():
    """T21b (M6, a pin). After a cached live verdict the server ends the session, and
    `verify_live` still reads it as lost. Revert: `verifylive_cache`."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        _get(client, app, "api/reports")                          # a live check, cached
        app.expire_all()
        assert mgr.verify_live(HOST, "user", app.base) is False
    finally:
        app.close()


# --- ADOPT: fail fast on an unapproved hop; a rotating id; generations; names ---------

@_BUG_0533
def test_an_unapproved_redirect_from_the_resource_fails_fast_and_never_pauses():
    """ADOPT. The resource now redirects to another origin. The check refuses the hop
    (FR-SESS-20) and raises at once; it never pauses. Revert: `hop_pauses`."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.health_redirect = "http://127.0.0.1:1/elsewhere"
        with pytest.raises(SessionAuthError):
            _get(client, app, "api/reports")
        assert clock.sleeps == []
    finally:
        app.close()


@_BUG_0533
def test_a_health_check_never_kills_a_rotating_session():
    """ADOPT. A live health answer that rotates the session id is adopted, so the check
    never kills its own session: the next send uses the new id and nothing logs in.
    Revert: `noadopt` (the next send carries the dead id; a second login)."""
    app = _App(mode="rotate")
    app.rotate_health = True
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        _get(client, app, "api/reports")                          # a live check: rotated
        assert _get(client, app, "home.php")[0].status == 200
        assert (app.logins, len(losses), app.health_gets()) == (1, 0, 1)
    finally:
        app.close()


@_BUG_0533
def test_prepare_records_the_generation_it_applied():
    """T22. A request carries the generation it was prepared with, and a re-login
    starts the next one."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        _resp, first = _get(client, app, "home.php")
        app.expire_all()
        _get(client, app, "home.php")                             # the loss is seen
        _resp, after = _get(client, app, "home.php")              # re-login
        assert (first.session_generation, after.session_generation) == (1, 2)
    finally:
        app.close()


@_BUG_0533
def test_request_entry_names_reads_query_form_and_json_leaves_and_is_total():
    """T23 (SP-16). Revert: `noentrynames`."""
    names = detect.request_entry_names
    assert names("http://h/x?a=1&b=", b"current_password=x&n=1",
                 "application/x-www-form-urlencoded") == ("a", "b", "current_password", "n")
    assert names("http://h/x", b'{"user":{"password":"x"},"k":[1]}',
                 "application/json") == ("user.password", "k[0]")
    for odd in (None, b"\xff\xfe", b"{", b"[1,2]"):
        assert isinstance(names("http://h/x", odd, "application/json"), tuple)
    assert names("http://h/x", b"--b\r\nContent-Disposition: form-data; name=\"p\"",
                 "multipart/form-data; boundary=b") == ()


#: F3 (DRAFT-AU-SESS403 §3.14), a stated residual: the oracle cannot tell a comparison
#: whose probes straddle a re-login, because a probe does not carry the session generation
#: it was sent on. It needs `Probe.session_generation` (set by `SeamProbeSender`) and the
#: oracle's layer-1 check: a FUZZ follow-up with its own CC-FUZZ number.
_F3 = pytest.mark.xfail(strict=True, reason="AU-SESS403 residual R6 (F3): a comparison "
                                            "that straddles a re-login is not detected")


@_F3
def test_a_seam_probe_carries_the_session_generation_it_was_sent_on():
    """F3's first half, pinned (PA-0054(3)). It fails on the base and on the prototype:
    `Probe` has no `session_generation`."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, _losses = _manager(**kw)
        probe = _sender(app, mgr).send(app.base + "home.php", "id", "1")
        assert probe.session_generation == 1
    finally:
        app.close()


# --- T10, T11: SP-16's predicate on its own -------------------------------------------

LOGIN = "http://127.0.0.1:8080/login.php"
PAGE = "http://127.0.0.1:8080/admin.php"


@pytest.mark.parametrize("status", [pytest.param(403, marks=_BUG_0533), 451])
def test_detect_logout_reads_a_policy_block_never_as_a_loss(status):
    """T10. SP-56's policy block (403, 451) is never a loss shape, for a form session
    or a Basic one. 451 never was one (a pin); 403 always was (BUG-0533). Revert:
    `403`."""
    for content_check in (True, False):                     # a Basic session too
        assert not detect.detect_logout(status, {}, "<h1>Forbidden</h1>", login_url=LOGIN,
                                        page_url=PAGE, content_check=content_check)


def test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle():
    """T11 (a pin). A credentialed 401, a redirect to this login page and this login
    form shown again stay loss shapes. A throttle, an unavailable server or a gateway
    never is one. Reverts: `throttle`, `content_rule_off`."""
    assert detect.detect_logout(401, {}, "", login_url=LOGIN, page_url=PAGE)
    assert detect.detect_logout(302, {"Location": "/login.php"}, "", login_url=LOGIN,
                                page_url=PAGE)
    assert detect.detect_logout(200, {}, _login_page("x").decode(), login_url=LOGIN,
                                page_url=PAGE, login_fields=("Login", "password",
                                                             "user_token", "username"))
    for status in (429, 502, 503, 504):
        assert not detect.detect_logout(status, {}, "", login_url=LOGIN, page_url=PAGE)


# --- T19: only the owner decides a session loss (whole package; ADOPT) ----------------

#: Who may write `valid`, and the constant each writes (FR-SESS-23): the one
#: invalidation, and each login end, `adopt`, the anonymous state and a captured one.
VALID_WRITERS = {
    ("fuzzlab/session/manager.py", "SessionManager._mark_lost"): False,
    ("fuzzlab/session/manager.py", "SessionManager.adopt"): True,
    ("fuzzlab/session/manager.py", "SessionManager.ensure"): True,
    ("fuzzlab/session/manager.py", "SessionManager._established"): True,
    ("fuzzlab/session/manager.py", "SessionManager._browser_login_state"): True,
    ("fuzzlab/session/manager.py", "SessionManager._basic_login"): True,
    ("fuzzlab/proxy/session_capture.py", "SessionCapture.state"): True,
}
#: Who may call `detect_logout`, the one loss predicate (SP-16): the signal in
#: `observe` and the verdict in `health_verdict`.
LOSS_PREDICATE_CALLERS = {("fuzzlab/session/manager.py", "SessionManager.observe"),
                          ("fuzzlab/session/manager.py", "health_verdict")}


def loss_decision_offenders(source: str, rel: str) -> list[str]:
    """Each write of a `valid` attribute (assignment, augmented or annotated,
    `setattr(x, "valid", v)`, a `valid=` keyword in any call such as
    `dataclasses.replace` or `SessionState`) that is not a constant written by its
    listed writer, and each call of `detect_logout` outside its listed callers."""
    out: list[str] = []

    def visit(node, scope):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = scope + (node.name,)
        where = (rel, ".".join(scope))
        writes = []
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for t in ast.walk(target):
                    if isinstance(t, ast.Attribute) and t.attr == "valid":
                        writes.append(node.value if not isinstance(node, ast.AugAssign)
                                      else None)
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name == "setattr" and len(node.args) >= 3 and \
                    isinstance(node.args[1], ast.Constant) and node.args[1].value == "valid":
                writes.append(node.args[2])
            for kw in node.keywords:
                if kw.arg == "valid":
                    writes.append(kw.value)
            if name == "detect_logout" and where not in LOSS_PREDICATE_CALLERS:
                out.append(f"{where[0]}::{where[1]} calls detect_logout")
        for value in writes:
            allowed = VALID_WRITERS.get(where, "none")
            const = value.value if isinstance(value, ast.Constant) and \
                isinstance(value.value, bool) else "non-constant"
            if const != allowed:
                out.append(f"{where[0]}::{where[1]} writes valid={const}")
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    visit(ast.parse(source), ())
    return out


@_BUG_0533
def test_only_the_owner_decides_a_session_loss():
    """T19 (PA-0533(4)). Over the whole package: `valid` is written only by its listed
    writers, each with its constant, and `detect_logout` is called only by the signal
    and the verdict. On the base it fails on `observe` and `verify_live`, which write
    `valid = False` themselves."""
    found = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        found += loss_decision_offenders(path.read_text(encoding="utf-8"), rel)
    assert found == []


def test_the_loss_decision_guard_catches_synthetic_offenders():
    """T19's guard, proven on each write form (PA-0034(2)). Each of these must be
    found: `state.valid = ok`, `setattr`, `dataclasses.replace(valid=…)`,
    `.valid = False` outside `_mark_lost`, `True` written by a non-writer, and
    `detect_logout` called elsewhere. The owner's own write is not."""
    rel = "fuzzlab/session/manager.py"
    src = ("import dataclasses\n"
           "class SessionManager:\n"
           "    def _mark_lost(self, state):\n"
           "        state.valid = False\n"
           "    def adopt(self, state):\n"
           "        state.valid = True\n"
           "    def verify_live(self, state, ok):\n"
           "        state.valid = ok\n"
           "    def observe(self, state):\n"
           "        state.valid = False\n"
           "    def other(self, state):\n"
           "        setattr(state, 'valid', False)\n"
           "        return dataclasses.replace(state, valid=False)\n"
           "    def _login(self, state):\n"
           "        state.valid = True\n"
           "def elsewhere(detect, r):\n"
           "    return detect.detect_logout(r.status, {}, '')\n")
    assert loss_decision_offenders(src, rel) == [
        f"{rel}::SessionManager.verify_live writes valid=non-constant",
        f"{rel}::SessionManager.observe writes valid=False",
        f"{rel}::SessionManager.other writes valid=False",
        f"{rel}::SessionManager.other writes valid=False",
        f"{rel}::SessionManager._login writes valid=True",
        f"{rel}::elsewhere calls detect_logout",
    ]


# --- the measurement table -------------------------------------------------------------

def run_rotating_ids(n: int = N) -> dict:
    """Every authenticated request rotates the session id (`rotate_all`). `n` probes of
    `/home.php`: logins and invalidations. The seam adopts no response cookie
    (`probesender.py:85-89`), so each probe after the first carries a dead id."""
    app = _App(mode="rotate_all")
    try:
        _clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        statuses = [sender.send(app.base + "home.php", "id", "1").status for _ in range(n)]
        return {"logins": app.logins, "invalidations": len(losses),
                "checks": app.health_gets(), "statuses": statuses}
    finally:
        app.close()


def measure() -> None:
    """Print what the code under test does in each scenario (the base, or the prototype
    when it is installed)."""
    print("scenario | mode | probes | logins | invalidations | sessions | checks | statuses")
    for mode in ("redirect", "none"):
        for name in SCENARIOS:
            got = run_scenario(name, mode=mode)
            print(" | ".join(str(c) for c in (name, mode, got["probes"], got["logins"],
                                              got["invalidations"], got["sessions"],
                                              got["checks"], got["statuses"])))
    for n in (1, 5, 20):
        got = run_scenario("admin-403", n)
        print(f"admin-403 n={n} | redirect | {n} | {got['logins']} | "
              f"{got['invalidations']} | {got['sessions']} | {got['checks']}")
    for mode in ("redirect", "none"):
        print(f"late answer ({mode}):", run_stale_answer(mode))
        print(f"4 rounds of 6 concurrent 403s ({mode}):", run_concurrent_rounds(4, mode=mode))
    print("one round of 6 concurrent first sends:", run_concurrent_rounds(1, mode="none"))
    for mode, path in (("redirect", "home.php"), ("redirect", "api/me"),
                       ("redirect", "profile.php"), ("forbid", "home.php"),
                       ("presence", "home.php"), ("static", "dashboard")):
        print(f"real expiry ({mode}, /{path}):", run_expiry(mode=mode, path=path,
                                                            max_pause_s=60.0))
    for mode in RESOURCE:
        if mode in ("rotate", "rotate_all"):
            continue
        print(f"protected resource ({mode}):", run_protected_resource(mode))
    print("rotating ids on every request:", run_rotating_ids())


if __name__ == "__main__":
    measure()
