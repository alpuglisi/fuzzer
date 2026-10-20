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
- `json`: a JSON/bearer login (`/api/bounce` ends the bearer it carries; `/api/cart`
  answers 200 to anyone, a guest view without a live bearer);
- `rotate` / `rotate_all`: a rotating session id;
- `ratelimit`: `/` answers anyone without a live session 429 (an anonymous rate limit).

FR-SESS-23's keywords (`clock`, `sleep`, the bounds, a store double) are passed to
`SessionManager` as given (`_manager`). Phase 1 passed only those the constructor
accepted, so the same module could run against the base; since CC-SESS-0029 every one is
accepted.

Written first (Phase 1, a strict xfail each on the base, 15a8a27 + 7ebf48a); CC-SESS-0029
implemented the design and removed the markers. The one marker left is residual R6's
pin (``_R6``). Every test fails against its named revert, a source edit of the real
modules (DRAFT-AU-SESS403 §6 and §13; PA-0034(2)).

``python3 -m tests.test_session_forbidden_answers`` prints the measurement table the
draft cites."""

from __future__ import annotations

import ast
import base64
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

#: The stable protected resource each mode's login should record (None: none can be).
#: `rotate_all` records none: the login's own verification already rotates the id away
#: from the state's copy, so every candidate's credentialed arm carries a dead id.
RESOURCE = {"redirect": "/", "static": "/dashboard", "presence": "/home.php",
            "forbid": "/", "basic": "/", "rotate": "/", "rotate_all": None,
            "ratelimit": "/home.php", "none": None, "json": None}


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
    - ``throttle_root`` (`ratelimit`): a GET of `/` carrying a live session, sent
      without the login fetcher's browser headers, is throttled (429) too.
    - ``waf_403``: a WAF answers 403 to every request to an `/item/` path and to every
      request carrying ``X-Forwarded-For`` (a path or header payload), whoever sends it.
    - ``idor_unauthenticated`` (`json`): `/api/orders?id=7` answers alice's orders to
      anyone, a guest included (an object reference with no check at all).

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
        self.throttle_root = False
        self.cart: list[str] = []          # `json`: each /api/cart view, live or guest
        self.orders: list[str] = []        # `json`: who each /api/orders view went to
        self.idor_unauthenticated = False  # `json`: /api/orders?id=7 answers anyone
        self.waf_403 = False               # a WAF: 403 to every /item/ path and XFF probe
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
                if app.waf_403 and (path.startswith("/item/")
                                    or self.headers.get("X-Forwarded-For")):
                    return self._send(403, b"<h1>Request blocked by the WAF</h1>")
                role = ACCOUNTS[who][2] if who else None
                login = [("Location", app.login_path)]
                if app.mode == "basic":
                    return self._basic(path, who, auth)
                if app.mode == "json":
                    return self._json(method, path, who, form, auth)
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
                if app.mode == "ratelimit":            # an anonymous rate limit on `/`
                    browser = (self.headers.get("User-Agent") or "").startswith("Mozilla")
                    if who and not (app.throttle_root and not browser):
                        return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>"
                                          .encode())
                    return self._send(429, b"<h1>slow down</h1>", [("Retry-After", "1")])
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

            def _json(self, method, path, who, form, auth=""):
                if path == "/" and method == "GET":
                    return self._send(200, _JSON_SHELL)
                if path == "/api/bounce":                 # it ends the bearer it carries
                    with app._lock:
                        app.bearers.pop(auth[7:] if auth.startswith("Bearer ") else "",
                                        None)
                    return self._send(401, b'{"error":"unauthenticated"}',
                                      ctype="application/json")
                if path == "/api/orders":                 # alice's object, id 7
                    oid = dict(parse_qsl(urlsplit(self.path).query)).get("id")
                    with app._lock:
                        app.orders.append(who or "guest")
                    if oid == "7" and (who == "user" or app.idor_unauthenticated):
                        return self._send(200, b"<p>orders of alice</p>")
                    if who is None:
                        return self._send(200, b"<p>guest: please sign in</p>")
                    return self._send(200, b"<p>no such order</p>")
                if path == "/api/slow":                   # slower than a short timeout
                    import time
                    time.sleep(1.0)
                    return self._send(200, b"{}", ctype="application/json")
                if path == "/api/cart":                   # anyone: a guest view without
                    with app._lock:                      # a live bearer (review 4's Q1)
                        app.cart.append("live" if who else "guest")
                    return self._send(200, b'{"items":["book"]}' if who else
                                      b'{"items":[]}', ctype="application/json")
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
    logout listener appends each valid -> invalid transition to (FR-SESS-16). FR-SESS-23's
    keywords (the clock, the bounds, a store double) are passed as given."""
    mgr = SessionManager(_creds(), scope_hosts=[HOST], browser_login=False, **kw)
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


def _until(predicate, timeout: float = 5.0) -> bool:
    """Poll ``predicate`` (real time, bounded) until it holds; whether it did."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


class _RecordingStore:
    """A store double for the manager's non-secret persistence (FR-SESS-3, T1.7): it
    starts empty and records every row `SessionManager._persist` upserts."""

    def __init__(self):
        self.rows: list[dict] = []

    def all_session_states(self) -> list:
        return []

    def get_session_state(self, host, identity):
        return None

    def upsert_session_state(self, row) -> None:
        self.rows.append(dict(row))


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


def test_a_throttle_is_never_a_resources_refusal_status_nor_a_loss():
    """T2b (B1; the reviewer's P1). On the `ratelimit` app, `/` answers a live session
    200 and everyone else 429, so its anonymous and corrupted arms agree on a throttle.
    - The login never records 429 as a refusal status: `/` is not the resource, the
      landing `/home.php` is (both its refusal arms are login redirects).
    - Then `/` throttles the tool's own GETs too, and a scope 401 is checked: nothing
      logs the session out.

    Revert: `throttle_refusal` (revision 2's admission: `/` is recorded with refusal
    status 429, so a throttled health GET of `/` read LOST)."""
    app = _App(mode="ratelimit")
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        state = mgr._state[(HOST, "user")]
        url = state.protected_probe
        recorded = (url.replace(app.base, "/") if url else None,
                    getattr(state, "probe_refusal_status", None))
        assert recorded == ("/home.php", None), recorded
        assert _get(client, app, "home.php")[0].status == 200
        app.throttle_root = True
        assert _get(client, app, "api/reports")[0].status == 401   # a suspicion: checked
        assert (losses, app.logins) == ([], 1)
    finally:
        app.close()


@pytest.mark.parametrize("status", [0, 429, 503, 502, 504, 407])
def test_health_verdict_never_matches_a_throttle_gateway_407_or_incomplete_answer(status):
    """T2c (B1). SP-56 classifies before any refusal status is matched: an incomplete
    answer, a throttle, a gateway or a 407 is INCONCLUSIVE, even when it equals the
    state's recorded refusal status. `health_verdict` is public (disco may build on it,
    §5.7, and `adopt` takes a resource), so it is total over any state it is handed,
    not only over the states the login records (T2b proves the login never records
    one). Revert: `throttle_verdict` (revision 2's order: the refusal status first)."""
    from fuzzlab.session import manager as M
    state = SessionState(HOST, "user", kind="cookie", cookies={"SID": "s"},
                         login_url=LOGIN, protected_probe=PAGE,
                         origins=frozenset({"http://127.0.0.1:8080"}), valid=True)
    state.probe_refusal_status = status
    state.generation = 1
    got = M.health_verdict(state, status, {"Retry-After": "1"}, "<h1>busy</h1>", PAGE,
                           stopped_at_login=False)
    assert got.state == M.INCONCLUSIVE, got


@pytest.mark.parametrize("name", ["scope-401", "privilege-login-redirect"])
def test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in(name):
    """T3. A credentialed 401 or login redirect is a suspected loss. One health check
    finds the session live, the cache covers the other nine, and nothing logs in.
    Reverts: `noconfirm` (10 logins), `nocache` (10 checks)."""
    got = run_scenario(name)
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got
    assert got["checks"] == 1, got


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
    ("redirect", None),
    ("static", None),
    ("presence", None),
    ("forbid", 403),
    ("basic", None),
    ("none", None),
])
def test_each_login_records_the_resource_its_answers_prove(mode, refusal):
    """T9. The credentialed answer must be LIVE on the walk that stops at a login
    redirect. The anonymous and the corrupted answers must agree as a refusal.
    - `redirect`: rule 2 on the base, so the resource is `/`, not the landing.
    - `basic`: rule 2 for a Basic session too (M4(b)), so the resource is `/`.
    - `static`: `/` always redirects to `/login`, so the resource is `/dashboard`.
    - `presence`: `/` answers any cookie, so the resource is `/home.php`.
    - `forbid`: refuses with 403, and that status is recorded.
    - `none`: no resource can be proved.

    A JSON/bearer login records none either (`json`, measured by `measure()`): its
    base is its login page, an auth endpoint, and it has no landing, so no revert can
    make it a candidate.

    Reverts: `norule2` (redirect, basic), `rule2_cookie_only` (basic), `rule2verify`
    (static), `nocorrupt` (presence), `norefusal` (forbid), `publicbase` (none)."""
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


def test_a_static_redirect_base_neither_churns_nor_misses_an_expiry():
    """TP6 (M4a). On the `static` app, ten scope 401s cost one check and no login, and a
    real expiry is recovered with one login. Revert: `rule2verify` (`/` is recorded,
    every check stops at `/login` and reads LOST: 10 logins)."""
    got = run_scenario("scope-401", mode="static")
    assert (got["logins"], got["invalidations"], got["checks"]) == (1, 0, 1), got
    exp = run_expiry(mode="static", path="dashboard")
    assert exp["statuses"] == [200, 302, 200, 200], exp
    assert (exp["logins"], exp["invalidations"]) == (2, 1), exp


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


def test_a_live_verdict_is_cached_for_its_window_its_generation_and_its_url():
    """T14 (M6). A live verdict covers later loss shapes of the same generation and URL
    key within `health_ttl_s` (30 s), and nothing else:
    - another URL's loss shape is checked (a scope 401 on `/api/r1`; review round 5: a
      403 would now be covered whatever its URL, T14p);
    - the same URL after the window is checked;
    - the same URL on the next generation is checked.

    Reverts: `nocache`, `cache_nourl`, `cache_nogen`."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, _losses, client = _logged_in(app, **kw)
        checks = []
        for path in ("api/reports", "api/reports", "api/r1"):
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


def test_policy_blocks_on_many_paths_and_headers_cost_one_check_per_window():
    """T14p (M6; review round 5). A WAF answers 403 to every path payload and every
    `X-Forwarded-For` payload. A policy block is no loss shape: within `health_ttl_s`
    one live verdict of the generation covers it whatever its URL or headers.
    - 20 path payloads and 20 header payloads: one health GET in the window;
    - the next window: one more;
    - a loss shape keeps its rule: a scope 401 on a new URL is checked, the same URL
      again is cached, and the same URL with a foreign header is checked (T18's rule).

    Revert: `policy_cache_by_url` (a policy block keyed by URL and bypassed by a foreign
    header: 40 health GETs)."""
    app = _App()
    app.waf_403 = True
    try:
        clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        statuses = [_get(client, app, f"item/{i}")[0].status for i in range(20)]
        for i in range(20):
            req = Request("GET", app.base + "home.php", identity="user",
                          headers={"X-Forwarded-For": f"10.0.0.{i}"})
            statuses.append(client.send(req).status)
        assert statuses == [403] * 40
        assert app.health_gets() == 1, app.health_gets()
        clock.t += 31.0                                            # the next window
        for i in range(5):
            _get(client, app, f"item/x{i}")
        assert app.health_gets() == 2, app.health_gets()
        _get(client, app, "api/reports")                           # a loss shape: checked
        _get(client, app, "api/reports")                           # same URL: cached
        assert app.health_gets() == 3, app.health_gets()
        req = Request("GET", app.base + "api/reports", identity="user",
                      headers={"X-Probe": "1"})                    # foreign: checked
        assert client.send(req).status == 401
        assert app.health_gets() == 4, app.health_gets()
        assert (losses, app.logins) == ([], 1)
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

def test_n_concurrent_signals_make_one_health_get():
    """M7 (B2). Six concurrent 401s on six URLs. The first GET is answered only after
    all six signals are seen. A live verdict covers only the signals seen before its
    GET was sent, so the signals seen while it was in flight make one more GET, whose
    verdict covers them all: at most two GETs, recorded before the lock is released.
    Revert: `noflight` (six GETs)."""
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
        assert 1 <= app.health_gets() <= 2, app.health_gets()
        assert (app.logins, len(losses)) == (1, 0)
    finally:
        app.close()


def test_a_pause_found_for_an_older_generation_never_pauses_the_new_one():
    """M7 (the compare-and-set on the generation).
    1. A check of session 1 is in flight.
    2. Session 2 is adopted meanwhile.
    3. The check then answers 503, which is inconclusive for session 1.
    4. The verdict is stale (B3): no pause is recorded (none counted, none logged), and
       the next send on session 2 neither waits nor rechecks.

    Revert: `nocas` (the check's compare-and-set: a pause is recorded for session 1,
    logged as "pausing the identity", though nothing is paused any more)."""
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
        assert _report(mgr).get("stale_verdicts") == 1, _report(mgr)
        assert _report(mgr).get("pauses", 0) == 0, _report(mgr)
        checks = app.health_gets()
        resp, _req = _get(client, app, "home.php")
        assert resp.status == 200 and clock.sleeps == []
        assert app.health_gets() == checks
    finally:
        app.close()


def test_a_pause_of_a_replaced_generation_never_delays_its_replacement():
    """M7 (a pause is keyed by its generation; §3.4). The 503 of a check pauses
    session 1, as it should. Session 2 is then adopted, which takes no health lock and
    leaves session 1's pause in place. The next send on session 2 neither waits nor
    re-checks: the pause is session 1's.

    Revert: `pause_anygen` (`prepare` waits a pause of any generation: 5 s, then a
    re-check of the replaced session)."""
    app = _App()
    try:
        clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")                                # session 1
        app.health_queue = [503]
        _get(client, app, "api/reports")                             # 503: paused
        assert _report(mgr).get("pauses") == 1, _report(mgr)
        old = mgr._state[(HOST, "user")]
        mgr.adopt(SessionState(HOST, "user", kind="cookie",
                               cookies={"SID": app.issue_session("user")},
                               origins=frozenset(old.origins), login_url=old.login_url))
        checks = app.health_gets()
        resp, _req = _get(client, app, "home.php")
        assert (resp.status, clock.sleeps, app.health_gets()) == (200, [], checks)
        assert (losses, app.logins) == ([], 1)
    finally:
        app.close()


def test_a_lost_verdict_for_a_replaced_session_tells_no_listener_and_writes_no_row():
    """M7 / B3 (the compare-and-set against the current state, LOST branch; the
    reviewer's P4).
    1. A check of session 1 is in flight.
    2. Session 2 is adopted meanwhile.
    3. The check then answers 401: LOST, for session 1.
    4. Session 1 is no longer the current state, so the verdict is stale: no listener
       is told, no row is written over session 2's, and session 2 stays current and
       valid.

    Two compare-and-sets stand in the way, the check's and `_mark_lost`'s, and either
    alone holds here; each has its own test (`nocas`: T M7b and T M7e; `nomlcas`: T M7f
    and T M7h). Revert: `cas_both` (both off: session 1 is marked lost, its row is
    persisted over session 2's, and the listener hears a loss of the session that
    replaced it)."""
    app = _App()
    store = _RecordingStore()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, store=store, **kw)
        _get(client, app, "home.php")                                # login: session 1
        arrived, release = threading.Event(), threading.Event()
        app.hold_health = (arrived, release, 401)
        first = threading.Thread(target=_get, args=(client, app, "api/reports"),
                                 daemon=True)
        first.start()
        assert arrived.wait(10)                                      # session 1's check
        old = mgr._state[(HOST, "user")]
        new = mgr.adopt(SessionState(HOST, "user", kind="cookie",
                                     cookies={"SID": app.issue_session("user")},
                                     origins=frozenset(old.origins),
                                     login_url=old.login_url))
        rows = len(store.rows)
        assert rows >= 2, store.rows           # the channel is live: login, then adopt
        release.set()
        first.join(10)
        assert not first.is_alive()
        assert (losses, len(store.rows)) == ([], rows), store.rows[rows:]
        assert mgr._state[(HOST, "user")] is new and new.valid
    finally:
        app.close()


def test_a_loss_seen_while_a_check_is_in_flight_is_still_acted_on():
    """M7 / B2 (a live verdict covers only the signals seen before its GET was sent;
    the reviewer's P2).
    1. A scope 401's check of `/` is in flight: the server has judged the session live
       and holds its answer.
    2. Meanwhile `/bounce.php` ends the session, and its login redirect is seen.
    3. The held answer (live) arrives.
    Its GET was sent before the second signal was seen, so it does not cover it: the
    second signal makes its own check, which finds the session lost, and the listener
    is told once.

    The `forbid` app is the one whose server judges `/` before the hold. (On `redirect`,
    `/` redirects to `/home.php`, which is judged after the hold, so the held check
    itself reads LOST and proves nothing about the cover.)

    Revert: `cover_at_record` (the live verdict, recorded after the second signal was
    seen, covers it: the session stays valid here while the server has ended it)."""
    app = _App(mode="forbid")
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        arrived, release = threading.Event(), threading.Event()
        app.hold_health = (arrived, release, None)                   # judged live, held
        a = threading.Thread(target=_get, args=(client, app, "api/reports"), daemon=True)
        a.start()
        assert arrived.wait(10)                                      # the GET in flight
        b = threading.Thread(target=_get, args=(client, app, "bounce.php"), daemon=True)
        b.start()
        assert _until(lambda: _report(mgr).get("suspected", 0) >= 2), _report(mgr)
        release.set()
        a.join(10)
        b.join(10)
        state = mgr._state[(HOST, "user")]
        assert (state.valid, losses) == (False, ["user"]), (state.valid, losses)
        assert state.cookies.get("SID") not in app.sessions
    finally:
        app.close()


def test_verify_live_asked_about_a_session_replaced_while_it_checked_answers_live():
    """M7 / B3 (the check's compare-and-set; §3.10's STALE row). `verify_live` (an isolated
    copy's `_verify_main`, the crawler) checks session 1. While its GET is in flight,
    session 2 is adopted, and the GET then answers 401: LOST, for session 1. The
    verdict is stale, so `verify_live` answers for the session that replaced it: True,
    and nothing is marked or told. A False here would trip the single-session breaker
    on a session that is not the run's any more.

    Revert: `nocas` (the stale LOST is returned: `verify_live` says False)."""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")                                # session 1
        arrived, release = threading.Event(), threading.Event()
        app.hold_health = (arrived, release, 401)
        got: list = []
        check = threading.Thread(target=lambda: got.append(
            mgr.verify_live(HOST, "user", app.base)), daemon=True)
        check.start()
        assert arrived.wait(10)                                      # the GET in flight
        old = mgr._state[(HOST, "user")]
        new = mgr.adopt(SessionState(HOST, "user", kind="cookie",
                                     cookies={"SID": app.issue_session("user")},
                                     origins=frozenset(old.origins),
                                     login_url=old.login_url))
        release.set()
        check.join(10)
        assert got == [True], got
        assert (losses, mgr._state[(HOST, "user")] is new, new.valid) == ([], True, True)
    finally:
        app.close()


def test_mark_lost_on_a_replaced_state_changes_nothing_and_writes_no_row():
    """B3 (`_mark_lost`'s own compare-and-set; review round 4's Q2). Session 2 has been
    adopted; `_mark_lost` is then asked to invalidate session 1 (of its own generation).
    It changes nothing: it returns False, session 1 stays as it was, and no row is
    written over session 2's.

    Revert: `nomlcas` (session 1 is marked lost and its row is written last)."""
    app = _App()
    store = _RecordingStore()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, store=store, **kw)
        _get(client, app, "home.php")
        old = mgr._state[(HOST, "user")]
        new = mgr.adopt(SessionState(HOST, "user", kind="cookie",
                                     cookies={"SID": app.issue_session("user")},
                                     origins=frozenset(old.origins),
                                     login_url=old.login_url))
        rows = len(store.rows)
        assert rows >= 2 and store.rows[-1]["valid"] is True, store.rows
        moved = mgr._mark_lost(old, old.generation)
        assert (moved, old.valid, len(store.rows)) == (False, True, rows), store.rows[rows:]
        assert mgr._state[(HOST, "user")] is new and new.valid and losses == []
    finally:
        app.close()


def test_an_adopt_between_the_checks_compare_and_the_mark_tells_no_listener():
    """B3 (`_mark_lost`'s compare-and-set on the observing send). A 401 on session 1 is
    checked; the check's own compare-and-set passes (session 1 is current when its GET
    returns), and before `_mark_lost` takes its lock, session 2 is adopted. (The race is
    made deterministic: the adopt runs at `_mark_lost`'s entry.) `_mark_lost` finds
    session 1 replaced: no listener is told and no row lands after session 2's.

    Revert: `nomlcas` (the listener hears a loss of the session that replaced it, and
    session 1's row is written last)."""
    app = _App()
    store = _RecordingStore()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, store=store, **kw)
        _get(client, app, "home.php")
        old = mgr._state[(HOST, "user")]
        app.expire_all()                                   # the check will read LOST
        new = SessionState(HOST, "user", kind="cookie",
                           cookies={"SID": app.issue_session("user")},
                           origins=frozenset(old.origins), login_url=old.login_url)
        real, raced = mgr._mark_lost, []

        def racing(state, generation):
            if not raced:
                raced.append(mgr.adopt(new))                   # lands between the two
            return real(state, generation)
        mgr._mark_lost = racing
        rows = len(store.rows)
        assert _get(client, app, "api/me")[0].status == 401        # a suspicion: LOST
        assert raced == [new] and app.health_gets() == 1, (raced, app.health_gets())
        assert losses == [], losses
        assert [r["valid"] for r in store.rows[rows:]] == [True], store.rows[rows:]
        assert mgr._state[(HOST, "user")] is new and new.valid
    finally:
        app.close()


class _SlowStore(_RecordingStore):
    """A store whose first write of an invalid row is slow (review round 4's Q3): it
    waits until ``release`` is set (bounded) before it lands."""

    def __init__(self):
        super().__init__()
        self.entered, self.release, self._armed = (threading.Event(), threading.Event(),
                                                   True)

    def upsert_session_state(self, row) -> None:
        if self._armed and row.get("valid") is False:
            self._armed = False
            self.entered.set()
            self.release.wait(10)
        super().upsert_session_state(row)


class _ContendedLock:
    """A lock that records a second thread waiting for it (stamped where the waiter
    acts, PA-0511), so a test can release a held step only once the other thread is
    blocked on the lock."""

    def __init__(self, lock):
        self._lock, self.contended = lock, threading.Event()

    def acquire(self, blocking=True, timeout=-1):
        if self._lock.acquire(False):
            return True
        self.contended.set()
        return self._lock.acquire(blocking, timeout)

    def release(self):
        self._lock.release()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


@pytest.mark.parametrize("install", ["relogin", "adopt"])
def test_a_slow_row_write_never_leaves_a_replaced_sessions_row_last(install):
    """B3 and review round 4's Q3 (the compare-and-set is atomic with installs). An
    unconfirmed loss marks session 1 lost, and its row's write is slow. Meanwhile session
    2 is installed: by a re-login (`ensure`) or by `adopt`. Session 2's install and row
    wait for the lock `_mark_lost` writes under, so session 1's row lands first and the
    rows' last word is the current session's: valid.

    Reverts: `persist_unlocked` (`_mark_lost` persists after releasing the lock),
    `install_unlocked` (an install and its row take no lock). Either way session 2's
    row lands first, and session 1's invalid row is written over it."""
    app = _App(mode="none")
    store = _SlowStore()
    try:
        _clock, kw = _fake()
        mgr, losses, client = _logged_in(app, store=store, **kw)
        mgr._observe_guard = guard = _ContendedLock(mgr._observe_guard)
        _get(client, app, "home.php")
        app.expire_all()
        lose = threading.Thread(target=_get, args=(client, app, "api/me"), daemon=True)
        lose.start()                                    # 401: an unconfirmed loss
        assert store.entered.wait(10)                   # session 1's row, held
        got: list = []

        def install_new():
            if install == "relogin":
                got.append(mgr.ensure(HOST, "user", app.base))
            else:
                old = mgr._state[(HOST, "user")]
                got.append(mgr.adopt(SessionState(
                    HOST, "user", kind="cookie", cookies={"SID": app.issue_session("user")},
                    origins=frozenset(old.origins), login_url=old.login_url)))
        installer = threading.Thread(target=install_new, daemon=True)
        installer.start()
        # release the held row once the installer waits on the lock, or once it has
        # finished without waiting (an unlocked install: its row is already written)
        assert _until(lambda: guard.contended.is_set() or not installer.is_alive(), 10)
        store.release.set()
        lose.join(10)
        installer.join(10)
        current = mgr._state[(HOST, "user")]
        assert got == [current] and current.valid, (got, current.valid)
        assert store.rows[-1]["valid"] is True, [r["valid"] for r in store.rows]
    finally:
        store.release.set()
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


def test_a_no_resource_identity_whose_budget_is_spent_carries_on_at_once():
    """T15b (the owner's decision D). The `json` app's login records no resource, and
    its `/api/reports` answers the low-privilege bearer 401 (scope): an unconfirmed loss
    on every probe.
    - The burst (5) re-logs in five times. Then each probe goes out at once on the
      session it has: no login, no sleep, no `SessionHealthUnknown`, nothing aborted.
    - 120 s later one token has refilled, and the next probe logs in once.

    Reverts: `nores_waits` (revision 2: it sleeps 120 s per token, then raises),
    `nobucket` (30 logins)."""
    app = _App(mode="json")
    try:
        clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        statuses = [sender.send(app.base + "api/reports", "id", "1").status
                    for _ in range(30)]
        assert statuses == [401] * 30
        assert (app.logins, len(losses), clock.sleeps) == (6, 6, []), \
            (app.logins, len(losses), clock.sleeps)
        clock.t += 120.0
        sender.send(app.base + "api/reports", "id", "1")
        assert (app.logins, clock.sleeps) == (7, [])
    finally:
        app.close()


def test_credential_posts_are_counted_and_the_json_control_too():
    """M10, F7. Credential POSTs are counted per account (the credential store's
    `(host, identity)`), each kind apart: a JSON login's wrong-password control too.
    These are the lockout residual's numbers (R15).
    - An isolated copy of the same identity counts into the same account (review round
      4, follow-up 3).
    - A peer identity is another account, on its own manager.

    Reverts: `nocount`, `copy_own_budget` (the copy counts apart: the run's account
    shows one login)."""
    app = _App(mode="json")
    try:
        _clock, kw = _fake()
        mgr, _losses = _manager(**kw)
        mgr.ensure(HOST, "user", app.base, operator=True)
        assert mgr.health_report()["credential_posts"] == {
            f"{HOST}/user": {"control": 1, "submitted": 1}}
        copy = mgr.isolated_copy("user", ordinal=1)
        copy.ensure(HOST, "user", app.base)
        assert mgr.health_report()["credential_posts"] == {
            f"{HOST}/user": {"control": 2, "submitted": 2}}
        peer, _l = _manager(**kw)
        peer.ensure(HOST, "admin", app.base, operator=True)
        assert peer.health_report()["credential_posts"] == {
            f"{HOST}/admin": {"control": 1, "submitted": 1}}
        assert mgr.health_report()["credential_posts"] == {
            f"{HOST}/user": {"control": 2, "submitted": 2}}
    finally:
        app.close()


def test_an_isolated_copys_pauses_draw_on_the_runs_pause_budget():
    """M8, F3 (whose budget; review round 4, follow-up 3). A run's manager and its
    isolated copies share one pause budget (50 s here, each pause bounded at 40 s).
    1. The copy's resource answers 503: its pause runs to its 40 s bound and the copy
       goes unknown (`IsolatedHealthUnknown`).
    2. The run's own pause would resolve after 15 s, but only 10 s of the budget are
       left: the run's send raises `SessionHealthUnknown`, within the 50 s.

    Revert: `copy_own_budget` (the copy spends a budget of its own: the run's pause
    resolves and its send goes out)."""
    app = _App()
    try:
        clock, kw = _fake(max_pause_s=40.0, pause_budget_s=50.0)
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        copy = mgr.isolated_copy("user", ordinal=1)
        cclient = _client(copy)
        assert _get(cclient, app, "home.php", identity=copy.label)[0].status == 200
        app.health_status = 503
        _get(cclient, app, "api/reports", identity=copy.label)    # the copy pauses
        with pytest.raises(SessionAuthError):
            _get(cclient, app, "home.php", identity=copy.label)   # its bound: unknown
        assert sum(clock.sleeps) == 40.0, clock.sleeps
        app.health_status = None
        app.health_queue = [503, 503, None]
        _get(client, app, "api/reports")                          # the run pauses
        with pytest.raises(SessionAuthError):
            _get(client, app, "home.php")
        assert sum(clock.sleeps) <= 50.0, clock.sleeps
    finally:
        app.close()


def test_verify_live_waits_out_an_unknown_and_then_reads_live():
    """T21 (M9). The resource answers 503. `verify_live` waits on its own bounded wait
    (never the identity's pause) and checks again. Still inconclusive, it keeps today's
    answer (live), changes nothing, and never goes sticky. Revert: `verifylive_false`."""
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


def test_an_inconclusive_verify_live_never_clears_a_sticky_unknown():
    """M9 (the reviewer's P3). The resource answers 503 until the identity is sticky
    unknown. `verify_live` (an isolated copy's `_verify_main`, the crawler) then
    checks: still inconclusive, it returns True (today's answer), but the sticky
    unknown stays. The next send raises at once, and nothing reaches the server.
    Revert: `verifylive_clears_sticky` (the next send goes out)."""
    app = _App()
    try:
        _clock, kw = _fake(max_pause_s=60.0)
        mgr, _losses = _manager(**kw)
        sender = _sender(app, mgr)
        sender.send(app.base + "home.php", "id", "1")
        app.health_status = 503
        sender.send(app.base + "api/reports", "id", "1")          # suspected: paused
        with pytest.raises(SessionAuthError):
            sender.send(app.base + "home.php", "id", "1")         # waits, then unknown
        assert mgr.verify_live(HOST, "user", app.base) is True
        n0 = app.count()
        with pytest.raises(SessionAuthError):
            sender.send(app.base + "home.php", "id", "1")
        assert app.count() == n0
    finally:
        app.close()


def test_verify_lives_waits_never_spend_the_runs_pause_budget():
    """M9 (a follow-up of review round 3). `verify_live`'s waits draw on their own
    budget, never on the one `prepare`'s pauses share.
    1. The resource answers 503: `verify_live` waits out its 40 s bound and reads live.
    2. A suspicion then pauses the identity, and the pause resolves after 15 s: inside
       the run's 50 s budget, which `verify_live` did not touch.

    Revert: `verifylive_budget` (40 of the 50 s are already spent: the pause ends
    early and the send raises)."""
    app = _App()
    try:
        clock, kw = _fake(max_pause_s=40.0, pause_budget_s=50.0)
        mgr, _losses, client = _logged_in(app, **kw)
        _get(client, app, "home.php")
        app.health_status = 503
        assert mgr.verify_live(HOST, "user", app.base) is True
        waited = sum(clock.sleeps)
        assert waited == 40.0, clock.sleeps
        app.health_status = None
        app.health_queue = [503, 503, None]
        _get(client, app, "api/reports")                          # pause: 5 s, then 10 s
        assert _get(client, app, "home.php")[0].status == 200
        assert sum(clock.sleeps) - waited == 15.0, clock.sleeps
    finally:
        app.close()


# --- ADOPT: fail fast on an unapproved hop; a rotating id; generations; names ---------

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


#: Residual R6 (DRAFT-AU-SESS403 §3.13), stated: the oracle cannot tell a comparison whose
#: probes straddle a re-login, because a probe does not carry the session generation it
#: was sent on. It needs `Probe.session_generation` (set by `SeamProbeSender`) and the
#: oracle's layer-1 check: a FUZZ follow-up with its own CC-FUZZ number. (Revision 3
#: called this "F3", which was also its change table's label for whose budget: renamed.)
_R6 = pytest.mark.xfail(strict=True, reason="AU-SESS403 residual R6: a comparison that "
                                            "straddles a re-login is not detected")


@_R6
def test_a_seam_probe_carries_the_session_generation_it_was_sent_on():
    """R6's first half, pinned (PA-0054(3)). It fails on the base and on the
    implementation: `Probe` has no `session_generation`. (D′'s `Probe.session_lost` is
    another fact: a probe sent on a session known lost, FR-FUZZ-65.)"""
    app = _App()
    try:
        _clock, kw = _fake()
        mgr, _losses = _manager(**kw)
        probe = _sender(app, mgr).send(app.base + "home.php", "id", "1")
        assert probe.session_generation == 1
    finally:
        app.close()


# --- D′ (FR-FUZZ-65): an answer on a session known to be lost is never evidence --------

def test_an_answer_on_a_session_known_lost_is_never_evidence():
    """D′ (the owner's decision after review round 4's Q1; FR-FUZZ-65). The `json` app's
    login records no resource. Seven probes of `/api/bounce` each end the bearer they
    carry: five re-logins draw the burst, and the seventh goes out in D's window, on
    the session marked lost.
    - A probe of `/api/cart` in that window gets the app's **guest view** (200
      ``{"items":[]}``), which SP-56 alone classes as the application's answer.
    - The request was marked (`Request.session_lost`), the probe carries the mark, and
      layer 1 (`require_observed`) reads it as not comparable, whatever its class.
    - Through the oracle, the candidate ends **inconclusive** (`not-comparable`, "sent
      on a lost session"), never a negative and never a finding: the payload itself
      was sent in the window.

    Reverts: `nolostmark` (`prepare` drops the mark: the guest view is a negative),
    `oracle_ignores_lost` (layer 1 ignores it: the same)."""
    from fuzzlab.oracle import Oracle
    from fuzzlab.oracle.oracle import NOT_COMPARABLE
    from fuzzlab.oracle.probe import Candidate, NotComparable, comparability, \
        require_observed
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    app = _App(mode="json")
    try:
        clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        bounces = [sender.send(app.base + "api/bounce", "id", "1") for _ in range(7)]
        assert [p.status for p in bounces] == [401] * 7
        assert (app.logins, len(losses), clock.sleeps) == (6, 6, [])
        assert [p.session_lost for p in bounces] == [False] * 6 + [True]
        cart = sender.send(app.base + "api/cart", "id", "1")
        assert (cart.status, cart.text, app.cart) == (200, '{"items":[]}', ["guest"])
        assert comparability(cart, url=app.base + "api/cart")[0] == "application"
        assert cart.session_lost is True
        with pytest.raises(NotComparable, match="sent on a lost session"):
            require_observed(cart)
        verdict, unsure = Oracle(strategies=[ReflectedXssStrategy()]).confirm_outcome(
            Candidate(app.base + "api/cart", "q"), sender)
        assert verdict is None and unsure is not None and unsure.inconclusive, \
            (verdict, unsure)
        assert unsure.mechanism == NOT_COMPARABLE, unsure
        assert "sent on a lost session" in unsure.evidence["unobserved"], unsure.evidence
        assert len(app.cart) == 2 and set(app.cart) == {"guest"}, app.cart
        assert app.logins == 6
    finally:
        app.close()


def test_a_resource_backed_identity_never_sends_on_a_lost_session():
    """D′'s other half: the base still re-logs in. On the `redirect` app every probe of
    `/bounce.php` ends the session, and each loss is confirmed on the resource. With a
    burst of 2 and a 300 s pause bound, the fourth re-login waits 120 s for its token
    and then logs in: four logins, and no request is ever sent on a lost state, so no
    probe carries the mark.

    Revert: `d_for_all` (D extended to a resource-backed identity: the fourth probe goes
    out on the lost session, marked, with no login)."""
    app = _App()
    try:
        clock, kw = _fake(relogin_burst=2, relogin_refill_s=120.0, max_pause_s=300.0)
        mgr, _losses = _manager(**kw)
        sender = _sender(app, mgr)
        probes = [sender.send(app.base + "bounce.php", "id", "1") for _ in range(4)]
        assert (app.logins, clock.sleeps) == (4, [120.0]), (app.logins, clock.sleeps)
        assert [p.session_lost for p in probes] == [False] * 4
        assert app.health_gets() == 4
    finally:
        app.close()


@pytest.mark.parametrize("status,headers", [
    (200, {}), (404, {}), (302, {"Location": "/cart"}), (302, {"Location": "/login"}),
    (401, {}), (403, {}), (500, {})])
def test_layer_one_reads_any_answer_on_a_lost_session_as_not_comparable(status, headers):
    """D′ (FR-FUZZ-65), layer 1 on its own: an answer to a request sent on a session
    known lost is `NotComparable` whatever its class -- the probe's own or its PRG
    follow-up's. The timing case is **synthetic**: layer 1 checks the mark before it
    keeps a read timeout as latency, but `SeamProbeSender` re-raises a timeout rather
    than returning a stand-in, so no live marked stand-in exists today. The same answers
    unmarked pass layer 1 (which reads only throttles and incomplete answers). Revert:
    `oracle_ignores_lost`."""
    from fuzzlab.oracle.probe import (LOST_SESSION, PRG_OBSERVED, NotComparable, Probe,
                                      require_observed)
    with pytest.raises(NotComparable, match="the probe was sent on a lost session") as err:
        require_observed(Probe(status, "body", headers=dict(headers), session_lost=True))
    assert err.value.response_class == LOST_SESSION
    followed = Probe(status, "body", headers=dict(headers), url="http://h/cart",
                     session_lost=True)
    outer = Probe(303, "", headers={"Location": "/cart"}, followed=followed,
                  prg=PRG_OBSERVED)
    with pytest.raises(NotComparable, match="follow-up was sent on a lost session"):
        require_observed(outer)
    with pytest.raises(NotComparable, match="sent on a lost session"):
        require_observed(Probe(0, "", elapsed=10.0, timeout="read", session_lost=True),
                         timing=True)
    require_observed(Probe(status, "body", headers=dict(headers)))
    require_observed(Probe(0, "", elapsed=10.0, timeout="read"), timing=True)


#: D′'s sweep (PA-0002): every consumer that reads answers through a session-managed seam
#: reads the lost-session mark -- the oracle (TD1, TD4), the live WAF filter (CC-MUT-0404)
#: and the blind-SQLi builder (CC-FUZZ-0110). Revision 1 of Phase 2 pinned the last two
#: with strict xfails; the owner's decision closed them.


def _in_ds_window(app: _App):
    """``(mgr, sender)`` on the `json` app, driven into D's window: seven probes of
    `/api/bounce` (six logins: the first and the burst of five; the seventh sent on the
    session marked lost)."""
    _clock, kw = _fake()
    mgr, _losses = _manager(**kw)
    sender = _sender(app, mgr)
    for _ in range(7):
        sender.send(app.base + "api/bounce", "id", "1")
    assert app.logins == 6 and not mgr._state[(HOST, "user")].valid
    return mgr, sender


def test_the_live_waf_filter_never_reads_an_answer_on_a_lost_session():
    """D′ (FR-FUZZ-65, FR-MUT-401; CC-MUT-0404). In D's window the live filter's probe
    of `/api/cart` gets the guest view (200), and a WAF-like 403 would look like a block.
    Neither is recorded as an allow or a block: the answer is not an observation of the
    WAF (`FilterUnobserved`, counted and skipped by `run_mutation`), as a throttle is.
    Revert: `livefilter_reads_lost` (the guest view reads as an allow)."""
    from fuzzlab.mutation.livefilter import FilterUnobserved, HttpFilter
    app = _App(mode="json")
    try:
        _mgr, sender = _in_ds_window(app)
        flt = HttpFilter(sender, app.base + "api/cart", "q")
        with pytest.raises(FilterUnobserved, match="sent on a lost session"):
            flt.evaluate("<b>x</b>")
        with pytest.raises(FilterUnobserved, match="sent on a lost session"):
            flt.caught("<b>y</b>")
        assert app.cart == ["guest", "guest"]
    finally:
        app.close()


def test_the_blind_sqli_builder_never_admits_an_answer_on_a_lost_session():
    """D′ (FR-FUZZ-65; CC-FUZZ-0110). In D's window the builder's seam sends are marked:
    - the guest view (200) is not SP-56's `application` to `answer_class`;
    - the baseline admits no such sample (`BaselineNotComparable`, "lost-session");
    - the cycle writes no row for it, nor for a lost session's client timeout (504),
      which otherwise stays a timing observation.

    Reverts: `bsqli_nomark` (the seam sender drops the mark), `bsqli_class_ignores_lost`
    (`answer_class` reads the guest view as the application's), `bsqli_504_kept` (the
    lost 504 is written as a row)."""
    from types import SimpleNamespace

    from fuzzlab.core.comparability import APPLICATION
    from fuzzlab.tools.blind_sqli_fuzzer import (BaselineNotComparable, SeamSender,
                                                 answer_class, establish_baseline,
                                                 run_fuzzing_cycle)
    app = _App(mode="json")
    try:
        mgr, _sender = _in_ds_window(app)
        cart, slow = app.base + "api/cart", app.base + "api/slow"
        seam = SeamSender(HttpClient(RequestBudget(10_000), [HOST], session=mgr,
                                     timeout=0.3), "user")
        answer = seam.get(cart, "id", "1", 0.3)
        assert (answer[1], answer.session_lost, app.cart) == (200, True, ["guest"])
        assert answer_class(answer, cart)[0] != APPLICATION
        with pytest.raises(BaselineNotComparable, match="lost-session"):
            establish_baseline(seam, cart, "id", 3, 0.3)
        args = SimpleNamespace(sigma=3.0, min_delay=2.0, repeats=2, timeout=0.3,
                               pause=0.0)
        baseline = {"avg_time": 0.01, "std_dev_time": 0.01, "avg_size": 12, "samples": 3}
        payloads = [{"text": "1", "family": "benign", "is_malicious": 0,
                     "expected_delay": 0}]
        assert run_fuzzing_cycle(seam, cart, "id", baseline, payloads, args) == []
        timed_out = seam.get(slow, "id", "1", 0.3)
        assert (timed_out[1], timed_out.session_lost) == (504, True)
        assert run_fuzzing_cycle(seam, slow, "id", baseline, payloads, args) == []
    finally:
        app.close()


def test_a_peer_replay_on_a_session_known_lost_is_never_evidence():
    """D′ (FR-FUZZ-65; review round 5). The cross-account replay sends through the
    **peer's** seam sender, which the oracle does not wrap in `_ObservedOnly`. The peer
    (root) is driven into its own D's window; the run's identity (alice) stays live.
    Alice's own request is her view and the other-value control is not, so the replay
    decides -- and every replay was sent on the peer's lost session:
    - the app shows the dead peer session a guest view: never a negative;
    - the app answers alice's object to anyone (no check at all): never a confirmation.

    Both end inconclusive (`not-comparable`, "sent on a lost session"): `_compared`
    applies layer 1 whichever sender made the send. Revert: `compared_skips_layer1`
    (a negative for the guest view, `confirmed` for the open object)."""
    from fuzzlab.oracle import Oracle
    from fuzzlab.oracle.oracle import NOT_COMPARABLE
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import CrossAccountReplayStrategy, PeerAccounts
    for idor in (False, True):
        app = _App(mode="json")
        try:
            _clock, kw = _fake()
            mgr, _losses = _manager(**kw)
            sender = _sender(app, mgr)                           # alice, live
            peer_mgr, _peer_losses = _manager(**_fake()[1])
            peer = SeamProbeSender(_client(peer_mgr), "admin", manager=peer_mgr,
                                   base_url=app.base)            # root, then lost
            for _ in range(7):
                peer.send(app.base + "api/bounce", "id", "1")
            assert not peer_mgr._state[(HOST, "admin")].valid
            app.idor_unauthenticated = idor
            strategy = CrossAccountReplayStrategy(PeerAccounts(
                sender=peer, owner="alice", peer_name="root", anonymous=None))
            verdict, unsure = Oracle(strategies=[strategy]).confirm_outcome(
                Candidate(app.base + "api/orders", "id", base_entries=(("id", "7"),),
                          category="access-control", vuln_class="access_control"),
                sender)
            assert verdict is None, (idor, verdict)
            assert unsure is not None and unsure.mechanism == NOT_COMPARABLE, (idor, unsure)
            assert "sent on a lost session" in unsure.evidence["unobserved"], unsure
            assert app.orders[:2] == ["user", "user"] and app.orders[2] == "guest", \
                app.orders
        finally:
            app.close()


def test_entering_ds_window_is_logged_once_per_window_without_a_credential():
    """D (review round 5). When an identity enters D's window one warning names it
    (never a credential), however many probes the window holds; a later window (after a
    token refilled and was spent) logs once more. Revert: `no_window_log`."""
    import logging
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append
    log = logging.getLogger("fuzzlab.session.health")
    log.addHandler(handler)
    app = _App(mode="json")
    try:
        clock, kw = _fake()
        mgr, _losses = _manager(**kw)
        sender = _sender(app, mgr)
        for _ in range(12):
            sender.send(app.base + "api/reports", "id", "1")       # 6 logins, then D
        window = [r.getMessage() for r in records if "re-login budget is spent" in
                  r.getMessage()]
        assert len(window) == 1 and window[0].startswith("user@"), window
        tokens = [b for b in app.bearers] + [v for v in mgr._state[(HOST, "user")]
                                              .headers.values()]
        assert not any(t and t.split()[-1] in window[0] for t in tokens), window
        clock.t += 120.0                                           # one token refills
        for _ in range(3):
            sender.send(app.base + "api/reports", "id", "1")       # a login, then D again
        window = [r.getMessage() for r in records if "re-login budget is spent" in
                  r.getMessage()]
        assert len(window) == 2 and app.logins == 7, (window, app.logins)
    finally:
        log.removeHandler(handler)
        app.close()


# --- T10, T11: SP-16's predicate on its own -------------------------------------------

LOGIN = "http://127.0.0.1:8080/login.php"
PAGE = "http://127.0.0.1:8080/admin.php"


@pytest.mark.parametrize("status", [403, 451])
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
    `setattr(x, "valid", v)`, `object.__setattr__(x, "valid", v)` or
    `x.__setattr__("valid", v)`, a `valid=` keyword in any call such as
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
            if name == "__setattr__":
                # object.__setattr__(x, "valid", v) and x.__setattr__("valid", v)
                for i, arg in enumerate(node.args[:2]):
                    if isinstance(arg, ast.Constant) and arg.value == "valid" and \
                            len(node.args) > i + 1:
                        writes.append(node.args[i + 1])
                        break
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
    `object.__setattr__` and a bound `__setattr__`, `.valid = False` outside
    `_mark_lost`, `True` written by a non-writer, and `detect_logout` called elsewhere.
    The owner's own write is not.

    Reverts (the guard weakened: one branch of `loss_decision_offenders` switched off):
    `guard_noassign`, `guard_nosetattr`, `guard_nodunder`, `guard_nokeyword`,
    `guard_nocall`."""
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
           "    def dunder(self, state):\n"
           "        object.__setattr__(state, 'valid', False)\n"
           "        state.__setattr__('valid', True)\n"
           "    def _login(self, state):\n"
           "        state.valid = True\n"
           "def elsewhere(detect, r):\n"
           "    return detect.detect_logout(r.status, {}, '')\n")
    assert loss_decision_offenders(src, rel) == [
        f"{rel}::SessionManager.verify_live writes valid=non-constant",
        f"{rel}::SessionManager.observe writes valid=False",
        f"{rel}::SessionManager.other writes valid=False",
        f"{rel}::SessionManager.other writes valid=False",
        f"{rel}::SessionManager.dunder writes valid=False",
        f"{rel}::SessionManager.dunder writes valid=True",
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


def run_relogin_window(mode: str, path: str, n: int = 30) -> dict:
    """The owner's decision D, measured (the reviewer's P5/P6 fixtures): ``n`` probes of
    ``path`` by the low-privilege identity on ``mode``, with the default bounds, on a
    fake clock. A `SessionAuthError` ends the run there, as it would end a real one."""
    app = _App(mode=mode)
    try:
        clock, kw = _fake()
        mgr, losses = _manager(**kw)
        sender = _sender(app, mgr)
        out: list = []
        for _ in range(n):
            try:
                out.append(sender.send(app.base + path, "id", "1").status)
            except SessionAuthError as exc:
                out.append(type(exc).__name__)
                break
        state = mgr._state.get((HOST, "user"))
        url = state.protected_probe if state is not None else None
        return {"resource": url.replace(app.base, "/") if url else None,
                "sends": len(out), "last": out[-1], "logins": app.logins,
                "invalidations": len(losses), "asleep_s": sum(clock.sleeps),
                "checks": app.health_gets()}
    finally:
        app.close()


def measure() -> None:
    """Print what the code under test does in each scenario (DRAFT-AU-SESS403 §1 cites
    the tables printed for the base and for the design)."""
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
    for mode, path in (("json", "api/reports"), ("json", "api/me"),
                       ("rotate_all", "home.php")):
        print(f"30 probes, default bounds ({mode}, /{path}):",
              run_relogin_window(mode, path))


if __name__ == "__main__":
    measure()
