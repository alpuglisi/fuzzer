"""Defect 6 / BUG-0533 (AU-SESS403, CC-SESS-0029): a forbidden answer is never, by
itself, a lost session.

`session.detect.detect_logout` read every 401 and 403 as a session loss, and
`SessionManager.observe` then marked the session invalid, so the next `prepare` logged
in again. A low-privilege identity denied an admin route, a WAF block on a quote or a
CSRF refusal each cost one login and changed the session in the middle of the run.

These tests measure that on a real loopback app: a PHP-like login form with a token
that changes on every load, an anonymous cookie before the login, and a protected
landing page. They send through the real `SessionManager` (its default requests
fetcher; no browser), the real `core.http.HttpClient` seam and `SeamProbeSender`.
- Logins are counted by the server.
- Invalidations are counted by an FR-SESS-16 logout listener.
- The session each probe carried is the server's own record of it.
- Credentials are in memory (`tests.test_credentials.FakeBackend`, D12).

A test marked ``_BUG_0533`` fails on 15a8a27. It is a strict xfail until CC-SESS-0029
lands, which removes the marker. The unmarked tests pin what must not change: a 429
was never a loss, a real expiry is still recovered with one login, and the single-flight
lock stops simultaneous duplicate logins.

``python3 -m tests.test_session_forbidden_answers`` prints the measurement table that
`docs/components/03-session-manager/DRAFT-AU-SESS403.md` cites."""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import HttpClient, Request
from fuzzlab.core.net import require_loopback
from fuzzlab.core.urls import canonical_origin
from fuzzlab.session import detect
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.probesender import SeamProbeSender
from tests.test_credentials import FakeBackend

HOST = "127.0.0.1"
#: identity -> (username, password, role)
ACCOUNTS = {"user": ("alice", "pw-alice-0533", "user"),
            "admin": ("root", "pw-root-0533", "admin")}
#: Probes per scenario.
N = 10

_BUG_0533 = pytest.mark.xfail(
    strict=True, reason="BUG-0533: a forbidden or unconfirmed answer logs the session in "
                        "again (defect 6); CC-SESS-0029 removes this marker")


def _login_page(token: str) -> bytes:
    return ("<html><body><form method='post' action='/login.php'>"
            f"<input type='hidden' name='user_token' value='{token}'>"
            "<input type='text' name='username'>"
            "<input type='password' name='password'>"
            "<input type='submit' name='Login' value='Login'>"
            "</form></body></html>").encode()


class _App:
    """A PHP-like app on loopback. Its routes:

    - ``GET /login.php``: the login form. It sets an anonymous ``SID`` first, as PHP's
      ``session_start()`` does (PA-0007). Its ``user_token`` is new on every load
      (``per_load_token``), as DVWA's is.
    - ``POST /login.php``: the right credentials and an issued token start a new
      ``SID`` (counted in ``logins``) and redirect to ``/home.php``. Anything else
      shows the form again.
    - ``/`` redirects to ``/home.php`` with a live session, else to ``/login.php``.
      Without a live session, every page but ``/``, ``/login.php`` and
      ``/products.php`` redirects to the login page, and ``/api/*`` answers 401.
    - ``/home.php``: the welcome page, a stable protected resource.
    - ``/admin.php``: 403 unless the role is admin (an authorization denial).
    - ``/search.php?q=``: 403 when ``q`` holds a quote (a WAF rule).
    - ``POST /comment.php``: 403 unless ``csrf`` is the session's token (CSRF).
    - ``/products.php``: 429 with ``Retry-After``, always (a rate limit).
    - ``/api/reports``: 401 for the user role (an API that answers 401 for scope).
    - ``/manager.php``: a redirect to the login page for the user role (a
      privilege-gated login redirect, FR-SESS-18's residual).
    - ``POST /account/password.php``: 401 when ``current_password`` is wrong (a
      credential submission's own refusal).
    - ``/slow.php``: answers only after ``slow_release``. It judges the session when it
      answers, so an earlier session's late answer can be produced on demand.
    - ``/sync403.php``: holds each request until ``round_size`` have arrived, then
      answers 403. A concurrent round is then prepared in full before any answer.

    Each request is recorded as ``(method, path, SID)`` when it arrives."""

    def __init__(self, *, per_load_token: bool = True, round_size: int = 1):
        self.per_load_token = per_load_token
        self._lock = threading.Lock()
        self.sessions: dict[str, str | None] = {}     # SID -> identity (None: anonymous)
        self.csrf: dict[str, str] = {}                # SID -> its CSRF token
        self.tokens: set[str] = set()
        self.logins = 0
        self.requests: list[tuple[str, str, str | None]] = []
        self.slow_arrived = threading.Event()
        self.slow_release = threading.Event()
        self.round = threading.Barrier(round_size) if round_size > 1 else None
        self.server = self._serve()
        self.base = f"http://{HOST}:{self.server.server_address[1]}/"

    def close(self) -> None:
        self.slow_release.set()
        self.server.shutdown()
        self.server.server_close()

    def expire_all(self) -> None:
        """The server ends every logged-in session (an expiry)."""
        with self._lock:
            for sid in [s for s, who in self.sessions.items() if who]:
                del self.sessions[sid]

    def sids(self, path: str) -> set:
        """The SIDs the requests to ``path`` carried, read from the whole log."""
        with self._lock:
            return {sid for _m, p, sid in self.requests if p == path}

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

            def _who(self, sid):
                with app._lock:
                    return app.sessions.get(sid) if sid else None

            def _send(self, status, body=b"", headers=(), ctype="text/html"):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _route(self, method):
                parts = urlsplit(self.path)
                path, sid = parts.path, self._sid()
                with app._lock:
                    app.requests.append((method, path, sid))
                    known = sid in app.sessions
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode(),
                                      keep_blank_values=True)) if length else {}
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                who = self._who(sid)
                role = ACCOUNTS[who][2] if who else None
                to_login = [("Location", "/login.php")]
                if path == "/login.php" and method == "GET":
                    extra = []
                    if not known:                       # PHP's session_start()
                        anon = "anon-" + secrets.token_hex(12)
                        with app._lock:
                            app.sessions[anon] = None
                        extra = [("Set-Cookie", f"SID={anon}; Path=/; HttpOnly")]
                    token = secrets.token_hex(8) if app.per_load_token else "static-0533"
                    with app._lock:
                        app.tokens.add(token)
                    return self._send(200, _login_page(token), extra)
                if path == "/login.php":
                    ident = next((i for i, (u, p, _r) in ACCOUNTS.items()
                                  if u == form.get("username") and p == form.get("password")),
                                 None)
                    with app._lock:
                        issued = form.get("user_token") in app.tokens
                    if ident is None or not issued:
                        return self._send(200, _login_page(secrets.token_hex(8)))
                    new = "sess-" + secrets.token_hex(16)
                    with app._lock:
                        app.sessions.pop(sid, None)     # the session id is regenerated
                        app.sessions[new] = ident
                        app.csrf[new] = secrets.token_hex(8)
                        app.logins += 1
                    return self._send(302, b"", [("Location", "/home.php"),
                                                 ("Set-Cookie", f"SID={new}; Path=/; HttpOnly")])
                if path == "/":
                    return self._send(302, b"", [("Location", "/home.php" if who
                                                  else "/login.php")])
                if path == "/products.php":
                    return self._send(429, b"<h1>Too Many Requests</h1>",
                                      [("Retry-After", "1")])
                if path == "/slow.php":
                    app.slow_arrived.set()
                    app.slow_release.wait(10)
                    who = self._who(sid)                # judged when it answers
                if who is None:
                    if path.startswith("/api/"):
                        return self._send(401, b'{"error":"unauthenticated"}',
                                          ctype="application/json")
                    return self._send(302, b"", to_login)
                if path in ("/home.php", "/slow.php"):
                    return self._send(200, f"<h1>Welcome {ACCOUNTS[who][0]}</h1>".encode())
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
                if path == "/api/reports":
                    return self._send(200, b'{"reports":[]}', ctype="application/json") \
                        if role == "admin" else \
                        self._send(401, b'{"error":"insufficient scope"}',
                                   ctype="application/json")
                if path == "/manager.php":
                    return self._send(200, b"<h1>Manager</h1>") if role == "admin" else \
                        self._send(302, b"", [("Location", "/login.php?next=/manager.php")])
                if path == "/account/password.php":
                    if form.get("current_password") != ACCOUNTS[who][1]:
                        return self._send(401, b"<p>current password is wrong</p>")
                    return self._send(200, b"<p>changed</p>")
                if path == "/sync403.php":
                    if app.round is not None:
                        try:
                            app.round.wait(10)
                        except threading.BrokenBarrierError:
                            pass
                    return self._send(403, b"<h1>403 Forbidden</h1>")
                return self._send(404, b"not found")

            def do_GET(self):  # noqa: N802 - http.server API
                self._route("GET")

            def do_POST(self):  # noqa: N802 - http.server API
                self._route("POST")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer((HOST, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


def _creds() -> CredentialStore:
    store = CredentialStore(backend=FakeBackend())
    for identity, (username, password, _role) in ACCOUNTS.items():
        store.set(HOST, identity, username, password)
    return store


def _manager():
    """The real manager with its default requests fetcher (no browser), and the list a
    logout listener appends each valid -> invalid transition to (FR-SESS-16)."""
    mgr = SessionManager(_creds(), scope_hosts=[HOST], browser_login=False)
    losses: list[str] = []
    mgr.add_logout_listener(lambda origin, identity: losses.append(identity))
    return mgr, losses


def _sender(app: _App, mgr: SessionManager, identity: str = "user") -> SeamProbeSender:
    client = HttpClient(RequestBudget(10_000), [HOST], session=mgr)
    return SeamProbeSender(client, identity, manager=mgr, base_url=app.base)


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
}


def run_scenario(name: str, n: int = N) -> dict:
    """``n`` probes of scenario ``name`` by the low-privilege identity: the server's
    login count, the listener's invalidations, the sessions the probes carried and the
    probes' statuses."""
    path, send = SCENARIOS[name]
    app = _App()
    try:
        mgr, losses = _manager()
        sender = _sender(app, mgr)
        statuses = [send(sender, app.base).status for _ in range(n)]
        return {"probes": n, "logins": app.logins, "invalidations": len(losses),
                "sessions": len(app.sids(path)), "statuses": sorted(set(statuses))}
    finally:
        app.close()


def run_real_expiry() -> dict:
    """A real server-side expiry in the middle of a run: a login, an expiry, then
    three sends of the protected page."""
    app = _App()
    try:
        mgr, losses = _manager()
        client = HttpClient(RequestBudget(1000), [HOST], session=mgr)

        def get(path):
            return client.send(Request("GET", app.base + path, identity="user")).status
        first = get("home.php")
        app.expire_all()
        after = [get("home.php") for _ in range(3)]
        return {"logins": app.logins, "invalidations": len(losses),
                "statuses": [first] + after}
    finally:
        app.close()


def run_stale_answer() -> dict:
    """A late answer from an earlier session: ``/slow.php`` is sent on session 1 and
    held; the server expires session 1; the loss is seen and session 2 logs in; then
    session 1's late redirect to the login page arrives; then one more send."""
    app = _App()
    try:
        mgr, losses = _manager()
        client = HttpClient(RequestBudget(1000), [HOST], session=mgr)

        def get(path):
            return client.send(Request("GET", app.base + path, identity="user")).status
        get("home.php")                                   # login 1
        late = threading.Thread(target=get, args=("slow.php",))
        late.start()
        assert app.slow_arrived.wait(10)                  # in flight on session 1
        app.expire_all()                                  # the server ends session 1
        get("home.php")                                   # the loss is seen
        get("home.php")                                   # login 2
        app.slow_release.set()                            # session 1's answer arrives
        late.join(10)
        get("home.php")
        return {"logins": app.logins, "invalidations": len(losses)}
    finally:
        app.close()


def run_concurrent_rounds(rounds: int, width: int = 6) -> dict:
    """``rounds`` rounds of ``width`` concurrent 403s. The server holds each round until
    all of it has arrived, so every send of a round is prepared before any answer."""
    app = _App(round_size=width)
    try:
        mgr, losses = _manager()
        client = HttpClient(RequestBudget(10_000), [HOST], session=mgr)
        per_round = []
        for _ in range(rounds):
            before = app.logins
            threads = [threading.Thread(target=client.send, args=(
                Request("GET", app.base + "sync403.php", identity="user"),))
                for _ in range(width)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            per_round.append(app.logins - before)
        return {"rounds": rounds, "width": width, "logins": app.logins,
                "logins_per_round": per_round, "invalidations": len(losses)}
    finally:
        app.close()


def run_protected_resource(per_load_token: bool = True) -> dict:
    """After an HTTP form login: the stable protected resource the session recorded,
    and what the one existing differential (`SessionManager._spa_probe`, FR-SESS-19)
    finds on this app's landing page and base URL."""
    app = _App(per_load_token=per_load_token)
    try:
        mgr, _losses = _manager()
        state = mgr.ensure(HOST, "user", app.base, operator=True)
        url, digest = mgr._spa_probe(HOST, app.base, state,
                                     [app.base + "home.php", app.base])
        return {"recorded": state.protected_probe, "differential": url,
                "refusal_digest": digest is not None,
                "origins": sorted(state.origins), "base": app.base}
    finally:
        app.close()


# --- the four scenarios of the item, and their neighbours ----------------------------

@_BUG_0533
@pytest.mark.parametrize("name", ["admin-403", "waf-403", "csrf-403"])
def test_a_forbidden_answer_never_logs_the_session_in_again(name):
    """A 403 is a policy block (SP-56): one login for the run, no invalidation, and
    every probe carries the same session. Today: one login and one invalidation per
    probe, and a new session for every probe."""
    got = run_scenario(name)
    assert got["statuses"] == [403], got
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got


def test_a_throttled_answer_never_logs_the_session_in_again():
    """A 429 was never a loss: a pin that the fix must keep."""
    got = run_scenario("throttle-429")
    assert got["statuses"] == [429], got
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got


@_BUG_0533
@pytest.mark.parametrize("name", ["scope-401", "privilege-login-redirect"])
def test_a_suspected_loss_on_a_live_session_is_confirmed_before_any_login(name):
    """A credentialed 401 or a login redirect is only a *suspected* loss. The session's
    stable protected resource (``/home.php``) is still live, so nothing is invalidated
    and nothing logs in again."""
    got = run_scenario(name)
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got


@_BUG_0533
def test_a_credential_submissions_own_refusal_is_never_a_session_loss():
    """PA-0529(3): a request that submits a credential (a wrong current password) is
    answered 401 by its own endpoint, which is never a lost session."""
    got = run_scenario("password-401")
    assert got["statuses"] == [401], got
    assert (got["logins"], got["invalidations"], got["sessions"]) == (1, 0, 1), got


def test_a_real_expiry_is_still_seen_and_recovered_with_one_login():
    """The pin on the other side: a real expiry is invalidated once and recovered with
    exactly one more login."""
    got = run_real_expiry()
    assert got == {"logins": 2, "invalidations": 1, "statuses": [200, 302, 200, 200]}, got


@_BUG_0533
def test_a_late_answer_from_an_earlier_session_never_logs_in_again():
    """The generation bound: the late answer was sent on session 1, so it says nothing
    about session 2. Today it invalidates session 2, and a third login follows."""
    got = run_stale_answer()
    assert got == {"logins": 2, "invalidations": 1}, got


def test_the_single_flight_lock_stops_simultaneous_duplicate_logins():
    """The audit's claim, measured: six concurrent first sends cost one login."""
    got = run_concurrent_rounds(1)
    assert got["logins_per_round"] == [1], got


@_BUG_0533
def test_concurrent_forbidden_rounds_cost_no_login_after_the_first():
    """The lock does not stop sequential churn: each round of concurrent 403s costs one
    more login today. The fix makes it none."""
    got = run_concurrent_rounds(4)
    assert (got["logins"], got["invalidations"]) == (1, 0), got


@_BUG_0533
def test_an_http_form_login_records_a_stable_protected_resource():
    """The health check needs a resource that tells a live session from a lost one.
    Here the base URL is one, with no extra request: login discovery followed its own
    redirect to this login form (the anonymous answer), and the post-login check of it
    was live (the session's answer). That is FR-SESS-5's "a protected probe stops
    redirecting to login" (DRAFT-AU-SESS403 §3.4, rule 2)."""
    got = run_protected_resource()
    assert got["recorded"] == got["base"], got
    assert canonical_origin(got["recorded"]) in got["origins"], got


# --- SP-16's predicate on its own ------------------------------------------------------

LOGIN = "http://127.0.0.1:8080/login.php"
PAGE = "http://127.0.0.1:8080/admin.php"


@pytest.mark.parametrize("status", [pytest.param(403, marks=_BUG_0533), 451])
def test_detect_logout_reads_a_policy_block_never_as_a_loss(status):
    """SP-56's policy block (403, 451) is never a suspected loss, for a form or a Basic
    session. 451 was never one (a pin); 403 always was (BUG-0533)."""
    for content_check in (True, False):                     # a Basic session too
        assert not detect.detect_logout(status, {}, "<h1>Forbidden</h1>", login_url=LOGIN,
                                        page_url=PAGE, content_check=content_check)


def test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle():
    """Pins: a credentialed 401, a redirect to this login page and this login form
    shown again stay suspected losses; a throttle, an unavailable server or a gateway
    never is."""
    assert detect.detect_logout(401, {}, "", login_url=LOGIN, page_url=PAGE)
    assert detect.detect_logout(302, {"Location": "/login.php"}, "", login_url=LOGIN,
                                page_url=PAGE)
    assert detect.detect_logout(200, {}, _login_page("x").decode(), login_url=LOGIN,
                                page_url=PAGE, login_fields=("Login", "password",
                                                             "user_token", "username"))
    for status in (429, 502, 503, 504):
        assert not detect.detect_logout(status, {}, "", login_url=LOGIN, page_url=PAGE)


# --- the measurement table -------------------------------------------------------------

def measure() -> None:
    """Print what 15a8a27 does in each scenario (cited by DRAFT-AU-SESS403.md)."""
    rows = []
    for name in SCENARIOS:
        got = run_scenario(name)
        rows.append((name, got["probes"], got["logins"], got["invalidations"],
                     got["sessions"], got["statuses"]))
    for n in (1, 5, 20):
        got = run_scenario("admin-403", n)
        rows.append((f"admin-403 n={n}", n, got["logins"], got["invalidations"],
                     got["sessions"], got["statuses"]))
    print("scenario | probes | logins | invalidations | sessions used | statuses")
    for row in rows:
        print(" | ".join(str(c) for c in row))
    print("real expiry:", run_real_expiry())
    print("late answer from an earlier session:", run_stale_answer())
    print("one round of 6 concurrent first sends:", run_concurrent_rounds(1))
    print("4 rounds of 6 concurrent 403s:", run_concurrent_rounds(4))
    for per_load in (True, False):
        got = run_protected_resource(per_load)
        print(f"protected resource, per-load token={per_load}:",
              {"recorded": got["recorded"],
               "differential": (got["differential"] or "").replace(got["base"], "/"),
               "refusal_digest": got["refusal_digest"]})
    for status in (401, 403, 451, 429, 503, 502, 504, 407):
        print(f"detect_logout({status}) =", detect.detect_logout(
            status, {}, "", login_url=LOGIN, page_url=PAGE))


if __name__ == "__main__":
    measure()
