"""A login whose page was not read is `LoginFetchFailed`, which every login caller
handles (FR-SESS-3; BUG-0558, review round 1, SESSROT-B1).

BUG-0558 made login discovery stop taking a transport failure (a cut, reset or
incomplete page) for "no login form here": on ffac4fa it let the ``requests`` error
escape `SessionManager.ensure` and ``prepare``. That broke every caller's contract,
which handles `SessionAuthError` only: the seam mapped the error to "not observed" with
no cap (one more login per send, every probe inconclusive, no loud stop), disco's
recovery escaped its worker (``stop='error'``), the spider's page handler retried the
login per page instead of stopping the crawl, both CLIs ended in a traceback, and one
reset candidate (``/login``) hid a form at another (``/signin``) and the browser
fallback (FR-SESS-19).

Now every candidate and the browser fallback have their turn; when none yields a login
and a page was not read, the login raises `LoginFetchFailed` (a `SessionAuthError`
naming only the transport error's class, chained to it), never charged to the re-auth
cap and capped on its own (``max_login_fetch_failures`` in a row, then a plain
`SessionAuthError`). A transport failure of the credentials POST is the same (the
sweep). One test per caller, each on a loopback app whose login page is cut short
(``Content-Length: 100``, ten bytes, then the close).

Each test fails on ffac4fa on its own assertion (the transport error escaped, or the
crawl went on), recorded in the lane's review-round proof.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.session.manager import SessionAuthError, SessionManager
from fuzzlab.session.state import SessionState
from tests.test_session_origin_scope import PASSWORD, USER, _creds

#: Discovery's candidates from the base ``/`` (`SessionManager._discover_login_form`).
CANDIDATES = ["/", "/login", "/login.php", "/signin", "/users/login"]
#: A page cut short: 100 bytes promised, ten sent, then the connection closed.
CUT = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n"
       b"<html><bo")
KEY = ("127.0.0.1", "user")


def _form(action: str) -> bytes:
    return (f"<html><body><form method='post' action='{action}'><input name='user'>"
            f"<input type='password' name='pw'><input type='submit' value='Sign in'>"
            f"</form></body></html>").encode()


class _LoginApp:
    """A loopback app (PA-0130). Its login form is served at ``form_at`` and a right
    POST there sets a fresh ``sid``; ``/`` is a welcome page with a live ``sid``, else a
    ``home`` page, both linking ``/expiring`` and ``/secret``; ``/expiring``'s first
    credentialed GET ends every session, cuts the login page from then on and answers a
    login redirect; ``/secret`` and ``/expiring`` answer 200 with a live ``sid``, else
    that redirect. A GET of a path in ``cut`` (every path with ``cut_every``) and, with
    ``cut_post``, the credentials POST are answered with `CUT`. Every request is
    recorded as ``(method, path)``."""

    def __init__(self, form_at: str = "/login"):
        self.form_at = form_at
        self.cut: set[str] = set()
        self.cut_every = False
        self.cut_post = False
        self.sessions: set[str] = set()
        self.logins = 0
        self.expired = False
        self.requests: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        require_loopback("127.0.0.1")
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _live(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and value in app.sessions:
                        return True
                return False

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _cut(self):
                self.wfile.write(CUT)
                self.wfile.flush()
                self.close_connection = True

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                with app._lock:
                    app.requests.append(("GET", path))
                if app.cut_every or path in app.cut:
                    return self._cut()
                live = self._live()
                if path == app.form_at:
                    return self._send(200, _form(app.form_at))
                if path == "/":
                    who = "welcome alice" if live else "home"
                    return self._send(200, f"<html><body><p>{who}</p><a href='/expiring'>"
                                           f"e</a><a href='/secret'>s</a></body></html>"
                                      .encode())
                if path == "/expiring" and live and not app.expired:
                    with app._lock:
                        app.expired = True
                        app.sessions.clear()               # the session ends ...
                        app.cut.add(app.form_at)           # ... and the login page is cut
                    return self._send(302, headers=[("Location", app.form_at)])
                if path in ("/secret", "/expiring"):
                    if not live:
                        return self._send(302, headers=[("Location", app.form_at)])
                    return self._send(200, f"<html><body><p>{path.strip('/').upper()}-PAGE"
                                           f"</p></body></html>".encode())
                return self._send(404, b"no")

            def do_POST(self):  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                with app._lock:
                    app.requests.append(("POST", self.path))
                if self.path == app.form_at:
                    if app.cut_post:
                        return self._cut()
                    if form.get("user") == USER and form.get("pw") == PASSWORD:
                        with app._lock:
                            app.logins += 1
                            sid = f"sid-{app.logins}-0123456789abcdef"
                            app.sessions.add(sid)
                        return self._send(200, b"<html><p>welcome alice</p></html>",
                                          [("Set-Cookie", f"sid={sid}; Path=/")])
                return self._send(200, _form(app.form_at))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def gets(self, since: int = 0) -> list[str]:
        with self._lock:
            return [p for m, p in self.requests[since:] if m == "GET"]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def app():
    a = _LoginApp()
    yield a
    a.close()


@pytest.fixture
def no_browser(monkeypatch):
    """The browser login (FR-SESS-19, on for the CLIs' managers) finding no login on
    the cut page: each call is recorded and refused as `browserlogin.run` refuses."""
    from fuzzlab.session import browserlogin
    calls: list[str] = []

    def run(destination_ok, base_url, cred, **kw):
        calls.append(base_url)
        raise browserlogin.BrowserLoginError("no login form found in the browser")
    monkeypatch.setattr(browserlogin, "run", run)
    return calls


def _mgr(**kw) -> SessionManager:
    return SessionManager(_creds(), scope_hosts=["127.0.0.1"], browser_login=False, **kw)


def _raised(call):
    """``call()``'s exception (None when it returned): a test asserts on it, so the old
    code's escaping error fails the test's own assertion, not the harness."""
    try:
        call()
    except BaseException as exc:  # noqa: BLE001 - SystemExit included (the CLIs)
        return exc
    return None


def _chain_names(exc: BaseException | None) -> list[str]:
    names = []
    while exc is not None:
        names.append(type(exc).__name__)
        exc = exc.__cause__
    return names


# --- the seam (SP-34): bounded logins, then a loud stop ------------------------------------
def test_a_seams_cut_login_page_costs_a_bounded_number_of_logins_then_stops_loudly(app):
    """Every page is cut. Each of the first three sends (``max_login_fetch_failures``)
    makes one login -- every candidate once -- and is "not observed" (the probe never
    left); the fourth and fifth are refused at once with the cap's `SessionAuthError`,
    before anything is fetched. The probe's own URL is never requested, and nothing is
    charged to the re-auth cap. Before (ffac4fa): five times "not observed", one GET per
    send, never capped (BUG-0558 review round 1, B1)."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.oracle.probe import ProbeUnobserved
    from fuzzlab.tools.probesender import SeamProbeSender
    app.cut_every = True
    mgr = _mgr()
    client = HttpClient(RequestBudget(500), ["127.0.0.1"], session=mgr, timeout=5)
    seam = SeamProbeSender(client, "user", manager=mgr, base_url=app.base)
    raised = [_raised(lambda: seam.send(app.base + "item", "q", "1")) for _ in range(5)]
    outcomes = [type(exc).__name__ for exc in raised]
    assert outcomes == ["ProbeUnobserved"] * 3 + ["SessionAuthError"] * 2, outcomes
    assert app.gets() == CANDIDATES * 3                  # bounded, then none
    assert "/item" not in app.gets()
    assert mgr._failures.get(KEY, 0) == 0                # never "no login form"
    for exc in raised[:3]:
        assert isinstance(exc, ProbeUnobserved) and "login" in str(exc)
        assert "ChunkedEncodingError" in str(exc) and app.base not in str(exc)
    for exc in raised[3:]:
        assert isinstance(exc, SessionAuthError) and "cap (3)" in str(exc)
        assert app.base not in str(exc)


# --- disco's recovery after a loss ---------------------------------------------------------
class _Page:
    def __init__(self, url):
        self.url = url

    def content(self):
        return "<p>board</p>"

    def is_closed(self):
        return False


def test_a_disco_recovery_whose_login_page_is_cut_ends_authenticated_exploration(app):
    """A confirmed loss; the provider's re-login finds every page cut. The recovery
    ends the run's authenticated exploration with a reason naming the failure's class
    (``_end_authenticated``), as for any failed login. Before (ffac4fa): the transport
    error escaped `_recover_session` -- in a worker, ``stop='error'`` and the run raised."""
    from fuzzlab.disco.explore import Explorer, ExploreSession, _SessionMaterial
    mgr = _mgr()
    state = mgr.adopt(SessionState("127.0.0.1", "user", kind="cookie",
                                   cookies={"sid": "sid-lost-0123456789abcdef"},
                                   origins=frozenset({app.base.rstrip("/")})),
                      protected_probe=app.base)
    state.valid = False                                   # the loss the run confirmed
    app.cut_every = True
    ex = Explorer(app.base, scope_urls=[app.base], proxy="127.0.0.1:9",
                  session=ExploreSession(mgr, "user", app.base))
    ex._shared.auth = _SessionMaterial(state.generation, scope=lambda _u: True,
                                       login_url=app.base + "login",
                                       login_fields=("pw", "user"))
    ex._ctx_generation = state.generation
    page = _Page(app.base)
    got = []
    exc = _raised(lambda: got.append(ex._recover_session(page, "lost",
                                                          "an auth failure (401)")))
    assert exc is None, f"{type(exc).__name__} escaped the recovery"
    assert got == [page] and ex._shared.stop == "session-lost"
    assert ex.report.auth_ended.startswith("no fresh session after a loss")
    assert ex.report.auth_ended.endswith("LoginFetchFailed")
    assert app.gets() == CANDIDATES                        # one login, every candidate
    assert mgr._failures.get(KEY, 0) == 0


# --- the spider's static crawl ---------------------------------------------------------------
def test_a_static_crawls_relogin_on_a_cut_login_page_stops_the_crawl(app, tmp_path,
                                                                      monkeypatch):
    """The crawl logs in, crawls ``/`` with the session, and ``/expiring`` ends the
    session and cuts the login page. The re-login on the next send fails at transport:
    the crawl stops with `IdentityUnavailable` (PA-0545(1)), after one login (every
    candidate once), and no page is sent without the session. Before (ffac4fa): the
    error fell into the per-page handler, each page failed and retried the login, and
    the crawl went on to its end."""
    from fuzzlab.tools import spider as sp
    monkeypatch.setattr(sp, "RETRY_BASE_S", 0.01)
    # a re-login bucket the old code's per-page retries never wait on
    mgr = _mgr(relogin_burst=20)
    spider = sp.LocalSpider(app.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                            engine="requests", session_manager=mgr, identity="user",
                            timeout_ms=5000)
    exc = _raised(spider.crawl)
    assert isinstance(exc, sp.IdentityUnavailable), (type(exc).__name__, exc)
    assert "LoginFetchFailed" in _chain_names(exc)
    assert app.logins == 1
    cut_at = app.requests.index(("GET", "/expiring"))
    after = app.gets(cut_at + 1)
    assert after.count("/login") == 1, after              # one re-login, then the stop
    assert not {"/secret", "/expiring"} & set(after), after
    assert mgr._failures.get(KEY, 0) == 0


# --- the CLIs ----------------------------------------------------------------------------------
def test_greybox_reports_a_cut_login_page_as_an_authentication_failure(
        app, no_browser, monkeypatch, tmp_path, capsys):
    """``greybox-run --identity``: every candidate and the browser fallback are tried
    (once), then the usage error naming the failure's class, not a traceback. Before
    (ffac4fa): the transport error escaped `main` at the first candidate, the browser
    fallback never tried."""
    from fuzzlab.core import config, credentials
    from fuzzlab.greybox import greybox_cli
    monkeypatch.setattr(config, "load_config", lambda: {"scope_hosts": []})
    monkeypatch.setattr(credentials.CredentialStore, "open",
                        classmethod(lambda cls, cfg: _creds()))
    app.cut_every = True
    exc = _raised(lambda: greybox_cli.main(["--base-url", app.base, "--store",
                                            str(tmp_path / "g.db"), "--authorized",
                                            "--identity", "user"]))
    assert isinstance(exc, SystemExit) and exc.code == 2, (type(exc).__name__, exc)
    err = capsys.readouterr().err
    assert "authentication failed for user@127.0.0.1" in err
    assert "not read (ChunkedEncodingError)" in err and app.base not in err
    assert no_browser == [app.base] and app.gets() == CANDIDATES
    assert not (tmp_path / "g.db").exists()


def test_session_print_reports_a_cut_login_page_as_a_failed_login(app, no_browser,
                                                                  monkeypatch, capsys):
    """``fuzzlab session print``: "login failed" and exit 1, after every candidate and
    the browser fallback. Before (ffac4fa): a traceback from the first candidate."""
    from fuzzlab.session import cli
    monkeypatch.setattr(cli, "load_config", lambda: {"scope_hosts": []})
    monkeypatch.setattr(cli.CredentialStore, "open", classmethod(lambda c, cfg: _creds()))
    app.cut_every = True
    got = []
    exc = _raised(lambda: got.append(cli.main(["print", "--host", "127.0.0.1",
                                               "--identity", "user", "--base-url",
                                               app.base])))
    assert exc is None and got == [1], (type(exc).__name__, exc)
    out = capsys.readouterr().out
    assert out.startswith("login failed: could not log user@127.0.0.1 in")
    assert "not read (ChunkedEncodingError)" in out and app.base not in out
    assert no_browser == [app.base] and app.gets() == CANDIDATES


# --- the login itself: the other candidates, and the sweep ----------------------------------
def test_a_cut_login_candidate_never_hides_a_form_at_another():
    """``/login`` is cut, the form is at ``/signin``: the login goes on to it and
    succeeds (FR-SESS-19's order: every candidate, then the browser). Before (ffac4fa):
    the cut ``/login`` ended the login before ``/signin`` was tried."""
    app = _LoginApp(form_at="/signin")
    try:
        app.cut.add("/login")
        mgr = _mgr()
        exc = _raised(lambda: mgr.ensure("127.0.0.1", "user", app.base, operator=True))
        assert exc is None, (type(exc).__name__, exc)
        state = mgr._state[KEY]
        assert state.valid and state.cookies["sid"].startswith("sid-1-")
        assert app.gets()[:4] == CANDIDATES[:4] and ("POST", "/signin") in app.requests
        assert mgr._fetch_failures.get(KEY, 0) == 0
    finally:
        app.close()


def test_a_cut_credentials_post_is_a_failed_fetch_never_a_rejected_login(app):
    """The credentials POST's answer is cut (the sweep of the handshake's other
    pages): `LoginFetchFailed`, counted on its own cap, never on ``max_reauth``. Before
    (ffac4fa, and 7393c90): the transport error escaped every caller."""
    app.cut_post = True
    mgr = _mgr()
    exc = _raised(lambda: mgr.ensure("127.0.0.1", "user", app.base, operator=True))
    assert isinstance(exc, SessionAuthError), (type(exc).__name__, exc)
    assert _chain_names(exc)[:2] == ["LoginFetchFailed", "ChunkedEncodingError"]
    assert "ChunkedEncodingError" in str(exc) and app.base not in str(exc)
    assert app.requests.count(("POST", "/login")) == 1
    assert mgr._failures.get(KEY, 0) == 0 and mgr._fetch_failures[KEY] == 1
