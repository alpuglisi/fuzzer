"""BUG-0690: the M6 browser executor's visits carry the run's session (FR-FUZZ-680/681).

Before: `harness/auto_cli._run_traced` built `PlaywrightBrowserExecutor()` with no
session, so in a run with ``--identity`` the stored-XSS plant (``context.request.fetch``
of the form/JSON write) and the observe page load went out anonymously. On a
cookie-session app the plant got ``302 -> /login`` (nothing stored) while the run's HTTP
probes (`SeamProbeSender`) got 200, and the observe page was the login page: the
payload was filed "did not fire" -- a false negative for every stored XSS behind a login.

Now the run's sender decides the session a visit carries
(`SeamProbeSender.browser_session_route`, through its auth-endpoint and isolation
gates), the executor adopts it (`session_route=`), and a plant whose answer is not the
application's own (SP-56: a credentialed login redirect, a 401, a throttle, a gateway, a
policy block) is no verdict (`NotObserved`), never "did not fire".

Every site here is a loopback server this test starts; each test asserts what the SITE
received, per request.
"""

from __future__ import annotations

import ast
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.oracle.browser import SENTINEL, ExecRequest, NotObserved, StoreStep
from fuzzlab.oracle.probe import UnplaceableLocation
from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
from tests.test_navigation_aborts import _chromium_or_skip
from tests.test_session_origin_scope import PASSWORD, USER, _creds

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "tok690"
PAYLOAD = f"<img src=x onerror={SENTINEL}('{TOKEN}')>"
LOGIN_FORM = ("<html><body><form method='post' action='/login'>"
              "<input name='user'><input type='password' name='pw'>"
              "<input type='submit' value='Sign in'></form></body></html>")


# --- the cookie-session app ---------------------------------------------------------
class _ProfileSite:
    """A loopback cookie-session app. ``GET /login``: a login form; a right ``POST
    /login`` sets a fresh ``sid``. ``POST /profile`` stores ``lastName`` only with a live
    ``sid`` (else ``302 -> /login``); ``GET /dashboard`` renders it unescaped only with a
    live ``sid`` (else ``302 -> /login``). ``reject_profile``: ``POST /profile`` answers
    ``302 -> /login`` even with a live ``sid`` (the app dropped the session).

    Every request is recorded as ``(method, path, live, body)``: ``live`` is whether its
    ``Cookie`` carried a session id the app had issued, decided when it arrived."""

    def __init__(self, host="127.0.0.1"):
        require_loopback(host)                       # PA-0130: loopback only
        self.sessions: set[str] = set()
        self.log: list[tuple[str, str, bool, str]] = []
        self.stored: str = ""
        self.reject_profile = False
        self._lock = threading.Lock()
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _live(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and value in site.sessions:
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

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                live = self._live()
                with site._lock:
                    site.log.append(("GET", path, live, ""))
                if path == "/login":
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/":
                    who = "welcome alice" if live else "home"
                    return self._send(200, f"<html><body><p>{who}</p><a href='/dashboard'>"
                                           f"d</a></body></html>".encode())
                if path == "/dashboard":
                    if not live:
                        return self._send(302, headers=[("Location", "/login")])
                    return self._send(200, f"<html><body><p>welcome alice</p>"
                                           f"<p>{site.stored}</p></body></html>".encode())
                return self._send(404, b"no")

            def do_POST(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                live = self._live()
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = raw.decode("utf-8", "replace")
                with site._lock:
                    site.log.append(("POST", path, live, body))
                form = dict(parse_qsl(body))
                if path == "/login":
                    if form.get("user") == USER and form.get("pw") == PASSWORD:
                        with site._lock:
                            sid = f"sid-{len(site.sessions)}-0123456789abcdef"
                            site.sessions.add(sid)
                        return self._send(200, b"<html><p>welcome alice</p></html>",
                                          [("Set-Cookie", f"sid={sid}; Path=/")])
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/profile":
                    if not live or site.reject_profile:
                        return self._send(302, headers=[("Location", "/login")])
                    with site._lock:
                        site.stored = form.get("lastName", "")
                    return self._send(200, b"<html><p>saved</p></html>")
                return self._send(404, b"no")

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.base = f"http://{host}:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def since(self, mark: int) -> list[tuple[str, str, bool, str]]:
        with self._lock:
            return list(self.log[mark:])

    def mark(self) -> int:
        with self._lock:
            return len(self.log)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = _ProfileSite()
    yield s
    s.close()


def _sender(site):
    """A real `SeamProbeSender` for identity ``user`` over a real `SessionManager` (no
    browser login: the requests login against the site's form) and a real `HttpClient`,
    as `make_probe_sender` builds it, minus the OS keyring."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.session.manager import SessionManager
    from fuzzlab.tools.probesender import SeamProbeSender
    mgr = SessionManager(_creds("127.0.0.1"), scope_hosts=["127.0.0.1"],
                         browser_login=False)
    client = HttpClient(RequestBudget(200), ["127.0.0.1"], session=mgr)
    return SeamProbeSender(client, "user", manager=mgr, base_url=site.base), mgr


def _stored_xss_request(site, store_path="profile"):
    return ExecRequest(url=site.base + "dashboard",
                       store=StoreStep(url=site.base + store_path, param="lastName",
                                       value=PAYLOAD, method="POST", location="body"))


def _run(executor, request):
    """Run the real executor. A launch failure skips (or fails, when a browser is
    required); every other no-verdict propagates to the test."""
    from tests._browser import skip_or_fail
    executor.SETTLE_MS = 1500
    try:
        return executor.run(request, TOKEN)
    except UnplaceableLocation as exc:
        if str(exc).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {exc}")
        raise


def _browser_requests(site, mark, paths):
    """The ``(method, path, live)`` of the visit's requests to ``paths`` (the session
    manager's own login and health fetches go to ``/`` and ``/login``)."""
    return [(m, p, live) for m, p, live, _b in site.since(mark) if p in paths]


# --- 1. the fix: the plant and the observe page carry the run's session ---------------
def test_the_plant_and_the_observe_page_carry_the_runs_session(monkeypatch, site):
    """A run with an identity: the executor built as auto_cli now builds it
    (``session_route=sender.browser_session_route``) plants as the identity -- the
    site's ``POST /profile`` carried the live session cookie and stored the payload --
    and loads the observe page as the identity, so the stored sink fires."""
    _chromium_or_skip(monkeypatch)
    sender, _mgr = _sender(site)
    executor = PlaywrightBrowserExecutor(timeout_ms=8000,
                                         session_route=sender.browser_session_route)
    mark = site.mark()
    obs = _run(executor, _stored_xss_request(site))
    seen = _browser_requests(site, mark, ("/profile", "/dashboard"))
    assert ("POST", "/profile", True) in seen, seen
    assert ("GET", "/dashboard", True) in seen, seen
    assert all(live for _m, _p, live in seen), seen        # never an anonymous request
    assert site.stored == PAYLOAD                           # the plant landed
    assert obs.executed is True, (obs, seen)


# --- 2. the pre-fix build: anonymous plant, no verdict of execution --------------------
def test_without_a_session_route_the_plant_goes_anonymously_the_bug(monkeypatch, site):
    """BUG-0690 as it was: ``PlaywrightBrowserExecutor()`` -- exactly what the pre-fix
    `auto_cli._run_traced` built, whatever ``--identity`` said. The same request on the
    same site: the plant ``POST /profile`` arrives WITHOUT the session cookie, is
    answered ``302 -> /login`` and stores nothing; the observe ``GET /dashboard`` is
    anonymous too (302 to the login page). The result is ``executed=False``: an
    anonymous plant's login redirect is the app's own answer to an anonymous request
    (SP-56, not credentialed), so `_plant_landed` does not raise, and the login page has
    no sink -- the false negative the fix removes."""
    _chromium_or_skip(monkeypatch)
    sender, _mgr = _sender(site)
    sender.browser_session_route([site.base])               # the run is logged in
    assert site.sessions                                    # the probes would carry it
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    mark = site.mark()
    obs = _run(executor, _stored_xss_request(site))
    seen = _browser_requests(site, mark, ("/profile", "/dashboard"))
    assert ("POST", "/profile", False) in seen, seen        # the bug: no cookie
    assert ("GET", "/dashboard", False) in seen, seen
    assert not any(live for _m, _p, live in seen), seen
    assert site.stored == ""                                 # nothing was planted
    assert obs.executed is False, obs


# --- 3. the sender's gates: auth endpoints and isolated paths go anonymous --------------
def test_a_visit_planting_to_the_auth_endpoint_carries_no_session(monkeypatch, site):
    """The plant URL is the manager's auth endpoint (the login form's action): the
    sender never sends the run's session there (BUG-0112), so `browser_session_route`
    is None and the whole visit -- the plant ``POST /login`` and the observe ``GET
    /dashboard`` -- reaches the site without a live session cookie."""
    _chromium_or_skip(monkeypatch)
    sender, mgr = _sender(site)
    login = site.base + "login"
    assert sender.browser_session_route([site.base + "dashboard"]) is not None
    assert mgr.is_auth_endpoint(login)
    assert sender.browser_session_route([site.base + "dashboard", login]) is None
    executor = PlaywrightBrowserExecutor(timeout_ms=8000,
                                         session_route=sender.browser_session_route)
    mark = site.mark()
    obs = _run(executor, _stored_xss_request(site, store_path="login"))
    plants = [(m, p, live) for m, p, live, body in site.since(mark)
              if m == "POST" and p == "/login" and "lastName=" in body]
    observes = _browser_requests(site, mark, ("/dashboard",))
    assert plants == [("POST", "/login", False)], site.since(mark)
    assert observes and not any(live for _m, _p, live in observes), observes
    assert obs.executed is False


def test_an_isolated_store_path_routes_the_visit_anonymously(site):
    """FR-FUZZ-44: an isolated path has no isolated copy in a browser visit, so a visit
    to it is anonymous -- never the run's session."""
    sender, mgr = _sender(site)
    store, observe = site.base + "profile", site.base + "dashboard"
    route = sender.browser_session_route([observe, store])
    assert route is not None and route[0] is mgr and route[1] == "user"
    sender.isolate([store])
    assert sender.browser_session_route([observe, store]) is None
    assert sender.browser_session_route([observe]) is not None


def test_an_anonymous_or_managerless_sender_has_no_route(site):
    from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
    _sender_, mgr = _sender(site)
    assert SeamProbeSender(object(), "anonymous", manager=mgr,
                           base_url=site.base).browser_session_route([site.base]) is None
    assert SeamProbeSender(object(), "user").browser_session_route([site.base]) is None
    assert not hasattr(RequestsProbeSender(), "browser_session_route")


# --- 4. a plant the app did not take is no verdict -------------------------------------
def test_a_credentialed_plant_answered_by_a_login_redirect_is_not_observed(monkeypatch,
                                                                            site):
    """The app drops the session at the plant (``POST /profile`` with a live cookie
    answers ``302 -> /login``): nothing was stored, so the payload is not observed
    (`NotObserved`), never "did not fire"; the observe page is never loaded."""
    _chromium_or_skip(monkeypatch)
    sender, _mgr = _sender(site)
    site.reject_profile = True
    executor = PlaywrightBrowserExecutor(timeout_ms=8000,
                                         session_route=sender.browser_session_route)
    mark = site.mark()
    with pytest.raises(NotObserved, match="not stored"):
        _run(executor, _stored_xss_request(site))
    seen = _browser_requests(site, mark, ("/profile", "/dashboard"))
    assert seen == [("POST", "/profile", True)], seen


class _Resp:
    def __init__(self, status, location=None):
        self.status = status
        self.headers = {"location": location} if location else {}


_SESSION = object()            # `_plant_landed` reads only whether a session was carried
URL = "http://127.0.0.1:8080/profile"


@pytest.mark.parametrize("status,location", [(200, None), (201, None), (204, None),
                                             (302, "/dashboard"), (303, "/profile?ok=1"),
                                             (400, None), (404, None), (500, None)])
def test_an_application_answer_to_a_credentialed_plant_lands(status, location):
    PlaywrightBrowserExecutor._plant_landed(URL, _Resp(status, location), _SESSION)


@pytest.mark.parametrize("status,location", [(302, "/login"), (303, "/login"),
                                             (302, "http://127.0.0.1:8080/login"),
                                             (401, None), (429, None), (503, None),
                                             (502, None), (504, None), (403, None),
                                             (407, None)])
def test_a_non_application_answer_to_a_credentialed_plant_is_not_observed(status,
                                                                          location):
    with pytest.raises(NotObserved, match="the plant was not stored"):
        PlaywrightBrowserExecutor._plant_landed(URL, _Resp(status, location), _SESSION)


@pytest.mark.parametrize("status,location", [(302, "/login"), (401, None)])
def test_an_anonymous_plants_login_answer_is_the_apps_own(status, location):
    """SP-56: to an anonymous request a login redirect or a 401 is the app's own answer
    (not a lost session): no raise."""
    PlaywrightBrowserExecutor._plant_landed(URL, _Resp(status, location), None)


@pytest.mark.parametrize("status", [429, 503, 502, 403])
def test_a_throttle_gateway_or_policy_answer_is_not_observed_even_anonymously(status):
    with pytest.raises(NotObserved):
        PlaywrightBrowserExecutor._plant_landed(URL, _Resp(status), None)


# --- 5. auto_cli wiring -------------------------------------------------------------------
def _args(**kw):
    base = dict(spider_db="/nonexistent/fuzzlab-spider.db", disco_run=[],
                base_url="http://127.0.0.1:9/", fuzz_json_writes=False, auth_origin=None,
                no_login=False, identity="user", peer_names=None, peer_identity=None,
                browser=True, oob=False, greybox_coverage_file=None,
                greybox_dbfault_file=None, bandit=False, mode="detect", points=None,
                confirm_budget=None, header_names=None, no_trace=True)
    base.update(kw)
    return types.SimpleNamespace(**base)


def _drive_run_traced(monkeypatch, args, sender):
    """Run `auto_cli._run_traced` with the sender, the run and the summary stubbed (no
    traffic, no browser launch); the browser executor the run was given."""
    from fuzzlab.harness import auto_cli
    from fuzzlab.tools import probesender
    got = {}
    monkeypatch.setattr(auto_cli, "make_probe_sender", lambda *a, **kw: sender)
    monkeypatch.setattr(probesender, "RequestsProbeSender", lambda *a, **kw: sender)
    monkeypatch.setattr(auto_cli, "_account_values", lambda _args: None)
    monkeypatch.setattr(auto_cli, "run_auto",
                        lambda **kw: got.setdefault("browser", kw["browser"]))
    monkeypatch.setattr(auto_cli, "_print_summary", lambda *a, **kw: 0)
    assert auto_cli._run_traced(None, args, None, 1, None, None, None) == 0
    return got["browser"]


def test_run_traced_gives_the_browser_the_runs_sender_session_route(monkeypatch):
    """Behavioural: with ``--browser`` and an identity, the executor `_run_traced`
    hands the run is built with the run's sender's own ``browser_session_route``."""
    class _Sender:
        def browser_session_route(self, urls):
            return None

    sender = _Sender()
    browser = _drive_run_traced(monkeypatch, _args(), sender)
    assert isinstance(browser, PlaywrightBrowserExecutor)
    assert browser._session_route == sender.browser_session_route


def test_run_traced_with_no_login_gives_the_browser_no_session(monkeypatch):
    """``--no-login``: the plain sender has no route -- the browser carries none."""
    sender = types.SimpleNamespace()                       # no browser_session_route
    browser = _drive_run_traced(monkeypatch, _args(no_login=True), sender)
    assert isinstance(browser, PlaywrightBrowserExecutor)
    assert browser._session_route is None


def _executor_calls_without_route(source: str) -> list[int]:
    """Lines of every ``PlaywrightBrowserExecutor(...)`` call without ``session_route=``."""
    bad = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else \
                fn.attr if isinstance(fn, ast.Attribute) else None
            if name == "PlaywrightBrowserExecutor" and \
                    not any(k.arg == "session_route" for k in node.keywords):
                bad.append(node.lineno)
    return bad


def test_every_auto_cli_executor_is_built_with_a_session_route():
    """Whole-module guard: every executor `auto_cli` builds passes ``session_route``;
    proven on a synthetic offender (the pre-fix line) and a compliant call."""
    offender = "def f(s):\n    return PlaywrightBrowserExecutor()\n"
    attr = "def f(s):\n    return browserexec.PlaywrightBrowserExecutor(timeout_ms=1)\n"
    good = ("def f(s):\n    return PlaywrightBrowserExecutor(\n"
            "        session_route=getattr(s, 'browser_session_route', None))\n")
    assert _executor_calls_without_route(offender) == [2]
    assert _executor_calls_without_route(attr) == [2]
    assert _executor_calls_without_route(good) == []
    source = (ROOT / "fuzzlab" / "harness" / "auto_cli.py").read_text()
    assert "PlaywrightBrowserExecutor(" in source
    assert _executor_calls_without_route(source) == []


# --- 6. one session source -----------------------------------------------------------------
def test_storage_headers_and_a_session_route_together_are_refused():
    with pytest.raises(ValueError, match="session route"):
        PlaywrightBrowserExecutor(storage_headers={"Authorization": "Bearer x"},
                                  session_route=lambda urls: None)
    PlaywrightBrowserExecutor(storage_headers={"X-A": "1"})           # each alone: fine
    PlaywrightBrowserExecutor(session_route=lambda urls: None)
