"""Behavioural discovery and a lost session (BUG-0552, FR-CRAWL-41, PA-0552).

The explorer used to decide a lost session by one predicate -- the page landed on a
login URL -- and "recovered" by building a new context from the storage state it started
with, without closing the old one. An app's API answering 401 while its route stays
``/dashboard``, or a login form rendered in place, went unseen; a server-invalidated
session was re-installed as if it were fresh; and each loss left a context open.

Now each answer an authenticated context gets is classified by SP-56
(`core.comparability.response_class`, with SP-16's `login_facts`), a login URL or this
session's login form on the page (SP-16) is a suspicion too, and SP-61
(`SessionManager.check_health`) decides for the generation the context carries. A
confirmed loss gets a fresh session from the session provider (`ExploreSession`: the
manager's `ensure`, shaped by `browserauth.browser_session`), revalidated by a protected
check, in a new context made only after the old one was released and closed; an
unresolved loss ends authenticated exploration with a reported reason; the action ids
of the answers in a known-lost window are marked (D'), never authenticated coverage.

Review round 1 (BUG-0552, "Review round 1"): a generation one worker finds lost is
recorded for every worker before any recovery, and no worker acts on it again or clears a
window sent on it (B1); no consumer of a capture's answers takes a known-lost window's
answer as evidence unless pinned (B2, `disco.capture.lost_action_ids`); without a known
login form, a password form shown where a restore or the start page showed none is in
place (R1); a login page after an action on a provider's live session reinstalls it
whatever answer came with it (R2); and a run without a provider checks a suspicion
against the start page, its protected resource, through SP-61's `health_verdict` (R3).

The real-browser tests drive a guarded Chromium through the real capture proxy against
a loopback app (`_SessionApp`) whose session dies after a number of API answers. Under
``FUZZLAB_REQUIRE_BROWSER=1`` a missing browser or mitmproxy fails instead of skipping
(PA-0065)."""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.disco.explore import Explorer, ExploreOptions
from tests._browser import skip_or_fail

USER, PASSWORD = "user", "pw-0123456789"

LOGIN = b"""<!doctype html><html><body><h1>Sign in</h1>
<form method=post action="/login"><input name=username>
<input type=password name=password><button>Sign in</button></form></body></html>"""

SHELL = b"""<!doctype html><html><head><title>Board</title></head><body>
<div id=root></div><script src="/app.js"></script></body></html>"""

#: The board's script. Its items come from ``/api/me``; a click on one fetches
#: ``/api/items/<n>`` and opens its panel. What it does on a 401 (or, in ``form`` mode,
#: an answer saying its session is gone) is the app's ``mode``: ``stay`` shows an error
#: line and keeps its route (``/dashboard``), ``form`` renders a login form in place (the
#: API answers 200 ``{"login": true}``), ``redirect`` goes to ``/login``, ``clear``
#: deletes its (script-readable) session cookie and goes to ``/login``.
APP_JS = r"""
const root = document.getElementById('root');
const MODE = '__MODE__';
function lost() {
  if (MODE === 'clear') {
    document.cookie = 'sid=; Max-Age=0; path=/'; location.href = '/login'; return;
  }
  if (MODE === 'redirect') { location.href = '/login'; return; }
  if (MODE === 'form') {
    root.innerHTML = '<form method=post action="/login"><input name=username>'
      + '<input type=password name=password><button>Sign in</button></form>';
    return;
  }
  const p = document.createElement('p'); p.className = 'error';
  p.textContent = 'Something went wrong'; root.appendChild(p);
}
// the answer is read whole before the app reacts to it (as an HTTP client's interceptor
// does): a 401 has arrived complete when the board then leaves for /login
function api(url) {
  return fetch(url).then(r => r.text().then(t => [r.status, t]))
    .then(([status, t]) => {
      if (status === 401) { lost(); return null; }
      const d = JSON.parse(t);
      if (d && d.login) { lost(); return null; }
      return d;
    });
}
api('/api/me').then(me => {
  if (!me) return;
  const h = document.createElement('h1'); h.textContent = 'Items'; root.appendChild(h);
  me.items.forEach(n => {
    const b = document.createElement('button'); b.id = 'item' + n;
    b.textContent = 'Item ' + n;
    b.addEventListener('click', () => api('/api/items/' + n).then(d => {
      if (!d) return;
      const s = document.createElement('section'); s.id = 'detail' + n;
      const q = document.createElement('button'); q.textContent = 'Close ' + n;
      s.appendChild(q); root.appendChild(s);
    }));
    root.appendChild(b);
  });
});
"""


class _SessionApp:
    """A loopback app with a server-side session. ``GET /login`` serves a login form; a
    ``POST`` with the right credentials issues a fresh ``sid`` and redirects to
    ``/dashboard``. ``/dashboard`` (the board's shell) needs a live ``sid`` (else a 302 to
    ``/login``): it is the session's stable protected resource. ``/api/*`` answers 200
    JSON with a live ``sid``; with a dead one, 401 (``stay``/``redirect``) or 200
    ``{"login": true}`` (``form``). A ``sid`` dies after ``budget`` API answers (every
    sid when ``every``, else the first only). ``gated`` items answer 401 to a live sid
    (this role may not read them: an authorization denial, the session untouched).
    Every request is recorded as ``(method, path, sid)``, in order."""

    def __init__(self, mode: str, budget: int, *, every: bool = False, gated=()):
        self.mode, self.budget, self.every = mode, budget, every
        self.gated = {f"/api/items/{n}" for n in gated}
        self.requests: list[tuple[str, str, str | None]] = []
        self.sids: list[str] = []            # issued, in order
        self.used: dict[str, int] = {}       # API answers per sid
        self.dead: set[str] = set()
        self._lock = threading.Lock()
        require_loopback("127.0.0.1")         # PA-0130: a loopback listener only
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def issue(self) -> str:
        sid = secrets.token_hex(16)
        with self._lock:
            self.sids.append(sid)
            self.used[sid] = 0
        return sid

    def live(self, sid: str | None) -> bool:
        return sid in self.used and sid not in self.dead

    def _spend(self, sid: str | None) -> bool:
        """One API answer on ``sid``: whether it was live for it."""
        with self._lock:
            if not self.live(sid):
                return False
            self.used[sid] += 1
            if self.used[sid] > self.budget and (self.every or sid == self.sids[0]):
                self.dead.add(sid)
                return False
            return True

    def paths(self, sid: str | None = None) -> list[str]:
        return [p for _m, p, s in self.requests if sid is None or s == sid]

    def _handler(self):
        app = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def _sid(self) -> str | None:
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _eq, value = part.strip().partition("=")
                    if name == "sid":
                        return value
                return None

            def _send(self, status: int, body: bytes = b"", ctype: str = "text/html",
                      headers=()) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - the http.server API
                sid = self._sid()
                path = self.path.split("?", 1)[0]
                with app._lock:
                    app.requests.append(("GET", path, sid))
                if path == "/login":
                    return self._send(200, LOGIN)
                if path == "/app.js":
                    return self._send(200, APP_JS.replace("__MODE__", app.mode).encode(),
                                      "application/javascript")
                if path in ("/", "/dashboard"):
                    if app.live(sid):
                        return self._send(200, SHELL)
                    return self._send(302, headers=[("Location", "/login")])
                if path in app.gated and app.live(sid):
                    return self._send(401, b'{"error": "not for this role"}',
                                      "application/json")
                if path.startswith("/api/"):
                    if not app._spend(sid):
                        if app.mode == "form":
                            return self._send(200, b'{"login": true}', "application/json")
                        return self._send(401, b'{"error": "unauthorized"}',
                                          "application/json")
                    if path == "/api/me":
                        return self._send(200, b'{"items": [1, 2, 3, 4]}',
                                          "application/json")
                    return self._send(200, json.dumps({"item": path}).encode(),
                                      "application/json")
                return self._send(404, b"not found", "text/plain")

            def do_POST(self):  # noqa: N802
                sid = self._sid()
                n = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(n).decode("latin-1")))
                with app._lock:
                    app.requests.append(("POST", self.path, sid))
                if self.path == "/login" and form.get("username") == USER and \
                        form.get("password") == PASSWORD:
                    new = app.issue()
                    return self._send(302, headers=[
                        ("Location", "/dashboard"),
                        ("Set-Cookie", f"sid={new}; Path=/; HttpOnly")])
                return self._send(200, LOGIN)
        return H


def _require_real():
    for mod in ("playwright.sync_api", "mitmproxy"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}")


def _manager():
    """A real session manager (the default fetcher: real HTTP) over a fake keyring."""
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.session.manager import SessionManager
    from tests.test_credentials import FakeBackend
    creds = CredentialStore(backend=FakeBackend())
    creds.set("127.0.0.1", "user", USER, PASSWORD)
    return SessionManager(creds, scope_hosts=["127.0.0.1"], browser_login=False)


class _Counting(Explorer):
    """Records how many contexts the worker's browser holds right after each new one."""

    def _new_context(self, browser, pw):
        ctx = super()._new_context(browser, pw)
        self.open_contexts.append(len(browser.contexts))
        return ctx


def _explore(app: _SessionApp, out, *, provider: bool, sid: str | None = None,
             **opts):
    """Explore ``app``'s board through the real capture proxy, as the provider's
    identity (``provider``) or from a storage state holding ``sid``."""
    _require_real()
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco.proxyproc import CaptureProxy
    start = app.base + "dashboard"
    kw: dict = {}
    if provider:
        from fuzzlab.disco.explore import ExploreSession
        kw["session"] = ExploreSession(_manager(), "user", start)
    else:
        kw["storage_state"] = {"cookies": [{
            "name": "sid", "value": sid, "domain": "127.0.0.1", "path": "/",
            "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
            "origins": []}
    options = ExploreOptions(max_actions=opts.pop("max_actions", 12), deadline_s=120,
                             max_states=8, idle_ms=250, max_quiet_ms=4000, **opts)
    with CaptureProxy([app.base], out=out / "capture.jsonl", profile="user") as proxy:
        ex = _Counting(start, scope_urls=[app.base], proxy=proxy.endpoint,
                       options=options, actions_log=out / "actions.jsonl", **kw)
        ex.open_contexts = []
        try:
            report = ex.run()
        except PlaywrightError as exc:
            if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
            raise
    return ex, report


def _records(out):
    from fuzzlab.disco.capture import read_capture
    return read_capture(out / "capture.jsonl").records


def _session_lines(out) -> list[dict]:
    lines = [json.loads(ln) for ln in (out / "actions.jsonl").read_text().splitlines()]
    return [d for d in lines if d.get("kind") == "session"]


@pytest.fixture
def app_factory():
    apps = []

    def make(*a, **k):
        apps.append(_SessionApp(*a, **k))
        return apps[-1]
    yield make
    for app in apps:
        app.close()


# --- real browser ------------------------------------------------------------------------

def test_an_api_401_on_an_unchanged_route_is_confirmed_and_a_fresh_session_installed(
        app_factory, tmp_path):
    """The audit's scenario: the board's session dies while its route stays
    ``/dashboard`` and its APIs answer 401. The 401 is classified (SP-56), the protected
    check (SP-61) confirms the loss for the context's generation, the provider logs in
    again, the fresh session passes its protected check, and exploring goes on in a new
    context -- the dead ``sid`` is never sent again. Every 401 the capture holds is on an
    action id the run marked lost (D')."""
    app = app_factory("stay", budget=3)
    ex, report = _explore(app, tmp_path, provider=True)
    assert report.session_lost == 1 and report.session_recovered == 1, report
    assert report.auth_ended is None
    first, second = app.sids                        # one login, one fresh login
    assert first in app.dead and second not in app.dead
    # the dead sid is never re-installed: from the fresh login on, nothing carries it
    # (the manager's own protected check of the dead one comes before that login)
    fresh = next(i for i, r in enumerate(app.requests) if r[2] == second)
    assert all(s != first for _m, _p, s in app.requests[fresh:]), app.requests[fresh:]
    assert any(p.startswith("/api/items/") for p in app.paths(second))   # it went on
    lost = set(report.session_lost_actions)
    unauthorised = [r for r in _records(tmp_path) if r.status == 401]
    assert unauthorised and all(r.action_id in lost for r in unauthorised), \
        ([r.action_id for r in unauthorised], lost)
    [line] = _session_lines(tmp_path)
    assert line["session"] == "lost" and set(line["action_ids"]) == lost
    assert ex.open_contexts == [1, 1]               # the old context closed first


def test_a_login_form_rendered_in_place_is_a_lost_session(app_factory, tmp_path):
    """The API answers 200 ``{"login": true}`` and the board renders its login form in
    place, at ``/dashboard``: no 401 and no login URL. The form is this session's login
    form (SP-16's `shows_login_form`), the protected check confirms, a fresh session is
    installed and revalidated."""
    app = app_factory("form", budget=3)
    ex, report = _explore(app, tmp_path, provider=True)
    assert report.session_lost == 1 and report.session_recovered == 1, report
    assert report.auth_ended is None and len(app.sids) == 2
    assert any(p.startswith("/api/items/") for p in app.paths(app.sids[1]))
    assert report.session_lost_actions
    assert ex.open_contexts == [1, 1]


def test_repeated_losses_never_leave_an_old_context_open(app_factory, tmp_path):
    """Every session dies after one API answer and the board then goes to ``/login``:
    the run loses its session again and again. Each fresh session is a new login (never
    the old snapshot), each replaced context is closed before its replacement exists,
    and past ``max_session_recoveries`` authenticated exploration ends, saying why."""
    app = app_factory("redirect", budget=1, every=True)
    ex, report = _explore(app, tmp_path, provider=True, max_session_recoveries=2)
    assert report.session_recovered == 2 and report.session_lost == 3, report
    assert report.auth_ended and "after 2 fresh session" in report.auth_ended
    assert len(app.sids) == 3 and len(set(app.sids)) == 3
    assert ex.open_contexts == [1, 1, 1]
    assert len(_session_lines(tmp_path)) == 3


@pytest.mark.parametrize("mode", ["stay", "redirect", "form"])
def test_without_a_provider_a_lost_session_ends_authenticated_exploration(
        app_factory, tmp_path, mode):
    """A storage state and no session provider: nothing can refresh the session. A loss
    shape (a credentialed 401, a login URL, a login form rendered in place at the same
    URL) is an unconfirmed loss (PA-0533(1)); exploration ends with the reason in the
    report, the storage state is never re-installed, and no second context is made."""
    app = app_factory(mode, budget=2)
    sid = app.issue()
    ex, report = _explore(app, tmp_path, provider=False, sid=sid)
    assert ex.open_contexts == [1]                  # the storage state never re-installed
    assert report.session_lost == 1, report
    assert report.auth_ended and "no session provider" in report.auth_ended
    assert report.session_lost_actions
    # nothing was explored on the dead session after the loss was found
    [line] = _session_lines(tmp_path)
    assert line["session"] == "lost"


def test_without_a_provider_a_login_form_rendered_on_a_restore_is_a_lost_session(
        app_factory, tmp_path):
    """Review R1: a storage state, no provider. The sid dies on the root state's restore
    (its second ``/api/me``) and the board renders its login form in place, at
    ``/dashboard``. A password form shown at the restored state's URL by a state found
    without one is in place: a suspicion, which the start page's protected check (R3)
    confirms. The run ends with its reason; nothing is acted on or loaded on the dead
    session."""
    app = app_factory("form", budget=1)
    sid = app.issue()
    ex, report = _explore(app, tmp_path, provider=False, sid=sid)
    assert sid in app.dead
    assert report.session_lost == 1 and report.actions == 0, report
    assert report.harvest_loads == 0
    assert report.auth_ended and "no session provider" in report.auth_ended
    [line] = _session_lines(tmp_path)
    assert line["session"] == "lost" and line["action_ids"]
    assert ex.open_contexts == [1]


def test_without_a_provider_a_login_form_at_the_seed_ends_before_anything_is_explored(
        app_factory, tmp_path):
    """Review R1: the sid dies on the start page's own ``/api/me`` and the board renders
    its login form there. The run's first look is in place: an unconfirmed loss (the
    start page cannot be the protected resource of a session already lost), and nothing
    is explored as the identity."""
    app = app_factory("form", budget=0)
    sid = app.issue()
    ex, report = _explore(app, tmp_path, provider=False, sid=sid)
    assert sid in app.dead
    assert report.session_lost == 1 and report.states == 0 and report.actions == 0, report
    assert report.auth_ended and "no session provider" in report.auth_ended
    assert ex.open_contexts == [1]


def test_without_a_provider_a_role_gated_401_on_a_live_session_is_a_denial(
        app_factory, tmp_path):
    """Review R3: a storage state, no provider, a session that stays live; item 2
    answers 401 to this role. The start page is the run's protected resource (SP-61's
    `health_verdict` reads it live with the context's cookies and refused without
    them); the 401 is checked against it, found live, counted an authorization denial,
    and exploring goes on. Measured here too: the checks reach the app straight (one
    with no session at all), never through the capture proxy."""
    app = app_factory("stay", budget=1000, gated=[2])
    sid = app.issue()
    ex, report = _explore(app, tmp_path, provider=False, sid=sid, max_same_signature=4)
    assert report.session_lost == 0 and report.auth_ended is None, report
    assert report.authorization_denials >= 1 and not report.session_lost_actions
    paths = app.paths(sid)
    denied = paths.index("/api/items/2")
    assert {"/api/items/3", "/api/items/4"} & set(paths[denied:]), paths
    assert not _session_lines(tmp_path) and ex.open_contexts == [1]
    assert ("GET", "/dashboard", None) in app.requests          # the uncredentialed check
    shown = [r for r in _records(tmp_path)
             if r.method == "GET" and r.url.endswith("/dashboard")]
    assert shown and all(r.action_id for r in shown)             # only the browser's own
    assert len([r for r in app.requests if r[1] == "/dashboard"]) > len(shown)


def test_a_401_whose_script_drops_the_session_and_goes_to_login_reinstalls_it(
        app_factory, tmp_path):
    """Review R2: a provider run; item 2 answers 401 to this role on a live session, and
    the board's 401 handler deletes its session cookie and goes to ``/login``. The
    action's window holds both the 401 and the login page: the provider's check finds
    the session live, so the context lost its copy -- it is given the live session again
    (no new login), and exploring goes on with it."""
    app = app_factory("clear", budget=1000, gated=[2])
    ex, report = _explore(app, tmp_path, provider=True, max_same_signature=4)
    assert report.session_reinstalled == 1 and report.session_lost == 0, report
    assert report.auth_ended is None and len(app.sids) == 1     # never logged in again
    paths = app.paths(app.sids[0])
    denied = paths.index("/api/items/2")
    assert {"/api/items/3", "/api/items/4"} & set(paths[denied:]), paths
    [line] = _session_lines(tmp_path)
    assert line["session"] == "reinstall" and line["action_ids"]
    assert ex.open_contexts == [1, 1]


# --- offline: the classification, with fakes ----------------------------------------------

class _Resp:
    def __init__(self, status, url, headers=None):
        self.status, self.url, self.headers = status, url, dict(headers or {})


class _Req:
    def __init__(self, method, url, status, headers=None, body=None, ctype=None):
        self.method, self.url = method, url
        self.post_data_buffer = body
        self.headers = {"content-type": ctype} if ctype else {}
        self._resp = _Resp(status, url, headers)

    def response(self):
        return self._resp


class _Page:
    def __init__(self, url, html="<p>board</p>"):
        self.url, self._html = url, html

    def content(self):
        return self._html

    def is_closed(self):
        return False


class _Manager:
    """Answers `check_health` with the states it is given, recording each call."""

    def __init__(self, *states):
        self.states = list(states)
        self.calls: list[dict] = []

    def check_health(self, host, identity, base_url=None, **kw):
        from fuzzlab.session.manager import Health
        self.calls.append(kw)
        return Health(self.states.pop(0), "", kw.get("generation")), False


START = "http://127.0.0.1:3000/dashboard"


def _material(generation):
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    from fuzzlab.disco.explore import _SessionMaterial
    origins = origin_scope(START)
    return _SessionMaterial(
        generation, scope=lambda u: in_origin_scope(u, origins),
        login_url="http://127.0.0.1:3000/login", login_fields=("password", "username"))


def _offline(manager=None):
    from fuzzlab.disco.explore import ExploreSession
    kw = {"session": ExploreSession(manager, "user", START)} if manager else \
        {"storage_state": {"cookies": [], "origins": []}}
    ex = Explorer(START, scope_urls=[START], proxy="127.0.0.1:9", **kw)
    ex._shared.auth = _material(7)
    ex._ctx_generation = 7
    ex.recovered = []
    ex._recover_session = lambda page, verdict, reason: ex.recovered.append(verdict) or page
    return ex


def test_a_policy_block_on_a_live_session_is_an_authorization_denial():
    """A 403 is no loss shape: with a provider the protected check decides (``policy``
    set, so a live verdict covers any URL within its window); live, it is an
    authorization denial and nothing is replaced. Without a provider it is never a
    loss."""
    manager = _Manager("live")
    ex = _offline(manager)
    ex._answers = [_Req("GET", "http://127.0.0.1:3000/api/admin", 403)]
    _page, outcome = ex._session_checkpoint(_Page(START))
    assert outcome is None and ex.recovered == []
    assert manager.calls[0]["policy"] is True and manager.calls[0]["generation"] == 7
    assert ex.report.authorization_denials == 1 and ex.report.session_lost == 0
    ex = _offline()
    ex._answers = [_Req("GET", "http://127.0.0.1:3000/api/admin", 403)]
    assert ex._session_checkpoint(_Page(START))[1] is None and ex.recovered == []


@pytest.mark.parametrize("req", [
    # a credential submission's own refusal is its endpoint's answer (FR-SESS-22)
    _Req("POST", "http://127.0.0.1:3000/login", 401, body=b"username=a&password=b",
         ctype="application/x-www-form-urlencoded"),
    # an intermediary's demand is no answer about this session (as detect_logout reads it)
    _Req("GET", "http://127.0.0.1:3000/api/me", 407),
    # another origin than the session's: not credentialed
    _Req("GET", "http://127.0.0.1:4000/api/me", 401),
    # a throttle or a gateway proves nothing (SP-56)
    _Req("GET", "http://127.0.0.1:3000/api/me", 429),
    _Req("GET", "http://127.0.0.1:3000/api/me", 502),
], ids=["credential-submission", "407", "other-origin", "throttle", "gateway"])
def test_an_answer_that_is_not_this_sessions_refusal_is_never_a_suspicion(req):
    manager = _Manager()
    ex = _offline(manager)
    ex._answers = [req]
    assert ex._session_checkpoint(_Page(START))[1] is None
    assert manager.calls == [] and ex.report.session_suspected == 0


def test_a_credentialed_401_is_checked_for_the_contexts_generation():
    """A loss shape is a suspicion the protected check decides (PA-0533(1)); lost, the
    window's action ids are marked and the session is recovered; live, the 401 was the
    endpoint's own answer."""
    manager = _Manager("lost")
    ex = _offline(manager)
    ex._window_tags = {"act-3", "restore-2"}
    ex._answers = [_Req("GET", "http://127.0.0.1:3000/api/items/3", 401)]
    _page, outcome = ex._session_checkpoint(_Page(START))
    assert outcome[0] == "lost" and ex.recovered == ["lost"]
    assert manager.calls[0]["generation"] == 7 and manager.calls[0]["policy"] is False
    assert ex.report.session_lost_actions == ["act-3", "restore-2"]
    manager = _Manager("live")
    ex = _offline(manager)
    ex._answers = [_Req("GET", "http://127.0.0.1:3000/api/items/3", 401)]
    assert ex._session_checkpoint(_Page(START))[1] is None and ex.recovered == []


def test_a_login_page_after_a_401_on_a_live_session_reinstalls_it():
    """Review R2: the provider's check finds the session live, but the action's window
    holds both a 401 and the page at ``/login`` (an app whose 401 handler drops its
    session and goes to its login page): the context lost its copy -- ``reinstall``,
    whichever sign came first. One check; no authorization denial counted."""
    manager = _Manager("live")
    ex = _offline(manager)
    ex._answers = [_Req("GET", "http://127.0.0.1:3000/api/admin", 401)]
    _page, outcome = ex._session_checkpoint(
        _Page("http://127.0.0.1:3000/login", LOGIN.decode()), before_url=START, action=True)
    assert outcome is not None and outcome[0] == "reinstall", outcome
    assert ex.recovered == ["reinstall"] and len(manager.calls) == 1
    assert ex.report.authorization_denials == 0


# --- offline: two workers and one generation (review B1) ----------------------------------

class _StepPage(_Page):
    """A page whose state (``fp``) the fake restore and acts set."""

    def __init__(self, url, html="<p>board</p>"):
        super().__init__(url, html)
        self.fp = "fp0"


class _Ctx:
    def new_page(self):
        return _StepPage(START)


def _stepper(ex, acts: list, on_act):
    """Drive ``ex``'s real `_process` over fakes: a board at START with three buttons.
    Each act sends one request (its action id in the window, an anonymous-looking 200
    answer: no sign), records ``(action id, the generation its context carries)`` in
    ``acts`` and calls ``on_act(n)``; the page then shows state ``fp<n>``. A replaced
    context carries the run's current generation."""
    from fuzzlab.disco.explore import ACTED, Reading
    from fuzzlab.disco.fingerprint import element_multiset
    els = [{"signature": f"button|id=b{n}", "occurrence": 0, "tag": "button",
            "type": "submit", "label": f"Item {n}", "in_form": False} for n in (1, 2, 3)]
    ex._ctx = _Ctx()
    ex._restore_any = lambda page, ctx, state: setattr(page, "fp", "fp0") or True
    # a reading of the merged explorer (BUG-0539's execution key is the page's ``fp``)
    ex.settled_fingerprint = lambda page, ctx: Reading(
        page.fp, "layout", page.url, els, element_multiset(els), ())
    ex.wait_quiet = lambda page: True
    ex._close_popups = lambda ctx, page: None
    ex._gather = lambda page: None
    ex._shared.started = ex.clock()

    def act(page, ctx, el, step):
        n = len(acts) + 1
        tag = ex._tag(ctx, "act")
        ex._window_tags.add(tag)
        ex._answers.append(_Req("GET", "http://127.0.0.1:3000/api/me", 200))
        acts.append((tag, ex._ctx_generation))
        on_act(n)
        page.fp = f"fp{n}"
        return ACTED

    def replace(page, *_verdict):
        ex._window_tags, ex._answers = set(), []
        ex._ctx_generation = ex._shared.auth.generation
        return _StepPage(START)
    ex.act, ex._replace_context = act, replace


def _action_lines(path) -> list[dict]:
    lines = [json.loads(ln) for ln in path.read_text().splitlines()]
    return [d for d in lines if "seq" in d]


def test_a_loss_another_worker_finds_mid_action_is_never_this_workers_coverage(tmp_path):
    """Review B1, the CLI's own path (a storage state, two workers): worker A's 401 is an
    unconfirmed loss and ends the run's authenticated exploration while worker B's action
    is in flight. B's answers show no sign (an anonymous 200), but they went out on the
    generation A found lost: B's window is marked, its action logged with no new state
    and no URL, nothing it showed becomes a state, and B acts no more."""
    from fuzzlab.disco.explore import State
    a = _offline()
    del a._recover_session                     # the real one: no provider, the run ends
    a.actions_log = tmp_path / "actions.jsonl"
    b = a._clone()
    b._ctx_generation = 7
    acts: list = []

    def a_loses(n):
        if n == 1:
            a._window_tags = {"act-0"}
            a._answers = [_Req("GET", "http://127.0.0.1:3000/api/items/1", 401)]
            assert a._session_checkpoint(_Page(START))[1][0] == "lost"
    _stepper(b, acts, a_loses)
    b._shared.known.add("fp0")
    b._process(State("fp0", START, START), _StepPage(START), None, None)
    assert [gen for _tag, gen in acts] == [7]
    assert b._shared.stop == "session-lost" and b.report.auth_ended
    assert acts[0][0] in b.report.session_lost_actions, b.report.session_lost_actions
    [mine] = [d for d in _action_lines(tmp_path / "actions.jsonl")
              if d["action_id"] == acts[0][0]]
    assert mine["new_state"] is None and mine["url"] is None
    assert b._shared.known == {"fp0"}


def test_no_worker_acts_on_a_generation_another_worker_found_lost(tmp_path):
    """Review B1 with a provider: worker A confirms that generation 7 is lost while
    worker B's action is in flight, and A's recovery has not installed anything yet
    (stubbed: in progress). B's answers show no sign, but its window is marked (stale)
    and B acts again only on a newer generation -- here 8, the fresh session its own
    single-flight recovery took -- never on 7. A's check is the only one."""
    from fuzzlab.disco.explore import State
    manager = _Manager("lost")
    a = _offline(manager)                     # A's recovery: in progress (stubbed)
    a.actions_log = tmp_path / "actions.jsonl"
    b = a._clone()
    del b._recover_session                    # B's: the real one
    b._ctx_generation = 7
    b._provider_session = lambda **_kw: _material(8)
    acts: list = []

    def a_loses(n):
        if n == 1:
            a._answers = [_Req("GET", "http://127.0.0.1:3000/api/items/1", 401)]
            a._session_checkpoint(_Page(START))
    _stepper(b, acts, a_loses)
    b._shared.known.add("fp0")
    b._process(State("fp0", START, START), _StepPage(START), None, None)
    assert [gen for _tag, gen in acts] == [7, 8, 8], acts
    assert a.recovered == ["lost"] and len(manager.calls) == 1
    assert acts[0][0] in b.report.session_lost_actions


def test_a_newer_session_never_drops_a_pending_window_unmarked(tmp_path):
    """Review B1: another worker installed generation 8 while this worker's context (7)
    had sent ``act-5`` since its last checkpoint. Before its context is replaced,
    ``act-5`` is marked (stale): what went out on the old generation is never coverage."""
    ex = _offline()
    del ex._recover_session
    ex.actions_log = tmp_path / "actions.jsonl"
    replaced = []
    ex._replace_context = lambda page, *a: replaced.append(a) or page
    ex._shared.auth = _material(8)
    ex._window_tags = {"act-5"}
    ex._session_current(_Page(START))
    assert ex.report.session_lost_actions == ["act-5"] and len(replaced) == 1
    [line] = _session_lines(tmp_path)
    assert line["session"] == "stale" and line["action_ids"] == ["act-5"]


# --- a consumer that does not read the mark yet (PA-0533(5), PA-0531(4)) -----------------

@pytest.mark.xfail(strict=True, reason=(
    "owner: disco.synth / `fuzzlab disco synth` (CRAWL, FR-CRAWL-20): the inventory "
    "does not read FR-CRAWL-41's lost-window mark (actions.jsonl's `session` lines, "
    "explore.json's `session_lost_actions`), so an answer on a session known lost is "
    "taken as the endpoint's answer under the run's profile (D'); BUG-0552 residual"))
def test_an_answer_in_a_lost_window_is_never_in_the_inventory(tmp_path):
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.disco.cli import main
    run = tmp_path / "run"
    run.mkdir()
    for action, status in (("act-1", 200), ("act-2", 401)):
        append_record(run / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id=action, method="GET",
            url="http://127.0.0.1:3000/api/items/1", req_headers={}, req_body=None,
            status=status, res_headers={"content-type": "application/json"},
            res_body=b'{"item": 1}', latency_ms=1, profile="user"))
    (run / "actions.jsonl").write_text(json.dumps(
        {"kind": "session", "session": "lost", "reason": "an auth failure (401)",
         "generation": 1, "action_ids": ["act-2"]}) + "\n")
    out = tmp_path / "inv.json"
    assert main(["synth", "--capture", str(run / "capture.jsonl"), "--out", str(out)]) == 0
    ops = [op for item in json.loads(out.read_text())["paths"].values()
           for op in item.values()]
    assert ops and all("401" not in op.get("responses", {}) for op in ops)


BASE = "http://127.0.0.1:3000/"


def _lost_window_run(tmp_path):
    """A run directory whose capture holds the identity's answers (``act-1``) and, in a
    known-lost window (``act-2``, marked by a ``session`` line), an anonymous view of the
    same API, a login shell and an id-shaped API GET."""
    from fuzzlab.disco.capture import append_record, make_record
    run = tmp_path / "run"
    run.mkdir()
    for action, path, ctype, body in (
            ("act-1", "dashboard", "text/html", b"<p>board</p>"),
            ("act-1", "api/me", "application/json", b'{"items": [1, 2]}'),
            ("act-2", "api/me", "application/json", b'{"login": true}'),
            ("act-2", "settings", "text/html", LOGIN),
            ("act-2", "api/items/9", "application/json", b'{"item": 9}')):
        append_record(run / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id=action, method="GET", url=BASE + path,
            req_headers={}, req_body=None, status=200,
            res_headers={"content-type": ctype}, res_body=body, latency_ms=1,
            profile="user"))
    (run / "actions.jsonl").write_text(json.dumps(
        {"kind": "session", "session": "lost", "reason": "an auth failure (401)",
         "generation": 1, "action_ids": ["act-2"]}) + "\n")
    return run


def test_ede_never_replays_or_tests_an_answer_from_a_lost_window(tmp_path, capsys):
    """Review B2: `fuzzlab disco ede` served the last 2xx JSON answer per URL -- the
    known-lost window's ``{"login": true}`` over the identity's -- and tested the login
    shell as a page of the run. It reads the mark (`capture.lost_action_ids`, SP-71):
    the identity's answer is the one served, and the lost window's document is no page."""
    from fuzzlab.disco import cli, ede
    from fuzzlab.disco.capture import lost_action_ids, read_capture
    run = _lost_window_run(tmp_path)
    lost = lost_action_ids(run)
    assert lost == {"act-2"}
    runner = ede.EdeRunner(read_capture(run / "capture.jsonl").records,
                           scope_urls=[BASE], lost_actions=lost)
    assert runner.replay[ede.replay_key("GET", BASE + "api/me")].action_id == "act-1"
    assert ede.replay_key("GET", BASE + "api/items/9") not in runner.replay
    assert runner.pages == [BASE + "dashboard"]
    assert cli.main(["ede", "--run", str(run), "--scope", BASE, "--dry-run"]) == 0
    assert "pages: 1  replayable answers: 1" in capsys.readouterr().out


@pytest.mark.xfail(strict=True, reason=(
    "owner: tools/store_adapter.import_disco (AUD, FR-AUD-23; `fuzzlab auto`'s "
    "import): it takes a known-lost window's answer as evidence -- its status as the "
    "page's (a 2xx page row: header injection points), its 2xx as path-template "
    "evidence, its HTML media type as a page -- and does not read FR-CRAWL-41's mark "
    "(`disco.capture.lost_action_ids`); BUG-0552 review B2 residual (a CC-AUD entry)"))
def test_import_disco_never_takes_a_lost_windows_answer_as_evidence(tmp_path):
    from fuzzlab.core.store import Store
    from fuzzlab.tools.store_adapter import import_disco
    run = _lost_window_run(tmp_path)
    store = Store(tmp_path / "store.db")
    run_id = store.start_run("auto", "x")
    import_disco(run, store, run_id, base_url=BASE)
    pages = {tuple(r) for r in store.conn.execute(
        "SELECT url, status FROM page WHERE run_id = ?", (run_id,)).fetchall()}
    templates = [tuple(r) for r in store.conn.execute(
        "SELECT name FROM parameter WHERE run_id = ? AND location = 'path'",
        (run_id,)).fetchall()]
    assert ("/settings", 200) not in pages and templates == [], (pages, templates)


def test_the_execution_keys_generation_is_the_session_each_worker_carries(monkeypatch):
    """Merge integration of AU-DISCO and DISCO4 (crawl batch): the execution key's
    session-generation slot (FR-CRAWL-31) is the run-wide generation of the session a
    worker's context carries (FR-CRAWL-41), never a per-worker count of its context
    rebuilds. A reinstall of the same session keeps its states one state space; a worker
    that adopts the fresh session another worker recovered reads the live session's
    states under that session's generation, never under a key recorded on the lost
    one (which would pass as known and leave the live session's states unexplored)."""
    from fuzzlab.disco import explore as E

    class _Ctx:
        def close(self):
            pass

        def new_page(self):
            return object()

    a = E.Explorer("http://127.0.0.1:1/", scope_urls=["http://127.0.0.1:1/"],
                   proxy="http://127.0.0.1:2", options=E.ExploreOptions(workers=2))
    b = a._clone()
    shared = a._shared
    shared.auth = E._SessionMaterial(generation=1)

    def contexts(ex):
        def make(browser, pw):
            ex._ctx_generation = shared.auth.generation
            return _Ctx()
        return make
    for ex in (a, b):
        monkeypatch.setattr(ex, "_new_context", contexts(ex))
        monkeypatch.setattr(ex, "_mark_window", lambda *args, **kw: [])
        ex._ctx = ex._new_context(None, None)
    monkeypatch.setattr(E.navguard, "release", lambda ctx: None)
    url = "http://127.0.0.1:1/home"
    els = [{"tag": "button", "how": "native", "signature": "button", "occurrence": 0}]

    def key(ex):
        return ex.reading(url, els).key
    first = key(a)
    assert key(b) == first
    a._replace_context(None, "reinstall", "the same session re-given")
    assert key(a) == key(b) == first                 # one session, one state space
    shared.auth = E._SessionMaterial(generation=2)  # A found a loss and recovered
    a._replace_context(None, "lost", "a confirmed loss")
    b._replace_context(None, "stale", "another worker's loss")   # B adopts it
    assert key(a) == key(b) != first                 # the live session's own states
