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
#: ``/api/items/<n>`` and opens its panel. What it does when its session is gone is the
#: app's ``mode``: ``stay`` shows an error line and keeps its route (``/dashboard``),
#: ``form`` renders a login form in place (the API answers 200 ``{"login": true}``),
#: ``redirect`` goes to ``/login``.
APP_JS = r"""
const root = document.getElementById('root');
const MODE = '__MODE__';
function lost() {
  if (MODE === 'redirect') { location.href = '/login'; return; }
  if (MODE === 'form') {
    root.innerHTML = '<form method=post action="/login"><input name=username>'
      + '<input type=password name=password><button>Sign in</button></form>';
    return;
  }
  const p = document.createElement('p'); p.className = 'error';
  p.textContent = 'Something went wrong'; root.appendChild(p);
}
function api(url) {
  return fetch(url).then(r => { if (r.status === 401) { lost(); return null; }
                                return r.json(); })
    .then(d => { if (d && d.login) { lost(); return null; } return d; });
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
    sid when ``every``, else the first only). Every request is recorded as ``(method,
    path, sid)``, in order."""

    def __init__(self, mode: str, budget: int, *, every: bool = False):
        self.mode, self.budget, self.every = mode, budget, every
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


def _offline(manager=None):
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    from fuzzlab.disco.explore import ExploreSession, _SessionMaterial
    kw = {"session": ExploreSession(manager, "user", START)} if manager else \
        {"storage_state": {"cookies": [], "origins": []}}
    ex = Explorer(START, scope_urls=[START], proxy="127.0.0.1:9", **kw)
    origins = origin_scope(START)
    ex._shared.auth = _SessionMaterial(
        7, scope=lambda u: in_origin_scope(u, origins),
        login_url="http://127.0.0.1:3000/login", login_fields=("password", "username"))
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
