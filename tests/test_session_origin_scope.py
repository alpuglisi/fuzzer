"""BUG-0134 / FR-SESS-20: a session is sent only to its own origins.

`SessionManager` keyed a session by ``(host, identity)`` and applied it to every
in-scope request whose **hostname** matched, so on a loopback lab Juice Shop's cookie
and bearer (``:3000``) reached bWAPP (``:8090``) or any other service on another port
of ``127.0.0.1``; a request there before any session existed could even log in there
with this host's credential. Now (Revision 2 of the design, O1-O13):

* ``SessionState.origins`` (O1) holds the canonical origins of the base URL the login
  ran from, the login page, the credential destination and the operator's
  ``auth_origins`` -- in memory only;
* ``prepare`` (O2) applies the session only on those origins; another origin goes out
  anonymously, never logs in there, is counted and its probe says so;
* ``ensure`` (O3), ``authorize`` / ``observe`` (O4), ``verify_live`` and the probe
  differential (O5), greybox (O6), proxy capture (O7), the browser route (O8), the
  logout listeners and auth endpoints (O9), ``session_header(s)`` (O10), isolated
  copies (O11) and the advice (O12, O13) all key on origins.

Where a test says "B receives nothing", B is a real loopback server on another port
(or, for the external crawl, on another port of ``127.0.0.2``) that records every
request it gets.
"""

from __future__ import annotations

import ast
import glob
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import HttpClient, Request
from fuzzlab.core.net import require_loopback
from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.oracle.probe import Probe
from fuzzlab.session.manager import (OUT_OF_ORIGIN, FetchResponse, SessionAuthError,
                                     SessionManager)
from fuzzlab.session.state import SessionState
from tests.test_credentials import FakeBackend

USER, PASSWORD = "alice", "PW-origin-7f3a9c"
LOGIN_FORM = ("<html><body><form method='post' action='/login'>"
              "<input name='user'><input type='password' name='pw'>"
              "<input type='submit' value='Sign in'></form></body></html>")


# --- real loopback apps -------------------------------------------------------------
class _App:
    """A loopback app on its own port. ``/login`` serves a login form; a POST with the
    right credentials sets a fresh ``sid`` cookie. ``/`` is the home page (logged in
    with a live ``sid``), ``/api/me`` answers 200 with a live ``sid`` else 401,
    ``/login.php`` is a login page. ``redirects`` maps a path to a ``Location``. Every
    request is recorded as ``(method, path, Cookie, Authorization)``."""

    def __init__(self, host: str = "127.0.0.1", links: str = "", basic: bool = False):
        self.host = host
        self.links = links
        #: path -> (status, body, extra headers): served as is (R1/R2 fixtures)
        self.pages: dict[str, tuple[int, bytes, list]] = {}
        #: HTTP Basic: every GET without the right Authorization answers 401 (R3)
        self.basic = basic
        self.requests: list[tuple[str, str, str | None, str | None]] = []
        self.sessions: set[str] = set()
        self.redirects: dict[str, str] = {}
        self.login_posts = 0
        self._lock = threading.Lock()
        self.server = self._serve(host)
        self.port = self.server.server_address[1]
        self.base = f"http://{host}:{self.port}/"

    def _serve(self, host: str) -> ThreadingHTTPServer:
        require_loopback(host)                    # PA-0130: a loopback listener only
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self, method):
                with app._lock:
                    app.requests.append((method, self.path, self.headers.get("Cookie"),
                                         self.headers.get("Authorization")))

            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and value in app.sessions:
                        return value
                return None

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                self._record("GET")
                path = self.path.split("?", 1)[0]
                if app.basic:
                    import base64
                    good = "Basic " + base64.b64encode(
                        f"{USER}:{PASSWORD}".encode()).decode()
                    if self.headers.get("Authorization") != good:
                        return self._send(401, b"auth", [("WWW-Authenticate",
                                                          'Basic realm="lab"')])
                if path in app.pages:
                    status, body, extra = app.pages[path]
                    return self._send(status, body, extra)
                if path in app.redirects:
                    return self._send(302, headers=[("Location", app.redirects[path])])
                if path in ("/login", "/login.php"):
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/api/me":
                    return self._send(200, b'{"me":"alice"}') if self._sid() \
                        else self._send(401, b'{"error":"no"}')
                body = (f"<html><body><p>{'welcome alice' if self._sid() else 'home'}"
                        f"</p>{app.links}<a href='/inner'>inner</a></body></html>")
                return self._send(200, body.encode())

            def do_POST(self):  # noqa: N802 - http.server API
                self._record("POST")
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                if self.path == "/login":
                    with app._lock:
                        app.login_posts += 1
                    if form.get("user") == USER and form.get("pw") == PASSWORD:
                        sid = f"sid-{app.port}-{len(app.sessions)}-0123456789abcdef"
                        app.sessions.add(sid)
                        return self._send(200, b"<html><p>welcome alice</p></html>",
                                          [("Set-Cookie", f"sid={sid}; Path=/")])
                    return self._send(200, LOGIN_FORM.encode())
                return self._send(200, b"ok")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer((host, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def got_session(self) -> bool:
        """Did any request carry a cookie value or an Authorization header?"""
        return any((cookie or "").strip() or auth
                   for _m, _p, cookie, auth in self.requests)


@pytest.fixture
def apps():
    a, b = _App(), _App()
    try:
        yield a, b
    finally:
        a.close()
        b.close()


def _creds(host: str = "127.0.0.1") -> CredentialStore:
    store = CredentialStore(backend=FakeBackend())
    store.set(host, "user", USER, PASSWORD)
    return store


def _mgr(host: str = "127.0.0.1", **kw) -> SessionManager:
    """A real manager: the default requests fetcher (real HTTP), no browser login."""
    return SessionManager(_creds(host), scope_hosts=[host], browser_login=False, **kw)


def _client(mgr, hosts=("127.0.0.1",), **kw) -> HttpClient:
    return HttpClient(RequestBudget(200), list(hosts), session=mgr, **kw)


def _get(client, url, identity="user"):
    return client.send(Request("GET", url, identity=identity))


# --- O1: the session's origins --------------------------------------------------------
def test_a_login_records_the_sessions_origins_in_memory_only(apps, tmp_path):
    from fuzzlab.core.store import Store
    a, _b = apps
    with Store(tmp_path / "u.db") as store:
        mgr = _mgr(store=store)
        state = mgr.ensure("127.0.0.1", "user", a.base, operator=True)
        assert state.origins == origin_scope(a.base)
        row = store.get_session_state("127.0.0.1", "user")
    assert row is not None and "origins" not in row          # A4: in memory only
    assert state.redacted()["origins"] == sorted(origin_scope(a.base))


def test_a_resumed_record_never_applies_a_session_by_itself(apps, tmp_path):
    """A4: origins are not persisted, and neither are secrets, so a manager resuming a
    persisted record holds no session: it must log in again, and with no credential it
    sends nothing."""
    from fuzzlab.core.credentials import CredentialError
    from fuzzlab.core.store import Store
    a, _b = apps
    with Store(tmp_path / "u.db") as store:
        _mgr(store=store).ensure("127.0.0.1", "user", a.base, operator=True)
        resumed = SessionManager(CredentialStore(backend=FakeBackend()),
                                 scope_hosts=["127.0.0.1"], store=store,
                                 browser_login=False)
        assert resumed.persisted_state("127.0.0.1", "user")["valid"]
        assert resumed._state == {}
        req = Request("GET", a.base + "inner", identity="user")
        with pytest.raises(CredentialError):
            resumed.prepare(req, "user")
    assert "Cookie" not in req.headers and "Authorization" not in req.headers


# --- O2: prepare ----------------------------------------------------------------------
def test_a_send_to_another_port_carries_no_session_and_never_logs_in_there(apps):
    """The repro: one host, two apps. A's session never reaches B, and B's login form
    never receives the credential, though B would accept it."""
    a, b = apps
    mgr = _mgr()
    client = _client(mgr)
    _get(client, a.base + "inner")                     # logs in on A (no operator base)
    _get(client, b.base + "page")
    _get(client, b.base + "login")
    assert a.got_session() and a.login_posts == 1
    assert b.requests and not b.got_session()          # B received no session
    assert b.login_posts == 0 and ("POST", "/login", None, None) not in b.requests
    assert mgr.out_of_origin_sends == 2


def test_prepare_records_its_decision_on_the_request(apps):
    """R6: the decision is recorded on the request prepare was given, never recomputed
    after the send."""
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    out = Request("GET", b.base + "x", identity="user")
    mgr.prepare(out, "user")
    inside = Request("GET", a.base + "x", identity="user")
    mgr.prepare(inside, "user")
    assert out.session_decision == OUT_OF_ORIGIN           # the declared field (T4)
    assert inside.session_decision is None
    assert Request("GET", a.base).session_decision is None  # its default


def test_an_operator_base_logs_in_on_its_own_origin_never_on_the_requests(apps):
    """O3 through prepare: with the operator's base on A, a first request to B logs in
    on A (the operator's base) and B gets nothing; B is never a login base."""
    a, b = apps
    mgr = _mgr()
    mgr._bases[("127.0.0.1", "user")] = a.base           # as ensure(operator=True) would
    client = _client(mgr)
    _get(client, b.base + "x")
    assert a.login_posts == 1 and b.login_posts == 0
    assert [r[1] for r in b.requests] == ["/x"] and not b.got_session()


def test_every_session_header_is_withheld_on_another_origin():
    """A bearer and a cookie together: nothing of either on another port (and the
    loopback alias of the session's own origin gets both)."""
    mgr = SessionManager(None, scope_hosts=["127.0.0.1", "localhost"])
    mgr._state[("127.0.0.1", "user")] = SessionState(
        "127.0.0.1", "user", kind="bearer", cookies={"token": "T0KEN-value-123456"},
        headers={"Authorization": "Bearer T0KEN-value-123456"}, valid=True,
        login_url="http://127.0.0.1:3000/rest/user/login",
        origins=origin_scope("http://127.0.0.1:3000/"))
    other = Request("GET", "http://127.0.0.1:8090/x", identity="user")
    mgr.prepare(other, "user")
    assert other.headers == {}
    alias = Request("GET", "http://localhost:3000/x", identity="user")
    mgr.prepare(alias, "user")
    assert alias.headers["Authorization"].startswith("Bearer ") and \
        "token=" in alias.headers["Cookie"]


def test_loopback_aliases_are_one_origin_and_get_the_session(apps):
    a, _b = apps
    mgr = _mgr(host="127.0.0.1")
    mgr._scope.add("localhost")
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    client = _client(mgr, hosts=("127.0.0.1", "localhost"))
    _get(client, f"http://localhost:{a.port}/inner")
    assert a.requests[-1][1] == "/inner" and "sid=" in (a.requests[-1][2] or "")
    assert mgr.out_of_origin_sends == 0


def test_an_auth_origin_is_one_of_the_sessions_origins(apps):
    """An SSO on another port that the operator authorised is one of the origins."""
    a, b = apps
    mgr = _mgr(auth_origins=[b.base])
    state = mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    assert state.origins == origin_scope(a.base, b.base)
    _get(_client(mgr), b.base + "sso")
    assert b.got_session()


def test_the_seam_sender_marks_an_out_of_origin_probe_and_counts_it(apps):
    """O2: the probe sent without the session says so, and the run counts it."""
    from fuzzlab.tools.probesender import SeamProbeSender
    a, b = apps
    mgr = _mgr()
    sender = SeamProbeSender(_client(mgr), "user", manager=mgr, base_url=a.base)
    inside = sender.send(a.base + "q", "q", "1")
    outside = sender.send(b.base + "q", "q", "1")
    assert inside.session is None and outside.session == OUT_OF_ORIGIN
    assert sender.session_out_of_origin == 1 and not b.got_session()


def test_the_oracle_stamps_the_out_of_origin_note_on_the_verdict():
    """B3: a verdict whose probes went without the session carries
    ``evidence["session"]``; one whose probes did not, does not."""
    from fuzzlab.oracle.oracle import Oracle
    from fuzzlab.oracle.probe import Candidate, Verdict

    class OneProbe:
        arm = "one"
        prg = False

        def applies(self, candidate):
            return True

        def confirm(self, candidate, sender):
            sender.send(candidate.url, candidate.param, "x")
            return Verdict(True, "xss", "one", {"why": "test"})

    class Sender:
        def __init__(self, note):
            self.note = note

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            return Probe(200, "ok", session=self.note)
    cand = Candidate(url="http://127.0.0.1:8090/x", param="q")
    stamped = Oracle(strategies=[OneProbe()]).confirm(cand, Sender(OUT_OF_ORIGIN))
    assert stamped.evidence == {"why": "test", "session": OUT_OF_ORIGIN}
    plain = Oracle(strategies=[OneProbe()]).confirm(cand, Sender(None))
    assert plain.evidence == {"why": "test"}


def test_the_auto_run_reports_the_out_of_origin_count(tmp_path):
    """A-N1: the auto summary's metric."""
    from fuzzlab.harness.auto import run_auto
    from tests.test_forms_phase2 import _import

    class Sender:
        session_out_of_origin = 3

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            return Probe(200, "<html>ok</html>")
    store, run, _counts = _import(tmp_path, pages=["http://localhost/a.php?id=1"])
    with store:
        result = run_auto(base_url="http://localhost/", store=store, run_id=run,
                          sender=Sender(), mode="manual", selected_categories=["xss"],
                          points_source="crawl")
    assert result.metrics["session_out_of_origin"] == 3


# --- O3: ensure -----------------------------------------------------------------------
def test_an_operator_base_on_another_port_is_refused_with_the_remedy(apps):
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    with pytest.raises(SessionAuthError, match="distinct identity name per app"):
        mgr.ensure("127.0.0.1", "user", b.base, operator=True)
    with pytest.raises(SessionAuthError, match="another port of the same host"):
        mgr.ensure("127.0.0.1", "user", b.base + "app/")           # a derived base too
    assert b.requests == [] and a.login_posts == 1


def test_a_relogin_after_a_logout_never_starts_from_another_origin(apps):
    """The session is logged out; the next request is to B: it goes anonymously and no
    login (on A or B) is attempted for it."""
    a, b = apps
    mgr = _mgr()
    client = _client(mgr)
    _get(client, a.base + "inner")
    mgr._state[("127.0.0.1", "user")].valid = False
    _get(client, b.base + "inner")
    assert a.login_posts == 1 and b.login_posts == 0
    assert [r[1] for r in b.requests] == ["/inner"] and not b.got_session()


# --- O4: authorize and observe --------------------------------------------------------
class _Retarget:
    def __init__(self, to):
        self.to = to

    def on_request(self, request):
        request.url = self.to
        return request

    def on_response(self, request, response):
        pass


def test_a_plugin_retarget_to_another_port_is_refused(apps):
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    client = _client(mgr, plugins=_Retarget(b.base + "x"))
    with pytest.raises(SessionAuthError, match="not one of the session's"):
        _get(client, a.base + "x")
    assert b.requests == []


def test_another_ports_login_page_never_logs_the_session_out(apps):
    a, b = apps
    mgr = _mgr()
    told = []
    mgr.add_logout_listener(lambda origin, identity: told.append(origin))
    client = _client(mgr)
    _get(client, a.base + "inner")
    resp = _get(client, b.base + "login.php")            # B's login page
    assert b"password" in resp.body
    assert mgr._state[("127.0.0.1", "user")].valid and told == []
    _get(client, a.base + "login.php")                   # A's own: a logout
    assert not mgr._state[("127.0.0.1", "user")].valid
    assert told == [f"http://127.0.0.1:{a.port}"]


# --- O5: verify_live and the probe differential ---------------------------------------
def test_verify_live_never_follows_a_redirect_to_another_port(apps):
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    assert mgr.verify_live("127.0.0.1", "user", a.base) is True
    a.redirects["/"] = b.base + "landing"
    with pytest.raises(SessionAuthError, match="--auth-origin"):
        mgr.verify_live("127.0.0.1", "user", a.base)       # cannot verify: fail closed
    assert b.requests == []


def test_verify_live_keeps_the_session_inside_its_origins_even_where_a_login_may_go(apps):
    """O5's own layer: an origin a *login* may reach (an auth origin) that is not one of
    *this session's* origins (here a session adopted before B was authorised) is still
    never sent the session (`_navigate(session_origins=)`)."""
    a, b = apps
    mgr = _mgr(auth_origins=[b.base])
    a.sessions.add("sid-adopted-0123456789abcdef")
    mgr._state[("127.0.0.1", "user")] = SessionState(
        "127.0.0.1", "user", kind="cookie", valid=True,
        cookies={"sid": "sid-adopted-0123456789abcdef"}, origins=origin_scope(a.base))
    a.redirects["/"] = b.base + "landing"
    with pytest.raises(SessionAuthError, match="not one of its origins"):
        mgr.verify_live("127.0.0.1", "user", a.base)
    assert b.requests == []


def test_the_probe_differential_never_fetches_another_port(apps):
    """A candidate on B is never fetched; one on A that redirects to B is refused at
    the hop: no protected probe is found, and B receives nothing."""
    a, b = apps
    a.sessions.add("sid-good-0123456789abcdef")
    a.redirects["/hop"] = b.base + "api/me"
    mgr = _mgr()
    state = SessionState("127.0.0.1", "user", kind="cookie",
                         cookies={"sid": "sid-good-0123456789abcdef"},
                         origins=origin_scope(a.base))
    assert mgr._spa_probe("127.0.0.1", a.base, state,
                          [b.base + "api/me", a.base + "hop"]) == (None, None)
    assert b.requests == []
    found, _digest = mgr._spa_probe("127.0.0.1", a.base, state, [a.base + "api/me"])
    assert found == a.base + "api/me"                      # the positive control


# --- O6: greybox ----------------------------------------------------------------------
def test_greybox_attaches_the_cookie_only_in_origin(apps, tmp_path):
    """A ground-truth point on B: probed without the cookie, counted, and the attempt
    records it."""
    import json

    from fuzzlab.core.store import Store
    from fuzzlab.greybox.coverage import InMemoryCoverageSource
    from fuzzlab.greybox.dbfault import InMemoryDbFaultSource
    from fuzzlab.greybox.run import GreyboxPoint, RequestsCorrelatingSender, run_greybox
    a, b = apps
    mgr = _mgr()
    header = mgr.session_header("127.0.0.1", "user", a.base, operator=True)
    origins = mgr.session_origins_for(a.base, "user")
    sender = RequestsCorrelatingSender(cookie=header[len("Cookie: "):],
                                       cookie_origins=origins)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("greybox", "127.0.0.1")
        summary = run_greybox(base_url=a.base, store=store, run_id=run,
                              points=[GreyboxPoint(b.base + "q.php", "q"),
                                      GreyboxPoint(a.base + "q.php", "q")],
                              sender=sender, coverage_source=InMemoryCoverageSource({}),
                              dbfault_source=InMemoryDbFaultSource({}))
        rows = [json.loads(r[0]) for r in store.conn.execute(
            "SELECT features_json FROM attempt WHERE run_id=?", (run,))]
    assert b.requests and not b.got_session()
    assert any("sid=" in (r[2] or "") for r in a.requests if r[1].startswith("/q.php"))
    probes = len([r for r in b.requests if r[1].startswith("/q.php")])
    assert summary["session_out_of_origin"] == sender.session_out_of_origin == probes
    assert sum(1 for r in rows if r.get("session") == OUT_OF_ORIGIN) == probes


def test_greybox_refuses_a_cookie_without_origins():
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    with pytest.raises(ValueError, match="origins"):
        RequestsCorrelatingSender(cookie="sid=x")


def test_greybox_cli_hands_the_sender_the_sessions_origins(apps, monkeypatch, capsys):
    from fuzzlab.core import config, credentials
    from fuzzlab.greybox import greybox_cli
    a, _b = apps
    monkeypatch.setattr(config, "load_config", lambda: {"scope_hosts": []})
    monkeypatch.setattr(credentials.CredentialStore, "open",
                        classmethod(lambda cls, cfg: _creds()))
    cookie, _secure, is_auth, origins = greybox_cli._cookie_for("127.0.0.1", "user",
                                                                 a.base)
    assert cookie.startswith("sid=") and origins == origin_scope(a.base)
    assert is_auth(a.base + "login") and not is_auth("http://127.0.0.1:1/login")
    import types
    greybox_cli._print_summary(
        types.SimpleNamespace(store="u.db", mutation_variants=False), "crawl", {}, [], [],
        {"points": 1, "attempts": 1, "novel_lines": 0, "db_faults": 0,
         "m10_would_confirm": 0, "baseline_reward": 0.0, "newcode_reward": 0.0,
         "max_reward": 0.0, "coverage_lines_seen": 1, "session_out_of_origin": 4}, 1)
    assert "without the session (another origin, FR-SESS-20): 4" in capsys.readouterr().out


# --- O7: proxy capture ----------------------------------------------------------------
_LOGIN_RESP = (b"HTTP/1.1 302 Found\r\nLocation: /home\r\n"
               b"Set-Cookie: PHPSESSID=abc123secretvalue; Path=/\r\n\r\n")
_NEXT_REQ = (b"GET /home HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
             b"Cookie: PHPSESSID=abc123secretvalue\r\n\r\n")


def test_a_capture_records_the_origins_it_observed_on_its_host():
    from fuzzlab.proxy.session_capture import SessionCapture
    cap = SessionCapture("127.0.0.1", "user")
    cap.observe_response(_LOGIN_RESP, url="http://127.0.0.1:8080/login")
    cap.observe_request(_NEXT_REQ, url="http://localhost:8080/home")
    cap.observe_request(_NEXT_REQ, url="https://cdn.example/x.js")     # another host
    assert cap.state().origins == frozenset({"http://127.0.0.1:8080"})


def test_adopt_refuses_a_capture_with_no_observed_origin():
    from fuzzlab.proxy.session_capture import SessionCapture
    mgr = SessionManager(None, scope_hosts=[])
    cap = SessionCapture("127.0.0.1", "user")
    cap.observe_response(_LOGIN_RESP)                   # no URL: no origin
    with pytest.raises(SessionAuthError, match="no origin was observed"):
        cap.adopt_into(mgr)
    assert mgr._state == {}


def test_an_adopted_capture_is_sent_only_to_its_origins(apps):
    from fuzzlab.proxy.session_capture import SessionCapture
    a, b = apps
    mgr = SessionManager(None, scope_hosts=[])
    cap = SessionCapture("127.0.0.1", "user")
    cap.observe_response(_LOGIN_RESP, url=a.base + "login")
    cap.adopt_into(mgr)
    client = _client(mgr)
    _get(client, a.base + "home")
    _get(client, b.base + "home")
    assert a.got_session() and b.requests and not b.got_session()


# --- O8: the browser path -------------------------------------------------------------
def test_header_scope_admits_only_the_sessions_origins():
    from fuzzlab.tools.browserauth import header_scope_for
    state = SessionState("127.0.0.1", "user", origins=origin_scope("http://127.0.0.1:3000/"))
    in_scope = lambda u: True                                       # noqa: E731
    scope = header_scope_for(state, "http://127.0.0.1:3000/", in_scope)
    assert scope("http://127.0.0.1:3000/api") and scope("http://localhost:3000/x")
    assert not scope("http://127.0.0.1:8090/api")                  # another port
    assert not header_scope_for(state, "http://127.0.0.1:3000/", lambda u: False)(
        "http://127.0.0.1:3000/api")                               # out of scope
    secure = SessionState("h", "user", secure_only=True,
                          origins=origin_scope("http://h/", "https://h/"))
    s = header_scope_for(secure, "http://h/", in_scope)
    assert s("https://h/x") and not s("http://h/x")                # the https floor
    bare = header_scope_for(SessionState("h", "user"), "http://h:81/", in_scope)
    assert bare("http://h:81/x") and not bare("http://h:82/x")     # no origins: base only


class _Resp:
    def __init__(self, status=200, headers=None):
        self.status, self.headers = status, dict(headers or {})


class _HdrRoute:
    def __init__(self, url, site=None, navigation=True):
        self.request = type("Req", (), {
            "url": url, "method": "GET", "headers": {"accept": "*/*"},
            "post_data_buffer": None, "resource_type": "document" if navigation else "image",
            "is_navigation_request": lambda _s: navigation})()
        self.site = site or {}
        self.sent_headers = "unset"
        self.fetched = False
        self.outcome = None
        self.fulfilled = None

    def fetch(self, max_redirects=None, headers=None):
        self.fetched, self.sent_headers = True, headers
        return self.site.get(self.request.url, _Resp())

    def abort(self, *a):
        self.outcome = "abort"
        self.abort_code = a[0] if a else None

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"
        self.fulfilled = (response, status, headers)


class _Iso:
    """The guard's cookie-less request context: records fetches; an answer may set a
    cookie (B's ``sid=FROM_B``)."""

    def __init__(self, site):
        self.site, self.calls, self.disposed = site, [], False

    def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
        assert max_redirects == 0
        self.calls.append((url, method, headers))
        return self.site.get(url, _Resp(200, {"set-cookie": "sid=FROM_B",
                                              "content-type": "image/png"}))

    def dispose(self):
        self.disposed = True


def test_the_route_aborts_other_origin_documents_and_fetches_the_rest_cookie_less():
    """R1 + R2 (review round 1, A-M1/A-M2): in an authenticated context a document on
    another origin -- a navigation, or a redirect landing there -- is aborted, never
    fetched; a subresource there (and every hop) goes through the guard's cookie-less
    request context, never `route.fetch` or the context's client (which send the jar
    and store that origin's Set-Cookie in it), and is fulfilled without Set-Cookie."""
    from fuzzlab.tools.navguard import make_route_handler
    host_scope = lambda u: "127.0.0.2" in u                         # noqa: E731
    origins = origin_scope("http://127.0.0.2:3000/")
    cookie_scope = lambda u: in_origin_scope(u, origins)            # noqa: E731
    withheld, api_calls, made = [], [], []

    class Api:
        def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
            api_calls.append(url)
            return _Resp(200)

    def factory():
        made.append(_Iso({}))
        return made[-1]
    bearer = {"Authorization": "Bearer T"}
    handler = make_route_handler(in_scope=host_scope, api=Api(), headers=bearer,
                                 header_scope=cookie_scope, cookie_scope=cookie_scope,
                                 on_session_withheld=lambda u, k, src: withheld.append(
                                     (u, k)),
                                 isolated_request=factory)
    own = _HdrRoute("http://127.0.0.2:3000/a")
    handler(own)
    assert own.sent_headers == {"accept": "*/*", **bearer}           # its own origin
    doc = _HdrRoute("http://127.0.0.2:8090/a")
    handler(doc)
    assert doc.outcome == "abort" and not doc.fetched and made == []  # never loaded
    assert doc.abort_code == "aborted"        # ERR_ABORTED: no error page (T1)
    frame = _HdrRoute("http://127.0.0.2:8090/f")
    frame.request.frame = type("F", (), {"parent_frame": object()})()
    handler(frame)
    assert frame.outcome == "abort" and ("http://127.0.0.2:8090/f", "frame") in withheld
    img = _HdrRoute("http://127.0.0.2:8090/i.png", navigation=False)
    handler(img)
    assert not img.fetched and made[0].calls == [
        ("http://127.0.0.2:8090/i.png", "GET", {"accept": "*/*"})]   # no cookie, no bearer
    assert "set-cookie" not in {k.lower() for k in img.fulfilled[2]}
    assert not made[0].disposed                      # its answer is still being fulfilled
    handler(_HdrRoute("http://127.0.0.2:8090/j.png", navigation=False))
    assert made[0].disposed                          # it got a cookie: never reused
    assert len(made) == 2 and made[1].calls[0][0] == "http://127.0.0.2:8090/j.png"
    site = {"http://127.0.0.2:3000/go": _Resp(302, {"location": "http://127.0.0.2:8090/land"})}
    nav = _HdrRoute("http://127.0.0.2:3000/go", site)
    handler(nav)
    assert nav.outcome == "abort" and api_calls == []               # the landing: aborted
    sub = _HdrRoute("http://127.0.0.2:3000/go", site, navigation=False)
    handler(sub)
    assert api_calls == [] and made[-1].calls[-1][0] == "http://127.0.0.2:8090/land"
    assert nav.abort_code == "aborted"
    assert ("http://127.0.0.2:8090/a", "document") in withheld and \
        ("http://127.0.0.2:8090/land", "landing") in withheld and \
        ("http://127.0.0.2:8090/i.png", "request") in withheld
    lone = _HdrRoute("http://127.0.0.2:8090/i.png", navigation=False)
    make_route_handler(in_scope=host_scope, cookie_scope=cookie_scope)(lone)
    assert lone.outcome == "abort" and not lone.fetched              # no context: closed
    plain = _HdrRoute("http://127.0.0.2:8090/a")
    make_route_handler(in_scope=host_scope)(plain)                  # no session: as is
    assert plain.fetched and plain.sent_headers is None


def test_a_websocket_to_another_origin_is_never_connected_in_an_authenticated_context():
    from fuzzlab.tools.navguard import make_ws_handler
    origins = origin_scope("http://127.0.0.2:3000/")
    told, connected = [], []

    class WS:
        def __init__(self, url):
            self.url = url

        def connect_to_server(self):
            connected.append(self.url)
    handler = make_ws_handler(lambda u: "127.0.0.2" in u,
                              cookie_scope=lambda u: in_origin_scope(u, origins),
                              on_session_withheld=lambda u, k, src: told.append(k))
    handler(WS("ws://127.0.0.2:3000/s"))
    handler(WS("ws://127.0.0.2:8090/s"))
    assert connected == ["ws://127.0.0.2:3000/s"] and told == ["websocket"]


def test_the_spiders_isolated_submit_withholds_the_jar_from_another_origin(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.2:3000/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    got = []

    class Ctx:
        def fetch(self, *a, **k):
            return type("R", (), {"status": 200, "headers": {}})()

        def dispose(self):
            pass

    class Request:
        def new_context(self, storage_state=None, extra_http_headers=None):
            got.append(storage_state)
            return Ctx()
    jar = {"cookies": [{"name": "sid", "value": "v", "domain": "127.0.0.2"}],
           "origins": []}
    sp.engine = "playwright"
    sp._pw = type("PW", (), {"request": Request()})()
    sp._page = type("P", (), {"context": type("C", (), {
        "storage_state": lambda _s: jar})()})()
    origins = origin_scope("http://127.0.0.2:3000/")
    sp._cookie_scope = lambda u: in_origin_scope(u, origins)
    sp._isolated_submit("POST", "http://127.0.0.2:3000/f", [("a", "1")])
    sp._isolated_submit("POST", "http://127.0.0.2:8090/f", [("a", "1")])
    assert got[0]["cookies"] and got[1]["cookies"] == []
    assert sp.session_out_of_origin == 1
    sp.storage.close()


def _chromium_or_skip(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])


def test_an_authenticated_crawl_never_hands_the_session_to_another_port(monkeypatch,
                                                                        tmp_path):
    """Real Chromium. An external (host-scoped, every port) crawl of 127.0.0.2:A,
    logged in with a cookie. A's page links B directly, embeds an image from B (which
    answers ``Set-Cookie: sid=FROM_B``), frames a page of B, opens a WebSocket to B,
    and links ``/go``, which
    302s to B's ``/land``: a page that beacons ``document.cookie`` and ``localStorage``
    back to a relative ``/leak`` and links a relative ``/only-b``. Review round 1 saw
    the landing load under A's URL and leak (A-M1), and B's cookie land in the shared
    jar (A-M2). Now: no document of B ever loads (R1), B's image is fetched without any
    cookie and its Set-Cookie never reaches the jar (R2), the WebSocket is never
    connected, and nothing of B is filed under A."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    b = _App("127.0.0.2")
    a = _App("127.0.0.2", links=(
        f"<a href='{b.base}link'>b</a><img src='{b.base}img.png'><a href='/go'>go</a>"
        f"<iframe src='{b.base}frame'></iframe>"
        f"<script>localStorage.setItem('k','LS-SECRET');"
        f"try{{new WebSocket('ws://127.0.0.2:{b.port}/ws')}}catch(e){{}}</script>"))
    a.redirects["/go"] = b.base + "land"
    b.pages["/land"] = (200, (
        b"<html><body><p>B-LANDING-BODY</p><a href='/only-b'>only</a><script>"
        b"fetch('/leak?c='+encodeURIComponent(document.cookie+'|'+"
        b"localStorage.getItem('k')))</script></body></html>"), [])
    b.pages["/img.png"] = (200, b"png", [("Set-Cookie", "sid=FROM_B; Path=/")])
    try:
        mgr = _mgr(host="127.0.0.2")
        sp = LocalSpider(a.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000, session_manager=mgr,
                         identity="user")
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
        b.close()
    a_paths = [p for _m, p, _c, _h in a.requests]
    b_paths = [p for _m, p, _c, _h in b.requests]
    a_sessions = {c for _m, _p, c, _h in a.requests if c and "sid=" in c}
    assert "/" in {p for _m, p, c, _h in a.requests if c and "sid=sid-" in (c or "")}
    assert "/img.png" in b_paths                            # B reached, as a subresource
    assert not b.got_session()                              # ... with no cookie at all
    # no document of B (a link, a frame, a redirect landing) and no socket to B
    assert not {"/link", "/frame", "/land", "/ws", "/only-b"} & set(b_paths)
    assert not [p for p in a_paths if p.startswith(("/leak", "/only-b"))]
    assert not [c for c in a_sessions if "FROM_B" in c]     # B's cookie never in the jar
    assert a_sessions and all(any(f"sid={v}" in c for v in a.sessions)
                              for c in a_sessions)          # A keeps getting A's value
    rows = sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall()
    assert not [u for u, c in rows if "B-LANDING-BODY" in (c or "")]
    assert sp.session_out_of_origin >= 1
    assert {b.base + "link", b.base + "land", b.base + "frame"} <= \
        set(sp.skipped_other_origin)
    # a child frame of B never costs A's own page its rendering
    assert [c for u, c in rows if u == a.base and "home" in (c or "") or
            u == a.base and "welcome" in (c or "")]
    # residual pinned (R8): the static engine's anonymous jar never holds the session
    sids = {sid for sid in a.sessions}
    assert not {c.value for c in sp.session.cookies} & sids


# --- O9: auth endpoints ---------------------------------------------------------------
def test_login_on_another_port_is_not_our_auth_endpoint(apps):
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    assert mgr.is_auth_endpoint(a.base + "login")
    assert mgr.is_auth_endpoint(f"http://localhost:{a.port}/login")   # an alias
    assert not mgr.is_auth_endpoint(b.base + "login")
    assert mgr.auth_endpoints("127.0.0.1") == {a.base + "login", a.base + "logout"}


# --- O10: session_header(s) and `session print` --------------------------------------
def test_session_headers_refuse_a_base_on_another_origin(apps):
    a, b = apps
    mgr = _mgr()
    assert mgr.session_header("127.0.0.1", "user", a.base, operator=True).startswith(
        "Cookie: sid=")
    for fn in (mgr.session_header, mgr.session_headers):
        with pytest.raises(SessionAuthError, match="distinct identity"):
            fn("127.0.0.1", "user", b.base, operator=True)
    assert b.requests == []


def test_the_action_check_refuses_even_a_cached_session():
    """O10 at the action: a state the base's origin is not in is never handed out."""
    from fuzzlab.session.manager import _check_origin
    state = SessionState("h", "user", origins=origin_scope("http://h:1/"))
    _check_origin(state, "http://h:1/app/")
    with pytest.raises(SessionAuthError, match="not one of its origins"):
        _check_origin(state, "http://h:2/")


# --- O11: isolated copies -------------------------------------------------------------
def test_an_isolated_copy_gets_the_same_origins_and_never_sends_on_another_port(apps):
    a, b = apps
    main = _mgr()
    run_state = main.ensure("127.0.0.1", "user", a.base, operator=True)
    copy = main.isolated_copy("user", ordinal=1)
    copy_state = copy.ensure("127.0.0.1", "user", a.base, operator=True)
    assert copy_state.origins == run_state.origins == origin_scope(a.base)
    assert copy_state.cookies != run_state.cookies
    client = _client(copy)
    _get(client, b.base + "x", identity=copy.label)
    assert b.requests and not b.got_session() and copy.out_of_origin_sends == 1


# --- O12 / O13: the advice ------------------------------------------------------------
class _Web:
    def __init__(self, routes, post=None):
        self.routes = routes
        self.post_resp = post
        self.log = []

    def get(self, url, headers=None, allow_redirects=True):
        self.log.append(("GET", url))
        return self.routes.get(url, FetchResponse(200, {}, "<p>home</p>"))

    def post(self, url, data=None, headers=None, allow_redirects=True):
        return self.post_resp

    def cookies(self):
        return {"s": "1-0123456789abcdef"}


class _Creds:
    def require(self, host, identity):
        return type("C", (), {"username": USER, "password": PASSWORD})()


def test_the_destination_refusal_names_the_origin_and_how_to_authorise_it():
    form = ("<form method=post action='http://sso.example:8443/login'><input name=u>"
            "<input type=password name=p></form>")
    web = _Web({"http://lab.example/login": FetchResponse(200, {}, form)})
    mgr = SessionManager(_Creds(), scope_hosts=["lab.example"], fetch_factory=lambda: web)
    with pytest.raises(SessionAuthError) as err:
        mgr.ensure("lab.example", "user", "http://lab.example/")
    assert "http://sso.example:8443" in str(err.value)
    assert "--auth-origin http://sso.example:8443" in str(err.value)


def test_a_login_redirect_to_another_origin_warns_with_the_same_advice(caplog):
    """The post-login redirect points at another port (an app shell): it is never
    followed (R3), the login is judged on the POST's own answer, the session is not
    sent there, and the operator is told how to authorise it (--auth-origin)."""
    form = FetchResponse(200, {}, "<form method=post action='/login'><input name=u>"
                                  "<input type=password name=p></form>")
    web = _Web({"http://lab.example/login": form,
                "http://lab.example:3001/shell": FetchResponse(200, {}, "<p>app</p>")},
               post=FetchResponse(302, {"Location": "http://lab.example:3001/shell"}, ""))
    mgr = SessionManager(_Creds(), scope_hosts=["lab.example"], fetch_factory=lambda: web)
    with caplog.at_level(logging.WARNING):
        state = mgr.ensure("lab.example", "user", "http://lab.example/")
    assert state.origins == origin_scope("http://lab.example/")
    assert ("GET", "http://lab.example:3001/shell") not in web.log
    text = caplog.text
    assert "http://lab.example:3001" in text and "--auth-origin" in text


def test_the_cli_help_names_distinct_identities_per_app():
    from fuzzlab.session.cli import build_parser
    sub = build_parser()._subparsers._group_actions[0].choices
    assert "distinct identity name per app" in sub["set-credential"].format_help()
    assert "distinct one per app" in sub["print"].format_help()


# --- PA-0134(3): no session send decision compares hosts ------------------------------
ROOT = Path(__file__).resolve().parents[1]
#: The modules that decide where a session's secrets go (PA-0134; R4 added the
#: crawler, the auditor's fetcher and the M6 executor).
SESSION_SEND_MODULES = ("fuzzlab/session/manager.py", "fuzzlab/session/browserlogin.py",
                        "fuzzlab/tools/browserauth.py", "fuzzlab/tools/navguard.py",
                        "fuzzlab/tools/probesender.py", "fuzzlab/greybox/run.py",
                        "fuzzlab/greybox/greybox_cli.py",
                        "fuzzlab/proxy/session_capture.py", "fuzzlab/tools/spider.py",
                        "fuzzlab/tools/fetcher.py", "fuzzlab/tools/browserexec.py")
#: Host comparisons that decide no send, as ``module:function`` -> (how many such
#: compares the function holds, why). The count is pinned (review round 2, T3): an
#: extra compare in an allowed function is flagged, and so is a stale count.
HOST_COMPARE_ALLOWED = {
    # each is a deny-only gate (a host scope that refuses, never admits a session) or
    # a filter of what is adopted; where a session goes is decided by origin elsewhere
    "fuzzlab/session/manager.py:prepare": (
        1, "the seam's host scope gate (refuses); the session is applied by origin after"),
    "fuzzlab/session/manager.py:ensure": (
        1, "the host scope gate (refuses a login outside scope); bases checked by origin"),
    "fuzzlab/session/manager.py:authorize": (
        1, "refuses a retarget to another host (deny only); origins checked after"),
    "fuzzlab/session/manager.py:auth_endpoints": (
        1, "lists recorded endpoints by host for display; never a send decision"),
    "fuzzlab/session/manager.py:_states_on_host": (
        1, "selects the sessions a retargeted request may carry, to refuse (deny only)"),
    "fuzzlab/session/manager.py:_jar_cookies": (
        1, "which jar cookies the session carries (cookie domain match); sent by origin"),
    "fuzzlab/session/browserlogin.py:filter_storage_state": (
        1, "which jar cookies a browser context adopts (domain match); sent by origin "
           "(the route's cookie_scope)"),
    "fuzzlab/session/browserlogin.py:cookie_ok": (
        1, "filter_storage_state's cookie-domain predicate (same reason)"),
    "fuzzlab/greybox/greybox_cli.py:_cookie_for": (
        1, "builds the scope list; the cookie goes by cookie_origins"),
    "fuzzlab/proxy/session_capture.py:_note_origin": (
        1, "keeps only the capture host's origins (narrows; deny only)"),
    "fuzzlab/tools/spider.py:_in_scope": (
        2, "the crawl's request scope (BUG-0050/0123), not where the session goes "
           "(cookie_scope / header_scope by origin)"),
    "fuzzlab/tools/spider.py:_start_browser": (
        1, "a loopback start chooses the launch's resolver rules (scope), not a session"),
}
#: Calls whose result is a host (``canonical_host`` and the crawler's ``_norm_host``).
_HOST_CALLS = {"canonical_host", "_norm_host", "_canonical_host"}
#: Calls that change a value's case or whitespace, never what host it names (R4).
_SEE_THROUGH = {"lower", "casefold", "upper", "strip", "lstrip", "rstrip"}


def _strip(node):
    """``node`` without the case/whitespace/str() calls around it (R4)."""
    while isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in _SEE_THROUGH:
            node = f.value
        elif isinstance(f, ast.Name) and f.id == "str" and len(node.args) == 1:
            node = node.args[0]
        else:
            break
    return node


def _hostish(node, tainted=frozenset()) -> bool:
    """A host: ``X.hostname``, a host-returning call, a name or ``self`` attribute
    assigned from one, or any of those inside ``(... or "")``, an f-string or a
    case/whitespace/str() call (R4)."""
    node = _strip(node)
    if isinstance(node, ast.BoolOp):
        return any(_hostish(v, tainted) for v in node.values)
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) and _hostish(v.value, tainted)
                   for v in node.values)
    if isinstance(node, ast.Attribute):
        if node.attr == "hostname":
            return True
        return isinstance(node.value, ast.Name) and node.value.id == "self" and \
            f"self.{node.attr}" in tainted
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        return name in _HOST_CALLS
    return False


def _tainted_names(tree) -> frozenset:
    """Names and ``self.`` attributes assigned from a host (to a fixed point)."""
    tainted: set[str] = set()
    while True:
        before = len(tainted)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None \
                    and _hostish(node.value, frozenset(tainted)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
                    elif isinstance(t, ast.Attribute) and \
                            isinstance(t.value, ast.Name) and t.value.id == "self":
                        tainted.add(f"self.{t.attr}")
        if len(tainted) == before:
            return frozenset(tainted)


def _host_compares(tree):
    """``(function, line)`` of every ``==``/``!=``/``in``/``not in`` with a host on
    either side (R4)."""
    tainted = _tainted_names(tree)
    ops = (ast.Eq, ast.NotEq, ast.In, ast.NotIn)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare) and \
                    any(isinstance(op, ops) for op in node.ops) and \
                    any(_hostish(side, tainted)
                        for side in [node.left, *node.comparators]):
                yield fn.name, node.lineno


def host_compare_offenders(source: str, module: str, allowed=None) -> list[str]:
    """Host comparisons outside `HOST_COMPARE_ALLOWED` (PA-0134: a send decision
    compares origins, never hosts), and every allowed function whose count of them is
    not the pinned one (T3)."""
    allowed = HOST_COMPARE_ALLOWED if allowed is None else allowed
    found: dict[str, list[int]] = {}
    for fn, line in _host_compares(ast.parse(source)):
        found.setdefault(f"{module}:{fn}", []).append(line)
    out = []
    for key, lines in sorted(found.items()):
        if key not in allowed:
            out += [f"{key}:{line}" for line in sorted(set(lines))]
        elif len(set(lines)) != allowed[key][0]:
            out.append(f"{key}: {len(set(lines))} host compare(s), pinned "
                       f"{allowed[key][0]} (lines {sorted(set(lines))})")
    return out


def test_no_session_send_decision_compares_hosts():
    offenders = []
    for module in SESSION_SEND_MODULES:
        offenders += host_compare_offenders((ROOT / module).read_text(), module)
    assert offenders == []


def test_every_host_compare_allowance_is_still_used():
    used = set()
    for module in SESSION_SEND_MODULES:
        used |= {f"{module}:{fn}" for fn, _line in
                 _host_compares(ast.parse((ROOT / module).read_text()))}
    assert set(HOST_COMPARE_ALLOWED) <= used


def test_an_extra_host_compare_in_an_allowed_function_is_flagged():
    """T3 (review A2-S2): an allowance is a pinned count, not a blanket pass for the
    function."""
    allowed = {"rogue.py:gate": (1, "a scope gate")}
    one = "def gate(self, u):\n    host = urlparse(u).hostname\n    return host in self._scope\n"
    assert host_compare_offenders(one, "rogue.py", allowed) == []
    extra = ("def gate(self, u, h):\n    host = urlparse(u).hostname\n"
             "    if host not in self._scope:\n        return False\n"
             "    return host == h\n")
    flagged = host_compare_offenders(extra, "rogue.py", allowed)
    assert flagged and "2 host compare(s), pinned 1" in flagged[0]
    assert host_compare_offenders("def gate(self):\n    return 1\n", "rogue.py",
                                  allowed) == []          # no compare: nothing to pin


@pytest.mark.parametrize("src", [
    # BUG-0134's own shapes: header_scope_for, _navigate(session_host=), _spa_probe
    "def scope(url, host):\n    return canonical_host(url) != host\n",
    ("def nav(current, session_host):\n"
     "    if (urlparse(current).hostname or '') != session_host:\n        raise X\n"),
    "def probe(url, host):\n    return urlparse(url).hostname == host\n",
    # R4 (review A-M4): case calls, str(), an aliased name, membership, an attribute
    "def a(t, b):\n    return (t.hostname or '').lower() == (b.hostname or '').lower()\n",
    "def b(u, h):\n    return str(urlparse(u).hostname).casefold() == h\n",
    "def c(u, h):\n    host = urlparse(u).hostname or ''\n    return host == h\n",
    "def d(self, u):\n    host = urlparse(u).hostname\n    return host in self._scope\n",
    "def e(self, u):\n    return f'{urlparse(u).hostname}:1' not in self._scope\n",
    ("class S:\n    def l(self, u):\n        self._run_host = urlparse(u).hostname\n"
     "    def m(self, h):\n        return h != self._run_host\n"),
])
def test_the_host_compare_guard_catches_synthetic_offenders(src):
    assert host_compare_offenders(src, "rogue.py") != []


def test_the_host_compare_guard_passes_origin_compares():
    src = ("def scope(url, origins):\n    return canonical_origin(url) in origins\n"
           "def f(state, url):\n    return canonical_origin(url) == state.origin\n")
    assert host_compare_offenders(src, "fine.py") == []


def test_an_anonymous_out_of_origin_request_may_still_be_edited_on_its_origin(apps):
    """O4's refusal is for a request that carries the session: a plugin that edits an
    out-of-origin (anonymous) request on its own origin is not refused."""
    a, b = apps
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    _get(_client(mgr, plugins=_Retarget(b.base + "x?edited=1")), b.base + "x")
    assert b.requests[-1][1] == "/x?edited=1" and not b.got_session()


# --- R3: the login handshake stays on the login's anchors -----------------------------
def test_a_form_action_on_another_port_is_refused_with_the_advice(apps):
    """R3 (review A-M3): an in-scope host on another port is no longer a credential
    destination; B's login form never receives the password."""
    a, b = apps
    a.pages["/login"] = (200, LOGIN_FORM.replace("action='/login'",
                                                 f"action='{b.base}login'").encode(), [])
    mgr = _mgr()
    with pytest.raises(SessionAuthError, match=f"--auth-origin http://127.0.0.1:{b.port}"):
        mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    assert b.login_posts == 0 and b.requests == []


def test_a_basic_login_whose_base_redirects_to_another_port_sends_it_nothing():
    """R3: the Basic header is never carried by a hop the login may not take."""
    import base64
    good = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    a, b = _App(basic=True), _App()
    a.redirects["/"] = b.base + "home"
    try:
        with pytest.raises(SessionAuthError, match="--auth-origin"):
            _mgr().ensure("127.0.0.1", "user", a.base, operator=True)
        assert any(r[3] == good for r in a.requests)          # the base was challenged
    finally:
        a.close()
        b.close()
    assert b.requests == []


def test_the_post_login_check_keeps_the_header_inside_the_sessions_origins():
    """R3's second layer: `_verify_authenticated` carries the session's header only to
    its origins, even to an origin a login may reach (the https upgrade)."""
    class Basic:
        def __init__(self):
            self.log = []

        def get(self, url, headers=None, allow_redirects=True):
            self.log.append((url, dict(headers or {})))
            if (headers or {}).get("Authorization"):
                return FetchResponse(302, {"Location": "https://lab.example/home"}, "")
            return FetchResponse(401, {"WWW-Authenticate": 'Basic realm="x"'}, "")

        def post(self, *a, **k):
            raise AssertionError("no form")

        def cookies(self):
            return {}
    web = Basic()
    mgr = SessionManager(_Creds(), scope_hosts=["lab.example"], fetch_factory=lambda: web)
    with pytest.raises(SessionAuthError, match="not one of its origins"):
        mgr.ensure("lab.example", "user", "http://lab.example/")
    assert not [u for u, h in web.log if u.startswith("https:")]


@pytest.mark.parametrize("target,ok", [
    ("http://h:8080/login", True),                    # the base's own origin
    ("https://h/login", True),                        # its https upgrade, default port
    ("https://h:8080/login", True),                   # ... or the same port
    ("https://h:8443/login", False),                  # an upgrade to another port
    ("http://h:9090/login", False),                   # another port of an in-scope host
    ("http://other.h/login", False),                  # another in-scope host
    ("http://sso.h:9/login", True),                   # an authorised auth origin
])
def test_the_login_anchors_are_origins(target, ok):
    mgr = SessionManager(None, scope_hosts=["h", "other.h"], auth_origins=["http://sso.h:9"])
    assert mgr._credential_destination_ok(target, "http://h:8080/app/") is ok


def test_after_a_login_the_origins_are_the_base_and_the_auth_origins(apps):
    a, b = apps
    state = _mgr(auth_origins=[b.base]).ensure("127.0.0.1", "user", a.base, operator=True)
    assert state.origins <= origin_scope(a.base, b.base)


# --- R5: --auth-origin ----------------------------------------------------------------
@pytest.fixture
def no_config(monkeypatch):
    from fuzzlab.core import config
    monkeypatch.setattr(config, "load_config", lambda: {"scope_hosts": []})


def test_auth_origin_values_are_bare_in_scope_origins():
    from fuzzlab.session.manager import parse_auth_origins
    assert parse_auth_origins(["http://localhost:9/", "https://h"], ["localhost", "h"]) == [
        "http://127.0.0.1:9", "https://h:443"]
    for bad in ("http://h:9/sso", "http://h:9?x=1", "ftp://h:9", "http://u:p@h:9", "h:9",
                "http://h:99999"):
        with pytest.raises(ValueError, match="bare origin|not an origin"):
            parse_auth_origins([bad], ["h"])
    with pytest.raises(ValueError, match="not in scope"):
        parse_auth_origins(["http://elsewhere:9"], ["h"])


def test_the_crawl_takes_auth_origins_and_rejects_bad_ones(no_config, capsys):
    from fuzzlab.tools.spider import parse_args
    args = parse_args(["--start", "http://127.0.0.1:3000/", "--auth-origin",
                       "http://127.0.0.1:3001"])
    assert args.auth_origin == ["http://127.0.0.1:3001"]
    for bad in ("http://127.0.0.1:3001/app", "http://elsewhere.example:1"):
        with pytest.raises(SystemExit):
            parse_args(["--start", "http://127.0.0.1:3000/", "--auth-origin", bad])
        assert "--auth-origin" in capsys.readouterr().err
    assert "--auth-origin" in __import__("fuzzlab.tools.spider", fromlist=["x"]) \
        .build_parser().format_help()


def test_auto_takes_auth_origins_and_rejects_bad_ones_before_any_side_effect(
        no_config, tmp_path, monkeypatch, capsys):
    from fuzzlab.harness import auto_cli
    from tests.test_auto import GT_DIR, AutoSender
    got = []

    def make(base, identity=None, **kw):
        got.append(kw)
        return AutoSender()
    monkeypatch.setattr(auto_cli, "make_probe_sender", make)
    args = ["--base-url", "http://127.0.0.1:8080", "--spider-db", str(tmp_path / "n.db"),
            "--ground-truth", GT_DIR, "--points", "ground-truth", "--authorized"]
    for bad, why in (("http://127.0.0.1:3001/app", "bare origin"),
                     ("http://elsewhere.example:1", "not in scope")):
        with pytest.raises(SystemExit):
            auto_cli.main([*args, "--store", str(tmp_path / "bad.db"), "--auth-origin", bad])
        assert why in capsys.readouterr().err
    assert not (tmp_path / "bad.db").exists() and got == []
    assert auto_cli.main([*args, "--store", str(tmp_path / "u.db"), "--auth-origin",
                          "http://127.0.0.1:3001/"]) == 0
    assert got == [{"auth_origins": ["http://127.0.0.1:3001"]}]
    assert "--auth-origin" in auto_cli.build_parser().format_help()


def test_greybox_rejects_a_bad_auth_origin_before_any_side_effect(no_config, tmp_path,
                                                                 capsys):
    from fuzzlab.greybox import greybox_cli
    with pytest.raises(SystemExit):
        greybox_cli.main(["--base-url", "http://127.0.0.1:3000/", "--store",
                          str(tmp_path / "u.db"), "--authorized", "--identity", "user",
                          "--auth-origin", "http://elsewhere.example:1"])
    assert "not in scope" in capsys.readouterr().err
    assert not (tmp_path / "u.db").exists()
    assert "--auth-origin" in greybox_cli.build_parser().format_help()


def test_session_print_takes_auth_origins(apps, monkeypatch, capsys):
    from fuzzlab.session import cli
    a, b = apps
    monkeypatch.setattr(cli, "load_config", lambda: {"scope_hosts": []})
    monkeypatch.setattr(cli.CredentialStore, "open", classmethod(lambda c, cfg: _creds()))
    assert cli.main(["print", "--host", "127.0.0.1", "--identity", "user", "--base-url",
                     a.base, "--auth-origin", b.base + "p"]) == 2
    assert "bare origin" in capsys.readouterr().out and a.requests == []
    assert cli.main(["print", "--host", "127.0.0.1", "--identity", "user", "--base-url",
                     a.base, "--auth-origin", b.base.rstrip("/")]) == 0
    assert capsys.readouterr().out.startswith("Cookie: sid=")


def test_the_builders_hand_auth_origins_to_the_manager(no_config, monkeypatch):
    from fuzzlab.core import credentials
    from fuzzlab.tools.authhttp import make_session_manager
    from fuzzlab.tools.probesender import make_probe_sender
    monkeypatch.setattr(credentials.CredentialStore, "open",
                        classmethod(lambda c, cfg: _creds()))
    sso = ["http://127.0.0.1:3001"]
    assert make_session_manager("http://127.0.0.1:3000/", auth_origins=sso) \
        ._auth_origins == set(sso)
    assert make_probe_sender("http://127.0.0.1:3000/", "user", auth_origins=sso) \
        ._manager._auth_origins == set(sso)


def test_adopt_adds_the_operators_auth_origins():
    from fuzzlab.proxy.session_capture import SessionCapture
    mgr = SessionManager(None, scope_hosts=[], auth_origins=["http://127.0.0.1:3001"])
    cap = SessionCapture("127.0.0.1", "user")
    cap.observe_response(_LOGIN_RESP, url="http://127.0.0.1:8080/login")
    assert cap.adopt_into(mgr).origins == frozenset(
        {"http://127.0.0.1:8080", "http://127.0.0.1:3001"})


# --- R7: what authorize treats as carrying the session -------------------------------
def test_a_retarget_carrying_an_edited_session_value_is_refused(apps):
    """R7 (review A-S1): containment, not equality: a plugin that appends to the cookie
    (``sid=<v>'OR1``) and retargets to another port still carries the session."""
    a, b = apps
    mgr = _mgr()
    state = mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    sid = state.cookies["sid"]

    class Edit:
        def on_request(self, request):
            request.url = b.base + "x"
            request.headers["Cookie"] = f"sid={sid}'OR1"
            return request

        def on_response(self, request, response):
            pass
    with pytest.raises(SessionAuthError, match="not one of the session's"):
        _get(_client(mgr, plugins=Edit()), a.base + "x")
    assert b.requests == []


# --- R9: the https floor before the origin rule ---------------------------------------
def test_an_https_session_refuses_plain_http_even_on_another_port():
    """R9 (review A-N1): an https-only session's plain-http request to another port of
    its host -- which would only go anonymously -- is still refused loudly (BUG-0098's
    floor runs first): fails closed, never silently sent."""
    mgr = SessionManager(None, scope_hosts=["lab.example"])
    mgr._state[("lab.example", "user")] = SessionState(
        "lab.example", "user", kind="cookie", cookies={"s": "SECRET-0123456789"},
        valid=True, secure_only=True, origins=origin_scope("https://lab.example/"))
    req = Request("GET", "http://lab.example:8080/x", identity="user")
    with pytest.raises(SessionAuthError, match="plain http"):
        mgr.prepare(req, "user")
    assert "Cookie" not in req.headers


# --- review round 2 ------------------------------------------------------------------
def test_a_script_navigation_to_another_origin_leaves_the_page_crawled(monkeypatch,
                                                                       tmp_path):
    """T1 (review A2-M1, B2-S2; reviewer A's live probe): A's page navigates to B 200 ms
    after load. The route aborts that document with ERR_ABORTED, so the page stays on A
    (``"blockedbyclient"`` committed Chromium's error page in its place). A is extracted
    normally -- its content stored, its ``/next`` link queued and crawled -- B receives
    nothing, and B is recorded as skipped."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    b = _App("127.0.0.2")
    a = _App("127.0.0.2")
    a.pages["/"] = (200, (
        f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a><script>"
        f"setTimeout(()=>location.href='{b.base}x',200)</script></body></html>").encode(),
        [])
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000,
                         session_manager=_mgr(host="127.0.0.2"), identity="user")
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
        b.close()
    rows = dict(sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall())
    assert "A-OWN-CONTENT" in (rows.get(a.base) or "")       # A's page, extracted
    assert "/next" in [p for _m, p, _c, _h in a.requests]    # its link queued and crawled
    assert b.requests == []                                  # B received nothing
    assert sp.skipped_other_origin.get(b.base + "x", "").startswith("document: ")


def test_carries_matches_short_plain_cookies_only_as_exact_pairs(apps):
    """T2 (review A2-S1): containment only for secret-looking values; a short plain
    cookie counts only as its exact pair. An anonymous out-of-origin request edited on
    its own origin with ordinary browser headers is not refused; a carried session is."""
    from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
    from fuzzlab.session.manager import _carries
    a, b = apps
    mgr = _mgr()
    state = mgr.ensure("127.0.0.1", "user", a.base, operator=True)
    state.cookies.update({"language": "en", "security": "low", "security_level": "0"})
    browserish = Request("GET", b.base + "x", headers=dict(DEFAULT_BROWSER_HEADERS))
    assert not _carries(browserish, state)                   # "en", "low", "0" as text
    assert _carries(Request("GET", "x", headers={"Cookie": "security=low"}), state)
    assert not _carries(Request("GET", "x", headers={"Cookie": "security=lowest"}), state)

    class Edit:
        def on_request(self, request):
            request.url = b.base + "x?edited=1"
            request.headers.update(DEFAULT_BROWSER_HEADERS)
            return request

        def on_response(self, request, response):
            pass
    _get(_client(mgr, plugins=Edit()), b.base + "x")          # anonymous: allowed
    assert b.requests[-1][1] == "/x?edited=1" and not b.got_session()

    class Carry(Edit):
        def on_request(self, request):
            request.url = b.base + "y"
            request.headers["Cookie"] = f"sid={state.cookies['sid']}'OR1"
            return request
    with pytest.raises(SessionAuthError, match="not one of the session's"):
        _get(_client(mgr, plugins=Carry()), a.base + "x")
    assert "/y" not in [p for _m, p, _c, _h in b.requests]


def test_a_localhost_auth_origin_is_accepted_for_a_127_scope():
    """T5 (review A2-OP2, B2-S1): canonical compare (loopback aliases one host)."""
    from fuzzlab.session.manager import parse_auth_origins
    assert parse_auth_origins(["http://localhost:3001"], ["127.0.0.1"]) == [
        "http://127.0.0.1:3001"]
    assert parse_auth_origins(["http://127.0.0.1:3001"], ["localhost"]) == [
        "http://127.0.0.1:3001"]
    with pytest.raises(ValueError, match="not in scope"):
        parse_auth_origins(["http://127.0.0.2:3001"], ["127.0.0.1"])   # another 127/8


def test_skipped_reasons_name_the_kind_and_isolated_contexts_are_counted(tmp_path):
    """T6 (review nits): a skipped page's reason names what was withheld; the cookie-less
    request contexts made are counted."""
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.2:3000/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    sp._note_session_withheld("http://127.0.0.2:8090/f", "frame", "http://127.0.0.2:3000/")
    sp._note_session_withheld("ws://127.0.0.2:8090/s", "websocket", "ws://127.0.0.2:8090/s")
    assert sp.skipped_other_origin["http://127.0.0.2:8090/f"].startswith("frame: ")
    assert sp.skipped_other_origin["ws://127.0.0.2:8090/s"].startswith("websocket: ")
    sp._pw = type("PW", (), {"request": type("R", (), {
        "new_context": lambda _s: object()})()})()
    sp._isolated_request()
    sp._isolated_request()
    assert sp.isolated_contexts_created == 2
    sp.storage.close()
