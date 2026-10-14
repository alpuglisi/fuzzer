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

    def __init__(self, host: str = "127.0.0.1", links: str = ""):
        self.host = host
        self.links = links
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
    assert mgr.session_note(b.base + "page", "user") == OUT_OF_ORIGIN
    assert mgr.session_note(a.base + "page", "user") is None


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
    with pytest.raises(SessionAuthError, match="not one of its origins"):
        mgr.verify_live("127.0.0.1", "user", a.base)       # cannot verify: fail closed
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


class _HdrRoute:
    def __init__(self, url, site=None):
        self.request = type("Req", (), {
            "url": url, "method": "GET", "headers": {"accept": "*/*"},
            "post_data_buffer": None, "is_navigation_request": lambda _s: True})()
        self.site = site or {}
        self.sent_headers = "unset"
        self.outcome = None

    def fetch(self, max_redirects=None, headers=None):
        self.sent_headers = headers
        return self.site.get(self.request.url, type("R", (), {"status": 200,
                                                              "headers": {}})())

    def abort(self, *a):
        self.outcome = "abort"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"
        self.fulfilled_with = "response" if response is not None else "redirect"


def test_the_route_withholds_the_jar_from_another_origin_and_its_hops():
    from fuzzlab.tools.navguard import make_route_handler
    host_scope = lambda u: "127.0.0.2" in u                         # noqa: E731
    origins = origin_scope("http://127.0.0.2:3000/")
    cookie_scope = lambda u: in_origin_scope(u, origins)            # noqa: E731
    withheld, calls = [], []

    class Api:
        def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
            calls.append((url, headers))
            return type("R", (), {"status": 200, "headers": {}})()
    bearer = {"Authorization": "Bearer T"}
    handler = make_route_handler(in_scope=host_scope, api=Api(), headers=bearer,
                                 header_scope=cookie_scope, cookie_scope=cookie_scope,
                                 on_session_withheld=withheld.append)
    own = _HdrRoute("http://127.0.0.2:3000/a")
    handler(own)
    assert own.sent_headers == {"accept": "*/*", **bearer}
    other = _HdrRoute("http://127.0.0.2:8090/a")
    handler(other)
    assert other.sent_headers == {"accept": "*/*", "cookie": ""}   # no jar, no bearer
    site = {"http://127.0.0.2:3000/r": type("R", (), {
        "status": 302, "headers": {"location": "http://127.0.0.2:8090/b"}})()}
    hop = _HdrRoute("http://127.0.0.2:3000/r", site)
    handler(hop)
    assert calls == [("http://127.0.0.2:8090/b", {"cookie": ""})]
    assert withheld == ["http://127.0.0.2:8090/a", "http://127.0.0.2:8090/b"]
    # a navigation landing on another origin is answered with the landing response, not
    # a redirect Chromium would follow unrouted with its jar
    assert hop.outcome == "fulfill" and hop.fulfilled_with == "response"
    calls.clear()
    site = {"http://127.0.0.2:3000/r2": type("R", (), {
        "status": 302, "headers": {"location": "/own"}})()}
    own_hop = _HdrRoute("http://127.0.0.2:3000/r2", site)
    handler(own_hop)
    assert own_hop.fulfilled_with == "redirect"            # its own origin: as before
    plain = _HdrRoute("http://127.0.0.2:8090/a")
    make_route_handler(in_scope=host_scope)(plain)                  # no session: as is
    assert plain.sent_headers is None


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
    logged in with a cookie, whose page links, embeds and redirects to 127.0.0.2:B (in
    scope). Browser cookies are port-agnostic (RFC 6265), so before FR-SESS-20 B got
    A's cookie; now B is crawled anonymously and receives no cookie value and no
    Authorization, while A's own requests carry the session."""
    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    b = _App("127.0.0.2")
    a = _App("127.0.0.2", links=(f"<a href='{b.base}link'>b</a>"
                                 f"<img src='{b.base}img.png'><a href='/go'>go</a>"))
    a.redirects["/go"] = b.base + "redirected"
    try:
        mgr = _mgr(host="127.0.0.2")
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000, session_manager=mgr,
                         identity="user")
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            skip_or_fail(f"chromium could not launch: {exc}")
        a_paths = {p for _m, p, c, _h in a.requests if c and "sid=" in c}
        b_paths = {p for _m, p, _c, _h in b.requests}
    finally:
        a.close()
        b.close()
    assert "/" in a_paths                                  # the crawl was logged in on A
    # B was in scope and reached: a link, a subresource, and a redirected navigation
    # (whose landing the browser would otherwise re-request unrouted, with its jar)
    assert {"/link", "/img.png", "/redirected"} <= b_paths
    assert not b.got_session()                              # ... with no session at all
    assert sp.session_out_of_origin >= 2


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

    def get(self, url, headers=None, allow_redirects=True):
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
    assert "auth_origins=['http://sso.example:8443']" in str(err.value)


def test_a_login_redirect_to_another_origin_warns_with_the_same_advice(caplog):
    """The post-login redirect lands on another port (an app shell): the login works,
    the session is not sent there, and the operator is told how to authorise it."""
    form = FetchResponse(200, {}, "<form method=post action='/login'><input name=u>"
                                  "<input type=password name=p></form>")
    web = _Web({"http://lab.example/login": form,
                "http://lab.example:3001/shell": FetchResponse(200, {}, "<p>app</p>")},
               post=FetchResponse(302, {"Location": "http://lab.example:3001/shell"}, ""))
    mgr = SessionManager(_Creds(), scope_hosts=["lab.example"], fetch_factory=lambda: web)
    with caplog.at_level(logging.WARNING):
        state = mgr.ensure("lab.example", "user", "http://lab.example/")
    assert state.origins == origin_scope("http://lab.example/")
    text = caplog.text
    assert "http://lab.example:3001" in text and "auth_origins=" in text


def test_the_cli_help_names_distinct_identities_per_app():
    from fuzzlab.session.cli import build_parser
    sub = build_parser()._subparsers._group_actions[0].choices
    assert "distinct identity name per app" in sub["set-credential"].format_help()
    assert "distinct one per app" in sub["print"].format_help()


# --- PA-0134(3): no session send decision compares hosts ------------------------------
ROOT = Path(__file__).resolve().parents[1]
#: The modules that decide where a session's secrets go (PA-0134).
SESSION_SEND_MODULES = ("fuzzlab/session/manager.py", "fuzzlab/session/browserlogin.py",
                        "fuzzlab/tools/browserauth.py", "fuzzlab/tools/navguard.py",
                        "fuzzlab/tools/probesender.py", "fuzzlab/greybox/run.py",
                        "fuzzlab/greybox/greybox_cli.py",
                        "fuzzlab/proxy/session_capture.py")
#: Host comparisons that decide no send, each with its reason (``module:function``).
HOST_COMPARE_ALLOWED = {
    "fuzzlab/session/manager.py:auth_endpoints":
        "lists recorded endpoints by host for display; never a send decision",
    "fuzzlab/session/manager.py:_states_on_host":
        "selects the sessions a retargeted request may carry, to refuse (deny only)",
    "fuzzlab/proxy/session_capture.py:_note_origin":
        "keeps only the capture host's origins (narrows; deny only)",
}


def _hostish(node) -> bool:
    """``X.hostname``, ``canonical_host(...)``, or either inside ``(... or "")``."""
    if isinstance(node, ast.BoolOp):
        return any(_hostish(v) for v in node.values)
    if isinstance(node, ast.Attribute) and node.attr == "hostname":
        return True
    if isinstance(node, ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        return name == "canonical_host"
    return False


def host_compare_offenders(source: str, module: str) -> list[str]:
    """``==``/``!=`` comparisons with a hostname on either side, by function, outside
    `HOST_COMPARE_ALLOWED` (PA-0134: a send decision compares origins, never hosts)."""
    tree = ast.parse(source)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Compare) or \
                    not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                continue
            if any(_hostish(side) for side in [node.left, *node.comparators]):
                key = f"{module}:{fn.name}"
                if key not in HOST_COMPARE_ALLOWED:
                    out.append(f"{key}:{node.lineno}")
    return sorted(set(out))


def test_no_session_send_decision_compares_hosts():
    offenders = []
    for module in SESSION_SEND_MODULES:
        offenders += host_compare_offenders((ROOT / module).read_text(), module)
    assert offenders == []


def test_every_host_compare_allowance_is_still_used():
    used = set()
    for module in SESSION_SEND_MODULES:
        tree = ast.parse((ROOT / module).read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(n, ast.Compare) and any(
                        _hostish(s) for s in [n.left, *n.comparators])
                    for n in ast.walk(fn)):
                used.add(f"{module}:{fn.name}")
    assert set(HOST_COMPARE_ALLOWED) <= used


@pytest.mark.parametrize("src", [
    # BUG-0134's own shapes: header_scope_for, _navigate(session_host=), _spa_probe
    "def scope(url, host):\n    return canonical_host(url) != host\n",
    ("def nav(current, session_host):\n"
     "    if (urlparse(current).hostname or '') != session_host:\n        raise X\n"),
    "def probe(url, host):\n    return urlparse(url).hostname == host\n",
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
