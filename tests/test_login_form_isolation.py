"""Forms phase 2, lane B: in-app login forms are probed on an isolated session.

Phase 1 skipped every form with a password control: fuzzing one with the run's own
session can re-bind that session's identity on the server (a SQLi such as
``' or 1=1-- -`` runs the app's login logic for the run's session id), and the seam
adopts no response cookie, so the run would carry on as the wrong user. Now an in-app
login form is imported, and every send to its path goes out on a separate, throwaway
login of the same identity, verified distinct, or anonymously; never with the run's
session. Credential-change forms stay excluded (FR-FUZZ-44, FR-SESS-17, FR-CORE-31).

The fake app below re-binds the session of whoever submits its login form, the worst
case; bWAPP's in-app login pages do not, so this is where the guarantee is proven.
"""

from __future__ import annotations

import ast
import json
import threading
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient, Request, Response
from fuzzlab.core.store import Store
from fuzzlab.core.urls import url_key
from fuzzlab.harness.auto import (injection_points_from_store, isolated_paths_from_store,
                                  run_auto)
from fuzzlab.session import manager as manager_mod
from fuzzlab.session.manager import (DISTINCT_MIN_LEN, FetchResponse, SessionAuthError,
                                     SessionIsolationError, SessionManager,
                                     distinctness_problem)
from fuzzlab.session.state import SessionState
from fuzzlab.tools import probesender
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
from fuzzlab.tools.store_adapter import form_skip_reason, import_spider
from tests.test_forms_phase1 import _rec, _spider_db
from tests.test_session_manager import CookieLoginFetcher, _factory, _store

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://localhost/app/"
LOGIN_PAGE = BASE + "login.php"
LOGIN_HTML = ("<form method='post' action='/app/login.php'><input name='login'>"
              "<input type='password' name='password'>"
              "<button name='form' value='submit'>Login</button></form>")
SQLI3 = ("<form method=post action='/app/sqli_3.php'><input name=login>"
         "<input type=password name=password>"
         "<button type=submit name=form value=submit>Login</button></form>")
SQL_ERROR = (b"Error: You have an error in your SQL syntax; check the manual that "
             b"corresponds to your MySQL server version")


# --- the fake app: a server-side session table, re-bound by its own login form ------
class FakeApp:
    """``sessions`` maps a session id to its user. A credentials POST to the login page
    creates a new id (or, per the knobs, re-issues one). A POST of the in-app login
    form (``/app/sqli_3.php``, with ``form``) re-binds the submitting session to
    ``victim`` when the login breaks the query, as an injection that logs in would."""

    def __init__(self, *, sid_mode="fresh", reject_copies=False, single_session=None,
                 public_base=False, https=False, cookie_redirect=None):
        self.sid_mode = sid_mode              # fresh | same_for_copies | same_for_all
        self.reject_copies = reject_copies
        self.single_session = single_session  # None | "eager" | "lazy"
        self.public_base = public_base
        # a session-carrying GET of the base (verify_live) is redirected here
        self.cookie_redirect = cookie_redirect
        self.scheme = "https" if https else "http"
        self.sessions: dict[str, str] = {}
        self.pending_kill: set[str] = set()
        self.issued: list[str] = []
        self.login_posts = 0
        self.requests: list[tuple[str, str, str | None, dict]] = []
        self.fetcher_gets: list[tuple[str, str | None]] = []
        self.fetcher_hosts: list[tuple[str, dict]] = []      # (host, headers) per GET

    # sids: realistic, distinct, sensitive-named
    def _new_sid(self) -> str:
        n = len(self.issued) + 1
        if self.sid_mode == "same_for_all" or (self.sid_mode == "same_for_copies"
                                               and n > 1):
            n = 1 if self.sid_mode == "same_for_all" else 2
        return f"{n:026x}"

    def login(self) -> str | None:
        self.login_posts += 1
        if self.reject_copies and self.issued:
            return None
        sid = self._new_sid()
        if self.single_session == "eager":
            for other in list(self.sessions):
                if other != sid:
                    del self.sessions[other]
        elif self.single_session == "lazy":
            self.pending_kill |= {s for s in self.sessions if s != sid}
        self.sessions[sid] = "admin"
        self.issued.append(sid)
        return sid

    def touch(self, sid):
        if sid in self.pending_kill:
            self.pending_kill.discard(sid)
            self.sessions.pop(sid, None)

    def fetch_factory(self):
        return lambda: _Fetcher(self)

    def page(self, method, url, sid, data):
        """``(status, headers, body)`` of the app for one request."""
        path = urlsplit(url).path
        self.touch(sid)
        if path == "/app/login.php":
            return 200, {"Content-Type": "text/html"}, LOGIN_HTML.encode()
        authed = sid in self.sessions
        if path == "/app/" and self.public_base:
            return 200, {"Content-Type": "text/html"}, b"<html>public home</html>"
        if not authed:
            return 302, {"Location": "/app/login.php"}, b""
        if path == "/app/sqli_3.php" and method == "POST" and "form" in data:
            if "'" in data.get("login", ""):
                self.sessions[sid] = "victim"         # the injection logged it in
                return 200, {"Content-Type": "text/html"}, SQL_ERROR
            return 200, {"Content-Type": "text/html"}, b"Invalid credentials!"
        if path == "/app/whoami.php":
            return 200, {"Content-Type": "text/plain"}, self.sessions[sid].encode()
        return 200, {"Content-Type": "text/html"}, b"<html>welcome page</html>"

    def transport(self, method, url, headers, body, timeout):
        sid = _sid_of(headers.get("Cookie"))
        data = dict(parse_qsl((body or b"").decode(), keep_blank_values=True))
        if method == "GET":
            data = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        self.requests.append((method, urlsplit(url).path, sid, data, dict(headers)))
        return self.page(method, url, sid, data)


def _sid_of(cookie):
    for part in (cookie or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "PHPSESSID":
            return value
    return None


class _Fetcher:
    """The session manager's login fetcher: its own jar, like a fresh requests.Session."""

    def __init__(self, app):
        self.app = app
        self.jar: dict[str, str] = {}

    def get(self, url, headers=None, allow_redirects=True):
        sid = _sid_of((headers or {}).get("Cookie")) or self.jar.get("PHPSESSID")
        self.app.fetcher_gets.append((urlsplit(url).path, sid))
        self.app.fetcher_hosts.append((urlsplit(url).hostname, dict(headers or {})))
        if self.app.cookie_redirect and (headers or {}).get("Cookie") and \
                urlsplit(url).path == "/app/":
            return FetchResponse(302, {"Location": self.app.cookie_redirect}, "", url)
        status, hdrs, body = self.app.page("GET", url, sid, {})
        return FetchResponse(status, hdrs, body.decode(), url)

    def post(self, url, data=None, headers=None, allow_redirects=True):
        fields = dict(list(data or []))
        if fields.get("login") == "admin" and fields.get("password") == "admin123":
            sid = self.app.login()
            if sid is not None:
                self.jar = {"PHPSESSID": sid, "security_level": "0"}
                return FetchResponse(200, {}, "<html>welcome admin</html>", url)
        return FetchResponse(200, {}, LOGIN_HTML, url)

    def cookies(self):
        return dict(self.jar)


def _seam(app, *, budget=None, base=BASE, store=None, run_id=None, factory=True,
          identity="admin", scope=("localhost",)):
    """The run's manager, client and sender, wired as `make_probe_sender` wires them."""
    budget = budget or RequestBudget(5000)
    mgr = SessionManager(_store(), scope_hosts=list(scope), store=store,
                         fetch_factory=app.fetch_factory())

    def isolated_client(copy):
        return HttpClient(budget, ["localhost"], session=copy, transport=app.transport,
                          store=store, run_id=run_id)
    client = HttpClient(budget, ["localhost"], session=mgr, transport=app.transport,
                        store=store, run_id=run_id)
    sender = SeamProbeSender(client, identity, manager=mgr, base_url=base,
                             isolated_client=isolated_client if factory else None)
    return mgr, client, sender


def _import(tmp_path, store, forms, pages=()):
    _spider_db(tmp_path / "s.db", [_rec(h, page=p) for h, p in forms], pages)
    run = store.start_run("auto", "localhost")
    import_spider(tmp_path / "s.db", store, run)
    return run


def _auto(store, run, sender):
    return run_auto(base_url=BASE, store=store, run_id=run, sender=sender, mode="manual",
                    selected_categories=["sql-injection"], points_source="crawl")


def _main_sid(app):
    return app.issued[0]


# --- T1/T1c: the main proof ---------------------------------------------------------
def test_a_login_form_is_confirmed_on_an_isolated_session_and_the_run_session_survives(
        tmp_path):
    app = FakeApp()
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        mgr, client, sender = _seam(app)
        result = _auto(store, run, sender)
        assert result.findings >= 1
        finding = store.conn.execute("SELECT url, param FROM finding").fetchone()
        assert (finding["url"], finding["param"]) == ("/app/sqli_3.php", "login")
    main = _main_sid(app)
    assert app.sessions[main] == "admin"                          # on the server
    probe = sender.send(BASE + "whoami.php", "x", "1")
    assert probe.text == "admin"                                  # through the app
    rebound = [s for s, user in app.sessions.items() if user == "victim"]
    assert rebound and main not in rebound                        # the copy took it
    to_form = [r for r in app.requests if r[1] == "/app/sqli_3.php"]
    assert to_form and all(r[2] != main for r in to_form)         # at the send
    assert app.login_posts == 2                                   # one extra login
    assert result.metrics["isolated_sessions"]["logins"] == 1


def test_control_the_fake_app_rebinds_a_session_that_sends_the_injection():
    """Non-vacuity control for the test above (passes without the change too)."""
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.send(BASE + "sqli_3.php", "login", "'", method="POST", location="body",
                entries=[("login", "'"), ("password", ""), ("form", "submit")])
    assert app.sessions[_main_sid(app)] == "victim"


# --- T2/T3: the password is never fuzzed; its sibling is sent empty ------------------
def test_the_password_sibling_is_sent_empty_and_never_fuzzed(tmp_path):
    app = FakeApp()
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        skipped: list = []
        pts = injection_points_from_store(store, run, BASE, skipped=skipped,
                                          isolated=set())
        assert [p.param for p in pts] == ["login"]
        assert ("password", "") in pts[0].base_entries
        _seam_mgr, _c, sender = _seam(app)
        _auto(store, run, sender)
    posts = [r[3] for r in app.requests if r[1] == "/app/sqli_3.php" and r[0] == "POST"]
    assert posts and all(d.get("password") == "" and d.get("form") == "submit"
                         for d in posts)


def test_a_password_control_is_never_a_point_whatever_its_name(tmp_path):
    html = ("<form method=get action='/app/q.php'><input name=user>"
            "<input type=password name=answer><button name=go value=1>Go</button></form>")
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(html, BASE + "q.php")],
                      pages=["http://localhost/app/q.php?answer=1"])
        skipped: list = []
        pts = injection_points_from_store(store, run, BASE, skipped=skipped,
                                          isolated=set())
        row = store.conn.execute("SELECT password_fields FROM form").fetchone()
        form_params = {r[0] for r in store.conn.execute(
            "SELECT name FROM parameter WHERE form_id IS NOT NULL")}
    assert json.loads(row["password_fields"]) == ["answer"]
    assert form_params == {"user"}                 # the importer, not only the reader
    assert {p.param for p in pts} == {"user"}
    assert ("/app/q.php", "GET", "answer", "password control") in skipped


# --- T4/T5/T26/T6: which password forms come in --------------------------------------
def _form(html, page=BASE + "p.php"):
    return {**_rec(html, page=page)}


@pytest.mark.parametrize("html", [
    "<form method=post><input name=u><input type=password name=p1>"
    "<input type=password name=p2></form>",                                   # >= 2
    "<form method=post><input name=u><input type=password name=password_new></form>",
    "<form method=post><input name=u><input type=password name=newpassword></form>",
    "<form method=post><input name=u><input type=password name=pwd_confirm></form>",
    "<form method=post><input name=u><input type=password name=old_password></form>",
    "<form method=post><input name=u><input type=password name=current_pwd></form>",
    "<form method=post action='/account/change_password.php'><input name=u>"
    "<input type=password name=password></form>",
    "<form method=post><input name=u><input type=password name=password>"
    "<button name=action value=change>Go</button></form>",
    # reviewer B-R3: the admin set-password shape, and each of its signals alone
    "<form method=post action='/admin/users/12'><input name=username>"
    "<input type=password name=password><input type=hidden name=user_id value=12>"
    "<button name=op value=save>Save</button></form>",
    "<form method=post action='/admin/x'><input name=u><input type=password name=password>"
    "</form>",
    "<form method=post action='/users/12'><input name=u><input type=password name=password>"
    "</form>",
    "<form method=post action='/x'><input name=u><input type=password name=password>"
    "<input type=hidden name=user_id value=12></form>",
    "<form method=post action='/x'><input name=u><input type=password name=password>"
    "<button name=op value=save>Go</button></form>",
    "<form method=post action='/account/profile'><input name=username>"
    "<input type=password name=password></form>",
    "<form method=post action='/manage/x'><input name=u><input type=password name=password>"
    "</form>",
    # bWAPP's six credential changers (PA-0111(3): a captured third-party shape)
    "<form method=post><input type=password name=password_curr>"
    "<input type=password name=password_new><input type=password name=password_conf>"
    "<button name=action value=change>Change</button></form>",
    "<form method=get><input type=password name=password_curr>"
    "<input type=password name=password_new><input type=password name=password_conf>"
    "<button name=action value=change>Change</button></form>",
    "<form method=post><input type=password name=password_new>"
    "<input type=password name=password_conf>"
    "<button name=action value=change>Change</button></form>",
    "<form method=post><input name=login><input name=email>"
    "<input type=password name=password><input type=password name=password_conf>"
    "<input name=secret><button name=action value=create>Create</button></form>",
])
def test_credential_change_forms_stay_excluded(html):
    reason = form_skip_reason(_form(html))
    assert reason and reason.startswith("credential-change")


@pytest.mark.parametrize("html", [
    "<form method=post><input name=login><input type=password name=password>"
    "<input name=server><input name=dn><button name=form value=submit>Go</button></form>",
    "<form method=post><input name=login><input type=password name=password>"
    "<input name=captcha_user><button name=form value=submit>Login</button></form>",
    "<form method=post><input type=password name=password><textarea name=t></textarea>"
    "</form>",
    "<form method=post><input type=password name=password></form>",          # no user
])
def test_password_forms_that_are_not_login_forms_stay_excluded(html):
    reason = form_skip_reason(_form(html))
    assert reason and "not a login form" in reason


#: bWAPP v2.2's login-shaped forms (from its source), action pages as shipped.
BWAPP_LOGIN_FORMS = {
    page: (f"<form method=post action='/bWAPP/{page}'><input name=login>"
           "<input type=password name=password>"
           "<button type=submit name=form value=submit>Login</button></form>")
    for page in ("sqli_3.php", "sqli_16.php", "xss_login.php", "ba_insecure_login_1.php",
                 "ba_insecure_login_3.php",
                 "insuff_transp_layer_protect_1.php", "sm_mitm_1.php")}
BWAPP_LOGIN_FORMS["xmli_1.php"] = BWAPP_LOGIN_FORMS["sqli_3.php"].replace(
    "post", "get").replace("sqli_3", "xmli_1")
BWAPP_LOGIN_FORMS["ba_insecure_login_2.php"] = (
    "<form action='/bWAPP/ba_insecure_login_2.php'><input name=name value=brucebanner>"
    "<input type=password name=passphrase><button type=button name=button>Unlock</button>"
    "</form>")


#: Accepted false positives of the action-path tokens (FR-FUZZ-44): two bWAPP login
#: pages are named after passwords (``pwd`` marks credential pages). No current oracle
#: confirms their bugs (weak password, password attacks), so nothing is lost.
BWAPP_PWD_NAMED = {
    "ba_weak_pwd.php": BWAPP_LOGIN_FORMS["sqli_3.php"].replace("sqli_3", "ba_weak_pwd"),
    "ba_pwd_attacks_2.php": (
        "<form method=post action='/bWAPP/ba_pwd_attacks_2.php'><input name=login>"
        "<input type=password name=password><input type=hidden name=salt value=abc>"
        "<button type=submit name=form value=submit>Login</button></form>")}


def test_bwapps_login_shaped_forms_are_imported_and_isolated(tmp_path):
    assert len(BWAPP_LOGIN_FORMS) == 9
    for page, html in BWAPP_PWD_NAMED.items():
        assert form_skip_reason(_form(html, "http://h/bWAPP/" + page)) == \
            "credential-change form (action has 'pwd')"
    for page, html in BWAPP_LOGIN_FORMS.items():
        assert form_skip_reason(_form(html, "http://h/bWAPP/" + page)) is None, page
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(h, "http://h/bWAPP/" + p)
                                        for p, h in BWAPP_LOGIN_FORMS.items()])
        keys = isolated_paths_from_store(store, run, "http://h/bWAPP/")
    assert keys == {url_key("http://h/bWAPP/" + p) for p in BWAPP_LOGIN_FORMS}


def test_the_phase1_unsafe_cases_other_than_login_forms_still_skip():
    login = "<form method=post><input name=login><input type=password name=password></form>"
    assert form_skip_reason(_form(login)) is None                   # lifted (FR-FUZZ-44)


# --- T7: fail-closed defaults --------------------------------------------------------
def test_without_isolated_the_points_are_dropped_and_reported(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")],
                      pages=["http://localhost/app/sqli_3.php?debug=1"])
        skipped: list = []
        pts = injection_points_from_store(store, run, BASE, skipped=skipped)
    assert pts == []                          # the GET link on that path too
    assert {(s[2], s[3]) for s in skipped} == {
        ("login", "needs an isolated session (login form)"),
        ("debug", "needs an isolated session (login form)")}


def test_greybox_never_gets_login_form_points(tmp_path):
    from fuzzlab.greybox.run import points_from_store
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        skipped: list = []
        assert points_from_store(store, run, BASE, skipped=skipped) == []
    assert any("isolated session" in s[3] for s in skipped)


class _NoIsolate:
    def __init__(self):
        self.urls = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        from fuzzlab.oracle.probe import Probe
        self.urls.append(url)
        return Probe(200, "ok")


def test_a_sender_without_isolate_never_gets_them(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        sender = _NoIsolate()
        result = _auto(store, run, sender)
    assert sender.urls == []
    assert any("cannot provide one" in s[3] for s in result.metrics["skipped_points"])


def test_the_requests_sender_is_isolated_by_construction():
    s = RequestsProbeSender(session=type("S", (), {"cookies": {}, "request": None})())
    s.isolate([BASE + "sqli_3.php"])
    assert s.isolated_copy_logins() == 0 and s.isolation_report()["paths"] == 1


# --- T8: the auth-endpoint rule wins -------------------------------------------------
def test_an_auth_endpoint_form_stays_anonymous_and_needs_no_isolated_login():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([LOGIN_PAGE])
    sender.send(LOGIN_PAGE, "login", "'", method="POST", location="body",
                entries=[("login", "'"), ("password", ""), ("form", "submit")])
    assert app.requests[-1][2] is None                     # no session at all
    assert app.login_posts == 1 and sender.isolated_copy_logins() == 0
    assert sender.auth_endpoint_anonymous_sends == 1


# --- T9/T10/T11/T21: sessions per path, and their failures -----------------------------
def _probe_form(sender, page="sqli_3.php", login="'"):
    return sender.send(BASE + page, "login", login, method="POST", location="body",
                       entries=[("login", login), ("password", ""), ("form", "submit")])


def test_one_isolated_session_per_path_reused_for_the_run():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php"])
    _probe_form(sender)
    _probe_form(sender, "sqli_16.php")
    _probe_form(sender)
    assert app.login_posts == 3                            # main + one per path
    sids = {r[1]: r[2] for r in app.requests}
    assert len({sids["/app/sqli_3.php"], sids["/app/sqli_16.php"], _main_sid(app)}) == 3
    labels = {f"admin#isolated:{n}" for n in (1, 2)}
    assert {c.label for c in sender._all_copies} == labels
    assert sender.isolation_report()["verifications"] == 1    # after the first only


def test_a_rejected_isolated_login_falls_back_to_anonymous_once():
    app = FakeApp(reject_copies=True)
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender)
    _probe_form(sender)
    to_form = [r for r in app.requests if r[1] == "/app/sqli_3.php"]
    assert [r[2] for r in to_form] == [None, None]          # anonymous, both
    assert app.login_posts == 2                             # main + 1 attempt, no retry
    report = sender.isolation_report()
    assert report["failures"][0]["path"] == "/app/sqli_3.php"
    assert report["failed_logins"] == 1 and report["breaker"] is None
    assert app.sessions[_main_sid(app)] == "admin"


def test_an_identical_session_id_is_not_isolation():
    app = FakeApp(sid_mode="same_for_all")
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender)
    assert [r[2] for r in app.requests if r[1] == "/app/sqli_3.php"] == [None]
    reason = sender.isolation_report()["failures"][0]["reason"]
    assert "not distinct from the run's session" in reason


def test_a_copy_must_differ_from_every_live_copy():
    """A1: a server handing every copy the same id (not the run's) is caught at path 2."""
    app = FakeApp(sid_mode="same_for_copies")
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php"])
    _probe_form(sender)
    _probe_form(sender, "sqli_16.php")
    first = [r[2] for r in app.requests if r[1] == "/app/sqli_3.php"]
    second = [r[2] for r in app.requests if r[1] == "/app/sqli_16.php"]
    assert first == [app.issued[1]] and second == [None]
    failures = sender.isolation_report()["failures"]
    assert [f["path"] for f in failures] == ["/app/sqli_16.php"]
    assert "admin#isolated:1" in failures[0]["reason"]


def test_rejected_copy_logins_stop_after_two_attempts():
    """B-R1: the failed-login breaker."""
    app = FakeApp(reject_copies=True)
    _mgr, _client, sender = _seam(app)
    pages = ["sqli_3.php", "sqli_16.php", "xss_login.php"]
    sender.isolate([BASE + p for p in pages])
    for p in pages:
        _probe_form(sender, p)
    assert app.login_posts == 3                            # main + exactly 2 attempts
    report = sender.isolation_report()
    assert report["breaker"]["trip"] == "failed-logins"
    assert sorted(f["path"] for f in report["failures"]) == sorted(
        "/app/" + p for p in pages)
    assert all(r[2] is None for r in app.requests if r[1] != "/app/")
    assert app.sessions[_main_sid(app)] == "admin"


# --- T12/T14/T15/T16: persistence, budget, sub-path, transport -------------------------
def test_the_isolated_session_is_never_persisted(tmp_path):
    app = FakeApp()
    with Store(tmp_path / "u.db") as store:
        _mgr, _client, sender = _seam(app, store=store)
        sender.isolate([BASE + "sqli_3.php"])
        _probe_form(sender)
        copy = sender._all_copies[0].manager
        # the copy is logged out (its own observe): nothing reaches the store
        copy.observe(Request("GET", BASE + "x.php"), Response(401, {}, b"", 1.0),
                     copy.label)
        rows = store.all_session_states()
    assert len(rows) == 1 and rows[0]["identity"] == "admin" and rows[0]["valid"] == 1
    assert copy._store is None


def test_isolated_sends_spend_the_runs_budget():
    from fuzzlab.core.budget import BudgetExceeded
    app = FakeApp()
    budget = RequestBudget(3)
    _mgr, _client, sender = _seam(app, budget=budget)
    sender.isolate([BASE + "sqli_3.php"])
    for _ in range(3):
        _probe_form(sender, login="x")
    with pytest.raises(BudgetExceeded):
        _probe_form(sender, login="x")
    assert budget.used() == 3


def test_isolated_login_uses_the_operators_sub_path_base():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender)
    assert sender.isolated_copy_logins() == 1
    assert all(path.startswith("/app/") for path, _sid in app.fetcher_gets)


def test_an_https_isolated_session_is_never_sent_over_http():
    app = FakeApp()
    _mgr, _client, sender = _seam(app, base="https://localhost/app/")
    sender.isolate(["https://localhost/app/sqli_3.php", "http://localhost/app/sqli_3.php"])
    sender.send("https://localhost/app/sqli_3.php", "login", "x", method="POST",
                location="body", entries=[("login", "x"), ("form", "submit")])
    with pytest.raises(SessionAuthError, match="plain http"):
        sender.send("http://localhost/app/sqli_3.php", "login", "x", method="POST",
                    location="body", entries=[("login", "x"), ("form", "submit")])


# --- T17/T25: the copy itself --------------------------------------------------------
def test_isolated_copy_shares_no_mutable_state():
    app = FakeApp()
    main = SessionManager(_store(), scope_hosts=["localhost"],
                          fetch_factory=app.fetch_factory(), auth_origins=["http://a:1"])
    main.ensure("localhost", "admin", BASE, operator=True)
    main.add_logout_listener(lambda h, i: None)
    copy = main.isolated_copy("admin", ordinal=1)
    for attr in ("_state", "_auth_endpoints", "_locks", "_failures", "_persisted",
                 "_attempts", "_logout_listeners", "_copies", "_scope", "_bases",
                 "_operator_bases", "_auth_origins"):
        assert getattr(copy, attr) is not getattr(main, attr), attr
    assert copy._state == {} and copy._logout_listeners == [] and copy._store is None
    assert copy._scope == main._scope and copy._bases == main._bases
    assert copy._auth_origins == main._auth_origins
    copy._scope.add("elsewhere")
    assert "elsewhere" not in main._scope
    assert copy.label == "admin#isolated:1" and copy in main._copies
    with pytest.raises(SessionAuthError):
        copy.adopt(SessionState("localhost", "admin", kind="cookie", cookies={"a": "b"}))
    main.release_copy(copy)
    assert copy not in main._copies


def test_isolated_copy_is_built_through_init_not_copy_copy():
    src = (ROOT / "fuzzlab/session/manager.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "isolated_copy")
    names = {getattr(c.func, "attr", getattr(c.func, "id", None))
             for c in ast.walk(fn) if isinstance(c, ast.Call)}
    assert "SessionManager" in names and not names & {"copy", "deepcopy"}


def test_a_copy_refuses_any_identity_but_its_label():
    app = FakeApp()
    main = SessionManager(_store(), scope_hosts=["localhost"],
                          fetch_factory=app.fetch_factory())
    main.ensure("localhost", "admin", BASE, operator=True)
    copy = main.isolated_copy("admin", ordinal=1)
    for identity in ("admin", "admin#isolated:2", "anonymous"):
        req = Request("GET", BASE + "x.php", identity=identity)
        with pytest.raises(SessionAuthError, match="refuses"):
            copy.prepare(req, identity)
        assert "Cookie" not in req.headers
    req = Request("GET", BASE + "x.php", identity="admin#isolated:1")
    copy.prepare(req, "admin#isolated:1")                  # its own label: logged in
    assert _sid_of(req.headers["Cookie"]) == app.issued[-1] != app.issued[0]


def test_a_logout_seen_by_a_copy_is_not_passed_to_the_main_listener():
    app = FakeApp()
    main = SessionManager(_store(), scope_hosts=["localhost"],
                          fetch_factory=app.fetch_factory())
    main.ensure("localhost", "admin", BASE, operator=True)
    seen = []
    main.add_logout_listener(lambda h, i: seen.append((h, i)))
    copy = main.isolated_copy("admin", ordinal=1)
    copy.ensure("localhost", "admin", BASE)
    copy.observe(Request("GET", BASE + "x.php"), Response(401, {}, b"", 1.0),
                 copy.label)
    assert not copy._state[("localhost", "admin")].valid and seen == []


# --- T22/T23: distinctness by value; no secrets in messages ---------------------------
def _cookie_state(**cookies):
    return SessionState("h", "u", kind="cookie", cookies=dict(cookies))


APPSID = "9f86d081884c7d659a2feaa0c55ad015"


def test_an_equal_identifier_cookie_under_any_name_is_not_distinct():
    from fuzzlab.core.redaction import is_sensitive_name, looks_like_identifier
    assert not is_sensitive_name("appsid")                       # precondition
    new = _cookie_state(appsid=APPSID, csrftoken="new-token-value-1")
    old = _cookie_state(appsid=APPSID, csrftoken="old-token-value-2")
    assert "'appsid'" in distinctness_problem(new, old)
    short = "a8Kq2Zp9xW"                                          # R2 of the shared rule
    assert len(short) < DISTINCT_MIN_LEN and looks_like_identifier(short)
    assert distinctness_problem(_cookie_state(tok=short, PHPSESSID="1" * 26),
                                _cookie_state(tok=short, PHPSESSID="2" * 26))
    assert not looks_like_identifier("abc") and len("abc") < DISTINCT_MIN_LEN
    assert "'sid'" in distinctness_problem(_cookie_state(sid="abc", other="1"),
                                           _cookie_state(sid="abc", other="2"))
    assert not looks_like_identifier("0")
    assert distinctness_problem(_cookie_state(security_level="0", PHPSESSID="a" * 26),
                                _cookie_state(security_level="0", PHPSESSID="b" * 26)) \
        is None
    longword = "abcdefghijklmnopq"                                # local length rule
    assert not looks_like_identifier(longword) and len(longword) >= DISTINCT_MIN_LEN
    assert distinctness_problem(_cookie_state(pref=longword, PHPSESSID="a" * 26),
                                _cookie_state(pref=longword, PHPSESSID="b" * 26))
    basic = SessionState("h", "u", kind="basic", headers={"Authorization": "Basic x"})
    assert distinctness_problem(basic, basic) is None
    assert distinctness_problem(_cookie_state(lang="en"), _cookie_state(lang="en")) \
        == "every credential is the same"
    assert distinctness_problem(_cookie_state(), _cookie_state(a="b"))


def test_the_distinctness_rule_calls_the_shared_predicate(monkeypatch):
    """Reviewer B: patch the name session.manager actually calls."""
    new = _cookie_state(lang="en", PHPSESSID="a" * 26)
    old = _cookie_state(lang="en", PHPSESSID="b" * 26)
    assert distinctness_problem(new, old) is None
    monkeypatch.setattr(manager_mod, "looks_like_identifier", lambda v: v == "en")
    assert "'lang'" in distinctness_problem(new, old)
    src = ast.parse((ROOT / "fuzzlab/session/manager.py").read_text())
    local = [n.name for n in ast.walk(src) if isinstance(n, ast.FunctionDef)
             and ("entropy" in n.name.lower() or n.name.lower() == "looks_like_identifier")]
    assert local == []


def test_isolation_errors_and_report_carry_no_secret_values(caplog):
    app = FakeApp(sid_mode="same_for_all")
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    with caplog.at_level("DEBUG"):
        _probe_form(sender)
    report = json.dumps(sender.isolation_report())
    secrets = {app.issued[0], "admin123"}
    assert not any(s in report or s in caplog.text for s in secrets)
    exc = SessionIsolationError("x")
    new = _cookie_state(appsid=APPSID, csrftoken="tok-new-123456")
    problem = distinctness_problem(new, _cookie_state(appsid=APPSID, csrftoken="t"))
    assert APPSID not in problem and "tok-new-123456" not in problem and str(exc) == "x"


# --- T24: flows are labelled ---------------------------------------------------------
def test_isolated_sends_are_recorded_under_their_own_label(tmp_path):
    app = FakeApp(reject_copies=False)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "localhost")
        _mgr, _client, sender = _seam(app, store=store, run_id=run)
        sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php", LOGIN_PAGE])
        _probe_form(sender)
        _probe_form(sender, "sqli_16.php")
        sender.send(BASE + "other.php", "q", "1")
        sender.send(LOGIN_PAGE, "login", "x")
        rows = store.conn.execute("SELECT identity, url FROM flow ORDER BY id").fetchall()
    by_path = {urlsplit(r["url"]).path: r["identity"] for r in rows}
    assert by_path == {"/app/sqli_3.php": "admin#isolated:1",
                       "/app/sqli_16.php": "admin#isolated:2",
                       "/app/other.php": "admin", "/app/login.php": "anonymous"}


# --- T13/T30/breaker: single-session apps --------------------------------------------
def test_a_single_session_app_trips_the_breaker_after_one_copy_login():
    app = FakeApp(single_session="eager")
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php"])
    _probe_form(sender)
    _probe_form(sender, "sqli_16.php")
    sender.send(BASE + "whoami.php", "x", "1")
    sender.send(BASE + "whoami.php", "x", "1")
    report = sender.isolation_report()
    assert report["breaker"]["trip"] == "single-session"
    assert sender.isolated_copy_logins() == 1                    # exactly one copy login
    assert app.login_posts == 3                                   # + one main re-login
    copy_sid = app.issued[1]
    assert all(r[2] != copy_sid for r in app.requests)           # never carried a probe
    form_sends = [r[2] for r in app.requests if r[1].startswith("/app/sqli_")]
    assert form_sends == [None, None]
    assert [r[2] for r in app.requests if r[1] == "/app/whoami.php"] == \
        [app.issued[2], app.issued[2]]                            # main recovered once


def test_a_lazy_single_session_logout_trips_the_breaker():
    """Reviewer B: the base page is public, so verify_live passes; the app invalidates
    the other session only on that session's next request. Run under a join timeout so
    a lock-order deadlock fails instead of hanging the suite."""
    app = FakeApp(single_session="lazy", public_base=True)
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php"])
    out: dict = {}

    def scenario():
        _probe_form(sender)                                       # copy 1 + verify (ok)
        out["after_copy"] = sender.isolation_report()["breaker"]
        sender.send(BASE + "page.php", "x", "1")                  # main: logged out
        sender.send(BASE + "page.php", "x", "1")                  # main re-logs in
        _probe_form(sender, "sqli_16.php")                        # no copy login now
        out["done"] = True
    worker = threading.Thread(target=scenario, daemon=True)
    worker.start()
    worker.join(timeout=20)
    assert not worker.is_alive(), "deadlock: the scenario did not finish"
    assert out.get("done") and out["after_copy"] is None
    report = sender.isolation_report()
    assert report["breaker"]["trip"] == "single-session"
    assert sender._copies == {} and _mgr._copies == []        # dropped
    assert report["verifications"] == 1
    assert sender.isolated_copy_logins() == 1                    # no further copy logins
    assert app.login_posts == 3                                   # exactly one re-login
    assert [r[2] for r in app.requests if r[1] == "/app/sqli_16.php"] == [None]
    main_sids = {app.issued[0], app.issued[2]}
    assert all(r[2] not in main_sids for r in app.requests if r[1].startswith("/app/sqli"))


def test_the_listener_is_registered_early_once_and_inert_until_a_copy_is_live():
    app = FakeApp(reject_copies=True)
    mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender)                       # registers, but the copy login fails
    _probe_form(sender)
    assert mgr._logout_listeners == [sender._on_main_logout]   # registered once
    sender._on_main_logout("localhost", "admin")               # no live copy: inert
    assert sender.isolation_report()["breaker"] is None


def test_the_listener_trips_only_for_the_runs_host_and_identity():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender)                                        # a live copy
    sender._on_main_logout("other.host", "admin")
    sender._on_main_logout("localhost", "user")
    assert sender.isolation_report()["breaker"] is None
    sender._on_main_logout("localhost", "admin")
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"


def test_a_copys_logout_never_reaches_the_main_listener():
    """T31: the copy is logged out by its own probe and re-logs in; the main session's
    listener is not told and the breaker stays off."""
    app = FakeApp()
    mgr, _client, sender = _seam(app)
    told = []
    mgr.add_logout_listener(lambda h, i: told.append((h, i)))
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")
    app.sessions.pop(app.issued[1])                            # the server drops the copy
    _probe_form(sender, login="x")                             # 302 -> copy logout
    _probe_form(sender, login="x")                             # copy re-logs in
    assert told == [] and sender.isolation_report()["breaker"] is None
    assert sender.isolated_copy_logins() == 2
    assert sender.isolation_report()["verifications"] == 2     # re-login re-verifies


def test_copy_logins_and_verify_live_never_pass_through_the_main_observe():
    """T32 (lane A's contract): copies are separate managers."""
    app = FakeApp()
    mgr, _client, sender = _seam(app)
    calls = []
    real = mgr.observe
    mgr.observe = lambda req, resp, identity: (calls.append(req.url), real(req, resp,
                                                                         identity))[1]
    told = []
    mgr.add_logout_listener(lambda h, i: told.append(i))
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")                             # copy login + verify_live
    app.sessions.pop(app.issued[1])
    _probe_form(sender, login="x")
    _probe_form(sender, login="x")                             # copy re-login
    assert calls == [] and told == []
    assert sender.isolated_copy_logins() == 2 == len(app.issued) - 1


# --- T18/T19: the store ---------------------------------------------------------------
def test_malformed_password_fields_fail_closed(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        store.conn.execute("UPDATE form SET password_fields='{\"x\": 1}'")
        skipped: list = []
        isolated: set = set()
        pts = injection_points_from_store(store, run, BASE, skipped=skipped,
                                          isolated=isolated)
    assert pts == [] and isolated == {url_key(BASE + "sqli_3.php")}
    assert {s[3] for s in skipped} == {"malformed form row (password_fields)"}


def test_migration_21_adds_password_fields_and_legacy_rows_read_empty(tmp_path):
    from fuzzlab.core import migrations
    head = max(v for v, _ in migrations.MIGRATIONS)
    path = tmp_path / "legacy.db"
    with Store(path) as store:                    # turn it back into a v20 store
        run = store.start_run("auto", "h")
        store.conn.execute("ALTER TABLE form DROP COLUMN password_fields")
        store.conn.execute("DELETE FROM schema_version WHERE version >= 21")
        eid = store.conn.execute("INSERT INTO endpoint (run_id, url, method, source) "
                                 "VALUES (?,?,?,?)", (run, "/a", "POST", "form")).lastrowid
        store.conn.execute("INSERT INTO form (run_id, endpoint_id, enctype, entries) "
                           "VALUES (?,?,?,?)", (run, eid, "", "[]"))     # a v20 row
        store.conn.commit()
    with Store(path) as store:                    # upgraded on open
        assert store.schema_version() == head >= 21
        cols = {r[1]: r for r in store.conn.execute("PRAGMA table_info(form)")}
        assert cols["password_fields"][4] == "'[]'"            # the default
        assert store.conn.execute("SELECT password_fields FROM form").fetchone()[0] == "[]"
        assert isolated_paths_from_store(store, run, "http://h/") == frozenset()


# --- T28/T29: fingerprint logins, verify_live -----------------------------------------
def test_a_fingerprint_login_is_counted(tmp_path):
    app = FakeApp()
    with Store(tmp_path / "u.db") as store:
        run = _import(tmp_path, store, [(SQLI3, BASE + "sqli_3.php")])
        _mgr, _client, sender = _seam(app)
        result = _auto(store, run, sender)
    report = result.metrics["isolated_sessions"]
    assert report["first_copy_login_send"] == 1           # the pipeline's baseline send
    assert report["logins"] == 1 and report["verifications"] == 1
    first = next(r for r in app.requests if r[1] == "/app/sqli_3.php")
    assert first[0] == "GET" and first[2] == app.issued[1]


def test_verify_live_carries_the_session_cookie_and_marks_a_dead_session(tmp_path):
    app = FakeApp()
    with Store(tmp_path / "u.db") as store:
        mgr = SessionManager(_store(), scope_hosts=["localhost"], store=store,
                             fetch_factory=app.fetch_factory())
        mgr.ensure("localhost", "admin", BASE, operator=True)
        app.fetcher_gets.clear()
        assert mgr.verify_live("localhost", "admin", BASE)
        assert app.fetcher_gets[0] == ("/app/", app.issued[0])
        app.sessions.clear()
        assert not mgr.verify_live("localhost", "admin", BASE)
        assert not mgr._state[("localhost", "admin")].valid
        assert store.all_session_states()[0]["valid"] == 0
        assert not mgr.verify_live("localhost", "nobody", BASE)


# --- make_probe_sender wires the factory onto the run's budget ------------------------
def test_make_probe_sender_wires_an_isolated_client_on_the_runs_budget(monkeypatch):
    from fuzzlab.tools import authhttp

    class FakeMgr:
        pass
    budget = RequestBudget(7)
    monkeypatch.setattr(authhttp, "_build_parts",
                        lambda url, timeout, store_path=None: (
                            FakeMgr(), "client", budget, ["localhost"]))
    sender = probesender.make_probe_sender(BASE, "admin")
    copy_client = sender._isolated_client(FakeMgr())
    assert isinstance(copy_client, HttpClient) and copy_client._budget is budget
    assert copy_client._scope == {"localhost"}


# --- the CredentialStore fake from the shared tests still logs the main in -----------
def test_the_shared_cookie_fetcher_gives_every_login_the_same_id():
    """Why the default test fetcher cannot isolate (it is the T11 shape)."""
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    mgr.ensure("localhost", "admin", "http://localhost")
    copy = mgr.isolated_copy("admin", ordinal=1)
    with pytest.raises(SessionIsolationError):
        copy.ensure("localhost", "admin", "http://localhost")


def test_the_isolated_session_cap_sends_further_paths_anonymously(monkeypatch):
    monkeypatch.setattr(probesender, "MAX_ISOLATED_SESSIONS", 1)
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php", BASE + "sqli_16.php"])
    _probe_form(sender, login="x")
    _probe_form(sender, "sqli_16.php", login="x")
    assert [r[2] for r in app.requests if r[1] == "/app/sqli_16.php"] == [None]
    assert sender.isolation_report()["failures"] == [
        {"path": "/app/sqli_16.php", "label": None, "reason": "isolated-session cap"}]
    assert app.login_posts == 2


def test_a_copys_login_cap_counts_attempts():
    """M08: ``max_logins`` attempts, then `LoginCapReached` (never one more)."""
    from fuzzlab.session.manager import LoginCapReached
    app = FakeApp()
    main = SessionManager(_store(), scope_hosts=["localhost"],
                          fetch_factory=app.fetch_factory())
    main.ensure("localhost", "admin", BASE, operator=True)
    copy = main.isolated_copy("admin", ordinal=1, max_logins=1)
    copy.ensure("localhost", "admin", BASE)
    copy._state[("localhost", "admin")].valid = False
    with pytest.raises(LoginCapReached):
        copy.ensure("localhost", "admin", BASE)
    assert copy.login_attempts() == 1 and app.login_posts == 2



# --- code review (reviewers A/B): the fallback, verify_live's hops, reasons -----------
def test_a_failed_copy_relogin_falls_back_with_no_session_at_all():
    """Must-fix 1: a live copy is logged out, then its re-login is rejected; the
    fallback send carries no Cookie (never the run's session)."""
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")                             # the copy logs in
    app.reject_copies = True
    app.sessions.pop(app.issued[1])                            # the server drops it
    _probe_form(sender, login="x")                             # 302: the copy logs out
    before = sender.isolation_report()["anonymous_sends"]
    _probe_form(sender, login="x")                             # re-login rejected
    last = [r for r in app.requests if r[1] == "/app/sqli_3.php"][-1]
    assert "Cookie" not in last[4] and last[2] is None
    assert all(r[2] != app.issued[0] for r in app.requests if r[1] == "/app/sqli_3.php")
    report = sender.isolation_report()
    assert report["anonymous_sends"] == before + 1
    assert report["failures"] == [{"path": "/app/sqli_3.php", "label": "admin#isolated:1",
                                   "reason": "isolated login rejected"}]
    assert report["failed_logins"] == 1


def test_a_login_cap_does_not_count_toward_the_failed_logins_breaker():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")                             # copy login 1 of 3
    for _ in range(3):
        app.sessions.pop(app.issued[-1])
        _probe_form(sender, login="x")                         # the copy logs out
        _probe_form(sender, login="x")                         # re-login 2, 3, then cap
    report = sender.isolation_report()
    assert sender.isolated_copy_logins() == 3
    assert report["failed_logins"] == 0 and report["breaker"] is None
    assert report["failures"][0]["reason"] == "isolated login cap reached"
    assert [r for r in app.requests if r[1] == "/app/sqli_3.php"][-1][2] is None


def test_an_unapproved_hop_while_verifying_trips_the_breaker():
    app = FakeApp(cookie_redirect="http://evil.example/steal")
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"
    assert all(host != "evil.example" for host, _h in app.fetcher_hosts)
    assert [r[2] for r in app.requests if r[1] == "/app/sqli_3.php"] == [None]


def test_verify_live_carries_the_session_to_the_session_host_only():
    """Must-fix 2: the base 302s to a second, in-scope host; it is never fetched (so it
    gets no Cookie or Authorization), and verification fails closed."""
    app = FakeApp(cookie_redirect="http://other.host/app/")
    _mgr, _client, sender = _seam(app, scope=("localhost", "other.host"))
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")
    assert all(host != "other.host" for host, _h in app.fetcher_hosts)
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"
    session_gets = [h for host, h in app.fetcher_hosts if "Cookie" in h]
    assert session_gets and all(host == "localhost" for host, h in app.fetcher_hosts
                                if "Cookie" in h or "Authorization" in h)


def test_reasons_are_fixed_texts_never_a_failure_message(monkeypatch):
    """Should-fix 4: a token-bearing URL in a login error never reaches the report."""
    app = FakeApp()
    real = SessionManager._login

    def login(self, host, identity, base_url):
        if self._isolated_from is not None:
            raise SessionAuthError("could not detect a login from "
                                   "http://localhost/app/?token=SECRETTOKEN123456")
        return real(self, host, identity, base_url)
    monkeypatch.setattr(SessionManager, "_login", login)
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])
    _probe_form(sender, login="x")
    report = sender.isolation_report()
    assert "SECRETTOKEN123456" not in json.dumps(report)
    assert report["failures"][0]["reason"] == "isolated login rejected"


def test_a_login_cap_at_creation_does_not_count_either(monkeypatch):
    original = SessionManager.isolated_copy
    monkeypatch.setattr(SessionManager, "isolated_copy",
                        lambda self, identity, *, ordinal, max_logins=3: original(
                            self, identity, ordinal=ordinal, max_logins=0))
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    pages = ["sqli_3.php", "sqli_16.php", "xss_login.php"]
    sender.isolate([BASE + p for p in pages])
    for p in pages:
        _probe_form(sender, p, login="x")
    report = sender.isolation_report()
    assert report["failed_logins"] == 0 and report["breaker"] is None
    assert {f["reason"] for f in report["failures"]} == {"isolated login cap reached"}
    assert app.login_posts == 1                                # only the run's login
