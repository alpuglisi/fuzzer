"""FR-SESS-19 / FR-CRAWL-14: browser-driven SPA login detection and its adoption.

Pure tests first (the gates, the detector, repr, storage filtering, the driver env),
then real-Chromium tests against `tests._spa_login_fixture.LoginSpa`, a loopback fake of
Juice Shop's login (fail, never skip, under ``FUZZLAB_REQUIRE_BROWSER=1``). Nothing here
talks to any lab or other host: every server is test-started on 127.0.0.1, port 0.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid

import pytest

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.session import browserlogin
from fuzzlab.session.browserlogin import (LoginGate, account_endpoint_reason, carries,
                                          filter_storage_state, login_form_refusal,
                                          secret_forms)
from fuzzlab.session.manager import SessionAuthError, SessionManager
from fuzzlab.session.state import SessionState
from tests._spa_fixture import Recorder, chromium_or_skip, db_text, run_crawl
from tests._spa_login_fixture import PROTECTED, USER, LoginSpa
from tests.test_credentials import FakeBackend

HOST = "127.0.0.1"


# =====================================================================================
# Pure
# =====================================================================================
@pytest.mark.parametrize("where", ["url", "header", "body"])
def test_the_password_detector_sees_every_encoding(where):
    secret = "p@ss w0rd/é+"
    forms = secret_forms(secret, "alice")
    import base64
    from urllib.parse import quote, quote_plus
    encodings = [secret, quote(secret, safe=""), quote_plus(secret),
                 json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1],
                 base64.b64encode(secret.encode()).decode(),
                 base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                 base64.b64encode(f"alice:{secret}".encode()).decode()]
    for enc in encodings:
        url, headers, body = "http://h/x", {"a": "b"}, b"{}"
        if where == "url":
            url = "http://h/x?p=" + quote(enc, safe="")
        elif where == "header":
            headers = {"authorization": "Basic " + enc}
        else:
            body = json.dumps({"password": enc}, ensure_ascii=False).encode() \
                if enc != json.dumps(secret)[1:-1] else b'{"password":"' + enc.encode() + b'"}'
        assert carries(forms, url, headers, body), (where, enc)
    assert not carries(forms, "http://h/x?p=other", {"a": "b"}, b'{"password":"x"}')


def test_a_hashed_password_is_not_identified_so_only_the_gate_can_stop_it():
    """Spotting the password only identifies the login request (reviewer A1): a
    sha256(password) body is not seen, which is why the destination gate never
    depends on it (the real-browser test below sends one to another port)."""
    secret = "hunter2-" + uuid.uuid4().hex
    digest = hashlib.sha256(secret.encode()).hexdigest()
    assert not carries(secret_forms(secret), "http://h/l", {}, json.dumps(
        {"password": digest}).encode())


class _Dest:
    """A stand-in for the manager's `_credential_destination_ok`."""

    def __init__(self, allowed):
        self.allowed = allowed

    def __call__(self, url, base, *, floor_https=False):
        return url.startswith(self.allowed) and not (
            floor_https and url.startswith("http:"))


def test_the_window_gate_refuses_a_non_destination_only_in_the_window():
    """Item 1: before the first fill the login scope alone decides; from the fill on,
    every request (any method) must also be a credential destination. Here the
    operator's auth origin is http under an https base: in scope, but never a
    credential destination (the transport floor)."""
    from fuzzlab.session.manager import SessionManager
    mgr = SessionManager(None, scope_hosts=["app.example"],
                         auth_origins=["http://auth.example:8080"],
                         fetch_factory=lambda: None)
    gate = LoginGate(mgr._credential_destination_ok, "https://app.example/",
                     ["http://auth.example:8080"], forms=secret_forms("pw"))
    assert gate.in_scope("http://auth.example:8080/token")            # window closed
    assert gate.in_scope("https://app.example/rest/login")
    assert not gate.in_scope("https://other.example/x")              # never in scope
    gate.window_open = True
    assert not gate.in_scope("http://auth.example:8080/token")        # the window gate
    assert gate.in_scope("https://app.example/rest/login")
    assert gate.window_refusals == 1
    assert all("auth.example" in r and "/token" not in r for r in gate.refusals)


@pytest.mark.parametrize("url, refused", [
    ("http://h/api/Users", True), ("http://h/api/users/", True),
    ("http://h/register", True), ("http://h/api/v1/sign-up", True),
    ("http://h/signup", True), ("http://h/rest/user/reset-password", True),
    ("http://h/account/change", True), ("http://h/accounts", True),
    ("http://h/rest/user/login", False), ("http://h/api/users/login", False),
    ("http://h/api/accounts/session", False), ("http://h/rest/join", False),
    ("http://h/api/Usersettings", False),        # whole tokens only (PA-0122)
])
def test_account_endpoints_are_judged_by_whole_token(url, refused):
    assert (account_endpoint_reason(url) is not None) is refused


def _form(controls, button="Log in", aria="Login", action=None):
    return {"controls": controls, "button": button, "button_aria": aria,
            "button_icons": "exit_to_app", "action": action,
            "ids": [f"c{i}" for i in range(len(controls))], "button_id": "b",
            "autocomplete": [""] * len(controls)}


LOGIN = [("email", "text"), ("password", "password"), ("rememberMe", "checkbox")]


@pytest.mark.parametrize("form, route, expect", [
    (_form(LOGIN), "login", None),
    (_form([("email", "email"), ("password", "password")], button="Sign in", aria=""),
     "signin", None),
    (_form(LOGIN + [("passwordRepeat", "password")]), "login", "password controls"),
    (_form(LOGIN + [("captcha", "text")]), "login", "not login-shaped"),
    (_form([("password", "password")]), "login", "not login-shaped"),
    (_form(LOGIN, button="Sign up", aria=""), "login", "sign up"),
    (_form(LOGIN, button="Join", aria=""), "login", "join"),
    (_form(LOGIN, button="Enroll now", aria=""), "login", "enroll"),
    (_form(LOGIN, button="Create account", aria=""), "login", "create"),
    (_form(LOGIN), "register", "register"),
    (_form(LOGIN), "forgot-password", "forgot"),
    (_form(LOGIN, action="/users/new"), "login", "new"),
    (_form([("email", "text"), ("securityAnswer", "password")]), "login",
     "security answer"),
    (_form([("otp", "text"), ("password", "password")]), "login", "otp"),
    (_form([("email", "text"), ("confirmPassword", "password")]), "login", "confirm"),
    (_form(LOGIN, button="Log out", aria=""), "login", "destructive"),
    # forms phase 4 (G2d, CC-CRAWL-0024): ``exit_to_app`` is a destructive glyph, judged
    # text-first on a form's submitter; a glyph-only one (no text, no aria-label) is
    # refused. FORMS_JS never yields this shape from a page anyway: an icon-only button
    # with no aria-label keeps its raw text, ``exit_to_app``, refused on ``exit``.
    (_form(LOGIN, button="", aria="", ), "login", "destructive button icon"),
    (_form(LOGIN, button="exit_to_app", aria="", ), "login", "destructive button"),
])
def test_only_a_login_shaped_form_with_no_account_word_is_used(form, route, expect):
    why = login_form_refusal(form, route)
    if expect is None:
        assert why is None
    else:
        assert why is not None and expect in why, why


def test_the_request_side_gate_needs_the_window():
    """Since A-S1 the gate is on every write in the window, password or not."""
    gate = LoginGate(_Dest("http://h"), "http://h/", forms=secret_forms("s3cret"))
    body = json.dumps({"email": "a", "password": "s3cret"}).encode()
    assert gate.request_refusal("POST", "http://h/api/Users", {}, body) is None  # closed
    gate.window_open = True
    assert gate.request_refusal("POST", "http://h/api/Users", {}, b"{}")
    assert gate.request_refusal("POST", "http://h/rest/user/login", {}, body) is None
    assert gate.request_refusal("POST", "http://h/api/Users", {}, body)
    assert "s3cret" not in (gate.account_refusal or "")


def test_session_state_repr_and_str_hold_no_secret():
    """Item 8 (reviewer B6): cookies, headers, browser_state, probe: never in repr."""
    state = SessionState(HOST, "user", kind="bearer", cookies={"sid": "COOKIESECRET"},
                         headers={"Authorization": "Bearer TOKENSECRET"},
                         browser_state={"origins": [{"origin": "http://h", "localStorage":
                                                     [{"name": "t", "value": "LSSECRET"}]}]},
                         protected_probe="http://h/api/me?k=PROBESECRET",
                         probe_refusal_digest="DIGESTSECRET", valid=True)
    for text in (repr(state), str(state), f"{state}"):
        for secret in ("COOKIESECRET", "TOKENSECRET", "LSSECRET", "PROBESECRET",
                       "DIGESTSECRET"):
            assert secret not in text
    other = SessionState(HOST, "user", kind="bearer", cookies={"sid": "COOKIESECRET"},
                         headers={"Authorization": "Bearer TOKENSECRET"},
                         protected_probe="http://h/api/me?k=PROBESECRET",
                         probe_refusal_digest="DIGESTSECRET", valid=True)
    assert other == state                         # browser_state is not compared


def test_storage_state_adoption_keeps_in_scope_origins_only():
    """Item 7 (reviewer A7)."""
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    origins = origin_scope("http://127.0.0.1:3000/")
    in_scope = lambda u: in_origin_scope(u, origins)  # noqa: E731
    state = {"cookies": [{"name": "token", "value": "T", "domain": "127.0.0.1"},
                         {"name": "x", "value": "X", "domain": "auth.example"},
                         {"name": "y", "value": "Y", "domain": ".localhost"}],
             "origins": [{"origin": "http://127.0.0.1:3000", "localStorage":
                          [{"name": "token", "value": "T"}]},
                         {"origin": "http://127.0.0.1:4000", "localStorage":
                          [{"name": "token", "value": "OTHER"}]},
                         {"origin": "https://auth.example", "localStorage":
                          [{"name": "id", "value": "I"}]}]}
    kept = filter_storage_state(state, in_scope, ["http://localhost:3000/app/"])
    assert [c["name"] for c in kept["cookies"]] == ["token", "y"]       # loopback aliases
    assert kept["origins"] == [{"origin": "http://127.0.0.1:3000",
                                "localStorage": [{"name": "token", "value": "T"}]}]
    assert filter_storage_state(None, in_scope, []) == {"cookies": [], "origins": []}


def test_the_browser_login_is_off_for_a_fetcher_double_and_copied_to_copies():
    off = SessionManager(_creds("x"), scope_hosts=[HOST], fetch_factory=lambda: None)
    on = SessionManager(_creds("x"), scope_hosts=[HOST])
    assert off._browser_login is False and on._browser_login is True
    assert on.isolated_copy("user", ordinal=1)._browser_login is True
    assert off.isolated_copy("user", ordinal=1)._browser_login is False
    forced = SessionManager(_creds("x"), scope_hosts=[HOST], fetch_factory=lambda: None,
                            browser_login=True)
    assert forced._browser_login is True


def test_the_driver_starts_without_debug_logging(monkeypatch):
    """Item 9 (reviewer B8): Playwright's ``pw:api`` log prints a filled value."""
    monkeypatch.setenv("DEBUG", "pw:api")
    monkeypatch.setenv("PWDEBUG", "1")
    with browserlogin._driver_env_without_api_logs():
        assert "DEBUG" not in os.environ and "PWDEBUG" not in os.environ
    assert os.environ["DEBUG"] == "pw:api" and os.environ["PWDEBUG"] == "1"


def test_debugp_refuses_the_browser_login(monkeypatch):
    monkeypatch.setenv("DEBUGP", "1")
    with pytest.raises(browserlogin.BrowserLoginError, match="DEBUGP"):
        browserlogin.run(lambda *a, **k: True, "http://127.0.0.1:9/", _Cred("u", "p"))


class _Cred:
    def __init__(self, username, password):
        self.username, self.password = username, password


def test_a_failure_text_never_holds_the_password():
    secret = "S3CR3T-" + uuid.uuid4().hex
    forms = secret_forms(secret, "u")
    text = browserlogin._scrub(f"fill({secret!r}) and {json.dumps(secret)}", forms)
    assert secret not in text and "***" in text


def _recording(source: str) -> list[str]:
    """What in ``source`` would record the login: a HAR or video, tracing, a spider-DB
    or store writer, or an import of the crawler or the store (item 2)."""
    import ast
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            out += [k.arg for k in node.keywords
                    if k.arg and k.arg.startswith(("record_har", "record_video"))]
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in (
                    "record_request", "record_form", "mark_visited", "upsert_session_state",
                    "record_stats"):
                out.append(f.attr)
        if isinstance(node, ast.Attribute) and node.attr == "tracing":
            out.append("tracing")
        if isinstance(node, ast.ImportFrom) and node.module in (
                "fuzzlab.tools.spider", "fuzzlab.core.store"):
            out.append(node.module)
    return out


def test_the_login_context_records_nothing():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "fuzzlab" / "session"
           / "browserlogin.py").read_text()
    assert _recording(src) == []


def test_the_recording_guard_catches_synthetic_offenders():
    bad = ("from fuzzlab.tools.spider import StorageManager\n"
           "def f(b, s):\n"
           "    c = b.new_context(record_har_path='x.har', record_video_dir='v')\n"
           "    c.tracing.start(screenshots=True)\n"
           "    s.record_request(1, 2, 3, 4, 5, 6)\n")
    assert sorted(_recording(bad)) == sorted([
        "fuzzlab.tools.spider", "record_har_path", "record_video_dir", "tracing",
        "record_request"])


# =====================================================================================
# Real browser
# =====================================================================================
def _creds(password: str) -> CredentialStore:
    store = CredentialStore(backend=FakeBackend())
    store.set(HOST, "user", USER, password)
    return store


def _password() -> str:
    return "pw-" + uuid.uuid4().hex


@pytest.fixture
def chromium(monkeypatch):
    """Playwright and the pinned Chromium, or skip (a failure when required)."""
    chromium_or_skip(monkeypatch)


@pytest.fixture
def spa(chromium):
    labs = []

    def make(password, **kw):
        lab = LoginSpa(password, **kw)
        labs.append(lab)
        return lab
    try:
        yield make
    finally:
        for lab in labs:
            lab.close()


def _manager(lab, password, **kw) -> SessionManager:
    return SessionManager(_creds(password), scope_hosts=[HOST], **kw)


def _login(mgr, lab):
    try:
        return mgr.ensure(HOST, "user", lab.base, operator=True)
    except SessionAuthError as exc:
        if "could not be launched" in str(exc) or "driver did not start" in str(exc):
            from tests._browser import skip_or_fail
            skip_or_fail(f"chromium unavailable: {exc}")
        raise


def test_a_spa_login_is_detected_as_a_bearer_and_verified(spa):
    """``session print``'s path (`session_header`): a bearer from the JSON body, the
    protected probe found, ``verify_live`` true, the browser state kept in memory."""
    pw = _password()
    lab = spa(pw)
    mgr = _manager(lab, pw)
    state = _login(mgr, lab)
    token = state.headers["Authorization"][len("Bearer "):]
    assert state.kind == "bearer" and state.valid and token in lab.tokens
    assert mgr.session_header(HOST, "user", lab.base) == f"Authorization: Bearer {token}"
    assert state.protected_probe and state.protected_probe.startswith(lab.base)
    assert state.token_exp == 9999999999.0
    (origin,) = state.browser_state["origins"]
    assert {"name": "token", "value": token} in origin["localStorage"]
    assert mgr.verify_live(HOST, "user", lab.base) is True
    assert len(lab.seen("POST", "/rest/user/login")) == 1          # one click
    assert mgr.is_auth_endpoint(lab.base + "rest/user/login")
    assert not mgr.is_auth_endpoint(lab.base)                      # never the shell


def test_a_spa_under_a_sub_path_logs_in(spa):
    """PA-0113(3): the operator's base keeps its path (``/app/``); the app's script,
    login and protected probe all live under it."""
    pw = _password()
    lab = spa(pw, prefix="/app/")
    assert lab.base.endswith("/app/")
    mgr = _manager(lab, pw)
    state = _login(mgr, lab)
    assert state.kind == "bearer" and state.protected_probe.startswith(lab.base)
    assert state.login_url == lab.base + "rest/user/login"
    assert mgr.verify_live(HOST, "user", lab.base) is True
    assert len(lab.seen("POST", "/rest/user/login")) == 1


def test_revocation_makes_verify_live_false(spa):
    """Item 4: the shell is public, so only the protected probe sees a revoked token."""
    pw = _password()
    lab = spa(pw)
    mgr = _manager(lab, pw)
    _login(mgr, lab)
    assert mgr.verify_live(HOST, "user", lab.base) is True
    lab.revoke_all()
    assert mgr.verify_live(HOST, "user", lab.base) is False
    assert not mgr._state[(HOST, "user")].valid


def test_a_wrong_password_fails_loudly_and_stops_at_the_cap(spa):
    """Item 10: each browser login is an attempt (one click each) toward max_reauth."""
    lab = spa("the-right-one")
    mgr = _manager(lab, "a-wrong-" + uuid.uuid4().hex, max_reauth=2)
    for _ in range(2):
        with pytest.raises(SessionAuthError, match="rejected"):
            _login(mgr, lab)
    with pytest.raises(SessionAuthError, match="re-auth cap"):
        _login(mgr, lab)
    assert len(lab.seen("POST", "/rest/user/login")) == 2


@pytest.mark.parametrize("variant", ["other", "other_sha"])
def test_the_password_never_leaves_to_another_port(spa, variant):
    """Item 1: the login posts to another loopback port, plain or as sha256: refused
    in the route before it is sent (whether or not the password is recognisable),
    nothing arrives there, and the login fails loudly."""
    other = Recorder()
    try:
        pw = _password()
        lab = spa(pw, variant=variant, other_port=other.server.server_address[1])
        mgr = _manager(lab, pw)
        with pytest.raises(SessionAuthError, match="in the login window") as err:
            _login(mgr, lab)
        assert other.requests == []
        assert lab.seen("POST") == []
        assert pw not in str(err.value)
    finally:
        other.close()


def test_register_and_change_password_forms_on_the_login_route_are_never_used(spa):
    pw = _password()
    lab = spa(pw, variant="mixed")
    state = _login(_manager(lab, pw), lab)
    assert state.valid
    assert lab.seen("POST", "/api/Users") == []
    assert lab.seen("POST", "/rest/user/change-password") == []
    assert len(lab.seen("POST", "/rest/user/login")) == 1


def test_a_login_route_posting_to_api_users_creates_nothing(spa):
    """Item 3, request side: a one-password "Log in" form (login-shaped, no account
    word) whose request goes to /api/Users is aborted before it is sent."""
    pw = _password()
    lab = spa(pw, variant="users")
    with pytest.raises(SessionAuthError, match="account endpoint"):
        _login(_manager(lab, pw), lab)
    assert lab.seen("POST") == []


def test_a_sign_up_button_on_the_login_route_is_never_clicked(spa):
    """Item 3, form side: account words ("Sign up") refuse the form."""
    pw = _password()
    lab = spa(pw, variant="signup")
    with pytest.raises(SessionAuthError, match="sign up"):
        _login(_manager(lab, pw), lab)
    assert lab.seen("POST") == []


def test_a_form_that_is_not_login_shaped_is_never_used(spa):
    pw = _password()
    lab = spa(pw, variant="captcha")
    with pytest.raises(SessionAuthError, match="not login-shaped"):
        _login(_manager(lab, pw), lab)
    assert lab.seen("POST") == []


def test_the_login_context_is_closed_before_anything_else(spa):
    """Item 2: the login context closes right after its storage_state is captured, before
    the manager's differential (and so before any crawl context): with the app polling
    every 50 ms and each replay of the probe slowed down, no app request arrives after
    the first replay."""
    pw = _password()
    lab = spa(pw, poll=True, probe_delay=0.3)
    _login(_manager(lab, pw), lab)
    reqs = lab.seen()
    login_at = next(i for i, r in enumerate(reqs) if r[1] == "/rest/user/login")
    replays = [i for i, r in enumerate(reqs) if i > login_at and "x-from-app" not in r[2]]
    assert replays, "the differential replayed nothing"
    late = [r[1] for r in reqs[replays[0]:] if "x-from-app" in r[2]]
    assert late == []


def _live_descendants() -> set[int]:
    """Live (not zombie) descendant pids of this process, from /proc."""
    parent: dict[int, int] = {}
    state: dict[int, str] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        state[int(entry)], parent[int(entry)] = fields[0], int(fields[1])
    out, frontier = set(), {os.getpid()}
    while frontier:
        nxt = {pid for pid, pp in parent.items() if pp in frontier and pid not in out}
        out |= nxt
        frontier = nxt
    return {pid for pid in out if state.get(pid) != "Z"}


def test_the_login_browser_is_gone_when_the_login_returns(spa):
    """Item 2: the dedicated login browser (driver, Chromium and every child) is closed
    by the time ``ensure`` returns: nothing it started is still alive."""
    import time
    pw = _password()
    lab = spa(pw, poll=True)
    before = _live_descendants()
    _login(_manager(lab, pw), lab)
    deadline = time.monotonic() + 10
    while _live_descendants() - before and time.monotonic() < deadline:
        time.sleep(0.2)
    assert _live_descendants() - before == set()


def test_the_password_appears_nowhere(spa, tmp_path, caplog, capfd, monkeypatch):
    """Item 2 (and 9): a unique password never reaches the spider DB, the store, the
    logs (caplog and stderr, with ``DEBUG=pw:api`` set), an exception text or a repr."""
    from fuzzlab.core.store import Store
    from fuzzlab.tools.spider import LocalSpider
    monkeypatch.setenv("DEBUG", "pw:api")
    caplog.set_level(logging.DEBUG)
    pw = _password()
    lab = spa(pw)
    store_path = tmp_path / "store.db"
    store = Store(str(store_path))
    try:
        mgr = SessionManager(_creds(pw), scope_hosts=[HOST], store=store,
                             logger=logging.getLogger("fuzzlab.test"))
        state = _login(mgr, lab)
        db = str(tmp_path / "s.db")
        sp = LocalSpider(lab.base, max_depth=1, db_name=db, engine="playwright",
                         timeout_ms=10000, session_manager=mgr, identity="user")
        run_crawl(sp)
        bad = SessionManager(_creds(pw + "-wrong"), scope_hosts=[HOST])
        with pytest.raises(SessionAuthError) as err:
            _login(bad, lab)
    finally:
        store.close()
    out, errs = capfd.readouterr()
    texts = [caplog.text, out, errs, str(err.value), repr(err.value), repr(state),
             str(state), db_text(db), store_path.read_bytes().decode("latin-1")]
    for text in texts:
        assert pw not in text
    assert len(lab.seen("POST", "/rest/user/login")) == 2          # it did log in


def test_an_authenticated_crawl_sees_the_protected_route(spa, tmp_path):
    """FR-CRAWL-14: the crawl adopts the browser login (localStorage and cookie, in
    scope) and adds the bearer through the route only; the dashboard route renders the
    protected content."""
    from tests._spa_fixture import db_rows

    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw)
    mgr = _manager(lab, pw)
    db = str(tmp_path / "s.db")
    sp = LocalSpider(lab.base, max_depth=2, db_name=db, engine="playwright",
                     timeout_ms=10000, session_manager=mgr, identity="user")
    run_crawl(sp)
    content = " ".join(c or "" for (c,) in db_rows(db, "SELECT content FROM discovered_pages"))
    assert PROTECTED in content
    token = mgr._state[(HOST, "user")].headers["Authorization"]
    me = [r for r in lab.seen("GET", "/api/me") if "x-from-app" in r[2]]
    assert me and all(r[2].get("authorization") == token for r in me)
    assert len(lab.seen("POST", "/rest/user/login")) == 1


def test_the_crawls_session_check_catches_a_revoked_token(spa, tmp_path):
    """Item 4: a named submission makes the server revoke the token; the crawl's session
    check (`verify_live` on the protected probe) sees it and stops submitting."""
    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw, revoke_on_feedback=True)
    sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=10000,
                     session_manager=_manager(lab, pw), identity="user",
                     submit_spa_forms=["feedback", "contact"])
    run_crawl(sp)
    assert len(lab.seen("POST", "/api/feedback")) == 1
    assert sp.spa_submit_stopped and "no longer accepts" in sp.spa_submit_stopped
    assert lab.seen("POST", "/api/contact") == []


def test_a_submission_that_clears_local_storage_stops_submitting(spa, tmp_path):
    """Item 4 (reviewer B4): the notes form clears ``localStorage['token']`` while the
    server still accepts the token and the cookie is untouched: only the localStorage
    check sees it."""
    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw, clear_ls=True)
    sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=10000,
                     session_manager=_manager(lab, pw), identity="user",
                     submit_spa_forms=["notes", "contact"])
    run_crawl(sp)
    assert len(lab.seen("POST", "/api/notes")) == 1
    assert sp.spa_submit_stopped and "localStorage entry 'token'" in sp.spa_submit_stopped
    assert lab.seen("POST", "/api/contact") == []


def test_a_relogin_during_an_authenticated_crawl(spa, tmp_path, monkeypatch):
    """Item 5 (reviewer B5): the crawl's own sync Playwright is running when the session
    is lost and re-established; the browser login runs on its own worker thread, so it
    does not nest inside it."""
    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw)
    mgr = _manager(lab, pw)
    relogins = []
    original = LocalSpider._after_fetch

    def after_fetch(self, url, *a, **kw):
        if not relogins:
            mgr._state[(HOST, "user")].valid = False          # the session was lost
            relogins.append(mgr.ensure(HOST, "user", lab.base))   # inside the crawl
        return original(self, url, *a, **kw)
    monkeypatch.setattr(LocalSpider, "_after_fetch", after_fetch)
    sp = LocalSpider(lab.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=10000, session_manager=mgr,
                     identity="user")
    run_crawl(sp)
    assert relogins and relogins[0].valid
    assert len(lab.seen("POST", "/rest/user/login")) == 2


# =====================================================================================
# Code review round 1 (reviewers A and B)
# =====================================================================================
class _Req:
    def __init__(self, url, method="POST", body=b'{"x":1}'):
        self.url, self.method, self.post_data_buffer = url, method, body
        self.headers = {"content-type": "application/json"}

    def is_navigation_request(self):
        return False


class _Resp:
    def __init__(self, status=200, location=None):
        self.status = status
        self.headers = {"location": location} if location else {}


class _FakeRoute:
    def __init__(self, req, site):
        self.request, self.site, self.outcome, self.fetched = req, site, None, []

    def fetch(self, max_redirects=None, headers=None):
        self.fetched.append(self.request.url)
        return self.site.get(self.request.url, _Resp())

    def abort(self):
        self.outcome = "abort"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"


class _FakeApi:
    def __init__(self, site):
        self.site, self.calls = site, []

    def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
        self.calls.append(url)
        return self.site.get(url, _Resp())


def test_every_write_to_an_account_endpoint_is_refused_in_the_window():
    """A-S1: whatever the body (a hashed password, nothing recognisable), a write to an
    account endpoint in the window is refused; a read, or a write before the window,
    is not this gate's business."""
    gate = LoginGate(_Dest("http://h"), "http://h/", forms=secret_forms("s3cret"))
    digest = json.dumps({"password": hashlib.sha256(b"s3cret").hexdigest()}).encode()
    assert gate.request_refusal("POST", "http://h/api/Users", {}, digest) is None
    gate.window_open = True
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert gate.request_refusal(method, "http://h/api/Users", {}, digest), method
    assert gate.request_refusal("GET", "http://h/api/Users", {}, None) is None
    assert gate.request_refusal("POST", "http://h/rest/user/login", {}, digest) is None


def test_a_body_keeping_redirect_to_an_account_endpoint_is_refused_at_the_hop():
    """A-N2: the login POST answers 307 to /api/Users in the window: the hop (which
    would re-send the body) is refused before it is fetched."""
    from fuzzlab.tools.navguard import make_route_handler
    gate = LoginGate(_Dest("http://h"), "http://h/", forms=secret_forms("s3cret"))
    gate.window_open = True
    site = {"http://h/rest/user/login": _Resp(307, "/api/Users")}
    api = _FakeApi(site)
    route = _FakeRoute(_Req("http://h/rest/user/login"), site)
    make_route_handler(in_scope=gate.in_scope, api=api,
                       request_refusal=gate.request_refusal)(route)
    assert route.fetched == ["http://h/rest/user/login"]
    assert route.outcome == "abort" and api.calls == []
    assert gate.account_refusal and "api" not in gate.account_refusal.split("(")[0]


def test_a_cancelled_gate_refuses_every_request():
    """B-M1: once `run` gives up, the abandoned worker's gate lets nothing out."""
    import threading
    cancelled = threading.Event()
    gate = LoginGate(_Dest("http://h"), "http://h/", forms=secret_forms("s3cret"),
                     cancelled=cancelled)
    assert gate.in_scope("http://h/a") and \
        gate.request_refusal("GET", "http://h/a", {}, None) is None
    cancelled.set()
    assert not gate.in_scope("http://h/a")
    assert gate.request_refusal("GET", "http://h/a", {}, None)


def test_the_corrupted_credential_has_the_same_shape_and_another_value():
    """A-M1: a bearer's last character flips its high bits (a lenient base64url decoder
    still sees another value); a cookie gets a random value under the same name."""
    from fuzzlab.session.manager import _corrupt_token, _corrupted
    for token in ("abc.def.ghA", "abc.def.ghB", "t-_9", "x+"):
        bad = _corrupt_token(token)
        assert bad != token and len(bad) == len(token) and bad[:-1] == token[:-1]
    state = SessionState(HOST, "u", kind="bearer", headers={"Authorization": "Bearer T0K"},
                         cookies={"sid": "abcdef0123456789"}, valid=True)
    bad = _corrupted(state)
    assert bad.headers["Authorization"].startswith("Bearer T0") and \
        bad.headers["Authorization"] != "Bearer T0K"
    assert set(bad.cookies) == {"sid"} and bad.cookies["sid"] != "abcdef0123456789"
    assert state.headers == {"Authorization": "Bearer T0K"}            # not touched


def test_persisted_login_urls_carry_no_query_or_fragment():
    """A-M2(a)."""
    state = SessionState(HOST, "u", login_url="http://h/rest/login?pw=SECRET#x",
                         logout_url="http://h/logout?t=SECRET")
    rec = state.non_secret_state()
    assert rec["login_url"] == "http://h/rest/login" and rec["logout_url"] == "http://h/logout"
    assert browserlogin.strip_url("http://h/a/b?c=d#e") == "http://h/a/b"


def test_storage_values_carrying_the_password_are_dropped():
    """A-M2(c): before `filter_storage_state`, any cookie or localStorage entry that
    carries the password (in any form) is dropped."""
    import base64
    forms = secret_forms("S3cr3t!", "alice")
    storage = {"cookies": [{"name": "token", "value": "T"},
                           {"name": "pw", "value": "S3cr3t%21"}],
               "origins": [{"origin": "http://h", "localStorage": [
                   {"name": "token", "value": "T"},
                   {"name": "lastpw", "value": "S3cr3t!"},
                   {"name": "basic", "value": base64.b64encode(b"alice:S3cr3t!").decode()}]}]}
    kept = browserlogin.drop_secret_values(storage, forms)
    assert kept["cookies"] == [{"name": "token", "value": "T"}]
    assert kept["origins"][0]["localStorage"] == [{"name": "token", "value": "T"}]


@pytest.mark.parametrize("value, rotated", [
    ("9f8e7d6c5b4a39281706f5e4d3c2b1a0", True),
    ("eyJhbGciOiAiSFMyNTYifQ.eyJleHAiOjF9.sig", True),
    (None, False), ("", False), ("null", False), ("undefined", False),
    ("NULL ", False), ("hello", False),
])
def test_a_rotated_storage_value_is_told_from_a_loss(value, rotated):
    """B-S3."""
    from fuzzlab.tools.spider import _storage_rotated
    assert _storage_rotated(value) is rotated


def _wait_worker_gone(lab, timeout=40.0):
    import time
    from fuzzlab.core.urls import url_key
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with browserlogin._LIVE_LOCK:
            worker = browserlogin._LIVE.get((url_key(lab.base), "user"))
        if worker is None or not worker.is_alive():
            return True
        time.sleep(0.2)
    return False


def test_an_abandoned_login_never_sends_the_password(spa):
    """B-M1: the login page stalls past the deadline; the abandoned worker stops at its
    next checkpoint, its gate refuses everything, and its browser is closed: no
    password-carrying POST arrives afterwards and nothing it started survives."""
    import time
    pw = _password()
    lab = spa(pw, script_delay=4.0)
    mgr = _manager(lab, pw)
    before = _live_descendants()
    with pytest.raises(browserlogin.BrowserLoginError, match="abandoned"):
        browserlogin.run(mgr._credential_destination_ok, lab.base, _Cred(USER, pw),
                         identity="user", deadline_s=1.0, cleanup_s=30.0)
    assert _wait_worker_gone(lab)
    assert lab.seen("POST") == []
    deadline = time.monotonic() + 10
    while _live_descendants() - before and time.monotonic() < deadline:
        time.sleep(0.2)
    assert _live_descendants() - before == set()


def test_no_second_login_starts_beside_an_abandoned_one(spa):
    """B-M2: the first login is abandoned with its cleanup still pending; a second
    login for the same base URL and identity refuses until the first has finished."""
    pw = _password()
    lab = spa(pw, script_delay=4.0)
    mgr = _manager(lab, pw)
    run = lambda **kw: browserlogin.run(  # noqa: E731
        mgr._credential_destination_ok, lab.base, _Cred(USER, pw), identity="user", **kw)
    with pytest.raises(browserlogin.BrowserLoginError, match="cleanup pending"):
        run(deadline_s=0.5, cleanup_s=0.1)
    with pytest.raises(browserlogin.BrowserLoginError, match="still finishing"):
        run()
    assert _wait_worker_gone(lab)
    assert lab.seen("POST") == []


def test_an_endpoint_that_echoes_the_credential_is_never_the_probe(spa):
    """A-M1: ``/rest/echo`` answers differently with and without an Authorization
    header, but a corrupted one gets the credentialed shape too: never accepted."""
    pw = _password()
    lab = spa(pw, echo=True)
    state = _login(_manager(lab, pw), lab)
    assert len(lab.seen("GET", "/rest/echo")) >= 2           # it was a candidate
    assert state.protected_probe and "rest/echo" not in state.protected_probe


def test_a_revoked_token_answered_with_a_2xx_error_body_is_not_live(spa):
    """A-M1: the probe answers a non-live token with ``200 {"error": ...}``; the
    corrupted-credential reference makes a revoked token read as not live."""
    pw = _password()
    lab = spa(pw, invalid_200=True)
    mgr = _manager(lab, pw)
    state = _login(mgr, lab)
    assert state.probe_refusal_digest is not None            # a body differential
    assert mgr.verify_live(HOST, "user", lab.base) is True
    lab.revoke_all()
    assert mgr.verify_live(HOST, "user", lab.base) is False


def test_the_password_is_kept_out_of_urls_and_storage(spa, tmp_path, caplog):
    """A-M2: the app puts the password in its login URL's query and in localStorage,
    and GETs a URL carrying it: the stored login URL has no query, that GET is never
    the probe, and neither the store, the log, the state nor the adopted crawl storage
    holds any form of it."""
    from fuzzlab.core.store import Store
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    from fuzzlab.tools import browserauth
    caplog.set_level(logging.DEBUG)
    pw = _password()
    lab = spa(pw, leaky=True)
    store_path = tmp_path / "store.db"
    store = Store(str(store_path))
    try:
        mgr = SessionManager(_creds(pw), scope_hosts=[HOST], store=store,
                             logger=logging.getLogger("fuzzlab.test"))
        state = _login(mgr, lab)
        origins = origin_scope(lab.base)
        adopted = browserauth.browser_session(
            mgr, "user", lab.base, in_scope=lambda u: in_origin_scope(u, origins))
    finally:
        store.close()
    assert len(lab.seen("POST", "/rest/user/login?pw=")) == 1        # it did leak it
    assert state.login_url == lab.base + "rest/user/login"
    assert "pw=" not in state.protected_probe
    texts = [caplog.text, repr(state), str(state), json.dumps(state.browser_state),
             json.dumps(adopted.storage_state), store_path.read_bytes().decode("latin-1"),
             json.dumps(sorted(mgr.auth_endpoints(HOST)))]
    for form in secret_forms(pw, USER):
        for text in texts:
            assert form.decode() not in text
    names = {e["name"] for o in adopted.storage_state["origins"] for e in o["localStorage"]}
    assert "token" in names and "lastpw" not in names


def test_a_hashed_password_posted_to_api_users_sends_nothing(spa):
    """A-S1: the app hashes the password client-side and posts it to ``/api/Users``:
    not recognisable as the password, still refused (a write to an account endpoint in
    the window)."""
    pw = _password()
    lab = spa(pw, variant="users_sha")
    with pytest.raises(SessionAuthError, match="account endpoint"):
        _login(_manager(lab, pw), lab)
    assert lab.seen("POST") == []


def test_a_rotated_token_keeps_the_crawl_submitting(spa, tmp_path):
    """B-S3: the app replaces its localStorage token every 300 ms: a rotation, re-adopted
    and still checked with `verify_live`; submitting goes on."""
    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw, rotate=True)
    mgr = _manager(lab, pw)
    sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=10000, session_manager=mgr,
                     identity="user", submit_spa_forms=["notes", "contact"])
    run_crawl(sp)
    assert len(lab.seen("POST", "/api/notes")) == 1
    assert len(lab.seen("POST", "/api/contact")) == 1
    assert sp.spa_submit_stopped is None
    token = mgr._state[(HOST, "user")].headers["Authorization"][len("Bearer "):]
    (entries,) = sp._adopted_storage.values()
    assert entries["token"] != token                         # rotated and re-adopted


def test_a_cleared_token_still_stops_the_crawl_with_rotation_on(spa, tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    pw = _password()
    lab = spa(pw, rotate=True, clear_ls=True)
    sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=10000,
                     session_manager=_manager(lab, pw), identity="user",
                     submit_spa_forms=["notes", "contact"])
    run_crawl(sp)
    assert len(lab.seen("POST", "/api/notes")) == 1
    assert sp.spa_submit_stopped and "localStorage entry 'token'" in sp.spa_submit_stopped
    assert lab.seen("POST", "/api/contact") == []


def test_a_cancelled_login_stops_at_a_checkpoint():
    """B-M1: the worker's checkpoint (before each navigation, fill and the click)
    raises once the login is cancelled."""
    import threading
    cancelled = threading.Event()
    browserlogin._alive(cancelled)                           # not cancelled: no raise
    cancelled.set()
    with pytest.raises(browserlogin.BrowserLoginError, match="abandoned"):
        browserlogin._alive(cancelled)
