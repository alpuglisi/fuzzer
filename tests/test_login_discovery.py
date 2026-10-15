"""BUG-0148 / PA-0154: a login page is found by what every web stack shares.

The browser login looked for a login page only by an exact path word, so a login
reached by a link or button named "Log in" / "Sign in" on another path, in a modal, or
behind an account menu was never found, and the form gates refused the standard login
pages of Rails, Devise, ASP.NET Identity and Django admin.

Pure tests first (the one SP-16 owner, its ranks, its frozen logout rule, the
affordance rule, the shared form gates, the pre-window gate), then real-Chromium tests
against `tests._framework_login_fixture`: login pages as frameworks ship them by
default (PA-0154(2), never a lab's shape), each through the browser login
(`browserlogin.run`) and, where it is server-rendered, the requests-side discovery
(`SessionManager._discover_login_form`). Stated residuals are strict xfails. The
private-vocabulary guard is `tests/test_private_vocabulary.py` (review B, B4).
"""

from __future__ import annotations

import itertools
import uuid
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.urls import canonical_origin
from fuzzlab.session import browserlogin
from fuzzlab.session.browserlogin import (IDENTIFIER_FIRST, NO_AFFORDANCE, LoginGate,
                                          affordance_refusal, disclosure_refusal,
                                          login_form_core_refusal, login_form_refusal,
                                          secret_forms)
from fuzzlab.session.detect import (MODE_CANDIDATE, MODE_LOGOUT, RANK_SEGMENT, RANK_TOKEN,
                                    login_affordance, login_forms, login_links,
                                    login_path_match, looks_like_login_url)
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.spa import route_of
from tests import _framework_login_fixture as fx
from tests._spa_fixture import Recorder, chromium_or_skip
from tests.test_credentials import FakeBackend


# =====================================================================================
# Pure: the one login-URL owner (SP-16) and its candidate ranks
# =====================================================================================
@pytest.mark.parametrize("target, rank", [
    ("/login", RANK_SEGMENT), ("/accounts/login/", RANK_SEGMENT),
    ("/admin/login/?next=/admin/", RANK_SEGMENT), ("/users/sign_in", RANK_SEGMENT),
    ("/Identity/Account/Login", RANK_SEGMENT), ("/session/new", RANK_SEGMENT),
    ("/sessions/new", RANK_SEGMENT), ("/login.php", RANK_SEGMENT),
    ("/auth/sign-in", RANK_SEGMENT), ("/SignIn", RANK_SEGMENT), ("Logon.aspx", RANK_SEGMENT),
    ("index.php?page=login", RANK_SEGMENT), ("#/sign-in", RANK_SEGMENT),
    ("auth/sign-in", RANK_SEGMENT), ("/user/login", RANK_SEGMENT),
    ("/login/index.php", RANK_SEGMENT),                    # Moodle (review B, B2(d))
    ("/wp-login.php", RANK_TOKEN), ("/member_login", RANK_TOKEN),
    ("/MemberLogin", RANK_TOKEN), ("/member-login", RANK_TOKEN),
    ("/exercise_login", RANK_TOKEN), ("/member-sign-in", RANK_TOKEN),
    ("/please-log-in", RANK_TOKEN),
    # no prefix or suffix of a run-together word (PA-0122(1)); found by affordance
    ("/memberlogin", None), ("/customerlogin", None), ("/loginpage", None),
    ("/loginhistory", None), ("/login_form", None), ("/blog", None),
    ("/catalogue", None), ("/session", None), ("/news", None), ("/users/new", None),
    ("/index.php", None), ("/catalogue/index.php", None), ("/", None), ("", None),
    ("mailto:login@example.invalid", None), ("javascript:login()", None),
])
def test_candidate_ranks(target, rank):
    assert login_path_match(target, mode=MODE_CANDIDATE) == rank


def _corpus() -> list[str]:
    """URL shapes over the login vocabulary and its neighbours: separators, case,
    extensions, prefixes, front controllers (neutral names, PA-0154(4))."""
    words = ["login", "signin", "sign_in", "sign-in", "log-in", "log_in", "logon",
             "Login", "SignIn", "LogOn", "member_login", "wp-login", "exercise_login",
             "loginhistory", "login_form", "memberlogin", "MemberLogin", "member-sign-in",
             "new", "session", "blog", "insecure_login_1", "index"]
    parents = ["", "auth/", "users/", "Account/", "session/", "sessions/", "app/",
               "login/"]
    exts = ["", ".php", ".aspx", "/"]
    out = [f"http://h/{p}{w}{e}" for p, w, e in itertools.product(parents, words, exts)]
    out += [f"http://h/index.php?page={w}" for w in words]
    out += [f"http://h/main.php?route=a/{w}" for w in words]
    out += ["", "http://", "mailto:a@b", "#/login", "/" * 50, "http://h/?page=login"]
    return out


def test_every_logout_positive_is_a_candidate_at_some_rank():
    """Design section 9's invariant: the candidate mode never misses what the logout
    mode accepts; the whole-segment half is rank 1."""
    corpus = _corpus()
    positives = [u for u in corpus if looks_like_login_url(u)]
    assert len(positives) > 50                                   # non-vacuous
    for url in positives:
        assert login_path_match(url, mode=MODE_CANDIDATE) in (RANK_SEGMENT, RANK_TOKEN), url
    for url in corpus:
        if looks_like_login_url(url, final_token=False):
            assert login_path_match(url, mode=MODE_CANDIDATE) == RANK_SEGMENT, url


# The logout rule as it stood at 13b1cff (BUG-0122), frozen here (review A, A4): the
# logout mode must keep deciding exactly this, whatever the owner's code becomes.
_F_SEGMENTS = frozenset({"login", "signin", "sign_in", "sign-in", "log_in", "log-in",
                         "logon"})
_F_TOKENS = frozenset({"login", "signin", "logon"})
_F_ROUTERS = frozenset({"index", "default", "main"})
_F_PARAMS = frozenset({"page", "action", "route", "r", "p", "view"})


def _frozen_segment(segment: str, final_token: bool) -> bool:
    from fuzzlab.core.redaction import name_tokens
    stem = segment.lower()
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    if stem in _F_SEGMENTS:
        return True
    tokens = name_tokens(stem) if final_token else []
    return bool(tokens) and tokens[-1] in _F_TOKENS


def _frozen_rule(url: str, final_token: bool = True) -> bool:
    parts = urlsplit(url or "")
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return False
    segments = [s for s in parts.path.split("/") if s]
    if not segments:
        return False
    if len(segments) >= 2 and segments[-1].lower() == "new" and \
            segments[-2].lower() in ("session", "sessions"):
        return True
    if _frozen_segment(segments[-1], final_token):
        return True
    if segments[-1].lower().rsplit(".", 1)[0] in _F_ROUTERS:
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            routed = [s for s in value.split("/") if s]
            if key.lower() in _F_PARAMS and routed and \
                    _frozen_segment(routed[-1], final_token):
                return True
    return False


def test_the_logout_mode_is_the_13b1cff_rule_unchanged():
    corpus = _corpus()
    assert sum(_frozen_rule(u) for u in corpus) > 50 and \
        sum(not _frozen_rule(u) for u in corpus) > 50              # both sides covered
    for url in corpus:
        for final in (True, False):
            assert login_path_match(url, mode=MODE_LOGOUT, final_token=final) is \
                _frozen_rule(url, final), (url, final)
            assert looks_like_login_url(url, final_token=final) is _frozen_rule(url, final)
    with pytest.raises(ValueError):
        login_path_match("/login", mode="substring")


@pytest.mark.parametrize("text, aria, hit", [
    ("Log in", "", True), ("Sign in", "", True), ("Login", "", True), ("LOG IN", "", True),
    ("Sign In ▾", "", True), ("Log in", "", True), ("Sign in to your account", "", True),
    ("Logon", "", True), ("", "Sign in", True), ("Members", "Sign in", True),
    # review B, B2(a): a label CONTAINING a login word or pair
    ("User Login", "", True), ("Member Login", "", True), ("Customer Login", "", True),
    ("Login / Register", "", True), ("Sign in / Register", "", True),
    ("Sign In or Register", "", True), ("Log In / Sign Up", "", True),
    ("Sign in to continue", "", True),
    ("Log out", "", False), ("Sign out", "", False), ("Sign up", "", False),
    ("Logout", "", False), ("Exit", "", False), ("Login", "Log out", False),
    ("Forgot password", "", False), ("Account", "", False), ("", "", False),
    ("Anmelden", "", False),                            # English labels only (residual)
])
def test_the_affordance_rule(text, aria, hit):
    assert login_affordance(text, aria) is hit


def test_an_affordance_still_passes_the_label_gates():
    assert affordance_refusal(["Log in", "", ""]) is None
    assert affordance_refusal(["Login / Register", "", ""]) is None     # account words
    assert affordance_refusal(["Log In / Sign Up", "", ""]) is None     # are waived
    assert affordance_refusal(["Sign up", "", ""]) == "not a login label"
    assert "destructive icon" in affordance_refusal(["", "Sign in", "logout"])
    assert "aria-label" in affordance_refusal(["Sign in", "Delete my data", ""])
    assert affordance_refusal(["Login and delete account", "", ""]) is not None


def test_only_an_account_menu_or_an_icon_is_opened():
    def item(labels, **kw):
        return {"labels": labels, "popup": True, "link": None, "visible": True,
                "disabled": False, "icon": False, **kw}
    assert disclosure_refusal(item(["", "Account", ""])) is None
    assert disclosure_refusal(item(["My account", "", ""])) is None
    assert disclosure_refusal(item(["", "", ""], icon=True)) is None
    assert disclosure_refusal(item(["", "", ""])) is not None             # nothing to judge
    assert disclosure_refusal(item(["Settings", "", ""])) is not None
    # an icon ligature's name is no signal (review B, B6)
    assert disclosure_refusal(item(["account_circle", "", ""])) is not None
    assert disclosure_refusal(item(["", "Account", ""], popup=False)) is not None
    assert disclosure_refusal(item(["", "Account", ""], link="http://h/a")) is not None
    assert disclosure_refusal(item(["", "", "delete"], icon=True)) is not None


def test_login_links_of_a_server_rendered_page():
    """Exact login labels, then rank-1 paths, then labels that only contain a login word
    (an app page titled "... login ..." never comes before ``/accounts/login/``)."""
    html = ("<a href='/exercise_login'>Exercise: login form</a>"
            "<a href='/register'>Register</a><a href='/blog/tips'>Tips</a>"
            "<a href='/accounts/login/'>Members</a><a href='/x' aria-label='Sign in'>"
            "<svg></svg></a><a href='#top'>Log in</a><a href='mailto:a@b'>Log in</a>"
            "<a href='/memberlogin'>Sign in</a><a href='/logout'>Log out</a>"
            "<a href='/login/index.php'>Site</a>")
    assert login_links(html, "http://h/") == ["http://h/x", "http://h/memberlogin",
                                              "http://h/accounts/login/",
                                              "http://h/login/index.php",
                                              "http://h/exercise_login"]


# =====================================================================================
# Pure: the shared form gates accept every framework's default login page
# =====================================================================================
def _login_page(shape: fx.Shape) -> str:
    return next(p for p, html in shape.pages.items()
                if not html.startswith("REDIRECT:") and "type='password'" in html)


@pytest.mark.parametrize("shape", fx.SERVER_RENDERED, ids=lambda s: s.name)
def test_framework_default_login_forms_pass_the_gates(shape):
    """Both login paths' gates accept the default login form, read as the requests
    side reads it (`detect.login_forms`)."""
    path = _login_page(shape)
    origin = "http://127.0.0.1:1"
    html = shape.pages[path].replace("{csrf}", "t0k").replace("{origin}", origin)
    (_form, described), = login_forms(html, origin + path)
    route = route_of(origin + path, origin + shape.base)
    assert login_form_core_refusal(described, route) is None
    assert login_form_refusal(described, route) is None


def _gate_form(controls, button="Log in", action=None):
    return {"controls": controls, "button": button, "button_aria": "", "button_icons": "",
            "action": action, "ids": [f"c{i}" for i in range(len(controls))],
            "button_id": "b", "autocomplete": [""] * len(controls)}


LOGIN = [("authenticity_token", "hidden"), ("user[email]", "email"),
         ("user[password]", "password")]


@pytest.mark.parametrize("form, route, expect", [
    # the override is for a login page's own route / action words only
    (_gate_form(LOGIN + [("user[password_confirmation]", "password")]), "users/sign_in",
     "password controls"),
    (_gate_form(LOGIN, button="Sign up"), "users/sign_in", "sign up"),
    (_gate_form(LOGIN, button="Create account"), "session/new", "create"),
    (_gate_form(LOGIN), "users/new", "new"),                           # no login name
    (_gate_form(LOGIN, action="http://h/users/new"), "users/sign_in", "new"),
    (_gate_form(LOGIN), "admin/settings", "admin"),
    (_gate_form(LOGIN), "auth/register", "register"),
    (_gate_form(LOGIN, action="http://h/users/sign_in/delete"), "users/sign_in",
     "destructive"),
    # review A, A1: the endpoint vocabulary (auth, session, token) is no login page name
    (_gate_form(LOGIN, action="http://h/auth/users/"), "", "users"),
    (_gate_form(LOGIN), "auth/account", "account"),
    (_gate_form(LOGIN), "auth/admin/users", "admin"),
    (_gate_form(LOGIN), "auth/users/new", "new"),
    # a hidden field is judged by the account and destructive words still
    (_gate_form(LOGIN + [("reset_token", "hidden")]), "users/sign_in", "reset"),
    (_gate_form(LOGIN + [("delete_account", "hidden")]), "login", "delete"),
])
def test_the_override_keeps_every_other_refusal(form, route, expect):
    for gate in (login_form_core_refusal, login_form_refusal):
        why = gate(form, route)
        assert why is not None and expect in why, (gate.__name__, why)


def test_a_hidden_field_on_a_login_shaped_form_is_never_an_object_selector():
    """Review B, B2(b): framework tokens (Drupal ``form_build_id``, Keycloak
    ``credentialId``, a checkbox's hidden value) pass on the login path."""
    for hidden in ("form_build_id", "credentialId", "user[remember_me]", "user[id]"):
        assert login_form_refusal(_gate_form(LOGIN + [(hidden, "hidden")]),
                                  "users/sign_in") is None, hidden


# =====================================================================================
# Pure: the pre-window phase (design section 5; review A, A5/A6)
# =====================================================================================
def test_every_write_before_the_window_is_aborted_and_named_by_host_and_path():
    gate = LoginGate(lambda *a, **k: True, "http://h/", forms=secret_forms("s3cret"))
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert gate.request_refusal(method, "http://h/api/track?id=7", {}, b"x")
    for method in ("GET", "HEAD", "OPTIONS"):                 # not writes (review A, A6)
        assert gate.request_refusal(method, "http://h/api/track", {}, None) is None
    assert gate.prewindow_write_count == 4
    assert gate.prewindow_writes == ["POST h/api/track", "PUT h/api/track",
                                     "PATCH h/api/track", "DELETE h/api/track"]


def test_websocket_messages_are_held_until_the_window_opens():
    gate = LoginGate(lambda *a, **k: True, "http://h/", forms=secret_forms("s3cret"))
    assert gate.ws_hold() is True                              # the whole pre-window phase
    gate.window_open = True
    assert gate.ws_hold() is False
    gate.clicking = True
    assert gate.ws_hold() is True


def test_a_click_captures_its_navigation_and_aborts_its_writes():
    gate = LoginGate(lambda *a, **k: True, "http://h/", forms=secret_forms("s3cret"))
    assert gate.window_refusal("GET", "http://h/login", True) is None        # no click
    gate.clicking = True
    assert gate.window_refusal("GET", "http://h/login", True)
    assert gate.window_refusal("POST", "http://h/api/subscribe", False)
    assert gate.window_refusal("GET", "http://h/api/config", False) is None
    assert gate.captured == ["http://h/login"]
    assert gate.prewindow_writes == ["POST h/api/subscribe"]


# =====================================================================================
# Real browser: the framework matrix, end to end
# =====================================================================================
@pytest.fixture
def chromium(monkeypatch):
    chromium_or_skip(monkeypatch)


@pytest.fixture
def apps(chromium):
    made = []

    def make(shape, **kw):
        app = fx.FrameworkApp(shape, "pw-" + uuid.uuid4().hex, **kw)
        made.append(app)
        return app
    try:
        yield make
    finally:
        for app in made:
            app.close()


class _Cred:
    def __init__(self, username, password):
        self.username, self.password = username, password


def _same_origin(url, base, *, floor_https=False):
    return canonical_origin(url) == canonical_origin(base)


def _browser_login(app):
    try:
        return browserlogin.run(_same_origin, app.base, _Cred(fx.USER, app.password),
                                timeout_ms=10000, deadline_s=90)
    except browserlogin.BrowserLoginError as exc:
        if "could not be launched" in str(exc) or "driver did not start" in str(exc):
            from tests._browser import skip_or_fail
            skip_or_fail(f"chromium unavailable: {exc}")
        raise


def _manager(app, **kw) -> SessionManager:
    store = CredentialStore(backend=FakeBackend())
    store.set("127.0.0.1", "user", fx.USER, app.password)
    return SessionManager(store, scope_hosts=["127.0.0.1"], **kw)


@pytest.mark.parametrize("shape", fx.SERVER_RENDERED + fx.SPA_SHAPES,
                         ids=lambda s: s.name)
def test_framework_default_login_pages_are_found_and_accepted(apps, shape):
    """Each framework's default login page is found (by its affordance, its redirect
    or its path) and accepted by the gates; the credentials go to its login action
    once, and nowhere else (no other POST at all)."""
    app = apps(shape)
    obs = _browser_login(app)
    assert app.logins == [shape.login], app.requests
    assert obs.login_url == app.origin + shape.login
    assert [p.split("?", 1)[0] for p in app.seen("POST")] == [shape.login]
    assert not any("register" in p.lower() or "sign_up" in p.lower()
                   for p in app.seen("GET")), app.seen("GET")


@pytest.mark.parametrize("shape", fx.SERVER_RENDERED, ids=lambda s: s.name)
def test_framework_default_login_pages_are_found_without_a_browser(shape):
    """The requests-side discovery (design section 7): the base page, then what it
    links to as its login, then the fixed fallback paths; every form gated."""
    app = fx.FrameworkApp(shape, "pw-" + uuid.uuid4().hex)
    try:
        mgr = _manager(app)
        form, _page, _challenge, _floor = mgr._discover_login_form(
            mgr._fetch_factory(), app.base)
        assert form is not None, app.requests
        assert form.action_url.split("?", 1)[0] == app.origin + shape.login
        if shape.csrf:
            assert shape.csrf in form.fields.names()
        assert form.password_field == shape.password
        assert not any(p.lower().startswith(("/register", "/users/sign_up",
                                             "/identity/account/register"))
                       for p in app.seen("GET"))
    finally:
        app.close()


@pytest.mark.parametrize("shape", [fx.RAILS, fx.DEVISE, fx.ASPNET, fx.DRUPAL],
                         ids=lambda s: s.name)
def test_a_full_login_through_the_requests_side(shape):
    """End to end through `SessionManager.ensure` with no browser: found by its link,
    posted once with its CSRF token, a cookie session."""
    app = fx.FrameworkApp(shape, "pw-" + uuid.uuid4().hex)
    try:
        state = _manager(app, browser_login=False).ensure("127.0.0.1", "user", app.base,
                                                           operator=True)
        assert state.valid and state.kind == "cookie"
        assert app.logins == [shape.login]
        assert [p.split("?", 1)[0] for p in app.seen("POST")] == [shape.login]
    finally:
        app.close()


def test_the_requests_side_never_fills_a_registration_form_before_the_login():
    """Review A, A2: "Sign in" leads to a page whose first password form registers an
    account; the gates refuse it, and the login form after it gets the credentials."""
    app = fx.FrameworkApp(fx.REGISTER_FIRST, "pw-" + uuid.uuid4().hex)
    try:
        state = _manager(app, browser_login=False).ensure("127.0.0.1", "user", app.base,
                                                           operator=True)
        assert state.valid
        assert app.logins == ["/session"]
        assert app.decoy_posts == []
        assert "/account/register" not in app.seen("POST")
    finally:
        app.close()


# --- negatives ---------------------------------------------------------------------------
def test_a_sign_in_submitter_of_another_form_is_never_clicked(apps):
    app = apps(fx.SUBMITTER_ONLY)
    with pytest.raises(browserlogin.BrowserLoginError) as err:
        _browser_login(app)
    assert app.seen("POST") == []
    assert NO_AFFORDANCE in str(err.value)
    assert IDENTIFIER_FIRST in str(err.value)          # an email-only form was seen


def test_a_sign_in_to_another_origin_is_not_followed_and_names_auth_origin(apps):
    other = Recorder()
    try:
        app = apps(fx.OFF_ORIGIN,
                   other=f"http://127.0.0.1:{other.server.server_address[1]}")
        with pytest.raises(browserlogin.BrowserLoginError) as err:
            _browser_login(app)
        assert other.requests == []
        assert "--auth-origin" in str(err.value)
        assert app.password not in str(err.value)
    finally:
        other.close()


def test_a_post_on_page_load_is_aborted_before_the_window_and_reported(apps):
    """The base page's on-load POST is aborted before the window (and named); once the
    login has landed back on that page, inside the window, the app's own write goes
    through as before (the window refuses account endpoints only)."""
    app = apps(fx.ONLOAD_WRITE)
    obs = _browser_login(app)
    assert app.logins == ["/login"]
    posts = app.seen("POST")
    assert posts[0] == "/login", posts                 # nothing was written before it
    assert any(w.endswith("/api/track") and w.startswith("POST ")
               for w in obs.aborted_writes), obs.aborted_writes


def test_a_mislabelled_sign_in_that_posts_is_aborted_and_named(apps):
    app = apps(fx.MISLABELLED)
    with pytest.raises(browserlogin.BrowserLoginError) as err:
        _browser_login(app)
    assert app.seen("POST") == []
    assert "/api/subscribe" in str(err.value)
    assert "aborted before the login window" in str(err.value)
    assert "GraphQL" in str(err.value)                 # the stated cost (A6, B3)


def test_a_decoy_login_linked_before_the_real_one_is_never_filled(apps):
    app = apps(fx.DECOY)
    _browser_login(app)
    assert app.logins == ["/login"]
    assert app.decoy_posts == []
    assert "/exercise_login" not in app.seen("GET")    # rank 1 found it first


def test_an_identifier_first_login_is_named_in_the_diagnosis(apps):
    app = apps(fx.IDENTIFIER_FIRST)
    with pytest.raises(browserlogin.BrowserLoginError) as err:
        _browser_login(app)
    assert IDENTIFIER_FIRST in str(err.value)
    assert "link /signin" in str(err.value)
    assert app.seen("POST") == []


def test_the_search_stops_at_its_time_budget_with_a_diagnosis(apps, monkeypatch):
    """Review A, A10: the user gets the diagnosis, not "abandoned"."""
    monkeypatch.setattr(browserlogin, "DISCOVERY_BUDGET_S", 0.0)
    app = apps(fx.DEVISE)
    with pytest.raises(browserlogin.BrowserLoginError) as err:
        _browser_login(app)
    assert "time budget" in str(err.value)
    assert "abandoned" not in str(err.value)
    assert app.seen("POST") == []


# --- stated residuals (strict xfails, PA-0054(3)) -----------------------------------------
@pytest.mark.xfail(strict=True, reason="residual (review A, A9): with nothing better "
                   "found, a rank-2 path's app page with a password form is filled")
def test_residual_a_rank_2_decoy_alone_is_never_filled(apps):
    app = apps(fx.DECOY_ONLY)
    try:
        _browser_login(app)
    except browserlogin.BrowserLoginError:
        pass
    assert app.decoy_posts == []


def _residual(shape):
    @pytest.mark.xfail(strict=True, raises=browserlogin.BrowserLoginError,
                       reason=f"residual: {shape.name}")
    def test(apps):
        _browser_login(apps(shape))
    test.__name__ = f"test_residual_{shape.name.replace('-', '_')}"
    return test


test_residual_a_shadow_dom_login_form = _residual(fx.SHADOW_DOM)
test_residual_a_clickable_div_with_no_role = _residual(fx.ROLELESS_DIV)
test_residual_a_non_english_login_label = _residual(fx.NON_ENGLISH)
test_residual_an_identifier_first_login = _residual(fx.IDENTIFIER_FIRST)
#: review B, B3: a read sent as a POST before the window is aborted
test_residual_a_graphql_query_before_the_login = _residual(fx.GRAPHQL_FIRST)
#: review B, B9
test_residual_a_role_tab_login_panel = _residual(fx.ROLE_TAB)
test_residual_a_details_summary_login = _residual(fx.DETAILS_SUMMARY)
test_residual_a_login_form_in_a_same_origin_iframe = _residual(fx.SAME_ORIGIN_IFRAME)


@pytest.mark.xfail(strict=True, reason="BUG-0151: spa.FORMS_JS re-marks a hidden form's "
                   "controls for an enclosing container; spa.py is another lane's file")
def test_residual_forms_js_marks_stay_unique_for_a_hidden_form(chromium):
    from playwright.sync_api import sync_playwright

    from fuzzlab.tools import spa
    from fuzzlab.tools.navguard import browser_launch_args, chromium_launch_kwargs
    app = fx.FrameworkApp(fx.BOOTSTRAP_MODAL, "pw")
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs(
                browser_launch_args([app.base])))
            try:
                page = browser.new_page()
                page.goto(app.base)                    # an unguarded test page
                forms = page.evaluate(spa.FORMS_JS, 20)
                ids = [i for f in forms for i in f["ids"]]
                assert all(page.query_selector(f'[data-fuzzlab-id="{i}"]') for i in ids)
            finally:
                browser.close()
    finally:
        app.close()
