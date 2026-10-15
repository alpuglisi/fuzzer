"""BUG-0148 / PA-0154: a login page is found by what every web stack shares.

The browser login looked for a login page only by an exact path word, so a login
reached by a link or button named "Log in" / "Sign in" on another path, in a modal, or
behind an account menu was never found, and the form gates refused the standard login
pages of Rails, Devise, ASP.NET Identity and Django admin.

Pure tests first (the one SP-16 owner, its ranks and invariant, the affordance rule,
the form-gate override, the private-vocabulary guard), then real-Chromium tests
against `tests._framework_login_fixture`: login pages as frameworks ship them by
default (PA-0154(b), never a lab's shape), each through the browser login
(`browserlogin.run`) and, where it is server-rendered, the requests-side discovery
(`SessionManager._discover_login_form`). Stated residuals are strict xfails.
"""

from __future__ import annotations

import ast
import itertools
import uuid
from pathlib import Path

import pytest

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.urls import canonical_origin
from fuzzlab.session import browserlogin
from fuzzlab.session.browserlogin import (IDENTIFIER_FIRST, NO_AFFORDANCE, LoginGate,
                                          affordance_refusal, disclosure_refusal,
                                          login_form_refusal, secret_forms)
from fuzzlab.session.detect import (MODE_CANDIDATE, MODE_LOGOUT, RANK_SEGMENT, RANK_TOKEN,
                                    login_affordance, login_links, login_path_match,
                                    looks_like_login_url)
from fuzzlab.session.manager import SessionManager
from tests import _framework_login_fixture as fx
from tests._spa_fixture import Recorder, chromium_or_skip
from tests.test_credentials import FakeBackend

ROOT = Path(__file__).resolve().parents[1]


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
    ("auth/sign-in", RANK_SEGMENT),
    ("/wp-login.php", RANK_TOKEN), ("/user_login", RANK_TOKEN), ("/UserLogin", RANK_TOKEN),
    ("/user-login", RANK_TOKEN), ("/xss_login", RANK_TOKEN), ("/user-sign-in", RANK_TOKEN),
    ("/please-log-in", RANK_TOKEN),
    # no prefix or suffix of a run-together word (PA-0122(1)); found by affordance
    ("/userlogin", None), ("/loginpage", None), ("/loginhistory", None),
    ("/login_form", None), ("/blog", None), ("/catalogue", None), ("/session", None),
    ("/news", None), ("/users/new", None), ("/", None), ("", None),
    ("mailto:login@example.invalid", None), ("javascript:login()", None),
])
def test_candidate_ranks(target, rank):
    assert login_path_match(target, mode=MODE_CANDIDATE) == rank


def _corpus() -> list[str]:
    """URL shapes over the login vocabulary and its neighbours: separators, case,
    extensions, prefixes, front controllers."""
    words = ["login", "signin", "sign_in", "sign-in", "log-in", "log_in", "logon",
             "Login", "SignIn", "LogOn", "user_login", "wp-login", "xss_login",
             "loginhistory", "login_form", "userlogin", "UserLogin", "user-sign-in",
             "new", "session", "blog", "ba_insecure_login_1"]
    parents = ["", "auth/", "users/", "Account/", "session/", "sessions/", "app/"]
    exts = ["", ".php", ".aspx", "/"]
    out = [f"http://h/{p}{w}{e}" for p, w, e in itertools.product(parents, words, exts)]
    out += [f"http://h/index.php?page={w}" for w in words]
    out += [f"http://h/main.php?route=a/{w}" for w in words]
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


def test_the_logout_mode_is_looks_like_login_url_unchanged():
    for url in _corpus():
        for final in (True, False):
            assert login_path_match(url, mode=MODE_LOGOUT, final_token=final) is \
                looks_like_login_url(url, final_token=final)
    with pytest.raises(ValueError):
        login_path_match("/login", mode="substring")


@pytest.mark.parametrize("text, aria, hit", [
    ("Log in", "", True), ("Sign in", "", True), ("Login", "", True), ("LOG IN", "", True),
    ("Sign In ▾", "", True), ("Log in", "", True), ("Sign in to your account", "", True),
    ("Log in here", "", True), ("Logon", "", True), ("", "Sign in", True),
    ("Sign up", "", False), ("Log out", "", False), ("Login with Google", "", False),
    ("Sign in with Google", "", False), ("Forgot password", "", False),
    ("Account", "", False), ("Login history", "", False), ("", "", False),
    ("Anmelden", "", False),                            # English labels only (residual)
    ("Members", "Sign in", False),                       # the text decides when present
])
def test_the_affordance_rule(text, aria, hit):
    assert login_affordance(text, aria) is hit


def test_an_affordance_still_passes_the_label_gates():
    assert affordance_refusal(["Log in", "", ""]) is None
    assert affordance_refusal(["Sign up", "", ""]) == "not a login label"
    assert "destructive icon" in affordance_refusal(["", "Sign in", "logout"])
    assert "aria-label" in affordance_refusal(["Sign in", "Delete my data", ""])


def test_only_an_account_menu_or_an_icon_is_opened():
    def item(labels, **kw):
        return {"labels": labels, "popup": True, "link": None, "visible": True,
                "disabled": False, "icon": False, **kw}
    assert disclosure_refusal(item(["", "Account", ""])) is None
    assert disclosure_refusal(item(["My account", "", ""])) is None
    assert disclosure_refusal(item(["", "", ""], icon=True)) is None
    assert disclosure_refusal(item(["", "", ""])) is not None             # nothing to judge
    assert disclosure_refusal(item(["Settings", "", ""])) is not None
    assert disclosure_refusal(item(["", "Account", ""], popup=False)) is not None
    assert disclosure_refusal(item(["", "Account", ""], link="http://h/a")) is not None
    assert disclosure_refusal(item(["", "", "delete"], icon=True)) is not None


def test_login_links_of_a_server_rendered_page():
    html = ("<a href='/register'>Register</a><a href='/blog/login-tips'>Tips</a>"
            "<a href='/accounts/login/'>Members</a><a href='/x' aria-label='Sign in'>"
            "<svg></svg></a><a href='#top'>Log in</a><a href='mailto:a@b'>Log in</a>"
            "<a href='/userlogin'>Log in</a>")
    assert login_links(html, "http://h/") == ["http://h/x", "http://h/userlogin",
                                              "http://h/accounts/login/"]


# =====================================================================================
# Pure: the form gates accept every framework's default login page (design section 2)
# =====================================================================================
def _form_of(shape: fx.Shape) -> tuple[dict, str]:
    """The `FORMS_JS` description of a shape's login form, read from its HTML."""
    from bs4 import BeautifulSoup
    page = shape.pages[_login_page(shape)]
    soup = BeautifulSoup(page, "html.parser").find("form")
    controls = [(c.get("name") or c.get("id") or "", (c.get("type") or "text").lower())
                for c in soup.find_all("input") if c.get("type") != "submit"]
    button = soup.find("button")
    submit = soup.find("input", attrs={"type": "submit"})
    label = button.get_text(" ", strip=True) if button else (submit.get("value") or "")
    action = soup.get("action")
    action = "http://127.0.0.1:1" + action if action else None
    route = _login_page(shape).strip("/")
    return ({"controls": controls, "button": label, "button_aria": "",
             "button_icons": "", "action": action,
             "ids": [f"c{i}" for i in range(len(controls))], "button_id": "b",
             "autocomplete": [""] * len(controls)}, route)


def _login_page(shape: fx.Shape) -> str:
    return next(p for p, html in shape.pages.items()
                if not html.startswith("REDIRECT:") and "type='password'" in html)


@pytest.mark.parametrize("shape", fx.SERVER_RENDERED, ids=lambda s: s.name)
def test_framework_default_login_forms_pass_the_gates(shape):
    form, route = _form_of(shape)
    assert login_form_refusal(form, route) is None


def _gate_form(controls, button="Log in", action=None):
    return {"controls": controls, "button": button, "button_aria": "", "button_icons": "",
            "action": action, "ids": [f"c{i}" for i in range(len(controls))],
            "button_id": "b", "autocomplete": [""] * len(controls)}


LOGIN = [("authenticity_token", "hidden"), ("user[email]", "email"),
         ("user[password]", "password")]


@pytest.mark.parametrize("form, route, expect", [
    # the override is for the route / action words only; every other rule stands
    (_gate_form(LOGIN + [("user[password_confirmation]", "password")]), "users/sign_in",
     "password controls"),
    (_gate_form(LOGIN, button="Sign up"), "users/sign_in", "sign up"),
    (_gate_form(LOGIN, button="Create account"), "session/new", "create"),
    (_gate_form(LOGIN), "users/new", "new"),                           # no login token
    (_gate_form(LOGIN, action="http://h/users/new"), "users/sign_in", "new"),
    (_gate_form(LOGIN), "admin/settings", "admin"),
    (_gate_form(LOGIN + [("account_action", "hidden")]), "Account/Login", "account"),
    (_gate_form(LOGIN), "auth/register", "register"),
    (_gate_form(LOGIN, action="http://h/users/sign_in/delete"), "users/sign_in",
     "destructive"),
    # a hidden object selector stays refused unless it is a checkbox's companion
    (_gate_form(LOGIN + [("user[id]", "hidden")]), "users/sign_in", "object selector"),
    (_gate_form(LOGIN + [("user[remember_me]", "hidden"), ("user[uid]", "checkbox")]),
     "users/sign_in", "object selector"),
])
def test_the_override_keeps_every_other_refusal(form, route, expect):
    why = login_form_refusal(form, route)
    assert why is not None and expect in why, why


# =====================================================================================
# Pure: the pre-window phase (design section 5)
# =====================================================================================
def test_every_write_before_the_window_is_aborted_and_named_by_host_and_path():
    gate = LoginGate(lambda *a, **k: True, "http://h/", forms=secret_forms("s3cret"))
    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert gate.request_refusal(method, "http://h/api/track?id=7", {}, b"x")
    assert gate.request_refusal("GET", "http://h/api/track", {}, None) is None
    assert gate.request_refusal("HEAD", "http://h/api/track", {}, None) is None
    assert gate.prewindow_write_count == 5
    assert gate.prewindow_writes[0] == "POST h/api/track"
    assert all("id=7" not in w for w in gate.prewindow_writes)


def test_a_click_captures_its_navigation_and_aborts_its_writes():
    gate = LoginGate(lambda *a, **k: True, "http://h/", forms=secret_forms("s3cret"))
    assert gate.window_refusal("GET", "http://h/login", True) is None        # no click
    gate.clicking = True
    assert gate.ws_hold() is True
    assert gate.window_refusal("GET", "http://h/login", True)
    assert gate.window_refusal("POST", "http://h/api/subscribe", False)
    assert gate.window_refusal("GET", "http://h/api/config", False) is None
    assert gate.captured == ["http://h/login"]
    assert gate.prewindow_writes == ["POST h/api/subscribe"]


# =====================================================================================
# Guard: no module imports another module's private vocabulary (PA-0154(c))
# =====================================================================================
_PRIVATE = ("_",)
#: Known private-constant imports across modules, each in a file this change may not
#: edit (a concurrent lane owns it): listed with the reason, and a stale entry fails.
#: The login vocabulary (``_LOGIN_*``) never has an entry.
_KNOWN_PRIVATE_IMPORTS = {
    ("fuzzlab/tools/spa.py", "fuzzlab.tools.store_adapter", "_FILLERS"):
        "filler values shared with the importer; spa.py is another lane's file (BUG-0148 sweep)",
    ("fuzzlab/tools/spa.py", "fuzzlab.tools.store_adapter", "_TEXT_FILLER"):
        "as above",
    ("fuzzlab/harness/auto.py", "fuzzlab.oracle.strategies", "_TIMING_TEMPLATES"):
        "timing templates read by the harness; harness/* is another lane's (BUG-0148 sweep)",
    ("fuzzlab/labgen/conformance/django_live_boot.py",
     "fuzzlab.labgen.conformance.live_boot", "_NO_REDIRECT_OPENER"):
        "a sibling harness's opener, not a keyword vocabulary; outside BUG-0148's scope",
}


def _private_imports(source: str, rel: str) -> set[tuple[str, str, str]]:
    """``(file, module, name)`` for each ``from fuzzlab.x import _NAME`` (a private
    upper-case constant) of another module. A package's own private names are shared
    with its submodules (``php_laravel/auth_session.py`` reads ``php_laravel``'s)."""
    found = set()
    own = rel[:-3].replace("/", ".")
    parents = {own.rsplit(".", n)[0] for n in range(1, own.count(".") + 1)}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("fuzzlab") \
                and node.module != own and node.module not in parents:
            for alias in node.names:
                name = alias.name
                if name.startswith("_") and name.lstrip("_")[:1].isupper() \
                        and name.upper() == name:
                    found.add((rel, node.module, name))
    return found


def _package_private_imports() -> set[tuple[str, str, str]]:
    out = set()
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        out |= _private_imports(path.read_text(encoding="utf-8"),
                                path.relative_to(ROOT).as_posix())
    return out


def test_no_module_imports_another_modules_private_vocabulary():
    found = _package_private_imports()
    login = sorted(f for f in found if f[2].startswith("_LOGIN"))
    assert login == [], "the login vocabulary is detect.py's public names (SP-16)"
    assert found - set(_KNOWN_PRIVATE_IMPORTS) == set()
    assert set(_KNOWN_PRIVATE_IMPORTS) - found == set(), "stale allowlist entry"


def test_the_private_vocabulary_guard_catches_synthetic_offenders():
    """PA-0034(2): BUG-0148's own line, a multi-line import, an aliased one."""
    rel = "fuzzlab/session/browserlogin.py"
    assert _private_imports("from fuzzlab.session.detect import _LOGIN_SEGMENTS", rel)
    assert _private_imports("from fuzzlab.session.detect import (\n  X,\n  _LOGIN_TOKENS)",
                            rel)
    assert _private_imports("from fuzzlab.tools.spa import _MAX_GAP as gap", rel)
    assert not _private_imports("from fuzzlab.session.detect import LOGIN_WORDS", rel)
    assert not _private_imports("from fuzzlab.session.detect import _login_segment", rel)
    assert not _private_imports("from fuzzlab.session.browserlogin import _X", rel)


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
    links to as its login, then the fixed fallback paths."""
    app = fx.FrameworkApp(shape, "pw-" + uuid.uuid4().hex)
    try:
        store = CredentialStore(backend=FakeBackend())
        store.set("127.0.0.1", "user", fx.USER, app.password)
        mgr = SessionManager(store, scope_hosts=["127.0.0.1"])
        form, page, _challenge, _floor = mgr._discover_login_form(
            mgr._fetch_factory(), app.base)
        assert form is not None, app.requests
        assert form.action_url.split("?", 1)[0] == app.origin + shape.login
        assert shape.csrf in form.fields.names()
        assert form.password_field == shape.password
        assert not any(p.lower().startswith(("/register", "/users/sign_up",
                                             "/identity/account/register"))
                       for p in app.seen("GET"))
    finally:
        app.close()


@pytest.mark.parametrize("shape", [fx.RAILS, fx.DEVISE, fx.ASPNET],
                         ids=lambda s: s.name)
def test_a_full_login_through_the_requests_side(shape):
    """End to end through `SessionManager.ensure` with no browser: found by its link,
    posted once with its CSRF token, a cookie session."""
    app = fx.FrameworkApp(shape, "pw-" + uuid.uuid4().hex)
    try:
        store = CredentialStore(backend=FakeBackend())
        store.set("127.0.0.1", "user", fx.USER, app.password)
        mgr = SessionManager(store, scope_hosts=["127.0.0.1"], browser_login=False)
        state = mgr.ensure("127.0.0.1", "user", app.base, operator=True)
        assert state.valid and state.kind == "cookie"
        assert app.logins == [shape.login]
        assert [p.split("?", 1)[0] for p in app.seen("POST")] == [shape.login]
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


def test_a_decoy_login_linked_before_the_real_one_is_never_filled(apps):
    app = apps(fx.DECOY)
    _browser_login(app)
    assert app.logins == ["/login"]
    assert app.decoy_posts == []
    assert "/xss_login" not in app.seen("GET")         # rank 1 found it first


def test_an_identifier_first_login_is_named_in_the_diagnosis(apps):
    app = apps(fx.IDENTIFIER_FIRST)
    with pytest.raises(browserlogin.BrowserLoginError) as err:
        _browser_login(app)
    assert IDENTIFIER_FIRST in str(err.value)
    assert "link /signin" in str(err.value)
    assert app.seen("POST") == []


# --- stated residuals (strict xfails, PA-0054(3)) -----------------------------------------
@pytest.mark.xfail(strict=True, raises=browserlogin.BrowserLoginError,
                   reason="residual: a form inside a shadow root is not read (FORMS_JS)")
def test_residual_a_shadow_dom_login_form(apps):
    app = apps(fx.SHADOW_DOM)
    _browser_login(app)


@pytest.mark.xfail(strict=True, raises=browserlogin.BrowserLoginError,
                   reason="residual: a clickable div with no role is not an affordance")
def test_residual_a_clickable_div_with_no_role(apps):
    app = apps(fx.ROLELESS_DIV)
    _browser_login(app)


@pytest.mark.xfail(strict=True, raises=browserlogin.BrowserLoginError,
                   reason="residual: login labels are English only")
def test_residual_a_non_english_login_label(apps):
    app = apps(fx.NON_ENGLISH)
    _browser_login(app)


@pytest.mark.xfail(strict=True, raises=browserlogin.BrowserLoginError,
                   reason="residual: identifier-first (two-step) login is not supported")
def test_residual_an_identifier_first_login(apps):
    app = apps(fx.IDENTIFIER_FIRST)
    _browser_login(app)


@pytest.mark.xfail(strict=True, reason="spa.FORMS_JS re-marks a hidden form's controls "
                   "for an enclosing container (measured, BUG-0148 section 0); "
                   "spa.py is another lane's file")
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
