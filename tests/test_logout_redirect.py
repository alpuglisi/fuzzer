"""BUG-0122 / PA-0122: a redirect is a logout only to an anchored login URL.

The old rule (`"login" in location.lower()`) read bWAPP's
`ba_insecure_login.php -> ba_insecure_login_1.php` redirect as a logout: the run's
session re-logged in for nothing and the header breaker (FR-FUZZ-43) blamed the header
probe before it, so the live run's User-Agent / Referer pages were never probed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from fuzzlab.session.detect import detect_logout, looks_like_login_url, redirect_is_logout

ROOT = Path(__file__).resolve().parents[1]
LOGIN = "http://127.0.0.1:8090/bWAPP/login.php"
PAGE = "http://127.0.0.1:8090/bWAPP/ba_insecure_login.php"


@pytest.mark.parametrize("location,logout", [
    ("ba_insecure_login_1.php", False),           # bWAPP's in-app login page (the bug)
    ("login_form.php", False), ("loginhistory", False), ("portal.php", False),
    ("login.php", True),                          # relative, the session's own
    ("/bWAPP/login.php?next=portal.php", True),   # query and fragment ignored
    ("http://127.0.0.1:8090/bWAPP/login.php#x", True),
    ("/login?expired=1", True),                   # another login route (reviewer B)
    ("wp-login.php", False),                      # with a known login URL: whole only
    ("/Account/Login/", True), ("/users/sign_in", True),
    ("/auth/sign-in", True), ("/sessions/new", True), ("Logon.aspx", True),
    ("index.php?page=login.php", True), ("index.php?page=home", False),
])
def test_a_redirect_is_a_logout_only_to_a_login_url(location, logout):
    assert redirect_is_logout(location, PAGE, LOGIN) is logout
    assert detect_logout(302, {"Location": location}, "", login_url=LOGIN,
                         page_url=PAGE) is logout


def test_without_a_known_login_url_the_anchored_rule_still_decides():
    assert redirect_is_logout("/users/sign_in", "http://h/a", None)
    assert redirect_is_logout("/wp-login.php", "http://h/a", None)      # final token
    assert redirect_is_logout("/user_login", "http://h/a", None)
    assert not redirect_is_logout("/ba_insecure_login_1.php", "http://h/a", None)
    assert not redirect_is_logout("/loginhistory", "http://h/a", None)


def test_the_sessions_own_login_url_matches_by_key_scheme_upgrade_and_query():
    custom = "http://h/auth/enter.php"           # no login word: only the key matches
    assert redirect_is_logout("https://h/auth/enter.php", "http://h/a", custom)
    assert not redirect_is_logout("https://h:8443/auth/enter.php", "http://h/a", custom)
    assert not redirect_is_logout("http://other/auth/enter.php", "http://h/a", custom)
    routed = "http://h/index.php?page=signin_form"   # query-routed (reviewer B)
    assert not redirect_is_logout("index.php", "http://h/x.php", routed)
    assert not redirect_is_logout("index.php?page=home", "http://h/x.php", routed)
    assert redirect_is_logout("index.php?page=signin_form&next=x", "http://h/x.php",
                              routed)


#: Page names of the lab app (PA-0022's vocabulary check, reviewer B): only bWAPP's own
#: login page is a login URL when the session knows it.
_BWAPP_PAGES = ["login.php", "portal.php", "ba_insecure_login.php",
                "ba_insecure_login_1.php", "xss_login.php", "sqli_3.php", "sqli_16.php",
                "ba_weak_pwd.php", "ba_pwd_attacks_2.php", "logout.php", "reset.php",
                "user_new.php", "info.php", "index.php?page=xss_login.php"]


def test_the_lab_vocabulary_has_one_login_url():
    hits = [p for p in _BWAPP_PAGES if redirect_is_logout(p, PAGE, LOGIN)]
    assert hits == ["login.php"]


def test_only_web_urls_are_judged():
    assert not redirect_is_logout("javascript:login", PAGE, None)
    assert not looks_like_login_url("mailto:login@example.invalid")


def test_looks_like_login_url_is_total():
    for value in ("", None, "?", "//", "http://", "/" * 1000, "a" * 10000):
        assert looks_like_login_url(value) in (True, False)


def test_an_in_app_login_redirect_neither_logs_out_nor_trips_the_header_breaker():
    from fuzzlab.oracle.probe import Probe  # noqa: F401  (import check)
    from tests.test_login_form_isolation import BASE, FakeApp, _seam

    class App(FakeApp):
        def page(self, method, url, sid, data):
            from urllib.parse import urlsplit
            if urlsplit(url).path == "/app/ba_insecure_login.php" and sid in self.sessions:
                return 302, {"Location": "ba_insecure_login_1.php"}, b""
            return super().page(method, url, sid, data)
    app = App()
    _mgr, _client, sender = _seam(app)
    sender.send(BASE + "portal.php", "x", "1")
    sender.send(BASE + "ba_insecure_login.php", "User-Agent", "fz", location="header")
    sender.send(BASE + "portal.php", "x", "1")
    assert sender.header_stop_reason is None
    assert app.login_posts == 1                       # no needless re-login


# --- PA-0122: no substring test decides session or auth state -------------------------
_AUTH_WORDS = re.compile(r"login|logon|sign_?in|logout|sign_?out|auth|session|sso|passw|"
                         r"credential", re.I)
#: Modules whose rules decide session or auth state, auth-endpoint membership or
#: credential handling from a URL, a Location or a name (reviewer A's scope). The
#: oracle's vulnerability detectors are out of scope by design.
_SCOPE = ["fuzzlab/session/manager.py", "fuzzlab/session/detect.py",
          "fuzzlab/session/state.py", "fuzzlab/session/cli.py",
          "fuzzlab/session/browserlogin.py",   # SPA login detection (CC-SESS-0021)
          "fuzzlab/tools/probesender.py", "fuzzlab/tools/authhttp.py",
          "fuzzlab/tools/browserauth.py", "fuzzlab/tools/formnav.py",
          "fuzzlab/tools/navguard.py", "fuzzlab/tools/spider.py",
          "fuzzlab/tools/spa.py",       # SPA form submission: password forms (CC-CRAWL-0017)
          "fuzzlab/tools/store_adapter.py", "fuzzlab/harness/auto.py",
          "fuzzlab/core/urls.py"]
#: Membership in a mapping by an exact key is not a substring test.
_MAPPINGS = {"applied", "low", "headers", "cookies", "jar"}


def _substring_auth_tests(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Compare)
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)):
            continue
        left, right = node.left, node.comparators[0]
        if not (isinstance(left, ast.Constant) and isinstance(left.value, str)
                and _AUTH_WORDS.search(left.value)):
            continue
        if isinstance(right, ast.Name) and right.id in _MAPPINGS:
            continue
        found.append(ast.unparse(node))
    return found


def test_no_substring_test_decides_session_or_auth_state():
    offenders = {}
    for rel in _SCOPE:
        hits = _substring_auth_tests((ROOT / rel).read_text())
        if hits:
            offenders[rel] = hits
    assert offenders == {}


def test_the_guard_catches_a_synthetic_offender():
    """PA-0034(2): the old rule, and two variants, are flagged."""
    assert _substring_auth_tests('x = "login" in location.lower()')
    assert _substring_auth_tests('y = "signin" in url')
    assert _substring_auth_tests('z = "logout" not in href')
    assert not _substring_auth_tests('w = "Authorization" in headers')
