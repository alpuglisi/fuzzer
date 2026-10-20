"""Tests for dynamic login/session detection and session state (T1.2-T1.5)."""

import base64
import json

from fuzzlab.session import detect
from fuzzlab.session.state import SessionState


def _jwt(exp):
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256'})}.{seg({'exp': exp, 'sub': 'admin'})}.sig"


PFF_LOGIN = """
<html><body>
  <form method="post" action="/login.php">
    <input type="hidden" name="user_token" value="abc123">
    <label>Username <input type="text" name="username"></label>
    <label>Password <input type="password" name="password"></label>
    <button type="submit">Log in</button>
  </form>
</body></html>
"""


def test_find_login_form_and_carry_hidden_fields():
    form = detect.find_login_form(PFF_LOGIN, "http://localhost/login.php")
    assert form is not None
    assert form.method == "POST"
    assert form.action_url == "http://localhost/login.php"
    assert form.username_field == "username"
    assert form.password_field == "password"
    data = form.fill("admin", "admin123")
    assert data.get("username") == "admin"
    assert data.get("password") == "admin123"
    assert data.get("user_token") == "abc123"        # CSRF hidden field carried through


def test_is_login_page():
    assert detect.is_login_page(PFF_LOGIN)
    assert not detect.is_login_page("<html><body>welcome</body></html>")


def test_no_login_form_on_ordinary_page():
    assert detect.find_login_form("<html><body>no form here</body></html>", "/x") is None


def test_detect_cookie_credential_from_jar():
    cred = detect.detect_session_credential(200, {}, "", cookies={"PHPSESSID": "xyz"})
    assert cred.kind == "cookie" and cred.cookies == {"PHPSESSID": "xyz"}


def test_detect_cookie_credential_from_header():
    cred = detect.detect_session_credential(
        302, {"Set-Cookie": "PHPSESSID=abc; Path=/; HttpOnly"}, "")
    assert cred.kind == "cookie" and cred.cookies == {"PHPSESSID": "abc"}


def test_detect_bearer_from_juice_shop_shape():
    token = _jwt(9999999999)
    body = json.dumps({"authentication": {"token": token, "umail": "a@b.c"}})
    cred = detect.detect_session_credential(200, {"Content-Type": "application/json"}, body)
    assert cred.kind == "bearer"
    assert cred.headers["Authorization"] == f"Bearer {token}"
    assert cred.token_exp == 9999999999.0


def test_detect_basic_challenge():
    cred = detect.detect_session_credential(
        401, {"WWW-Authenticate": 'Basic realm="x"'}, "")
    assert cred.kind == "basic"


def test_undetectable_returns_none():
    assert detect.detect_session_credential(200, {}, "just some html") is None


def test_decode_jwt_exp():
    assert detect.decode_jwt_exp(_jwt(1700000000)) == 1700000000.0
    assert detect.decode_jwt_exp("not-a-jwt") is None


def test_detect_logout_signals():
    assert detect.detect_logout(401, {}, "")
    assert detect.detect_logout(302, {"Location": "/login.php"}, "")
    assert detect.detect_logout(200, {}, PFF_LOGIN)          # login page reappeared
    assert not detect.detect_logout(200, {}, "<html>welcome back</html>")


def test_session_state_apply_and_redacted():
    st = SessionState("localhost", "admin", kind="cookie", cookies={"PHPSESSID": "s"})
    applied = st.apply({"Accept": "text/html"})
    assert applied["Cookie"] == "PHPSESSID=s" and applied["Accept"] == "text/html"
    st2 = SessionState("h", "u", kind="bearer",
                       headers={"Authorization": "Bearer SECRETVALUE123"})
    assert st2.apply({})["Authorization"] == "Bearer SECRETVALUE123"
    red = st2.redacted()
    assert "SECRETVALUE123" not in json.dumps(red)           # values never leak
    assert red["auth_headers"] == ["Authorization"]


def test_session_state_time_expiry():
    st = SessionState("h", "u", kind="bearer", token_exp=1000.0)
    assert st.is_time_expired(now=2000.0)
    assert not st.is_time_expired(now=500.0)
    assert not SessionState("h", "u").is_time_expired(now=2000.0)   # no exp -> not expired


# --- SP-16 login facts for SP-56 (CC-SESS-0028, FR-SESS-22; AU-OUTCOME, BUG-0529) -------

def test_login_facts_reads_location_in_any_case_against_the_follow_ups_url():
    """A1: ``Location`` in any case; a relative one resolved against the answer's own URL
    (a PRG follow-up's), not the request's."""
    for name in ("Location", "location", "LOCATION"):
        facts = detect.login_facts("http://h/app/items", {name: "/login"})
        assert facts.redirect_to_login, name
    # "enter" relative to the follow-up's URL is /app/enter, the session's login page;
    # relative to the request's URL it is /other/enter, which is none
    known = "http://h/app/enter"
    assert detect.login_facts("http://h/other/x", {"Location": "enter"},
                              response_url="http://h/app/items",
                              login_url=known).redirect_to_login
    assert not detect.login_facts("http://h/other/x", {"Location": "enter"},
                                  login_url=known).redirect_to_login
    assert not detect.login_facts("http://h/app/items", {"Location": "/items?page=2"}
                                  ).redirect_to_login
    assert not detect.login_facts("http://h/app/items", None).redirect_to_login


def test_login_facts_names_every_credential_submission():
    """M2 (reviewer A's measured true positives) and B1: an SP-16 login URL; a path
    naming account creation or a password reset; a credential name among the entries
    (a JSON leaf by its display name). A path that names a user or an account resource
    is none: the four measured over-matches of the login window's account test."""
    named = ["http://h/rest/user/login", "http://h/register", "http://h/api/sign-up",
             "http://h/api/signup", "http://h/user/password/reset",
             "http://h/registration"]
    for url in named:
        assert detect.login_facts(url).credential_submission, url
    assert detect.login_facts("http://h/j_security_check",
                              entry_names=("j_username", "j_password")).credential_submission
    assert detect.login_facts("http://h/api/session",
                              entry_names=("email", "password")).credential_submission
    for url in ("http://h/api/users/42", "http://h/api/account/billing",
                "http://h/rest/user/whoami", "http://h/api/orders/42/change-status",
                "http://h/api/items"):
        assert not detect.login_facts(url, entry_names=("id", "csrf_token")
                                      ).credential_submission, url
    # a name that is not a string (a JSON path tuple) is ignored, never a TypeError
    assert not detect.login_facts("http://h/api/x", entry_names=(("password",), 3)
                                  ).credential_submission


def test_login_facts_names_an_account_submission_apart_from_a_login():
    """ADOPT 5: a registration's redirect to the login page is its success; a login's is
    its failure -- only a path naming account creation or a password reset, at no login
    URL, is an account submission."""
    assert detect.login_facts("http://h/api/register").account_submission
    assert detect.login_facts("http://h/password/reset").account_submission
    assert not detect.login_facts("http://h/api/login").account_submission
    assert not detect.login_facts("http://h/api/session",
                                  entry_names=("password",)).account_submission


def test_login_facts_uses_the_sessions_known_login_url():
    """A known ``login_url`` names its own login route and its redirects, even one SP-16's
    anchored tokens would not."""
    known = "http://h/auth/enter"
    assert not detect.login_facts("http://h/auth/enter").credential_submission
    assert detect.login_facts("http://h/auth/enter", login_url=known).credential_submission
    assert detect.login_facts("http://h/items", {"Location": "/auth/enter"},
                              login_url=known).redirect_to_login


def test_login_facts_is_total():
    for url, headers in ((None, None), ("", 5), ("::not a url", {"Location": None}),
                         ("http://h/x", ["bad"])):
        facts = detect.login_facts(url, headers, entry_names=None)
        assert facts.credential_submission in (True, False)
