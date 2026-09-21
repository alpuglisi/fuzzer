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
    assert data["username"] == "admin"
    assert data["password"] == "admin123"
    assert data["user_token"] == "abc123"        # CSRF hidden field carried through


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
