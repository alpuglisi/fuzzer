"""Phase 6 T6.5: manual-login session capture (FR-PROXY-9) + manager adoption."""

import base64
import json
import types

from fuzzlab.core.store import Store
from fuzzlab.proxy.session_capture import SessionCapture
from fuzzlab.session.manager import SessionManager

HOST = "127.0.0.1"

LOGIN_RESP = (b"HTTP/1.1 302 Found\r\nLocation: /home\r\n"
              b"Set-Cookie: PHPSESSID=abc123secret; Path=/; HttpOnly\r\n\r\n")
NEXT_REQ = (b"GET /home HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            b"Cookie: PHPSESSID=abc123secret\r\n\r\n")


def _jwt(exp: int) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256'})}.{seg({'exp': exp})}.sig"


def _request(url):
    return types.SimpleNamespace(url=url, headers={})


def test_capture_cookies_from_flows():
    cap = SessionCapture(HOST, "user")
    assert cap.has_session() is False and cap.state() is None
    cap.observe_response(LOGIN_RESP)
    cap.observe_request(NEXT_REQ)
    st = cap.state()
    assert st is not None and st.kind == "cookie" and st.valid
    assert st.cookies == {"PHPSESSID": "abc123secret"}


def test_capture_bearer_token_and_exp():
    cap = SessionCapture(HOST, "user")
    token = _jwt(9999999999)
    cap.observe_request(
        b"GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        b"Authorization: Bearer " + token.encode() + b"\r\n\r\n")
    st = cap.state()
    assert st.kind == "bearer"
    assert st.headers["Authorization"] == f"Bearer {token}"
    assert st.token_exp == 9999999999.0


def test_adopt_into_manager_authenticates_without_login(tmp_path):
    with Store(tmp_path / "u.db") as store:
        # A manager that could never log in on its own (no creds, empty scope).
        mgr = SessionManager(credentials=None, scope_hosts=[], store=store)
        cap = SessionCapture(HOST, "user")
        cap.observe_response(LOGIN_RESP)
        cap.observe_request(NEXT_REQ)
        cap.adopt_into(mgr)

        # prepare() now applies the captured cookie — no login handshake happens.
        req = _request("http://127.0.0.1:8080/product.php?id=1")
        mgr.prepare(req, "user")
        assert req.headers.get("Cookie") == "PHPSESSID=abc123secret"


def test_adopt_persists_only_non_secret_metadata(tmp_path):
    with Store(tmp_path / "u.db") as store:
        mgr = SessionManager(credentials=None, scope_hosts=[], store=store)
        cap = SessionCapture(HOST, "user")
        cap.observe_response(LOGIN_RESP)
        cap.adopt_into(mgr)

        row = store.get_session_state(HOST, "user")
        assert row is not None and row["kind"] == "cookie" and row["valid"] == 1
        # the secret cookie value never lands in the store
        dumped = json.dumps(row)
        assert "abc123secret" not in dumped
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(session_state)")}
        assert "cookies" not in cols and "headers" not in cols
