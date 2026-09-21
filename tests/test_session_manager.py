"""Tests for the SessionManager: detection-only login, per-host creds (T1.4-T1.9)."""

import base64
import json
import threading

import pytest

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import Request, Response
from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager
from tests.test_credentials import FakeBackend

LOGIN_HTML = """
<form method="post" action="/login.php">
  <input type="hidden" name="user_token" value="abc123">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
"""


def _jwt(exp):
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256'})}.{seg({'exp': exp})}.sig"


class CookieLoginFetcher:
    def __init__(self):
        self.logged_in = False
        self._cookies = {}
        self.post_count = 0

    def get(self, url, headers=None):
        if url.endswith("/login.php"):
            return FetchResponse(200, {}, LOGIN_HTML)
        if self.logged_in:
            return FetchResponse(200, {}, "<html>welcome admin</html>")
        return FetchResponse(200, {}, "<html>home</html>")

    def post(self, url, data=None, headers=None):
        self.post_count += 1
        data = data or {}
        if (data.get("username") == "admin" and data.get("password") == "admin123"
                and data.get("user_token") == "abc123"):
            self.logged_in = True
            self._cookies = {"PHPSESSID": "sess1"}
            return FetchResponse(200, {}, "<html>welcome</html>")
        return FetchResponse(200, {}, LOGIN_HTML)  # re-render on bad creds

    def cookies(self):
        return dict(self._cookies)


class BearerLoginFetcher:
    def __init__(self, token):
        self.token = token
        self.logged_in = False

    def get(self, url, headers=None):
        if self.logged_in:
            return FetchResponse(200, {}, "<html>dashboard</html>")
        # login form served on the base URL, posting to a JSON endpoint
        return FetchResponse(200, {}, LOGIN_HTML.replace("/login.php", "/rest/user/login"))

    def post(self, url, data=None, headers=None):
        self.logged_in = True
        body = json.dumps({"authentication": {"token": self.token, "umail": "a@b.c"}})
        return FetchResponse(200, {"Content-Type": "application/json"}, body)

    def cookies(self):
        return {}


def _store():
    store = CredentialStore(backend=FakeBackend())
    store.set("localhost", "admin", "admin", "admin123")
    return store


def _factory(fetcher, created=None):
    def factory():
        if created is not None:
            created.append(fetcher)
        return fetcher
    return factory


def test_cookie_login_and_prepare_attaches_session():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    state = mgr.ensure("localhost", "admin", "http://localhost")
    assert state.valid and state.kind == "cookie" and state.cookies == {"PHPSESSID": "sess1"}
    req = Request("GET", "http://localhost/product.php", identity="admin")
    mgr.prepare(req, "admin")
    assert req.headers["Cookie"] == "PHPSESSID=sess1"


def test_bearer_login_reads_jwt_exp():
    token = _jwt(9999999999)
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(BearerLoginFetcher(token)))
    state = mgr.ensure("localhost", "admin", "http://localhost")
    assert state.kind == "bearer"
    assert state.headers["Authorization"] == f"Bearer {token}"
    assert state.token_exp == 9999999999.0


def test_wrong_credentials_fail_loud():
    store = CredentialStore(backend=FakeBackend())
    store.set("localhost", "admin", "admin", "WRONG")
    mgr = SessionManager(store, scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    with pytest.raises(SessionAuthError):
        mgr.ensure("localhost", "admin", "http://localhost")


def test_no_login_form_fails_loud():
    class NoFormFetcher:
        def get(self, url, headers=None):
            return FetchResponse(200, {}, "<html>no login here</html>")
        def post(self, url, data=None, headers=None):
            return FetchResponse(200, {}, "")
        def cookies(self):
            return {}
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(NoFormFetcher()))
    with pytest.raises(SessionAuthError):
        mgr.ensure("localhost", "admin", "http://localhost")


def test_missing_credentials_fail_loud():
    mgr = SessionManager(CredentialStore(backend=FakeBackend()), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    with pytest.raises(Exception):  # CredentialError (a fail-loud, no silent run)
        mgr.ensure("localhost", "admin", "http://localhost")


def test_out_of_scope_host_refused():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    with pytest.raises(SessionAuthError):
        mgr.ensure("evil.example", "admin", "http://evil.example")


def test_anonymous_needs_no_login():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    state = mgr.ensure("localhost", "anonymous", "http://localhost")
    assert state.valid and state.kind == "none"


def test_single_flight_logs_in_once():
    created = []
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher(), created))
    barrier = threading.Barrier(5)

    def worker():
        barrier.wait()
        mgr.ensure("localhost", "admin", "http://localhost")

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    # Concurrent ensure -> exactly one login handshake.
    assert len(created) == 1
    assert created[0].post_count == 1


def test_auth_endpoints_recorded_for_exclusion():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    mgr.ensure("localhost", "admin", "http://localhost")
    assert mgr.is_auth_endpoint("http://localhost/login.php")
    assert not mgr.is_auth_endpoint("http://localhost/product.php")


def test_observe_marks_logout_and_reauth_recovers():
    fetcher = CookieLoginFetcher()
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(fetcher))
    mgr.ensure("localhost", "admin", "http://localhost")
    req = Request("GET", "http://localhost/profile.php", identity="admin")
    # A response that is a login page => logged out.
    mgr.observe(req, Response(200, {}, LOGIN_HTML.encode(), 5.0), "admin")
    assert not mgr._state[("localhost", "admin")].valid
    # prepare() re-authenticates on the next request.
    mgr.prepare(req, "admin")
    assert mgr._state[("localhost", "admin")].valid


def test_standalone_session_header():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    header = mgr.session_header("localhost", "admin", "http://localhost")
    assert header == "Cookie: PHPSESSID=sess1"


def test_manager_is_drop_in_http_seam_addon():
    """The HTTP seam calls prepare/observe; the manager attaches the session."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient

    seen = {}

    def transport(method, url, headers, body, timeout):
        seen["headers"] = dict(headers)
        return 200, {"Content-Type": "text/html"}, b"<html>welcome admin</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(10), ["localhost"], session=mgr, transport=transport)
    resp = client.send(Request("GET", "http://localhost/profile.php", identity="admin"))
    assert resp.status == 200
    # prepare() logged in and attached the session cookie to the outbound request.
    assert seen["headers"].get("Cookie") == "PHPSESSID=sess1"
