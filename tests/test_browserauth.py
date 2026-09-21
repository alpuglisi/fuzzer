"""Tests for Playwright session injection (Option A, browser path).

No browser needed: browserauth only shapes the session data and applies it to a
context object, so a fake context captures the calls.
"""

from fuzzlab.session.manager import SessionManager
from fuzzlab.tools import browserauth
from tests.test_session_manager import BearerLoginFetcher, CookieLoginFetcher, _factory, _jwt, _store


class FakeContext:
    def __init__(self):
        self.added_cookies = None
        self.extra_headers = None

    def add_cookies(self, cookies):
        self.added_cookies = cookies

    def set_extra_http_headers(self, headers):
        self.extra_headers = headers


def test_cookie_session_becomes_playwright_cookies():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    cookies, headers = browserauth.playwright_auth(mgr, "admin", "http://localhost")
    assert cookies == [{"name": "PHPSESSID", "value": "sess1", "url": "http://localhost"}]
    assert headers == {}

    ctx = FakeContext()
    browserauth.apply_to_context(ctx, cookies, headers)
    assert ctx.added_cookies == cookies
    assert ctx.extra_headers is None                 # no extra headers for cookie auth


def test_bearer_session_becomes_extra_header():
    token = _jwt(9999999999)
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(BearerLoginFetcher(token)))
    cookies, headers = browserauth.playwright_auth(mgr, "admin", "http://localhost")
    assert cookies == []
    assert headers == {"Authorization": f"Bearer {token}"}

    ctx = FakeContext()
    browserauth.apply_to_context(ctx, cookies, headers)
    assert ctx.added_cookies is None
    assert ctx.extra_headers == {"Authorization": f"Bearer {token}"}
