"""Tests for Playwright session injection (Option A, browser path).

No browser needed: browserauth only shapes the session data and applies it to a
context object, so a fake context captures the calls.
"""

from fuzzlab.session.manager import SessionManager
from fuzzlab.tools import browserauth
from tests.test_session_manager import BearerLoginFetcher, CookieLoginFetcher, _factory, _jwt, _store


class FakeContext:
    """Records what is applied; ``set_extra_http_headers`` must never be called."""

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
    # scoped to the origin root, whatever path the base has (BUG-0113)
    assert cookies == [{"name": "PHPSESSID", "value": "sess1", "url": "http://localhost/"}]
    assert headers == {}

    ctx = FakeContext()
    browserauth.apply_to_context(ctx, cookies, headers)
    assert ctx.added_cookies == cookies
    assert ctx.extra_headers is None                 # no extra headers for cookie auth


def test_bearer_session_headers_go_through_the_route_only():
    """FR-CRAWL-14 (reviewers A6/B7): a bearer session's header is never set on the
    context (``set_extra_http_headers`` would send it wherever the browser goes); it is
    handed to the guarded route with a scope (`browser_session`)."""
    import pytest
    token = _jwt(9999999999)
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(BearerLoginFetcher(token)))
    cookies, headers = browserauth.playwright_auth(mgr, "admin", "http://localhost")
    assert cookies == []
    assert headers == {"Authorization": f"Bearer {token}"}

    ctx = FakeContext()
    with pytest.raises(ValueError):
        browserauth.apply_to_context(ctx, cookies, headers)
    assert ctx.extra_headers is None and ctx.added_cookies is None

    from fuzzlab.core.urls import in_origin_scope, origin_scope
    origins = origin_scope("http://localhost/")
    session = browserauth.browser_session(mgr, "admin", "http://localhost",
                                          in_scope=lambda u: in_origin_scope(u, origins))
    assert session.headers == {"Authorization": f"Bearer {token}"}
    assert session.storage_state is None and session.local_storage == {}
    scope = session.header_scope
    assert scope("http://localhost/a") and scope("http://127.0.0.1/a")     # aliases
    assert not scope("http://localhost:3000/a")                            # another port
    assert not scope("https://evil.example/a")
    assert token not in repr(session)


def test_an_https_sessions_headers_never_go_over_http():
    """FR-SESS-13 at the browser: a secure-only session's header scope refuses http."""
    from fuzzlab.session.state import SessionState

    class Mgr:
        def ensure(self, host, identity, base_url, *, operator=False):
            return SessionState(host, identity, kind="bearer",
                                headers={"Authorization": "Bearer T"}, valid=True,
                                secure_only=True)
    session = browserauth.browser_session(Mgr(), "u", "https://shop.example/",
                                          in_scope=lambda u: "shop.example" in u)
    assert session.header_scope("https://shop.example/x")
    assert not session.header_scope("http://shop.example/x")
