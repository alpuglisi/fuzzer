"""Login navigation is anchored to operator input, and a session never travels over a
downgrade (BUG-0097 / BUG-0098, FR-SESS-12 / FR-SESS-13, PA-0098 / PA-0099).

BUG-0097: an in-scope login page that redirected to another origin made that origin
the trust anchor, so a relative form action there received the password. BUG-0098: an
https-established session was applied to plain-http requests (and greybox sent its
cookie unchecked).
"""

from __future__ import annotations

import pytest

from fuzzlab.session.manager import (MAX_LOGIN_HOPS, FetchResponse, SessionAuthError,
                                     SessionManager)
from fuzzlab.session.state import SessionState, secure_only_of

FORM = ('<form method=post action="{action}"><input name=user>'
        '<input type=password name=pw></form>')


class _Cred:
    username, password = "alice", "S3CRET"


class _Creds:
    def require(self, host, identity):
        return _Cred()


class _Web:
    """A fetcher that never follows redirects: ``routes`` maps a URL to a response."""

    def __init__(self, routes, post=None):
        self.routes, self.log = routes, []
        self.post_resp = post or FetchResponse(200, {"Set-Cookie": "s=1"}, "welcome")

    def get(self, url, headers=None, allow_redirects=True):
        assert allow_redirects is False            # discovery never lets it follow
        self.log.append(("GET", url))
        return self.routes.get(url, FetchResponse(200, {}, "<p>home</p>"))

    def post(self, url, data=None, headers=None, allow_redirects=True):
        self.log.append(("POST", url))
        return self.post_resp

    def cookies(self):
        return {"s": "1"}


def _302(to):
    return FetchResponse(302, {"Location": to}, "")


def _mgr(web, scope=("lab.example",), **kw):
    return SessionManager(_Creds(), scope_hosts=list(scope), fetch_factory=lambda: web, **kw)


# --- BUG-0097 ---------------------------------------------------------------------

def test_a_redirect_to_another_origin_is_never_fetched_nor_trusted():
    """The audit's repro: https://lab.example/login -> https://attacker.example/login,
    whose form posts to a relative /collect."""
    web = _Web({"https://lab.example/login": _302("https://attacker.example/login"),
                "https://attacker.example/login":
                    FetchResponse(200, {}, FORM.format(action="/collect"))})
    with pytest.raises(SessionAuthError, match="auth_origins"):
        _mgr(web).ensure("lab.example", "user", "https://lab.example/")
    assert not [u for _m, u in web.log if "attacker" in u]     # never even fetched
    assert not [e for e in web.log if e[0] == "POST"]


def test_an_in_scope_multi_hop_login_still_works():
    web = _Web({"https://lab.example/login": _302("/auth/start"),
                "https://lab.example/auth/start": _302("/auth/login"),
                "https://lab.example/auth/login":
                    FetchResponse(200, {}, FORM.format(action="/auth/login"))})
    state = _mgr(web).ensure("lab.example", "user", "https://lab.example/")
    assert state.valid and ("POST", "https://lab.example/auth/login") in web.log


def test_an_authorised_sso_origin_may_host_the_login():
    web = _Web({"https://lab.example/login": _302("https://sso.lab:8443/login"),
                "https://sso.lab:8443/login":
                    FetchResponse(200, {}, FORM.format(action="/login"))})
    state = _mgr(web, auth_origins=["https://sso.lab:8443"]).ensure(
        "lab.example", "user", "https://lab.example/")
    assert state.valid and ("POST", "https://sso.lab:8443/login") in web.log


def test_too_many_hops_are_refused():
    routes = {f"https://lab.example/h{i}": _302(f"/h{i + 1}")
              for i in range(MAX_LOGIN_HOPS + 2)}
    routes["https://lab.example/login"] = _302("/h0")
    web = _Web(routes)
    with pytest.raises(SessionAuthError, match="redirects"):
        _mgr(web).ensure("lab.example", "user", "https://lab.example/")


def test_a_fetcher_that_cannot_refuse_redirects_fails_closed():
    """A3: a fetcher whose `get` has no allow_redirects must prove it did not follow
    one, by reporting the URL it was asked for."""
    class Following:
        def get(self, url, headers=None):
            if url.endswith("/login"):
                return FetchResponse(200, {}, FORM.format(action="/collect"),
                                     url="https://attacker.example/login")
            return FetchResponse(200, {}, "<p>home</p>", url=url)

        def post(self, url, data=None, headers=None, allow_redirects=True):
            raise AssertionError("never reached")

        def cookies(self):
            return {}
    with pytest.raises(SessionAuthError, match="cannot refuse redirects"):
        _mgr(Following()).ensure("lab.example", "user", "https://lab.example/")


def test_the_destination_anchor_is_the_base_url_not_the_page():
    m = _mgr(_Web({}))
    # same origin as the base, in scope, an upgrade: allowed
    assert m._credential_destination_ok("https://lab.example/x", "https://lab.example/")
    assert m._credential_destination_ok("https://lab.example:9/x", "https://lab.example/")
    assert m._credential_destination_ok("https://lab.example/x", "http://lab.example/")
    # an off-scope origin is never allowed, whatever page it came from
    assert not m._credential_destination_ok("https://attacker.example/c",
                                            "https://lab.example/")


# --- BUG-0098 ---------------------------------------------------------------------

class _Req:
    def __init__(self, url):
        self.url, self.headers = url, {}


def _with_state(secure_only=None, login_url="https://lab.example/login"):
    m = SessionManager(None, scope_hosts=["lab.example"], fetch_factory=lambda: None)
    m._state[("lab.example", "user")] = SessionState(
        "lab.example", "user", kind="cookie", cookies={"s": "SECRET"},
        headers={"Authorization": "Bearer SECRET"}, login_url=login_url, valid=True,
        secure_only=secure_only)
    return m


def test_an_https_session_is_never_applied_over_http():
    """The audit's repro: the cookie and bearer token went to http://lab.example/x."""
    m = _with_state()
    req = _Req("http://lab.example/x")
    with pytest.raises(SessionAuthError, match="plain http"):
        m.prepare(req, "user")
    assert req.headers == {}


def test_another_port_over_https_is_allowed_by_design():
    """Sessions are keyed per host (D12, FR-SESS-13): another https port is allowed."""
    m = _with_state()
    req = _Req("https://lab.example:9999/x")
    m.prepare(req, "user")
    assert "SECRET" in req.headers["Cookie"]


def test_an_http_session_on_http_is_allowed():
    m = _with_state(login_url="http://lab.example/login")
    req = _Req("http://lab.example/x")
    m.prepare(req, "user")
    assert req.headers["Authorization"] == "Bearer SECRET"


def test_a_login_over_https_marks_the_session_secure_only():
    web = _Web({"https://lab.example/login": FetchResponse(200, {},
                                                           FORM.format(action="/login"))})
    state = _mgr(web).ensure("lab.example", "user", "https://lab.example/")
    assert state.secure_only is True
    web = _Web({"http://lab.example/login": FetchResponse(200, {},
                                                          FORM.format(action="/login"))})
    assert _mgr(web).ensure("lab.example", "user", "http://lab.example/").secure_only is False


def test_session_header_refuses_an_http_base_for_an_https_session():
    m = _with_state()
    with pytest.raises(SessionAuthError, match="plain http"):
        m.session_header("lab.example", "user", "http://lab.example/")
    assert "SECRET" in m.session_header("lab.example", "user", "https://lab.example/")


def test_a_plugin_retarget_cannot_carry_the_session_elsewhere():
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient, Request
    sent = []

    class Retarget:
        def __init__(self, to):
            self.to = to

        def on_request(self, request):
            request.url = self.to
            return request

        def on_response(self, request, response):
            pass

    for to in ("http://lab.example/x", "https://other.lab/x"):
        m = _with_state()
        client = HttpClient(RequestBudget(10), ["lab.example", "other.lab"], session=m,
                            plugins=Retarget(to),
                            transport=lambda *a: sent.append(a) or (200, {}, b""))
        with pytest.raises(SessionAuthError):
            client.send(Request("GET", "https://lab.example/x", identity="user"))
    assert sent == []                                   # nothing left the client


def test_captured_https_sessions_are_secure_only():
    from fuzzlab.proxy.session_capture import SessionCapture
    cap = SessionCapture("lab.example", "user")
    cap.observe_request(b"GET / HTTP/1.1\r\nHost: lab.example\r\nCookie: s=1\r\n\r\n",
                        url="https://lab.example/")
    assert cap.state().secure_only is True
    cap = SessionCapture("lab.example", "user")
    cap.observe_response(b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/; Secure\r\n\r\n")
    assert cap.state().secure_only is True
    cap = SessionCapture("lab.example", "user")
    cap.observe_request(b"GET / HTTP/1.1\r\nHost: lab.example\r\nCookie: s=1\r\n\r\n",
                        url="http://lab.example/")
    assert cap.state().secure_only is False


@pytest.mark.parametrize("record,want", [
    ({"login_url": "https://lab.example/login"}, True),
    ({"login_url": "http://lab.example/login"}, False),
    ({"login_url": None}, True),                         # unknown: fail closed (B-N6)
    ({}, True),
    ({"login_url": "http://x/", "secure_only": True}, True),
])
def test_legacy_persisted_sessions_get_a_derived_secure_only(record, want):
    assert secure_only_of(record) is want


def test_greybox_never_sends_an_https_cookie_over_http():
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    sent = []

    class Session:
        def request(self, method, url, **kw):
            sent.append(url)
            raise AssertionError("must not be reached")

    s = RequestsCorrelatingSender(cookie="s=SECRET", cookie_secure_only=True,
                                  session=Session(), id_factory=lambda: "id")
    with pytest.raises(SessionAuthError, match="plain http"):
        s.send_correlated("http://lab.example/q", "q", "v")
    assert sent == []
