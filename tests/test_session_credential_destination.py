"""Credentials go only to an authorised origin, and never ride a redirect
(BUG-0081, FR-SESS-12, PA-0082). HTTP Basic is detected at discovery.

A login page whose form said `action="http://attacker.example/c"` got the stored
username and password POSTed there. The default fetcher also followed redirects on the
POST, so a 307 re-sent the body anywhere. And a Basic-auth site (no form) could never
log in.
"""

from __future__ import annotations

import base64

import pytest

from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager


class _Cred:
    username, password = "alice", "s3cr3t-pw"


class _Creds:
    def require(self, host, identity):
        return _Cred()


FORM = ('<form method=post action="{action}"><input name=user>'
        '<input type=password name=pw></form>')


class _Site:
    """A fake fetcher: the login page has a form posting to ``action``; the POST answers
    ``post_resp``; every request is logged."""

    def __init__(self, action, post_resp=None, follow=None):
        self.action, self.log = action, []
        self.post_resp = post_resp or FetchResponse(200, {"Set-Cookie": "s=1"}, "welcome")
        self.follow = follow or {}

    def get(self, url, headers=None):
        self.log.append(("GET", url))
        if url in self.follow:
            return self.follow[url]
        if url.endswith("/login"):
            return FetchResponse(200, {}, FORM.format(action=self.action))
        return FetchResponse(200, {}, "<p>home</p>")

    def post(self, url, data=None, headers=None, allow_redirects=True):
        assert allow_redirects is False                   # the manager never lets it
        self.log.append(("POST", url))
        return self.post_resp

    def cookies(self):
        return {"s": "1"}


def _manager(site, **kw):
    return SessionManager(_Creds(), scope_hosts=kw.pop("scope", ["127.0.0.1"]),
                          fetch_factory=lambda: site, **kw)


@pytest.mark.parametrize("action", ["http://attacker.example/c",
                                    "https://127.0.0.1.attacker.example/c",
                                    "//attacker.example/c"])
def test_a_cross_origin_form_action_gets_no_credentials(action):
    site = _Site(action)
    with pytest.raises(SessionAuthError, match="auth_origins"):
        _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert not [e for e in site.log if e[0] == "POST"]


@pytest.mark.parametrize("action,kw", [
    ("/login", {}),                                        # relative
    ("http://127.0.0.1:8080/login", {}),                   # same origin, absolute
    ("https://127.0.0.1:8080/login", {}),                  # same host, https upgrade
    ("http://127.0.0.1:9000/auth", {}),                    # in-scope host, other port
    ("http://auth.lab:7000/sso", {"auth_origins": ["http://auth.lab:7000"]}),
])
def test_an_allowed_destination_gets_the_post(action, kw):
    site = _Site(action)
    state = _manager(site, **kw).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert state.valid and any(e[0] == "POST" for e in site.log)


def test_an_out_of_scope_host_on_another_port_is_refused():
    """Same host name is not enough on its own: `other.lab:8080` is neither the login
    page's origin nor in scope."""
    site = _Site("http://other.lab:8080/login")
    with pytest.raises(SessionAuthError):
        _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert not [e for e in site.log if e[0] == "POST"]


@pytest.mark.parametrize("status", [307, 308])
def test_a_307_or_308_is_never_followed(status):
    site = _Site("/login", post_resp=FetchResponse(
        status, {"Location": "http://attacker.example/steal", "Set-Cookie": "s=1"}, ""))
    _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert not [u for _m, u in site.log if "attacker" in u]


@pytest.mark.parametrize("status", [307, 308])
def test_a_307_is_not_followed_even_to_the_same_origin(status):
    """Following a 307/308 re-sends the credentials body, so it is never followed."""
    site = _Site("/login", post_resp=FetchResponse(
        status, {"Location": "/next", "Set-Cookie": "s=1"}, ""))
    _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert ("GET", "http://127.0.0.1:8080/next") not in site.log


def test_a_302_is_followed_only_to_an_allowed_origin():
    site = _Site("/login", post_resp=FetchResponse(
        302, {"Location": "http://attacker.example/x", "Set-Cookie": "s=1"}, ""))
    _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert not [u for _m, u in site.log if "attacker" in u]
    home = "http://127.0.0.1:8080/home"
    site = _Site("/login", post_resp=FetchResponse(302, {"Location": "/home"}, ""),
                 follow={home: FetchResponse(200, {}, "<p>welcome</p>")})
    _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert ("GET", home) in site.log


class _BasicSite:
    """A Basic-protected site: no form; the base URL challenges unless authorised."""

    def __init__(self, password="s3cr3t-pw"):
        self.good = "Basic " + base64.b64encode(f"alice:{password}".encode()).decode()
        self.log = []

    def get(self, url, headers=None):
        self.log.append((url, (headers or {}).get("Authorization")))
        if (headers or {}).get("Authorization") == self.good:
            return FetchResponse(200, {}, "<p>private</p>")
        return FetchResponse(401, {"WWW-Authenticate": 'Basic realm="lab"'}, "")

    def post(self, url, data=None, headers=None, allow_redirects=True):
        raise AssertionError("Basic auth never POSTs")

    def cookies(self):
        return {}


def test_basic_auth_is_detected_at_discovery():
    site = _BasicSite()
    state = _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert state.kind == "basic" and state.valid
    assert {u for u, auth in site.log if auth} == {"http://127.0.0.1:8080/"}


def test_wrong_basic_credentials_are_rejected():
    with pytest.raises(SessionAuthError, match="Basic"):
        _manager(_BasicSite(password="other")).ensure("127.0.0.1", "user",
                                                      "http://127.0.0.1:8080/")


def test_a_post_answering_401_basic_switches_to_basic():
    class Hybrid(_BasicSite):
        def get(self, url, headers=None):
            if url.endswith("/login") and not headers:
                return FetchResponse(200, {}, FORM.format(action="/login"))
            if not headers:
                return FetchResponse(200, {}, "<p>public</p>")
            return super().get(url, headers)

        def post(self, url, data=None, headers=None, allow_redirects=True):
            return FetchResponse(401, {"WWW-Authenticate": 'Basic realm="lab"'}, "")
    state = _manager(Hybrid()).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert state.kind == "basic" and state.valid


def test_a_401_without_a_challenge_is_still_rejected():
    site = _Site("/login", post_resp=FetchResponse(401, {}, ""))
    with pytest.raises(SessionAuthError, match="rejected"):
        _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
