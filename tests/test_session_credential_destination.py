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

    def get(self, url, headers=None, allow_redirects=True):
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
    # another port only as an authorised auth origin (FR-SESS-20, R3, BUG-0134)
    ("http://127.0.0.1:9000/auth", {"auth_origins": ["http://127.0.0.1:9000"]}),
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

    def get(self, url, headers=None, allow_redirects=True):
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
        def get(self, url, headers=None, allow_redirects=True):
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


# --- BUG-0092 / PA-0093: the transport deny runs before every allow ------------------

class _HttpsSite(_Site):
    """``_Site`` served at https://lab.example, with an optional discovery redirect."""

    def __init__(self, action, *, login_redirect=None, **kw):
        super().__init__(action, **kw)
        self.login_redirect = login_redirect

    def get(self, url, headers=None, allow_redirects=True):
        resp = super().get(url, headers)
        if url.endswith("/login") and self.login_redirect:
            # the fetcher followed an https -> http redirect to the real login page
            return FetchResponse(resp.status, resp.headers, resp.text,
                                 url=self.login_redirect,
                                 history_schemes=("https", "http"))
        return resp


_HTTPS = "https://lab.example/"


@pytest.mark.parametrize("action,kw", [
    ("http://lab.example/login", {}),                              # in scope, same host
    ("http://lab.example:9999/login", {}),                         # in scope, other port
    ("http://auth.lab:7000/sso", {"auth_origins": ["http://auth.lab:7000"]}),
    ("http://lab.example/login", {"auth_origins": ["http://lab.example"]}),
    ("ftp://lab.example/login", {}),                               # not http(s) at all
])
def test_an_https_login_never_sends_credentials_over_http(action, kw):
    """The finding: every allow (scope, auth_origins) used to override the downgrade."""
    site = _HttpsSite(action)
    with pytest.raises(SessionAuthError, match="downgrade"):
        _manager(site, scope=["lab.example"], **kw).ensure("lab.example", "user", _HTTPS)
    assert not [e for e in site.log if e[0] == "POST"]


def test_every_allow_path_is_overridden_by_the_deny():
    """A destination each allow rule admits (same origin, auth_origins; the in-scope
    host rule is gone since FR-SESS-20) is refused once the transport floor is https
    (PA-0093: deny before allow)."""
    m = _manager(_Site("/login"), scope=["lab.example"],
                 auth_origins=["http://lab.example", "http://auth.lab",
                               "http://lab.example:81"])
    for target in ("http://lab.example/login",            # same origin as the page
                   "http://lab.example:81/x",             # another port, authorised
                   "http://auth.lab/sso"):                # auth_origins
        assert m._credential_destination_ok(target, "http://lab.example/login")
        assert not m._credential_destination_ok(target, "http://lab.example/login",
                                                 floor_https=True)
        assert not m._credential_destination_ok(target, "https://lab.example/login")


class _Hops(_Site):
    """``_Site`` whose ``/login`` answers a chain of 302s (the fetcher never follows:
    the manager walks the hops itself, BUG-0097)."""

    def __init__(self, action, hops, **kw):
        super().__init__(action, **kw)
        self.hops = hops                          # {url: next_url}

    def get(self, url, headers=None, allow_redirects=True):
        if url in self.hops:
            self.log.append(("GET", url))
            return FetchResponse(302, {"Location": self.hops[url]}, "")
        if url.startswith("http://lab.example/real-login"):
            self.log.append(("GET", url))
            return FetchResponse(200, {}, FORM.format(action=self.action))
        return super().get(url, headers)


def test_a_discovery_redirect_from_https_to_http_is_refused():
    """base_url https -> 302 -> an http login page: refused before it is even fetched."""
    site = _Hops("/login", {"https://lab.example/login": "http://lab.example/real-login"})
    with pytest.raises(SessionAuthError, match="downgrade"):
        _manager(site, scope=["lab.example"]).ensure("lab.example", "user", _HTTPS)
    assert ("GET", "http://lab.example/real-login") not in site.log
    assert not [e for e in site.log if e[0] == "POST"]


def test_a_post_redirect_from_https_to_http_is_not_followed():
    site = _HttpsSite("/login", post_resp=FetchResponse(
        302, {"Location": "http://lab.example/home", "Set-Cookie": "s=1"}, ""))
    _manager(site, scope=["lab.example"]).ensure("lab.example", "user", _HTTPS)
    assert ("GET", "http://lab.example/home") not in site.log


@pytest.mark.parametrize("action,base,kw", [
    ("https://lab.example/login", _HTTPS, {}),                         # https -> https
    ("https://lab.example:8443/login", _HTTPS,                         # authorised
     {"auth_origins": ["https://lab.example:8443"]}),
    ("https://lab.example/login", "http://lab.example/", {}),          # upgrade
    ("http://lab.example:9000/login", "http://lab.example/",           # authorised
     {"auth_origins": ["http://lab.example:9000"]}),
])
def test_same_or_upgraded_transport_is_still_allowed(action, base, kw):
    site = _HttpsSite(action)
    state = _manager(site, scope=["lab.example"], **kw).ensure("lab.example", "user", base)
    assert state.valid and any(e[0] == "POST" for e in site.log)


def test_the_default_fetcher_reports_the_final_url_and_every_hop():
    from types import SimpleNamespace

    from fuzzlab.session.manager import _hops
    r = SimpleNamespace(url="http://lab.example/login",
                        history=[SimpleNamespace(url="https://lab.example/")])
    assert _hops(r) == ("https", "http")


def test_an_https_hop_in_discovery_sets_the_floor_even_for_an_http_base():
    """http base -> https hop -> http login page: the chain went down from https, so
    the http hop is refused before any request to it or any POST."""
    site = _Hops("/login", {"http://lab.example/login": "https://lab.example/sso",
                            "https://lab.example/sso": "http://lab.example/real-login"})
    with pytest.raises(SessionAuthError, match="downgrade"):
        _manager(site, scope=["lab.example"]).ensure("lab.example", "user",
                                                     "http://lab.example/")
    assert ("GET", "http://lab.example/real-login") not in site.log
    assert not [e for e in site.log if e[0] == "POST"]


@pytest.mark.parametrize("action", ["http://127.0.0.1:9000/auth",      # another port
                                    "https://127.0.0.1:8443/auth"])   # upgrade elsewhere
def test_another_port_of_an_in_scope_host_gets_no_credentials(action):
    """Superseded rule (FR-SESS-20, R3, BUG-0134): an in-scope host on another port, or
    an https upgrade to another port, was a credential destination. It is another app:
    refused, naming --auth-origin."""
    site = _Site(action)
    with pytest.raises(SessionAuthError, match="--auth-origin"):
        _manager(site).ensure("127.0.0.1", "user", "http://127.0.0.1:8080/")
    assert not [e for e in site.log if e[0] == "POST"]
