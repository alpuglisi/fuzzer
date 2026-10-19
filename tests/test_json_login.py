"""JSON login from the page's own script (FR-SESS-21): a login form with no ``action``
whose page script POSTs it as JSON is logged in by POSTing that JSON object; the login
holds only when the real password gets a credential a wrong one does not. A fake site
stands for the app (one server, a cookie jar per fetcher)."""

from __future__ import annotations

import json

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.session import detect
from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager
from tests.test_credentials import FakeBackend

BASE = "http://127.0.0.1:3079/"


def _page(script_url="/login?format=json", call="xhr", action="", json_body=True):
    send = "XHR.send(JSON.stringify(data));" if json_body else "XHR.send(data);"
    calls = {
        "xhr": f"XHR.open('POST', '{script_url}'); {send}",
        "fetch": f"fetch('{script_url}', {{method: 'POST', body: JSON.stringify(data)}});",
        "axios": f"axios.post('{script_url}', data, {{headers: {{'Content-Type': "
                 f"'application/json'}}}});",
    }
    return (f'<html><body><form id="login"{action}><input name="username">'
            '<input name="password" type="password"><button>Login</button></form>'
            '<form id="register"><input name="username"><input name="password" '
            'type="password"></form>'
            f"<script>{calls[call]}</script><script>XHR.open('POST', '/register'); "
            "XHR.send(JSON.stringify(other));</script></body></html>")


@pytest.mark.parametrize("call", ["xhr", "fetch", "axios"])
def test_the_scripts_one_json_login_url_is_found(call):
    form = detect.find_login_form(_page(call=call), BASE)
    assert form.json_url == "http://127.0.0.1:3079/login?format=json"
    assert dict(form.fill("u", "p")) == {"username": "u", "password": "p"}


def test_a_protocol_relative_url_resolves_against_the_page():
    form = detect.find_login_form(_page("//localhost:10005/login"), BASE)
    assert form.json_url == "http://localhost:10005/login"


@pytest.mark.parametrize("page", [
    _page(action=' action="/session"'),                    # a native form: submitted as is
    _page(json_body=False),                                # no JSON body built
    _page("/api/${path}/login"),                           # a URL built at run time
    _page("/users"),                                       # not a login URL
    _page().replace("/register", "/signin"),               # two login URLs: not guessed
    _page(json_body=False).replace("<script>XHR.open('POST', '/register')",
                                   "<script>XHR.open('POST', '/elsewhere')"),
])
def test_no_json_login_is_guessed(page):
    assert detect.find_login_form(page, BASE).json_url is None


def test_a_linked_script_is_not_read():
    soup = BeautifulSoup('<script src="/app.js">XHR.open("POST", "/login"); '
                         'JSON.stringify(x)</script>', "html.parser")
    assert detect.json_login_target(soup, BASE) is None


# --- the login itself -------------------------------------------------------------------
class _Site:
    """One app. ``POST /login`` takes JSON {username, password}; ``mode``: ``cookie``
    (a session cookie for the right password, 400 otherwise), ``token`` (a JWT in the
    answer, 401 otherwise), ``ambient`` (200 and a fresh ``sid`` cookie whatever the
    password: a wrong one cannot be told apart), ``reject`` (400 always)."""

    def __init__(self, mode="cookie", page=None):
        self.mode, self.page = mode, page or _page()
        self.posts = []

    def fetcher(self):
        site, jar = self, {}

        class F:
            def get(self, url, headers=None, allow_redirects=True):
                if url.rstrip("/").endswith("/login"):
                    return FetchResponse(404, {}, "")
                return FetchResponse(200, {}, site.page, url)

            def post(self, url, data=None, headers=None, allow_redirects=True):
                site.posts.append((url, dict(headers or {}), data))
                body = json.loads(data)
                right = body == {"username": "alice", "password": "pw"}
                if site.mode == "ambient":
                    jar["sid"] = f"s{len(site.posts)}"
                    return FetchResponse(200, {}, '{"result": "ok"}', url)
                if site.mode == "token":
                    if right:
                        return FetchResponse(200, {}, json.dumps({"token": "aaa.bbb.ccc"}),
                                             url)
                    return FetchResponse(401, {}, '{"error": "bad"}', url)
                if right and site.mode == "cookie":
                    jar["session"] = "authed"
                    return FetchResponse(200, {}, '{"result": "success"}', url)
                return FetchResponse(400, {}, '{"result": "error"}', url)

            def cookies(self):
                return dict(jar)
        return F()


def _manager(site, auth_origins=None):
    store = CredentialStore(backend=FakeBackend())
    store.set("127.0.0.1", "user", "alice", "pw")
    return SessionManager(store, scope_hosts=["127.0.0.1"], fetch_factory=site.fetcher,
                          auth_origins=auth_origins)


def test_a_json_login_posts_the_forms_object_after_a_wrong_password_control():
    site = _Site("cookie")
    state = _manager(site).ensure("127.0.0.1", "user", BASE)
    assert state.valid and state.kind == "cookie" and state.cookies == {"session": "authed"}
    (wrong_url, wrong_h, wrong_body), (url, headers, body) = site.posts
    assert url == wrong_url == "http://127.0.0.1:3079/login?format=json"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"username": "alice", "password": "pw"}
    assert json.loads(wrong_body)["password"] != "pw"            # the control went first
    assert state.login_url == url


def test_a_token_in_the_answer_is_a_bearer_session():
    state = _manager(_Site("token")).ensure("127.0.0.1", "user", BASE)
    assert state.kind == "bearer" and state.headers == {"Authorization": "Bearer aaa.bbb.ccc"}


@pytest.mark.parametrize("mode, why", [
    ("ambient", "no credential that a wrong password does not also get"),
    ("reject", "was rejected"),
])
def test_a_login_that_is_not_proven_fails_loudly(mode, why):
    with pytest.raises(SessionAuthError, match=why):
        _manager(_Site(mode)).ensure("127.0.0.1", "user", BASE)


def test_a_json_login_on_another_origin_needs_it_authorised():
    site = _Site("cookie", page=_page("//localhost:10005/login"))
    with pytest.raises(SessionAuthError, match="--auth-origin"):
        _manager(site).ensure("127.0.0.1", "user", BASE)
    assert site.posts == []                                      # nothing was sent
    state = _manager(site, ["http://localhost:10005"]).ensure("127.0.0.1", "user", BASE)
    assert state.valid and "http://127.0.0.1:10005" in state.origins
