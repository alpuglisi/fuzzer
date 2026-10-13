"""BUG-0113: an app under a sub-path (bWAPP at /bWAPP/) works end to end.

Every lab we built serves at the origin root, so "base URL" and "origin" were
interchangeable in every test. The crawler logged in at the bare origin, the session
manager re-logged in at the bare origin, and crawl points doubled the app's path.
"""

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import HttpClient, Request
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import injection_points_from_store
from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager
from fuzzlab.tools import browserauth
from tests.test_credentials import FakeBackend

LOGIN = """<form action="/app/login.php" method="POST">
  <input name="login"><input type="password" name="password">
  <button type="submit" name="form" value="submit">Login</button></form>"""


class SubpathApp:
    """The app lives under /app/; the origin root is someone else's page (404)."""

    def __init__(self):
        self.gets = []
        self.logged_in = False

    def get(self, url, headers=None, allow_redirects=True):
        self.gets.append(url)
        path = url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else ""
        path = "/" + path.split("?", 1)[0]
        if path == "/app/login.php":
            return FetchResponse(200, {}, LOGIN, url)
        if path.startswith("/app/"):
            if self.logged_in:
                return FetchResponse(200, {}, "<html>welcome bee</html>", url)
            return FetchResponse(302, {"Location": "/app/login.php"}, "", url)
        return FetchResponse(404, {}, "not here", url)

    def post(self, url, data=None, headers=None):
        d = dict(data or [])
        if url.endswith("/app/login.php") and d.get("login") == "bee" and \
                d.get("password") == "bug" and d.get("form") == "submit":
            self.logged_in = True
            return FetchResponse(302, {"Location": "/app/portal.php"}, "", url)
        return FetchResponse(200, {}, LOGIN, url)

    def cookies(self):
        return {"PHPSESSID": "authed"} if self.logged_in else {}


def _mgr(app):
    store = CredentialStore(backend=FakeBackend())
    store.set("h", "user", "bee", "bug")
    return SessionManager(store, scope_hosts=["h"], fetch_factory=lambda: app)


def test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    start = "http://h:8090/app/portal.php"
    spider = LocalSpider(start, db_name=str(tmp_path / "s.db"), engine="requests")
    assert spider._auth_base_url == start
    app = SubpathApp()
    mgr = _mgr(app)
    cookies, _ = browserauth.playwright_auth(mgr, "user", start)
    assert cookies and all(c["url"] == "http://h:8090/" for c in cookies)
    assert mgr._bases[("h", "user")] == start          # operator input, kept for re-login


def test_prepare_discovers_the_login_in_the_requests_directory_without_its_query():
    app = SubpathApp()
    mgr = _mgr(app)
    req = Request("GET", "http://h:8090/app/sqli_1.php?title=%27+OR+1%3D1--",
                  identity="user")
    mgr.prepare(req, "user")
    assert req.headers.get("Cookie") == "PHPSESSID=authed"
    assert not any("title=" in u for u in app.gets)          # the probe is never replayed
    assert "http://h:8090/app/" in app.gets                   # its directory is the base


def test_a_relogin_reuses_the_operators_base():
    app = SubpathApp()
    mgr = _mgr(app)
    mgr.ensure("h", "user", "http://h:8090/app/portal.php", operator=True)
    mgr._state[("h", "user")].valid = False                   # expired
    app.logged_in = False
    app.gets.clear()
    mgr.prepare(Request("GET", "http://h:8090/app/deep/x.php?q=1", identity="user"), "user")
    assert app.gets[0] == "http://h:8090/app/portal.php"


def test_an_operator_call_on_a_cached_session_still_sets_the_relogin_base():
    app = SubpathApp()
    mgr = _mgr(app)
    mgr.prepare(Request("GET", "http://h:8090/app/a.php", identity="user"), "user")
    mgr.ensure("h", "user", "http://h:8090/app/portal.php", operator=True)   # cached
    mgr._state[("h", "user")].valid = False
    app.logged_in = False
    app.gets.clear()
    mgr.prepare(Request("GET", "http://h:8090/app/deep/x.php", identity="user"), "user")
    assert app.gets[0] == "http://h:8090/app/portal.php"


def test_an_expired_session_during_a_destructive_probe_never_fetches_it():
    app = SubpathApp()
    mgr = _mgr(app)
    mgr.prepare(Request("GET", "http://h:8090/app/reset.php?x=1", identity="user"), "user")
    assert not any("reset.php" in u or "x=1" in u for u in app.gets)


def test_a_destructive_derived_base_is_refused_and_never_fetched():
    app = SubpathApp()
    mgr = _mgr(app)
    with pytest.raises(SessionAuthError):
        mgr.prepare(Request("GET", "http://h:8090/app/delete/x.php", identity="user"),
                    "user")
    assert "http://h:8090/app/delete/" not in app.gets


def test_only_an_operator_base_is_exempt_and_the_default_fails_closed():
    mgr = _mgr(SubpathApp())
    assert not mgr._navigation_ok("http://h:8090/app/setup.php",
                                  "http://h:8090/app/setup.php", False)
    mgr._operator_bases.add("http://h:8090/app/setup.php")
    assert mgr._navigation_ok("http://h:8090/app/setup.php",
                              "http://h:8090/app/setup.php", False)


def test_a_basic_session_never_reads_an_app_page_redirect_as_logout():
    class BasicApp:
        def get(self, url, headers=None, allow_redirects=True):
            if (headers or {}).get("Authorization"):
                return FetchResponse(200, {}, "<html>in</html>", url)
            return FetchResponse(401, {"WWW-Authenticate": 'Basic realm="x"'}, "", url)

        def post(self, url, data=None, headers=None):
            return FetchResponse(404, {}, "", url)

        def cookies(self):
            return {}
    mgr = _mgr(BasicApp())
    state = mgr.ensure("h", "user", "http://h:8090/app/", operator=True)
    assert state.kind == "basic" and state.login_url is None
    from fuzzlab.core.http import Response
    mgr.observe(Request("GET", "http://h:8090/app/a.php", identity="user"),
                Response(302, {"Location": "http://h:8090/app/portal.php"}, b"", 1.0), "user")
    assert mgr._state[("h", "user")].valid
    mgr.observe(Request("GET", "http://h:8090/app/a.php", identity="user"),
                Response(200, {}, b"<form><input type=password name=p></form>", 1.0), "user")
    assert mgr._state[("h", "user")].valid          # a Basic session: 401/403 only


def test_crawl_points_join_absolute_paths_to_the_origin(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        eid = store.conn.execute(
            "INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
            (run_id, "/app/a.php", "GET", "link")).lastrowid
        store.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
            "VALUES (?,?,?,?,?)", (run_id, eid, "id", "query", "1"))
        store.conn.commit()
        for base in ("http://h:8090/app/", "http://h:8090", "http://h:8090/app"):
            urls = [p.url for p in injection_points_from_store(store, run_id, base)]
            assert urls == ["http://h:8090/app/a.php"], base


def test_an_authenticated_subpath_request_through_the_seam():
    app = SubpathApp()
    mgr = _mgr(app)
    sent = []

    def transport(method, url, headers, body, timeout):
        sent.append(dict(headers))
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"
    client = HttpClient(RequestBudget(10), ["h"], session=mgr, transport=transport)
    resp = client.send(Request("GET", "http://h:8090/app/sqli_1.php?title=x",
                               identity="user"))
    assert resp.status == 200 and sent[0].get("Cookie") == "PHPSESSID=authed"


def test_the_auditor_and_the_fuzzer_log_in_from_the_operator_url_first(monkeypatch):
    calls = []

    class Mgr:
        def ensure(self, host, identity, base_url, *, operator=False):
            calls.append((host, identity, base_url, operator))

    import fuzzlab.tools.authhttp as authhttp
    monkeypatch.setattr(authhttp, "make_auth", lambda *a, **k: (Mgr(), object()))
    from fuzzlab.tools import blind_sqli_fuzzer
    monkeypatch.setattr(blind_sqli_fuzzer, "establish_baseline",
                        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    blind_sqli_fuzzer.main(["--url", "http://h:8090/app/sqli_1.php", "--param", "title",
                            "--identity", "user", "--authorized",
                            "--output", "/dev/null"])
    assert calls == [("h", "user", "http://h:8090/app/sqli_1.php", True)]


def test_the_auditor_logs_in_from_its_base_url_before_any_fetch(monkeypatch, tmp_path):
    import runpy
    import sys
    calls = []

    class Mgr:
        def ensure(self, host, identity, base_url, *, operator=False):
            calls.append((host, identity, base_url, operator))

    import fuzzlab.tools.authhttp as authhttp
    monkeypatch.setattr(authhttp, "make_auth", lambda *a, **k: (Mgr(), object()))
    monkeypatch.setattr(sys, "argv", [
        "fetcher", "--identity", "user", "--base-url", "http://h:8090/app/",
        "--spider-db", str(tmp_path / "none.db"), "--indicator-db", str(tmp_path / "i.db"),
        "--out", str(tmp_path / "o.db")])
    runpy.run_module("fuzzlab.tools.fetcher", run_name="__main__")
    assert calls == [("h", "user", "http://h:8090/app/", True)]


def test_a_browser_sends_the_injected_cookie_to_sibling_pages(tmp_path):
    """A1: the session cookie injected for a sub-path start page reaches the app's other
    pages in a real browser (it is scoped to the origin root)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests._browser import launch_browser_or_skip, skip_or_fail
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            seen[self.path] = self.headers.get("Cookie")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

        def log_message(self, *a):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    class Mgr:
        def ensure(self, host, identity, base_url, *, operator=False):
            from fuzzlab.session.state import SessionState
            return SessionState(host, identity, kind="cookie",
                                cookies={"PHPSESSID": "authed"}, valid=True)
    try:
        cookies, headers = browserauth.playwright_auth(Mgr(), "user",
                                                       base + "/app/sub/portal.php")
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                page = browser.new_page()
                browserauth.apply_to_context(page.context, cookies, headers)
                page.goto(base + "/app/other.php")
            finally:
                browser.close()
    finally:
        server.shutdown()
    assert seen.get("/app/other.php") == "PHPSESSID=authed"


def test_a_sender_without_a_base_treats_no_probe_url_as_operator_input():
    from fuzzlab.tools.probesender import SeamProbeSender
    app = SubpathApp()
    mgr = _mgr(app)

    def transport(method, url, headers, body, timeout):
        return 200, {}, b"ok"
    client = HttpClient(RequestBudget(10), ["h"], session=mgr, transport=transport)
    SeamProbeSender(client, "user", manager=mgr).send("http://h:8090/app/a.php", "id", "1")
    assert mgr._operator_bases == set() and ("h", "user") not in mgr._bases


def test_a_page_with_its_own_password_field_is_neither_a_failed_login_nor_a_logout():
    """Live (bWAPP): starting the crawl on ldapi.php / sqli_3.php — pages with a
    password form of their own — failed verification, and such pages read as logouts."""
    ldap = ("<form action='/app/ldapi.php' method=post><input name=login>"
            "<input type=password name=password></form>")

    class LdapStart(SubpathApp):
        def get(self, url, headers=None, allow_redirects=True):
            if url.endswith("/app/ldapi.php") and self.logged_in:
                self.gets.append(url)
                return FetchResponse(200, {}, ldap, url)
            return super().get(url, headers, allow_redirects)
    app = LdapStart()
    mgr = _mgr(app)
    state = mgr.ensure("h", "user", "http://h:8090/app/ldapi.php", operator=True)
    assert state.valid
    from fuzzlab.core.http import Response
    mgr.observe(Request("GET", "http://h:8090/app/ldapi.php", identity="user"),
                Response(200, {}, ldap.encode(), 1.0), "user")
    assert mgr._state[("h", "user")].valid                      # not a logout
    mgr.observe(Request("GET", "http://h:8090/app/x.php", identity="user"),
                Response(200, {}, LOGIN.encode(), 1.0), "user")
    assert not mgr._state[("h", "user")].valid                  # the login form is


def test_a_login_that_lands_on_a_page_with_its_own_password_form_succeeds():
    change = ("<form action='/app/password_change.php' method=post>"
              "<input type=password name=password_curr></form>")

    class LandsOnChangePassword(SubpathApp):
        def get(self, url, headers=None, allow_redirects=True):
            if url.endswith("/app/portal.php") and self.logged_in:
                self.gets.append(url)
                return FetchResponse(200, {}, change, url)
            return super().get(url, headers, allow_redirects)
    state = _mgr(LandsOnChangePassword()).ensure("h", "user", "http://h:8090/app/",
                                                 operator=True)
    assert state.valid and state.cookies.get("PHPSESSID") == "authed"


def _logged_in_mgr():
    mgr = _mgr(SubpathApp())
    mgr.ensure("h", "user", "http://h:8090/app/", operator=True)
    return mgr


def _observe(mgr, url, html):
    from fuzzlab.core.http import Response
    mgr.observe(Request("GET", url, identity="user"), Response(200, {}, html.encode(), 1.0),
                "user")
    return mgr._state[("h", "user")].valid


def test_the_login_form_re_rendered_in_place_is_a_logout():
    """Reviewers A/B: an expired session answered by the login form inline at the
    protected URL (posting to itself) must still be seen as a logout."""
    # the app's login form ({login, password, form}), posting to the protected page
    inline = ("<form action='' method=post><input name=login>"
              "<input type=password name=password>"
              "<button type=submit name=form value=submit>Login</button></form>")
    assert not _observe(_logged_in_mgr(), "http://h:8090/app/secret.php", inline)


def test_in_app_password_forms_with_other_fields_are_not_logouts():
    shapes = [
        ("<form action='' method=post><input name=login><input type=password name=password>"
         "<button type=submit name=submit value=go>Go</button></form>"),          # other login
        ("<form action='' method=post><input type=password name=password_curr>"
         "<input type=password name=password_new>"
         "<input type=password name=password_conf></form>"),                      # change pw
        ("<form action='' method=post><input name=server><input name=login>"
         "<input type=password name=password></form>"),                           # ldapi
    ]
    for html in shapes:
        assert _observe(_logged_in_mgr(), "http://h:8090/app/page.php", html), html


def test_basic_verification_ignores_a_password_field_on_the_base_page():
    class BasicSettings:
        def get(self, url, headers=None, allow_redirects=True):
            if (headers or {}).get("Authorization"):
                return FetchResponse(200, {}, "<form><input type=password name=p></form>", url)
            return FetchResponse(401, {"WWW-Authenticate": 'Basic realm="x"'}, "", url)

        def post(self, url, data=None, headers=None):
            return FetchResponse(404, {}, "", url)

        def cookies(self):
            return {}
    state = _mgr(BasicSettings()).ensure("h", "user", "http://h:8090/app/settings.php",
                                         operator=True)
    assert state.kind == "basic" and state.valid
