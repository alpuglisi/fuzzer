"""BUG-0111 / BUG-0112: NFR-CRAWL-safe and NFR-FUZZ-safe, enforced.

Found preparing an authenticated run against a loopback bWAPP, whose portal links
``reset.php`` (``DROP DATABASE`` on GET) and ``logout.php``: the crawler had no
deny-list, and nothing ever excluded the session's auth endpoints from fuzzing.
"""

import ast
import glob
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.core.store import Store
from fuzzlab.core.urls import (
    DestructiveUrlRefused,
    check_send_url,
    destructive_reason,
    url_key,
)
from fuzzlab.harness.auto import injection_points_from_store, run_auto
from fuzzlab.oracle.probe import Probe
from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager
from fuzzlab.tools.navguard import make_route_handler
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
from tests.test_session_manager import CookieLoginFetcher, _factory, _store

DESTRUCTIVE = [
    "http://127.0.0.1:8090/bWAPP/reset.php", "/logout.php", "/ba_logout_1.php",
    "/user/deleteAccount", "/sign-out", "/x.php?action=delete", "/install.php",
    "/%72eset.php", "/%2572eset.php", "/set-up-database.php", "/x?act=del", "/logOut",
    "/api/cache/clear", "/admin/shutdown", "/account?op=revoke", "/bWAPP/update.php",
    "/item.php?id=3&action=update&qty=0", "/x?op=update", "/update_db.php", "/db_update.php",
    "/updatedb.php", "/wp-admin/upgrade.php?step=1", "/schema/update",
]
HARMLESS = [
    "/sqli_1.php", "/password_change.php", "/dropdown.php", "/xss_login.php",
    "/portal.php", "/model?id=1", "/delivery.php", "/clearance.php", "/exitpoll.php",
    "/installation.php", "/banner.php", "/export?format=csv", "/login.php",
    "/admin/customers/update", "/webhooks/customers/update", "/update_profile.php",
]


@pytest.mark.parametrize("url", DESTRUCTIVE)
def test_destructive_urls_are_recognised(url):
    assert destructive_reason(url) is not None


@pytest.mark.parametrize("url", HARMLESS)
def test_harmless_urls_are_not(url):
    assert destructive_reason(url) is None


def test_the_send_gate_refuses_a_write_or_an_unknown_method_never_a_visit():
    """D72: a GET or HEAD send is never refused for its URL's words; a write (POST,
    PUT) and a send that does not say its method still are; DELETE always is."""
    check_send_url("http://127.0.0.1:8080/logout.php", method="GET")
    check_send_url("http://127.0.0.1:8080/reset.php", method="HEAD")
    for method in ("POST", "PUT", None):
        with pytest.raises(DestructiveUrlRefused):
            check_send_url("http://127.0.0.1:8080/logout.php", method=method)
    with pytest.raises(DestructiveUrlRefused):
        check_send_url("http://127.0.0.1:8080/items.php", method="DELETE")


def test_the_send_gate_refuses_unless_explicit_and_keys_canonically():
    with pytest.raises(DestructiveUrlRefused):
        check_send_url("http://127.0.0.1:8080/logout.php")
    check_send_url("http://127.0.0.1:8080/logout.php",
                   frozenset({url_key("http://localhost:8080/logout.php")}))
    check_send_url("http://127.0.0.1:8080/product.php")


# --- crawler ---------------------------------------------------------------------
class _Resp:
    def __init__(self, status, body="", location=None):
        self.status_code = status
        self.text = body
        self.headers = {"Content-Type": "text/html"}
        if location:
            self.headers["Location"] = location


class _SiteSession:
    """A fake requests session: records every URL it is asked for."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def get(self, url, timeout=None, allow_redirects=True):
        assert allow_redirects is False                  # redirects are followed by hand
        self.requested.append(url)
        return self.pages.get(url, _Resp(404))


def test_static_crawl_fetches_a_destructive_link_or_redirect_last(tmp_path):
    """D72 (owner, 2026-10-16): a GET visit is never refused for its words; a
    destructive-looking link is crawled after every other page (`_deferrable`), so a
    logout or bWAPP's reset.php cannot end the crawl early. A redirect hop to one is
    followed (a GET)."""
    from fuzzlab.tools.spider import LocalSpider
    base = "http://127.0.0.1:8090/bWAPP/"
    session = _SiteSession({
        base + "portal.php": _Resp(200, '<a href="a.php">a</a><a href="reset.php">r</a>'
                                        '<a href="b.php">b</a><a href="x.php?act=del">d</a>'),
        base + "a.php": _Resp(200, "<p>a</p>"),
        base + "b.php": _Resp(302, location="logout.php"),
    })
    spider = LocalSpider(base + "portal.php", db_name=str(tmp_path / "s.db"),
                         engine="requests")
    spider.session = session
    spider.crawl()
    got = session.requested
    for url in (base + "reset.php", base + "x.php?act=del", base + "logout.php"):
        assert url in got, url
    # the deferred links come after every other link (the redirect hop to logout.php is
    # followed when b.php is fetched)
    assert max(got.index(base + "a.php"), got.index(base + "b.php")) < \
        min(got.index(base + "reset.php"), got.index(base + "x.php?act=del"))
    assert spider.skipped_destructive == {}
    assert spider.spa_counts["pages_deferred"] == 2


def test_the_start_url_is_the_operators_own_and_is_fetched(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    start = "http://127.0.0.1:8090/setup.php"
    session = _SiteSession({start: _Resp(200, "<p>hi</p>")})
    spider = LocalSpider(start, db_name=str(tmp_path / "s.db"), engine="requests")
    spider.session = session
    spider.crawl()
    assert session.requested == [start]
    # ...and is never deferred, though its own words look destructive (D72: ordering)
    assert spider._deferrable(start) is False
    assert spider._deferrable("http://127.0.0.1:8090/reset.php") is True


class _Route:
    """A fake Playwright route whose fetch answers 200: an allowed request is fetched
    by the guard and fulfilled (BUG-0123), shown here as "continue"."""
    def __init__(self, url, method="GET"):
        class Req:
            headers: dict = {}
            post_data_buffer = None

            def is_navigation_request(self):
                return False
        self.request = Req()
        self.request.url = url
        self.request.method = method
        self.request.post_data_buffer = b"x=1" if method != "GET" else None
        self.outcome = None

    def fetch(self, max_redirects=None):
        assert max_redirects == 0
        return type("Resp", (), {"status": 200, "headers": {}})()

    def abort(self):
        self.outcome = "abort"

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, **kw):
        self.outcome = "continue"


def test_the_browser_route_aborts_destructive_writes_only():
    """D72: a GET to a destructive URL goes through; a write to one is aborted (unless
    it is the operator's own URL); the login flow's ``strict`` guard aborts both."""
    aborted = []
    handler = make_route_handler(frozenset({url_key("http://h/setup.php")}),
                                 on_abort=lambda u, r: aborted.append(u),
                                 in_scope=lambda u: True)
    for url, method, outcome in [("http://h/logout.php", "GET", "continue"),
                                 ("http://h/logout.php", "POST", "abort"),
                                 ("http://h/a.php", "POST", "continue"),
                                 ("http://h/setup.php", "POST", "continue")]:
        route = _Route(url, method)
        handler(route)
        assert route.outcome == outcome, (url, method)
    assert aborted == ["http://h/logout.php"]
    strict = make_route_handler(in_scope=lambda u: True, strict=True)
    route = _Route("http://h/logout.php")
    strict(route)
    assert route.outcome == "abort"


class _LoggingHandler(BaseHTTPRequestHandler):
    seen: list = []
    PAGE = (b"<html><body><a href='/delete.php'>d</a><a href='/ok.php'>ok</a>"
            b"<img src='/logout.php'><script>fetch('/reset.php')</script></body></html>")

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append(self.path)
        body = self.PAGE if self.path == "/" else b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _loopback_site():
    _LoggingHandler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoggingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _chromium_or_skip(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])


def test_rendered_crawl_visits_destructive_links_and_subresources(tmp_path, monkeypatch):
    """D72: a destructive-looking link, ``<img>`` and script GET fetch are sent like any
    other GET (writes are covered by the route test above)."""
    _chromium_or_skip(monkeypatch)
    from fuzzlab.tools import spider as spider_mod
    server = _loopback_site()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        sp = spider_mod.LocalSpider(base, max_depth=1, db_name=str(tmp_path / "s.db"),
                                    engine="playwright", timeout_ms=5000)
        if sp.engine != "playwright":
            from tests._browser import skip_or_fail
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            from tests._browser import skip_or_fail
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        server.shutdown()
    seen = set(_LoggingHandler.seen)
    assert "/" in seen and "/ok.php" in seen                  # the crawl did run
    assert {"/delete.php", "/logout.php", "/reset.php"} <= seen


# --- auditor ---------------------------------------------------------------------
def test_the_auditor_refetches_a_destructive_url_last(tmp_path):
    from fuzzlab.tools.fetcher import load_urls
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, depth INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,?,?)",
                    [("http://h/a.php", 0, "link"), ("http://h/reset.php", 1, "link"),
                     ("http://h/logout.php", 1, "link")])
    con.commit()
    con.close()
    assert load_urls(str(db)) == [("http://h/a.php", "link"), ("http://h/reset.php", "link"),
                                  ("http://h/logout.php", "link")]          # D72: last


def test_the_auditors_static_fetch_follows_a_redirect_to_one():
    """D72: a redirect hop is a GET visit; the same-origin rule still holds."""
    from fuzzlab.tools.fetcher import ContentFetcher
    fetcher = ContentFetcher(engine="requests")
    fetcher.session = _SiteSession({"http://h/a.php": _Resp(302, location="/reset.php"),
                                    "http://h/b.php": _Resp(302,
                                                            location="http://x/reset.php")})
    fetcher.fetch("http://h/a.php")
    assert fetcher.session.requested == ["http://h/a.php", "http://h/reset.php"]
    fetcher.session.requested.clear()
    fetcher.fetch("http://h/b.php")
    assert fetcher.session.requested == ["http://h/b.php"]       # another origin: never


# --- probe senders ---------------------------------------------------------------
class _CountingSession:
    def __init__(self):
        self.calls = 0

        class Jar(dict):
            def clear(self):
                self.cleared = True
                super().clear()
        self.cookies = Jar()

    def request(self, method, url, **kwargs):
        self.calls += 1

        class R:
            status_code = 200
            text = "ok"
            headers = {}
        return R()


def test_requests_probe_sender_refuses_a_destructive_write_and_sends_nothing():
    """D72: a GET probe to a destructive URL is sent; a POST to one is refused, unless
    the operator enumerated it."""
    session = _CountingSession()
    sender = RequestsProbeSender(session=session)
    sender.send("http://localhost/logout.php", "x", "1")                 # a GET
    assert session.calls == 1
    with pytest.raises(DestructiveUrlRefused):
        sender.send("http://localhost/logout.php", "x", "1", method="POST",
                    location="body")
    assert session.calls == 1
    sender.allow_explicit(["http://localhost/logout.php"])
    sender.send("http://localhost/logout.php", "x", "1", method="POST", location="body")
    assert session.calls == 2


def test_requests_probe_sender_keeps_no_cookie_between_probes():
    session = _CountingSession()
    session.cookies["PHPSESSID"] = "planted-by-a-probe-response"
    RequestsProbeSender(session=session).send("http://localhost/a.php", "x", "1")
    assert dict(session.cookies) == {}


def _seam(manager_fetcher=None):
    captured = []

    def transport(method, url, headers, body, timeout):
        captured.append((url, dict(headers)))
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(manager_fetcher or CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    return SeamProbeSender(client, "admin", manager=mgr, base_url="http://localhost"), \
        captured


def test_an_auth_endpoint_is_probed_without_the_session_and_the_session_survives():
    sender, captured = _seam()
    sender.send("http://localhost/login.php", "username", "admin' --",
                method="POST", location="body")
    sender.send("http://localhost/product.php", "id", "1")
    (login_url, login_headers), (_u, next_headers) = captured
    assert "Cookie" not in login_headers                     # anonymous
    assert next_headers.get("Cookie") == "PHPSESSID=sess1"   # still the identity
    assert sender.auth_endpoint_anonymous_sends == 1


def test_a_failed_login_surfaces_as_a_session_error_before_any_probe():
    class Rejecting(CookieLoginFetcher):
        def post(self, url, data=None, headers=None):
            return FetchResponse(200, {}, "<form><input type=password name=p></form>")
    sender, captured = _seam(Rejecting())
    with pytest.raises(SessionAuthError):
        sender.send("http://localhost/login.php", "username", "x")
    assert captured == []


def test_greybox_sender_gates_drops_the_cookie_on_auth_endpoints_and_clears_the_jar():
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    sent = []

    class S:
        def __init__(self):
            self.cookies = {}

        def request(self, method, url, **kw):
            sent.append((url, dict(kw["headers"]), dict(self.cookies)))
            self.cookies["planted"] = "1"                  # a probe response's Set-Cookie

            class R:
                status_code = 200
                text = "ok"
                headers = {}
            return R()

    sender = RequestsCorrelatingSender(cookie="PHPSESSID=s", session=S(),
                                       cookie_origins=frozenset({"http://h:80"}),
                                       is_auth_endpoint=lambda u: u.endswith("/login.php"))
    sender.send_correlated("http://h/login.php", "u", "x")
    sender.send_correlated("http://h/a.php", "id", "1")
    with pytest.raises(DestructiveUrlRefused):                     # a write (D72)
        sender.send_correlated("http://h/logout.php", "x", "1", method="POST",
                               location="body")
    (_u1, h1, jar1), (_u2, h2, jar2) = sent
    assert "Cookie" not in h1 and h2["Cookie"] == "PHPSESSID=s"
    assert jar2 == {}                                      # nothing carried over
    assert sender.auth_endpoint_anonymous_sends == 1


def test_blind_sqli_senders_gate_but_allow_the_operators_own_url():
    from fuzzlab.tools.blind_sqli_fuzzer import RequestsSender, _explicit_url

    class S:
        calls = 0

        def get(self, url, **kw):
            S.calls += 1

            class R:
                status_code = 200
                text = "ok"
            return R()
    sender = RequestsSender(S(), explicit=_explicit_url("http://h/delete.php"))
    sender.get("http://h/delete.php", "id", "1", 5)
    # D72: these senders only GET, and now say so: a destructive URL is a visit
    RequestsSender(S()).get("http://h/delete.php", "id", "1", 5)
    assert S.calls == 2


# --- point selection ---------------------------------------------------------------
def _seed(store, run_id, rows):
    for path, param in rows:
        eid = store.conn.execute(
            "INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
            (run_id, path, "GET", "link")).lastrowid
        store.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
            "VALUES (?,?,?,?,?)", (run_id, eid, param, "query", "1"))
    store.conn.commit()


class _Recorder:
    def __init__(self):
        self.urls = []

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        self.urls.append(url)
        return Probe(200, "ok")


def test_crawl_sourced_runs_fuzz_a_destructive_get_point_last(tmp_path):
    """D72: a GET crawl point on a destructive URL is fuzzed, after every other point
    (`auto._late`); nothing is skipped for its words."""
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed(store, run_id, [("/a.php", "id"), ("/logout.php", "x"), ("/reset.php", "y")])
        sender = _Recorder()
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=sender, mode="manual", selected_categories=["sql-injection"],
                          points_source="crawl")
    order = [u.split("?")[0] for u in sender.urls]
    assert {"http://localhost/a.php", "http://localhost/logout.php",
            "http://localhost/reset.php"} <= set(order)
    assert order.index("http://localhost/logout.php") > \
        max(i for i, u in enumerate(order) if u == "http://localhost/a.php")
    assert not result.metrics["skipped_points"]


def test_greybox_crawl_points_keep_a_destructive_get_point_last(tmp_path):
    from fuzzlab.greybox.run import points_from_store
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        _seed(store, run_id, [("/a.php", "id"), ("/delete.php", "x")])
        skipped = []
        points = points_from_store(store, run_id, "http://localhost", skipped=skipped)
    assert [p.url for p in points] == ["http://localhost/a.php", "http://localhost/delete.php"]
    assert skipped == []


def test_ground_truth_runs_mark_their_points_explicit(tmp_path):
    """run_auto hands the operator-enumerated URLs to the sender's allowance, so a
    ground-truth point is never refused as destructive (only crawl points are)."""
    from fuzzlab.labels import contract

    class Allowing(_Recorder):
        allowed = None

        def allow_explicit(self, urls):
            self.allowed = set(urls)

    sender = Allowing()
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        run_auto(base_url="http://localhost", store=store, run_id=run_id, sender=sender,
                 mode="automatic", ground_truth=contract.load("lab/ground-truth"),
                 points_source="ground-truth")
    assert "http://localhost/login.php" in sender.allowed
    explicit = RequestsProbeSender(session=_CountingSession())
    explicit.allow_explicit(["http://localhost/logout.php"])
    explicit.send("http://localhost/logout.php", "next", "x")     # not refused


# --- session discovery ---------------------------------------------------------------
def test_login_discovery_never_follows_a_redirect_to_a_destructive_url():
    class Bouncing(CookieLoginFetcher):
        requested = []

        def get(self, url, headers=None, allow_redirects=True):
            Bouncing.requested.append(url)
            if url.endswith("/login.php") or url == "http://localhost":
                return FetchResponse(302, {"Location": "/logout.php?next=login"}, "")
            return FetchResponse(404, {}, "")
    fetcher = Bouncing()
    mgr = SessionManager(_store(), scope_hosts=["localhost"], fetch_factory=_factory(fetcher))
    with pytest.raises(SessionAuthError):
        mgr.ensure("localhost", "admin", "http://localhost")
    assert not any("logout" in u for u in Bouncing.requested)


# --- every HTTP probe sender calls the gate (PA-0083(1)) --------------------------------
SENDER_METHODS = {"send", "send_correlated", "get"}
#: Classes with a send-like method that only delegate to another, gated sender (or are
#: not probe senders at all), with the reason.
NOT_PROBE_SENDERS = {
    "_CountingSender": "delegates to the wrapped sender",
    "Sender": "the oracle's abstract interface",
    "HttpClient": "core transport; senders gate before calling it",
}


def _sender_offenders(root: Path) -> list[str]:
    offenders = []
    for path in sorted(root.rglob("*.py")):
        src = path.read_text()
        tree = ast.parse(src)
        does_http = any(isinstance(n, (ast.Import, ast.ImportFrom)) and any(
            (a.name if isinstance(n, ast.Import) else (n.module or "")).split(".")[0]
            in ("requests", "httpx", "urllib3", "http", "socket")
            or (isinstance(n, ast.ImportFrom) and (n.module or "") == "fuzzlab.core.http")
            for a in n.names) for n in ast.walk(tree))
        if not does_http:
            continue
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            if cls.name in NOT_PROBE_SENDERS:
                continue
            for fn in cls.body:
                if not (isinstance(fn, ast.FunctionDef) and fn.name in SENDER_METHODS):
                    continue
                args = [a.arg for a in fn.args.args]
                if args[:4] != ["self", "url", "param", "value"]:
                    continue                                 # not a probe-sender shape
                calls = {getattr(c.func, "id", getattr(c.func, "attr", None))
                         for c in ast.walk(fn) if isinstance(c, ast.Call)}
                if "check_send_url" not in calls:
                    offenders.append(f"{path.name}:{cls.name}.{fn.name}")
    return offenders


def test_every_probe_sender_calls_the_send_gate():
    assert _sender_offenders(Path(__file__).resolve().parents[1] / "fuzzlab") == []


def test_the_sender_guard_catches_a_synthetic_offender(tmp_path):
    (tmp_path / "rogue.py").write_text(
        "import requests\n"
        "class Rogue:\n"
        "    def send(self, url, param, value):\n"
        "        return requests.get(url, params={param: value})\n")
    assert _sender_offenders(tmp_path) == ["rogue.py:Rogue.send"]


def test_the_m6_browser_aborts_destructive_writes_but_loads_its_targets(monkeypatch):
    """`browserexec` runs only on-host (its Chromium is the pinned bundled build), so its
    wiring is checked with a fake Playwright: the context is guarded, the observe and
    store URLs are the explicit allowance, anything else destructive is aborted."""
    import sys
    import types

    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    routes = []

    class Page:
        def on(self, *a):
            pass

        def goto(self, url, **kw):
            pass

        def evaluate(self, js):
            return []

        def wait_for_timeout(self, ms):              # the settle poll (BUG-0126)
            pass

        def wait_for_load_state(self, state, **kw):  # the bounded load wait (BUG-0137)
            pass

        def once(self, event, fn):                   # the load time (BUG-0137 review)
            pass

    class Context:
        request = types.SimpleNamespace(post=lambda *a, **k: None)

        def add_init_script(self, s):
            pass

        def expose_binding(self, name, fn):          # the sentinel (reviewers A, B)
            pass

        def route(self, pattern, handler):
            routes.append((pattern, handler))

        def new_page(self):
            return Page()

    class Browser:
        def new_context(self, **kw):
            assert kw.get("service_workers") == "block"   # workers bypass page.route
            return Context()

        def close(self):
            pass

    class PW:
        chromium = types.SimpleNamespace(launch=lambda **kw: Browser())

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    fake.Error = type("Error", (Exception,), {})       # playwright.sync_api.Error
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)
    monkeypatch.setattr("fuzzlab.tools.browserexec.PlaywrightBrowserExecutor.SETTLE_MS", 0)
    PlaywrightBrowserExecutor().run(
        ExecRequest(url="http://h/comments/delete.php", param="q", value="x",
                    store=StoreStep(url="http://h/post.php", param="c", value="x")), "tok")
    (pattern, handler), = routes
    assert pattern == "**/*"
    outcomes = {}
    for url, method in (("http://h/comments/delete.php?q=x", "GET"),
                        ("http://h/logout.php", "GET"), ("http://h/logout.php", "POST"),
                        ("http://h/app.js", "GET")):
        route = _Route(url, method)
        handler(route)
        outcomes[(url, method)] = route.outcome
    # D72: a destructive GET subresource goes through; a write to one is aborted
    assert outcomes == {("http://h/comments/delete.php?q=x", "GET"): "continue",
                        ("http://h/logout.php", "GET"): "continue",
                        ("http://h/logout.php", "POST"): "abort",
                        ("http://h/app.js", "GET"): "continue"}
