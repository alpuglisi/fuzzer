"""BUG-0123: every request a browser we launch makes is confined to the target origin.

The crawler's Chromium followed Juice Shop's ``/redirect?to=https://github.com/...`` to
github.com: ``guard_page`` (BUG-0111) aborted destructive URLs only, so redirects,
subresources, popups, WebSockets and preconnects went wherever the page pointed. Scope
is now checked where every outbound browser path is made (PA-0123):

* ``guard_page`` routes the whole *context* (popups included), scope before the
  destructive check, ``in_scope`` required, ``allow`` never lifting scope;
* WebSockets are routed (``route_web_socket``);
* every launch takes ``browser_launch_args`` (no proxy; no host resolvable outside
  scope -- IP literals included);
* the API-request clients (``context.request``, ``pw.request.new_context``) are
  scope-checked and never redirect.

The real-browser tests below run Chromium against a loopback page that reaches for a
second loopback service (another port: another service) and the open web; the second
service is a raw TCP listener, so it sees *any* connection, not just HTTP requests.
Under ``FUZZLAB_REQUIRE_BROWSER=1`` they fail rather than skip.
"""

from __future__ import annotations

import ast
import glob
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fuzzlab.core.urls import in_origin_scope, origin_scope, url_key
from fuzzlab.tools.navguard import (browser_launch_args, checked_api_request,
                                    make_route_handler, make_ws_handler)

ROOT = Path(__file__).resolve().parents[1]


# --- the predicate -----------------------------------------------------------------
@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:8080/a", True),
    ("http://localhost:8080/a?b=1", True),           # alias, same port
    ("http://[::1]:8080/a", True),
    ("ws://127.0.0.1:8080/socket", True),            # ws compares as http
    ("http://127.0.0.1:3000/a", False),              # another loopback port
    ("http://127.0.0.2:8080/a", False),              # another 127/8 address
    ("https://127.0.0.1:8080/a", False),             # another scheme
    ("wss://127.0.0.1:8080/a", False),
    ("https://github.com/juice-shop", False),
    ("http://203.0.113.9/x.png", False),
    ("/relative", False),                            # no origin: never in scope
    ("", False),
])
def test_origin_scope_is_scheme_host_and_port(url, expected):
    assert in_origin_scope(url, origin_scope("http://127.0.0.1:8080/")) is expected


def test_origin_scope_ignores_empty_inputs():
    assert origin_scope(None, "", "http://h/") == frozenset({"http://h:80"})


# --- the handlers ------------------------------------------------------------------
class _Resp:
    def __init__(self, status=200, location=None):
        self.status = status
        self.headers = {"location": location} if location else {}


class _Route:
    """A fake Playwright route: ``fetch`` answers from ``site`` (url -> _Resp)."""

    def __init__(self, url, site=None, *, method="GET", navigation=False):
        self.request = type("Req", (), {
            "url": url, "method": method, "headers": {"content-type": "x/y"},
            "post_data_buffer": b"body" if method == "POST" else None,
            "is_navigation_request": lambda _self: navigation})()
        self.site = site or {}
        self.outcome = None
        self.fulfilled = None
        self.fetched = []

    def fetch(self, max_redirects=None):
        assert max_redirects == 0
        self.fetched.append(self.request.url)
        return self.site.get(self.request.url, _Resp())

    def abort(self):
        self.outcome = "abort"

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"
        self.fulfilled = response if response is not None else (status, headers)


class _Api:
    """The context's request client: records every hop it is asked for."""

    def __init__(self, site):
        self.site, self.calls = site, []

    def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
        assert max_redirects == 0
        self.calls.append((url, method, data))
        return self.site.get(url, _Resp())


def _scope(url="http://127.0.0.1:8080/"):
    origins = origin_scope(url)
    return lambda u: in_origin_scope(u, origins)


def test_out_of_scope_requests_are_aborted_and_reported():
    out, destructive = [], []
    handler = make_route_handler(on_abort=lambda u, r: destructive.append(u),
                                 in_scope=_scope(), on_out_of_scope=out.append)
    cases = [("http://127.0.0.1:8080/a.js", "fulfill"),
             ("https://github.com/x", "abort"),
             ("http://127.0.0.1:3000/rest", "abort"),
             ("http://127.0.0.1:8080/logout.php", "abort"),
             ("data:image/png;base64,AAAA", "continue"),     # not network requests
             ("blob:http://127.0.0.1:8080/uuid", "continue"),
             ("about:blank", "continue")]
    for url, outcome in cases:
        route = _Route(url)
        handler(route)
        assert route.outcome == outcome, url
    assert out == ["https://github.com/x", "http://127.0.0.1:3000/rest"]
    assert destructive == ["http://127.0.0.1:8080/logout.php"]


H = "http://127.0.0.1:8080"


def test_a_redirected_navigation_is_walked_hop_by_hop_and_lands_checked():
    site = {f"{H}/r0": _Resp(302, "/r1"), f"{H}/r1": _Resp(301, f"{H}/sub/end")}
    api = _Api(site)
    route = _Route(f"{H}/r0", site, navigation=True)
    make_route_handler(in_scope=_scope(), api=api)(route)
    assert route.fetched == [f"{H}/r0"]
    assert [c[0] for c in api.calls] == [f"{H}/r1", f"{H}/sub/end"]
    # one redirect to the checked landing URL, so page.url and relative links are right
    assert (route.outcome, route.fulfilled) == ("fulfill", (302, {"location": f"{H}/sub/end"}))


def test_a_redirected_subresource_is_answered_with_the_landing_response():
    final = _Resp(200)
    site = {f"{H}/img": _Resp(302, "/real.png"), f"{H}/real.png": final}
    route = _Route(f"{H}/img", site)
    make_route_handler(in_scope=_scope(), api=_Api(site))(route)
    assert route.fulfilled is final


@pytest.mark.parametrize("location", [
    "https://github.com/juice-shop/juice-shop",      # the BUG-0123 incident
    "http://127.0.0.1:3000/rest",                    # another loopback service
    "http://localhost:3000/",
])
def test_a_redirect_hop_out_of_scope_is_never_requested(location):
    out = []
    site = {f"{H}/redirect": _Resp(302, "/hop"), f"{H}/hop": _Resp(302, location)}
    api = _Api(site)
    route = _Route(f"{H}/redirect", site, navigation=True)
    make_route_handler(in_scope=_scope(), on_out_of_scope=out.append, api=api)(route)
    assert route.outcome == "abort" and out == [location]
    assert [c[0] for c in api.calls] == [f"{H}/hop"]           # the bad hop: never


def test_a_redirect_hop_to_a_destructive_url_is_never_requested():
    """BUG-0111's guard never saw redirect hops either (Playwright does not route
    them): the hop is checked here like a first request."""
    hits = []
    site = {f"{H}/a.php": _Resp(302, "/logout.php")}
    api = _Api(site)
    route = _Route(f"{H}/a.php", site)
    make_route_handler(on_abort=lambda u, r: hits.append((u, r)), in_scope=_scope(),
                       api=api)(route)
    assert route.outcome == "abort" and api.calls == []
    assert hits == [(f"{H}/logout.php", "logout")]


def test_an_endless_redirect_chain_is_aborted():
    from fuzzlab.tools.navguard import MAX_REDIRECTS
    site = {f"{H}/r{i}": _Resp(302, f"/r{i + 1}") for i in range(20)}
    api = _Api(site)
    route = _Route(f"{H}/r0", site, navigation=True)
    make_route_handler(in_scope=_scope(), api=api)(route)
    assert route.outcome == "abort" and len(api.calls) == MAX_REDIRECTS + 1


def test_redirect_methods_follow_the_browser_rules():
    site = {f"{H}/post": _Resp(303, "/next"), f"{H}/keep": _Resp(307, "/again")}
    api = _Api(site)
    route = _Route(f"{H}/post", site, method="POST", navigation=True)
    make_route_handler(in_scope=_scope(), api=api)(route)
    assert api.calls == [(f"{H}/next", "GET", None)]
    assert route.fulfilled == (303, {"location": f"{H}/next"})
    api.calls.clear()
    route = _Route(f"{H}/keep", site, method="POST", navigation=True)
    make_route_handler(in_scope=_scope(), api=api)(route)
    assert api.calls == [(f"{H}/again", "POST", b"body")]
    # a kept body is never sent twice: the landing response itself is the answer
    assert route.fulfilled is site.get(f"{H}/again", route.fulfilled)
    assert route.outcome == "fulfill" and not isinstance(route.fulfilled, tuple)


def test_scope_is_checked_before_any_fetch():
    """Routed requests are fetched by the Playwright driver, which Chromium's resolver
    rules never confine (reviewer A, verified live): the predicate must run first."""
    route = _Route("http://127.0.0.1:3000/x")
    api = _Api({})
    make_route_handler(in_scope=_scope(), api=api)(route)
    assert route.fetched == [] and api.calls == [] and route.outcome == "abort"


def test_without_a_request_client_a_redirect_is_aborted_not_followed():
    site = {f"{H}/r": _Resp(302, "/ok")}
    route = _Route(f"{H}/r", site)
    make_route_handler(in_scope=_scope())(route)
    assert route.outcome == "abort"


def test_an_unfetchable_request_is_aborted():
    route = _Route(f"{H}/x")
    route.fetch = lambda max_redirects=None: (_ for _ in ()).throw(OSError("reset"))
    make_route_handler(in_scope=_scope())(route)
    assert route.outcome == "abort"


def test_allow_never_lifts_scope():
    """The operator's explicit URLs lift the destructive deny-list, never scope."""
    off = "https://github.com/setup.php"
    handler = make_route_handler(frozenset({url_key(off)}), in_scope=_scope())
    route = _Route(off)
    handler(route)
    assert route.outcome == "abort"


def test_scope_is_checked_before_the_destructive_rule():
    """An out-of-scope destructive URL is reported as out of scope (scope first)."""
    out, destructive = [], []
    handler = make_route_handler(on_abort=lambda u, r: destructive.append(u),
                                 in_scope=_scope(), on_out_of_scope=out.append)
    handler(_Route("https://evil.example/logout"))
    assert out == ["https://evil.example/logout"] and destructive == []


def test_the_route_handler_has_no_unscoped_form():
    with pytest.raises(TypeError):
        make_route_handler(frozenset())                    # in_scope is required


class _WS:
    def __init__(self, url):
        self.url, self.outcome = url, None

    def connect_to_server(self):
        self.outcome = "connect"

    def close(self):
        self.outcome = "close"


def test_websockets_are_scope_checked():
    out = []
    handler = make_ws_handler(_scope(), out.append)
    inside, outside = _WS("ws://127.0.0.1:8080/socket.io/"), _WS("wss://evil.example/s")
    handler(inside)
    handler(outside)
    # never connected = a server-less mock; close() would deadlock a sync handler
    assert (inside.outcome, outside.outcome) == ("connect", None)
    assert out == ["wss://evil.example/s"]


def test_api_requests_are_refused_out_of_scope():
    checked_api_request(_scope(), "http://localhost:8080/form")        # no raise
    for url in ("https://github.com/", "http://127.0.0.1:3000/", "/rel"):
        with pytest.raises(PermissionError):
            checked_api_request(_scope(), url)


# --- launch arguments --------------------------------------------------------------
def _resolver_rules(args):
    (rules,) = [a.split("=", 1)[1] for a in args if a.startswith("--host-resolver-rules=")]
    return rules


def test_launch_args_disable_the_proxy_and_resolve_only_scope_origins():
    args = browser_launch_args(["https://shop.example.org/x", None])
    assert "--no-proxy-server" in args
    assert _resolver_rules(args) == ("MAP shop.example.org:443 shop.example.org:443, "
                                     "MAP * ~NOTFOUND")
    for flag in ("--disable-background-networking", "--no-pings", "--dns-prefetch-disable",
                 "--disable-features=NetworkPrediction", "--disable-component-update",
                 "--disable-sync", "--disable-domain-reliability"):
        assert flag in args


def test_a_loopback_origin_admits_its_three_spellings_on_its_port_only():
    rules = _resolver_rules(browser_launch_args(["http://localhost:3000/"]))
    assert rules == ("MAP 127.0.0.1:3000 127.0.0.1:3000, MAP localhost:3000 localhost:3000, "
                     "MAP [::1]:3000 [::1]:3000, MAP * ~NOTFOUND")


def test_any_port_hosts_are_admitted_by_host():
    rules = _resolver_rules(browser_launch_args([], any_port_hosts=["Shop.example.org"]))
    assert rules == "EXCLUDE shop.example.org, MAP * ~NOTFOUND"


# --- the spider's API-request client ------------------------------------------------
def test_the_spiders_isolated_submit_refuses_an_out_of_scope_action(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        with pytest.raises(PermissionError):
            sp._isolated_submit("POST", "http://127.0.0.1:3000/f", [("a", "1")])
        with pytest.raises(PermissionError):
            sp._isolated_submit("GET", "https://github.com/f", [("a", "1")])
    finally:
        sp.storage.close()


def test_the_m6_browser_is_launched_scoped_and_plants_without_redirects(monkeypatch):
    """`browserexec` runs on-host only (its pinned Chromium), so its wiring is checked
    with a fake Playwright: scoped launch args, a scoped context route, and the stored
    plant made with ``max_redirects=0``."""
    import sys
    import types

    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    seen = {"routes": [], "ws": [], "posts": [], "launch": None}

    class Page:
        def on(self, *a):
            pass

        def goto(self, url, **kw):
            pass

        def evaluate(self, js):
            return []

    class Context:
        request = types.SimpleNamespace(
            post=lambda url, **kw: seen["posts"].append((url, kw)))

        def add_init_script(self, s):
            pass

        def route(self, pattern, handler):
            seen["routes"].append(handler)

        def route_web_socket(self, pattern, handler):
            seen["ws"].append(handler)

        def new_page(self):
            return Page()

    class Browser:
        def new_context(self, **kw):
            return Context()

        def close(self):
            pass

    def launch(**kw):
        seen["launch"] = kw
        return Browser()

    class PW:
        chromium = types.SimpleNamespace(launch=launch)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)
    monkeypatch.setattr("time.sleep", lambda s: None)
    PlaywrightBrowserExecutor().run(
        ExecRequest(url="http://127.0.0.1:8090/view.php", param="q", value="x",
                    store=StoreStep(url="http://127.0.0.1:8090/post.php", param="c",
                                    value="x", location="body")), "tok")
    assert "--no-proxy-server" in seen["launch"]["args"]
    assert _resolver_rules(seen["launch"]["args"]).startswith("MAP 127.0.0.1:8090 ")
    assert seen["posts"] == [("http://127.0.0.1:8090/post.php",
                              {"form": {"c": "x"}, "max_redirects": 0})]
    (handler,), (ws_handler,) = seen["routes"], seen["ws"]
    for url, outcome in [("http://127.0.0.1:8090/app.js", "fulfill"),
                         ("http://127.0.0.1:3000/x", "abort"),
                         ("https://github.com/", "abort")]:
        route = _Route(url)
        handler(route)
        assert route.outcome == outcome, url
    sock = _WS("ws://127.0.0.1:3000/")
    ws_handler(sock)
    assert sock.outcome is None                       # never connected through


# --- real browser: nothing leaves the target origin ---------------------------------
class _Sink:
    """A raw TCP listener on another loopback port: records every connection and every
    byte, so a preconnect or WebSocket handshake shows up as surely as a GET."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.data = b""
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.connections += 1
            conn.settimeout(0.5)
            try:
                self.data += conn.recv(4096)
            except OSError:
                pass
            conn.close()

    def close(self):
        self._stop = True
        self._t.join(timeout=2)
        self.sock.close()


def _page(q):
    off = f"http://127.0.0.1:{q}"
    return (f"<html><head><title>t</title><link rel='preconnect' href='{off}/'>"
            f"<link rel='dns-prefetch' href='//leak.example/'></head><body>"
            f"<a href='/after'>after</a><a href='/go'>go</a><a href='{off}/link'>x</a>"
            f"<img src='{off}/img.png'><img src='http://203.0.113.9/x.png'>"
            f"<iframe src='{off}/frame'></iframe>"
            f"<script>document.body.insertAdjacentHTML('beforeend','<p id=js-built>r</p>');"
            f"fetch('{off}/fetch').catch(function(){{}});"
            f"try{{new WebSocket('ws://127.0.0.1:{q}/ws')}}catch(e){{}}"
            f"window.open('{off}/popup');</script></body></html>").encode()


def _target(q):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            seen.append(self.path)
            if self.path == "/go":                      # an open redirect off-origin
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{q}/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = _page(q) if self.path == "/" else b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def _chromium_or_skip(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])


@pytest.fixture
def lab(monkeypatch):
    _chromium_or_skip(monkeypatch)
    sink = _Sink()
    server, seen = _target(sink.port)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/", seen, sink
    finally:
        server.shutdown()
        sink.close()


def test_a_rendered_crawl_never_leaves_the_target_origin(tmp_path, lab):
    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    base, seen, sink = lab
    sp = LocalSpider(base, max_depth=2, db_name=str(tmp_path / "s.db"),
                     engine="playwright", timeout_ms=5000)
    if sp.engine != "playwright":
        skip_or_fail("playwright engine unavailable")
    try:
        sp.crawl()
    except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
        skip_or_fail(f"chromium could not launch: {exc}")
    assert (sink.connections, sink.data) == (0, b"")         # no socket, no byte
    assert {"/", "/after", "/go"} <= set(seen)               # the crawl ran past /go
    assert sp.skipped_out_of_scope.get("127.0.0.1", 0) >= 3  # img, iframe, fetch, ...
    assert "203.0.113.9" in sp.skipped_out_of_scope


def test_the_auditors_browser_never_leaves_the_target_origin(lab):
    from tests._browser import skip_or_fail
    from fuzzlab.tools.fetcher import ContentFetcher
    base, seen, sink = lab
    fetcher = ContentFetcher(engine="playwright", timeout_ms=5000)
    if fetcher.engine != "playwright":
        skip_or_fail("playwright engine unavailable")
    try:
        with fetcher:
            status, _ct, html, _xhr = fetcher.fetch(base)
            fetcher.fetch(base + "go")              # aborted redirect -> static, unfollowed
    except Exception as exc:  # noqa: BLE001
        skip_or_fail(f"chromium could not launch: {exc}")
    assert status == 200 and 'id="js-built"' in html      # rendered, not a static fallback
    assert (sink.connections, sink.data) == (0, b"")
    assert fetcher.skipped_out_of_scope


def test_the_auditors_scope_is_fixed_and_never_moves(lab):
    """Reviewer A: the scope was re-derived from every fetched URL, and the driver's
    fetches are not confined by the resolver rules. A later URL on another origin is
    refused before anything is sent."""
    from tests._browser import skip_or_fail
    from fuzzlab.tools.fetcher import ContentFetcher
    base, seen, sink = lab
    fetcher = ContentFetcher(engine="playwright", timeout_ms=5000)
    if fetcher.engine != "playwright":
        skip_or_fail("playwright engine unavailable")
    try:
        with fetcher:
            fetcher.fetch(base + "after")
            refused = fetcher.fetch(f"http://127.0.0.1:{sink.port}/other")
            refused_localhost = fetcher.fetch(f"http://localhost:{sink.port}/other")
    except Exception as exc:  # noqa: BLE001
        skip_or_fail(f"chromium could not launch: {exc}")
    assert refused == refused_localhost == (0, "", "", [])
    assert (sink.connections, sink.data) == (0, b"")
    assert seen == ["/after"]


def test_the_static_auditor_refuses_another_origin_too():
    from fuzzlab.tools.fetcher import ContentFetcher
    fetcher = ContentFetcher(engine="requests", auth_base_url="http://127.0.0.1:8090/app/")

    class Boom:
        def get(self, *a, **k):
            raise AssertionError("an out-of-scope URL was fetched")
    fetcher.session = Boom()
    assert fetcher.fetch("http://127.0.0.1:3000/x") == (0, "", "", [])
    assert fetcher.skipped_out_of_scope == {"127.0.0.1": 1}


@pytest.mark.parametrize("code", [307, 308])
def test_a_redirected_post_navigation_is_submitted_once(code, monkeypatch):
    """Reviewer B's repro: an auto-submitted POST whose action 307/308-redirects. The
    guard walks the hop (one POST); answering the navigation with a redirect made the
    browser POST again, unrouted."""
    import os

    from playwright.sync_api import sync_playwright

    from tests._browser import skip_or_fail
    from fuzzlab.tools.navguard import guard_page, release
    _chromium_or_skip(monkeypatch)
    posts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = (b"<form method=post action=/a><input name=q value=1></form>"
                    b"<script>document.forms[0].submit()</script>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            posts.append(self.path)
            if self.path == "/a":
                self.send_response(code)
                self.send_header("Location", "/b")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"<html><body>landed</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    kw = {"headless": True, "args": browser_launch_args([base])}
    if os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE"):
        kw["executable_path"] = os.environ["PLAYWRIGHT_CHROMIUM_EXECUTABLE"]
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**kw)
            except Exception as exc:  # noqa: BLE001
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                context = browser.new_context(service_workers="block")
                guard_page(context, in_scope=_scope(base))
                page = context.new_page()
                page.goto(base, timeout=5000)
                page.wait_for_function("document.body && "
                                       "document.body.innerText.includes('landed')",
                                       timeout=5000)
                release(context)
            finally:
                browser.close()
    finally:
        server.shutdown()
    assert posts == ["/a", "/b"]                       # each exactly once


def test_the_launch_args_alone_confine_an_unrouted_page_to_the_origin(lab):
    """The network backstop on its own (no route installed): the scope origin loads;
    another port on the same loopback host, in any spelling, and an off-scope IP
    literal do not even resolve -- so nothing a route cannot see gets out either."""
    import os

    from playwright.sync_api import sync_playwright

    from tests._browser import skip_or_fail
    base, seen, sink = lab
    kw = {"headless": True, "args": browser_launch_args([base])}
    if os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE"):
        kw["executable_path"] = os.environ["PLAYWRIGHT_CHROMIUM_EXECUTABLE"]
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(**kw)
        except Exception as exc:  # noqa: BLE001
            skip_or_fail(f"chromium could not launch: {exc}")
        try:
            page = browser.new_page()
            page.goto(base + "after", timeout=5000)
            page.goto(base.replace("127.0.0.1", "localhost") + "after", timeout=5000)
            for url in (f"http://127.0.0.1:{sink.port}/", f"http://localhost:{sink.port}/",
                        "http://203.0.113.9/", "http://127.0.0.2/"):
                with pytest.raises(Exception, match="ERR_NAME_NOT_RESOLVED"):
                    page.goto(url, timeout=5000)
        finally:
            browser.close()
    assert seen.count("/after") == 2 and sink.connections == 0


# --- static guards (PA-0123): every outbound browser path is scoped where made -------
_API_VERBS = {"get", "post", "put", "patch", "delete", "head", "fetch"}


def _browser_offenders(root: Path) -> list[str]:
    """Functions that launch Chromium without ``browser_launch_args``, call
    ``guard_page`` without ``in_scope``, or make an API request (``x.request.<verb>``
    or a ``.request.new_context()`` client's ``fetch``) without ``max_redirects=0``
    or without a ``checked_api_request`` in the same function."""
    offenders = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
            names = {c.func.id if isinstance(c.func, ast.Name) else
                     getattr(c.func, "attr", None) for c in calls}
            made_client = any(isinstance(c.func, ast.Attribute)
                              and c.func.attr == "new_context"
                              and isinstance(c.func.value, ast.Attribute)
                              and c.func.value.attr == "request" for c in calls)
            where = f"{path.relative_to(root)}:{fn.name}"
            for c in calls:
                f = c.func
                kws = {k.arg: k.value for k in c.keywords}
                if (isinstance(f, ast.Attribute) and f.attr == "launch"
                        and isinstance(f.value, ast.Attribute)
                        and f.value.attr == "chromium"
                        and "browser_launch_args" not in names):
                    offenders.append(f"{where}: unscoped launch")
                if getattr(f, "id", getattr(f, "attr", None)) == "guard_page" \
                        and "in_scope" not in kws:
                    offenders.append(f"{where}: guard_page without in_scope")
                api = (isinstance(f, ast.Attribute) and f.attr in _API_VERBS
                       and ((isinstance(f.value, ast.Attribute)
                             and f.value.attr == "request")
                            or (made_client and f.attr == "fetch")))
                if api:
                    redirects = kws.get("max_redirects")
                    if not (isinstance(redirects, ast.Constant) and redirects.value == 0):
                        offenders.append(f"{where}: API request may redirect")
                    if "checked_api_request" not in names:
                        offenders.append(f"{where}: API request not scope-checked")
    return offenders


def test_every_browser_path_in_fuzzlab_is_scoped():
    assert _browser_offenders(ROOT / "fuzzlab") == []


def test_the_browser_guard_catches_synthetic_offenders(tmp_path):
    (tmp_path / "rogue.py").write_text(
        "def launch(pw):\n"
        "    b = pw.chromium.launch(headless=True)\n"
        "    ctx = b.new_context()\n"
        "    guard_page(ctx, allow=frozenset())\n"
        "    ctx.request.post('http://h/', form={})\n"
        "def submit(pw, url):\n"
        "    c = pw.request.new_context()\n"
        "    checked_api_request(lambda u: True, url)\n"
        "    return c.fetch(url, method='GET')\n")
    assert _browser_offenders(tmp_path) == [
        "rogue.py:launch: unscoped launch",
        "rogue.py:launch: guard_page without in_scope",
        "rogue.py:launch: API request may redirect",
        "rogue.py:launch: API request not scope-checked",
        "rogue.py:submit: API request may redirect",
    ]


def test_the_launch_sites_are_the_three_known_ones():
    """Not vacuous: the guard sees every launch site there is."""
    sites = set()
    for path in (ROOT / "fuzzlab").rglob("*.py"):
        if ".chromium.launch(" in path.read_text():
            sites.add(path.name)
    assert sites == {"spider.py", "fetcher.py", "browserexec.py"}
