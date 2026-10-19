"""BUG-0136 / PA-0136: a guard's abort of a navigation keeps the current document.

`navguard`'s route aborted a refused navigation with Playwright's default error code,
which makes Chromium commit its error page (``chrome-error://chromewebdata/``) in the
page's place. A page whose script navigated somewhere the guard refuses (out of scope,
a destructive URL) therefore lost its content and links to the crawl, although the
navigation itself was rightly refused. Only the reveal window (FR-CRAWL-15/16) and,
since BUG-0134's T1, the session-withheld branch used ``"aborted"`` (ERR_ABORTED),
which leaves the page where it is.

Now every abort of a document request -- a navigation, top-level or frame, and each of
its redirect hops -- uses ``"aborted"``, whatever the reason; a subresource keeps the
default code. ``goto`` of a refused target still raises, and each reason is still
recorded.
"""

from __future__ import annotations

import glob
import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.tools.navguard import DOCUMENT_ABORT, make_route_handler

H = "http://127.0.0.1:8080"


# --- the abort code, per reason (unit) ----------------------------------------------
class _Resp:
    def __init__(self, status=200, location=None):
        self.status = status
        self.headers = {"location": location} if location else {}


def _cannot_say(_req):
    raise RuntimeError("is_navigation_request unavailable")


class _Frame:
    def __init__(self, parent=None):
        self.parent_frame = parent


#: request kind -> (resource_type, is_navigation_request, frame): a top-level
#: navigation, an iframe's navigation, a ``document`` request whose
#: ``is_navigation_request`` raises (counted by its type, B-N1), and a subresource
KINDS = {
    "navigation": ("document", lambda _r: True, _Frame()),
    "frame": ("document", lambda _r: True, _Frame(parent=_Frame())),
    "document, cannot say": ("document", _cannot_say, _Frame()),
    "subresource": ("image", lambda _r: False, _Frame()),
}


class _Route:
    def __init__(self, url, *, navigation=None, kind=None, method="GET", site=None,
                 boom=False):
        kind = kind or ("navigation" if navigation else "subresource")
        rtype, is_nav, frame = KINDS[kind]
        self.request = type("Req", (), {
            "url": url, "method": method, "headers": {"content-type": "x/y"},
            "post_data_buffer": b"pw=1" if method == "POST" else None,
            "resource_type": rtype, "frame": frame,
            "is_navigation_request": is_nav})()
        self.site, self.boom = site or {}, boom
        self.outcome = self.code = None

    def fetch(self, max_redirects=None, headers=None):
        if self.boom:
            raise RuntimeError("connection refused")
        return self.site.get(self.request.url, _Resp())

    def abort(self, code=None):
        self.outcome, self.code = "abort", code

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"


class _Api:
    def __init__(self, site):
        self.site = site

    def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
        return self.site.get(url, _Resp())


def _in_scope(u):
    return in_origin_scope(u, origin_scope(H + "/"))


_SESSION = origin_scope(H + "/")
_LOOP = {f"{H}/r{i}": _Resp(302, f"{H}/r{i + 1}") for i in range(10)}

#: reason -> (url, handler keywords, route keywords): every abort branch of the handler
REASONS = {
    "out of scope": (f"http://127.0.0.1:3000/x", {}, {}),
    "destructive": (f"{H}/logout.php", {}, {}),
    "method refused": (f"{H}/item", {"method_refusal": lambda m, u: "DELETE"},
                       {"method": "DELETE"}),
    "body refused": (f"{H}/login", {"request_refusal": lambda m, u, h, b: "password"},
                     {"method": "POST"}),
    "reveal window": (f"{H}/next", {"window": lambda m, u, n: "window open"}, {}),
    "session withheld": ("http://127.0.0.1:3000/x",
                         {"in_scope": lambda u: "127.0.0.1" in u,
                          "cookie_scope": lambda u: in_origin_scope(u, _SESSION)}, {}),
    "hop out of scope": (f"{H}/go", {}, {"site": {f"{H}/go": _Resp(302,
                                                                  "http://x.example/")}}),
    "hop destructive": (f"{H}/go", {}, {"site": {f"{H}/go": _Resp(302,
                                                                  "/logout.php")}}),
    "hop withheld": (f"{H}/go", {"in_scope": lambda u: "127.0.0.1" in u,
                                 "cookie_scope": lambda u: in_origin_scope(u, _SESSION)},
                     {"site": {f"{H}/go": _Resp(302, "http://127.0.0.1:3000/land")}}),
    "too many redirects": (f"{H}/r0", {}, {"site": _LOOP}),
    "unfetchable": (f"{H}/x", {}, {"boom": True}),
}


@pytest.mark.parametrize("reason", sorted(REASONS))
@pytest.mark.parametrize("kind,code", [("navigation", DOCUMENT_ABORT),
                                       ("frame", DOCUMENT_ABORT),
                                       ("document, cannot say", DOCUMENT_ABORT),
                                       ("subresource", None)])
def test_every_abort_reason_keeps_the_document_for_a_navigation(reason, kind, code):
    """PA-0136: one rule for every reason -- a document request (a top-level or an
    iframe's navigation, or a ``document`` request that cannot say whether it is one)
    is aborted with ``"aborted"`` (the current document survives), a subresource with
    the default."""
    url, kw, route_kw = REASONS[reason]
    kw = {"in_scope": _in_scope, **kw}
    site = route_kw.get("site", {})
    route = _Route(url, kind=kind, **route_kw)
    make_route_handler(api=_Api(site), **kw)(route)
    assert (route.outcome, route.code) == ("abort", code), (reason, kind)


def test_the_document_abort_code_is_err_aborted():
    assert DOCUMENT_ABORT == "aborted"


# --- real Chromium ------------------------------------------------------------------
class _Site:
    """A loopback server: ``pages`` maps a path (or a path with its query) to HTML,
    ``redirects`` a path to a 302
    ``Location``, ``delays`` a path to seconds its answer is held back. Every GET path
    is recorded in ``requests``, every POST path in ``posts``, and both in order in
    ``log`` as ``(method, path)``; every POST body in ``bodies``."""

    def __init__(self, host="127.0.0.1"):
        require_loopback(host)                    # PA-0130
        self.pages, self.redirects, self.delays = {}, {}, {}
        self.requests, self.posts, self.log, self.bodies = [], [], [], []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                path = self.path.split("?", 1)[0]
                if site.delays.get(path):
                    time.sleep(site.delays[path])
                if path in site.redirects:
                    self.send_response(302)
                    self.send_header("Location", site.redirects[path])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # a page keyed by its path and query wins over its path's
                body = site.pages.get(self.path) or site.pages.get(
                    path, "<html><body>other</body></html>")
                body = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                site.requests.append(self.path)
                site.log.append(("GET", self.path))
                self._answer()

            def do_POST(self):  # noqa: N802 - http.server API
                site.bodies.append(
                    self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                site.posts.append(self.path)
                site.log.append(("POST", self.path))
                self._answer()

            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.base = f"http://{host}:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _chromium_or_skip(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])


def _crawl(tmp_path, monkeypatch, build, hook=None, timeout_ms=8000):
    """Start two loopback sites A and B, let ``build(a, b)`` set them up, and crawl A
    to depth 1 with the browser (``hook(spider, a, b)`` first, if given). Return
    ``(spider, a, b, rows)``; ``rows`` maps each stored URL to ``(status, content)``."""
    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a, b = _Site(), _Site()
    build(a, b)
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=timeout_ms)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        if hook is not None:
            hook(sp, a, b)
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
        b.close()
    rows = {u: (st, c) for u, st, c in sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, status_code, content FROM discovered_pages").fetchall()}
    return sp, a, b, rows


def _content(rows, url):
    return (rows.get(url) or (None, ""))[1] or ""


def _crawl_a_page_that_navigates_to(target_of, tmp_path, monkeypatch):
    """Crawl A, whose page navigates by script to ``target_of(a, b)`` 200 ms after
    load; return ``(spider, a, b, rows)``."""
    def build(a, b):
        a.pages["/"] = (f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a><script>"
                        f"setTimeout(()=>location.href='{target_of(a, b)}',200)</script>"
                        f"</body></html>")
    return _crawl(tmp_path, monkeypatch, build)


def test_a_script_navigation_out_of_scope_keeps_the_page_crawled(monkeypatch, tmp_path):
    """The scope guard (BUG-0123) refuses it; the page keeps its content and links,
    and the out-of-scope request is still recorded."""
    sp, a, b, rows = _crawl_a_page_that_navigates_to(lambda a, b: b.base + "away",
                                                     tmp_path, monkeypatch)
    assert "A-OWN-CONTENT" in _content(rows, a.base)
    assert "/next" in a.requests                               # its link was crawled
    assert b.requests == []                                    # nothing left scope
    assert sp.skipped_out_of_scope.get("127.0.0.1", 0) >= 1    # the reason, recorded


def test_a_script_navigation_to_a_destructive_url_keeps_the_page_crawled(monkeypatch,
                                                                       tmp_path):
    """The destructive rule (BUG-0111) refuses it; the page keeps its content and
    links, and the refusal is still recorded."""
    sp, a, _b, rows = _crawl_a_page_that_navigates_to(lambda a, b: a.base + "logout.php",
                                                      tmp_path, monkeypatch)
    assert "A-OWN-CONTENT" in _content(rows, a.base)
    assert "/next" in a.requests
    assert "/logout.php" not in a.requests                     # never requested
    assert a.base + "logout.php" in sp.skipped_destructive     # the reason, recorded


def test_goto_of_a_refused_target_still_raises_and_the_page_stays(monkeypatch):
    """The callers' signal is unchanged: `goto` of a refused target raises (the crawl
    then records or falls back as before), and the page already shown stays."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    from tests._browser import launch_browser_or_skip
    from fuzzlab.tools.navguard import guard_page, release
    _chromium_or_skip(monkeypatch)
    a, b = _Site(), _Site()
    a.pages["/"] = "<html><body><p>A-OWN-CONTENT</p></body></html>"
    origins = origin_scope(a.base)
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                ctx = browser.new_context(service_workers="block")
                guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                page = ctx.new_page()
                page.goto(a.base, wait_until="load")
                for refused in (b.base + "x", a.base + "logout.php"):
                    with pytest.raises(PlaywrightError, match="ERR_ABORTED"):
                        page.goto(refused, wait_until="load")
                    assert page.url == a.base and "A-OWN-CONTENT" in page.content()
                release(ctx)
                ctx.close()
            finally:
                browser.close()
    finally:
        a.close()
        b.close()
    assert b.requests == [] and "/logout.php" not in a.requests


# --- review of BUG-0136 (D50) -------------------------------------------------------
_REFUSED = {
    "out of scope": lambda a, b: b.base + "away",
    "destructive": lambda a, b: "/logout.php",
}


def _nothing_refused_was_sent(where, sp, a, b):
    """Nothing reached the refused URL, and the refusal is recorded under its reason."""
    assert b.requests == [] and b.posts == []
    assert "/logout.php" not in a.requests and "/logout.php" not in a.posts
    if where == "out of scope":
        assert sp.skipped_out_of_scope.get("127.0.0.1", 0) >= 1
    else:
        assert a.base + "logout.php" in sp.skipped_destructive


@pytest.mark.parametrize("where", sorted(_REFUSED))
def test_the_crawls_own_target_redirected_to_a_refused_url_raises_and_falls_back(
        where, monkeypatch, tmp_path):
    """X4 (A-S1): the crawl's own `goto` of /go, whose 302 lands on a refused URL,
    raises ERR_ABORTED with the previous page still shown (no error page); the spider
    records /go through its static fallback (the redirect response itself), and the
    refusal under its reason."""
    raised = {}

    def build(a, b):
        a.pages["/"] = "<html><body><p>A-OWN-CONTENT</p><a href='/go'>g</a></body></html>"
        a.redirects["/go"] = _REFUSED[where](a, b)

    def hook(sp, a, b):
        real = sp._goto_and_parse

        def goto_and_parse(url):
            page = sp._page
            before = (page.url, page.content()) if page is not None else None
            try:
                return real(url)
            except Exception as exc:
                raised[url] = (str(exc).splitlines()[0], before,
                               (sp._page.url, sp._page.content()))
                raise
        sp._goto_and_parse = goto_and_parse
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build, hook)
    error, before, after = raised[a.base + "go"]
    assert "ERR_ABORTED" in error
    # the page shown before /go stayed, unchanged (the crawl's known-file seeds may
    # come first, so it is whatever was loaded last, never an error page)
    assert before is not None and after == before
    assert rows[a.base + "go"][0] == 302                       # via the static fallback
    _nothing_refused_was_sent(where, sp, a, b)


@pytest.mark.parametrize("where", sorted(_REFUSED))
def test_a_refused_post_form_submission_keeps_the_page_crawled(where, monkeypatch,
                                                               tmp_path):
    """X4 (A-S2): a page's script submits a POST form to a refused URL: the
    navigation is aborted, nothing is posted, and the page keeps its content and its
    links."""
    def build(a, b):
        a.pages["/"] = (f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a>"
                        f"<form method='post' action='{_REFUSED[where](a, b)}'>"
                        f"<input name='q' value='1'></form><script>"
                        f"setTimeout(()=>document.forms[0].submit(),200)</script>"
                        f"</body></html>")
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build)
    assert "A-OWN-CONTENT" in _content(rows, a.base)
    assert "/next" in a.requests
    _nothing_refused_was_sent(where, sp, a, b)


@pytest.mark.parametrize("where", sorted(_REFUSED))
def test_a_refused_iframe_keeps_its_parent_crawled(where, monkeypatch, tmp_path):
    """X4 (A-S2): an iframe whose source is refused is aborted; its parent page keeps
    its content and its links."""
    def build(a, b):
        a.pages["/"] = (f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a>"
                        f"<iframe src='{_REFUSED[where](a, b)}'></iframe></body></html>")
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build)
    assert "A-OWN-CONTENT" in _content(rows, a.base)
    assert "/next" in a.requests
    _nothing_refused_was_sent(where, sp, a, b)


#: A 50 ms POST ticker. Each tick's key is its own (`k<n>`, so the spider keeps every
#: one) and its value is the browser's clock when it was sent.
_TICKER = ("<script>let n = 0; setInterval(() => fetch('/tick', {method: 'POST', "
           "headers: {'content-type': 'application/json'}, "
           "body: JSON.stringify({['k' + (n++)]: Date.now()})}), 50)</script>")


def _ticks_sent_after(bodies, ended):
    """The send times in `bodies` (raw or JSON text) later than `ended`."""
    times = [t for body in bodies for t in json.loads(body).values()]
    assert times                                    # not vacuous: A did tick
    return [t for t in times if t > ended]


def test_a_failed_load_ends_the_previous_document(monkeypatch, tmp_path):
    """X1 (B-M1): after a refused `goto` the previous page is still alive; its timers
    and fetches would be filed under the URLs crawled next. The failed load sends the
    page to ``about:blank`` before the fallback: A's 50 ms POST ticker stops there, so
    no tick the server gets or the spider captures was sent after that (BUG-0511).
    Before, the ticks queued during the fallback were sent and captured under /next,
    the next URL crawled."""
    import time
    marks = {}

    def build(a, b):
        a.pages["/"] = (
            "<html><body><p>A-OWN-CONTENT</p><a href='/go'>g</a><a href='/next'>n</a>"
            f"{_TICKER}</body></html>")
        a.redirects["/go"] = "/logout.php"

    def hook(sp, a, b):
        real = sp._fetch_static

        def fetch_static(url):
            # what the page shows, what the server saw and what was captured, when the
            # fallback starts; then time for a live document's ticker to run
            marks[url] = (sp._page.url, sp._page.evaluate("Date.now()"))
            time.sleep(0.4)
            return real(url)
        sp._fetch_static = fetch_static
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build, hook, timeout_ms=3000)
    shown, ended = marks[a.base + "go"]
    db = sqlite3.connect(str(tmp_path / "s.db"))
    ticks = db.execute("SELECT page_url, body_json FROM discovered_requests "
                       "WHERE url LIKE '%/tick%'").fetchall()
    assert any(page == a.base for page, _body in ticks)        # the ticker was captured
    assert shown == "about:blank"                              # the failed load ended A
    # each tick carries the browser's clock when A sent it, and `ended` is that clock
    # once the page shows about:blank: no tick, received or captured, was sent after
    # it. Arrival order is not the test (BUG-0511): under load a tick sent before A
    # ended can reach the server after the fallback's own request.
    assert _ticks_sent_after(a.bodies, ended) == []
    assert _ticks_sent_after([body for _page, body in ticks], ended) == []
    assert "/next" in a.requests and "/logout.php" not in a.requests




def _audit_through_a_refused_load(monkeypatch):
    """Fetch A (ticking), then /go (refused: it redirects to /logout.php), then /next,
    with one `ContentFetcher`. Returns the site, what the page showed and the browser
    clock when the static fallback for /go started, and /next's XHR list."""
    import time

    from tests._browser import skip_or_fail
    from fuzzlab.tools.fetcher import ContentFetcher
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = f"<html><body><p>A-OWN-CONTENT</p>{_TICKER}</body></html>"
    a.redirects["/go"] = "/logout.php"
    marks = {}
    try:
        with ContentFetcher(engine="playwright", timeout_ms=3000) as fetcher:
            real = fetcher._static_fetch

            def static_fetch(url):
                marks[url] = (fetcher._page.url, fetcher._page.evaluate("Date.now()"))
                time.sleep(0.4)                  # time for a live document's ticker
                return real(url)
            fetcher._static_fetch = static_fetch
            try:
                first = fetcher.fetch(a.base)
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                skip_or_fail(f"chromium could not launch: {exc}")
            assert "A-OWN-CONTENT" in first[2]
            fetcher.fetch(a.base + "go")
            _status, _ct, _html, next_xhr = fetcher.fetch(a.base + "next")
    finally:
        a.close()
    shown, ended = marks[a.base + "go"]
    return a, shown, ended, next_xhr


def test_the_auditors_failed_load_ends_the_previous_document(monkeypatch):
    """X1's twin in the auditor (CC-AUD-0042): `ContentFetcher.fetch` keeps one page
    for the whole audit. After a refused `goto` (/go redirects to /logout.php) it sends
    the page to ``about:blank`` before the static fallback: A's ticker stops there, so
    no tick the server gets was sent after that (BUG-0511), and the next URL's XHR list
    holds none of A's ticks (before, the ticks queued during the fallback were listed
    under the next URL)."""
    a, shown, ended, next_xhr = _audit_through_a_refused_load(monkeypatch)
    assert shown == "about:blank"                              # the failed load ended A
    assert _ticks_sent_after(a.bodies, ended) == []            # no tick sent after that
    assert not any("/tick" in url for url in next_xhr)         # none filed under /next
    assert "/logout.php" not in a.requests


def test_the_send_time_oracle_sees_a_document_left_alive(monkeypatch):
    """BUG-0511's oracle on the defect it guards (PA-0034(2)): with the failed load's
    ``about:blank`` step removed, A keeps ticking through the fallback's 400 ms, and
    those ticks carry send times after the mark."""
    from fuzzlab.tools import navguard
    real = navguard.navigate

    def navigate(page, url, **kw):
        if url == "about:blank":
            return None                          # the defect: A is left alive
        return real(page, url, **kw)
    monkeypatch.setattr(navguard, "navigate", navigate)
    a, shown, ended, _next_xhr = _audit_through_a_refused_load(monkeypatch)
    assert shown != "about:blank"
    assert _ticks_sent_after(a.bodies, ended)


# --- the M6 executor (X2, B-S1) -----------------------------------------------------
def _m6_site():
    from fuzzlab.oracle.browser import SENTINEL
    site = _Site()
    site.pages["/fire"] = (f"<html><body><script>window.{SENTINEL}('tok');"
                           f"setTimeout(() => location.href = '/logout.php', 50)"
                           f"</script></body></html>")
    # the page navigates away once loaded, before (and instead of) any payload
    site.pages["/early"] = ("<html><body><p>escaped</p><script>"
                            "window.addEventListener('load', () => "
                            "location.href = '/logout.php')</script></body></html>")
    # the page navigates away once loaded; its sink fires 300 ms later
    site.pages["/late"] = (f"<html><body><script>"
                           f"window.addEventListener('load', () => "
                           f"location.href = '/logout.php');"
                           f"setTimeout(() => window.{SENTINEL}('tok'), 300)"
                           f"</script></body></html>")
    site.redirects["/redir"] = "/logout.php"
    return site


def _m6_run(site, path, settle_ms=1500, value="x"):
    """Run the real M6 executor on ``path``. A launch failure skips (or fails, when a
    browser is required); any other no-verdict (`UnplaceableLocation`) propagates."""
    from tests._browser import skip_or_fail
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.oracle.probe import UnplaceableLocation
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = settle_ms
    try:
        return executor.run(ExecRequest(url=site.base + path.lstrip("/"), param="q",
                                        value=value), "tok")
    except UnplaceableLocation as exc:
        if str(exc).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {exc}")
        raise


def test_m6_a_sink_that_fires_before_a_refused_navigation_is_executed(monkeypatch):
    """(a): the sentinel fires, then the page navigates to /logout.php (refused):
    executed, and /logout.php is never requested."""
    _chromium_or_skip(monkeypatch)
    site = _m6_site()
    try:
        assert _m6_run(site, "/fire").executed is True
    finally:
        site.close()
    assert "/logout.php" not in site.requests


def test_m6_a_refused_navigation_before_the_payload_runs_is_a_negative(monkeypatch):
    """(b): once loaded, the page navigates to /logout.php before any payload runs
    (and none does). The navigation is aborted with ERR_ABORTED, so the page stays and
    the run reports executed=False, with no exception. (A navigation during parsing,
    before ``load``, is no verdict instead: BUG-0137,
    `tests/test_m6_navigation_failures.py`.)"""
    _chromium_or_skip(monkeypatch)
    site = _m6_site()
    try:
        assert _m6_run(site, "/early", settle_ms=500).executed is False
    finally:
        site.close()
    assert "/logout.php" not in site.requests


def test_m6_a_sink_that_fires_after_a_refused_navigation_is_executed(monkeypatch):
    """(d), the semantic shift: the page navigates to /logout.php once loaded, and its
    sink fires afterwards. ERR_ABORTED keeps the page, so the hit is seen: executed.
    Before BUG-0136 the error page replaced it and the run reported executed=False (a
    false negative)."""
    _chromium_or_skip(monkeypatch)
    site = _m6_site()
    try:
        assert _m6_run(site, "/late").executed is True
    finally:
        site.close()
    assert "/logout.php" not in site.requests


def test_m6_a_target_whose_own_redirect_is_refused_is_no_verdict(monkeypatch):
    """(c): the observe URL itself redirects to /logout.php: the hop is refused with
    ``net::ERR_ABORTED`` (it was ``net::ERR_FAILED``), and the run reports the page not
    observed (`NotObserved`, BUG-0137), never a Playwright error that ends the run. The
    reason never carries the URL (whose query carries the payload)."""
    from fuzzlab.oracle.browser import NotObserved
    _chromium_or_skip(monkeypatch)
    site = _m6_site()
    try:
        with pytest.raises(NotObserved, match="ERR_ABORTED") as err:
            _m6_run(site, "/redir", value="PAYLOAD-MARK")
    finally:
        site.close()
    assert "PAYLOAD-MARK" not in str(err.value) and site.base not in str(err.value)
    assert "/logout.php" not in site.requests


# --- BUG-0504: teardown lets a just-started navigation out -------------------------
def test_a_navigation_started_at_teardown_is_refused_never_sent(monkeypatch):
    """BUG-0504: a page that starts a refused navigation just as its guarded context is
    released (an app's timer firing then). Before the fix `release` closed the page and
    unrouted, and a navigation paused at interception went out unguarded (18 of 80 loaded
    M6 runs). Here the navigation is started by the page in the same task as `release`
    is called, many times over; `/logout.php` must never reach the server."""
    from playwright.sync_api import sync_playwright

    from tests._browser import launch_browser_or_skip
    from fuzzlab.tools.navguard import guard_page, navigate, release
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = "<html><body><p>A</p></body></html>"
    origins = origin_scope(a.base)
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                for _ in range(15):
                    ctx = browser.new_context(service_workers="block")
                    guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                    page = ctx.new_page()
                    navigate(page, a.base, timeout_ms=8000, wait_until="load")
                    # starts now, lands at interception while the teardown runs
                    page.evaluate("() => { setTimeout(() => location.href = "
                                  "'/logout.php', 0); }")
                    release(ctx)
                    ctx.close()
            finally:
                browser.close()
    finally:
        a.close()
    assert "/logout.php" not in a.requests


# --- BUG-0522: a failed navigation settles on its own error page before it raises -------
#: Each scenario repeats this many times: on the old code most single repetitions already
#: fail (DG-NAVBLANK Table 1), so five make a pass by chance negligible.
_REPS = 5
#: Orders of failed loads before the next one: "404" is an empty-bodied 404 (Chromium
#: commits its own error page), "ref" a redirect every guard refuses (ERR_ABORTED).
_ORDERS = {"404": ["404"], "404x2": ["404", "404"], "404x3": ["404", "404", "404"],
           "refused-404": ["ref", "404"], "404-refused": ["404", "ref"]}


class _ErrorSite:
    """``/missing<..>``: 404 with an empty body; ``/go<..>``: 302 to ``/logout.php``
    (refused); ``/x<..>``: JSON; ``/``: a 50 ms POST ticker; any other path: a page whose
    script fetches ``/x<path>``. POST bodies are kept in ``bodies``."""

    def __init__(self):
        require_loopback("127.0.0.1")              # PA-0130
        self.bodies: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", ctype="text/html", headers=()):
                self.send_response(status)
                if body:
                    self.send_header("Content-Type", ctype)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                if path.startswith("/missing"):
                    return self._send(404)
                if path.startswith("/go"):
                    return self._send(302, headers=[("Location", "/logout.php")])
                if path.startswith("/x"):
                    return self._send(200, b"{}", "application/json")
                if path == "/":
                    return self._send(200, f"<html><body>A{_TICKER}</body></html>".encode())
                return self._send(200, f"<html><body><a href='/y'>y</a>ok<script>"
                                       f"fetch('/x{path}')</script></body></html>".encode())

            def do_POST(self):  # noqa: N802 - http.server API
                n = int(self.headers.get("Content-Length") or 0)
                site.bodies.append(self.rfile.read(n).decode())
                return self._send(200, b"{}", "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def step(self, kind, i, j):
        return f"{self.base}missing{i}_{j}" if kind == "404" else f"{self.base}go{i}_{j}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def error_site():
    s = _ErrorSite()
    yield s
    s.close()


def _fetched(xhr, path) -> bool:
    return any(u.endswith(f"/x/{path}") for u in xhr)


def _spider_on(site, tmp_path, monkeypatch):
    from tests._browser import skip_or_fail

    from fuzzlab.tools import spider as sp
    _chromium_or_skip(monkeypatch)
    s = sp.LocalSpider(site.base, db_name=str(tmp_path / "s.db"), engine="playwright",
                       reveal=False, timeout_ms=10000)
    try:
        s._start_browser()
    except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
        s.storage.close()
        skip_or_fail(f"chromium could not launch: {exc}")
    return s


@pytest.mark.parametrize("order", sorted(_ORDERS))
def test_the_spiders_load_after_failed_loads_is_rendered(order, error_site, tmp_path,
                                                         monkeypatch):
    """BUG-0522: after failed loads (in each order), the next URL is rendered by the
    browser -- its script ran, its fetch is listed -- never the static fallback. Before:
    Chromium's late error page (or X1's late about:blank) overtook the next load (C0:
    17-18/20 lost; the r1 draft, which judged the error page by the current URL: 11-16/20
    after two or three 404s in a row). ``404-refused`` is not a pinning test (it passes
    on the old code too: the refused load absorbs the late navigation); it covers the
    mixed path."""
    s = _spider_on(error_site, tmp_path, monkeypatch)
    fallbacks = []
    real = s._fetch_static
    s._fetch_static = lambda url: (fallbacks.append(url), real(url))[1]
    try:
        for i in range(_REPS):
            for j, kind in enumerate(_ORDERS[order]):
                s._fetch_rendered(error_site.step(kind, i, j))
            fallbacks.clear()
            xhr = s._fetch_rendered(f"{error_site.base}ok{i}")[5]
            assert fallbacks == [], f"rep {i}: the next load fell back to a request"
            assert _fetched(xhr, f"ok{i}"), (i, xhr)
    finally:
        s._stop_browser()
        s.storage.close()


@pytest.mark.parametrize("order", sorted(_ORDERS))
def test_the_auditors_load_after_failed_loads_is_rendered(order, error_site,
                                                          monkeypatch):
    """BUG-0522's twin in `ContentFetcher.fetch` (one page for the whole audit).
    ``404-refused`` is not a pinning test (see the spider's)."""
    from fuzzlab.tools.fetcher import ContentFetcher
    _chromium_or_skip(monkeypatch)
    from tests._browser import skip_or_fail
    with ContentFetcher(engine="playwright", timeout_ms=10000) as f:
        fallbacks = []
        real = f._static_fetch
        f._static_fetch = lambda url: (fallbacks.append(url), real(url))[1]
        try:
            f.fetch(error_site.base + "warmup")
        except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
            skip_or_fail(f"chromium could not launch: {exc}")
        for i in range(_REPS):
            for j, kind in enumerate(_ORDERS[order]):
                f.fetch(error_site.step(kind, i, j))
            fallbacks.clear()
            xhr = f.fetch(f"{error_site.base}ok{i}")[3]
            assert fallbacks == [], f"rep {i}: the next load fell back to a request"
            assert _fetched(xhr, f"ok{i}"), (i, xhr)


def _guarded_page(pw, base):
    from fuzzlab.tools import navguard
    browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
        navguard.browser_launch_args([base])))
    ctx = browser.new_context()
    navguard.guard_page(ctx, in_scope=lambda u: u.startswith(base))
    return browser, ctx, ctx.new_page()


@pytest.mark.parametrize("failures", [1, 2, 3])
def test_a_failed_navigation_returns_after_its_own_error_page(failures, error_site,
                                                               monkeypatch):
    """SP-01's oracle (BUG-0522): each failed navigation to an empty error answer raises
    only after the main frame committed ITS OWN error page -- a commit a listener
    registered before that navigation saw -- and the cleanup then leaves that page
    (``"error-page"``, the page on ``chrome-error:``). A wait that took the page's current
    URL for the error page returns before the second failure's commit: no fresh commit
    is seen (failures 2 and 3 fail against that mutant, by assertion)."""
    from playwright.sync_api import Error, sync_playwright

    from fuzzlab.tools import navguard
    _chromium_or_skip(monkeypatch)
    with sync_playwright() as pw:
        browser, ctx, page = _guarded_page(pw, error_site.base)
        try:
            navguard.navigate(page, error_site.base + "start", timeout_ms=10000)
            for k in range(failures):
                seen: list[str] = []
                page.on("framenavigated", lambda fr, seen=seen: seen.append(fr.url)
                        if fr == page.main_frame else None)
                with pytest.raises(Error) as raised:
                    navguard.navigate(page, f"{error_site.base}missing{k}",
                                      timeout_ms=10000)
                fresh = [u for u in seen if u.startswith("chrome-error:")]
                assert fresh, f"failure {k + 1}: raised before its own error page"
                assert navguard.end_failed_load(page, raised.value,
                                                timeout_ms=10000) == "error-page"
                assert page.url.startswith("chrome-error:")
            navguard.navigate(page, error_site.base + "after", timeout_ms=10000,
                              wait_until="load")
            assert page.url == error_site.base + "after"
        finally:
            navguard.release(ctx)
            browser.close()


def test_a_navigation_overtaken_by_an_error_page_waits_for_it(error_site, monkeypatch):
    """"Interrupted by another navigation to chrome-error://": a raw failed ``goto`` (its
    error page still coming), then a guarded navigation the late error page overtakes.
    The overtaken navigation still lands (measured 30/30): the guarded one raises after
    that, the cleanup ends whatever shows, and the next navigation lands. The one
    overtaken load itself is lost (it raised)."""
    from playwright.sync_api import Error, sync_playwright

    from fuzzlab.tools import navguard
    _chromium_or_skip(monkeypatch)
    with sync_playwright() as pw:
        browser, ctx, page = _guarded_page(pw, error_site.base)
        try:
            navguard.navigate(page, error_site.base + "start", timeout_ms=10000)
            overtaken = 0
            for k in range(_REPS):
                with pytest.raises(Error):
                    page.goto(f"{error_site.base}missing{k}", wait_until="commit")
                try:
                    navguard.navigate(page, f"{error_site.base}ok{k}", timeout_ms=10000)
                except Error as exc:
                    overtaken += 1
                    assert "chrome-error:" in str(exc).splitlines()[0]
                    label = navguard.end_failed_load(page, exc, timeout_ms=10000)
                    assert (label == "blank" and page.url == "about:blank") or \
                        (label == "error-page" and page.url.startswith("chrome-error:")), \
                        (label, page.url)
                navguard.navigate(page, f"{error_site.base}next{k}", timeout_ms=10000,
                                  wait_until="load")
                assert page.url == f"{error_site.base}next{k}"
            assert overtaken, "not vacuous: an error page overtook a navigation"
        finally:
            navguard.release(ctx)
            browser.close()


@pytest.mark.parametrize("message,expected", [
    ("Page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE at http://h/a", "error-page"),
    ("Page.goto: net::ERR_CONNECTION_REFUSED at http://h/a", "error-page"),
    ("Page.reload: net::ERR_EMPTY_RESPONSE at http://h/a", "error-page"),
    ('Page.goto: Navigation to "http://h/a" is interrupted by another navigation to '
     '"chrome-error://chromewebdata/"', "overtaken"),
    ("Page.goto: net::ERR_ABORTED at http://h/a", None),
    # target-controlled text never decides (PA-0022): only the leading code does
    ("Page.goto: net::ERR_ABORTED at http://h/x/net::ERR_FAILED", None),
    ("Page.goto: net::ERR_ABORTED at http://h/x net::ERR_FAILED at y", None),
    ('Page.goto: Navigation to "http://h/chrome-error://x" is interrupted by another '
     'navigation to "about:blank"', None),
    ("Page.goto: Download is starting", None),
    ("Page.goto: Timeout 1500ms exceeded.", None),
])
def test_only_the_leading_code_decides_a_wait_for_an_error_page(message, expected):
    from fuzzlab.tools import navguard
    exc = Exception(message + "\nCall log:\n  - navigating to \"x\", waiting until")
    assert navguard._settles_on_error_page(exc) == expected


def test_a_refused_load_naming_a_network_error_in_its_url_is_not_waited_for(
        error_site, monkeypatch):
    """A refused load (ERR_ABORTED: the previous document is alive) of a URL that
    contains ``net::ERR_FAILED``: no wait for an error page (the counter is unchanged)
    and the cleanup leaves for about:blank at once. A classifier that read the whole
    message waited out its budget here (the r1 draft: 1 s a load)."""
    from playwright.sync_api import Error, sync_playwright

    from fuzzlab.tools import navguard
    _chromium_or_skip(monkeypatch)
    with sync_playwright() as pw:
        browser, ctx, page = _guarded_page(pw, error_site.base)
        try:
            navguard.navigate(page, error_site.base + "start", timeout_ms=10000)
            before = navguard.error_page_waits()["waited"]
            with pytest.raises(Error) as raised:
                navguard.navigate(page, error_site.base + "go/net::ERR_FAILED",
                                  timeout_ms=10000)
            assert str(raised.value).startswith("Page.goto: net::ERR_ABORTED at ")
            assert navguard.error_page_waits()["waited"] == before
            assert navguard.end_failed_load(page, raised.value,
                                            timeout_ms=10000) == "blank"
            assert page.url == "about:blank"
        finally:
            navguard.release(ctx)
            browser.close()


def test_an_error_page_ends_the_previous_document(error_site, tmp_path, monkeypatch):
    """X1 on the path BUG-0522 adds: when the failure settled on the browser's own error
    page, nothing more is navigated -- and the previous document (A, a 50 ms POST
    ticker) has ended all the same: no tick was sent after the static fallback started
    (judged by the send time each tick carries, PA-0511)."""
    s = _spider_on(error_site, tmp_path, monkeypatch)
    marks = {}
    real = s._fetch_static

    def fetch_static(url):
        marks[url] = (s._page.url, s._page.evaluate("Date.now()"))
        time.sleep(0.4)                           # time for a live document's ticker
        return real(url)
    s._fetch_static = fetch_static
    try:
        s._fetch_rendered(error_site.base)
        time.sleep(0.3)                            # A ticks
        s._fetch_rendered(error_site.base + "missing0")
    finally:
        s._stop_browser()
        s.storage.close()
    shown, ended = marks[error_site.base + "missing0"]
    assert shown.startswith("chrome-error:"), shown       # the error page, not blank
    assert _ticks_sent_after(error_site.bodies, ended) == []


def test_a_query_load_after_a_failed_load_is_rendered(error_site, tmp_path, monkeypatch):
    """The spider's window paths after a failed load (BUG-0522): the pre-seed
    about:blank (`_visit`) right after a failed load, then the seed's own load (no
    fallback) -- rendered; a seed whose own load gets an empty error answer -- its
    window's exit (`_leave`) does not raise and the next load is rendered. Before:
    15/20 seeds lost, `_leave` raised 8-20/20."""
    from fuzzlab.tools import spa
    s = _spider_on(error_site, tmp_path, monkeypatch)
    raised = []
    real_leave = s._leave

    def leave(*a, **k):
        try:
            return real_leave(*a, **k)
        except Exception:
            raised.append(1)
            raise
    s._leave = leave
    ok = {}
    real_fr = s._fetch_rendered

    def fetch_rendered(url, fallback=True):
        try:
            r = real_fr(url, fallback=fallback)
        except Exception:
            ok[url] = False
            raise
        ok[url] = bool(s._rendered_ok)
        return r
    s._fetch_rendered = fetch_rendered
    queue: list = []
    try:
        for i in range(_REPS):
            s._fetch_rendered(f"{error_site.base}missing{i}")
            # "route", not "seed": the destructive rule refuses a "seed" path
            route = f"{error_site.base}route{i}?q=x"
            s._visit(route, 1, spa.SEED_SOURCE, queue)
            assert ok.get(route), f"rep {i}: the query load after a failed load failed"
            s._visit(f"{error_site.base}missing-route{i}?q=x", 1, spa.SEED_SOURCE, queue)
            assert raised == [], f"rep {i}: the window's exit raised"
            s._fetch_rendered(f"{error_site.base}after{i}")
            assert ok.get(f"{error_site.base}after{i}"), i
    finally:
        s._stop_browser()
        s.storage.close()
