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
    # D72: a destructive URL is refused for a write only (a GET goes through)
    "destructive": (f"{H}/logout.php", {}, {"method": "POST"}),
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
    # a 307 keeps the POST, so the hop is a write to a destructive URL (D72)
    "hop destructive": (f"{H}/go", {}, {"method": "POST",
                                        "site": {f"{H}/go": _Resp(307, "/logout.php")}}),
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
    ``log`` as ``(method, path)``."""

    def __init__(self, host="127.0.0.1"):
        require_loopback(host)                    # PA-0130
        self.pages, self.redirects, self.delays = {}, {}, {}
        self.requests, self.posts, self.log = [], [], []
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
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
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


def test_a_script_navigation_to_a_destructive_url_is_a_visit(monkeypatch, tmp_path):
    """D72 (owner, 2026-10-16): a page's script navigation to a destructive-looking GET
    is not refused (it was, BUG-0111): the navigation's target is requested, and --
    like any same-origin script navigation -- the crawl reads the page it landed on, so
    the start page's row holds the landed page's text (a stated consequence of D72);
    nothing is recorded as refused."""
    sp, a, _b, rows = _crawl_a_page_that_navigates_to(lambda a, b: a.base + "logout.php",
                                                      tmp_path, monkeypatch)
    assert a.base in rows and a.base + "logout.php" in rows
    assert "/logout.php" in a.requests
    assert sp.skipped_destructive == {}


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
                for refused in (b.base + "x", b.base + "logout.php"):
                    with pytest.raises(PlaywrightError, match="ERR_ABORTED"):
                        page.goto(refused, wait_until="load")
                    assert page.url == a.base and "A-OWN-CONTENT" in page.content()
                page.goto(a.base + "logout.php", wait_until="load")   # D72: a visit
                release(ctx)
                ctx.close()
            finally:
                browser.close()
    finally:
        a.close()
        b.close()
    assert b.requests == [] and "/logout.php" in a.requests


# --- review of BUG-0136 (D50) -------------------------------------------------------
#: What the crawl still refuses for a GET (a redirect, an iframe): another origin. D72
#: removed the destructive GET rule, so it is not a refusal reason for these.
_REFUSED = {
    "out of scope": lambda a, b: b.base + "away",
}
#: ... and for a write (a POST form submission): also a destructive URL.
_REFUSED_WRITE = {**_REFUSED, "destructive": lambda a, b: "/logout.php"}


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
            try:
                return real(url)
            except Exception as exc:
                raised[url] = (str(exc).splitlines()[0], sp._page.url,
                               "A-OWN-CONTENT" in sp._page.content())
                raise
        sp._goto_and_parse = goto_and_parse
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build, hook)
    error, shown, kept = raised[a.base + "go"]
    assert "ERR_ABORTED" in error
    assert shown == a.base and kept                            # the page stayed
    assert rows[a.base + "go"][0] == 302                       # via the static fallback
    _nothing_refused_was_sent(where, sp, a, b)


@pytest.mark.parametrize("where", sorted(_REFUSED_WRITE))
def test_a_refused_post_form_submission_keeps_the_page_crawled(where, monkeypatch,
                                                               tmp_path):
    """X4 (A-S2): a page's script submits a POST form to a refused URL: the
    navigation is aborted, nothing is posted, and the page keeps its content and its
    links."""
    def build(a, b):
        a.pages["/"] = (f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a>"
                        f"<form method='post' action='{_REFUSED_WRITE[where](a, b)}'>"
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


def test_a_failed_load_ends_the_previous_document(monkeypatch, tmp_path):
    """X1 (B-M1): after a refused `goto` the previous page is still alive; its timers
    and fetches would be filed under the URLs crawled next. The failed load sends the
    page to ``about:blank`` before the fallback: A's 50 ms POST ticker stops there, so
    the server sees no tick once the fallback's own request is sent, and nothing is
    captured but what A sent before it ended (whereas before, the
    ticks queued during the fallback were sent and captured under /next, the next URL
    crawled)."""
    import time
    marks = {}

    def build(a, b):
        a.pages["/"] = (
            "<html><body><p>A-OWN-CONTENT</p><a href='/go'>g</a><a href='/next'>n</a>"
            "<script>let n = 0; setInterval(() => fetch('/tick', {method: 'POST', "
            "headers: {'content-type': 'application/json'}, "
            "body: JSON.stringify({['k' + (n++)]: 1})}), 50)</script></body></html>")
        a.redirects["/go"] = b.base + "away"            # refused: another origin (D72)

    def hook(sp, a, b):
        real = sp._fetch_static

        def fetch_static(url):
            # what the page shows, what the server saw and what was captured, when the
            # fallback starts; then time for a live document's ticker to run
            captured = sp.storage.cursor.execute(
                "SELECT COALESCE(MAX(id), 0) FROM discovered_requests").fetchone()[0]
            marks[url] = (sp._page.url, len(a.log), captured)
            time.sleep(0.4)
            return real(url)
        sp._fetch_static = fetch_static
    sp, a, b, rows = _crawl(tmp_path, monkeypatch, build, hook, timeout_ms=3000)
    shown, seen, captured = marks[a.base + "go"]
    db = sqlite3.connect(str(tmp_path / "s.db"))
    ticks = db.execute("SELECT id, page_url FROM discovered_requests "
                       "WHERE url LIKE '%/tick%'").fetchall()
    assert any(page == a.base for _id, page in ticks)          # the ticker was captured
    assert shown == "about:blank"                              # the failed load ended A
    # the fallback's own GET /go was sent 400 ms after A ended: no tick after it. A
    # tick A sent before it ended may still be in flight then (it reaches the server
    # or is captured just after the mark); every captured tick is one the server got
    # before the fallback's request, so none was sent by a document left alive
    fallback = a.log.index(("GET", "/go"), seen)
    assert ("POST", "/tick") not in a.log[fallback:]
    assert a.log[seen:fallback].count(("POST", "/tick")) <= 2
    late = [i for i, _page in ticks if i > captured]
    assert len(late) <= 2
    assert len(ticks) <= a.log[:fallback].count(("POST", "/tick"))
    assert "/next" in a.requests and b.requests == []


_TICKER = ("<script>let n = 0; setInterval(() => fetch('/tick', {method: 'POST', "
           "headers: {'content-type': 'application/json'}, "
           "body: JSON.stringify({['k' + (n++)]: 1})}), 50)</script>")


def test_the_auditors_failed_load_ends_the_previous_document(monkeypatch):
    """X1's twin in the auditor (CC-AUD-0042): `ContentFetcher.fetch` keeps one page
    for the whole audit. After a refused `goto` (/go redirects to another origin; to
    /logout.php before D72) it sends
    the page to ``about:blank`` before the static fallback: A's ticker stops there, so
    the server sees no tick once the fallback's own request is sent, and the next
    URL's XHR list holds none of A's ticks (before, the ticks queued during the
    fallback were listed under the next URL)."""
    import time

    from tests._browser import skip_or_fail
    from fuzzlab.tools.fetcher import ContentFetcher
    _chromium_or_skip(monkeypatch)
    a, b = _Site(), _Site()
    a.pages["/"] = f"<html><body><p>A-OWN-CONTENT</p>{_TICKER}</body></html>"
    a.redirects["/go"] = b.base + "away"                # refused: another origin (D72)
    marks = {}
    try:
        with ContentFetcher(engine="playwright", timeout_ms=3000) as fetcher:
            real = fetcher._static_fetch

            def static_fetch(url):
                marks[url] = (fetcher._page.url, len(a.log))
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
        b.close()
    shown, seen = marks[a.base + "go"]
    assert shown == "about:blank"                              # the failed load ended A
    fallback = a.log.index(("GET", "/go"), seen)
    assert ("POST", "/tick") not in a.log[fallback:]           # no tick after that
    assert not any("/tick" in url for url in next_xhr)         # none filed under /next
    assert b.requests == []


# --- the M6 executor (X2, B-S1) -----------------------------------------------------
def _m6_site():
    """The M6 test site and the other origin its pages navigate to. The executor's scope
    is the observe URL's origin, so every navigation to ``away`` is refused there -- a
    request reaching ``away`` is an escape from origin containment (QUALITY_POLICY §9).
    Before D72 the target was this site's ``/logout.php``, refused as destructive."""
    from fuzzlab.oracle.browser import SENTINEL
    site, away = _Site(), _Site()
    target = away.base + "logout.php"
    site.pages["/fire"] = (f"<html><body><script>window.{SENTINEL}('tok');"
                           f"setTimeout(() => location.href = '{target}', 50)"
                           f"</script></body></html>")
    # the page navigates away once loaded, before (and instead of) any payload
    site.pages["/early"] = ("<html><body><p>escaped</p><script>"
                            "window.addEventListener('load', () => "
                            f"location.href = '{target}')</script></body></html>")
    # the page navigates away once loaded; its sink fires 300 ms later
    site.pages["/late"] = (f"<html><body><script>"
                           f"window.addEventListener('load', () => "
                           f"location.href = '{target}');"
                           f"setTimeout(() => window.{SENTINEL}('tok'), 300)"
                           f"</script></body></html>")
    site.redirects["/redir"] = target
    site.away = away
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
    """(a): the sentinel fires, then the page navigates to another origin (refused):
    executed, and the other origin is never requested."""
    _chromium_or_skip(monkeypatch)
    site = _m6_site()
    try:
        assert _m6_run(site, "/fire").executed is True
    finally:
        site.close()
        site.away.close()
    assert site.away.requests == []                     # nothing left the origin


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
        site.away.close()
    assert site.away.requests == []                     # nothing left the origin


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
        site.away.close()
    assert site.away.requests == []                     # nothing left the origin


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
        site.away.close()
    assert "PAYLOAD-MARK" not in str(err.value) and site.base not in str(err.value)
    assert site.away.requests == []                     # nothing left the origin
