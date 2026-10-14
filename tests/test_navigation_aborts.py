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


class _Route:
    def __init__(self, url, *, navigation, method="GET", site=None, boom=False):
        self.request = type("Req", (), {
            "url": url, "method": method, "headers": {"content-type": "x/y"},
            "post_data_buffer": b"pw=1" if method == "POST" else None,
            "resource_type": "document" if navigation else "image",
            "is_navigation_request": lambda _s: navigation})()
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
@pytest.mark.parametrize("navigation,code", [(True, DOCUMENT_ABORT), (False, None)])
def test_every_abort_reason_keeps_the_document_for_a_navigation(reason, navigation,
                                                                code):
    """PA-0136: one rule for every reason -- a document request is aborted with
    ``"aborted"`` (the current document survives), a subresource with the default."""
    url, kw, route_kw = REASONS[reason]
    kw = {"in_scope": _in_scope, **kw}
    site = route_kw.get("site", {})
    route = _Route(url, navigation=navigation, **route_kw)
    make_route_handler(api=_Api(site), **kw)(route)
    assert (route.outcome, route.code) == ("abort", code), reason


def test_the_document_abort_code_is_err_aborted():
    assert DOCUMENT_ABORT == "aborted"


# --- real Chromium ------------------------------------------------------------------
class _Site:
    """A loopback server: ``pages`` maps a path to HTML; every request is recorded."""

    def __init__(self, host="127.0.0.1"):
        require_loopback(host)                    # PA-0130
        self.pages, self.requests = {}, []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                site.requests.append(self.path)
                body = site.pages.get(self.path.split("?", 1)[0],
                                      "<html><body>other</body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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


def _crawl_a_page_that_navigates_to(target_of, tmp_path, monkeypatch):
    """Crawl A, whose page navigates by script to ``target_of(a, b)`` 200 ms after
    load; return ``(spider, a, b, rows)``."""
    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a, b = _Site(), _Site()
    a.pages["/"] = (f"<html><body><p>A-OWN-CONTENT</p><a href='/next'>n</a><script>"
                    f"setTimeout(()=>location.href='{target_of(a, b)}',200)</script>"
                    f"</body></html>")
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
        b.close()
    rows = dict(sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall())
    return sp, a, b, rows


def test_a_script_navigation_out_of_scope_keeps_the_page_crawled(monkeypatch, tmp_path):
    """The scope guard (BUG-0123) refuses it; the page keeps its content and links,
    and the out-of-scope request is still recorded."""
    sp, a, b, rows = _crawl_a_page_that_navigates_to(lambda a, b: b.base + "away",
                                                     tmp_path, monkeypatch)
    assert "A-OWN-CONTENT" in (rows.get(a.base) or "")
    assert "/next" in a.requests                               # its link was crawled
    assert b.requests == []                                    # nothing left scope
    assert sp.skipped_out_of_scope.get("127.0.0.1", 0) >= 1    # the reason, recorded


def test_a_script_navigation_to_a_destructive_url_keeps_the_page_crawled(monkeypatch,
                                                                       tmp_path):
    """The destructive rule (BUG-0111) refuses it; the page keeps its content and
    links, and the refusal is still recorded."""
    sp, a, _b, rows = _crawl_a_page_that_navigates_to(lambda a, b: a.base + "logout.php",
                                                      tmp_path, monkeypatch)
    assert "A-OWN-CONTENT" in (rows.get(a.base) or "")
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
