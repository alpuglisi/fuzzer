"""BUG-0670 / PA-0670: an empty HTTP error answer fails a guarded navigation onto the
browser's error page on every Chromium binary.

The full Chromium fails a navigation whose answer is HTTP 400-599 with an empty body
itself (``net::ERR_HTTP_RESPONSE_CODE_FAILURE``, its error page committed after ``goto``
raised); the headless shell 157.0.8103.78 -- the binary Playwright launches by default,
so the product's -- loads that answer as an empty page (measured:
`tests/test_chromium_navigation_outcomes.py`). SP-01's error-page path (BUG-0522,
BUG-0561) and every caller's fallback were measured on the full browser only, so on the
default binary a guarded crawl or audit took an empty 404 for a rendered page, and the
outcome of one target depended on the binary. Now `navguard`'s route handler aborts such
a navigation with `ERROR_ANSWER_ABORT` (ERR_FAILED, error page) on every binary, after
its observer saw the answer; any other answer is given as it was.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.tools.navguard import ERROR_ANSWER_ABORT, make_route_handler

H = "http://127.0.0.1:8080"


# --- the route handler (unit) --------------------------------------------------------
class _Resp:
    def __init__(self, status=200, body=b"", location=None, boom=False):
        self.status, self._body, self._boom = status, body, boom
        self.headers = {"location": location} if location else {}

    def body(self):
        if self._boom:
            raise RuntimeError("disposed")
        return self._body


class _Frame:
    def __init__(self, parent=None):
        self.parent_frame = parent


class _Route:
    def __init__(self, url, *, navigation=True, frame=None, rtype=None, site=None):
        self.request = type("Req", (), {
            "url": url, "method": "GET", "headers": {}, "post_data_buffer": None,
            "resource_type": rtype or ("document" if navigation else "image"),
            "frame": frame or _Frame(),
            "is_navigation_request": lambda _r: navigation})()
        self.site = site or {}
        self.calls: list = []

    def fetch(self, max_redirects=None, headers=None):
        return self.site[self.request.url]

    def abort(self, code=None):
        self.calls.append(("abort", code))

    def continue_(self):
        self.calls.append(("continue",))

    def fulfill(self, response=None, status=None, headers=None, body=None, **_kw):
        self.calls.append(("fulfill", status if response is None else response.status))


class _Api:
    def __init__(self, site):
        self.site = site

    def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
        return self.site[url]


def _handle(route, site=None, observed=None):
    def observe(req, resp):
        if observed is not None:
            observed.append((req.url, resp.status))
    make_route_handler(api=_Api(site or route.site), observe=observe,
                       in_scope=lambda u: in_origin_scope(u, origin_scope(H + "/")))(route)
    return route.calls


#: answer -> what the handler does with a top-level navigation that gets it
CASES = {
    "404 empty": (_Resp(404), [("abort", ERROR_ANSWER_ABORT)]),
    "400 empty": (_Resp(400), [("abort", ERROR_ANSWER_ABORT)]),
    "500 empty": (_Resp(500), [("abort", ERROR_ANSWER_ABORT)]),
    "599 empty": (_Resp(599), [("abort", ERROR_ANSWER_ABORT)]),
    # measured on the full Chromium: these load as a page there, so here too
    "399 empty": (_Resp(399), [("fulfill", 399)]),
    "404 one byte": (_Resp(404, b" "), [("fulfill", 404)]),
    "200 empty": (_Resp(200), [("fulfill", 200)]),
    "600 empty": (_Resp(600), [("fulfill", 600)]),
    # an answer that cannot say what its body is is given as it is
    "404 body unreadable": (_Resp(404, boom=True), [("fulfill", 404)]),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_an_empty_error_answer_fails_the_navigation_and_nothing_else_does(case):
    answer, expected = CASES[case]
    url = f"{H}/p"
    observed: list = []
    assert _handle(_Route(url, site={url: answer}), observed=observed) == expected
    assert observed == [(url, answer.status)], "the observer sees every answer first"


def test_an_iframes_empty_error_answer_is_given_as_it_is():
    """Both binaries load a frame's empty 404 as a page (measured:
    `tests/test_chromium_navigation_outcomes.py` ``FRAME_404``): the full browser's
    rule is a main-frame rule, so the guard changes nothing for a frame."""
    url = f"{H}/f"
    route = _Route(url, frame=_Frame(parent=_Frame()), site={url: _Resp(404)})
    assert _handle(route) == [("fulfill", 404)]


def test_a_subresources_empty_error_answer_is_given_as_it_is():
    url = f"{H}/i.png"
    route = _Route(url, navigation=False, site={url: _Resp(404)})
    assert _handle(route) == [("fulfill", 404)]


def test_a_redirect_landing_on_an_empty_error_answer_fails_the_navigation():
    """The landing a checked redirect chain reaches is the navigation's answer: an empty
    error there fails the navigation instead of a redirect to it the browser would
    re-request through the enforcer (and, on the headless shell, load as a page)."""
    url, land = f"{H}/go", f"{H}/land"
    site = {url: _Resp(302, location="/land"), land: _Resp(404)}
    assert _handle(_Route(url, site=site), site=site) == [("abort", ERROR_ANSWER_ABORT)]


def test_a_redirect_landing_on_a_page_is_still_relanded():
    url, land = f"{H}/go", f"{H}/land"
    site = {url: _Resp(302, location="/land"), land: _Resp(200, b"<p>x</p>")}
    assert _handle(_Route(url, site=site), site=site) == [("fulfill", 302)]


def test_the_error_answer_code_commits_the_error_page():
    """ERR_FAILED (measured: the error page commits after ``goto`` raised), never
    ERR_ABORTED (the document kept; BUG-0136's code for a refusal)."""
    assert ERROR_ANSWER_ABORT == "failed"


# --- real Chromium, every binary -------------------------------------------------------
class _Site:
    """``/e<status>``: that status, empty body; ``/b404``: 404 with a one-byte body;
    ``/r<status>``: 302 to ``/e<status>``; anything else: a page whose script sets the
    title to ``ran``."""

    def __init__(self):
        require_loopback("127.0.0.1")              # PA-0130

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                if path[:2] == "/e" and path[2:5].isdigit():
                    return self._send(int(path[2:5]))
                if path[:2] == "/r" and path[2:5].isdigit():
                    return self._send(302, headers=[("Location", f"/e{path[2:5]}")])
                if path == "/b404":
                    return self._send(404, b" ")
                return self._send(200, b"<html><body>ok<script>document.title='ran'"
                                       b"</script></body></html>",
                                  [("Content-Type", "text/html")])

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = _Site()
    yield s
    s.close()


@pytest.mark.parametrize("binary", ["shell", "full"])
def test_a_guarded_empty_error_answer_settles_on_the_error_page_on_every_binary(
        binary, site):
    """On the headless shell (which loads the answer itself) and on the full browser
    (which fails it itself) alike: ``navigate`` raises ERR_FAILED only after the error
    page committed (SP-01), the cleanup leaves that page, the next navigation lands and
    its script runs; a redirect landing on such an answer does the same; a one-byte 404
    is a page on both."""
    from playwright.sync_api import Error, sync_playwright
    from tests._browser import guarded_chromium

    from fuzzlab.tools import navguard
    with sync_playwright() as pw:
        browser, ctx, page = guarded_chromium(pw, binary, site.base)
        try:
            navguard.navigate(page, site.base + "start", timeout_ms=10000,
                              wait_until="load")
            for k, path in enumerate(["e404", "e500", "r404", "e403"]):
                seen: list[str] = []
                page.on("framenavigated", lambda fr, seen=seen: seen.append(fr.url)
                        if fr == page.main_frame else None)
                with pytest.raises(Error) as raised:
                    navguard.navigate(page, site.base + path, timeout_ms=10000)
                assert str(raised.value).startswith("Page.goto: net::ERR_FAILED at "), \
                    (path, str(raised.value).splitlines()[0])
                assert any(u.startswith("chrome-error:") for u in seen), path
                assert navguard.end_failed_load(page, raised.value,
                                                timeout_ms=10000) == "error-page"
                nav = navguard.navigate(page, f"{site.base}after{k}", timeout_ms=10000,
                                        wait_until="load")
                assert nav.reached and page.url == f"{site.base}after{k}"
                assert page.title() == "ran"
            got = navguard.navigate(page, site.base + "b404", timeout_ms=10000)
            assert got.response is not None and got.response.status == 404
            assert page.url == site.base + "b404"
        finally:
            navguard.release(ctx)
            browser.close()
