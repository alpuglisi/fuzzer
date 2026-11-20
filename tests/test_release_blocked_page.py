"""BUG-0672 / PA-0672: releasing a guarded context never hangs on a page whose main
thread is blocked.

`navguard.close_pages` freezes every page first (``Emulation.setScriptExecutionDisabled``,
BUG-0504) and `release` then adds a refusing route on the context. Neither call returns
while a page's renderer is stuck in ``while(true){}`` -- measured on the headless shell
and the full Chromium (`tests/test_chromium_navigation_outcomes.py`
``test_a_blocked_main_thread_answers_only_the_browsers_own_calls``) -- so the M6 executor,
the spider and disco hung forever in teardown on such a target (found by an
independent verifier at d492b9d). Now each such call is bounded by
`navguard.RELEASE_CALL_MS`, counted (`release_expiries`) and logged; a page that did
not answer its freeze is closed after the drain and before the refusing route.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core.net import require_loopback

#: blocks its main thread forever 50 ms after load
BLOCKED = (b"<html><body>blocked<script>addEventListener('load',()=>setTimeout(()=>"
           b"{while(true){}},50))</script></body></html>")
#: navigates to a refused URL every 20 ms (BUG-0504's teardown race)
TICKER = (b"<html><body>ticker<script>setInterval(()=>{location.href='/logout.php?'"
          b"+Date.now()},20)</script></body></html>")


class _Site:
    def __init__(self):
        require_loopback("127.0.0.1")              # PA-0130
        self.paths: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                site.paths.append(self.path)
                body = TICKER if self.path.startswith("/ticker") else BLOCKED
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
def test_release_of_a_blocked_page_is_bounded_counted_and_refuses_the_rest(binary, site):
    """A blocked page and a page whose timer keeps navigating to a refused URL, in one
    guarded context: `release` returns within its bound, counts the blocked page's
    freeze, adds the refusing route in time (the blocked page is closed first), closes
    both, and the refused URL never reaches the server (BUG-0504 still holds)."""
    from playwright.sync_api import sync_playwright
    from tests._browser import guarded_chromium

    from fuzzlab.tools import navguard
    with sync_playwright() as pw:
        browser, ctx, blocked = guarded_chromium(pw, binary, site.base)
        try:
            navguard.navigate(blocked, site.base + "blocked", timeout_ms=10000,
                              wait_until="load")
            ticker = ctx.new_page()
            navguard.navigate(ticker, site.base + "ticker", timeout_ms=10000,
                              wait_until="load")
            blocked.wait_for_timeout(300)                 # the loop has started
            before = navguard.release_expiries()
            t = time.monotonic()
            navguard.release(ctx)
            took = time.monotonic() - t
            after = navguard.release_expiries()
            assert took < (navguard.RELEASE_CALL_MS + 3000) / 1000, took
            assert after["freeze"] == before["freeze"] + 1
            assert after["route"] == before["route"]
            assert blocked.is_closed() and ticker.is_closed()
            assert not any(p.startswith("/logout.php") for p in site.paths), site.paths
            ctx.close()
        finally:
            browser.close()


def test_a_healthy_release_counts_nothing(site):
    from playwright.sync_api import sync_playwright
    from tests._browser import guarded_chromium

    from fuzzlab.tools import navguard
    with sync_playwright() as pw:
        browser, ctx, page = guarded_chromium(pw, "shell", site.base)
        try:
            navguard.navigate(page, site.base + "ticker", timeout_ms=10000,
                              wait_until="load")
            before = navguard.release_expiries()
            navguard.release(ctx)
            assert navguard.release_expiries() == before
            assert page.is_closed()
        finally:
            browser.close()


def test_the_m6_executor_returns_on_a_page_that_blocks_its_main_thread(site,
                                                                      monkeypatch):
    """The verifier's path: `PlaywrightBrowserExecutor.run` on a page that blocks its
    main thread after load returns (here its "loaded, no hit" verdict) within its
    timeout plus the release bound, where d492b9d never returned."""
    from tests._browser import skip_or_fail

    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.oracle.probe import UnplaceableLocation
    from fuzzlab.oracle.strategies import _xss_exec_payloads
    from fuzzlab.tools import navguard
    from fuzzlab.tools.browserexec import NotObserved, PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=5000)
    before = navguard.release_expiries()["freeze"]
    t = time.monotonic()
    try:
        executor.run(ExecRequest(url=site.base + "blocked", param="q",
                                 value=_xss_exec_payloads("tk672")[0]), "tk672")
    except NotObserved:                   # a subclass of UnplaceableLocation: first
        pass
    except UnplaceableLocation as exc:
        skip_or_fail(f"chromium could not launch: {exc}")
    assert time.monotonic() - t < (5000 + executor.SETTLE_MS +
                                   navguard.RELEASE_CALL_MS + 5000) / 1000
    assert navguard.release_expiries()["freeze"] == before + 1
