"""Network quiet (`fuzzlab.tools.netquiet`, SP-40): a settle waits for the app's own
requests, never for a long-lived one (a long-poll, an event stream).

Unit cases on a fake clock, then a real browser: a page holding a long-poll open while
an ordinary 800 ms XHR renders its result. The crawler's `_settle`, disco's
`wait_quiet` and browser login's `_settle` each wait for the XHR and stop soon after,
instead of running to their budget (measured before: `_settle` 64% of the crawler's
self time on Juice Shop, CC-CRAWL-0037)."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.tools import netquiet
from fuzzlab.tools.netquiet import Inflight


class _Req:
    def __init__(self, rtype="fetch"):
        self.resource_type = rtype


def test_a_request_counts_until_it_ends_or_turns_long_lived():
    clock = {"t": 0.0}
    net = Inflight(clock=lambda: clock["t"], long_lived_ms=2000)
    a, b = _Req(), _Req("xhr")
    assert net.started(a) and net.started(b) and net.n == 2
    clock["t"] = 0.5
    assert net.ended(b) and net.n == 1 and net.last_change == 0.5
    clock["t"] = 2.1                                   # `a` is a long-poll now
    assert net.n == 0 and net.long_lived == 1
    assert net.ended(a) is False and net.last_change == 0.5   # its answer: no activity


def test_event_streams_and_websockets_are_never_waited_for():
    net = Inflight(clock=lambda: 0.0)
    for rtype in netquiet.STREAMING_TYPES:
        assert net.started(_Req(rtype)) is False
    assert net.n == 0


def test_an_unknown_end_changes_nothing():
    net = Inflight(clock=lambda: 1.0)
    before = net.last_change
    assert net.ended(_Req()) is False and net.last_change == before


# --- real browser ---------------------------------------------------------------------
_PAGE = b"""<!doctype html><html><body><p id=out>waiting</p><script>
fetch('/poll').catch(() => {});
setTimeout(() => fetch('/slow').then(r => r.text())
  .then(t => { document.getElementById('out').textContent = t; }), 100);
</script></body></html>"""


class _Site:
    """``/`` (the page), ``/poll`` (held open until the site closes, as a long-poll),
    ``/slow`` (answered after 800 ms)."""

    def __init__(self):
        self.release = threading.Event()
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/poll":
                    site.release.wait(30)
                    body, ctype = b"{}", "application/json"
                elif self.path == "/slow":
                    time.sleep(0.8)
                    body, ctype = b"RENDERED", "text/plain"
                else:
                    body, ctype = _PAGE, "text/html"
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def browser_page(monkeypatch):
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright

    from tests._browser import launch_browser_or_skip
    site = _Site()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                yield site, browser
            finally:
                browser.close()
    finally:
        site.close()


def _load(browser, site, attach):
    page = browser.new_page()
    attach(page)                                  # before the load, as the tools do
    page.goto(site.url, wait_until="load")
    return page


def _timed(fn):
    t0 = time.monotonic()
    fn()
    return time.monotonic() - t0


def test_the_crawlers_settle_waits_for_the_xhr_not_the_long_poll(browser_page, tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    site, browser = browser_page
    sp = LocalSpider(site.url, db_name=str(tmp_path / "s.db"), engine="playwright")
    try:
        page = _load(browser, site, sp._track)
        took = _timed(lambda: sp._settle(page, budget_ms=8000))
        assert page.text_content("#out") == "RENDERED"        # the XHR was waited for
        assert took < 4.0, took                               # not the 8 s budget
    finally:
        sp.storage.close()


def test_discos_quiet_waits_for_the_xhr_not_the_long_poll(browser_page):
    from fuzzlab.disco.explore import ExploreOptions, Explorer
    site, browser = browser_page
    ex = Explorer(site.url, scope_urls=[site.url], proxy="127.0.0.1:2",
                  options=ExploreOptions(max_quiet_ms=8000))

    def attach(page):
        page.on("request", ex._on_request)
        page.on("requestfinished", ex._on_done)
        page.on("requestfailed", ex._on_done)
    page = _load(browser, site, attach)
    ex.mark_activity()
    took = _timed(lambda: ex.wait_quiet(page))
    assert page.text_content("#out") == "RENDERED"
    assert took < 4.0, took


def test_browser_logins_settle_waits_for_the_xhr_not_the_long_poll(browser_page):
    from fuzzlab.session import browserlogin
    site, browser = browser_page
    holder = {}
    page = _load(browser, site, lambda p: holder.setdefault("n", Inflight(p)))
    took = _timed(lambda: browserlogin._settle(page, holder["n"], 8000))
    assert page.text_content("#out") == "RENDERED"
    assert took < 4.0, took


# --- SP-40: one implementation --------------------------------------------------------
def inflight_offenders(sources: dict[str, str]) -> list[str]:
    """Modules other than netquiet that define their own in-flight counter (a class or
    function whose name contains ``inflight``)."""
    import ast
    out = []
    for rel, src in sources.items():
        if rel.endswith("tools/netquiet.py"):
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and \
                    "inflight" in node.name.lower():
                out.append(f"{rel}:{node.name}")
    return out


def test_every_settle_counts_through_the_one_tracker():
    """SP-40: the crawler, disco and browser login count requests through
    `netquiet.Inflight` and nothing else defines a counter. Proven on a synthetic
    offender."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    sources = {str(p.relative_to(root)): p.read_text(encoding="utf-8")
               for p in (root / "fuzzlab").rglob("*.py") if "__pycache__" not in p.parts}
    assert inflight_offenders(sources) == []
    for rel in ("fuzzlab/tools/spider.py", "fuzzlab/disco/explore.py",
                "fuzzlab/session/browserlogin.py"):
        assert "netquiet import Inflight" in sources[rel], rel
    bad = {"fuzzlab/x.py": "class _Inflight:\n    pass\n"}
    assert inflight_offenders(bad) == ["fuzzlab/x.py:_Inflight"]
