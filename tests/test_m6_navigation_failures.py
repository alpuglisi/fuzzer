"""BUG-0137 / PA-0137: a page the M6 executor could not load is no verdict, never the end
of the run.

An exception from `PlaywrightBrowserExecutor.run` reached neither a containment in the
oracle nor in `harness/pipeline._confirm`, so one observe or plant `goto` that timed out
or failed ended confirmation for every remaining candidate. BUG-0136 added a trigger:
a page that navigates by script to a refused URL before ``load`` made `goto` wait out
its 8 s timeout and raise.

Now the observe navigation waits for the commit, then for ``load`` for at most
`LOAD_WAIT_MS`. A Playwright error or timeout of the plant or observe navigation, or a
page that never reached ``load``, with no hit, is `UnplaceableLocation` (no verdict, the
BUG-0126 path); a hit recorded at any point is executed=True. Only Playwright errors are
caught (PA-0106).
"""

from __future__ import annotations

import sys
import time
import types

import pytest

from fuzzlab.oracle.browser import SENTINEL, ExecRequest
from fuzzlab.oracle.probe import Probe, UnplaceableLocation
from tests.test_navigation_aborts import _chromium_or_skip, _m6_run, _Site

_NAV = "location.href = '/logout.php'"


def _site():
    site = _Site()
    # navigates by script to a refused URL while it is being parsed (before `load`)
    site.pages["/inline"] = f"<html><body><script>{_NAV}</script><p>x</p></body></html>"
    # the same, and its sink fires 300 ms later
    site.pages["/inline-fire"] = (f"<html><body><script>{_NAV}; setTimeout(() => "
                                  f"window.{SENTINEL}('tok'), 300)</script></body></html>")
    # a DOM XSS sink: the `q` parameter is written into the page
    site.pages["/dom"] = ("<html><body><div id=o></div><script>document.getElementById"
                          "('o').innerHTML = new URLSearchParams(location.search)"
                          ".get('q') || ''</script></body></html>")
    site.redirects["/redir"] = "/logout.php"
    return site


def test_a_before_load_navigation_is_no_verdict_well_under_the_timeout(monkeypatch):
    """The load a refused navigation superseded is not waited out (it was the full
    8 s, then a raise): the run ends after the bounded load wait and the sentinel wait,
    with no verdict -- not a negative, not a Playwright error."""
    _chromium_or_skip(monkeypatch)
    site = _site()
    try:
        started = time.monotonic()
        with pytest.raises(UnplaceableLocation) as err:
            _m6_run(site, "/inline", settle_ms=500)
        took = time.monotonic() - started
    finally:
        site.close()
    assert took < 6.5, f"{took:.1f}s: the superseded load was waited out"
    assert "did not finish loading" in str(err.value)
    assert "/logout.php" not in site.requests


def test_a_hit_after_a_before_load_navigation_counts(monkeypatch):
    """A hit recorded at any point is executed=True, even when the page never loads."""
    _chromium_or_skip(monkeypatch)
    site = _site()
    try:
        assert _m6_run(site, "/inline-fire", settle_ms=1500).executed is True
    finally:
        site.close()


class _QuietSender:
    """The non-browser mechanisms' sender: nothing is reflected."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        return Probe(200, "<html><body>ok</body></html>")


def test_a_page_that_cannot_load_never_ends_the_pipeline(monkeypatch, tmp_path):
    """Two DOM-XSS candidates in one pipeline run: the first one's own redirect is
    refused (its `goto` fails), the second is a real DOM sink. The first is no verdict
    from M6, and the run goes on: the second is still confirmed."""
    from tests._browser import skip_or_fail
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.core.runmode import resolve_run
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _chromium_or_skip(monkeypatch)
    site = _site()
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = 1500
    points = [InjectionPoint(url=site.base + "redir", param="q"),
              InjectionPoint(url=site.base + "dom", param="q")]
    try:
        with Store(tmp_path / "u.db") as store:
            run = store.start_run("auto", "h")
            plan = resolve_run("manual", selected_categories=["xss"],
                               all_categories=["xss"])
            run_pipeline(points, store, run, _QuietSender(), plan, browser=executor)
            if executor._unavailable is not None:
                skip_or_fail(f"chromium could not launch: {executor._unavailable}")
            found = {(r["url"], r["vuln_class"]) for r in store.conn.execute(
                "SELECT url, vuln_class FROM finding WHERE run_id=?", (run,))}
            statuses = {r["status"] for r in store.conn.execute(
                "SELECT oracle_status status FROM candidate WHERE run_id=?", (run,))}
    finally:
        site.close()
    assert any(url.endswith("/dom") and vc == "xss-dom" for url, vc in found)
    assert not any(url.endswith("/redir") for url, _vc in found)
    assert "pending" not in statuses                  # every candidate was reached
    assert "/logout.php" not in site.requests


# --- only Playwright errors are no verdict (PA-0106) ------------------------------
class _FakeError(Exception):
    pass


def _fake_playwright(monkeypatch, goto):
    class Page:
        def on(self, *a):
            pass

        def goto(self, url, **kw):
            goto(url, **kw)

        def wait_for_load_state(self, state, **kw):
            pass

        def wait_for_timeout(self, ms):
            pass

    class Context:
        request = types.SimpleNamespace(post=lambda *a, **k: None)

        def expose_binding(self, name, fn):
            pass

        def route(self, pattern, handler):
            pass

        def route_web_socket(self, pattern, handler):
            pass

        def new_page(self):
            return Page()

        def unroute_all(self, **kw):
            pass

        pages: list = []

    class Browser:
        def new_context(self, **kw):
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
    fake.Error = _FakeError
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)


def _run():
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor()
    executor.SETTLE_MS = 0
    return executor.run(ExecRequest(url="http://127.0.0.1:3000/x", param="q",
                                    value="PAYLOAD-MARK"), "tok")


def test_a_playwright_error_is_no_verdict_and_names_no_url(monkeypatch):
    def goto(url, **kw):
        raise _FakeError(f"Page.goto: net::ERR_ABORTED at {url}\nCall log: ...")
    _fake_playwright(monkeypatch, goto)
    with pytest.raises(UnplaceableLocation, match="ERR_ABORTED") as err:
        _run()
    assert "PAYLOAD-MARK" not in str(err.value) and "127.0.0.1" not in str(err.value)


def test_any_other_error_is_not_swallowed(monkeypatch):
    """PA-0106: a defect (not a Playwright error) propagates; it is never turned into
    a quiet no-verdict."""
    def goto(url, **kw):
        raise KeyError("a defect")
    _fake_playwright(monkeypatch, goto)
    with pytest.raises(KeyError):
        _run()
