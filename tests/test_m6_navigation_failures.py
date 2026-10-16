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

from fuzzlab.oracle.browser import SENTINEL, ExecRequest, NotObserved
from fuzzlab.oracle.probe import Probe, UnplaceableLocation
from fuzzlab.oracle.strategies import _xss_exec_payloads
from tests.test_navigation_aborts import _chromium_or_skip, _m6_run, _Site

def _site():
    """The test site, and the other origin its pages navigate to (``site.away``,
    listening). The executor's scope is the observe URL's origin, so the navigation is
    refused: a request reaching ``away`` is an escape (QUALITY_POLICY §9). D72: it was
    this site's ``/logout.php``, refused as destructive; a GET there is a visit now."""
    site, away = _Site(), _Site()
    site.away = away
    _NAV = f"location.href = '{away.base}logout.php'"
    # navigates by script to a refused URL while it is being parsed (before `load`)
    site.pages["/inline"] = f"<html><body><script>{_NAV}</script><p>x</p></body></html>"
    # the same, and its sink fires 300 ms later
    site.pages["/inline-fire"] = (f"<html><body><script>{_NAV}; setTimeout(() => "
                                  f"window.{SENTINEL}('tok'), 300)</script></body></html>")
    # a DOM XSS sink: the `q` parameter is written into the page
    site.pages["/dom"] = ("<html><body><div id=o></div><script>document.getElementById"
                          "('o').innerHTML = new URLSearchParams(location.search)"
                          ".get('q') || ''</script></body></html>")
    site.redirects["/redir"] = away.base + "logout.php"
    return site


def test_a_before_load_navigation_is_no_verdict_well_under_the_timeout(monkeypatch):
    """The load a refused navigation superseded is not waited out (it was the full
    8 s, then a raise): the run ends after the bounded load wait and the sentinel wait,
    with no verdict -- not a negative, not a Playwright error."""
    _chromium_or_skip(monkeypatch)
    site = _site()
    try:
        started = time.monotonic()
        with pytest.raises(NotObserved) as err:
            _m6_run(site, "/inline", settle_ms=500)
        took = time.monotonic() - started
    finally:
        site.close()
        site.away.close()
    assert took < 6.5, f"{took:.1f}s: the superseded load was waited out"
    assert "did not finish loading" in str(err.value)
    assert site.away.requests == []


def test_a_hit_after_a_before_load_navigation_counts(monkeypatch):
    """A hit recorded at any point is executed=True, even when the page never loads."""
    _chromium_or_skip(monkeypatch)
    site = _site()
    try:
        assert _m6_run(site, "/inline-fire", settle_ms=1500).executed is True
    finally:
        site.close()
        site.away.close()
    assert site.away.requests == []


class _QuietSender:
    """The non-browser mechanisms' sender: nothing is reflected."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        return Probe(200, "<html><body>ok</body></html>")


def test_a_page_that_cannot_load_never_ends_the_pipeline(monkeypatch, tmp_path):
    """Two DOM-XSS candidates in one pipeline run: the first one's own redirect is
    refused (its `goto` fails), the second is a real DOM sink. The run goes on: the
    second is still confirmed. The first is INCONCLUSIVE (D54, Z4) -- not CHECKED, so
    it never enters the ML negatives -- and counted as such."""
    import json
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
            result = run_pipeline(points, store, run, _QuietSender(), plan,
                                  browser=executor)
            if executor._unavailable is not None:
                skip_or_fail(f"chromium could not launch: {executor._unavailable}")
            found = {(r["url"], r["vuln_class"]) for r in store.conn.execute(
                "SELECT url, vuln_class FROM finding WHERE run_id=?", (run,))}
            status = {json.loads(r["evidence"])["url"].rsplit("/", 1)[-1]: r["status"]
                      for r in store.conn.execute(
                          "SELECT evidence, oracle_status status FROM candidate "
                          "WHERE run_id=?", (run,))}
    finally:
        site.close()
        site.away.close()
    assert any(url.endswith("/dom") and vc == "xss-dom" for url, vc in found)
    assert not any(url.endswith("/redir") for url, _vc in found)
    assert status == {"redir": "inconclusive", "dom": "checked"}
    assert result.metrics["oracle_inconclusive"] == 1
    assert result.metrics["oracle_inconclusive_browser-execution"] == 1
    assert result.metrics["oracle_rejected"] == 0     # no negative from the redirect
    # the run's inconclusive detail says why (review B-N1), with no URL in it
    detail, = [item for item in result.inconclusive if item["url"].endswith("/redir")]
    assert "could not load" in detail["reason"] and "http" not in detail["reason"]
    assert site.away.requests == []


# --- a fake Playwright: failures the real browser cannot be made to give on demand --
class _FakeError(Exception):
    pass


def _token_in(url):
    """The token a payload in ``url`` calls the sentinel with, if any."""
    import re
    from urllib.parse import unquote_plus
    m = re.search(SENTINEL + r"\('([^']+)'\)", unquote_plus(url))
    return m.group(1) if m else None


def _fake_playwright(monkeypatch, goto=None, *, fires=lambda url: False,
                     stop_fails=0):
    """A fake ``playwright.sync_api``. ``goto(url, **kw)`` may raise; a page whose URL
    ``fires(url)`` calls the sentinel with its payload's token; the driver's stop
    raises `_FakeError` the first ``stop_fails`` times. Returns the call record."""
    calls = {"goto": [], "stops": 0}

    class Page:
        def __init__(self, binding):
            self._binding = binding

        def on(self, *a):
            pass

        def once(self, *a):
            pass

        def goto(self, url, **kw):
            calls["goto"].append(url)
            if goto is not None:
                goto(url, **kw)
            if fires(url) and _token_in(url):
                self._binding[0](None, _token_in(url))

        def wait_for_load_state(self, state, **kw):
            pass

        def wait_for_timeout(self, ms):
            pass

    class Context:
        request = types.SimpleNamespace(post=lambda *a, **k: None)
        pages: list = []

        def __init__(self):
            self._binding = [None]

        def expose_binding(self, name, fn):
            self._binding[0] = fn

        def route(self, pattern, handler):
            pass

        def route_web_socket(self, pattern, handler):
            pass

        def new_page(self):
            return Page(self._binding)

        def unroute_all(self, **kw):
            pass

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
            calls["stops"] += 1
            if calls["stops"] <= stop_fails:
                raise _FakeError("Connection closed while stopping the driver")
            return False
    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    fake.Error = _FakeError
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)
    return calls


def _run(executor=None, value="PAYLOAD-MARK"):
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = executor or PlaywrightBrowserExecutor()
    executor.SETTLE_MS = 0
    return executor.run(ExecRequest(url="http://127.0.0.1:3000/x", param="q",
                                    value=value), "tok")


# --- only Playwright errors are no verdict (PA-0106) ------------------------------
def test_a_playwright_error_is_no_verdict_and_names_no_url(monkeypatch):
    def goto(url, **kw):
        raise _FakeError(f"Page.goto: net::ERR_ABORTED at {url}\nCall log: ...")
    _fake_playwright(monkeypatch, goto)
    with pytest.raises(NotObserved, match="ERR_ABORTED") as err:
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


# --- Z1 / Z4: per payload; inconclusive, never a negative --------------------------
class _ScriptedExecutor:
    """An executor whose answers per payload are scripted: "miss" (observed, no hit),
    "hit", "unobserved" (`NotObserved`) or "no-browser" (`UnplaceableLocation`)."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    def run(self, request, token):
        from fuzzlab.oracle.browser import ExecObservation
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        if answer == "unobserved":
            raise NotObserved("the browser could not load the page (TimeoutError: x)")
        if answer == "no-browser":
            raise UnplaceableLocation("browser unavailable: no chromium")
        return ExecObservation(executed=answer == "hit", detail="scripted")


def _dom_confirm(executor):
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import DomXssStrategy
    cand = Candidate(url="http://127.0.0.1:3000/p", param="q", category="xss",
                     location="query")
    return DomXssStrategy(executor).confirm(cand, _QuietSender())


@pytest.mark.parametrize("answers", [("unobserved", "hit"),
                                     ("unobserved", "miss", "hit")])
def test_a_later_payload_is_tried_after_an_unobserved_one(answers):
    """Z1: one unobserved payload does not end the loop; a later payload's hit
    confirms."""
    executor = _ScriptedExecutor(*answers)
    verdict = _dom_confirm(executor)
    assert verdict is not None and verdict.confirmed
    assert executor.calls == len(answers)


def test_two_unobserved_payloads_in_a_row_stop_and_are_inconclusive():
    """Z1's cost bound and Z4: with every page unobservable the strategy stops after
    two loads, plus one last load of the first untried quote-free payload (BUG-0139
    review B-S1), and is inconclusive (FR-FUZZ-45), never a negative."""
    executor = _ScriptedExecutor("unobserved")
    verdict = _dom_confirm(executor)
    assert executor.calls == 3
    assert verdict is not None and not verdict.confirmed and verdict.inconclusive
    assert "could not load" in verdict.evidence["not_observed"]


def test_a_partly_observed_candidate_without_a_hit_is_inconclusive():
    """Z4: no hit, and one payload was not observed: inconclusive, not a negative."""
    verdict = _dom_confirm(_ScriptedExecutor("miss", "unobserved", "miss", "miss"))
    assert verdict is not None and verdict.inconclusive and not verdict.confirmed


def test_every_payload_observed_without_a_hit_is_a_plain_negative():
    """Z4: all observed, no hit: None (a real negative), as before."""
    executor = _ScriptedExecutor("miss")
    assert _dom_confirm(executor) is None
    assert executor.calls == len(_xss_exec_payloads("t0"))   # every payload (6, BUG-0139)


def test_a_browser_that_cannot_start_stops_at_once():
    """Z1: a launch failure (`UnplaceableLocation`, BUG-0126) is not a per-payload
    miss: the strategy stops at the first payload and gives no verdict."""
    executor = _ScriptedExecutor("no-browser")
    with pytest.raises(UnplaceableLocation) as err:
        _dom_confirm(executor)
    assert not isinstance(err.value, NotObserved) and executor.calls == 1


# --- Z2: the driver's stop is contained --------------------------------------------
def test_a_failed_driver_stop_keeps_the_result(monkeypatch, tmp_path):
    """Z2: the driver's stop raising never replaces a probe's result nor ends the run:
    in a two-candidate pipeline whose first probes' driver stop fails, the second
    candidate is still confirmed."""
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.core.runmode import resolve_run
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    calls = _fake_playwright(monkeypatch, fires=lambda url: "/dom" in url, stop_fails=1)
    executor = PlaywrightBrowserExecutor()
    executor.SETTLE_MS = 0
    points = [InjectionPoint(url="http://127.0.0.1:3000/a", param="q"),
              InjectionPoint(url="http://127.0.0.1:3000/dom", param="q")]
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        plan = resolve_run("manual", selected_categories=["xss"], all_categories=["xss"])
        run_pipeline(points, store, run, _QuietSender(), plan, browser=executor)
        found = {r["url"] for r in store.conn.execute(
            "SELECT url FROM finding WHERE run_id=? AND vuln_class='xss-dom'", (run,))}
    assert calls["stops"] >= 2                        # the first stop failed, then more
    assert any(url.endswith("/dom") for url in found)
    assert executor._unavailable is None              # one failure is not "unavailable"


def test_a_driver_that_never_stops_cleanly_makes_the_browser_unavailable(monkeypatch):
    """Z2: stops failing `MAX_LAUNCH_FAILURES` times in a row turn the browser off for
    the run (BUG-0126's path); each probe's own result is kept meanwhile."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _fake_playwright(monkeypatch, fires=lambda url: True, stop_fails=99)
    executor = PlaywrightBrowserExecutor()
    firing = f"<svg onload=\"{SENTINEL}('tok')\">"
    for _ in range(PlaywrightBrowserExecutor.MAX_LAUNCH_FAILURES):
        assert _run(executor, firing).executed is True   # the result survives the stop
    with pytest.raises(UnplaceableLocation, match="did not stop cleanly") as err:
        _run(executor)
    assert not isinstance(err.value, NotObserved)


# --- Z3: a slow page's sink, a full settle after `load` -----------------------------
def test_a_sink_that_fires_after_a_slow_load_is_seen(monkeypatch):
    """Z3: the page's `load` fires at about 5 s (a slow image), its sink 2.5 s later.
    The wait lasts a full `SETTLE_MS` from `load`, so the hit is seen (before, the
    wait ended 3 s + 4 s after the commit, at 7 s)."""
    _chromium_or_skip(monkeypatch)
    site = _site()
    site.delays["/slow.png"] = 5.0
    site.pages["/slowpage"] = (f"<html><body><img src='/slow.png'><script>"
                               f"window.addEventListener('load', () => setTimeout("
                               f"() => window.{SENTINEL}('tok'), 2500))</script>"
                               f"</body></html>")
    try:
        assert _m6_run(site, "/slowpage", settle_ms=4000).executed is True
    finally:
        site.close()


# --- review of 1702c29: the reason never carries a URL; late launch failure; oracle --
_PAYLOAD_URL = "http://127.0.0.1:3000/x?q=%3Cimg+src%3Dx+onerror%3DPAYLOADMARK%3E"


@pytest.mark.parametrize("message", [
    # Playwright's interrupted navigation: both URLs quoted, no " at "
    f'Page.goto: Navigation to "{_PAYLOAD_URL}" is interrupted by another navigation '
    f'to "http://127.0.0.1:3000/logout.php"\nCall log:\n  - navigating to "x"',
    f"Page.goto: net::ERR_ABORTED at {_PAYLOAD_URL}\nCall log:\n  - navigating",
    f'Page.goto: Timeout 8000ms exceeded.\nCall log:\n  - navigating to "{_PAYLOAD_URL}"',
    # a quoted raw payload with spaces, and a URL that is not quoted
    "Page.goto: Navigation to \"http://h/x?q=<img src=x onerror=PAYLOADMARK>\" failed",
    f"frame was detached while loading {_PAYLOAD_URL} (PAYLOADMARK-free tail)",
])
def test_the_reason_never_carries_a_url_or_the_payload(message):
    """Review A: every quoted string and every ``scheme://`` token is removed from the
    stored reason (``evidence["not_observed"]``), whatever the message's shape."""
    from fuzzlab.tools.browserexec import _failure_reason
    reason = _failure_reason(_FakeError(message))
    assert "http" not in reason and "://" not in reason
    assert '"' not in reason and "'" not in reason
    assert "PAYLOADMARK" not in reason.replace("PAYLOADMARK-free", "")
    assert reason.startswith("the browser could not load the page (_FakeError: ")


def test_a_launch_failure_after_an_unobserved_payload_is_still_inconclusive():
    """Review B-N2: a payload went unobserved, then the browser could not start: the
    candidate is inconclusive (Z4), not "no verdict" from a propagated error."""
    executor = _ScriptedExecutor("unobserved", "no-browser")
    verdict = _dom_confirm(executor)
    assert verdict is not None and verdict.inconclusive and not verdict.confirmed
    assert executor.calls == 2


class _Stub:
    """A strategy that returns a fixed verdict."""
    category = "xss"

    def __init__(self, arm, verdict):
        self.arm, self.mechanism, self._verdict = arm, arm, verdict

    def applies(self, candidate):
        return True

    def confirm(self, candidate, sender):
        return self._verdict


def _oracle_outcome(*strategies):
    from fuzzlab.oracle import Oracle
    from fuzzlab.oracle.probe import Candidate
    cand = Candidate(url="http://127.0.0.1:3000/p", param="q", category="xss",
                     location="query")
    return Oracle(strategies=list(strategies)).confirm_outcome(cand, _QuietSender())


def _m6_inconclusive():
    from fuzzlab.oracle.probe import Verdict
    return Verdict(False, "xss-dom", "browser-execution",
                   {"not_observed": "the browser could not load the page (x)"},
                   inconclusive=True)


def test_an_m6_inconclusive_first_never_hides_a_later_confirmation():
    """Review B-N3: M6's inconclusive verdict, ordered first, then a confirming
    strategy: the candidate is confirmed, with no inconclusive."""
    from fuzzlab.oracle.probe import Verdict
    confirmed = Verdict(True, "xss", "reflection", {})
    verdict, unsure = _oracle_outcome(_Stub("m6", _m6_inconclusive()),
                                      _Stub("reflected", confirmed))
    assert verdict is confirmed and unsure is None


def test_the_first_inconclusive_is_kept_before_an_m6_one():
    """Review B-N3: a cost-capped strategy's inconclusive verdict comes first; M6's
    after it does not replace it."""
    from fuzzlab.oracle.probe import Verdict
    capped = Verdict(False, "xss", "cost-cap", {"families_not_started": ["x"]},
                     inconclusive=True)
    verdict, unsure = _oracle_outcome(_Stub("capped", capped),
                                      _Stub("m6", _m6_inconclusive()))
    assert verdict is None and unsure is capped
