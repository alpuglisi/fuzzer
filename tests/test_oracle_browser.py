"""Tests for M6 browser-execution XSS confirmation (stored + DOM), offline.

The BrowserExecutor is injected and faked, so these run without a real browser.
"""

from fuzzlab.core.store import Store
from fuzzlab.labels import contract
from fuzzlab.oracle import Candidate, Oracle
from fuzzlab.oracle.browser import (
    SENTINEL,
    ExecObservation,
    FakeBrowserExecutor,
)
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import DomXssStrategy, StoredXssStrategy

GT_DIR = "lab/ground-truth"


def _dom_candidate(location="query"):
    return Candidate(url="http://h/feedback.php", param="ref", location=location,
                     category="xss")


def test_dom_xss_confirmed_when_payload_executes():
    v = DomXssStrategy(FakeBrowserExecutor()).confirm(_dom_candidate(), sender=None)
    assert v is not None and v.confirmed
    assert v.vuln_class == "xss-dom" and v.mechanism == "browser-execution"


def test_dom_xss_not_confirmed_when_page_escapes():
    escaped = FakeBrowserExecutor(escape=True)          # page HTML-escapes input
    assert DomXssStrategy(escaped).confirm(_dom_candidate(), sender=None) is None


def test_dom_xss_noop_without_a_browser():
    # No executor injected -> cannot confirm (stays fail-closed), no crash.
    assert DomXssStrategy(None).confirm(_dom_candidate(), sender=None) is None


def test_dom_xss_places_payload_in_fragment():
    seen = {}

    class RecordingExec:
        def run(self, request, token):
            seen["location"] = request.location
            seen["value"] = request.value
            return ExecObservation(executed=True)
    DomXssStrategy(RecordingExec()).confirm(_dom_candidate(location="fragment"), sender=None)
    assert seen["location"] == "fragment"
    assert SENTINEL in seen["value"]                    # payload calls the sentinel


def test_stored_xss_stores_then_observes():
    steps = {}

    class RecordingExec:
        def run(self, request, token):
            steps["store_url"] = request.store.url if request.store else None
            steps["observe_url"] = request.url
            return ExecObservation(executed=True)      # simulate it fired on render
    cand = Candidate(url="http://h/profile.php", param="bio", category="xss",
                     store_url="http://h/edit_profile.php", store_param="bio")
    v = StoredXssStrategy(RecordingExec()).confirm(cand, sender=None)
    assert v is not None and v.vuln_class == "xss-stored"
    assert steps["store_url"] == "http://h/edit_profile.php"
    assert steps["observe_url"] == "http://h/profile.php"


def test_stored_xss_needs_store_endpoint():
    # Without store_url there is nothing to plant -> not confirmed.
    cand = Candidate(url="http://h/profile.php", param="bio", category="xss")
    assert StoredXssStrategy(FakeBrowserExecutor()).confirm(cand, sender=None) is None


class _NoReflect:
    """A sender that never reflects, so the reflected (M5) strategy declines and the
    DOM (M6) strategy gets its turn."""
    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, "ok", headers={})


def test_oracle_with_browser_confirms_dom_and_writes_finding(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("m6", "h")
        oracle = Oracle(store=store, run_id=run_id, browser=FakeBrowserExecutor())
        v = oracle.confirm(_dom_candidate(location="fragment"), _NoReflect())
        assert v is not None and v.vuln_class == "xss-dom"
        row = store.conn.execute(
            "SELECT vuln_class, url, param, confidence FROM finding WHERE run_id=?",
            (run_id,)).fetchone()
        assert row["vuln_class"] == "xss-dom" and row["url"] == "/feedback.php"
        assert row["confidence"] == "browser-execution"


class _RefOrExec:
    """Reflects for M5 and 'executes' for M6, so an xss candidate can hit either."""
    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, f"<html>{value}</html>", headers={})


def test_xss_category_runs_reflected_without_browser(tmp_path):
    # An xss candidate still confirms via reflected (M5) when no browser is present.
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("m6", "h")
        oracle = Oracle(store=store, run_id=run_id)      # no browser
        v = oracle.confirm(Candidate(url="http://h/search.php", param="q",
                                     category="xss"), _RefOrExec())
        assert v is not None and v.vuln_class == "xss-reflected"
