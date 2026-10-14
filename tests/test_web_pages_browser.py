"""Every page of the control panel, in a real browser (BUG-0063, BUG-0064, PA-0065).

`TestClient` tests never execute the panel's JS, never apply its CSP and never draw a
chart. That is how every chart on the ML and Diagnostics tabs (a uPlot option misuse that
threw on construction) and every CSP-blocked template construct (the no-FOUC preferences
script, the Overview severity bar) shipped broken while all tests passed. This module
loads each HTML page in real Chromium against a seeded store and asserts:

(a) every HTML GET route of the app (walked from `app.routes`, not a hand-kept list) plus
    the not-found page: zero page errors, zero console errors, zero CSP violations;
(b) /ml: in every panel the payload marks available, every chart mount holds a rendered
    uPlot chart carrying its `fl-chart--<type>` class; the evaluation labels show;
(c) /diagnostics: picking a run and a metric draws both charts, labelled, and a second
    metric updates the chart's accessible name;
(d) /ml: one panel that throws no longer blanks the panels after it;
(e) a persisted theme is applied on load;
(f) /: the severity bar's segments render with widths proportional to the counts;
(g) /ml: an earlier-trained model's evaluation label, forward numbers and seen share show.

Skips only if the browser genuinely cannot run, and fails instead under
`FUZZLAB_REQUIRE_BROWSER=1` (see `tests/_browser.py`).
"""

from __future__ import annotations

import json
import re

import pytest

from tests._browser import Server, free_port, launch_browser_or_skip, require_modules

require_modules()
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.ml.rank_train import train_and_rank  # noqa: E402
from fuzzlab.ml.train import train_and_score  # noqa: E402
from fuzzlab.web import labcontrol  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests.test_ml_train import _finding, _seed_rich  # noqa: E402

# Collects CSP violations from the moment the document starts (an init script runs
# before any page script, so a blocked <head> script is caught too).
_CSP_COLLECTOR = """
window.__cspViolations = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI} line ${e.lineNumber}`);
});
"""

SETTLE_MS = 600


def _seed(path) -> dict:
    with Store(path) as store:
        run_id = _seed_rich(store)                 # 20 candidates, 6 sqli findings
        _finding(store, run_id, "/p0.php", "id", "xss")          # a second severity
        store.conn.commit()
        train_and_score(store, run_id)             # classifier + metric_series
        train_and_rank(store, run_id)              # ranker
        finding_id = store.conn.execute("SELECT MIN(id) i FROM finding").fetchone()["i"]
        sev = {"critical": store.conn.execute(
                   "SELECT COUNT(*) c FROM finding WHERE vuln_class='sqli'").fetchone()["c"],
               "high": 1}
    return {"run_id": run_id, "finding_id": finding_id, "severity": sev}


@pytest.fixture(scope="module")
def site(tmp_path_factory, monkeypatch_module):
    async def no_engine():                         # /lab must not shell out to labctl.sh
        return {}, None
    monkeypatch_module.setattr(labcontrol, "fetch_states", no_engine)
    path = tmp_path_factory.mktemp("pages") / "s.db"
    seeded = _seed(path)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080",
                                 "web_port": port}, environ={})
    app = create_app(cfg)
    server = Server(app, port)
    server.start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            yield {"app": app, "base": f"http://127.0.0.1:{port}", "browser": browser,
                   **seeded}
            browser.close()
    finally:
        server.stop()


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


class _Page:
    """A page plus everything it reported: page errors, console errors, CSP violations."""

    def __init__(self, browser, base):
        self.base = base
        self.ctx = browser.new_context()
        self.ctx.add_init_script(_CSP_COLLECTOR)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(15000)
        self.errors: list[str] = []
        self.expected_document_status = 200
        self.page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        self.page.on("console", self._on_console)

    def _on_console(self, msg):
        if msg.type != "error":
            return
        # The not-found page is *meant* to be served with 404, and Chromium logs that
        # status for the document itself; any other failed resource is a real problem.
        own_document = (msg.location or {}).get("url") == self.page.url
        if (self.expected_document_status == 404 and own_document
                and "status of 404" in msg.text):
            return
        self.errors.append(f"console.{msg.type}: {msg.text}")

    def open(self, path, ready: str | None = None):
        self.page.goto(self.base + path, wait_until="load")
        if ready:
            self.page.wait_for_selector(ready)
        self.page.wait_for_timeout(SETTLE_MS)
        return self.page

    def problems(self) -> list[str]:
        csp = self.page.evaluate("window.__cspViolations || []")
        return self.errors + [f"csp: {v}" for v in csp]

    def close(self):
        self.ctx.close()


@pytest.fixture
def tab(site):
    t = _Page(site["browser"], site["base"])
    yield t
    t.close()


# --- (a) every HTML page: no errors, no CSP violations ----------------------

_READY = {"/ml": ".uplot", "/diagnostics": ".diag-run-chip input"}


def _html_pages(app, seeded) -> list[str]:
    """Every non-/api GET route, which must be an HTML page with fillable params —
    so a page added later is smoked automatically, never silently skipped."""
    fill = {"run_id": seeded["run_id"], "finding_id": seeded["finding_id"]}
    pages = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or "GET" not in route.methods:
            continue
        if route.path.startswith("/api/"):
            continue
        assert route.response_class is HTMLResponse, (
            f"{route.path}: a non-/api GET route that is not an HTML page — classify it "
            "here so the browser smoke covers it")
        params = re.findall(r"{(\w+)}", route.path)
        missing = [p for p in params if p not in fill]
        assert not missing, f"{route.path}: no seeded value for {missing} — add one"
        pages.append(re.sub(r"{(\w+)}", lambda m: str(fill[m.group(1)]), route.path))
    return pages


def test_route_walk_finds_the_known_pages(site):
    pages = _html_pages(site["app"], site)
    for known in ("/", "/ml", "/diagnostics", "/lab", f"/runs/{site['run_id']}"):
        assert known in pages


def test_every_page_loads_without_errors_or_csp_violations(site):
    failures = {}
    for path in _html_pages(site["app"], site) + ["/runs/999999"]:   # + the 404 page
        t = _Page(site["browser"], site["base"])
        if path == "/runs/999999":
            t.expected_document_status = 404
        try:
            t.open(path, _READY.get(path))
            if t.problems():
                failures[path] = t.problems()
        finally:
            t.close()
    assert failures == {}, json.dumps(failures, indent=2)


# --- (b) /ml: every available panel's charts render -------------------------

def test_ml_tab_renders_every_available_chart(site, tab):
    page = tab.open("/ml", ".uplot")
    payload = page.evaluate("fetch('/api/ml/data').then(r => r.json())")
    expected = 0
    for panel in page.query_selector_all(".ml-panel[data-panel]"):
        key = panel.get_attribute("data-panel")
        if not (payload.get(key) or {}).get("available"):
            continue
        for mount in panel.query_selector_all(".ml-chart"):
            expected += 1
            chart = mount.query_selector(".uplot")
            assert chart, f"panel {key}: chart mount #{mount.get_attribute('id')} is empty"
            classes = chart.get_attribute("class").split()
            assert "fl-chart" in classes
            assert any(c in classes for c in ("fl-chart--line", "fl-chart--bars",
                                              "fl-chart--scatter")), classes
            assert mount.get_attribute("role") == "figure"
    assert expected >= 8, "seeded store should make the main ML panels available"
    # CC-UI-0042: a run-mode model's numbers are recomputed from its stored
    # out-of-fold scores, and say so
    meta = page.inner_text("#panel-ranker")
    assert "out-of-fold (labelled rows)" in meta and "out-of-fold (labelled rows)" in \
        page.inner_text("#panel-calibration")
    assert tab.problems() == []


# --- (c) /diagnostics: charts render, labelled, accessible name tracks metric -

def test_diagnostics_charts_render_and_relabel(site, tab):
    page = tab.open("/diagnostics", ".diag-run-chip input")
    page.check(".diag-run-chip input")
    buttons = page.locator("#diag-metric-groups button")
    buttons.first.wait_for()
    assert buttons.count() >= 2
    labels = []
    for i in (0, 1):
        buttons.nth(i).click()
        page.wait_for_timeout(SETTLE_MS)
        charts = page.locator(".uplot.fl-chart")
        assert charts.count() >= 1, "no diagnostics chart rendered"
        mounts = page.locator("#diag-trend-chart[aria-label], #diag-series-chart[aria-label]")
        labels.append([mounts.nth(j).get_attribute("aria-label")
                       for j in range(mounts.count())])
    assert labels[0] and labels[1] and labels[0] != labels[1], labels
    legend = page.inner_text("#diagnostics-root")
    assert re.search(r"run #\d+|ml_|train/", legend)
    assert tab.problems() == []


# --- (d) /ml: a panel that throws does not blank the later panels ------------

def test_one_broken_ml_panel_does_not_blank_the_rest(site, tab):
    real = tab.page.request.get(site["base"] + "/api/ml/data").json()
    broken = dict(real, classifier={"available": True})     # missing every field
    tab.page.route("**/api/ml/data", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(broken)))
    page = tab.open("/ml", "#panel-ranker .uplot")
    assert "could not render this panel" in page.inner_text("#panel-calibration").lower()
    assert page.locator("#panel-ranker .uplot").count() >= 1
    # the failure is still reported, not swallowed
    assert any("could not render panel" in e for e in tab.errors)


# --- (g) /ml: an earlier-trained model's labels, forward numbers, seen share --

def test_ml_tab_shows_an_earlier_trained_models_evaluation(site, tab):
    real = tab.page.request.get(site["base"] + "/api/ml/data").json()
    note = "not trained on this run's labels (trained on earlier runs)"
    clf = dict(real["classifier"], evaluation=note, oof={
        "pr_auc": 0.8, "pr_auc_prevalence": 0.3, "pr_auc_sigma": 0.4,
        "scope": "earlier runs", "seen_fraction": 0.75, "train_run_ids": [1, 2],
        "forward": {"pr_auc": 0.61, "pr_auc_prevalence": 0.25},
        "forward_skipped_reason": None})
    rank = dict(real["ranker"], evaluation=note, oof={
        "at_k": 10, "ndcg": 0.9, "precision": 0.5, "ndcg_random": 0.4,
        "precision_random": 0.2, "scope": "earlier runs", "seen_fraction": 0.5,
        "train_run_ids": [1, 2], "forward": None,
        "forward_skipped_reason": "budget-selected labels"})
    payload = dict(real, classifier=clf, ranker=rank)
    tab.page.route("**/api/ml/data", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(payload)))
    page = tab.open("/ml", "#panel-ranker .uplot")
    cal, rnk = page.inner_text("#panel-calibration"), page.inner_text("#panel-ranker")
    assert note in cal and note in rnk
    assert "out-of-fold PR-AUC 0.800 on earlier runs" in cal
    assert "forward PR-AUC 0.610 (prevalence 0.250)" in cal
    assert "75% of this run's candidates seen in training" in cal
    assert "no forward evaluation (budget-selected labels)" in rnk
    assert "50% of this run's candidates seen in training" in rnk
    assert tab.problems() == []


# --- (e) a persisted theme is applied on load --------------------------------

def test_an_unknown_exit_status_renders_as_unknown(site, tab):
    """BUG-0125 review round 3: the launcher and Lab pages print ``[exit unknown]`` for a
    ``done`` event whose ``returncode`` is null (a job whose supervisor was reaped
    outside fuzzlab), never ``[exit null]``. The run and its stream are routed (no job
    runs, no container is touched)."""
    page = tab.page
    sse = 'event: done\ndata: {"returncode": null}\n\n'
    page.route("**/api/launch/tok-unknown/stream",
               lambda r: r.fulfill(status=200, headers={"Content-Type": "text/event-stream"},
                                   body=sse))
    page.route("**/api/launch",
               lambda r: r.fulfill(status=200, content_type="application/json",
                                   body='{"token": "tok-unknown", "argv": []}'))
    tab.open("/launcher")
    form = 'form.launch-form[data-command="report"]'
    page.click('.actlist .act[data-for="report"]')
    page.locator(f"{form} [data-action='run']").wait_for(state="visible")
    page.click(f"{form} [data-action='run']")
    out = page.locator(f"{form} .launch-output")
    page.wait_for_function("el => el.textContent.includes('[exit')", arg=out.element_handle())
    assert "[exit unknown]" in out.inner_text()

    page.route("**/api/lab/services",
               lambda r: r.fulfill(status=200, content_type="application/json",
                                   body=_lab_services_with_one_stopped()))
    page.route("**/api/lab/*/start",
               lambda r: r.fulfill(status=200, content_type="application/json",
                                   body='{"token": "tok-unknown"}'))
    tab.open("/lab", ready="#lab-table tbody tr")
    first = page.locator("#lab-table tbody tr").first
    first.locator('[data-action="start"]:not([disabled])').wait_for()
    first.locator('[data-action="start"]').click()
    lab_out = page.locator("#lab-output")
    page.wait_for_function("el => el.textContent.includes('[exit')", arg=lab_out.element_handle())
    assert "[exit unknown]" in lab_out.inner_text()
    assert tab.problems() == []


def _lab_services_with_one_stopped() -> str:
    import json

    services = [{**s.to_dict(), "state": "exited", "status": "", "container": None,
                 "running": False} for s in labcontrol.services()]
    return json.dumps({"services": services, "error": None})


def test_persisted_theme_is_applied_on_load(site, tab):
    page = tab.open("/")
    page.evaluate("localStorage.setItem('fl-theme', 'dark')")
    page.reload(wait_until="load")
    assert page.get_attribute("html", "data-theme") == "dark"
    assert tab.problems() == []


# --- (f) /: severity bar segments are drawn, proportional --------------------

def test_overview_severity_bar_is_proportional(site, tab):
    page = tab.open("/", ".sev-bar")
    widths = {sev: page.locator(f".sev-bar .sev-seg.sev-{sev}").bounding_box()["width"]
              for sev in site["severity"]}
    assert all(w > 0 for w in widths.values()), widths
    want = site["severity"]["critical"] / site["severity"]["high"]
    assert widths["critical"] / widths["high"] == pytest.approx(want, rel=0.05)
    assert tab.problems() == []
