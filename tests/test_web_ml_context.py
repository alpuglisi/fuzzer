"""The ML tab run picker and the run page's ML context (CC-UI-0043, FR-UI-19).

Data-level tests run on `TestClient`/direct calls; everything that "renders" is checked
in real Chromium (PA-0065(3)), including hostile values seeded into every new text
field (PA-0034(1)): they must show as literal text, inject nothing and trip no CSP.
"""

from __future__ import annotations

import json
import time

import pytest

from tests._browser import Server, free_port, launch_browser_or_skip, require_modules

require_modules()
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.oracle_status import CHECKED, NO_CONFIRMER, SKIPPED_BUDGET  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.ml.anomaly import detect_anomalies  # noqa: E402
from fuzzlab.ml.rank_train import train_and_rank  # noqa: E402
from fuzzlab.ml.train import train_and_score  # noqa: E402
from fuzzlab.web import labcontrol, mlview  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.results import list_runs, run_detail  # noqa: E402
from tests.test_ml_train import _cand, _seed_rich  # noqa: E402
from tests.test_web_pages_browser import _Page  # noqa: E402

HOSTILE = '<img src=x onerror="window.__pwned=1">'


def _seed(path) -> dict:
    with Store(path) as store:
        trained = _seed_rich(store)                       # run 1: scored + ranked
        # hostile text in a candidate's param / path, flagged as an anomaly
        bad = _cand(store, trained, f"/{HOSTILE}.php", HOSTILE, "xss")
        store.conn.commit()
        train_and_score(store, trained)
        train_and_rank(store, trained)
        detect_anomalies(store, trained, contamination=0.2)
        store.conn.execute("UPDATE candidate SET anomaly_flag=1, anomaly_score=99.0 "
                           "WHERE id=?", (bad,))
        statuses = [CHECKED] * 12 + [SKIPPED_BUDGET] * 5 + [NO_CONFIRMER] * 3
        ids = [r[0] for r in store.conn.execute(
            "SELECT id FROM candidate WHERE run_id=? ORDER BY id", (trained,))]
        for cid, st in zip(ids, statuses):
            store.conn.execute("UPDATE candidate SET oracle_status=? WHERE id=?", (st, cid))
        for name, status, error, config in (
                ("ml-classifier", "ok", None, '{"train_on":"run"}'),
                ("ml-ranker", "failed", HOSTILE + "x" * 400, json.dumps({"h": HOSTILE})),
                ("ml-anomaly", "attached", None, '{"contamination":0.2}'),
                ("legacy", None, None, None)):
            store.conn.execute(
                "INSERT INTO run_plugin (run_id, name, version, priority, config, status, "
                "error) VALUES (?,?,?,?,?,?,?)", (trained, name, "2", 10, config, status, error))
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (trained, "anomaly_flagged", 5.0))
        unscored = _seed_rich(store)                      # run 2: candidates, no models
        crawl = store.start_run(HOSTILE, "127.0.0.1:8080")    # run 3: no candidates
        store.conn.commit()
        oof_line = mlview.classifier_panel(store, trained)["oof"]
    return {"trained": trained, "unscored": unscored, "crawl": crawl,
            "oof_pr_auc": oof_line["pr_auc"]}


# --- data -------------------------------------------------------------------------

def test_run_detail_carries_the_runs_ml_context(tmp_path):
    seeded = _seed(tmp_path / "s.db")
    with Store(tmp_path / "s.db") as store:
        d = run_detail(store, seeded["trained"])
    assert d["oracle_status"] == {"checked": 12, "skipped_budget": 5, "no_confirmer": 3,
                                  "unrecorded": 1}
    assert d["anomaly"]["flagged"] == 5.0
    assert d["anomaly"]["top"][0]["param"] == HOSTILE        # highest stored score first
    assert len(d["anomaly"]["top"]) <= 10
    by = {p["name"]: p for p in d["plugins"]}
    assert by["ml-classifier"]["status_text"] == "ok"
    assert by["ml-ranker"]["status_text"] == "FAILED" and by["ml-ranker"]["failed"]
    assert len(by["ml-ranker"]["error"]) == 301 and by["ml-ranker"]["error"].endswith("…")
    assert by["ml-anomaly"]["status_text"] == "attached — run did not finish"
    assert by["legacy"]["status_text"] == "unknown"
    assert d["anomaly"]["config"] == '{"contamination":0.2}'


def test_list_runs_marks_runs_without_candidates(tmp_path):
    seeded = _seed(tmp_path / "s.db")
    with Store(tmp_path / "s.db") as store:
        runs = {r["id"]: r for r in list_runs(store)}
    assert runs[seeded["crawl"]]["candidates"] == 0
    assert runs[seeded["trained"]]["candidates"] == 21


def test_per_run_payload_differs_from_all_runs(tmp_path):
    seeded = _seed(tmp_path / "s.db")
    with Store(tmp_path / "s.db") as store:
        per_run = mlview.classifier_panel(store, seeded["trained"])
        assert per_run["oof"] is not None
        assert mlview.classifier_panel(store, seeded["unscored"])["available"] is False


# --- real browser --------------------------------------------------------------------

@pytest.fixture(scope="module")
def site(tmp_path_factory):
    mp = pytest.MonkeyPatch()

    async def no_engine():
        return {}, None
    mp.setattr(labcontrol, "fetch_states", no_engine)
    path = tmp_path_factory.mktemp("mlctx") / "s.db"
    seeded = _seed(path)
    real = mlview.ml_overview
    delayed = {"run": None}

    def slow_overview(store, run_id=None):              # lets a test delay one run
        if run_id is not None and run_id == delayed["run"]:
            time.sleep(1.5)
        return real(store, run_id)

    mp.setattr(mlview, "ml_overview", slow_overview)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path), "web_port": port,
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            yield {"base": f"http://127.0.0.1:{port}", "browser": browser,
                   "delayed": delayed, **seeded}
            browser.close()
    finally:
        server.stop()
        mp.undo()


@pytest.fixture
def tab(site):
    t = _Page(site["browser"], site["base"])
    t.ml_requests = []
    t.page.on("request", lambda r: "/api/ml/data" in r.url and t.ml_requests.append(r.url))
    yield t
    t.close()


def _calibration_state(page) -> tuple[bool, bool]:
    """(chart drawn, empty message visible) for the classifier panel."""
    chart = page.locator("#panel-calibration .uplot").count() > 0
    empty = page.locator('#panel-calibration [data-field="empty"]').is_visible()
    return chart, empty


def test_picker_lists_runs_as_text_and_disables_empty_ones(site, tab):
    page = tab.open("/ml", ".uplot")
    options = page.locator("#ml-run option")
    labels = [options.nth(i).inner_text() for i in range(options.count())]
    assert labels[0] == "All runs"
    crawl = page.locator(f'#ml-run option[value="{site["crawl"]}"]')
    assert HOSTILE in crawl.inner_text()                  # literal text, not markup
    assert crawl.inner_text().endswith("(no candidates)") and crawl.is_disabled()
    assert page.evaluate("window.__pwned") is None
    assert page.locator("#ml-run img").count() == 0
    assert tab.problems() == []


def test_choosing_a_run_fetches_and_shows_that_runs_numbers(site, tab):
    page = tab.open("/ml", ".uplot")
    tab.ml_requests.clear()
    page.select_option("#ml-run", str(site["trained"]))
    page.wait_for_timeout(800)
    assert any(f"run_id={site['trained']}" in u for u in tab.ml_requests)
    text = page.inner_text("#panel-calibration")
    assert f"out-of-fold PR-AUC {site['oof_pr_auc']:.3f}" in text      # run-specific
    assert page.url.endswith(f"?run={site['trained']}")
    assert tab.problems() == []


def test_switching_runs_never_leaves_a_stale_panel(site, tab):
    page = tab.open("/ml", ".uplot")
    for run, want in ((site["trained"], (True, False)), (site["unscored"], (False, True)),
                      (site["trained"], (True, False))):
        page.select_option("#ml-run", str(run))
        page.wait_for_timeout(800)
        assert _calibration_state(page) == want, run
    assert tab.problems() == []


def test_a_late_response_for_an_older_choice_is_dropped(site, tab):
    page = tab.open("/ml", ".uplot")
    site["delayed"]["run"] = site["trained"]
    try:
        page.select_option("#ml-run", str(site["trained"]))       # slow
        page.wait_for_timeout(100)
        page.select_option("#ml-run", str(site["unscored"]))      # fast, chosen last
        page.wait_for_timeout(2500)                               # the slow one is due
        assert _calibration_state(page) == (False, True)          # still the last choice
    finally:
        site["delayed"]["run"] = None
    assert [e for e in tab.problems() if "abort" not in e.lower()] == []


@pytest.mark.parametrize("value", ["0", "-1", "abc", "999999"])
def test_bad_run_parameters_fall_back_to_all_runs(site, tab, value):
    page = tab.open(f"/ml?run={value}", ".uplot")
    assert page.input_value("#ml-run") == ""
    assert not any(f"run_id={value}" in u for u in tab.ml_requests)
    assert all("run_id=" not in u for u in tab.ml_requests)
    assert tab.problems() == []


def test_run_query_restores_the_choice(site, tab):
    page = tab.open(f"/ml?run={site['trained']}", ".uplot")
    assert page.input_value("#ml-run") == str(site["trained"])
    assert any(f"run_id={site['trained']}" in u for u in tab.ml_requests)


def test_run_page_shows_oracle_coverage_anomalies_and_plugins_as_text(site, tab):
    page = tab.open(f"/runs/{site['trained']}")
    coverage = page.inner_text("#run-oracle-status")
    assert "checked 12" in coverage and "skipped (budget) 5" in coverage
    assert "no confirmer 3" in coverage
    anomaly = page.inner_text("#run-anomaly")
    assert HOSTILE in anomaly and "Flagged on this run: 5" in anomaly
    plugins = page.inner_text("#run-plugins")
    assert "attached — run did not finish" in plugins and "unknown" in plugins
    assert "FAILED: " + HOSTILE in plugins
    assert page.locator("#run-plugins img, #run-anomaly img").count() == 0
    assert page.evaluate("window.__pwned") is None
    assert tab.problems() == []


def test_a_run_without_candidates_in_the_query_falls_back(site, tab):
    """A real but disabled option (no candidates) is not a valid choice either."""
    page = tab.open(f"/ml?run={site['crawl']}", ".uplot")
    assert page.input_value("#ml-run") == ""
    assert all("run_id=" not in u for u in tab.ml_requests)
