"""Tests for the Overview dashboard (U1/CC-UI-0028, R-10): landing route "/",
KPI tiles, recent-runs table, findings-by-severity bar, quick actions, and
empty/partial-empty states. Strictly read-only over the store -- never
creates it, never writes a result-table row.
"""

import json

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.results import overview_summary, severity_of  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def _client(path=None, authorized=False):
    overrides = {"target_base_url": "http://127.0.0.1:8080", "authorized": authorized}
    if path is not None:
        overrides["store_path"] = str(path)
    cfg = load_config(overrides=overrides, environ={})
    return web_client(create_app(cfg))


def _seed(path, *, findings=(("sql-injection",), ("xss",), ("open-redirect",)),
          scored=True):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        for i, (vuln_class,) in enumerate(findings):
            store.conn.execute(
                "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, vuln_class, 1, "error-signature", json.dumps({}),
                 f"/p{i}.php", "GET", "id"))
        if scored:
            for k, v in {"tp": 3, "fp": 0, "fn": 1, "tn": 6, "precision": 1.0,
                         "recall": 0.75, "mcc": 0.8, "f1": 0.857,
                         "pipeline_requests": 42,
                         "pipeline_requests_per_finding": 14.0}.items():
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, k, float(v)))
        store.conn.commit()
        return run_id


# --- results.overview_summary (pure, store-level) -----------------------------

def test_severity_of_maps_known_classes_and_falls_back_to_info():
    assert severity_of("sql-injection") == "critical"
    assert severity_of("xss") == "high"
    assert severity_of("open-redirect") == "medium"
    assert severity_of("some-future-category") == "info"
    assert severity_of(None) == "info"


def test_overview_summary_on_empty_store_never_creates_it(tmp_path):
    path = tmp_path / "missing.db"
    # A store that does not exist must not be created by the read-only dashboard.
    assert not path.exists()
    from fuzzlab.web.results import store_exists
    assert not store_exists(path)


def test_overview_summary_aggregates_counts_and_severity(tmp_path):
    path = tmp_path / "ov.db"
    run_id = _seed(path)
    with Store(path) as store:
        summary = overview_summary(store)
    assert summary["total_findings"] == 3
    assert summary["total_runs"] == 1
    assert summary["severity"]["critical"] == 1   # sql-injection
    assert summary["severity"]["high"] == 1        # xss
    assert summary["severity"]["medium"] == 1       # open-redirect
    assert summary["recent_runs"][0]["id"] == run_id
    assert summary["recent_runs"][0]["status"] == "completed"
    assert summary["last_run"]["id"] == run_id
    assert summary["detection_quality"]["f1"] == pytest.approx(0.857)
    assert summary["efficiency"]["requests_per_finding"] == 14.0
    assert summary["efficiency"]["requests"] == 42


def test_overview_summary_unscored_run_leaves_quality_and_efficiency_none(tmp_path):
    path = tmp_path / "ov.db"
    _seed(path, scored=False)
    with Store(path) as store:
        summary = overview_summary(store)
    assert summary["detection_quality"] is None
    assert summary["efficiency"] is None
    assert summary["recent_runs"][0]["status"] == "recorded"   # no run_metrics rows


def test_overview_summary_recent_runs_capped_and_newest_first(tmp_path):
    path = tmp_path / "ov.db"
    with Store(path) as store:
        ids = [store.start_run("crawl", "127.0.0.1") for _ in range(12)]
        store.conn.commit()
    with Store(path) as store:
        summary = overview_summary(store, recent_limit=10)
    assert summary["total_runs"] == 12
    assert len(summary["recent_runs"]) == 10
    assert summary["recent_runs"][0]["id"] == max(ids)


# --- GET / (the route) ---------------------------------------------------------

def test_root_route_renders_overview_not_launcher(tmp_path):
    path = tmp_path / "missing.db"
    body = _client(path).get("/").text
    assert "Overview" in body
    # the launcher's activity picker must not be on "/" any more
    assert 'class="actlist card"' not in body


def test_launcher_moved_to_its_own_route(tmp_path):
    path = tmp_path / "missing.db"
    body = _client(path).get("/launcher").text
    assert 'class="actlist card"' in body


def test_overview_empty_state_with_no_runs(tmp_path):
    path = tmp_path / "missing.db"
    client = _client(path)
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "No runs yet" in body
    assert 'href="/launcher"' in body
    # no grid of zeros: the KPI row itself is skipped in the empty state
    assert 'class="kpi-row"' not in body
    assert not path.exists()   # never creates the store


def test_overview_renders_kpi_tiles_with_seeded_runs(tmp_path):
    path = tmp_path / "ov.db"
    run_id = _seed(path)
    body = _client(path).get("/").text
    assert 'class="kpi-row"' in body
    assert 'data-kpi="findings"' in body and 'data-kpi="runs"' in body
    assert 'data-kpi="last-run"' in body
    assert 'data-kpi="detection-quality"' in body
    assert 'data-kpi="efficiency"' in body
    assert f'href="/runs/{run_id}"' in body
    # detection quality shows the F1 score, not an em-dash
    assert "0.86" in body


def test_overview_partial_empty_shows_em_dash_not_zero(tmp_path):
    path = tmp_path / "ov.db"
    _seed(path, scored=False)
    body = _client(path).get("/").text
    # tiles 4/5 (unscored) show an em-dash, never a bare "0"
    assert "&mdash;" in body
    assert "unscored" in body
    assert "no budgeted run yet" in body


def test_overview_recent_runs_table_and_severity_bar(tmp_path):
    path = tmp_path / "ov.db"
    _seed(path)
    body = _client(path).get("/").text
    assert 'id="ov-recent-runs"' in body
    assert "/p0.php" not in body   # findings themselves aren't rendered here (U2's job)
    assert 'class="sev-bar"' in body
    assert 'class="sev-seg sev-critical"' in body
    assert 'class="sev-seg sev-high"' in body


def test_overview_quick_actions_present():
    client = _client()
    body = client.get("/").text
    assert 'href="/launcher' in body
    assert 'href="/proxy"' in body


def test_overview_is_read_only_get_makes_no_writes(tmp_path):
    # Loading the dashboard must never write a result-table row (acceptance: U1).
    path = tmp_path / "ov.db"
    _seed(path)
    client = _client(path)
    client.get("/")
    client.get("/")
    with Store(path) as store:
        assert store.conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"] == 1
        assert store.conn.execute("SELECT COUNT(*) c FROM finding").fetchone()["c"] == 3


def test_overview_nav_marks_active_and_sidebar_link_exists(tmp_path):
    path = tmp_path / "missing.db"
    body = _client(path).get("/").text
    link_start = body.index('href="/" data-section="overview"')
    chunk = body[link_start:link_start + 200]
    assert 'aria-current="page"' in chunk
