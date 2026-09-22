"""Tests for the Overview dashboard route (U1, D11): landing route at ``/``.

Per the R-09 test-strategy note (docs/UI_IMPLEMENTATION_PLAN.md), these assert
``response.template.name``/``response.context`` rather than matching HTML strings,
covering both the empty-store onboarding state and the seeded-runs aggregate.
"""

import json

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

from ._web_client import web_client  # noqa: E402


def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return web_client(create_app(cfg))


def _seed_unscored(path):
    """One run, two findings (one critical-mapped, one info-mapped), no scoring
    metrics at all — the "partial-empty" (unscored) case."""
    with Store(path) as store:
        run_id = store.start_run("audit", "127.0.0.1:8080")
        for vuln_class in ("sqli", "open-redirect"):
            store.conn.execute(
                "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, vuln_class, 1, "error-signature", json.dumps({}),
                 "/product.php", "GET", "id"))
        store.conn.commit()
        return run_id


def _seed_scored(path):
    """Two runs: an older unscored one, and a newer one the harness scored
    (f1/mcc + requests-per-finding present) — the fully-populated case."""
    with Store(path) as store:
        older_id = store.start_run("crawl", "127.0.0.1:8080")
        newer_id = store.start_run("auto", "127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (newer_id, "sqli", 1, "error-signature", json.dumps({}),
             "/product.php", "GET", "id"))
        for k, v in {"f1": 0.8, "mcc": 0.75, "tp": 4, "fp": 1,
                     "pipeline_requests_per_finding": 12.5,
                     "pipeline_requests": 50}.items():
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (newer_id, k, float(v)))
        store.conn.commit()
        return older_id, newer_id


def test_overview_route_is_the_landing_route_and_no_store_shows_onboarding(tmp_path):
    # A store that does not exist must not be created by the read-only panel.
    path = tmp_path / "missing.db"
    r = _client(path).get("/")
    assert r.status_code == 200
    assert r.template.name == "sections/overview.html"
    assert r.context["active"] == "overview"
    assert r.context["has_store"] is False
    assert r.context["kpi"] is None
    assert r.context["recent_runs"] == []
    assert not path.exists()


def test_overview_empty_store_with_zero_runs_shows_onboarding(tmp_path):
    path = tmp_path / "s.db"
    with Store(path):
        pass  # migrated, but no run rows yet
    r = _client(path).get("/")
    assert r.status_code == 200
    assert r.context["has_store"] is False
    assert r.context["kpi"] is None


def test_overview_aggregate_with_unscored_findings_is_em_dash_not_zero(tmp_path):
    path = tmp_path / "s.db"
    run_id = _seed_unscored(path)
    r = _client(path).get("/")
    assert r.status_code == 200
    kpi = r.context["kpi"]
    assert kpi["findings_total"] == 2
    assert kpi["runs_total"] == 1
    assert kpi["newest_run"]["id"] == run_id
    assert kpi["newest_run"]["findings"] == 2
    # partial-empty: no scoring metrics recorded -> None (template renders em-dash,
    # never a literal 0).
    assert kpi["detection_quality"] is None
    assert kpi["efficiency"] is None
    # severity heuristic: sqli -> Critical, open-redirect -> Low.
    severities = {b["severity"]: b["count"] for b in kpi["severity_bars"]}
    assert severities == {"Critical": 1, "Low": 1}


def test_overview_aggregate_with_scored_run(tmp_path):
    path = tmp_path / "s.db"
    older_id, newer_id = _seed_scored(path)
    r = _client(path).get("/")
    assert r.status_code == 200
    kpi = r.context["kpi"]
    assert kpi["runs_total"] == 2
    assert kpi["findings_total"] == 1
    assert kpi["newest_run"]["id"] == newer_id
    assert kpi["detection_quality"] == {"run_id": newer_id, "f1": 0.8, "mcc": 0.75}
    assert kpi["efficiency"] == {
        "run_id": newer_id, "requests_per_finding": 12.5, "total_requests": 50}
    # recent runs are newest-first, capped, and joined with their finding count
    # (no N+1: one query).
    ids = [r["id"] for r in r.context["recent_runs"]]
    assert ids == [newer_id, older_id]
    assert r.context["recent_runs"][1]["findings"] == 0


def test_overview_recent_runs_cap_at_ten(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        for i in range(15):
            store.start_run("crawl", f"127.0.0.1:{8000 + i}")
    r = _client(path).get("/")
    assert len(r.context["recent_runs"]) == 10
    assert r.context["kpi"]["runs_total"] == 15
