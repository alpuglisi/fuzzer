"""Tests for the R1 Overview dashboard (FR-UI-9, docs/UI_LAYOUT_REDESIGN.md).

Covers the pure aggregate (``results.overview_summary``) and the ``/`` route that
renders it, real data wiring (no mock data) and safe empty-store rendering
(NFR-UI-read-only: never creates a store that doesn't exist).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.results import overview_summary  # noqa: E402


def _seed(path, n_findings=2, with_metrics=True):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        for i in range(n_findings):
            store.conn.execute(
                "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, "sqli" if i == 0 else "xss", 1, "error-signature",
                 json.dumps({}), "/product.php", "GET", "id"))
        if with_metrics:
            for k, v in {"tp": 2, "fp": 0, "fn": 0, "tn": 2, "precision": 1.0,
                         "recall": 1.0, "f1": 1.0, "mcc": 1.0,
                         "pipeline_requests": 20, "requests_per_finding": 10.0}.items():
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, k, float(v)))
        store.conn.commit()
        return run_id


def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return TestClient(create_app(cfg))


# --- overview_summary: pure aggregate, no FastAPI --------------------------

def test_overview_summary_on_empty_store_reads_nothing(tmp_path):
    path = tmp_path / "e.db"
    with Store(path) as store:
        summary = overview_summary(store)
    assert summary == {
        "total_runs": 0, "runs_7d": 0, "total_findings": 0,
        "findings_by_category": [], "last_run": None,
        "quality": None, "efficiency": None, "recent_runs": [],
    }


def test_overview_summary_wires_real_findings_runs_and_metrics(tmp_path):
    path = tmp_path / "o.db"
    run_id = _seed(path)
    with Store(path) as store:
        summary = overview_summary(store)
    assert summary["total_runs"] == 1
    assert summary["runs_7d"] == 1                       # just started -> within 7d
    assert summary["total_findings"] == 2
    cats = {c["category"]: c["count"] for c in summary["findings_by_category"]}
    assert cats == {"sqli": 1, "xss": 1}
    assert summary["last_run"]["id"] == run_id
    assert summary["quality"] == {"run_id": run_id, "f1": 1.0, "mcc": 1.0}
    assert summary["efficiency"]["requests_per_finding"] == 10.0
    assert summary["efficiency"]["pipeline_requests"] == 20.0
    assert summary["recent_runs"][0]["id"] == run_id


def test_overview_summary_unscored_run_leaves_quality_and_efficiency_none(tmp_path):
    path = tmp_path / "u.db"
    _seed(path, with_metrics=False)
    with Store(path) as store:
        summary = overview_summary(store)
    assert summary["total_findings"] == 2
    assert summary["quality"] is None
    assert summary["efficiency"] is None


def test_overview_summary_recent_limit_bounds_the_slice(tmp_path):
    path = tmp_path / "m.db"
    with Store(path) as store:
        for _ in range(3):
            store.start_run("auto", "127.0.0.1:8080")
        store.conn.commit()
        summary = overview_summary(store, recent_limit=2)
    assert summary["total_runs"] == 3
    assert len(summary["recent_runs"]) == 2


# --- "/" route: real data wiring, not mock/placeholder ---------------------

def test_overview_route_renders_with_no_store_at_all(tmp_path):
    # A store that does not exist must not be created by the read-only dashboard.
    path = tmp_path / "missing.db"
    client = _client(path)
    body = client.get("/").text
    assert not path.exists()
    assert "No runs yet" in body
    assert "unscored" in body           # em-dash tiles, never a bare 0 (R-10)
    assert "no metrics yet" in body


def test_overview_route_shows_real_kpis_and_recent_run(tmp_path):
    path = tmp_path / "o.db"
    run_id = _seed(path)
    body = _client(path).get("/").text
    assert f'href="/runs/{run_id}"' in body     # last run + recent-runs both link through
    assert "sqli" in body and "xss" in body     # findings-by-category chips
    assert "1.00" in body                        # F1 formatted
    assert "10.0" in body                        # requests/finding
    assert "All runs" in body and 'href="/runs"' in body


def test_overview_route_quick_actions_link_to_launch_and_proxy(tmp_path):
    body = _client(tmp_path / "missing2.db").get("/").text
    assert 'href="/launch"' in body and 'href="/proxy"' in body
