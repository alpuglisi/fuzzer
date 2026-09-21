"""Tests for the control panel's store-backed results review (D11)."""

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.results import list_runs, run_detail  # noqa: E402


def _seed(path):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sqli", 1, "error-signature", json.dumps({"dbms": "MySQL"}),
             "/product.php", "GET", "id"))
        for fired in (1, 1, 0, 0, 0):        # 2 fired, 3 negatives
            store.conn.execute(
                "INSERT INTO evaluation (run_id, url, method, param, location, rule_id, "
                "category, transaction_type, fired) VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, "/product.php", "GET", "id", "query", "R-SQLI-PARAM",
                 "sql-injection", "SQL Injection", fired))
        store.conn.execute(
            "INSERT INTO target (run_id, base_url, dbms, framework, waf, fingerprint) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, "http://127.0.0.1:8080", "MySQL", "PHP/8.3", None, "{}"))
        for k, v in {"tp": 4, "fp": 0, "fn": 4, "tn": 8,
                     "pipeline_requests": 57}.items():
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, k, float(v)))
        store.conn.commit()
        return run_id


def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return TestClient(create_app(cfg))


def test_results_functions_read_the_store(tmp_path):
    path = tmp_path / "r.db"
    run_id = _seed(path)
    with Store(path) as store:
        runs = list_runs(store)
        assert runs and runs[0]["id"] == run_id and runs[0]["findings"] == 1
        detail = run_detail(store, run_id)
        assert detail["counts"]["negatives"] == 3 and detail["counts"]["candidates"] == 0
        assert detail["score"] == {"tp": 4.0, "fp": 0.0, "fn": 4.0, "tn": 8.0}
        assert detail["target_fingerprint"]["framework"] == "PHP/8.3"
        assert detail["findings"][0]["vuln_class"] == "sqli"


def test_api_runs_lists_runs(tmp_path):
    path = tmp_path / "r.db"
    run_id = _seed(path)
    data = _client(path).get("/api/runs").json()
    assert any(r["id"] == run_id and r["findings"] == 1 for r in data["runs"])


def test_api_run_detail_and_404(tmp_path):
    path = tmp_path / "r.db"
    run_id = _seed(path)
    client = _client(path)
    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["score"]["fp"] == 0.0 and detail["counts"]["negatives"] == 3
    assert client.get("/api/runs/9999").status_code == 404


def test_run_html_page_renders_findings(tmp_path):
    path = tmp_path / "r.db"
    run_id = _seed(path)
    r = _client(path).get(f"/runs/{run_id}")
    assert r.status_code == 200
    body = r.text
    assert "/product.php" in body and "error-signature" in body
    assert "TP=4" in body and "FP=0" in body


def test_index_shows_runs_table(tmp_path):
    path = tmp_path / "r.db"
    _seed(path)
    body = _client(path).get("/").text
    assert "Review runs" in body and "/runs/1" in body


def test_run_page_surfaces_model_scores(tmp_path):
    from fuzzlab.ml.train import train_and_score
    path = tmp_path / "r.db"
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        for i in range(8):
            ev = json.dumps({"url": f"http://h/p{i}.php", "param": "id",
                             "category": "sql-injection", "method": "GET",
                             "location": "query"})
            store.conn.execute(
                "INSERT INTO candidate (run_id, rule, evidence, sink_context) "
                "VALUES (?,?,?,?)", (run_id, "sql-injection", ev, "html" if i < 3 else None))
        store.conn.commit()
        train_and_score(store, run_id)                 # thin -> fallback, still scores
    r = _client(path).get(f"/runs/{run_id}")
    assert r.status_code == 200
    body = r.text
    assert "Model scores (advisory)" in body           # the panel surfaces scores
    assert "/p0.php" in body


def test_panel_without_store_shows_no_runs(tmp_path):
    # A store that does not exist must not be created by the read-only panel.
    path = tmp_path / "missing.db"
    client = _client(path)
    assert client.get("/api/runs").json()["runs"] == []
    assert not path.exists()
    assert "No runs recorded yet" in client.get("/").text
