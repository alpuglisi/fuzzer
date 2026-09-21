"""Tests for Phase 5 T5.2/T5.3: store dataset assembly, training, scoring, persistence."""

import json

from fuzzlab.core.store import Store
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.train import train_and_score


def _cand(store, run_id, path, param, cat, sink=None):
    ev = json.dumps({"url": f"http://h{path}", "param": param, "category": cat,
                     "method": "GET", "location": "query"})
    cur = store.conn.execute(
        "INSERT INTO candidate (run_id, rule, evidence, sink_context) VALUES (?,?,?,?)",
        (run_id, cat, ev, sink))
    return cur.lastrowid


def _finding(store, run_id, path, param, vuln_class):
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?,?,1,?,?,?,?)", (run_id, vuln_class, "error-signature", path, "GET", param))


def _seed_rich(store):
    run_id = store.start_run("auto", "127.0.0.1:8080")
    for i in range(10):
        _cand(store, run_id, f"/p{i}.php", "id", "sql-injection", sink="html" if i < 6 else None)
        _cand(store, run_id, f"/p{i}.php", "id", "xss")
        for fired in (1, 1, 0):
            store.conn.execute(
                "INSERT INTO evaluation (run_id, url, method, param, location, rule_id, "
                "category, transaction_type, fired) VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, f"/p{i}.php", "GET", "id", "query", "R-SQLI-PARAM",
                 "sql-injection", "SQL Injection", fired))
    for i in range(6):                       # sqli confirmed on p0..p5
        _finding(store, run_id, f"/p{i}.php", "id", "sqli")
    store.conn.commit()
    return run_id


def test_build_dataset_labels_and_groups(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rich(store)
        ds = build_dataset(store, run_id)
        assert len(ds) == 20 and ds.positives == 6        # 6 confirmed sqli candidates
        assert set(ds.groups) == {f"/p{i}.php" for i in range(10)}   # grouped by endpoint
        assert len(ds.feature_names) == len(ds.X[0])


def test_train_and_score_writes_scores_model_and_metrics(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rich(store)
        result = train_and_score(store, run_id)
        assert result["model"] == "logistic" and result["fallback"] is False
        assert "pr_auc" in result and "beats_baselines" in result
        # advisory scores written to every candidate (never labels)
        n_scored = store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND score IS NOT NULL",
            (run_id,)).fetchone()["c"]
        assert n_scored == 20
        # a model row + the honest metric are persisted
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM model WHERE name='logistic'").fetchone()["c"] == 1
        keys = {r["key"] for r in store.conn.execute(
            "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}
        assert "ml_pr_auc" in keys and "ml_pr_auc_prevalence" in keys
        # no findings were written by ML (oracle/advisory split holds)
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"] == 6


def test_train_and_score_with_gbt(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rich(store)
        result = train_and_score(store, run_id, model_kind="gbt")
        assert result["model"] == "gbt" and result["fallback"] is False
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM model WHERE name='gbt'").fetchone()["c"] == 1
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND score IS NOT NULL",
            (run_id,)).fetchone()["c"] == 20


def test_train_and_score_auto_selects_a_model(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rich(store)
        result = train_and_score(store, run_id, model_kind="auto")
        assert result["model"] in ("logistic", "gbt")          # deployed the OOF winner
        assert set(result["model_selection"]) == {"logistic", "gbt"}   # both compared
        assert result["model"] == max(result["model_selection"],
                                       key=lambda m: result["model_selection"][m])


def test_train_and_score_falls_back_when_thin(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _cand(store, run_id, "/a.php", "id", "sql-injection")
        _cand(store, run_id, "/b.php", "q", "xss")
        store.conn.commit()
        result = train_and_score(store, run_id)
        assert result["fallback"] is True and result["model"] == "prevalence-fallback"
        # scores still written; a model row persisted
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND score IS NOT NULL",
            (run_id,)).fetchone()["c"] == 2
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM model").fetchone()["c"] == 1
