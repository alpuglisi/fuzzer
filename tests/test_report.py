"""Phase 10 T10.4: the reproducible evaluation report."""

import json

from fuzzlab.core.store import Store
from fuzzlab.report import build_report, format_json, format_text
from fuzzlab.report.cli import main as report_main


def _seed(store) -> int:
    run_id = store.start_run("auto", "127.0.0.1:8080")
    store.conn.execute(
        "INSERT INTO target (run_id, base_url, dbms, framework, waf, fingerprint) "
        "VALUES (?,?,?,?,?,?)", (run_id, "http://127.0.0.1:8080", "MySQL", "PHP", None, "{}"))
    for i in range(3):
        store.conn.execute(
            "INSERT INTO candidate (run_id, rule, evidence, feature_version) VALUES (?,?,?,?)",
            (run_id, "sqli", "{}", 1))
    store.conn.execute(
        "INSERT INTO evaluation (run_id, url, method, param, location, rule_id, category, "
        "transaction_type, fired) VALUES (?,?,?,?,?,?,?,?,1)",
        (run_id, "/p.php", "GET", "id", "query", "R-SQLI", "sql-injection", "SQL Injection"))
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?,?,1,?,?,?,?)", (run_id, "sqli", "error-signature", "/p.php", "GET", "id"))
    store.conn.execute(
        "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)", (run_id, "tp", 4.0))
    store.conn.execute(
        "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)", (run_id, "fp", 0.0))
    # scoped to the run, as every production trainer writes it (a scope-less legacy row
    # now covers only a run holding stored scores — BUG-0074)
    store.conn.execute(
        "INSERT OR IGNORE INTO model (name, version, feature_version, calibration) "
        "VALUES ('logistic',1,1,?)", (json.dumps({"run_id": run_id}),))
    store.conn.execute(
        "INSERT INTO run_plugin (run_id, name, version, priority) VALUES (?,?,?,?)",
        (run_id, "sample", "1.0", 10))
    store.conn.commit()
    return run_id


def test_build_report_captures_the_run(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        rep = build_report(store, run_id)
        assert rep["run"]["id"] == run_id and rep["run"]["tool"] == "auto"
        assert rep["target"]["dbms"] == "MySQL"
        assert rep["counts"]["candidates"] == 3 and rep["counts"]["findings"] == 1
        assert rep["counts"]["evaluations_fired"] == 1
        assert rep["metrics"] == {"tp": 4.0, "fp": 0.0}
        assert rep["findings"][0]["vuln_class"] == "sqli"
        assert {"name": "logistic", "version": 1, "feature_version": 1} in rep["models"]
        # a legacy (pre-migration-15) plugin row: config/status/error read NULL
        assert rep["plugins"] == [{"name": "sample", "version": "1.0", "priority": 10,
                                   "config": None, "status": None, "error": None}]
        repro = rep["reproducibility"]
        # per counter since BUG-0069 (report JSON contract change, CC-UI-0047)
        assert repro["feature_versions"] == {"candidate": [1], "flow": []}
        assert repro["model_versions"] == {"logistic": 1}
        assert repro["plugins"] == {"sample": "1.0"} and repro["schema_version"] >= 10
        assert repro["plugin_config"] == {"sample": None}       # CC-UI-0041 siblings
        assert repro["plugin_status"] == {"sample": None}
        assert "models_unavailable" not in rep


def test_report_json_is_deterministic(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        a = format_json(build_report(store, run_id))
        b = format_json(build_report(store, run_id))
        assert a == b                                   # byte-identical
        parsed = json.loads(a)
        assert parsed["counts"]["findings"] == 1        # valid JSON round-trips


def test_build_report_defaults_to_latest_run(tmp_path):
    with Store(tmp_path / "u.db") as store:
        _seed(store)
        second = _seed(store)                           # a newer run
        assert build_report(store)["run"]["id"] == second


def test_empty_store(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert build_report(store) == {"run": None}
        assert format_text({"run": None}) == "no runs in the store"


def test_format_text_summarizes(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        text = format_text(build_report(store, run_id))
        assert "fuzzlab run #" in text and "1 finding(s)" in text
        assert "metric tp = 4.0" in text and "logistic v1" in text
        assert "sqli GET /p.php [id]" in text


def test_cli_prints_report(tmp_path, capsys):
    db = tmp_path / "u.db"
    with Store(db) as store:
        _seed(store)
    assert report_main(["--store", str(db)]) == 0
    assert "fuzzlab run #" in capsys.readouterr().out
    assert report_main(["--store", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["findings"] == 1


# --- BUG-0069: feature versions come from what the run's stages actually read ----------

def test_feature_versions_come_from_production_writers_only(tmp_path):
    """Seeded only through production writers (PA-0071): no hand-written
    `candidate.feature_version`."""
    from fuzzlab.ml.anomaly import detect_anomalies
    from fuzzlab.ml.rank_train import train_and_rank
    from fuzzlab.ml.train import train_and_score
    from tests.test_ml_train import _seed_rich
    with Store(tmp_path / "f.db") as store:
        plain = _seed_rich(store)                         # no ML stage ran
        assert build_report(store, plain)["reproducibility"]["feature_versions"] == \
            {"candidate": [], "flow": []}
        trained = _seed_rich(store)
        train_and_score(store, trained)
        train_and_rank(store, trained)
        rep = build_report(store, trained)
        assert rep["reproducibility"]["feature_versions"] == {"candidate": [1], "flow": []}
        assert "feature versions: candidate [1], flow —" in format_text(rep)
        anomaly_only = _seed_rich(store)
        detect_anomalies(store, anomaly_only)
        assert build_report(store, anomaly_only)["reproducibility"]["feature_versions"][
            "candidate"] == [1]
        detect_anomalies(store, plain, persist=False)    # a read-only refit records nothing
        assert build_report(store, plain)["reproducibility"]["feature_versions"][
            "candidate"] == []


def test_flow_and_budget_stages_record_their_versions(tmp_path):
    from fuzzlab.ml.flow_anomaly import FLOW_FEATURE_VERSION, detect_flow_anomalies
    with Store(tmp_path / "g.db") as store:
        r = store.start_run("proxy", "h")
        for i in range(5):
            store.conn.execute("INSERT INTO flow (run_id, method, url, host, status) "
                               "VALUES (?,?,?,?,?)", (r, "GET", f"http://a/p{i}", "a", 200))
        store.conn.commit()
        detect_flow_anomalies(store, r)
        detect_flow_anomalies(store, r)                  # a rerun replaces, never duplicates
        assert store.conn.execute(
            "SELECT COUNT(*) FROM run_metrics WHERE run_id=? AND "
            "key='flow_anomaly_feature_version'", (r,)).fetchone()[0] == 1
        assert build_report(store, r)["reproducibility"]["feature_versions"] == \
            {"candidate": [], "flow": [FLOW_FEATURE_VERSION]}


def test_the_budget_prioritizer_reports_its_feature_version(tmp_path):
    from fuzzlab.ml.active import prioritize
    from tests.test_ml_budget_and_scope import _current_run, _prior_runs
    with Store(tmp_path / "b.db") as store:
        _prior_runs(store)
        run_id, ids = _current_run(store)
        assert prioritize(store, run_id, ids).feature_version == 1
        assert prioritize(store, run_id, ids, method="random").feature_version is None
