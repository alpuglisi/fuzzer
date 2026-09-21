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
    store.conn.execute(
        "INSERT OR IGNORE INTO model (name, version, feature_version, calibration) "
        "VALUES ('logistic',1,1,'{}')")
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
        assert rep["plugins"] == [{"name": "sample", "version": "1.0", "priority": 10}]
        repro = rep["reproducibility"]
        assert repro["feature_versions"] == [1] and repro["model_versions"] == {"logistic": 1}
        assert repro["plugins"] == {"sample": "1.0"} and repro["schema_version"] >= 10


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
