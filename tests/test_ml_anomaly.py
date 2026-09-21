"""Phase 10 T10.3: ECOD anomaly tripwire + the XGBOD-style hybrid feature."""

import json
import random

from fuzzlab.core.store import Store
from fuzzlab.ml.anomaly import ECOD, augment, detect_anomalies, flag_top, skewness
from fuzzlab.ml.train import train_and_score


def _cluster(n=60, seed=0):
    rng = random.Random(seed)
    return [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(n)]


# --- ECOD --------------------------------------------------------------------
def test_ecod_scores_same_direction_outliers_highest():
    data = _cluster() + [[9.0, 9.0], [-8.0, -8.0]]
    ec = ECOD().fit(data)
    scores = ec.scores(data)
    inlier_max = max(scores[:60])
    assert scores[60] > inlier_max and scores[61] > inlier_max


def test_ecod_is_deterministic():
    data = _cluster()
    ec = ECOD().fit(data)
    assert ec.scores(data) == ec.scores(data)


def test_ecod_empty_and_degenerate():
    assert ECOD().fit([]).score([1, 2]) == 0.0            # nothing fitted
    ec = ECOD().fit([[5.0], [5.0], [5.0]])                # zero-variance feature
    assert ec.score([5.0]) >= 0.0 and skewness([5, 5, 5]) == 0.0


def test_flag_top_picks_the_top_fraction():
    scores = [0.1, 0.2, 9.0, 0.15, 8.0]
    flags = flag_top(scores, contamination=0.4)           # top ~2 of 5
    assert flags[2] and flags[4] and not flags[0]


def test_augment_appends_anomaly_score():
    ec = ECOD().fit(_cluster())
    rows = augment([[0.0, 0.0], [9.0, 9.0]], ec)
    assert len(rows[0]) == 3                               # one extra feature
    assert rows[1][2] > rows[0][2]                         # the outlier scores higher


# --- store-facing detection (advisory) ---------------------------------------
def _cand(store, run_id, path, param, cat, sink=None):
    ev = json.dumps({"url": f"http://h{path}", "param": param, "category": cat,
                     "method": "GET", "location": "query"})
    store.conn.execute(
        "INSERT INTO candidate (run_id, rule, evidence, sink_context) VALUES (?,?,?,?)",
        (run_id, cat, ev, sink))


def test_detect_anomalies_is_advisory(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        for i in range(20):                                # ordinary candidates
            _cand(store, run_id, f"/p{i}.php", "id", "sql-injection")
        _cand(store, run_id, "/weird.php", "x" * 40, "xss", sink="html")  # odd one out
        store.conn.commit()
        result = detect_anomalies(store, run_id, contamination=0.1)
        assert result["rows"] == 21 and result["flagged"] >= 1
        # recorded as a metric, and NO findings were written (tripwire, not confirmer)
        m = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))}
        assert m.get("anomaly_flagged") == float(result["flagged"])
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"] == 0


def test_detect_anomalies_empty_store(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        assert detect_anomalies(store, run_id)["flagged"] == 0


# --- XGBOD-style hybrid (train_and_score hybrid=True) ------------------------
def _finding(store, run_id, path, param, vc):
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?,?,1,?,?,?,?)", (run_id, vc, "error-signature", path, "GET", param))


def test_hybrid_augments_features_and_stays_advisory(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        for i in range(10):
            _cand(store, run_id, f"/p{i}.php", "id", "sql-injection", sink="html")
            _cand(store, run_id, f"/p{i}.php", "q", "xss")
            for fired in (1, 1, 0):
                store.conn.execute(
                    "INSERT INTO evaluation (run_id, url, method, param, location, rule_id, "
                    "category, transaction_type, fired) VALUES (?,?,?,?,?,?,?,?,?)",
                    (run_id, f"/p{i}.php", "GET", "id", "query", "R-SQLI-PARAM",
                     "sql-injection", "SQL Injection", fired))
        for i in range(6):
            _finding(store, run_id, f"/p{i}.php", "id", "sqli")
        store.conn.commit()

        result = train_and_score(store, run_id, hybrid=True)
        assert result["hybrid"] is True and result["fallback"] is False
        # advisory scores written to every candidate; no labels written by ML
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND score IS NOT NULL",
            (run_id,)).fetchone()["c"] == 20
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"] == 6
