"""Phase 7 T7.2: pointwise ranker, migration 7, train_and_rank + persistence."""

import json

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.ml.rank_train import train_and_rank
from fuzzlab.ml.ranker import Ranker
from fuzzlab.ml.text_features import candidate_text


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


def _seed_rank(store, pages=12):
    run_id = store.start_run("auto", "127.0.0.1:8080")
    for i in range(pages):
        path = f"/p{i}.php"
        _cand(store, run_id, path, "id", "sql-injection", sink="html")   # positive
        _cand(store, run_id, path, "q", "xss")
        _cand(store, run_id, path, "lang", "xss")
        _cand(store, run_id, path, "sort", "sql-injection")              # sqli, no sink
        _finding(store, run_id, path, "id", "sqli")                      # confirm the 'id'
    store.conn.commit()
    return run_id


# --- migration 7 -------------------------------------------------------------
def test_migration_7_adds_rank_columns(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 7
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(candidate)")}
        assert {"rank_score", "rank_uncertainty"} <= cols


# --- the ranker --------------------------------------------------------------
def test_ranker_scores_positive_above_negative():
    structural = [[1, 0, 1, 1, 0, 2, 1, 0, 0, 0, 2],    # has_sink + cat_sqli + name_id
                  [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1]]    # xss, no sink
    texts = ["id /p.php sql-injection get", "q /p.php xss get"]
    r = Ranker().fit(structural * 5, texts * 5, [1, 0] * 5)
    s_pos, s_neg = r.score(structural, texts)
    assert s_pos > s_neg


def test_ranker_explanation_lists_named_contributions():
    structural = [[1, 0, 1, 1, 0, 2, 1, 0, 0, 0, 2],
                  [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1]]
    texts = ["id /p.php sql-injection get", "q /p.php xss get"]
    r = Ranker().fit(structural * 5, texts * 5, [1, 0] * 5)
    exp = r.explain(structural[0], texts[0], top=3)
    assert 0.0 <= exp.score <= 1.0
    assert len(exp.contributions) == 3
    assert all(isinstance(name, str) for name, _ in exp.contributions)


# --- train_and_rank ----------------------------------------------------------
def test_train_and_rank_beats_random_and_persists(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rank(store)
        result = train_and_rank(store, run_id)
        assert result["model"] == "ranker" and result["fallback"] is False
        # the ranker beats a random ordering on held-out pages
        assert result["ndcg"] > result["baseline_ndcg"]
        assert result["beats_baseline"] is True
        # advisory rank scores written to every candidate (never labels)
        n_ranked = store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND rank_score IS NOT NULL",
            (run_id,)).fetchone()["c"]
        assert n_ranked == 48
        # a model row + the rank metrics are persisted
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM model WHERE name='ranker'").fetchone()["c"] == 1
        keys = {r["key"] for r in store.conn.execute(
            "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}
        assert {"rank_ndcg", "rank_ndcg_random"} <= keys
        # ML wrote no findings (oracle/advisory split holds)
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"] == 12


def test_rank_uncertainty_peaks_at_the_boundary(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed_rank(store)
        train_and_rank(store, run_id)
        rows = store.conn.execute(
            "SELECT rank_score s, rank_uncertainty u FROM candidate WHERE run_id=?",
            (run_id,)).fetchall()
        for r in rows:
            assert 0.0 <= r["u"] <= 1.0
            assert r["u"] == round(1.0 - abs(2.0 * r["s"] - 1.0), 6)  # max at s=0.5


def test_train_and_rank_falls_back_when_thin(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _cand(store, run_id, "/a.php", "id", "sql-injection")
        _cand(store, run_id, "/b.php", "q", "xss")
        store.conn.commit()
        result = train_and_rank(store, run_id)
        assert result["fallback"] is True and result["model"] == "rank-prevalence-fallback"
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND rank_score IS NOT NULL",
            (run_id,)).fetchone()["c"] == 2
        assert store.conn.execute("SELECT COUNT(*) c FROM model").fetchone()["c"] == 1


def test_candidate_texts_align_with_ids(tmp_path):
    # a sanity check that the text builder maps evidence to lowercased text
    ev = {"param": "Redirect", "url": "http://h/Go.php", "category": "open-redirect",
          "method": "GET"}
    assert candidate_text(ev) == "redirect /go.php open-redirect get"
