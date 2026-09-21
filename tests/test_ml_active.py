"""Phase 7 T7.3: active learning — uncertainty sampling and query-by-committee."""

import json

from fuzzlab.core.store import Store
from fuzzlab.ml.active import (Committee, disagreement, propose_queries,
                               query_by_committee, uncertainty, uncertainty_sampling)
from fuzzlab.ml.rank_train import train_and_rank


def _cand(store, run_id, path, param, cat, sink=None):
    ev = json.dumps({"url": f"http://h{path}", "param": param, "category": cat,
                     "method": "GET", "location": "query"})
    return store.conn.execute(
        "INSERT INTO candidate (run_id, rule, evidence, sink_context) VALUES (?,?,?,?)",
        (run_id, cat, ev, sink)).lastrowid


def _finding(store, run_id, path, param, vuln_class):
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?,?,1,?,?,?,?)", (run_id, vuln_class, "error-signature", path, "GET", param))


def _seed(store, pages=12):
    run_id = store.start_run("auto", "127.0.0.1:8080")
    for i in range(pages):
        p = f"/p{i}.php"
        _cand(store, run_id, p, "id", "sql-injection", sink="html")
        _cand(store, run_id, p, "q", "xss")
        _cand(store, run_id, p, "lang", "xss")
        _cand(store, run_id, p, "sort", "sql-injection")
        _finding(store, run_id, p, "id", "sqli")
    store.conn.commit()
    return run_id


# --- uncertainty -------------------------------------------------------------
def test_uncertainty_peaks_at_boundary():
    assert uncertainty(0.5) == 1.0
    assert uncertainty(0.99) < 0.1 and uncertainty(0.01) < 0.1


def test_uncertainty_sampling_picks_nearest_half():
    scores = [0.5, 0.99, 0.01, 0.6]
    assert uncertainty_sampling(scores, 2) == [0, 3]          # 0.5 then 0.6
    assert uncertainty_sampling(scores, 2, ids=[10, 11, 12, 13]) == [10, 13]


def test_uncertainty_sampling_budget_bounds():
    assert uncertainty_sampling([0.5, 0.5], 0) == []
    assert len(uncertainty_sampling([0.5, 0.6, 0.7], 10)) == 3   # budget > n


# --- query-by-committee ------------------------------------------------------
def test_disagreement_and_query_by_committee():
    members = [[0.9, 0.5, 0.1],
               [0.9, 0.1, 0.1],
               [0.9, 0.9, 0.1]]                                # item 1 varies most
    dis = disagreement(members)
    assert dis[1] > dis[0] and dis[1] > dis[2]
    assert query_by_committee(members, 1) == [1]
    assert query_by_committee(members, 1, ids=[7, 8, 9]) == [8]


def test_committee_trains_members_and_scores(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        from fuzzlab.ml.dataset import build_dataset
        from fuzzlab.ml.rank_train import _candidate_texts
        ds = build_dataset(store, run_id)
        texts = _candidate_texts(store, run_id, ds.ids)
        com = Committee(n_members=4, seed=1).fit(ds.X, texts, ds.y)
        ms = com.member_scores(ds.X, texts)
        assert len(ms) == 4 and all(len(row) == len(ds) for row in ms)
        assert all(0.0 <= v <= 1.0 for row in ms for v in row)


# --- store-facing proposal ---------------------------------------------------
def test_propose_uncertainty_reads_rank_uncertainty(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        train_and_rank(store, run_id)                        # writes rank_uncertainty
        ids = propose_queries(store, run_id, budget=5, method="uncertainty")
        assert len(ids) == 5
        # returned in descending uncertainty order
        us = [store.conn.execute(
            "SELECT rank_uncertainty u FROM candidate WHERE id=?", (i,)).fetchone()["u"]
            for i in ids]
        assert us == sorted(us, reverse=True)


def test_propose_committee_returns_budget_ids(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = _seed(store)
        ids = propose_queries(store, run_id, budget=6, method="committee", n_members=4)
        assert len(ids) == 6
        all_ids = {r["id"] for r in store.conn.execute(
            "SELECT id FROM candidate WHERE run_id=?", (run_id,))}
        assert set(ids) <= all_ids                           # valid candidate ids
