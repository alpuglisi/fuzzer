"""Dataset scope (BUG-0065), budget-skipped candidates, the budget prioritizer, and the
persisted anomaly tripwire (CC-ML-0013 / CC-ML-0014, FR-ML-11 / FR-ML-12)."""

from __future__ import annotations

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.ml.active import BUDGET_METHODS, prioritize, propose_queries
from fuzzlab.ml.anomaly import detect_anomalies
from fuzzlab.ml.dataset import SKIPPED_BUDGET, build_dataset
from fuzzlab.ml.rank_train import train_and_rank
from fuzzlab.ml.train import train_and_score
from fuzzlab.web import mlview
from tests.test_ml_train import _cand, _finding, _seed_rich

TARGET = "http://127.0.0.1:8080"


def _evaluation(store, run_id, path, param, fired=1):
    store.conn.execute(
        "INSERT INTO evaluation (run_id, url, method, param, location, rule_id, category, "
        "transaction_type, fired) VALUES (?,?,?,?,?,?,?,?,?)",
        (run_id, path, "GET", param, "query", "R", "sql-injection", "x", fired))


def _target(store, run_id, base_url=TARGET):
    store.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (run_id, base_url))
    store.conn.commit()


def _skip(store, ids):
    store.conn.executemany("UPDATE candidate SET oracle_status=? WHERE id=?",
                           [(SKIPPED_BUDGET, i) for i in ids])
    store.conn.commit()


# --- migration 13 -------------------------------------------------------------

def test_migration_13_adds_the_candidate_columns(tmp_path):
    with Store(tmp_path / "m.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 13
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(candidate)")}
        assert {"oracle_status", "anomaly_score", "anomaly_flag"} <= cols


# --- BUG-0065: labels and rule counts never cross runs -----------------------

def test_store_wide_dataset_takes_labels_and_counts_from_each_rows_own_run(tmp_path):
    with Store(tmp_path / "a.db") as store:
        r1, r2 = store.start_run("auto", "h"), store.start_run("auto", "h")
        for r in (r1, r2):
            _cand(store, r, "/p.php", "id", "sql-injection")
            _evaluation(store, r, "/p.php", "id")
        _finding(store, r1, "/p.php", "id", "sqli")          # only run 1 confirmed it
        store.conn.commit()
        per_run = [build_dataset(store, r) for r in (r1, r2)]
        everything = build_dataset(store, None)
        # store-wide == the per-run datasets concatenated (labels AND features)
        assert everything.y == per_run[0].y + per_run[1].y == [1, 0]
        assert everything.X == per_run[0].X + per_run[1].X
        assert [x[-1] for x in everything.X] == [1.0, 1.0]  # rules_fired: own run only


def test_store_wide_dataset_never_labels_across_targets(tmp_path):
    with Store(tmp_path / "a.db") as store:
        a, b = store.start_run("auto", "a:1"), store.start_run("auto", "b:2")
        _cand(store, a, "/index.php", "id", "sql-injection")
        _cand(store, b, "/index.php", "id", "sql-injection")
        _finding(store, a, "/index.php", "id", "sqli")
        store.conn.commit()
        assert build_dataset(store, None).y == [1, 0]


# --- budget-skipped candidates: never trained on, still scored ----------------

def test_skipped_rows_are_excluded_from_training_but_included_when_asked(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        all_ids = build_dataset(store, run_id).ids
        _skip(store, all_ids[:4])
        trained_on = build_dataset(store, run_id)
        assert trained_on.ids == all_ids[4:] and all(trained_on.labelled)
        every = build_dataset(store, run_id, include_unlabelled=True)
        assert every.ids == all_ids
        assert every.labelled == [False] * 4 + [True] * (len(all_ids) - 4)
        assert every.positives == trained_on.positives      # placeholders never count


def test_trainers_score_and_rank_skipped_candidates_too(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        ids = build_dataset(store, run_id).ids
        _skip(store, ids[-3:])
        assert train_and_score(store, run_id)["scored"] == len(ids)
        assert train_and_rank(store, run_id)["ranked"] == len(ids)
        rows = store.conn.execute(
            "SELECT score, rank_score FROM candidate WHERE oracle_status=?",
            (SKIPPED_BUDGET,)).fetchall()
        assert len(rows) == 3 and all(r["score"] is not None and r["rank_score"] is not None
                                      for r in rows)


def test_hybrid_scores_every_row_with_the_feature_it_trained_on(tmp_path, monkeypatch):
    from fuzzlab.ml import anomaly as anomaly_mod
    fits = []
    real_fit = anomaly_mod.ECOD.fit

    def counting_fit(self, X):
        fits.append(len(X))
        return real_fit(self, X)
    monkeypatch.setattr(anomaly_mod.ECOD, "fit", counting_fit)
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        ids = build_dataset(store, run_id).ids
        _skip(store, ids[-3:])
        result = train_and_score(store, run_id, hybrid=True)
        assert result["scored"] == len(ids)
    assert fits == [len(ids)]          # ONE detector, fit on every row, used for both sets


# --- the prioritizer -----------------------------------------------------------

def _prior_runs(store, n=2, target=TARGET):
    runs = []
    for _ in range(n):
        r = _seed_rich(store)
        _target(store, r, target)
        runs.append(r)
    return runs


def _current_run(store, target=TARGET):
    run_id = store.start_run("auto", "127.0.0.1:8080")
    ids = [_cand(store, run_id, f"/q{i}.php", "id", "sql-injection",
                 sink="html" if i % 3 == 0 else None) for i in range(9)]
    store.conn.commit()
    _target(store, run_id, target)
    return run_id, ids


def test_prioritize_falls_back_without_usable_earlier_labels(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id, ids = _current_run(store)
        assert prioritize(store, run_id, ids, method="score") is None     # no earlier runs
        later = _seed_rich(store)                                          # a LATER run only
        _target(store, later)
        assert prioritize(store, run_id, ids, method="score") is None
    with Store(tmp_path / "b.db") as store:
        _prior_runs(store, target="http://other:9")                       # another target
        run_id, ids = _current_run(store)
        assert prioritize(store, run_id, ids, method="score") is None
    with Store(tmp_path / "c.db") as store:
        _prior_runs(store, n=1)                                            # one-class
        store.conn.execute("DELETE FROM finding")
        store.conn.commit()
        run_id, ids = _current_run(store)
        assert prioritize(store, run_id, ids, method="committee") is None


@pytest.mark.parametrize("method", BUDGET_METHODS)
def test_prioritize_orders_exactly_the_given_ids_deterministically(tmp_path, method):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id, ids = _current_run(store)
        first = prioritize(store, run_id, ids, method=method)
        again = prioritize(store, run_id, ids, method=method)
        assert sorted(first.order) == sorted(ids) and first.order == again.order
        assert first.method == method
        if method != "random":
            assert first.training_rows == 40 and first.training_positives == 12


def test_score_puts_the_most_likely_candidates_first(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)                 # earlier runs: sqli confirmed where sink=html
        run_id, ids = _current_run(store)
        order = prioritize(store, run_id, ids, method="score").order
        html = {i for k, i in enumerate(ids) if k % 3 == 0}
        assert set(order[:len(html)]) == html


def test_prioritize_never_learns_from_the_current_run(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id, ids = _current_run(store)
        before = prioritize(store, run_id, ids, method="score").order
        for i in range(9):                                 # current-run "labels" appear
            _finding(store, run_id, f"/q{i}.php", "id", "sqli")
        store.conn.commit()
        assert prioritize(store, run_id, ids, method="score").order == before


def test_unknown_budget_method_is_rejected(tmp_path):
    with Store(tmp_path / "a.db") as store:
        with pytest.raises(ValueError):
            prioritize(store, 1, [], method="greedy")


def test_committee_query_queue_covers_skipped_candidates(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        ids = build_dataset(store, run_id).ids
        _skip(store, ids[:5])
        picked = propose_queries(store, run_id, budget=len(ids), method="committee")
        assert set(ids[:5]) <= set(picked)
        queue = mlview.disagreement_panel(store, run_id, top_n=len(ids))["queue"]
        assert set(ids[:5]) <= {q["candidate_id"] for q in queue}


# --- the anomaly tripwire, persisted ------------------------------------------

def test_detect_anomalies_persists_every_candidates_score_and_flag(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        ids = build_dataset(store, run_id).ids
        _skip(store, ids[:2])                              # label-free: scored too
        result = detect_anomalies(store, run_id, contamination=0.2)
        rows = store.conn.execute(
            "SELECT id, anomaly_score, anomaly_flag FROM candidate WHERE run_id=? ORDER BY id",
            (run_id,)).fetchall()
        assert [r["id"] for r in rows] == ids == result["ids"]
        assert [r["anomaly_score"] for r in rows] == result["scores"]
        assert sum(r["anomaly_flag"] for r in rows) == result["flagged"]
        metric = store.conn.execute(
            "SELECT value FROM run_metrics WHERE run_id=? AND key='anomaly_flagged'",
            (run_id,)).fetchone()["value"]
        assert metric == result["flagged"]
        assert mlview.anomaly_panel(store, run_id, contamination=0.2)["n"] == len(ids)


@pytest.mark.parametrize("bad", [0, -0.1, 0.51, 1.0])
def test_detect_anomalies_rejects_bad_contamination(tmp_path, bad):
    with Store(tmp_path / "a.db") as store:
        with pytest.raises(ValueError):
            detect_anomalies(store, None, contamination=bad)
