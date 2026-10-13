"""Batch 1 of the remaining ML work (CC-ML-0018, CC-CORE-0029, CC-UI-0042, BUG-0067).

- D-a: `no_confirmer` rows are unlabelled (never training negatives).
- D-b: targets match as canonical origins (loopback aliases are one target).
- D-c: run mode stores each labelled row's out-of-fold score beside the deploy score,
  and every conformal gate judges only the score it was calibrated for (BUG-0067).
- F-1: `train_on="saved"` applies a saved earlier model without retraining.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.oracle_status import NO_CONFIRMER, SKIPPED_BUDGET
from fuzzlab.core.store import Store
from fuzzlab.core.urls import canonical_origin
from fuzzlab.ml.dataset import build_dataset, target_runs
from fuzzlab.ml.rank_train import _candidate_texts, latest_ranker, load_ranker, train_and_rank
from fuzzlab.ml.train import (forward_skip_reason, gate_input, latest_classifier,
                              load_classifier, train_and_score)
from fuzzlab.web import mlview
from fuzzlab.web.results import _scored_candidates
from tests.test_ml_budget_and_scope import _prior_runs, _target
from tests.test_ml_train import _seed_rich


def _status(store, run_id, status, where="rule='xss'"):
    store.conn.execute(f"UPDATE candidate SET oracle_status=? WHERE run_id=? AND {where}",
                       (status, run_id))
    store.conn.commit()


def _col(store, cid, col):
    return store.conn.execute(f"SELECT {col} FROM candidate WHERE id=?", (cid,)).fetchone()[0]


# --- D-a: no_confirmer rows are unlabelled ------------------------------------------

def test_no_confirmer_rows_are_not_training_labels_but_are_still_scored(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        _status(store, run_id, NO_CONFIRMER)              # the 10 xss rows
        assert len(build_dataset(store, run_id)) == 10
        every = build_dataset(store, run_id, include_unlabelled=True)
        assert len(every) == 20 and every.labelled.count(False) == 10
        train_and_score(store, run_id)
        assert store.conn.execute("SELECT COUNT(*) FROM candidate WHERE run_id=? AND "
                                  "score IS NULL", (run_id,)).fetchone()[0] == 0


def test_no_confirmer_rows_do_not_skip_the_forward_evaluation(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        _status(store, run_id, NO_CONFIRMER, "id IN (SELECT id FROM candidate LIMIT 2)")
        assert forward_skip_reason(store, run_id, build_dataset(store, run_id).y) is None
        _status(store, run_id, SKIPPED_BUDGET, "id IN (SELECT id FROM candidate LIMIT 1)")
        assert forward_skip_reason(store, run_id, build_dataset(store, run_id).y) == \
            "budget-selected labels"


def test_earlier_mode_excludes_earlier_no_confirmer_rows(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, _ = _prior_runs(store)
        _status(store, first, NO_CONFIRMER)               # 10 of run 1's rows
        run_id = _seed_rich(store)
        _target(store, run_id)
        result = train_and_score(store, run_id, train_on="earlier")
        assert result["train_rows"] == 30


# --- D-b: canonical target origins ----------------------------------------------------

@pytest.mark.parametrize("url, want", [
    ("http://localhost:8080", "http://127.0.0.1:8080"),
    ("HTTP://LocalHost:8080/x?y#z", "http://127.0.0.1:8080"),
    ("http://localhost.:8080", "http://127.0.0.1:8080"),
    ("http://[::1]:8080", "http://127.0.0.1:8080"),
    ("http://[0:0:0:0:0:0:0:1]:8080", "http://127.0.0.1:8080"),
    ("http://[::ffff:127.0.0.1]:8080", "http://127.0.0.1:8080"),
    ("localhost:8080", "http://127.0.0.1:8080"),
    ("http://user:pw@localhost:8080", "http://127.0.0.1:8080"),
    ("http://localhost", "http://127.0.0.1:80"),
    ("https://localhost", "https://127.0.0.1:443"),
    ("http://127.0.0.2:8080", "http://127.0.0.2:8080"),        # a distinct service
    ("http://Example.ORG:8080/", "http://example.org:8080"),
    ("http://[fe80::1]:81", "http://[fe80::1]:81"),
    ("", None), (None, None), ("://", None), ("http://", None),
    ("http://h:abc", None), ("http://h:99999", None), ("http://u:p@localhost:abc", None),
])
def test_canonical_origin(url, want):
    assert canonical_origin(url) == want


def test_loopback_aliases_are_one_target_for_earlier_training(tmp_path):
    with Store(tmp_path / "a.db") as store:
        r1, r2 = _prior_runs(store, target="http://localhost:8080")
        r3 = _seed_rich(store)
        _target(store, r3, "http://[::1]:8080")
        other_port = _seed_rich(store)
        _target(store, other_port, "http://127.0.0.1:9090")
        broken = _seed_rich(store)
        _target(store, broken, "")
        assert target_runs(store, "http://127.0.0.1:8080") == [r1, r2, r3]
        assert target_runs(store, "") == []                   # never matches anything
        run_id = _seed_rich(store)
        _target(store, run_id, "http://127.0.0.1:8080")
        result = train_and_score(store, run_id, train_on="earlier")
        assert result["train_run_ids"] == [r1, r2, r3]


# --- D-c: out-of-fold columns; gates judge the score they were calibrated for -------

def _run_trained(store):
    run_id = _seed_rich(store)
    _target(store, run_id)
    train_and_score(store, run_id)
    train_and_rank(store, run_id)
    return run_id


def test_run_mode_stores_out_of_fold_scores_beside_the_deploy_scores(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _run_trained(store)
        rows = store.conn.execute("SELECT score, score_oof, rank_score, rank_score_oof "
                                  "FROM candidate WHERE run_id=?", (run_id,)).fetchall()
        assert all(r["score_oof"] is not None and r["rank_score_oof"] is not None
                   for r in rows)
        # precondition: the out-of-fold scores are genuinely different numbers
        assert any(abs(r["score"] - r["score_oof"]) > 1e-3 for r in rows)
        clf = latest_classifier(store, run_id)
        assert clf.calibration["score_source"] == "oof-labelled"
        # the tab's numbers recomputed from them ARE the model's out-of-fold numbers
        cp = mlview.classifier_panel(store, run_id)
        assert cp["evaluation"] == mlview.OUT_OF_FOLD
        assert cp["pr_auc"] == pytest.approx(clf.calibration["oof_pr_auc"], abs=1e-4)
        # and the saved model still reproduces every deploy score (CC-ML-0015)
        every = build_dataset(store, run_id, include_unlabelled=True)
        loaded = load_classifier(store, clf)
        assert [round(p, 6) for p in loaded.predict_proba(every.X)] == \
            [_col(store, c, "score") for c in every.ids]


def test_unlabelled_rows_get_no_out_of_fold_score(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        skipped = store.conn.execute("SELECT id FROM candidate WHERE run_id=? AND "
                                     "rule='xss' AND evidence LIKE '%p9%'",
                                     (run_id,)).fetchone()[0]
        _status(store, run_id, SKIPPED_BUDGET, f"id={skipped}")
        train_and_score(store, run_id)
        assert _col(store, skipped, "score") is not None
        assert _col(store, skipped, "score_oof") is None


def test_rescoring_in_another_mode_clears_the_old_out_of_fold_scores(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id = _run_trained(store)
        train_and_score(store, run_id, train_on="earlier")
        train_and_rank(store, run_id, train_on="earlier")
        assert store.conn.execute(
            "SELECT COUNT(*) FROM candidate WHERE run_id=? AND (score_oof IS NOT NULL OR "
            "rank_score_oof IS NOT NULL)", (run_id,)).fetchone()[0] == 0
        model, scored = _scored_candidates(store, run_id)
        clf = latest_classifier(store, run_id)
        assert clf.calibration["trained_on"] == "earlier"
        for s in scored:                                  # the new gate judges `score`
            assert s["decision_score"] == s["score"]


def test_run_page_decides_on_the_out_of_fold_score_and_shows_it(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _run_trained(store)
        clf = latest_classifier(store, run_id)
        _, scored = _scored_candidates(store, run_id, limit=50)
        oof = {}
        for r in store.conn.execute("SELECT evidence, score_oof FROM candidate WHERE "
                                    "run_id=?", (run_id,)):
            ev = json.loads(r["evidence"])
            oof[(ev["url"].replace("http://h", ""), ev["param"], ev["category"])] = \
                round(r["score_oof"], 4)
        assert len(scored) == 20
        for s in scored:
            assert s["decision_score"] == oof[(s["url"], s["param"], s["category"])]
            assert s["decision"] == clf.gate.decide(s["decision_score"])


def test_legacy_run_mode_rows_are_never_gated_on_in_sample_scores(tmp_path):
    calibration = {"alpha": 0.1, "t_lo": 0.3, "t_hi": 0.7}      # no score_source
    assert gate_input(calibration, None, 0.9, None) is None
    assert gate_input(calibration, NO_CONFIRMER, 0.9, None) is None   # trained on then
    assert gate_input(calibration, SKIPPED_BUDGET, 0.9, None) == 0.9  # never trained on
    run_mode = {**calibration, "score_source": "oof-labelled"}
    assert gate_input(run_mode, None, 0.9, 0.2) == 0.2
    assert gate_input(run_mode, NO_CONFIRMER, 0.9, None) == 0.9
    assert gate_input(run_mode, None, 0.9, None) is None
    for trained_on in ("earlier", "saved"):
        assert gate_input({**calibration, "trained_on": trained_on}, None, 0.9, None) == 0.9


def test_legacy_shaped_run_page_says_in_sample(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        store.conn.execute("UPDATE candidate SET score=0.8 WHERE run_id=?", (run_id,))
        store.conn.execute(
            "INSERT INTO model (name, version, feature_version, calibration) VALUES "
            "('logistic', 1, 1, ?)", (json.dumps({"alpha": 0.1, "t_lo": 0.3, "t_hi": 0.7,
                                                   "run_id": run_id}),))
        store.conn.commit()
        _, scored = _scored_candidates(store, run_id)
        assert {s["decision"] for s in scored} == {"n/a (in-sample score)"}
        assert {s["decision_score"] for s in scored} == {None}


# --- F-1: score / rank with a saved model, no retraining ---------------------------

def _model_row(store, name, calibration, params=True):
    src = store.conn.execute("SELECT params, params_sha256 FROM model WHERE params IS NOT "
                             "NULL AND name=? LIMIT 1", (name,)).fetchone()
    version = store.conn.execute("SELECT MAX(version) FROM model WHERE name=?",
                                 (name,)).fetchone()[0] + 1
    cur = store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (name, version, 1, json.dumps(calibration), src[0] if params else None,
         src[1] if params else None))
    store.conn.commit()
    return cur.lastrowid


def _two_trained_runs(store):
    first, second = _prior_runs(store)
    for r in (first, second):
        train_and_score(store, r)
        train_and_rank(store, r)
    return first, second


def test_saved_mode_applies_the_newest_earlier_model_exactly(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, second = _two_trained_runs(store)
        run_id = _seed_rich(store)
        _target(store, run_id)
        source = latest_classifier(store, second)
        result = train_and_score(store, run_id, train_on="saved")
        assert result["refused"] is False and result["source_model_id"] == source.id
        assert result["source_run_id"] == second and result["train_run_ids"] == [second]
        copy = latest_classifier(store, run_id)
        assert copy.calibration["trained_on"] == "saved"
        assert copy.params_sha256 == source.params_sha256
        assert copy.calibration["oof_scope"] == f"run #{second} (saved model #{source.id})"
        assert copy.calibration["seen_fraction_recomputed"] is True
        every = build_dataset(store, run_id, include_unlabelled=True)
        loaded = load_classifier(store, copy)
        assert [round(p, 6) for p in loaded.predict_proba(every.X)] == \
            [_col(store, c, "score") for c in every.ids]
        assert {_col(store, c, "score_oof") for c in every.ids} == {None}
        assert "ml_pr_auc_forward" in {r[0] for r in store.conn.execute(
            "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}
        rank = train_and_rank(store, run_id, train_on="saved")
        assert rank["refused"] is False
        row, calib = latest_ranker(store, run_id)
        texts = _candidate_texts(store, run_id, every.ids)
        assert [round(s, 6) for s in load_ranker(store, row).score(every.X, texts)] == \
            [_col(store, c, "rank_score") for c in every.ids]
        assert calib["trained_on"] == "saved"


def test_saved_mode_never_picks_a_model_that_could_have_read_this_runs_labels(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, _ = _two_trained_runs(store)
        run_id = _seed_rich(store)
        _target(store, run_id)
        later = _seed_rich(store)
        _target(store, later)
        train_and_score(store, later)                     # a LATER run's model
        train_and_score(store, run_id)                    # this run's own model
        other = _seed_rich(store)
        _target(store, other, "http://other:9")
        # rows that must never be chosen, all newer than the qualifying ones
        bad = {
            "store-wide": _model_row(store, "logistic", {"run_id": None}),
            "legacy": _model_row(store, "logistic", {}),
            "non-int": _model_row(store, "logistic", {"run_id": str(first)}),
            "bool": _model_row(store, "logistic", {"run_id": True}),
            "no-params": _model_row(store, "logistic", {"run_id": first}, params=False),
            "this-run": latest_classifier(store, run_id).id,
            "later-run": latest_classifier(store, later).id,
        }
        result = train_and_score(store, run_id, train_on="saved")
        assert result["source_model_id"] not in bad.values()
        assert result["source_run_id"] < run_id
        for why, model_id in bad.items():
            pinned = train_and_score(store, run_id, train_on="saved", model_id=model_id)
            assert pinned["refused"] is True, why


def test_saved_mode_resolves_a_copy_to_its_original_and_refuses_wrong_family(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _, second = _two_trained_runs(store)
        r3 = _seed_rich(store)
        _target(store, r3)
        train_and_score(store, r3, train_on="saved")      # copy scoped to r3
        copy = latest_classifier(store, r3)
        r4 = _seed_rich(store)
        _target(store, r4)
        auto = train_and_score(store, r4, train_on="saved")
        assert auto["source_model_id"] == copy.calibration["source_model_id"]  # not the copy
        pinned = train_and_score(store, r4, train_on="saved", model_id=copy.id)
        assert pinned["source_model_id"] == copy.calibration["source_model_id"]
        assert pinned["train_run_ids"] == [second]
        ranker_id = latest_ranker(store, second)[0]["id"]
        assert train_and_score(store, r4, train_on="saved",
                               model_id=ranker_id)["refused"] is True


def test_saved_mode_refuses_and_writes_nothing_without_a_model(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        _target(store, run_id)
        result = train_and_score(store, run_id, train_on="saved")
        assert result["refused"] is True
        assert store.conn.execute("SELECT COUNT(*) FROM model").fetchone()[0] == 0
        assert store.conn.execute("SELECT COUNT(*) FROM candidate WHERE score IS NOT "
                                  "NULL").fetchone()[0] == 0
        no_target = _seed_rich(store)
        assert train_and_rank(store, no_target, train_on="saved")["reason"] == \
            "no target recorded for this run"


def test_saved_mode_refuses_a_corrupted_saved_model(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _two_trained_runs(store)
        store.conn.execute("UPDATE model SET params_sha256='0'*64 WHERE params IS NOT NULL")
        store.conn.commit()
        run_id = _seed_rich(store)
        _target(store, run_id)
        result = train_and_score(store, run_id, train_on="saved")
        assert result["refused"] is True and "cannot be applied" in result["reason"]


def test_saved_mode_validation(tmp_path):
    with Store(tmp_path / "a.db") as store:
        with pytest.raises(ValueError):
            train_and_score(store, None, train_on="saved")
        with pytest.raises(ValueError):
            train_and_score(store, 1, train_on="saved", hybrid=True)
        with pytest.raises(ValueError):
            train_and_score(store, 1, model_id=3)          # needs train_on="saved"
        with pytest.raises(ValueError):
            train_and_rank(store, 1, model_id=3)


def test_ui_and_report_recognise_a_saved_model(tmp_path):
    from fuzzlab.report.report import build_report, format_text
    with Store(tmp_path / "a.db") as store:
        _, second = _two_trained_runs(store)
        run_id = _seed_rich(store)
        _target(store, run_id)
        train_and_score(store, run_id, train_on="saved")
        source = latest_classifier(store, run_id).calibration["source_model_id"]
        cp = mlview.classifier_panel(store, run_id)
        assert cp["evaluation"] == f"not trained on this run's labels (saved model #{source})"
        assert cp["oof"]["forward"] is not None
        rep = build_report(store, run_id)
        assert rep["reproducibility"]["model_training"]["logistic"] == {
            "trained_on": "saved", "train_run_ids": [second], "source_model_id": source}
        assert f"(saved model #{source}, trained on runs {second})" in format_text(rep)


def test_tab_metrics_are_the_out_of_fold_ones_on_noisy_data(tmp_path):
    """On separable toy data in-sample and out-of-fold PR-AUC are both 1.0; make them
    differ so the test can tell which scores the tab recomputes from."""
    from tests.test_ml_train import _finding
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        store.conn.execute("DELETE FROM finding WHERE run_id=? AND url IN ('/p0.php', "
                           "'/p1.php')", (run_id,))
        for i in (7, 8, 9):
            _finding(store, run_id, f"/p{i}.php", "id", "sqli")
        store.conn.commit()
        train_and_score(store, run_id)
        clf = latest_classifier(store, run_id)
        ds = build_dataset(store, run_id)
        from fuzzlab.ml.metrics import pr_auc
        deploy = pr_auc(ds.y, [_col(store, c, "score") for c in ds.ids])
        assert abs(deploy - clf.calibration["oof_pr_auc"]) > 1e-3        # precondition
        cp = mlview.classifier_panel(store, run_id)
        assert cp["pr_auc"] == pytest.approx(clf.calibration["oof_pr_auc"], abs=1e-4)


def test_saved_mode_copies_an_earlier_trained_sources_training_runs(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, second = _prior_runs(store)
        r3 = _seed_rich(store)
        _target(store, r3)
        train_and_score(store, r3, train_on="earlier")    # trained on runs 1, 2
        r4 = _seed_rich(store)
        _target(store, r4)
        result = train_and_score(store, r4, train_on="saved")
        assert result["source_run_id"] == r3
        assert result["train_run_ids"] == [first, second]
        assert latest_classifier(store, r4).calibration["train_run_ids"] == [first, second]
