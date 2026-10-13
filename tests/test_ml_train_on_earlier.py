"""`train_on="earlier"` (CC-ML-0016, FR-ML-14): train the classifier / ranker on earlier
runs against the same target and score / rank this run without reading its labels.

The core guarantee is pinned as *model identity*: the saved model (`params_sha256`) and
its training-related calibration do not change when this run's labels or candidates,
a later run, or another target's run change.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.metrics import pr_auc
from fuzzlab.ml.rank_train import (_candidate_texts, latest_ranker, load_ranker,
                                   train_and_rank)
from fuzzlab.ml.ranking import mean_ndcg_at_k, mean_precision_at_k
from fuzzlab.ml.train import latest_classifier, load_classifier, train_and_score
from fuzzlab.report.report import build_report, format_text
from fuzzlab.web import mlview
from tests.test_ml_budget_and_scope import TARGET, _prior_runs, _skip, _target
from tests.test_ml_train import _cand, _finding, _seed_rich

#: calibration keys that describe this run (by design), not the trained model
_THIS_RUN_KEYS = {"seen_fraction"}


def _setup(store, *, target=TARGET):
    """Two earlier labelled runs, then this run (same endpoints, its own findings)."""
    _prior_runs(store)
    run_id = _seed_rich(store)
    _target(store, run_id, target)
    return run_id


def _train(store, run_id, which, **kw):
    if which == "score":
        return train_and_score(store, run_id, train_on="earlier", **kw)
    return train_and_rank(store, run_id, train_on="earlier", **kw)


def _model(store, run_id, which):
    if which == "score":
        clf = latest_classifier(store, run_id)
        return clf.params_sha256, clf.calibration
    row, calib = latest_ranker(store, run_id)
    return load_ranker(store, row).sha256, calib


def _identity(store, run_id, which, **kw):
    _train(store, run_id, which, **kw)
    sha, calib = _model(store, run_id, which)
    return sha, {k: v for k, v in calib.items()
                 if k not in _THIS_RUN_KEYS and not k.startswith("forward_")}


def _metrics(store, run_id) -> dict:
    return {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))}


# --- the leakage guarantee: model identity ---------------------------------------

def _labels_appear(store, run_id):              # this run gets new findings, incl. keys
    for i in range(6, 10):                      # unlabelled in every earlier run
        _finding(store, run_id, f"/p{i}.php", "id", "sqli")
        _finding(store, run_id, f"/p{i}.php", "id", "xss")


def _labels_vanish(store, run_id):
    store.conn.execute("DELETE FROM finding WHERE run_id=?", (run_id,))


def _more_candidates(store, run_id):
    for i in range(7):
        _cand(store, run_id, f"/new{i}.php", "q", "sql-injection", sink="html")


def _fewer_candidates(store, run_id):
    store.conn.execute("DELETE FROM candidate WHERE run_id=? AND rule='xss'", (run_id,))


def _later_run(store, run_id):
    _target(store, _seed_rich(store))


def _other_target_run(store, run_id):
    _target(store, _seed_rich(store), "http://other:9")


MUTATIONS = [_labels_appear, _labels_vanish, _more_candidates, _fewer_candidates,
             _later_run, _other_target_run]


@pytest.mark.parametrize("mutate", MUTATIONS, ids=lambda f: f.__name__)
@pytest.mark.parametrize("which,kw", [("score", {}), ("score", {"hybrid": True}),
                                      ("score", {"model_kind": "auto"}), ("rank", {})],
                         ids=["logistic", "hybrid", "auto", "ranker"])
def test_model_identity_ignores_this_run_later_runs_and_other_targets(
        tmp_path, which, kw, mutate):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        base = _identity(store, run_id, which, **kw)
    with Store(tmp_path / "b.db") as store:
        run_id = _setup(store)
        mutate(store, run_id)
        store.conn.commit()
        assert _identity(store, run_id, which, **kw) == base


def test_identity_check_is_not_vacuous(tmp_path):     # PA-0034(2): it can fail
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        base = _identity(store, run_id, "score")
    with Store(tmp_path / "b.db") as store:
        run_id = _setup(store)
        _finding(store, 1, "/p7.php", "id", "sqli")    # an EARLIER run's label changes
        store.conn.commit()
        assert _identity(store, run_id, "score") != base


def test_a_key_labelled_only_in_this_run_trains_as_negative(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _labels_appear(store, run_id)
        store.conn.commit()
        result = _train(store, run_id, "score")
        assert result["train_rows"] == 40 and result["train_positives"] == 12


def test_earlier_budget_skipped_rows_are_excluded(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        skipped = [r["id"] for r in store.conn.execute(
            "SELECT id FROM candidate WHERE run_id=1 AND rule='xss' ORDER BY id")]
        _skip(store, skipped)
        result = _train(store, run_id, "score")
        assert result["train_rows"] == 40 - len(skipped) == 30
        marked = latest_classifier(store, run_id).params_sha256
    with Store(tmp_path / "b.db") as store:
        run_id = _setup(store)
        store.conn.execute("DELETE FROM candidate WHERE run_id=1 AND rule='xss'")
        store.conn.commit()
        _train(store, run_id, "score")
        assert latest_classifier(store, run_id).params_sha256 == marked


# --- what is written ----------------------------------------------------------------

@pytest.mark.parametrize("hybrid", [False, True])
def test_scores_are_the_saved_model_applied_to_this_runs_rows(tmp_path, hybrid):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _more_candidates(store, run_id)                  # unlabelled rows are scored too
        store.conn.commit()
        result = _train(store, run_id, "score", hybrid=hybrid)
        every = build_dataset(store, run_id, include_unlabelled=True)
        assert result["scored"] == len(every) == 27
        loaded = load_classifier(store, latest_classifier(store, run_id))
        loaded.check_compatible()
        expected = [round(p, 6) for p in loaded.predict_proba(every.X)]
        stored = [store.conn.execute("SELECT score FROM candidate WHERE id=?",
                                     (cid,)).fetchone()["score"] for cid in every.ids]
        assert stored == expected


def test_ranks_are_the_saved_ranker_applied_to_this_runs_rows(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        result = _train(store, run_id, "rank")
        every = build_dataset(store, run_id, include_unlabelled=True)
        assert result["ranked"] == len(every) == 20
        loaded = load_ranker(store, latest_ranker(store, run_id)[0])
        loaded.check_compatible()
        texts = _candidate_texts(store, run_id, every.ids)
        expected = [round(s, 6) for s in loaded.score(every.X, texts)]
        stored = [store.conn.execute("SELECT rank_score FROM candidate WHERE id=?",
                                     (cid,)).fetchone()["rank_score"] for cid in every.ids]
        assert stored == expected


def test_ranker_vocabulary_comes_from_the_earlier_runs_texts(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id = store.start_run("auto", "127.0.0.1:8080")
        for i in range(5):
            _cand(store, run_id, f"/zzz{i}.php", "qqq", "sql-injection")
        store.conn.commit()
        _target(store, run_id)
        _train(store, run_id, "rank")
        vocab = load_ranker(store, latest_ranker(store, run_id)[0]).model.vectorizer.vocab
        assert vocab and any("/p" in g or "id " in g for g in vocab)   # earlier texts
        assert not any("qqq" in g or "zzz" in g for g in vocab)      # never this run's


@pytest.mark.parametrize("which", ["score", "rank"])
def test_latest_reader_selects_the_earlier_trained_row_for_this_run(tmp_path, which):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _train(store, run_id, which)
        sha, calib = _model(store, run_id, which)
        assert calib["trained_on"] == "earlier" and calib["run_id"] == run_id
        assert calib["train_run_ids"] == [1, 2] and calib["oof_scope"] == "earlier runs"
        for key in ("seed", "k", "min_rows", "min_positives", "min_groups",
                    "feature_version", "train_rows", "train_positives"):
            assert key in calib, key
        # scoped to THIS run: it does not cover the earlier runs it trained on
        assert latest_classifier(store, 1) is None and latest_ranker(store, 1) is None


def test_seen_fraction_is_the_share_of_this_runs_keys_in_training(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)                            # 20 keys, all seen earlier
        _more_candidates(store, run_id)                   # 7 new keys (/new0..6)
        _cand(store, run_id, "/p0.php", "id", "path-traversal")   # new category: unseen
        store.conn.commit()
        for which in ("score", "rank"):
            assert _train(store, run_id, which)["seen_fraction"] == round(20 / 28, 6)
        m = _metrics(store, run_id)
        assert m["ml_seen_fraction"] == m["rank_seen_fraction"] == round(20 / 28, 6)


# --- metrics ------------------------------------------------------------------------

EARLIER_ML = {"ml_pr_auc_earlier", "ml_pr_auc_prevalence_earlier",
              "ml_pr_auc_sigma_earlier", "ml_seen_fraction"}
FORWARD_ML = {"ml_pr_auc_forward", "ml_pr_auc_prevalence_forward"}
EARLIER_RANK = {"rank_ndcg_earlier", "rank_precision_earlier", "rank_ndcg_random_earlier",
                "rank_precision_random_earlier", "rank_seen_fraction"}
FORWARD_RANK = {"rank_ndcg_forward", "rank_precision_forward", "rank_ndcg_random_forward",
                "rank_precision_random_forward"}


def test_exact_metric_keys_and_no_run_mode_keys_or_training_curves(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _train(store, run_id, "score", model_kind="auto")
        _train(store, run_id, "rank")
        assert set(_metrics(store, run_id)) == (EARLIER_ML | FORWARD_ML | EARLIER_RANK
                                                | FORWARD_RANK)
        assert store.conn.execute("SELECT COUNT(*) c FROM metric_series").fetchone()["c"] == 0


def test_forward_metrics_equal_this_runs_labels_against_the_stored_scores(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        score = _train(store, run_id, "score")
        rank = _train(store, run_id, "rank")
        now = build_dataset(store, run_id)
        col = lambda c, cid: store.conn.execute(          # noqa: E731
            f"SELECT {c} FROM candidate WHERE id=?", (cid,)).fetchone()[c]
        m = _metrics(store, run_id)
        assert m["ml_pr_auc_forward"] == pytest.approx(
            pr_auc(now.y, [col("score", c) for c in now.ids]), abs=1e-5)
        assert m["ml_pr_auc_prevalence_forward"] == pytest.approx(
            pr_auc(now.y, [0.3] * len(now)))
        ranks = [col("rank_score", c) for c in now.ids]
        assert m["rank_ndcg_forward"] == pytest.approx(
            mean_ndcg_at_k(now.y, ranks, now.groups, 10), abs=1e-5)
        assert m["rank_precision_forward"] == pytest.approx(
            mean_precision_at_k(now.y, ranks, now.groups, 10), abs=1e-5)
        assert score["pr_auc_forward"] == m["ml_pr_auc_forward"]
        assert rank["ndcg_forward"] == m["rank_ndcg_forward"]
        assert latest_classifier(store, run_id).calibration["forward_pr_auc"] == \
            score["pr_auc_forward"]


@pytest.mark.parametrize("which", ["score", "rank"])
def test_no_forward_metrics_on_budget_selected_labels(tmp_path, which):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        one = store.conn.execute("SELECT id FROM candidate WHERE run_id=? LIMIT 1",
                                 (run_id,)).fetchone()["id"]
        _skip(store, [one])
        result = _train(store, run_id, which)
        assert result["forward_skipped_reason"] == "budget-selected labels"
        assert not set(_metrics(store, run_id)) & (FORWARD_ML | FORWARD_RANK)
        calib = _model(store, run_id, which)[1]
        assert calib["forward_skipped_reason"] == "budget-selected labels"
        assert not {k for k in calib if k.startswith("forward_")} - {"forward_skipped_reason"}


@pytest.mark.parametrize("which", ["score", "rank"])
def test_no_forward_metrics_on_one_class_labels(tmp_path, which):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _labels_vanish(store, run_id)
        store.conn.commit()
        result = _train(store, run_id, which)
        assert result["forward_skipped_reason"] == "one-class labels"
        assert not set(_metrics(store, run_id)) & (FORWARD_ML | FORWARD_RANK)


# --- refusal --------------------------------------------------------------------------

def _nothing_written(store, run_id):
    assert store.conn.execute("SELECT COUNT(*) c FROM model").fetchone()["c"] == 0
    assert _metrics(store, run_id) == {}
    assert store.conn.execute(
        "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND (score IS NOT NULL "
        "OR rank_score IS NOT NULL)", (run_id,)).fetchone()["c"] == 0


@pytest.mark.parametrize("which", ["score", "rank"])
def test_refuses_and_writes_nothing_without_usable_earlier_labels(tmp_path, which):
    with Store(tmp_path / "a.db") as store:               # no earlier runs at all
        run_id = _seed_rich(store)
        _target(store, run_id)
        result = _train(store, run_id, which)
        assert result["refused"] is True and result["train_rows"] == 0
        assert result["reason"] == "no usable earlier labels for this target"
        _nothing_written(store, run_id)
    with Store(tmp_path / "b.db") as store:               # earlier runs, other target
        _prior_runs(store, target="http://other:9")
        run_id = _seed_rich(store)
        _target(store, run_id)
        assert _train(store, run_id, which)["refused"] is True
        _nothing_written(store, run_id)


@pytest.mark.parametrize("which", ["score", "rank"])
def test_refuses_a_run_with_no_target_row(tmp_path, which):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id = _seed_rich(store)                         # no target row
        result = _train(store, run_id, which)
        assert result == {**result, "refused": True,
                          "reason": "no target recorded for this run"}
        _nothing_written(store, run_id)


@pytest.mark.parametrize("which", ["score", "rank"])
def test_train_on_validation(tmp_path, which):
    with Store(tmp_path / "a.db") as store:
        with pytest.raises(ValueError):
            _train(store, None, which)
        fn = train_and_score if which == "score" else train_and_rank
        with pytest.raises(ValueError):
            fn(store, 1, train_on="later")


def test_run_mode_is_the_default_and_unchanged(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        result = train_and_score(store, run_id, train_on="run")
        assert "train_on" not in result and result["rows"] == 20
        calib = latest_classifier(store, run_id).calibration
        assert "trained_on" not in calib and "oof_pr_auc" in calib
        assert "ml_pr_auc" in _metrics(store, run_id)


# --- the ML tab and the report say how the scoring model was trained (CC-UI-0040) ----

def test_ml_tab_labels_an_earlier_trained_runs_evaluation(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        score = _train(store, run_id, "score")
        rank = _train(store, run_id, "rank")
        cp = mlview.classifier_panel(store, run_id)
        rp = mlview.ranker_panel(store, run_id)
        assert cp["evaluation"] == rp["evaluation"] == mlview.NOT_TRAINED_ON_RUN
        assert cp["evaluation"] == "not trained on this run's labels (trained on earlier runs)"
        assert cp["oof"] == {"pr_auc": score["pr_auc_earlier"],
                             "pr_auc_prevalence": score["baseline_prevalence_earlier"],
                             "pr_auc_sigma": score["baseline_sigma_earlier"],
                             "scope": "earlier runs", "train_run_ids": [1, 2],
                             "seen_fraction": 1.0, "forward_skipped_reason": None,
                             "forward": {"pr_auc": score["pr_auc_forward"],
                                         "pr_auc_prevalence":
                                             score["baseline_prevalence_forward"]}}
        assert rp["oof"]["scope"] == "earlier runs" and rp["oof"]["seen_fraction"] == 1.0
        assert rp["oof"]["forward"] == {"ndcg": rank["ndcg_forward"],
                                        "precision": rank["precision_forward"],
                                        "ndcg_random": rank["baseline_ndcg_forward"],
                                        "precision_random": rank["baseline_precision_forward"]}
        assert rp["oof"]["ndcg"] == rank["ndcg_earlier"]


def test_ml_tab_shows_why_there_is_no_forward_evaluation(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _setup(store)
        _labels_vanish(store, run_id)
        store.conn.commit()
        _train(store, run_id, "score")
        oof = mlview.classifier_panel(store, run_id)["oof"]
        assert oof["forward"] is None and oof["forward_skipped_reason"] == "one-class labels"


def test_all_runs_view_is_mixed_unless_every_pooled_run_was_earlier_trained(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, second = _prior_runs(store)
        train_and_score(store, first)                     # run-trained (in-sample)
        train_and_rank(store, first)
        run_id = _seed_rich(store)
        _target(store, run_id)
        _train(store, run_id, "score")
        _train(store, run_id, "rank")
        # run 2 has no scores: not pooled; runs 1 (in-sample) and 3 (earlier) are
        assert mlview.classifier_panel(store)["evaluation"] == mlview.MIXED
        assert mlview.ranker_panel(store)["evaluation"] == mlview.MIXED
        assert mlview.classifier_panel(store, first)["evaluation"] == mlview.IN_SAMPLE
        store.conn.execute("UPDATE candidate SET score=NULL, rank_score=NULL "
                           "WHERE run_id=?", (first,))
        store.conn.commit()
        assert mlview.classifier_panel(store)["evaluation"] == mlview.NOT_TRAINED_ON_RUN
        assert mlview.ranker_panel(store)["evaluation"] == mlview.NOT_TRAINED_ON_RUN


def test_report_records_what_each_model_was_trained_on(tmp_path):
    with Store(tmp_path / "a.db") as store:
        first, _ = _prior_runs(store)
        train_and_score(store, first)
        train_and_rank(store, first)
        run_id = _seed_rich(store)
        _target(store, run_id)
        _train(store, run_id, "score")
        _train(store, run_id, "rank")
        rep = build_report(store, run_id)
        assert rep["reproducibility"]["model_training"] == {
            "logistic": {"trained_on": "earlier", "train_run_ids": [1, 2]},
            "ranker": {"trained_on": "earlier", "train_run_ids": [1, 2]}}
        assert "logistic v2 (trained on earlier runs 1, 2)" in format_text(rep)
        assert build_report(store, first)["reproducibility"]["model_training"] == {
            "logistic": {"trained_on": "run", "train_run_ids": None},
            "ranker": {"trained_on": "run", "train_run_ids": None}}


def test_report_training_block_defaults_for_a_legacy_row(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "h")
        store.conn.execute("INSERT INTO model (name, version, feature_version, calibration) "
                           "VALUES ('logistic', 1, 1, '{}')")
        store.conn.commit()
        assert build_report(store, run_id)["reproducibility"]["model_training"] == {
            "logistic": {"trained_on": "run", "train_run_ids": None}}
