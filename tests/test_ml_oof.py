"""BUG-0062 / PA-0064: an out-of-fold evaluation must never silently be in-sample.

`group_kfold` used to yield one `(idx, idx)` fold (train == test) when there were fewer
than 2 groups or k < 2, so both trainers reported in-sample PR-AUC / nDCG as out-of-fold
and could claim to beat their baselines. These tests pin the degenerate branch itself
(PA-0029: exercise the branch that used to switch the invariant off), the trainers'
thin-data fallback, the fail-closed `oof_folds`, and the ML tab's in-sample labelling
(CC-ML-0012, CC-UI-0035).
"""

from __future__ import annotations

import json
import random

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.metrics import group_kfold, oof_folds
from fuzzlab.ml.rank_train import _candidate_texts, train_and_rank
from fuzzlab.ml.rank_train import _oof_scores as rank_oof_scores
from fuzzlab.ml.train import LogisticRegression, train_and_score
from fuzzlab.ml.train import _oof_scores as clf_oof_scores
from fuzzlab.web import mlview
from tests.test_ml_train import _cand, _finding, _seed_rich


def _seed_one_endpoint(store, rows=24, positives=6):
    """Plenty of rows and positives — but every candidate on one endpoint (path)."""
    run_id = store.start_run("auto", "127.0.0.1:8080")
    for i in range(rows):
        _cand(store, run_id, "/one.php", f"p{i}", "sql-injection",
              sink="html" if i < positives else None)
    for i in range(positives):
        _finding(store, run_id, "/one.php", f"p{i}", "sqli")
    store.conn.commit()
    return run_id


def _metric_keys(store, run_id):
    return {r["key"] for r in store.conn.execute(
        "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}


def _calibration(store, name):
    row = store.conn.execute(
        "SELECT calibration FROM model WHERE name=? ORDER BY version DESC", (name,)).fetchone()
    return json.loads(row["calibration"])


# --- group_kfold's degenerate branch ----------------------------------------

@pytest.mark.parametrize("groups,k", [(["/a"] * 4, 5), (["/a", "/b", "/c"], 1),
                                     (["/a", "/b", "/c"], 0), ([], 5)])
def test_group_kfold_yields_no_fold_when_no_held_out_split_exists(groups, k):
    assert list(group_kfold(groups, k=k)) == []


def test_group_kfold_folds_are_a_true_partition():
    rng = random.Random(7)
    for _ in range(300):
        n = rng.randint(2, 40)
        groups = [rng.randrange(rng.randint(2, 12)) for _ in range(n)]
        k = rng.randint(2, 8)
        folds = list(group_kfold(groups, k=k, seed=rng.randrange(1000)))
        tested = [0] * n
        for train, test in folds:
            assert train and test
            assert not {groups[i] for i in train} & {groups[i] for i in test}
            for i in test:
                tested[i] += 1
        if len(set(groups)) >= 2:
            assert tested == [1] * n


@pytest.mark.parametrize("groups,k", [(["/a"] * 6, 5), (["/a", "/b"], 1)])
def test_oof_folds_fails_closed(groups, k):
    with pytest.raises(ValueError, match="out-of-fold"):
        oof_folds(groups, k=k)


def test_oof_folds_returns_the_partition_on_real_groups():
    groups = [g for g in range(6) for _ in range(3)]
    folds = oof_folds(groups, k=3)
    assert sorted(i for _, test in folds for i in test) == list(range(18))


# --- the trainers never report in-sample metrics as out-of-fold -------------

def test_classifier_falls_back_on_a_single_endpoint(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_one_endpoint(store)
        result = train_and_score(store, run_id, model_kind="auto")
        assert result["fallback"] is True and result["groups"] == 1
        assert "pr_auc" not in result and "beats_baselines" not in result
        assert not _metric_keys(store, run_id) & {"ml_pr_auc", "ml_pr_auc_prevalence",
                                                  "ml_pr_auc_sigma"}
        assert not any(k.startswith("oof_") for k in _calibration(store, result["model"]))


def test_ranker_falls_back_on_a_single_endpoint(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_one_endpoint(store)
        result = train_and_rank(store, run_id)
        assert result["fallback"] is True and result["groups"] == 1
        assert "ndcg" not in result and "beats_baseline" not in result
        assert not any(k.startswith("rank_") for k in _metric_keys(store, run_id))
        assert not any(k.startswith("oof_") for k in _calibration(store, result["model"]))


@pytest.mark.parametrize("trainer", [train_and_score, train_and_rank])
def test_trainers_fall_back_instead_of_raising_when_k_is_below_two(tmp_path, trainer):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)                       # 10 endpoints: data is fine
        result = trainer(store, run_id, k=1)
        assert result["fallback"] is True and result["groups"] == 10


@pytest.mark.parametrize("trainer", [train_and_score, train_and_rank])
def test_min_groups_raises_the_floor(tmp_path, trainer):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        assert trainer(store, run_id)["fallback"] is False
        assert trainer(store, run_id, min_groups=11)["fallback"] is True


def test_private_oof_scorers_fail_closed_on_one_endpoint(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_one_endpoint(store)
        ds = build_dataset(store, run_id)
        with pytest.raises(ValueError):
            clf_oof_scores(ds, LogisticRegression, 5)
        with pytest.raises(ValueError):
            rank_oof_scores(ds, _candidate_texts(store, run_id, ds.ids), 5, 0)


# --- the ML tab labels in-sample numbers and shows the honest ones ----------

def test_ml_tab_labels_in_sample_and_shows_the_scoring_models_oof(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        clf = train_and_score(store, run_id)
        rank = train_and_rank(store, run_id)
        cp = mlview.classifier_panel(store, run_id)
        rp = mlview.ranker_panel(store, run_id)
        assert cp["evaluation"] == rp["evaluation"] == mlview.IN_SAMPLE
        assert cp["oof"] == {"pr_auc": clf["pr_auc"],
                             "pr_auc_prevalence": clf["baseline_prevalence"],
                             "pr_auc_sigma": clf["baseline_sigma"]}
        assert rp["oof"] == {"at_k": rank["at_k"], "ndcg": rank["ndcg"],
                             "precision": rank["precision"],
                             "ndcg_random": rank["baseline_ndcg"],
                             "precision_random": rank["baseline_precision"]}


def test_ml_tab_shows_no_oof_for_a_fallback_or_mixed_runs(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_one_endpoint(store)               # -> fallback models
        train_and_score(store, run_id)
        train_and_rank(store, run_id)
        assert mlview.classifier_panel(store, run_id)["oof"] is None
        assert mlview.ranker_panel(store, run_id)["oof"] is None
        rich = _seed_rich(store)
        train_and_score(store, rich)
        train_and_rank(store, rich)
        # all-runs view: the newest rows were trained for one run, but the scores shown
        # span several runs' models — so no single model's OOF numbers apply.
        assert mlview.classifier_panel(store, None)["oof"] is None
        assert mlview.ranker_panel(store, None)["oof"] is None
        train_and_score(store, None)                     # store-wide: scored every run
        train_and_rank(store, None)
        assert mlview.classifier_panel(store, None)["oof"] is not None
        assert mlview.ranker_panel(store, None)["oof"] is not None


# --- guard: every out-of-fold scorer goes through the verified partition (PA-0064) --

def _calls(source: str, name: str) -> int:
    import ast
    return sum(1 for n in ast.walk(ast.parse(source))
               if isinstance(n, ast.Call)
               and (getattr(n.func, "id", None) == name
                    or getattr(n.func, "attr", None) == name))


def test_guard_counts_a_raw_group_kfold_call():          # PA-0034(2): prove it first
    assert _calls("for tr, te in group_kfold(g, k=5):\n    pass", "group_kfold") == 1
    assert _calls("for tr, te in metrics.group_kfold(g):\n    pass", "group_kfold") == 1
    assert _calls("folds = oof_folds(g, k=5)", "group_kfold") == 0


def test_no_out_of_fold_scorer_bypasses_oof_folds():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "fuzzlab"
    raw = {str(p.relative_to(root.parent)): _calls(p.read_text(encoding="utf-8"), "group_kfold")
           for p in sorted(root.rglob("*.py")) if p.name != "metrics.py"}
    assert {k: v for k, v in raw.items() if v} == {}, (
        "score out-of-fold through fuzzlab.ml.metrics.oof_folds, which fails closed "
        "unless every row is held out exactly once (BUG-0062)")
