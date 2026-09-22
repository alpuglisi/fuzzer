"""Tests for the Phase 5 detection-ML groundwork (pure-Python, dependency-light).

The exit criteria in miniature: the classifier beats both dumb baselines on held-out
PR-AUC under GroupKFold, and the conformal gate's error rates are calibrated.
"""

import math
import random

from fuzzlab.ml import (
    ConformalGate,
    LogisticRegression,
    PrevalenceBaseline,
    SigmaBaseline,
    group_kfold,
    pr_auc,
)


# --- metrics -----------------------------------------------------------------

def test_pr_auc_perfect_and_degenerate():
    assert pr_auc([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) == 1.0     # perfect ranking
    assert pr_auc([0, 0, 0], [0.1, 0.2, 0.3]) == 0.0            # no positives
    # a worst-case ranking scores below the positive prevalence
    assert pr_auc([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1]) < 0.6


def test_group_kfold_never_splits_a_group():
    groups = [g for g in range(10) for _ in range(3)]           # 10 groups x 3
    seen_test = set()
    for train, test in group_kfold(groups, k=5, seed=1):
        train_groups = {groups[i] for i in train}
        test_groups = {groups[i] for i in test}
        assert train_groups.isdisjoint(test_groups)            # no leakage
        seen_test |= test_groups
    assert seen_test == set(range(10))                         # every group tested


# --- synthetic separable data (positives have higher feature 0) --------------

def _dataset(seed=0, n=240, prevalence=0.3, groups=24):
    rng = random.Random(seed)
    X, y, g = [], [], []
    for i in range(n):
        label = 1 if rng.random() < prevalence else 0
        x0 = rng.gauss(2.0 if label else 0.0, 1.0)             # signal (signed)
        x1 = rng.gauss(0.0, 1.0)                               # noise
        X.append([x0, x1]); y.append(label); g.append(i % groups)
    return X, y, g


def _cv_pr_auc(model_factory, X, y, groups):
    aucs = []
    for train, test in group_kfold(groups, k=6, seed=3):
        m = model_factory().fit([X[i] for i in train], [y[i] for i in train])
        scores = m.predict_proba([X[i] for i in test])
        aucs.append(pr_auc([y[i] for i in test], scores))
    return sum(aucs) / len(aucs)


def test_logistic_beats_both_baselines_on_groupkfold():
    X, y, groups = _dataset()
    logistic = _cv_pr_auc(LogisticRegression, X, y, groups)
    prevalence = _cv_pr_auc(PrevalenceBaseline, X, y, groups)
    sigma = _cv_pr_auc(SigmaBaseline, X, y, groups)
    assert logistic > prevalence                    # beats the prevalence floor
    assert logistic > sigma                          # beats the mean+kσ anomaly baseline
    assert logistic > 0.6                            # and is actually good


def test_prevalence_baseline_predicts_base_rate():
    m = PrevalenceBaseline().fit([[0.0]] * 10, [1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    assert m.predict_proba([[0.0], [9.0]]) == [0.3, 0.3]


# --- per-step training callbacks (B0's GBT/logistic emitter, CC-ML-0009) -----

def test_logistic_on_epoch_callback_fires_once_per_epoch_with_finite_loss():
    X, y, _ = _dataset()
    calls = []
    LogisticRegression(epochs=15).fit(X, y, on_epoch=lambda step, m: calls.append((step, m)))
    assert [c[0] for c in calls] == list(range(15))
    for _, metrics in calls:
        assert set(metrics) == {"train/loss", "train/l2_norm"}
        assert all(math.isfinite(v) for v in metrics.values())
    # loss should trend down over epochs of gradient descent
    assert calls[-1][1]["train/loss"] < calls[0][1]["train/loss"]


def test_logistic_fit_without_on_epoch_is_unaffected():
    X, y, _ = _dataset()
    baseline = LogisticRegression(epochs=15).fit(X, y).predict_proba(X)
    with_cb = LogisticRegression(epochs=15).fit(
        X, y, on_epoch=lambda step, m: None).predict_proba(X)
    assert baseline == with_cb   # callback is purely observational


def test_gbt_on_round_callback_fires_once_per_round_with_finite_loss():
    from fuzzlab.ml.gbt import GradientBoostedTrees
    X, y, _ = _dataset()
    calls = []
    GradientBoostedTrees(n_estimators=10).fit(
        X, y, on_round=lambda step, m: calls.append((step, m)))
    assert [c[0] for c in calls] == list(range(10))
    for _, metrics in calls:
        assert set(metrics) == {"train/loss", "train/mean_abs_update"}
        assert all(math.isfinite(v) for v in metrics.values())


def test_gbt_fit_without_on_round_is_unaffected():
    from fuzzlab.ml.gbt import GradientBoostedTrees
    X, y, _ = _dataset()
    baseline = GradientBoostedTrees(n_estimators=10).fit(X, y).predict_proba(X)
    with_cb = GradientBoostedTrees(n_estimators=10).fit(
        X, y, on_round=lambda step, m: None).predict_proba(X)
    assert baseline == with_cb   # callback is purely observational


# --- conformal ---------------------------------------------------------------

def test_conformal_decisions_and_calibration():
    rng = random.Random(5)
    # calibration set: positives skew high, negatives low, with overlap
    cal_scores, cal_y = [], []
    for _ in range(400):
        y = rng.random() < 0.4
        cal_scores.append(rng.uniform(0.4, 1.0) if y else rng.uniform(0.0, 0.6))
        cal_y.append(1 if y else 0)
    gate = ConformalGate.calibrate(cal_scores, cal_y, alpha=0.1)

    assert gate.decide(0.99) == "flag"
    assert gate.decide(0.01) == "drop"
    assert gate.t_lo <= gate.t_hi
    mid = (gate.t_lo + gate.t_hi) / 2
    assert gate.decide(mid) == "abstain"

    # held-out calibration: negatives are rarely flagged, positives rarely dropped.
    neg_flag = pos_drop = neg = pos = 0
    for _ in range(600):
        y = rng.random() < 0.4
        s = rng.uniform(0.4, 1.0) if y else rng.uniform(0.0, 0.6)
        if y:
            pos += 1
            pos_drop += gate.decide(s) == "drop"
        else:
            neg += 1
            neg_flag += gate.decide(s) == "flag"
    assert neg_flag / neg < 0.2                      # bounded false-positive rate
    assert pos_drop / pos < 0.2                      # bounded false-negative rate
