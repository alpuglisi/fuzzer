"""Tests for the gradient-boosted-trees detection model (Phase 5 T5.4, pure Python).

GBT captures non-linear structure the linear model cannot, so on a checkerboard
(XOR-like) boundary it beats logistic *and* both baselines on GroupKFold PR-AUC.
"""

import random

from fuzzlab.ml import GradientBoostedTrees, LogisticRegression, pr_auc
from fuzzlab.ml.baselines import PrevalenceBaseline, SigmaBaseline
from fuzzlab.ml.metrics import group_kfold


def _nonlinear(seed=0, n=300, groups=30):
    """Positive iff x0 and x1 share sign (two diagonal quadrants) — not linearly
    separable, so logistic is near chance while GBT can carve the quadrants."""
    rng = random.Random(seed)
    X, y, g = [], [], []
    for i in range(n):
        x0, x1 = rng.gauss(0, 1), rng.gauss(0, 1)
        label = 1 if (x0 > 0) == (x1 > 0) else 0
        X.append([x0, x1]); y.append(label); g.append(i % groups)
    return X, y, g


def _cv_pr_auc(factory, X, y, groups):
    aucs = []
    for tr, te in group_kfold(groups, k=6, seed=3):
        m = factory().fit([X[i] for i in tr], [y[i] for i in tr])
        aucs.append(pr_auc([y[i] for i in te], m.predict_proba([X[i] for i in te])))
    return sum(aucs) / len(aucs)


def test_gbt_predict_proba_in_range():
    X, y, _ = _nonlinear(n=60, groups=6)
    probs = GradientBoostedTrees(n_estimators=20).fit(X, y).predict_proba(X)
    assert all(0.0 <= p <= 1.0 for p in probs)


def test_gbt_beats_logistic_and_baselines_on_nonlinear_data():
    X, y, groups = _nonlinear()
    gbt = _cv_pr_auc(lambda: GradientBoostedTrees(n_estimators=60, lr=0.3), X, y, groups)
    logistic = _cv_pr_auc(LogisticRegression, X, y, groups)
    prevalence = _cv_pr_auc(PrevalenceBaseline, X, y, groups)
    sigma = _cv_pr_auc(SigmaBaseline, X, y, groups)
    assert gbt > logistic                       # non-linear structure the line misses
    assert gbt > prevalence and gbt > sigma      # beats both dumb baselines
    assert gbt > 0.75
