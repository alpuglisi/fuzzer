"""ML components (Phase 5): a *detection* classifier that produces advisory scores.

Strict oracle/advisory split: nothing here writes `finding` labels — the oracle is the
sole label authority. This layer produces **scores** and **uncertainty** (and a
conformal flag/abstain/drop), which rank and triage candidates but never confirm.

Phase 5 groundwork, dependency-light (pure Python — no numpy/sklearn):
- `metrics` — PR-AUC (average precision) and a leakage-free `group_kfold` (never split
  an endpoint across folds);
- `baselines` — the dumb baselines a real model must beat (prevalence, mean+kσ);
- `logistic` — a pure-Python logistic-regression classifier (standardized, L2,
  class-balanced);
- `conformal` — split-conformal calibration producing flag / abstain / drop.

Gradient-boosted trees (needs numpy/sklearn) and the store-trained pipeline come later.
"""

from fuzzlab.ml.baselines import PrevalenceBaseline, SigmaBaseline
from fuzzlab.ml.conformal import ConformalGate
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.metrics import group_kfold, pr_auc

__all__ = ["PrevalenceBaseline", "SigmaBaseline", "LogisticRegression",
           "ConformalGate", "group_kfold", "pr_auc"]
