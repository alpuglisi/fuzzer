"""The dumb baselines a real classifier must beat (honest comparison, Phase 5).

- `PrevalenceBaseline` — predicts the training positive rate for everything (no
  features). The floor: any useful model must beat it on PR-AUC.
- `SigmaBaseline` — the classic "mean + kσ" anomaly detector: score = the largest
  per-feature z-score, fit on the training features. A model must beat this too.

Pure Python; both expose `fit(X, y)` / `predict_proba(X)` returning P(positive)-like
scores in [0, 1] (monotonic is enough for ranking / PR-AUC).
"""

from __future__ import annotations

import math
from typing import Sequence


class PrevalenceBaseline:
    def __init__(self) -> None:
        self._rate = 0.0

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int]) -> "PrevalenceBaseline":
        self._rate = (sum(1 for v in y if v) / len(y)) if y else 0.0
        return self

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        return [self._rate for _ in X]


class SigmaBaseline:
    """Anomaly score = max over features of the z-score |x-mean|/std (squashed to [0,1))."""

    def __init__(self) -> None:
        self._mean: list[float] = []
        self._std: list[float] = []

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int] | None = None) -> "SigmaBaseline":
        if not X:
            self._mean, self._std = [], []
            return self
        d = len(X[0])
        self._mean = [sum(row[j] for row in X) / len(X) for j in range(d)]
        self._std = []
        for j in range(d):
            var = sum((row[j] - self._mean[j]) ** 2 for row in X) / len(X)
            self._std.append(math.sqrt(var) or 1.0)     # guard zero-variance features
        return self

    def _z(self, row: Sequence[float]) -> float:
        return max((abs(row[j] - self._mean[j]) / self._std[j]
                    for j in range(len(self._mean))), default=0.0)

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        # squash z >= 0 to [0, 1): 1 - exp(-z/k) is monotonic in z (k spreads the scale).
        return [1.0 - math.exp(-self._z(row) / 3.0) for row in X]
