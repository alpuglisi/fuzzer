"""A pure-Python logistic-regression detection classifier (Phase 5).

Standardizes features, trains by full-batch gradient descent with L2 and class
balancing (the positive class is rare), and outputs a calibrated-ish probability.
Advisory only: it scores/ranks candidates; it never writes labels.
"""

from __future__ import annotations

import math
from typing import Sequence


def _sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class LogisticRegression:
    def __init__(self, epochs: int = 300, lr: float = 0.1, l2: float = 0.001,
                 class_balanced: bool = True):
        self.epochs = epochs
        self.lr = lr
        self.l2 = l2
        self.class_balanced = class_balanced
        self._w: list[float] = []
        self._b = 0.0
        self._mean: list[float] = []
        self._std: list[float] = []

    def _standardize(self, X: Sequence[Sequence[float]]) -> list[list[float]]:
        return [[(row[j] - self._mean[j]) / self._std[j] for j in range(len(self._mean))]
                for row in X]

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int]) -> "LogisticRegression":
        n, d = len(X), (len(X[0]) if X else 0)
        self._mean = [sum(r[j] for r in X) / n for j in range(d)]
        self._std = []
        for j in range(d):
            var = sum((r[j] - self._mean[j]) ** 2 for r in X) / n
            self._std.append(math.sqrt(var) or 1.0)
        Xs = self._standardize(X)
        self._w = [0.0] * d
        self._b = 0.0

        pos = sum(1 for v in y if v) or 1
        neg = (n - pos) or 1
        w_pos = (n / (2.0 * pos)) if self.class_balanced else 1.0
        w_neg = (n / (2.0 * neg)) if self.class_balanced else 1.0

        for _ in range(self.epochs):
            gw = [0.0] * d
            gb = 0.0
            for row, label in zip(Xs, y):
                p = _sigmoid(sum(self._w[j] * row[j] for j in range(d)) + self._b)
                weight = w_pos if label else w_neg
                err = weight * (p - label)
                for j in range(d):
                    gw[j] += err * row[j]
                gb += err
            for j in range(d):
                self._w[j] -= self.lr * (gw[j] / n + self.l2 * self._w[j])
            self._b -= self.lr * (gb / n)
        return self

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        Xs = self._standardize(X)
        return [_sigmoid(sum(self._w[j] * row[j] for j in range(len(self._w))) + self._b)
                for row in Xs]
