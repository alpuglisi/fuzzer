"""A pure-Python logistic-regression detection classifier (Phase 5).

Standardizes features, trains by full-batch gradient descent with L2 and class
balancing (the positive class is rare), and outputs a calibrated-ish probability.
Advisory only: it scores/ranks candidates; it never writes labels.
"""

from __future__ import annotations

import math
from typing import Callable, Sequence


#: The smallest standard deviation a feature is scaled by (BUG-0103). A smaller one —
#: a near-constant feature — is treated like a constant one (scaled by 1.0), so a fitted
#: model never divides by a value that turns a finite feature into infinity.
STD_FLOOR = 1e-12


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

    def fit(
        self,
        X: Sequence[Sequence[float]],
        y: Sequence[int],
        on_epoch: "Callable[[int, dict[str, float]], None] | None" = None,
    ) -> "LogisticRegression":
        """Fit by full-batch gradient descent. ``on_epoch``, if given, is called
        after every epoch as ``on_epoch(step, {\"train/loss\": ..., \"train/l2_norm\": ...})``
        with the (class-weighted) training log-loss and the L2 weight norm — purely
        observational (metric emission), never touching the optimization path."""
        n, d = len(X), (len(X[0]) if X else 0)
        self._mean = [sum(r[j] for r in X) / n for j in range(d)]
        self._std = []
        for j in range(d):
            var = sum((r[j] - self._mean[j]) ** 2 for r in X) / n
            sd = math.sqrt(var)
            self._std.append(sd if sd >= STD_FLOOR else 1.0)
        Xs = self._standardize(X)
        self._w = [0.0] * d
        self._b = 0.0

        pos = sum(1 for v in y if v) or 1
        neg = (n - pos) or 1
        w_pos = (n / (2.0 * pos)) if self.class_balanced else 1.0
        w_neg = (n / (2.0 * neg)) if self.class_balanced else 1.0

        for epoch in range(self.epochs):
            gw = [0.0] * d
            gb = 0.0
            loss = 0.0
            for row, label in zip(Xs, y):
                p = _sigmoid(sum(self._w[j] * row[j] for j in range(d)) + self._b)
                weight = w_pos if label else w_neg
                err = weight * (p - label)
                for j in range(d):
                    gw[j] += err * row[j]
                gb += err
                pc = min(1 - 1e-12, max(1e-12, p))
                loss += weight * -(label * math.log(pc) + (1 - label) * math.log(1 - pc))
            for j in range(d):
                self._w[j] -= self.lr * (gw[j] / n + self.l2 * self._w[j])
            self._b -= self.lr * (gb / n)
            if on_epoch is not None:
                l2_norm = math.sqrt(sum(w * w for w in self._w))
                on_epoch(epoch, {"train/loss": loss / n, "train/l2_norm": l2_norm})
        return self

    def check_finite(self, X: Sequence[Sequence[float]]) -> None:
        """Raise ``ValueError`` unless every standardized feature and every logit of
        ``X`` is finite (BUG-0103: individually finite parameters do not prove the
        arithmetic stays finite)."""
        for row in self._standardize(X):
            if not all(math.isfinite(z) for z in row):
                raise ValueError("a standardized feature is not finite")
            logit = sum(self._w[j] * row[j] for j in range(len(self._w))) + self._b
            if not math.isfinite(logit):
                raise ValueError("a logit is not finite")

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        Xs = self._standardize(X)
        return [_sigmoid(sum(self._w[j] * row[j] for j in range(len(self._w))) + self._b)
                for row in Xs]

    # --- persistence (CC-ML-0015; envelope + validation live in fuzzlab.ml.persist) ---
    def to_params(self) -> dict:
        return {"epochs": self.epochs, "lr": self.lr, "l2": self.l2,
                "class_balanced": self.class_balanced, "w": list(self._w), "b": self._b,
                "mean": list(self._mean), "std": list(self._std)}

    @classmethod
    def from_params(cls, d: dict) -> "LogisticRegression":
        m = cls(epochs=d["epochs"], lr=d["lr"], l2=d["l2"],
                class_balanced=d["class_balanced"])
        m._w, m._b = list(d["w"]), d["b"]
        m._mean, m._std = list(d["mean"]), list(d["std"])
        return m
