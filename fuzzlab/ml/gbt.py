"""Gradient-boosted decision trees for detection (Phase 5 T5.4), pure Python.

Logistic-loss gradient boosting over shallow weighted regression trees: it captures
non-linear feature interactions the linear model misses, behind the same
`fit`/`predict_proba` interface as `LogisticRegression`. Class-balanced (rare
positives up-weighted) via per-sample weights folded into the trees' weighted splits.
Deterministic (no subsampling) so tests are exact. Advisory only — scores, never labels.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Sequence


def _sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class _Node:
    feature: int = -1
    threshold: float = 0.0
    left: "_Node | None" = None
    right: "_Node | None" = None
    value: float = 0.0             # leaf prediction (weighted mean residual)

    @property
    def is_leaf(self) -> bool:
        return self.left is None


class _RegressionTree:
    """A weighted CART regression tree fit to residuals (squared-error splits)."""

    def __init__(self, max_depth: int = 3, min_leaf: int = 3):
        self.max_depth = max_depth
        self.min_leaf = min_leaf
        self.root: _Node | None = None

    def fit(self, X, residuals, weights, idx=None, depth=0) -> "_RegressionTree":
        if idx is None:
            idx = list(range(len(residuals)))
        self.root = self._build(X, residuals, weights, idx, depth)
        return self

    def _leaf(self, residuals, weights, idx) -> _Node:
        wsum = sum(weights[i] for i in idx) or 1.0
        return _Node(value=sum(weights[i] * residuals[i] for i in idx) / wsum)

    def _build(self, X, residuals, weights, idx, depth) -> _Node:
        if depth >= self.max_depth or len(idx) < 2 * self.min_leaf:
            return self._leaf(residuals, weights, idx)
        split = self._best_split(X, residuals, weights, idx)
        if split is None:
            return self._leaf(residuals, weights, idx)
        f, thr = split
        left = [i for i in idx if X[i][f] <= thr]
        right = [i for i in idx if X[i][f] > thr]
        node = _Node(feature=f, threshold=thr)
        node.left = self._build(X, residuals, weights, left, depth + 1)
        node.right = self._build(X, residuals, weights, right, depth + 1)
        return node

    def _best_split(self, X, residuals, weights, idx):
        d = len(X[0])
        total_w = sum(weights[i] for i in idx)
        total_wg = sum(weights[i] * residuals[i] for i in idx)
        best_gain, best = 0.0, None
        parent = (total_wg * total_wg / total_w) if total_w else 0.0
        for f in range(d):
            order = sorted(idx, key=lambda i: X[i][f])
            lw = lwg = 0.0
            lc = 0
            for pos in range(len(order) - 1):
                i = order[pos]
                lw += weights[i]; lwg += weights[i] * residuals[i]; lc += 1
                if X[order[pos]][f] == X[order[pos + 1]][f]:
                    continue
                rc = len(order) - lc
                if lc < self.min_leaf or rc < self.min_leaf or lw <= 0 or (total_w - lw) <= 0:
                    continue
                rw, rwg = total_w - lw, total_wg - lwg
                gain = (lwg * lwg / lw) + (rwg * rwg / rw) - parent   # SSE reduction
                if gain > best_gain:
                    best_gain = gain
                    best = (f, (X[order[pos]][f] + X[order[pos + 1]][f]) / 2.0)
        return best

    def predict_one(self, x) -> float:
        node = self.root
        while node is not None and not node.is_leaf:
            node = node.left if x[node.feature] <= node.threshold else node.right
        return node.value if node else 0.0


class GradientBoostedTrees:
    def __init__(self, n_estimators: int = 60, lr: float = 0.3, max_depth: int = 3,
                 min_leaf: int = 3, class_balanced: bool = True):
        self.n_estimators = n_estimators
        self.lr = lr
        self.max_depth = max_depth
        self.min_leaf = min_leaf
        self.class_balanced = class_balanced
        self._trees: list[_RegressionTree] = []
        self._f0 = 0.0
        self._w: list[float] = []

    def fit(
        self,
        X: Sequence[Sequence[float]],
        y: Sequence[int],
        on_round: "Callable[[int, dict[str, float]], None] | None" = None,
    ) -> "GradientBoostedTrees":
        """Fit by gradient boosting. ``on_round``, if given, is called after every
        boosting round as ``on_round(step, {\"train/loss\": ..., \"train/leaf_gain\": ...})``
        with the (class-weighted) training log-loss under the current ensemble and that
        round's tree's total weighted split gain — purely observational (metric
        emission), never touching the optimization path."""
        n = len(y)
        pos = sum(1 for v in y if v) or 1
        neg = (n - pos) or 1
        self._w = [((n / (2.0 * pos)) if v else (n / (2.0 * neg)))
                   if self.class_balanced else 1.0 for v in y]
        wsum = sum(self._w) or 1.0
        p0 = min(1 - 1e-6, max(1e-6, sum(w * v for w, v in zip(self._w, y)) / wsum))
        self._f0 = math.log(p0 / (1.0 - p0))
        F = [self._f0] * n
        self._trees = []
        wsum_all = sum(self._w) or 1.0
        for step in range(self.n_estimators):
            resid = [y[i] - _sigmoid(F[i]) for i in range(n)]        # -gradient of logloss
            tree = _RegressionTree(self.max_depth, self.min_leaf).fit(X, resid, self._w)
            updates = [tree.predict_one(X[i]) for i in range(n)]
            for i in range(n):
                F[i] += self.lr * updates[i]
            self._trees.append(tree)
            if on_round is not None:
                loss = 0.0
                for i in range(n):
                    p = min(1 - 1e-12, max(1e-12, _sigmoid(F[i])))
                    loss += self._w[i] * -(y[i] * math.log(p) + (1 - y[i]) * math.log(1 - p))
                mean_abs_update = sum(abs(u) for u in updates) / n if n else 0.0
                on_round(step, {
                    "train/loss": loss / wsum_all,
                    "train/mean_abs_update": mean_abs_update,
                })
        return self

    def _raw(self, x) -> float:
        return self._f0 + self.lr * sum(t.predict_one(x) for t in self._trees)

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        return [_sigmoid(self._raw(x)) for x in X]
