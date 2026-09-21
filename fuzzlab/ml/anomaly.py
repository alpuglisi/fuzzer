"""Anomaly-detection tripwire — ECOD (Phase 10 T10.3, ML component A.5).

ECOD (Empirical-Cumulative-distribution Outlier Detection) is a parameter-free,
pure-Python outlier detector: for each feature it estimates the empirical distribution,
then scores a point by how far into the distribution's tails it sits — aggregating
``-log(tail probability)`` across features (left, right, and a skewness-selected
aggregate; the score is their max). No numpy/sklearn, no hyperparameters, no labels.

It is **advisory** (same split as the Phase 5/7 ML): it produces scores/flags and a
hybrid feature for the classifier (XGBOD-style); it never writes `finding` labels. Use it
as a tripwire over attempt/flow feature vectors, and via ``augment`` to feed the anomaly
score into the detection classifier.
"""

from __future__ import annotations

import bisect
import math
from typing import Sequence


def skewness(values: Sequence[float]) -> float:
    """Sample skewness; 0 for a degenerate (zero-variance) feature."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    if var <= 0:
        return 0.0
    std = math.sqrt(var)
    return (sum((v - mean) ** 3 for v in values) / n) / (std ** 3)


class ECOD:
    """Empirical-CDF outlier detector. Fit on inlier-ish data; higher score = weirder."""

    def __init__(self):
        self._sorted: list[list[float]] = []
        self._skew: list[float] = []
        self._n = 0
        self._d = 0

    def fit(self, X: Sequence[Sequence[float]]) -> "ECOD":
        self._n = len(X)
        self._d = len(X[0]) if X else 0
        self._sorted = [sorted(row[j] for row in X) for j in range(self._d)]
        self._skew = [skewness([row[j] for row in X]) for j in range(self._d)]
        return self

    def _p_left(self, j: int, v: float) -> float:
        cnt = bisect.bisect_right(self._sorted[j], v)      # P(X <= v)
        return max(cnt, 1) / self._n                       # floor a count of 1

    def _p_right(self, j: int, v: float) -> float:
        cnt = self._n - bisect.bisect_left(self._sorted[j], v)  # P(X >= v)
        return max(cnt, 1) / self._n

    def score(self, x: Sequence[float]) -> float:
        """Outlier score of one point (max of the left / right / skew-auto aggregates)."""
        if self._n == 0 or self._d == 0:
            return 0.0
        o_left = o_right = o_auto = 0.0
        for j in range(self._d):
            ol = -math.log(self._p_left(j, x[j]))
            orr = -math.log(self._p_right(j, x[j]))
            o_left += ol
            o_right += orr
            o_auto += ol if self._skew[j] < 0 else orr     # skewness picks the tail
        return round(max(o_left, o_right, o_auto), 6)

    def scores(self, X: Sequence[Sequence[float]]) -> list[float]:
        return [self.score(row) for row in X]


def flag_top(scores: Sequence[float], contamination: float = 0.1) -> list[bool]:
    """Flag the top ``contamination`` fraction of scores as anomalies (advisory)."""
    if not scores:
        return []
    k = max(1, int(round(len(scores) * contamination)))
    threshold = sorted(scores, reverse=True)[k - 1]
    return [s >= threshold for s in scores]


def augment(X: Sequence[Sequence[float]], ecod: ECOD) -> list[list[float]]:
    """Append each row's ECOD score as an extra feature (the XGBOD-style hybrid)."""
    return [list(row) + [ecod.score(row)] for row in X]


def detect_anomalies(store, run_id: int | None = None,
                     contamination: float = 0.1) -> dict:
    """Fit ECOD over the run's candidate feature vectors and flag outliers (advisory).

    Returns scores + flags and records the flagged count in `run_metrics`. Writes **no**
    labels — this is a tripwire, not a confirmer.
    """
    from fuzzlab.ml.dataset import build_dataset
    ds = build_dataset(store, run_id)
    if not len(ds):
        return {"rows": 0, "flagged": 0, "scores": [], "flags": [], "ids": []}
    ecod = ECOD().fit(ds.X)
    scores = ecod.scores(ds.X)
    flags = flag_top(scores, contamination)
    if run_id is not None:
        store.conn.execute(
            "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
            (run_id, "anomaly_flagged", float(sum(flags))))
        store.conn.commit()
    return {"rows": len(ds), "flagged": sum(flags), "scores": scores,
            "flags": flags, "ids": ds.ids}
