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

**Isolation Forest** (CC-ML-0021, FR-ML-22) is the alternative detector
(``method="iforest"``): random isolation trees, score ``2^(-E[h(x)] / c(ψ))`` in (0, 1),
higher = more anomalous. Pure Python, deterministic per ``(seed, n_trees,
max_samples)``. ECOD stays the default (parameter-free) and the hybrid feature.
"""

from __future__ import annotations

import bisect
import math
from collections import Counter
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

    def to_params(self) -> dict:                       # CC-ML-0015
        return {"n": self._n, "d": self._d, "sorted": [list(c) for c in self._sorted],
                "skew": list(self._skew)}

    @classmethod
    def from_params(cls, d: dict) -> "ECOD":
        e = cls()
        e._n, e._d = d["n"], d["d"]
        e._sorted = [list(c) for c in d["sorted"]]
        e._skew = list(d["skew"])
        return e


#: Recorded as ``run_metrics.anomaly_flag_rule`` by `detect_anomalies` since
#: CC-ML-0019: flags never split a tie group and never exceed `flag_budget`. A run with
#: stored flags and no such metric used the earlier rule (tie groups could exceed it).
FLAG_RULE = 2


_EULER = 0.5772156649015329


def average_path_length(n: int) -> float:
    """``c(n)``: the average path length of an unsuccessful BST search over ``n`` points
    — the normaliser of Isolation Forest path lengths. ``c(n) = 2·H(n-1) - 2(n-1)/n``
    with the harmonic number computed exactly for ``n ≤ 10_000`` (``ln + γ`` above);
    ``c(2) = 1``, ``c(n ≤ 1) = 0``."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    m = n - 1
    harmonic = sum(1.0 / i for i in range(1, m + 1)) if m <= 10_000 else \
        math.log(m) + _EULER
    return 2.0 * harmonic - 2.0 * (n - 1) / n


class IsolationForest:
    """Random isolation trees over feature rows (Liu, Ting & Zhou 2008).

    Each tree is grown on a seeded sample of ``ψ = min(max_samples, n)`` rows to depth
    ``ceil(log2 ψ)``: a node splits on a random feature **among those with range > 0**
    at a uniform random value; a node with no such feature (all rows equal) is a leaf.
    A leaf holding ``size`` rows adds ``c(size)``. With ``n ≤ 2`` there is nothing to
    isolate: every score is 0.5 (and `detect_anomalies` flags nothing)."""

    def __init__(self, n_trees: int = 100, max_samples: int = 256, seed: int = 0):
        self.n_trees, self.max_samples, self.seed = n_trees, max_samples, seed
        self._trees: list = []
        self._psi = 0

    def fit(self, X: Sequence[Sequence[float]]) -> "IsolationForest":
        import random
        n = len(X)
        self._trees, self._psi = [], min(self.max_samples, n)
        if n <= 2:
            return self
        rng = random.Random(self.seed)
        limit = math.ceil(math.log2(self._psi))
        for _ in range(self.n_trees):
            rows = [list(X[i]) for i in rng.sample(range(n), self._psi)]
            self._trees.append(self._grow(rows, 0, limit, rng))
        return self

    def _grow(self, rows, depth: int, limit: int, rng):
        if depth >= limit or len(rows) <= 1:
            return ("leaf", len(rows))
        width = len(rows[0])
        spans = [(j, min(r[j] for r in rows), max(r[j] for r in rows)) for j in range(width)]
        spans = [s for s in spans if s[2] > s[1]]
        if not spans:                                # all rows identical
            return ("leaf", len(rows))
        j, lo, hi = spans[rng.randrange(len(spans))]
        cut = rng.uniform(lo, hi)
        left = [r for r in rows if r[j] < cut]
        right = [r for r in rows if r[j] >= cut]
        return ("split", j, cut, self._grow(left, depth + 1, limit, rng),
                self._grow(right, depth + 1, limit, rng))

    def _path(self, x, node, depth: int = 0) -> float:
        while node[0] == "split":
            _, j, cut, left, right = node
            node = left if x[j] < cut else right
            depth += 1
        return depth + average_path_length(node[1])

    def score(self, x: Sequence[float]) -> float:
        if not self._trees:
            return 0.5
        mean = sum(self._path(x, t) for t in self._trees) / len(self._trees)
        return 2.0 ** (-mean / average_path_length(self._psi))

    def scores(self, X: Sequence[Sequence[float]]) -> list[float]:
        return [self.score(x) for x in X]


#: `detect_anomalies(method=…)` choices; ECOD is the default (parameter-free).
ANOMALY_METHODS = ("ecod", "iforest")


def fit_detector(method: str, X, *, seed: int = 0):
    """A fitted detector (``.scores(X)``) for ``method``."""
    if method == "ecod":
        return ECOD().fit(X)
    if method == "iforest":
        return IsolationForest(seed=seed).fit(X)
    raise ValueError(f"anomaly method must be one of {ANOMALY_METHODS}, got {method!r}")


def flag_budget(n: int, contamination: float) -> int:
    """The most candidates a ``contamination`` fraction may flag among ``n``:
    ``max(1, round(n·contamination))`` (0 when there are none). One definition for the
    detector and the ML tab (PA-0003)."""
    return max(1, int(round(n * contamination))) if n else 0


def flag_top(scores: Sequence[float], contamination: float = 0.1) -> list[bool]:
    """Flag **at most** `flag_budget` of the highest scores as anomalies (advisory),
    taking **whole tie groups only**: identical scores are equally unusual, so a group is
    flagged entirely or not at all (CC-ML-0019, BUG-0070's sweep — the earlier rule
    flagged every score tied with the k-th, e.g. 30% at contamination 0.1). When the top
    tie group alone exceeds the budget nothing is flagged: nothing stands out.

    One counting pass, ``O(n + u log u)`` for ``u`` distinct scores (BUG-0094, PA-0095:
    the tie groups were once counted by rescanning every score per distinct value). A
    non-finite score raises ``ValueError``: NaN has no place in an ordering."""
    if not all(math.isfinite(s) for s in scores):
        raise ValueError("flag_top: anomaly scores must be finite")
    k = flag_budget(len(scores), contamination)
    sizes = Counter(scores)
    cutoff = None                        # lowest score still flagged
    taken = 0
    for value in sorted(sizes, reverse=True):
        size = sizes[value]
        if taken + size > k:
            break
        taken += size
        cutoff = value
    return [cutoff is not None and s >= cutoff for s in scores]


def flag_reason(scores: Sequence[float], flags: Sequence[bool],
                contamination: float) -> str | None:
    """Why fewer than `flag_budget` were flagged (a tie group straddles the cut), or
    ``None`` when the budget was met."""
    k = flag_budget(len(scores), contamination)
    flagged = sum(1 for f in flags if f)
    if flagged >= k:
        return None
    rest = [s for s, f in zip(scores, flags) if not f]
    top = max(rest)
    size = sum(1 for s in rest if s == top)
    if not flagged:
        return f"top tie group of {size} exceeds k={k}: nothing stands out"
    return (f"flagged {flagged} of at most k={k}: the next tie group of {size} would "
            f"exceed it")


def augment(X: Sequence[Sequence[float]], ecod: ECOD) -> list[list[float]]:
    """Append each row's ECOD score as an extra feature (the XGBOD-style hybrid)."""
    return [list(row) + [ecod.score(row)] for row in X]


def detect_anomalies(store, run_id: int | None = None, contamination: float = 0.1, *,
                     persist: bool = True, method: str = "ecod", seed: int = 0) -> dict:
    """Fit ECOD over the run's candidate feature vectors and flag outliers (advisory).

    Label-free, so every candidate is scored — including ones the oracle skipped for
    budget. With ``persist`` (default) each candidate's ``anomaly_score`` /
    ``anomaly_flag`` is written to the store (migration 13), and the flagged count, the
    budget k and the flag rule are recorded in `run_metrics` (``anomaly_flagged``,
    ``anomaly_flag_budget``, ``anomaly_flag_rule``). At most k are flagged, whole tie
    groups only (`flag_top`); ``flag_reason`` says why fewer were. Writes **no** labels —
    this is a tripwire, not a confirmer.

    A flag is relative to the candidates scored together: call it per run (the CLI
    does); a later store-wide call (``run_id=None``) would overwrite per-run flags.

    ``method="iforest"`` (CC-ML-0021) uses `IsolationForest` (seeded) instead of ECOD;
    with two or fewer candidates it flags nothing.
    """
    if not 0 < contamination <= 0.5:
        raise ValueError(f"contamination must be in (0, 0.5], got {contamination!r}")
    if method not in ANOMALY_METHODS:
        raise ValueError(f"anomaly method must be one of {ANOMALY_METHODS}, got {method!r}")
    from fuzzlab.ml.dataset import build_dataset
    ds = build_dataset(store, run_id, include_unlabelled=True)
    if not len(ds):
        return {"rows": 0, "flagged": 0, "flag_budget": 0, "flag_reason": None,
                "method": method, "scores": [], "flags": [], "ids": []}
    scores = fit_detector(method, ds.X, seed=seed).scores(ds.X)
    flags = flag_top(scores, contamination)
    k = flag_budget(len(scores), contamination)
    reason = flag_reason(scores, flags, contamination)
    if method == "iforest" and len(scores) <= 2:     # nothing to isolate: budget 0
        flags, k = [False] * len(scores), 0
        reason = "too few candidates to isolate (n ≤ 2)"
    if persist:
        for cid, sc, fl in zip(ds.ids, scores, flags):
            store.conn.execute(
                "UPDATE candidate SET anomaly_score=?, anomaly_flag=? WHERE id=?",
                (sc, 1 if fl else 0, cid))
    if run_id is not None:
        for key, value in (("anomaly_flagged", sum(flags)), ("anomaly_flag_budget", k),
                           ("anomaly_flag_rule", FLAG_RULE)):
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, key, float(value)))
        if persist:          # the candidate feature version the stored flags read (BUG-0069)
            # appended like the other anomaly metrics: the stage runs under the advisory
            # write guard, which denies DELETE; a rerun adds an identical value
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, "anomaly_feature_version", float(ds.feature_version)))
    store.conn.commit()
    return {"rows": len(ds), "flagged": sum(flags), "flag_budget": k, "method": method,
            "flag_reason": reason, "scores": scores, "flags": flags, "ids": ds.ids}
