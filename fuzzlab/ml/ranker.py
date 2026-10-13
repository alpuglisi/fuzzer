"""Candidate ranker — pointwise, or pairwise learning-to-rank (Phase 7 T7.2, FR-ML-2).

Orders the auditor's candidates so real vulnerabilities surface first, at **zero request
cost**. It augments the fixed structural feature vector (Phase 5's `dataset` features)
with char n-gram TF-IDF over the candidate's text (param/path/category/method) and fits
a **pointwise** scorer — the existing pure-Python logistic model reused as a ranker.

Advisory only: it emits a ranking score (and, via the active learner, an uncertainty);
it never writes labels. Because the model is linear over interpretable features, it can
**explain** a score as the top contributing features.

``objective="pairwise"`` (CC-ML-0021, FR-ML-21) fits the same logistic model on
**pair differences** ``x_pos − x_neg`` (label 1) and ``x_neg − x_pos`` (label 0) over
every (positive, negative) pair in the training set — run-wide, because consumers order
the whole run — a seeded sample capped at `MAX_PAIRS`. The score ``σ(w·x)`` is monotone
in the learned order but is **not a probability** (so no uncertainty is derived from
it). With no pair (one class) it falls back to the pointwise fit
(``objective_used``).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence

from fuzzlab.ml.dataset import FEATURE_NAMES
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.text_features import CharNgramVectorizer


@dataclass
class Explanation:
    score: float
    contributions: list[tuple[str, float]]      # (feature_name, signed contribution)


#: Cap on (positive, negative) pairs per pairwise fit (each enters in both orders).
MAX_PAIRS = 5000
OBJECTIVES = ("pointwise", "pairwise")


def sample_pairs(y: Sequence[int], seed: int, cap: int = MAX_PAIRS) -> list[tuple[int, int]]:
    """Every (positive, negative) index pair, or a seeded sample of ``cap`` of them."""
    pos = [i for i, v in enumerate(y) if v]
    neg = [i for i, v in enumerate(y) if not v]
    total = len(pos) * len(neg)
    picks = range(total) if total <= cap else sorted(random.Random(seed).sample(
        range(total), cap))
    return [(pos[t // len(neg)], neg[t % len(neg)]) for t in picks]


class Ranker:
    def __init__(self, n: int = 3, max_features: int = 64, model=None, seed: int = 0,
                 objective: str = "pointwise"):
        if objective not in OBJECTIVES:
            raise ValueError(f"ranker objective must be one of {OBJECTIVES}, "
                             f"got {objective!r}")
        self.vectorizer = CharNgramVectorizer(n=n, max_features=max_features)
        self.model = model if model is not None else LogisticRegression()
        self.seed = seed
        self.objective = objective
        self.objective_used = objective         # pairwise with no pair → pointwise
        self.feature_names: list[str] = []

    def _augment(self, structural: Sequence[Sequence[float]], texts: Sequence[str],
                 fit: bool) -> list[list[float]]:
        tfidf = (self.vectorizer.fit_transform(texts) if fit
                 else self.vectorizer.transform(texts))
        return [list(s) + t for s, t in zip(structural, tfidf)]

    def fit(self, structural: Sequence[Sequence[float]], texts: Sequence[str],
            y: Sequence[int]) -> "Ranker":
        X = self._augment(structural, texts, fit=True)
        pairs = sample_pairs(y, self.seed) if self.objective == "pairwise" else []
        if pairs:
            diffs, labels = [], []
            for i, j in pairs:
                d = [a - b for a, b in zip(X[i], X[j])]
                diffs += [d, [-v for v in d]]
                labels += [1, 0]
            self.model.fit(diffs, labels)
            self.objective_used = "pairwise"
        else:
            self.model.fit(X, y)
            self.objective_used = "pointwise"
        self.feature_names = list(FEATURE_NAMES) + self.vectorizer.feature_names()
        return self

    def score(self, structural: Sequence[Sequence[float]],
              texts: Sequence[str]) -> list[float]:
        return self.model.predict_proba(self._augment(structural, texts, fit=False))

    def explain(self, structural_row: Sequence[float], text: str,
                top: int = 5) -> Explanation:
        """Top contributing features for one candidate (linear model contributions)."""
        X = self._augment([structural_row], [text], fit=False)[0]
        score = self.model.predict_proba([X])[0]
        w = getattr(self.model, "_w", [])
        mean = getattr(self.model, "_mean", [])
        std = getattr(self.model, "_std", [])
        contribs: list[tuple[str, float]] = []
        for j, name in enumerate(self.feature_names):
            if j < len(w) and j < len(mean) and j < len(std) and std[j]:
                contribs.append((name, w[j] * (X[j] - mean[j]) / std[j]))
        contribs.sort(key=lambda t: abs(t[1]), reverse=True)
        return Explanation(score=round(score, 6), contributions=contribs[:top])

    # --- persistence (CC-ML-0015; envelope + validation live in fuzzlab.ml.persist) ---
    # The ranker accepts an injected model, so the nested model records its own kind.
    def to_params(self) -> dict:
        if not isinstance(self.model, LogisticRegression):
            raise TypeError(f"cannot persist a ranker over {type(self.model).__name__}")
        out = {"seed": self.seed, "vectorizer": self.vectorizer.to_params(),
               "model": {"kind": "logistic", "params": self.model.to_params()},
               "feature_names": list(self.feature_names)}
        if self.objective_used == "pairwise":   # absent = pointwise: old text unchanged
            out["objective"] = "pairwise"
        return out

    @classmethod
    def from_params(cls, d: dict) -> "Ranker":
        if d["model"]["kind"] != "logistic":
            raise ValueError(f"unsupported ranker model kind {d['model']['kind']!r}")
        objective = d.get("objective", "pointwise")
        r = cls(seed=d["seed"], model=LogisticRegression.from_params(d["model"]["params"]),
                objective=objective)
        r.vectorizer = CharNgramVectorizer.from_params(d["vectorizer"])
        r.feature_names = list(d["feature_names"])
        return r
