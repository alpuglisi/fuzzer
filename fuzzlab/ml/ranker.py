"""Pointwise candidate ranker (Phase 7 T7.2).

Orders the auditor's candidates so real vulnerabilities surface first, at **zero request
cost**. It augments the fixed structural feature vector (Phase 5's `dataset` features)
with char n-gram TF-IDF over the candidate's text (param/path/category/method) and fits
a **pointwise** scorer — the existing pure-Python logistic model reused as a ranker.

Advisory only: it emits a ranking score (and, via the active learner, an uncertainty);
it never writes labels. Because the model is linear over interpretable features, it can
**explain** a score as the top contributing features.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from fuzzlab.ml.dataset import FEATURE_NAMES
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.text_features import CharNgramVectorizer


@dataclass
class Explanation:
    score: float
    contributions: list[tuple[str, float]]      # (feature_name, signed contribution)


class Ranker:
    def __init__(self, n: int = 3, max_features: int = 64, model=None, seed: int = 0):
        self.vectorizer = CharNgramVectorizer(n=n, max_features=max_features)
        self.model = model if model is not None else LogisticRegression()
        self.seed = seed
        self.feature_names: list[str] = []

    def _augment(self, structural: Sequence[Sequence[float]], texts: Sequence[str],
                 fit: bool) -> list[list[float]]:
        tfidf = (self.vectorizer.fit_transform(texts) if fit
                 else self.vectorizer.transform(texts))
        return [list(s) + t for s, t in zip(structural, tfidf)]

    def fit(self, structural: Sequence[Sequence[float]], texts: Sequence[str],
            y: Sequence[int]) -> "Ranker":
        X = self._augment(structural, texts, fit=True)
        self.model.fit(X, y)
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
