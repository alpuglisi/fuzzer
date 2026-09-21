"""Char n-gram TF-IDF features for candidates (Phase 7 T7.1).

Parameter names and URL paths carry weak but real signal a fixed structural vector
misses — ``id`` vs ``redirect_url`` vs ``tpl`` vs ``q``, ``/admin`` vs ``/static``.
Character n-grams capture it without a hand-built vocabulary and shrug off unseen
tokens. This is a small, deterministic, pure-Python TF-IDF vectorizer (no
numpy/sklearn): fit a bounded vocabulary of the most frequent n-grams, then emit
L2-normalized TF-IDF vectors.

Deterministic: the vocabulary is the top ``max_features`` n-grams ordered by document
frequency, ties broken by the n-gram itself, so the same corpus always yields the same
columns.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

from fuzzlab.core.urls import to_path


def candidate_text(ev: dict) -> str:
    """The text an injection point is described by: param, path, category, method."""
    param = (ev.get("param") or "").strip()
    path = to_path(ev.get("url") or "")
    cat = (ev.get("category") or "").strip()
    method = (ev.get("method") or "GET").strip()
    return f"{param} {path} {cat} {method}".lower()


def _ngrams(text: str, n: int) -> list[str]:
    if len(text) < n:
        return [text] if text else []
    return [text[i:i + n] for i in range(len(text) - n + 1)]


class CharNgramVectorizer:
    """Bounded, deterministic char n-gram TF-IDF."""

    def __init__(self, n: int = 3, max_features: int = 64):
        self.n = n
        self.max_features = max_features
        self.vocab: list[str] = []
        self._index: dict[str, int] = {}
        self._idf: list[float] = []

    def fit(self, texts: Sequence[str]) -> "CharNgramVectorizer":
        n_docs = len(texts) or 1
        doc_freq: Counter = Counter()
        for t in texts:
            for g in set(_ngrams(t, self.n)):
                doc_freq[g] += 1
        # top-k by document frequency, deterministic tie-break on the n-gram
        ranked = sorted(doc_freq.items(), key=lambda kv: (-kv[1], kv[0]))
        self.vocab = [g for g, _ in ranked[:self.max_features]]
        self._index = {g: j for j, g in enumerate(self.vocab)}
        # smoothed idf so a term in every doc still contributes a little
        self._idf = [math.log((1 + n_docs) / (1 + doc_freq[g])) + 1.0 for g in self.vocab]
        return self

    def transform(self, texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for t in texts:
            counts = Counter(g for g in _ngrams(t, self.n) if g in self._index)
            total = sum(counts.values()) or 1
            vec = [0.0] * len(self.vocab)
            for g, c in counts.items():
                j = self._index[g]
                vec[j] = (c / total) * self._idf[j]           # tf * idf
            norm = math.sqrt(sum(v * v for v in vec))
            if norm > 0:
                vec = [v / norm for v in vec]                 # L2 normalize
            out.append(vec)
        return out

    def fit_transform(self, texts: Sequence[str]) -> list[list[float]]:
        return self.fit(texts).transform(texts)

    def feature_names(self) -> list[str]:
        return [f"ng[{g}]" for g in self.vocab]
