"""Ranking metrics: NDCG@k and Precision@k, per page (Phase 7 T7.1).

The ranker's job is to *order* candidates so real vulnerabilities surface first, at zero
request cost. Ordering quality is measured per endpoint (page): Precision@k (how many of
the top k are real) and NDCG@k (rank-discounted gain, normalized by the ideal order).
Positives are rare and correlated by page, so metrics are computed per group and
averaged over the groups that actually have a positive to rank. Pure Python.

Ties in the score are broken by the items' original order (a stable sort), so a constant
scorer degrades to the input order rather than silently winning.
"""

from __future__ import annotations

import math
from typing import Sequence


def _order(scores: Sequence[float]) -> list[int]:
    """Indices sorted by score descending; ties keep their original order (stable)."""
    return sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)


def _dcg(rels: Sequence[float], k: int) -> float:
    return sum(rel / math.log2(i + 2) for i, rel in enumerate(rels[:k]))


def ndcg_at_k(y_true: Sequence[int], scores: Sequence[float], k: int = 10) -> float:
    """Normalized discounted cumulative gain at k (binary relevance).

    Returns 0.0 when the group has no positives (nothing to rank up).
    """
    order = _order(scores)
    ranked = [y_true[i] for i in order]
    ideal = _dcg(sorted(y_true, reverse=True), k)
    if ideal <= 0:
        return 0.0
    return round(_dcg(ranked, k) / ideal, 6)


def precision_at_k(y_true: Sequence[int], scores: Sequence[float], k: int = 10) -> float:
    """Fraction of the top-k that are positive (denominator = min(k, n))."""
    if not y_true:
        return 0.0
    top = _order(scores)[:k]
    return round(sum(y_true[i] for i in top) / min(k, len(y_true)), 6)


def _by_group(y_true, scores, groups):
    buckets: dict[object, list[int]] = {}
    for i, g in enumerate(groups):
        buckets.setdefault(g, []).append(i)
    return buckets


def _mean_per_group(metric, y_true, scores, groups, k, require_positive) -> float:
    vals = []
    for _, idxs in _by_group(y_true, scores, groups).items():
        yt = [y_true[i] for i in idxs]
        if require_positive and sum(yt) == 0:
            continue                       # no positive on this page → nothing to rank
        sc = [scores[i] for i in idxs]
        vals.append(metric(yt, sc, k))
    return round(sum(vals) / len(vals), 6) if vals else 0.0


def mean_ndcg_at_k(y_true, scores, groups, k: int = 10,
                   require_positive: bool = True) -> float:
    """Average NDCG@k over pages (default: only pages with a positive)."""
    return _mean_per_group(ndcg_at_k, y_true, scores, groups, k, require_positive)


def mean_precision_at_k(y_true, scores, groups, k: int = 10,
                        require_positive: bool = True) -> float:
    """Average Precision@k over pages (default: only pages with a positive)."""
    return _mean_per_group(precision_at_k, y_true, scores, groups, k, require_positive)
