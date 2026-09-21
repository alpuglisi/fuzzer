"""Active learning: allocate the oracle's budget by informativeness (Phase 7 T7.3).

Confirmation (an oracle probe) is the scarce resource. Two dependency-light strategies
pick the candidates whose labels would teach the model the most:

* **Uncertainty sampling** — prefer candidates the model is least sure about (score
  nearest the 0.5 decision boundary). Uses the advisory `rank_uncertainty` the ranker
  already wrote (T7.2), so it needs no retraining.
* **Query-by-committee** — train a bootstrap committee and prefer candidates the members
  most *disagree* on (highest score variance).

Both are **advisory**: they propose which candidates to hand the oracle; the oracle
alone confirms. Pure Python.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Sequence

from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.ranker import Ranker


def uncertainty(score: float) -> float:
    """Boundary uncertainty: 1.0 at score 0.5, 0.0 at 0 or 1."""
    return 1.0 - abs(2.0 * score - 1.0)


def uncertainty_sampling(scores: Sequence[float], budget: int,
                         ids: Sequence[int] | None = None) -> list[int]:
    """Top-``budget`` items by boundary uncertainty (ties → original order)."""
    order = sorted(range(len(scores)), key=lambda i: uncertainty(scores[i]), reverse=True)
    chosen = order[:max(0, budget)]
    return [ids[i] for i in chosen] if ids is not None else chosen


def disagreement(member_scores: Sequence[Sequence[float]]) -> list[float]:
    """Per-item score variance across committee members."""
    if not member_scores:
        return []
    n_items = len(member_scores[0])
    out = []
    for i in range(n_items):
        vals = [m[i] for m in member_scores]
        mean = sum(vals) / len(vals)
        out.append(sum((v - mean) ** 2 for v in vals) / len(vals))
    return out


def query_by_committee(member_scores: Sequence[Sequence[float]], budget: int,
                       ids: Sequence[int] | None = None) -> list[int]:
    """Top-``budget`` items by committee disagreement (ties → original order)."""
    dis = disagreement(member_scores)
    order = sorted(range(len(dis)), key=lambda i: dis[i], reverse=True)
    chosen = order[:max(0, budget)]
    return [ids[i] for i in chosen] if ids is not None else chosen


@dataclass
class Committee:
    """A bootstrap committee of rankers, for query-by-committee disagreement."""

    n_members: int = 5
    seed: int = 0
    members: list = field(default_factory=list)

    def fit(self, structural, texts, y) -> "Committee":
        rng = random.Random(self.seed)
        n = len(y)
        self.members = []
        for m in range(self.n_members):
            idx = [rng.randrange(n) for _ in range(n)]        # bootstrap resample
            r = Ranker(seed=self.seed + m).fit(
                [structural[i] for i in idx], [texts[i] for i in idx],
                [y[i] for i in idx])
            self.members.append(r)
        return self

    def member_scores(self, structural, texts) -> list[list[float]]:
        return [m.score(structural, texts) for m in self.members]


def propose_queries(store, run_id: int | None, budget: int,
                    method: str = "uncertainty", *, n_members: int = 5,
                    seed: int = 0) -> list[int]:
    """Propose up to ``budget`` candidate ids for the oracle to confirm next.

    ``uncertainty`` reads the advisory `rank_uncertainty` (run the ranker first);
    ``committee`` trains a bootstrap committee over the store's candidate dataset. Both
    are advisory — they never confirm anything.
    """
    if method == "uncertainty":
        where = "run_id=? AND " if run_id is not None else ""
        args: tuple = (run_id, budget) if run_id is not None else (budget,)
        rows = store.conn.execute(
            f"SELECT id FROM candidate WHERE {where}rank_uncertainty IS NOT NULL "
            "ORDER BY rank_uncertainty DESC, id LIMIT ?", args).fetchall()
        return [r["id"] for r in rows]

    if method == "committee":
        from fuzzlab.ml.rank_train import _candidate_texts
        ds = build_dataset(store, run_id)
        if not len(ds):
            return []
        texts = _candidate_texts(store, run_id, ds.ids)
        com = Committee(n_members=n_members, seed=seed).fit(ds.X, texts, ds.y)
        return query_by_committee(com.member_scores(ds.X, texts), budget, ids=ds.ids)

    raise ValueError(f"unknown active-learning method: {method!r}")
