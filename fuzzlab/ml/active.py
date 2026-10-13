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

from fuzzlab.ml.dataset import build_dataset, target_of
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
        from fuzzlab.ml.train import _apply_seal
        from fuzzlab.ml.train import _refuse_quarantine
        ds = build_dataset(store, run_id)                         # fit on labelled rows
        _refuse_quarantine(ds)                                    # BUG-0107
        ds = _apply_seal(store, run_id, ds, False)[0]       # never on sealed rows
        if not len(ds):
            return []
        every = build_dataset(store, run_id, include_unlabelled=True)   # query any row
        com = Committee(n_members=n_members, seed=seed).fit(
            ds.X, _candidate_texts(store, run_id, ds.ids), ds.y)
        every_texts = _candidate_texts(store, run_id, every.ids)
        return query_by_committee(com.member_scores(every.X, every_texts), budget,
                                  ids=every.ids)

    raise ValueError(f"unknown active-learning method: {method!r}")


# --- budgeted confirmation (CC-ML-0013, FR-ML-11) -----------------------------

BUDGET_METHODS = ("score", "uncertainty", "committee", "random")


@dataclass
class Prioritized:
    """The order in which to spend an oracle budget on a run's candidates."""
    order: list[int]                 # candidate ids, most-wanted first
    method: str
    training_rows: int = 0           # earlier labelled candidates the model learned from
    training_positives: int = 0
    # Identity of the model that produced `order` (CC-ML-0015). It is retrained per call
    # (seeded, on earlier runs only) and not saved as a `model` row; this sha pins it.
    model_sha256: str | None = None
    seed: int = 0
    # The candidate feature version the order model read (BUG-0069; None for `random`,
    # which reads no features) — recorded by the pipeline as
    # `pipeline_budget_feature_version` for the report's reproducibility block.
    feature_version: int | None = None


def prioritize(store, run_id: int, candidate_ids: Sequence[int], *, method: str = "score",
               n_members: int = 5, seed: int = 0, min_rows: int = 20,
               min_positives: int = 5, min_groups: int = 2,
               holdout: bool = False) -> Prioritized | None:
    """Order ``candidate_ids`` (this run's confirmable candidates) for a confirmation budget.

    The model learns only from **earlier runs against the same target** (the pipeline's
    ``target.base_url``) — never from this run, whose labels do not exist yet. Methods:

    * ``score`` — most likely vulnerable first (a ranker's score; the default, which
      maximises findings per confirmation);
    * ``uncertainty`` — closest to the 0.5 boundary first (best for improving labels);
    * ``committee`` — most committee disagreement first (likewise);
    * ``random`` — a seeded shuffle; the control a budget method must beat (T7.4).

    Returns ``None`` — meaning "confirm everything" — when the earlier data is too thin
    to train on (fewer than ``min_rows`` rows or ``min_positives`` positives, no
    negatives, or fewer than ``min_groups`` endpoints). ``random`` never needs data.
    Advisory: it only orders work for the oracle, which alone confirms.

    Limitation: candidate text includes the URL path, so a model trained on earlier runs
    of the same app partly remembers which endpoints were vulnerable — useful for
    re-testing, but a "beats random" claim must be measured on held-out endpoints.

    ``holdout=True`` (CC-ML-0020, FR-ML-19) leaves the blind holdout's endpoints out of
    the earlier-run training, so a held-out endpoint never teaches the order. On a
    **sealed** target this is implied, ``--holdout`` or not (BUG-0091); a target whose
    membership is unknown raises `holdout.SealingUnknown` — never ``None``, which would
    mean "confirm everything" past the budget cap (the guarded wrapper then spends the
    cap in row order and the run exits 1).
    """
    if method not in BUDGET_METHODS:
        raise ValueError(f"unknown budget method: {method!r} (choose from {BUDGET_METHODS})")
    wanted = list(dict.fromkeys(int(i) for i in candidate_ids))
    if method == "random":
        order = list(wanted)
        random.Random(seed).shuffle(order)
        return Prioritized(order=order, method=method, seed=seed)

    target = target_of(store, run_id)
    if target is None:
        return None
    from fuzzlab.ml import holdout as ho
    hplan = ho.holdout_plan(store, run_id, holdout)    # raises SealingUnknown
    prior = build_dataset(store, before_run_id=run_id, target=target)
    from fuzzlab.ml.train import _refuse_quarantine
    _refuse_quarantine(prior)              # raises, never None (BUG-0107, like B's nit)
    if hplan is not None:
        prior = ho.sealed_split(store, prior, run_id=run_id, plan=hplan)[0]
    n, pos = len(prior), prior.positives
    if (n < min_rows or pos < min_positives or (n - pos) < 1
            or len(set(prior.groups)) < max(2, min_groups)):
        return None

    from fuzzlab.ml.rank_train import _candidate_texts
    prior_texts = _candidate_texts(store, None, prior.ids)
    now = build_dataset(store, run_id, include_unlabelled=True)
    index = {cid: i for i, cid in enumerate(now.ids)}
    ids = [cid for cid in wanted if cid in index]
    X = [now.X[index[cid]] for cid in ids]
    texts = _candidate_texts(store, run_id, ids)

    from fuzzlab.ml.persist import committee_sha, dumps_model

    def ranker_sha(r: Ranker) -> str:
        return dumps_model("ranker", r, feature_names=r.feature_names,
                           feature_version=prior.feature_version)[1]

    if method == "committee":
        com = Committee(n_members=n_members, seed=seed).fit(prior.X, prior_texts, prior.y)
        key = disagreement(com.member_scores(X, texts))
        model_sha = committee_sha([ranker_sha(m) for m in com.members])
    else:
        ranker = Ranker(seed=seed).fit(prior.X, prior_texts, prior.y)
        scores = ranker.score(X, texts)
        key = scores if method == "score" else [uncertainty(sc) for sc in scores]
        model_sha = ranker_sha(ranker)
    ranked = sorted(range(len(ids)), key=lambda i: key[i], reverse=True)   # stable ties
    order = [ids[i] for i in ranked]
    order += [cid for cid in wanted if cid not in index]   # unknown ids: last, in order
    return Prioritized(order=order, method=method, training_rows=n, training_positives=pos,
                       model_sha256=model_sha, seed=seed, feature_version=prior.feature_version)
