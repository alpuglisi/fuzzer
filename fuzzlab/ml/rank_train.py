"""Train the candidate ranker on the store, write advisory ranks, persist (Phase 7 T7.2).

Honest out-of-fold GroupKFold (never ranking a page with a model that saw it), scored by
NDCG@k / Precision@k and compared against a **random-order baseline** — the control a
zero-request ranker must beat. Writes advisory `candidate.rank_score` /
`candidate.rank_uncertainty` (never labels), persists a `model` row and the metrics, and
falls back to a constant order on thin data. Wired as `fuzzlab auto --rank`.
"""

from __future__ import annotations

import json
import random

from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.metrics import group_kfold
from fuzzlab.ml.ranker import Ranker
from fuzzlab.ml.ranking import mean_ndcg_at_k, mean_precision_at_k
from fuzzlab.ml.text_features import candidate_text


def _candidate_texts(store, run_id, ids: list[int]) -> list[str]:
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()
    text_by_id: dict[int, str] = {}
    for c in store.conn.execute(
            f"SELECT id, evidence FROM candidate {where}", args).fetchall():
        try:
            ev = json.loads(c["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        text_by_id[int(c["id"])] = candidate_text(ev)
    return [text_by_id.get(i, "") for i in ids]


def _oof_scores(ds, texts, k: int, seed: int) -> list[float]:
    oof = [0.0] * len(ds)
    for train, test in group_kfold(ds.groups, k=k, seed=seed):
        r = Ranker(seed=seed).fit([ds.X[i] for i in train], [texts[i] for i in train],
                                  [ds.y[i] for i in train])
        for idx, s in zip(test, r.score([ds.X[i] for i in test],
                                        [texts[i] for i in test])):
            oof[idx] = s
    return oof


def _next_version(store, name: str) -> int:
    row = store.conn.execute(
        "SELECT MAX(version) v FROM model WHERE name=?", (name,)).fetchone()
    return int(row["v"]) + 1 if row and row["v"] is not None else 1


def train_and_rank(store, run_id: int | None = None, *, min_rows: int = 20,
                   min_positives: int = 5, k: int = 5, at_k: int = 10,
                   seed: int = 0) -> dict:
    """Train the ranker, write advisory rank scores, and report NDCG@k/Precision@k vs a
    random-order baseline. Falls back to a constant order on thin data."""
    ds = build_dataset(store, run_id)
    texts = _candidate_texts(store, run_id, ds.ids)
    n, pos = len(ds), ds.positives
    result: dict = {"rows": n, "positives": pos, "at_k": at_k}

    if n < min_rows or pos < min_positives or (n - pos) < 1:
        scores = [0.0] * n                       # constant order (no signal)
        name = "rank-prevalence-fallback"
        result.update(model=name, fallback=True)
    else:
        oof = _oof_scores(ds, texts, k, seed)
        rng = random.Random(seed)
        rand = [rng.random() for _ in range(n)]
        ndcg = mean_ndcg_at_k(ds.y, oof, ds.groups, at_k)
        prec = mean_precision_at_k(ds.y, oof, ds.groups, at_k)
        ndcg_rand = mean_ndcg_at_k(ds.y, rand, ds.groups, at_k)
        prec_rand = mean_precision_at_k(ds.y, rand, ds.groups, at_k)
        ranker = Ranker(seed=seed).fit(ds.X, texts, ds.y)   # deploy: fit on all data
        scores = ranker.score(ds.X, texts)
        name = "ranker"
        result.update(model=name, fallback=False, ndcg=ndcg, precision=prec,
                      baseline_ndcg=ndcg_rand, baseline_precision=prec_rand,
                      beats_baseline=(ndcg > ndcg_rand and prec >= prec_rand))
        if run_id is not None:
            for key, val in (("rank_ndcg", ndcg), ("rank_precision", prec),
                             ("rank_ndcg_random", ndcg_rand),
                             ("rank_precision_random", prec_rand)):
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, key, float(val)))

    # Advisory rank score + uncertainty (max at the 0.5 boundary). Never labels.
    # Derive uncertainty from the rounded score so the two stored values are consistent.
    for cid, s in zip(ds.ids, scores):
        sr = round(s, 6)
        store.conn.execute(
            "UPDATE candidate SET rank_score=?, rank_uncertainty=? WHERE id=?",
            (sr, round(1.0 - abs(2.0 * sr - 1.0), 6), cid))

    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration) VALUES (?,?,?,?)",
        (name, version, ds.feature_version, json.dumps({"at_k": at_k})))
    store.conn.commit()
    result.update(version=version, ranked=len(scores))
    return result
