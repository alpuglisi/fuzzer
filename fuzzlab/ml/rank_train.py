"""Train the candidate ranker on the store, write advisory ranks, persist (Phase 7 T7.2).

Honest out-of-fold GroupKFold (never ranking a page with a model that saw it), scored by
NDCG@k / Precision@k and compared against a **random-order baseline** — the control a
zero-request ranker must beat. Writes advisory `candidate.rank_score` /
`candidate.rank_uncertainty` (never labels), persists a `model` row and the metrics, and
falls back to a constant order on thin data. Wired as `fuzzlab auto --rank`.

Like the classifier, the `model` row's calibration records the run trained on (`run_id`)
and the out-of-fold evaluation (`oof_*`, at `at_k`); read it back only through
`latest_ranker` / `fuzzlab.ml.model_registry` (BUG-0061, PA-0063).
"""

from __future__ import annotations

import json
import random

from fuzzlab.ml.metrics import oof_folds
from fuzzlab.ml.dataset import (FEATURE_NAMES, FEATURE_VERSION, build_dataset, run_ids_of,
                              seen_fraction, target_of)
from fuzzlab.ml.model_registry import params_for, select_latest
from fuzzlab.ml.persist import LoadedModel, dumps_model, loads_model
from fuzzlab.ml.ranker import Ranker
from fuzzlab.ml.ranking import mean_ndcg_at_k, mean_precision_at_k
from fuzzlab.ml.train import _metric, _thin, forward_skip_reason
from fuzzlab.ml.text_features import candidate_text

#: `model.name`s the ranker writes (disjoint from `train.CLASSIFIER_MODEL_NAMES`).
RANKER_NAME = "ranker"
RANK_FALLBACK_NAME = "rank-prevalence-fallback"
RANKER_MODEL_NAMES = (RANKER_NAME, RANK_FALLBACK_NAME)


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
    for train, test in oof_folds(ds.groups, k=k, seed=seed):   # raises unless truly OOF
        r = Ranker(seed=seed).fit([ds.X[i] for i in train], [texts[i] for i in train],
                                  [ds.y[i] for i in train])
        for idx, s in zip(test, r.score([ds.X[i] for i in test],
                                        [texts[i] for i in test])):
            oof[idx] = s
    return oof


def _evaluate(y, scores, groups, at_k: int, seed: int):
    """``(ndcg, precision, ndcg_random, precision_random)`` of ``scores`` at ``at_k``,
    against a seeded random order over the same rows (the ranker's control)."""
    rng = random.Random(seed)
    rand = [rng.random() for _ in range(len(y))]
    return (mean_ndcg_at_k(y, scores, groups, at_k),
            mean_precision_at_k(y, scores, groups, at_k),
            mean_ndcg_at_k(y, rand, groups, at_k),
            mean_precision_at_k(y, rand, groups, at_k))


def _next_version(store, name: str) -> int:
    row = store.conn.execute(
        "SELECT MAX(version) v FROM model WHERE name=?", (name,)).fetchone()
    return int(row["v"]) + 1 if row and row["v"] is not None else 1


def train_and_rank(store, run_id: int | None = None, *, min_rows: int = 20,
                   min_positives: int = 5, k: int = 5, at_k: int = 10,
                   seed: int = 0, min_groups: int = 2, train_on: str = "run") -> dict:
    """Train the ranker, write advisory rank scores, and report NDCG@k/Precision@k vs a
    random-order baseline. Falls back to a constant order on thin data — including fewer
    than ``max(2, min_groups)`` distinct endpoints or ``k < 2``, where no out-of-fold split
    exists and any "OOF" metric would be in-sample (BUG-0062).

    ``train_on="earlier"`` (CC-ML-0016) instead trains on earlier runs against the same
    target and ranks this run without reading its labels — see `_rank_from_earlier`."""
    if train_on == "earlier":
        return _rank_from_earlier(store, run_id, min_rows=min_rows,
                                  min_positives=min_positives, k=k, at_k=at_k, seed=seed,
                                  min_groups=min_groups)
    if train_on != "run":
        raise ValueError(f"train_on must be 'run' or 'earlier', got {train_on!r}")
    ds = build_dataset(store, run_id)                         # train/evaluate: labelled
    texts = _candidate_texts(store, run_id, ds.ids)
    every = build_dataset(store, run_id, include_unlabelled=True)   # rank: every row
    every_texts = _candidate_texts(store, run_id, every.ids)
    n, pos = len(ds), ds.positives
    groups = len(set(ds.groups))
    result: dict = {"rows": n, "positives": pos, "groups": groups, "at_k": at_k}
    calibration: dict = {"at_k": at_k, "run_id": run_id}

    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        scores = [0.0] * len(every)              # constant order (no signal)
        params, params_sha = dumps_model("constant", 0.0, feature_names=FEATURE_NAMES,
                                         feature_version=FEATURE_VERSION)
        name = RANK_FALLBACK_NAME
        result.update(model=name, fallback=True)
    else:
        ndcg, prec, ndcg_rand, prec_rand = _evaluate(
            ds.y, _oof_scores(ds, texts, k, seed), ds.groups, at_k, seed)
        ranker = Ranker(seed=seed).fit(ds.X, texts, ds.y)   # deploy: fit on all data
        # advisory rank for EVERY row, including budget-skipped candidates
        scores = ranker.score(every.X, every_texts)
        params, params_sha = dumps_model("ranker", ranker,
                                         feature_names=ranker.feature_names,
                                         feature_version=ds.feature_version)
        name = RANKER_NAME
        result.update(model=name, fallback=False, ndcg=ndcg, precision=prec,
                      baseline_ndcg=ndcg_rand, baseline_precision=prec_rand,
                      beats_baseline=(ndcg > ndcg_rand and prec >= prec_rand))
        calibration.update(oof_ndcg=ndcg, oof_precision=prec, oof_ndcg_random=ndcg_rand,
                           oof_precision_random=prec_rand)
        if run_id is not None:
            for key, val in (("rank_ndcg", ndcg), ("rank_precision", prec),
                             ("rank_ndcg_random", ndcg_rand),
                             ("rank_precision_random", prec_rand)):
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, key, float(val)))

    _write_ranks(store, every.ids, scores)

    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (name, version, ds.feature_version, json.dumps(calibration), params, params_sha))
    store.conn.commit()
    result.update(version=version, ranked=len(scores), params_sha256=params_sha)
    return result


def _write_ranks(store, ids, scores) -> None:
    # Advisory rank score + uncertainty (max at the 0.5 boundary). Never labels.
    # Derive uncertainty from the rounded score so the two stored values are consistent.
    for cid, s in zip(ids, scores):
        sr = round(s, 6)
        store.conn.execute(
            "UPDATE candidate SET rank_score=?, rank_uncertainty=? WHERE id=?",
            (sr, round(1.0 - abs(2.0 * sr - 1.0), 6), cid))


def _rank_from_earlier(store, run_id, *, min_rows, min_positives, k, at_k, seed,
                       min_groups) -> dict:
    """Train the ranker on EARLIER runs against the same target; rank EVERY candidate
    of this run. The ranker counterpart of `train._score_from_earlier` — same refusal,
    same "not trained on this run's labels" (not out-of-sample) caveat."""
    if run_id is None:
        raise ValueError("train_on='earlier' needs the run to rank")
    base: dict = {"train_on": "earlier", "at_k": at_k, "train_rows": 0,
                  "train_positives": 0}
    target = target_of(store, run_id)
    if target is None:
        return {**base, "refused": True, "reason": "no target recorded for this run"}
    prior = build_dataset(store, before_run_id=run_id, target=target)       # labelled
    n, pos, groups = len(prior), prior.positives, len(set(prior.groups))
    base.update(train_rows=n, train_positives=pos)
    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        return {**base, "refused": True,
                "reason": "no usable earlier labels for this target"}
    # earlier runs' texts: not filtered to this run (A1)
    texts = _candidate_texts(store, None, prior.ids)
    every = build_dataset(store, run_id, include_unlabelled=True)           # to rank
    every_texts = _candidate_texts(store, run_id, every.ids)

    ndcg, prec, ndcg_rand, prec_rand = _evaluate(
        prior.y, _oof_scores(prior, texts, k, seed), prior.groups, at_k, seed)
    ranker = Ranker(seed=seed).fit(prior.X, texts, prior.y)   # deploy: earlier labels
    scores = ranker.score(every.X, every_texts)               # this run: never its labels
    _write_ranks(store, every.ids, scores)

    seen = seen_fraction(store, prior.ids, every.ids)
    train_runs = run_ids_of(store, prior.ids)
    result = {**base, "refused": False, "model": RANKER_NAME, "fallback": False,
              "rows": len(every), "train_run_ids": train_runs, "seen_fraction": seen,
              "ndcg_earlier": ndcg, "precision_earlier": prec,
              "baseline_ndcg_earlier": ndcg_rand, "baseline_precision_earlier": prec_rand}
    for key, val in (("rank_ndcg_earlier", ndcg), ("rank_precision_earlier", prec),
                     ("rank_ndcg_random_earlier", ndcg_rand),
                     ("rank_precision_random_earlier", prec_rand),
                     ("rank_seen_fraction", seen)):
        _metric(store, run_id, key, val)

    # Forward evaluation against this run's own oracle labels (never fed back).
    now = build_dataset(store, run_id)
    by_id = dict(zip(every.ids, scores))
    reason = forward_skip_reason(store, run_id, now.y)
    calibration = {"at_k": at_k, "run_id": run_id, "trained_on": "earlier",
                   "train_run_ids": train_runs, "train_rows": n, "train_positives": pos,
                   "seen_fraction": seen, "seed": seed, "k": k, "min_rows": min_rows,
                   "min_positives": min_positives, "min_groups": min_groups,
                   "feature_version": prior.feature_version, "oof_scope": "earlier runs",
                   "oof_ndcg": ndcg, "oof_precision": prec, "oof_ndcg_random": ndcg_rand,
                   "oof_precision_random": prec_rand}
    if reason is None:
        f_ndcg, f_prec, f_ndcg_rand, f_prec_rand = _evaluate(
            now.y, [by_id[c] for c in now.ids], now.groups, at_k, seed)
        fwd = {"ndcg": f_ndcg, "precision": f_prec, "ndcg_random": f_ndcg_rand,
               "precision_random": f_prec_rand}
        for key, val in fwd.items():
            _metric(store, run_id, f"rank_{key}_forward", val)
            calibration[f"forward_{key}"] = val
        result.update(ndcg_forward=f_ndcg, precision_forward=f_prec,
                      baseline_ndcg_forward=f_ndcg_rand,
                      baseline_precision_forward=f_prec_rand)
    else:
        result["forward_skipped_reason"] = calibration["forward_skipped_reason"] = reason

    params, params_sha = dumps_model("ranker", ranker, feature_names=ranker.feature_names,
                                     feature_version=prior.feature_version)
    version = _next_version(store, RANKER_NAME)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (RANKER_NAME, version, prior.feature_version, json.dumps(calibration), params,
         params_sha))
    store.conn.commit()
    result.update(version=version, ranked=len(scores), params_sha256=params_sha)
    return result


def latest_ranker(store, run_id: int | None = None):
    """The newest ranker `model` row whose scope covers ``run_id`` (any run when
    ``None``) as ``(row, calibration)``, or ``None`` — never another family's row."""
    return select_latest(store, RANKER_MODEL_NAMES, run_id)


def load_ranker(store, row) -> LoadedModel | None:
    """Rebuild a ranker row's saved model (``row`` from `latest_ranker`), or ``None``
    if it was trained before models were saved. Raises `persist.ModelParamsError` on
    corrupted params; call `check_compatible()` before using it on new data."""
    saved = params_for(store, row["id"])
    return None if saved is None else loads_model(*saved)
