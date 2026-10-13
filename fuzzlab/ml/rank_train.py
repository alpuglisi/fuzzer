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
from fuzzlab.ml.ranking import mean_ndcg_at_k, mean_precision_at_k, ndcg_at_k, precision_at_k
from fuzzlab.ml.train import (SCORE_DEPLOY, SCORE_EARLIER, SCORE_OOF_LABELLED, SCORE_SAVED,
                              _insert_model, _metric, _saved_oof_scope, _seal, _thin,
                              forward_skip_reason, saved_training_rows)
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


#: `train_and_rank(objective=…)` choices (CC-ML-0021, FR-ML-21).
RANK_OBJECTIVES = ("pointwise", "pairwise", "auto")


def _oof_scores(ds, texts, k: int, seed: int, objective: str = "pointwise") -> list[float]:
    oof = [0.0] * len(ds)
    for train, test in oof_folds(ds.groups, k=k, seed=seed):   # raises unless truly OOF
        r = Ranker(seed=seed, objective=objective).fit(
            [ds.X[i] for i in train], [texts[i] for i in train], [ds.y[i] for i in train])
        for idx, s in zip(test, r.score([ds.X[i] for i in test],
                                        [texts[i] for i in test])):
            oof[idx] = s
    return oof


def _fold_global(ds, oof, k: int, seed: int, at_k: int) -> tuple[float, float]:
    """Run-wide ("global") NDCG@k / precision@k computed **within each fold's test set**
    and averaged over the folds with a positive (B4v2-1): out-of-fold scores pooled
    across folds would compare different fold models' scales — for a pairwise score,
    which is no probability, that comparison is meaningless."""
    nd, pr = [], []
    for _, test in oof_folds(ds.groups, k=k, seed=seed):
        y = [ds.y[i] for i in test]
        if not any(y):
            continue
        sc = [oof[i] for i in test]
        nd.append(ndcg_at_k(y, sc, at_k))
        pr.append(precision_at_k(y, sc, at_k))
    return (round(sum(nd) / len(nd), 6) if nd else 0.0,
            round(sum(pr) / len(pr), 6) if pr else 0.0)


def _choose_objective(ds, texts, k: int, seed: int, at_k: int, objective: str):
    """``(objective to deploy, its out-of-fold scores, calibration info)``. ``pointwise``
    adds nothing (bit-identical to before); ``pairwise`` records the run-wide per-fold
    metrics; ``auto`` evaluates both on the same folds and deploys the higher run-wide
    NDCG (ties → pointwise) — optimistic by selection, so recorded
    ``selection_biased`` (the sealed holdout, if on, is the honest number)."""
    if objective not in RANK_OBJECTIVES:
        raise ValueError(f"objective must be one of {RANK_OBJECTIVES}, got {objective!r}")
    if objective == "pointwise":
        return "pointwise", _oof_scores(ds, texts, k, seed), {}
    by = {o: _oof_scores(ds, texts, k, seed, o) for o in
          (("pointwise", "pairwise") if objective == "auto" else ("pairwise",))}
    glob = {o: _fold_global(ds, sc, k, seed, at_k) for o, sc in by.items()}
    chosen = "pairwise"
    if objective == "auto":
        chosen = "pairwise" if glob["pairwise"][0] > glob["pointwise"][0] else "pointwise"
    info = {"objective": objective, "rank_ndcg_global": glob[chosen][0],
            "rank_precision_global": glob[chosen][1]}
    if objective == "auto":
        info.update(objective_selected=chosen, selection_biased=True,
                    oof_ndcg_global_by_objective={o: g[0] for o, g in glob.items()})
    return chosen, by[chosen], info


def _objective_record(calibration: dict, result: dict, info: dict, ranker) -> None:
    """Record the objective (only when not plain pointwise) and what the deploy fit
    actually used (a pairwise fit with no pair falls back to pointwise)."""
    if not info:
        return
    calibration.update(info)
    calibration["objective_used"] = ranker.objective_used
    result.update(objective=info["objective"], objective_used=ranker.objective_used,
                  ndcg_global=info["rank_ndcg_global"],
                  precision_global=info["rank_precision_global"])


def evaluate_vs_random(y, scores, groups, at_k: int, seed: int):
    """``(ndcg, precision, ndcg_random, precision_random)`` of ``scores`` at ``at_k``,
    against a seeded random order over the same rows (the ranker's control). The one
    definition of a ranker metric and its baseline: the trainer and the ML tab both call
    it, so the two numbers are always computed over the same rows and groups (BUG-0073,
    PA-0074). Scores are rounded to the 6 dp `_write_ranks` stores, so ties — averaged
    by the metrics — are the ones the panel sees on the stored values (PA-0069(3))."""
    scores = [round(s, 6) for s in scores]
    rng = random.Random(seed)
    rand = [rng.random() for _ in range(len(y))]
    return (mean_ndcg_at_k(y, scores, groups, at_k),
            mean_precision_at_k(y, scores, groups, at_k),
            mean_ndcg_at_k(y, rand, groups, at_k),
            mean_precision_at_k(y, rand, groups, at_k))


def _holdout_ranking(store, run_id: int, held, scores_by_id: dict, at_k: int,
                     seed: int) -> tuple:
    """Sealed NDCG / precision@k of the deploy rank scores on this run's held-out
    labelled rows against the seeded random control, or ``(None, reason)`` — gated like
    the forward metrics (CC-ML-0020, FR-ML-19)."""
    if not len(held):
        return None, "no held-out labelled rows"
    reason = forward_skip_reason(store, run_id, held.y)
    if reason is not None:
        return None, reason
    ndcg, prec, ndcg_rand, prec_rand = evaluate_vs_random(
        held.y, [round(scores_by_id[c], 6) for c in held.ids], held.groups, at_k, seed)
    return {"rank_ndcg_holdout": ndcg, "rank_precision_holdout": prec,
            "rank_ndcg_random_holdout": ndcg_rand,
            "rank_precision_random_holdout": prec_rand,
            "holdout_rows": len(held), "holdout_positives": held.positives}, None


def _holdout_record(calibration: dict, result: dict, held, sealed, reason) -> None:
    from fuzzlab.ml.holdout import record
    if held is not None:
        calibration["holdout"] = {**record(), "rows": len(held)}
    result["holdout"] = {"sealed": sealed is not None}
    if held is not None:
        result["holdout"]["rows"] = len(held)
    if reason is not None:
        calibration["holdout_skipped_reason"] = reason
        result["holdout"]["skipped_reason"] = reason


def train_and_rank(store, run_id: int | None = None, *, min_rows: int = 20,
                   min_positives: int = 5, k: int = 5, at_k: int = 10,
                   seed: int = 0, min_groups: int = 2, train_on: str = "run",
                   model_id: int | None = None, holdout: bool = False,
                   objective: str = "pointwise") -> dict:
    """Train the ranker, write advisory rank scores, and report NDCG@k/Precision@k vs a
    random-order baseline. Falls back to a constant order on thin data — including fewer
    than ``max(2, min_groups)`` distinct endpoints or ``k < 2``, where no out-of-fold split
    exists and any "OOF" metric would be in-sample (BUG-0062).

    ``train_on="earlier"`` (CC-ML-0016) instead trains on earlier runs against the same
    target and ranks this run without reading its labels — see `_rank_from_earlier`;
    ``train_on="saved"`` (CC-ML-0018) ranks it with a saved earlier ranker, no training
    — see `_rank_from_saved`. In run mode a labelled row's out-of-fold rank score is
    also stored (``rank_score_oof``).

    ``holdout=True`` (CC-ML-0020, FR-ML-19) keeps held-out endpoints out of training
    and out-of-fold evaluation, ranks them with the deploy ranker and seals their
    metrics, as `train.train_and_score` does.

    ``objective`` (CC-ML-0021, FR-ML-21): ``pointwise`` (default, unchanged),
    ``pairwise`` (pair-difference learning-to-rank; its scores are not probabilities,
    so ``rank_uncertainty`` is left NULL), or ``auto`` (the better run-wide out-of-fold
    NDCG). The budget prioritizer always stays pointwise."""
    if objective not in RANK_OBJECTIVES:
        raise ValueError(f"objective must be one of {RANK_OBJECTIVES}, got {objective!r}")
    if train_on == "saved":
        if objective != "pointwise":
            raise ValueError("objective does not apply to a saved ranker (it keeps its own)")
        return _rank_from_saved(store, run_id, model_id=model_id, at_k=at_k, seed=seed,
                                holdout=holdout)
    if model_id is not None:
        raise ValueError("model_id needs train_on='saved'")
    if train_on == "earlier":
        return _rank_from_earlier(store, run_id, min_rows=min_rows,
                                  min_positives=min_positives, k=k, at_k=at_k, seed=seed,
                                  min_groups=min_groups, holdout=holdout,
                                  objective=objective)
    if train_on != "run":
        raise ValueError(f"train_on must be 'run', 'earlier' or 'saved', got {train_on!r}")
    if holdout and run_id is None:
        raise ValueError("holdout needs a run: membership is per target")
    ds = build_dataset(store, run_id)                         # train/evaluate: labelled
    held = None
    if holdout:
        from fuzzlab.ml import holdout as ho
        ds, held = ho.split(store, ds)           # held-out rows never train (FR-ML-19)
    texts = _candidate_texts(store, run_id, ds.ids)
    every = build_dataset(store, run_id, include_unlabelled=True)   # rank: every row
    every_texts = _candidate_texts(store, run_id, every.ids)
    n, pos = len(ds), ds.positives
    groups = len(set(ds.groups))
    result: dict = {"rows": n, "positives": pos, "groups": groups, "at_k": at_k}
    calibration: dict = {"at_k": at_k, "run_id": run_id}

    oof_by_id: dict = {}
    sealed, holdout_reason = None, None
    pairwise = False
    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        holdout_reason = "fallback model"
        scores = [0.0] * len(every)              # constant order (no signal)
        calibration["score_source"] = SCORE_DEPLOY
        params, params_sha = dumps_model("constant", 0.0, feature_names=FEATURE_NAMES,
                                         feature_version=FEATURE_VERSION)
        name = RANK_FALLBACK_NAME
        result.update(model=name, fallback=True)
    else:
        chosen, oof, obj_info = _choose_objective(ds, texts, k, seed, at_k, objective)
        ndcg, prec, ndcg_rand, prec_rand = evaluate_vs_random(ds.y, oof, ds.groups, at_k, seed)
        # each labelled row's out-of-fold rank score, stored beside the deploy one
        oof_by_id = dict(zip(ds.ids, oof))
        calibration["score_source"] = SCORE_OOF_LABELLED
        ranker = Ranker(seed=seed, objective=chosen).fit(ds.X, texts, ds.y)   # deploy
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
        _objective_record(calibration, result, obj_info, ranker)
        pairwise = ranker.objective_used == "pairwise"
        if run_id is not None:
            extra = ((("rank_ndcg_global", obj_info["rank_ndcg_global"]),
                      ("rank_precision_global", obj_info["rank_precision_global"]))
                     if obj_info else ())
            for key, val in (("rank_ndcg", ndcg), ("rank_precision", prec),
                             ("rank_ndcg_random", ndcg_rand),
                             ("rank_precision_random", prec_rand)) + extra:
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, key, float(val)))
        if held is not None:
            sealed, holdout_reason = _holdout_ranking(
                store, run_id, held, dict(zip(every.ids, scores)), at_k, seed)

    _write_ranks(store, every.ids, scores, oof_by_id,
                 probabilistic=not pairwise)
    if run_id is None:
        # a store-wide row covers exactly the runs it ranked (BUG-0074)
        calibration["scored_run_ids"] = run_ids_of(store, every.ids)
    if held is not None:
        _holdout_record(calibration, result, held, sealed, holdout_reason)

    version, new_id = _insert_model(store, name, ds.feature_version, calibration, params,
                                    params_sha)
    _seal(store, run_id, new_id, sealed)
    store.conn.commit()
    result.update(version=version, ranked=len(scores), params_sha256=params_sha)
    return result


def _write_ranks(store, ids, scores, oof_by_id=None, probabilistic: bool = True) -> None:
    # Advisory rank score + uncertainty (max at the 0.5 boundary). Never labels.
    # Derive uncertainty from the rounded score so the two stored values are consistent.
    # `rank_score_oof` is written (or cleared) in the same pass (PA-0068 rule 3).
    # A pairwise score is no probability, so it gets no uncertainty (NULL, CC-ML-0021).
    oof_by_id = oof_by_id or {}
    for cid, s in zip(ids, scores):
        sr = round(s, 6)
        oof = oof_by_id.get(cid)
        store.conn.execute(
            "UPDATE candidate SET rank_score=?, rank_uncertainty=?, rank_score_oof=? "
            "WHERE id=?",
            (sr, round(1.0 - abs(2.0 * sr - 1.0), 6) if probabilistic else None,
             None if oof is None else round(oof, 6), cid))


def _forward_ranking(store, run_id: int, ids, scores, at_k: int, seed: int):
    """This run's stored rank scores against its OWN oracle labels, after the fact,
    for a ranker that never read them (earlier / saved): result and calibration
    updates, or the skip reason (budget-selected or one-class labels)."""
    now = build_dataset(store, run_id)
    by_id = dict(zip(ids, scores))
    reason = forward_skip_reason(store, run_id, now.y)
    if reason is not None:
        return {"forward_skipped_reason": reason}, {"forward_skipped_reason": reason}
    f_ndcg, f_prec, f_ndcg_rand, f_prec_rand = evaluate_vs_random(
        now.y, [by_id[c] for c in now.ids], now.groups, at_k, seed)
    fwd = {"ndcg": f_ndcg, "precision": f_prec, "ndcg_random": f_ndcg_rand,
           "precision_random": f_prec_rand}
    for key, val in fwd.items():
        _metric(store, run_id, f"rank_{key}_forward", val)
    return ({"ndcg_forward": f_ndcg, "precision_forward": f_prec,
             "baseline_ndcg_forward": f_ndcg_rand, "baseline_precision_forward": f_prec_rand},
            {f"forward_{k}": v for k, v in fwd.items()})


#: Calibration keys a saved-mode ranker copy carries over from its original.
_SAVED_CARRY = ("at_k", "seed", "feature_version", "oof_ndcg", "oof_precision",
                "oof_ndcg_random", "oof_precision_random", "holdout", "objective",
                "objective_used", "objective_selected", "selection_biased",
                "rank_ndcg_global", "rank_precision_global")


def _rank_from_saved(store, run_id, *, model_id=None, at_k: int = 10,
                     seed: int = 0, holdout: bool = False) -> dict:
    """Rank EVERY candidate of this run with a saved earlier ranker — no retraining
    (CC-ML-0018, FR-ML-15). The ranker counterpart of `train._score_from_saved`."""
    from fuzzlab.ml.dataset import target_runs
    from fuzzlab.ml.model_registry import saved_source
    from fuzzlab.ml.persist import ModelIncompatibleError, ModelParamsError
    if run_id is None:
        raise ValueError("train_on='saved' needs the run to rank")
    base: dict = {"train_on": "saved", "at_k": at_k}
    target = target_of(store, run_id)
    if target is None:
        return {**base, "refused": True, "reason": "no target recorded for this run"}
    earlier = [r for r in target_runs(store, target) if r < run_id]
    row, source, reason = saved_source(store, (RANKER_NAME,), run_id, earlier,
                                       model_id=model_id)
    if row is None:
        return {**base, "refused": True, "reason": reason}
    try:
        loaded = loads_model(*params_for(store, row["id"]))
        loaded.check_compatible()
    except (ModelParamsError, ModelIncompatibleError) as exc:
        return {**base, "refused": True,
                "reason": f"saved model #{row['id']} cannot be applied: {exc}"}
    at_k = source.get("at_k", at_k)
    every = build_dataset(store, run_id, include_unlabelled=True)
    texts = _candidate_texts(store, run_id, every.ids)
    scores = loaded.score(every.X, texts) if len(every) else []
    _write_ranks(store, every.ids, scores,             # and clears rank_score_oof
                 probabilistic=getattr(loaded.model, "objective_used", "pointwise")
                 != "pairwise")
    train_runs = source.get("train_run_ids") or [source["run_id"]]
    seen = seen_fraction(store, saved_training_rows(store, source), every.ids)
    result = {**base, "at_k": at_k, "refused": False, "model": RANKER_NAME,
              "fallback": False, "rows": len(every), "source_model_id": row["id"],
              "source_run_id": source["run_id"], "train_run_ids": train_runs,
              "seen_fraction": seen, "params_sha256": loaded.sha256}
    _metric(store, run_id, "rank_seen_fraction", seen)
    fwd_result, fwd_calibration = _forward_ranking(store, run_id, every.ids, scores,
                                                   at_k, seed)
    result.update(fwd_result)
    calibration = {k: source[k] for k in _SAVED_CARRY if k in source}
    calibration.update(run_id=run_id, trained_on="saved", source_model_id=row["id"],
                       source_run_id=source["run_id"], train_run_ids=train_runs,
                       seen_fraction=seen, seen_fraction_recomputed=True,
                       score_source=SCORE_SAVED,
                       oof_scope=_saved_oof_scope(source, row["id"]), **fwd_calibration)
    sealed = None
    if holdout:
        from fuzzlab.ml import holdout as ho
        if ho.matches_current(source.get("holdout")):
            held = ho.split(store, build_dataset(store, run_id))[1]
            sealed, reason = _holdout_ranking(store, run_id, held,
                                              dict(zip(every.ids, scores)), at_k, seed)
        else:
            reason = "source model not trained with the current holdout"
        _holdout_record(calibration, result, None, sealed, reason)
    params, params_sha = params_for(store, row["id"])
    version, new_id = _insert_model(store, RANKER_NAME, row["feature_version"],
                                    calibration, params, params_sha)
    _seal(store, run_id, new_id, sealed)
    store.conn.commit()
    result.update(version=version, ranked=len(scores))
    return result


def _rank_from_earlier(store, run_id, *, min_rows, min_positives, k, at_k, seed,
                       min_groups, holdout=False, objective="pointwise") -> dict:
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
    held = None
    if holdout:
        from fuzzlab.ml import holdout as ho
        prior = ho.split(store, prior)[0]        # held-out endpoints never train
        held = ho.split(store, build_dataset(store, run_id))[1]
    n, pos, groups = len(prior), prior.positives, len(set(prior.groups))
    base.update(train_rows=n, train_positives=pos)
    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        return {**base, "refused": True,
                "reason": "no usable earlier labels for this target"}
    # earlier runs' texts: not filtered to this run (A1)
    texts = _candidate_texts(store, None, prior.ids)
    every = build_dataset(store, run_id, include_unlabelled=True)           # to rank
    every_texts = _candidate_texts(store, run_id, every.ids)

    chosen, oof, obj_info = _choose_objective(prior, texts, k, seed, at_k, objective)
    ndcg, prec, ndcg_rand, prec_rand = evaluate_vs_random(prior.y, oof, prior.groups, at_k, seed)
    ranker = Ranker(seed=seed, objective=chosen).fit(prior.X, texts, prior.y)   # deploy
    scores = ranker.score(every.X, every_texts)               # this run: never its labels
    _write_ranks(store, every.ids, scores,
                 probabilistic=ranker.objective_used != "pairwise")

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

    calibration = {"at_k": at_k, "run_id": run_id, "trained_on": "earlier",
                   "train_run_ids": train_runs, "train_rows": n, "train_positives": pos,
                   "seen_fraction": seen, "seed": seed, "k": k, "min_rows": min_rows,
                   "min_positives": min_positives, "min_groups": min_groups,
                   "feature_version": prior.feature_version, "oof_scope": "earlier runs",
                   "score_source": SCORE_EARLIER,
                   "oof_ndcg": ndcg, "oof_precision": prec, "oof_ndcg_random": ndcg_rand,
                   "oof_precision_random": prec_rand}
    fwd_result, fwd_calibration = _forward_ranking(store, run_id, every.ids, scores,
                                                   at_k, seed)
    result.update(fwd_result)
    calibration.update(fwd_calibration)
    _objective_record(calibration, result, obj_info, ranker)
    sealed = None
    if held is not None:
        sealed, reason = _holdout_ranking(store, run_id, held,
                                          dict(zip(every.ids, scores)), at_k, seed)
        _holdout_record(calibration, result, held, sealed, reason)

    params, params_sha = dumps_model("ranker", ranker, feature_names=ranker.feature_names,
                                     feature_version=prior.feature_version)
    version, new_id = _insert_model(store, RANKER_NAME, prior.feature_version, calibration,
                                    params, params_sha)
    _seal(store, run_id, new_id, sealed)
    store.conn.commit()
    result.update(version=version, ranked=len(scores), params_sha256=params_sha)
    return result


def latest_ranker(store, run_id: int | None = None):
    """The newest ranker `model` row whose scope covers ``run_id`` (any run when
    ``None``) as ``(row, calibration)``, or ``None`` — never another family's row."""
    return select_latest(store, RANKER_MODEL_NAMES, run_id, score_column="rank_score")


def load_ranker(store, row) -> LoadedModel | None:
    """Rebuild a ranker row's saved model (``row`` from `latest_ranker`), or ``None``
    if it was trained before models were saved. Raises `persist.ModelParamsError` on
    corrupted params; call `check_compatible()` before using it on new data."""
    saved = params_for(store, row["id"])
    return None if saved is None else loads_model(*saved)
