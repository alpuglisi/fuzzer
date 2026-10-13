"""Train the detection classifier on the store, write advisory scores, persist (T5.3).

Honest evaluation with out-of-fold GroupKFold (never scoring a point with a model that
saw its endpoint), compared to both dumb baselines. When the data is too thin the
classifier falls back to the prevalence baseline. Writes advisory `candidate.score`
(never labels), persists a `model` row with the conformal calibration, and records the
evaluation in `run_metrics`.

The `model` row's calibration also records the run it was trained on (`run_id`, null for a
store-wide train) and its out-of-fold evaluation (`oof_*`), so a reader can pick the
classifier that actually scored a run and show the honest numbers of *that* model —
always through `latest_classifier` / `fuzzlab.ml.model_registry` (BUG-0061, PA-0063).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from fuzzlab.core.oracle_status import SKIPPED_BUDGET, UNLABELLED
from fuzzlab.core.store import MetricLogger
from fuzzlab.ml.baselines import PrevalenceBaseline, SigmaBaseline
from fuzzlab.ml.conformal import ConformalGate
from fuzzlab.ml.dataset import build_dataset, run_ids_of, seen_fraction, target_of
from fuzzlab.ml.gbt import GradientBoostedTrees
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.metrics import oof_folds, pr_auc
from fuzzlab.ml.model_registry import params_for, params_sha256_for, select_latest
from fuzzlab.ml.persist import LoadedModel, dumps_model, loads_model

_MODELS = {"logistic": LogisticRegression, "gbt": GradientBoostedTrees}

#: The `model.name` written when data is too thin for a model (prevalence baseline).
PREVALENCE_FALLBACK_NAME = "prevalence-fallback"
#: Every `model.name` the detection classifier writes — derived from `_MODELS` so a new
#: classifier kind is picked up by readers automatically (PA-0001/PA-0027).
CLASSIFIER_MODEL_NAMES = tuple(_MODELS) + (PREVALENCE_FALLBACK_NAME,)

#: Where a model row's stored scores came from (`calibration["score_source"]`,
#: CC-ML-0018). Absent on rows written before it: in-sample deploy-fit scores.
SCORE_OOF_LABELLED = "oof-labelled"    # `score` deploy fit; labelled rows also `score_oof`
SCORE_DEPLOY = "deploy"                # thin-data fallback: `score` only, no gate
SCORE_EARLIER = "earlier"              # model trained on earlier runs: `score` only
SCORE_SAVED = "saved-model"            # a saved earlier model applied: `score` only


def gate_input(calibration: dict, oracle_status, score, score_oof):
    """The score a model's conformal gate may judge for one candidate, or ``None`` when
    no stored score matches the distribution the gate was calibrated on (BUG-0067,
    PA-0068): the gate thresholds are out-of-fold quantiles, so they are applied to an
    out-of-fold score, or to a score the model never trained on — never to an in-sample
    deploy-fit score.

    - Earlier / saved models never read this run's labels: ``score``.
    - Run-mode models (``score_source`` = oof-labelled): a labelled row's ``score_oof``;
      a row nobody checked (`UNLABELLED`) was never trained on: ``score``.
    - Legacy run-mode rows (no ``score_source``): they trained on every row except a
      budget-skipped one (the only unlabelled status then), so only that gets ``score``.
    """
    if calibration.get("trained_on") in ("earlier", "saved"):
        return score
    source = calibration.get("score_source")
    if source is None:
        return score if oracle_status == SKIPPED_BUDGET else None
    if source == SCORE_OOF_LABELLED:
        if score_oof is not None:
            return score_oof
        return score if oracle_status in UNLABELLED else None
    return score


def _write_scores(store, ids, scores, oof_by_id=None) -> None:
    """Write ``candidate.score`` and — always, in the same pass — ``score_oof`` (the
    labelled rows' out-of-fold score, else NULL), so a re-scored run never keeps another
    model's out-of-fold scores (PA-0068 rule 3)."""
    oof_by_id = oof_by_id or {}
    for cid, s in zip(ids, scores):
        oof = oof_by_id.get(cid)
        store.conn.execute("UPDATE candidate SET score=?, score_oof=? WHERE id=?",
                           (round(s, 6), None if oof is None else round(oof, 6), cid))


# Per-model ``metric_series`` source name (B0's GBT/logistic emitter,
# CC-ML-0009): mirrors the existing subsystem-prefix convention (R-05).
_METRIC_SOURCE = {"logistic": "logreg", "gbt": "gbt"}


def _fit_with_metrics(model, X, y, store, run_id: int | None, name: str):
    """Fit ``model`` on ``(X, y)``, emitting per-round/per-epoch scalars to
    ``metric_series`` via :class:`MetricLogger` when ``run_id`` is given. Additive
    only — with ``run_id is None`` (or an unrecognized model) this is exactly
    ``model.fit(X, y)``."""
    if run_id is None or name not in _METRIC_SOURCE:
        return model.fit(X, y)
    source = _METRIC_SOURCE[name]
    with MetricLogger(store, run_id, source) as logger:
        if name == "gbt":
            return model.fit(X, y, on_round=lambda step, m: [
                logger.log(k, step, v) for k, v in m.items()])
        return model.fit(X, y, on_epoch=lambda step, m: [
            logger.log(k, step, v) for k, v in m.items()])


def _oof_scores(ds, model_factory, k: int) -> list[float]:
    oof = [0.0] * len(ds)
    for train, test in oof_folds(ds.groups, k=k, seed=0):   # raises unless truly OOF
        m = model_factory().fit([ds.X[i] for i in train], [ds.y[i] for i in train])
        for idx, p in zip(test, m.predict_proba([ds.X[i] for i in test])):
            oof[idx] = p
    return oof


def _next_version(store, name: str) -> int:
    row = store.conn.execute(
        "SELECT MAX(version) v FROM model WHERE name=?", (name,)).fetchone()
    return int(row["v"]) + 1 if row and row["v"] is not None else 1


def _thin(n: int, pos: int, groups: int, min_rows: int, min_positives: int,
          min_groups: int, k: int) -> bool:
    """The trainers' thin-data gate (CC-ML-0012): too few rows or positives, no
    negatives, too few endpoints for a held-out split, or k < 2."""
    return (n < min_rows or pos < min_positives or (n - pos) < 1
            or groups < max(2, min_groups) or k < 2)


def _select_and_evaluate(ds, model_kind: str, k: int, alpha: float):
    """Out-of-fold model selection + evaluation + conformal calibration on ``ds``.

    Returns ``(name, pr_auc, prevalence, sigma, gate, selection, oof)``; ``selection`` is
    the per-model OOF PR-AUC for ``auto``, else None; ``oof`` is the selected model's
    out-of-fold score per row of ``ds``."""
    selection = None
    if model_kind == "auto":
        oof_by = {k2: _oof_scores(ds, f, k) for k2, f in _MODELS.items()}
        praucs = {k2: pr_auc(ds.y, s) for k2, s in oof_by.items()}
        name = max(praucs, key=lambda m: praucs[m])   # deploy the OOF winner
        oof, prauc = oof_by[name], praucs[name]
        selection = {k2: round(v, 6) for k2, v in praucs.items()}
    else:
        name = model_kind if model_kind in _MODELS else "logistic"
        oof = _oof_scores(ds, _MODELS[name], k)
        prauc = pr_auc(ds.y, oof)
    prevalence = pr_auc(ds.y, _oof_scores(ds, PrevalenceBaseline, k))
    sigma = pr_auc(ds.y, _oof_scores(ds, SigmaBaseline, k))
    gate = ConformalGate.calibrate(oof, ds.y, alpha=alpha)
    return name, prauc, prevalence, sigma, gate, selection, oof


def _metric(store, run_id: int, key: str, value: float) -> None:
    store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                       (run_id, key, float(value)))


def forward_skip_reason(store, run_id: int, labels) -> str | None:
    """Why a forward evaluation on this run's own labels would not be honest, or None.

    With a confirmation budget the labels are the ones the prioritizer chose (grading the
    model on rows it picked itself); one-class labels make PR-AUC / NDCG meaningless."""
    skipped = store.conn.execute(
        "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND oracle_status=?",
        (run_id, SKIPPED_BUDGET)).fetchone()["c"]
    if skipped:
        return "budget-selected labels"
    if not labels or sum(labels) == 0 or sum(labels) == len(labels):
        return "one-class labels"
    return None


def train_and_score(store, run_id: int | None = None, *, model_kind: str = "logistic",
                    min_rows: int = 20, min_positives: int = 5, k: int = 5,
                    alpha: float = 0.1, hybrid: bool = False,
                    min_groups: int = 2, train_on: str = "run",
                    model_id: int | None = None) -> dict:
    """Train and write advisory scores. ``model_kind``: ``logistic``, ``gbt``, or
    ``auto`` (out-of-fold-select the better of the two). ``hybrid=True`` appends the
    unsupervised ECOD anomaly score as an extra feature (XGBOD-style; label-free, so no
    leakage). Falls back to the prevalence baseline on thin data — including fewer than
    ``max(2, min_groups)`` distinct endpoints or ``k < 2``, where no out-of-fold split
    exists and any "OOF" metric would be in-sample (BUG-0062).

    ``train_on="earlier"`` (CC-ML-0016) instead trains on earlier runs against the same
    target and scores this run without reading its labels — see `_score_from_earlier`;
    ``train_on="saved"`` (CC-ML-0018) scores it with a saved earlier model, no training
    (``model_id`` pins one) — see `_score_from_saved`.

    In run mode a labelled row's out-of-fold score is also stored (``score_oof``), the
    score its conformal gate is calibrated for (BUG-0067)."""
    if train_on == "saved":
        if hybrid:
            raise ValueError("hybrid does not apply to a saved model (it keeps its own)")
        return _score_from_saved(store, run_id, model_id=model_id)
    if model_id is not None:
        raise ValueError("model_id needs train_on='saved'")
    if train_on == "earlier":
        return _score_from_earlier(store, run_id, model_kind=model_kind, min_rows=min_rows,
                                   min_positives=min_positives, k=k, alpha=alpha,
                                   hybrid=hybrid, min_groups=min_groups)
    if train_on != "run":
        raise ValueError(f"train_on must be 'run', 'earlier' or 'saved', got {train_on!r}")
    ds = build_dataset(store, run_id)                         # train/evaluate: labelled
    every = build_dataset(store, run_id, include_unlabelled=True)   # score: every row
    ecod = None                                  # the hybrid's fitted detector, if any
    if hybrid and len(every):
        # ECOD is label-free: fit it ONCE on every row and apply that same detector to
        # both sets, so the scored rows' anomaly feature is the one the model trained on.
        from fuzzlab.ml.anomaly import ECOD, augment
        ecod = ECOD().fit(every.X)
        ds.X, every.X = augment(ds.X, ecod), augment(every.X, ecod)
        ds.feature_names = list(ds.feature_names) + ["anomaly_ecod"]
    n, pos = len(ds), ds.positives
    groups = len(set(ds.groups))
    result: dict = {"rows": n, "positives": pos, "groups": groups, "hybrid": hybrid}
    calibration: dict = {"alpha": alpha, "feature_version": ds.feature_version,
                         "run_id": run_id}

    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        # Fallback: not enough labelled data for a model — score with the base rate.
        model = PrevalenceBaseline().fit(ds.X, ds.y)
        scores = model.predict_proba(every.X)
        gate, name, kind = None, PREVALENCE_FALLBACK_NAME, "prevalence"
        result.update(model=name, fallback=True)
        oof_by_id = {}
        calibration["score_source"] = SCORE_DEPLOY
    else:
        name, prauc, prevalence, sigma, gate, selection, oof = _select_and_evaluate(
            ds, model_kind, k, alpha)
        # each labelled row's out-of-fold score, stored beside the deploy score: the
        # distribution the conformal gate is calibrated on (BUG-0067, CC-ML-0018)
        oof_by_id = dict(zip(ds.ids, oof))
        calibration["score_source"] = SCORE_OOF_LABELLED
        if selection is not None:
            result["model_selection"] = selection
        model, kind = _MODELS[name](), name
        _fit_with_metrics(model, ds.X, ds.y, store, run_id, name)   # deploy: fit on all labels
        # advisory scores for EVERY row, including candidates the oracle skipped for
        # budget (they have no label to train on, but they are the ones to triage)
        scores = model.predict_proba(every.X)
        result.update(model=name, fallback=False, pr_auc=prauc,
                      baseline_prevalence=prevalence, baseline_sigma=sigma,
                      beats_baselines=prauc > prevalence and prauc > sigma)
        calibration.update(oof_pr_auc=prauc, oof_pr_auc_prevalence=prevalence,
                           oof_pr_auc_sigma=sigma)
        if run_id is not None:
            for key, val in (("ml_pr_auc", prauc), ("ml_pr_auc_prevalence", prevalence),
                             ("ml_pr_auc_sigma", sigma)):
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, key, float(val)))

    # Advisory scores onto the candidate rows (never labels).
    _write_scores(store, every.ids, scores, oof_by_id)

    if gate is not None:
        calibration.update(t_lo=gate.t_lo, t_hi=gate.t_hi)
    # Save the deployed model itself (CC-ML-0015): reloadable, sha-pinned.
    params, params_sha = dumps_model(kind, model, feature_names=ds.feature_names,
                                     feature_version=ds.feature_version, ecod=ecod)
    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (name, version, ds.feature_version, json.dumps(calibration), params, params_sha))
    store.conn.commit()
    result.update(version=version, scored=len(scores), params_sha256=params_sha)
    return result


def _score_from_earlier(store, run_id, *, model_kind, min_rows, min_positives, k, alpha,
                        hybrid, min_groups) -> dict:
    """Train on EARLIER runs against the same target; score EVERY candidate of this run.

    This run's labels are never read for training, model selection or calibration, so
    its scores are "not trained on this run's labels" — but not truly out-of-sample:
    endpoints recur across runs of the same target (see ``seen_fraction``). The conformal
    gate is calibrated on earlier out-of-fold scores, so its error bound is nominal, valid
    only under exchangeability, which repeated endpoints and drift break.

    Refuses — writes nothing — when the run has no target row or the earlier data is too
    thin to train on; it never falls back to in-sample training under this mode."""
    if run_id is None:
        raise ValueError("train_on='earlier' needs the run to score")
    base: dict = {"train_on": "earlier", "hybrid": hybrid, "train_rows": 0,
                  "train_positives": 0}
    target = target_of(store, run_id)
    if target is None:
        return {**base, "refused": True, "reason": "no target recorded for this run"}
    prior = build_dataset(store, before_run_id=run_id, target=target)       # labelled
    every = build_dataset(store, run_id, include_unlabelled=True)           # to score
    n, pos, groups = len(prior), prior.positives, len(set(prior.groups))
    base.update(train_rows=n, train_positives=pos)
    if _thin(n, pos, groups, min_rows, min_positives, min_groups, k):
        return {**base, "refused": True,
                "reason": "no usable earlier labels for this target"}
    train_ids = list(prior.ids)
    ecod = None
    if hybrid:
        # label-free: fit ONCE on the earlier rows (labelled or not) and apply that same
        # detector to the training rows and this run's rows
        from fuzzlab.ml.anomaly import ECOD, augment
        ecod = ECOD().fit(build_dataset(store, before_run_id=run_id, target=target,
                                        include_unlabelled=True).X)
        prior.X = augment(prior.X, ecod)
        every.X = augment(every.X, ecod) if len(every) else every.X
        prior.feature_names = list(prior.feature_names) + ["anomaly_ecod"]

    name, prauc, prevalence, sigma, gate, selection, _ = _select_and_evaluate(
        prior, model_kind, k, alpha)
    model = _MODELS[name]().fit(prior.X, prior.y)      # deploy: all earlier labels
    scores = model.predict_proba(every.X)              # this run: never its labels
    _write_scores(store, every.ids, scores)            # and clears score_oof

    seen = seen_fraction(store, train_ids, every.ids)
    train_runs = run_ids_of(store, train_ids)
    result = {**base, "refused": False, "model": name, "fallback": False,
              "rows": len(every), "train_run_ids": train_runs, "seen_fraction": seen,
              "pr_auc_earlier": prauc, "baseline_prevalence_earlier": prevalence,
              "baseline_sigma_earlier": sigma}
    if selection is not None:
        result["model_selection"] = selection
    for key, val in (("ml_pr_auc_earlier", prauc),
                     ("ml_pr_auc_prevalence_earlier", prevalence),
                     ("ml_pr_auc_sigma_earlier", sigma), ("ml_seen_fraction", seen)):
        _metric(store, run_id, key, val)

    fwd_result, fwd_calibration = _forward_evaluation(store, run_id, every.ids, scores)
    result.update(fwd_result)

    calibration = {"alpha": alpha, "feature_version": prior.feature_version,
                   "run_id": run_id, "trained_on": "earlier", "train_run_ids": train_runs,
                   "train_rows": n, "train_positives": pos, "seen_fraction": seen,
                   "seed": 0, "k": k, "min_rows": min_rows, "min_positives": min_positives,
                   "min_groups": min_groups, "model_kind": model_kind,
                   "oof_scope": "earlier runs", "score_source": SCORE_EARLIER,
                   "oof_pr_auc": prauc,
                   "oof_pr_auc_prevalence": prevalence, "oof_pr_auc_sigma": sigma,
                   "t_lo": gate.t_lo, "t_hi": gate.t_hi}
    calibration.update(fwd_calibration)
    params, params_sha = dumps_model(name, model, feature_names=prior.feature_names,
                                     feature_version=prior.feature_version, ecod=ecod)
    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (name, version, prior.feature_version, json.dumps(calibration), params, params_sha))
    store.conn.commit()
    result.update(version=version, scored=len(scores), params_sha256=params_sha)
    return result


def _forward_evaluation(store, run_id: int, ids, scores) -> tuple[dict, dict]:
    """This run's stored scores against this run's OWN oracle labels, after the fact
    (never fed back) — for a model that never read them (earlier / saved). Written only
    when those labels were not budget-selected and have both classes; otherwise the
    reason. Returns the result-dict and calibration updates."""
    now = build_dataset(store, run_id)                 # labelled rows of this run
    by_id = dict(zip(ids, scores))
    reason = forward_skip_reason(store, run_id, now.y)
    if reason is not None:
        return {"forward_skipped_reason": reason}, {"forward_skipped_reason": reason}
    fwd = pr_auc(now.y, [by_id[c] for c in now.ids])
    fwd_prev = pr_auc(now.y, [now.positives / len(now)] * len(now))
    _metric(store, run_id, "ml_pr_auc_forward", fwd)
    _metric(store, run_id, "ml_pr_auc_prevalence_forward", fwd_prev)
    return ({"pr_auc_forward": fwd, "baseline_prevalence_forward": fwd_prev},
            {"forward_pr_auc": fwd, "forward_pr_auc_prevalence": fwd_prev})


#: The classifier kinds a saved model may be reused from (never a fallback).
SAVED_CLASSIFIER_NAMES = tuple(_MODELS)
#: Calibration keys a saved-mode copy carries over from its original (the original's
#: own out-of-fold evaluation and gate; not re-derived from this run).
_SAVED_CARRY = ("alpha", "feature_version", "model_kind", "t_lo", "t_hi", "oof_pr_auc",
                "oof_pr_auc_prevalence", "oof_pr_auc_sigma")


def saved_training_rows(store, calibration: dict) -> list[int]:
    """Candidate ids an original model was trained on, rebuilt with today's dataset
    rules (for `seen_fraction`; recomputed, so marked as such)."""
    runs = calibration.get("train_run_ids") or [calibration.get("run_id")]
    ids: list[int] = []
    for r in runs:
        if isinstance(r, int) and not isinstance(r, bool):
            ids += build_dataset(store, r).ids
    return ids


def _saved_oof_scope(calibration: dict, model_id: int) -> str:
    scope = calibration.get("oof_scope")
    if not scope or scope == "this run":
        scope = f"run #{calibration.get('run_id')}"
    return f"{scope} (saved model #{model_id})"


def _score_from_saved(store, run_id, *, model_id=None) -> dict:
    """Score EVERY candidate of this run with a saved earlier model — no retraining
    (CC-ML-0018, FR-ML-15). The model is the original trained row chosen by
    `model_registry.saved_source` (never one that read this run's labels); a copy row
    scoped to this run is written so the run-scoped readers find it. Refuses — writes
    nothing — when there is no qualifying model or it cannot be applied."""
    from fuzzlab.ml.dataset import target_runs
    from fuzzlab.ml.model_registry import saved_source
    from fuzzlab.ml.persist import ModelIncompatibleError, ModelParamsError
    if run_id is None:
        raise ValueError("train_on='saved' needs the run to score")
    base: dict = {"train_on": "saved"}
    target = target_of(store, run_id)
    if target is None:
        return {**base, "refused": True, "reason": "no target recorded for this run"}
    earlier = [r for r in target_runs(store, target) if r < run_id]
    row, source, reason = saved_source(store, SAVED_CLASSIFIER_NAMES, run_id, earlier,
                                       model_id=model_id)
    if row is None:
        return {**base, "refused": True, "reason": reason}
    try:
        loaded = loads_model(*params_for(store, row["id"]))
        loaded.check_compatible()
    except (ModelParamsError, ModelIncompatibleError) as exc:
        return {**base, "refused": True,
                "reason": f"saved model #{row['id']} cannot be applied: {exc}"}
    every = build_dataset(store, run_id, include_unlabelled=True)
    scores = loaded.predict_proba(every.X) if len(every) else []
    _write_scores(store, every.ids, scores)            # and clears score_oof
    train_runs = source.get("train_run_ids") or [source["run_id"]]
    seen = seen_fraction(store, saved_training_rows(store, source), every.ids)
    result = {**base, "refused": False, "model": row["name"], "fallback": False,
              "rows": len(every), "source_model_id": row["id"],
              "source_run_id": source["run_id"], "train_run_ids": train_runs,
              "seen_fraction": seen, "params_sha256": loaded.sha256}
    _metric(store, run_id, "ml_seen_fraction", seen)
    fwd_result, fwd_calibration = _forward_evaluation(store, run_id, every.ids, scores)
    result.update(fwd_result)
    calibration = {k: source[k] for k in _SAVED_CARRY if k in source}
    calibration.update(run_id=run_id, trained_on="saved", source_model_id=row["id"],
                       source_run_id=source["run_id"], train_run_ids=train_runs,
                       seen_fraction=seen, seen_fraction_recomputed=True,
                       score_source=SCORE_SAVED,
                       oof_scope=_saved_oof_scope(source, row["id"]), **fwd_calibration)
    params, params_sha = params_for(store, row["id"])
    version = _next_version(store, row["name"])
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration, params, "
        "params_sha256) VALUES (?,?,?,?,?,?)",
        (row["name"], version, row["feature_version"], json.dumps(calibration), params,
         params_sha))
    store.conn.commit()
    result.update(version=version, scored=len(scores))
    return result


@dataclass
class ClassifierModel:
    """The deployed detection classifier for a run, as read back from the store."""
    name: str
    version: int
    feature_version: int | None
    calibration: dict
    gate: ConformalGate | None          # None when the row has no conformal thresholds
    id: int | None = None               # the `model` row (to fetch its saved params)
    params_sha256: str | None = None    # None: trained before models were saved


def latest_classifier(store, run_id: int | None = None) -> ClassifierModel | None:
    """The newest classifier `model` row whose scope covers ``run_id`` (any run when
    ``None``), with its parsed calibration and conformal gate — never another model
    family's row (BUG-0061). The selection itself lives in `model_registry`."""
    found = select_latest(store, CLASSIFIER_MODEL_NAMES, run_id)
    if found is None:
        return None
    row, calibration = found
    gate = None
    if "t_lo" in calibration and "t_hi" in calibration:
        gate = ConformalGate(t_lo=calibration["t_lo"], t_hi=calibration["t_hi"])
    return ClassifierModel(name=row["name"], version=row["version"],
                           feature_version=row["feature_version"],
                           calibration=calibration, gate=gate, id=row["id"],
                           params_sha256=params_sha256_for(store, row["id"]))


def load_classifier(store, clf: ClassifierModel) -> LoadedModel | None:
    """Rebuild a classifier's saved model, or ``None`` if it was trained before models
    were saved. Raises `persist.ModelParamsError` if the stored params are corrupted;
    call `check_compatible()` before using it on new data."""
    saved = params_for(store, clf.id) if clf.id is not None else None
    return None if saved is None else loads_model(*saved)
