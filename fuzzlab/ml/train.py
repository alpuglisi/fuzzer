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

from fuzzlab.core.store import MetricLogger
from fuzzlab.ml.baselines import PrevalenceBaseline, SigmaBaseline
from fuzzlab.ml.conformal import ConformalGate
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.gbt import GradientBoostedTrees
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.metrics import oof_folds, pr_auc
from fuzzlab.ml.model_registry import select_latest

_MODELS = {"logistic": LogisticRegression, "gbt": GradientBoostedTrees}

#: The `model.name` written when data is too thin for a model (prevalence baseline).
PREVALENCE_FALLBACK_NAME = "prevalence-fallback"
#: Every `model.name` the detection classifier writes — derived from `_MODELS` so a new
#: classifier kind is picked up by readers automatically (PA-0001/PA-0027).
CLASSIFIER_MODEL_NAMES = tuple(_MODELS) + (PREVALENCE_FALLBACK_NAME,)

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


def train_and_score(store, run_id: int | None = None, *, model_kind: str = "logistic",
                    min_rows: int = 20, min_positives: int = 5, k: int = 5,
                    alpha: float = 0.1, hybrid: bool = False,
                    min_groups: int = 2) -> dict:
    """Train and write advisory scores. ``model_kind``: ``logistic``, ``gbt``, or
    ``auto`` (out-of-fold-select the better of the two). ``hybrid=True`` appends the
    unsupervised ECOD anomaly score as an extra feature (XGBOD-style; label-free, so no
    leakage). Falls back to the prevalence baseline on thin data — including fewer than
    ``max(2, min_groups)`` distinct endpoints or ``k < 2``, where no out-of-fold split
    exists and any "OOF" metric would be in-sample (BUG-0062)."""
    ds = build_dataset(store, run_id)                         # train/evaluate: labelled
    every = build_dataset(store, run_id, include_unlabelled=True)   # score: every row
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

    if (n < min_rows or pos < min_positives or (n - pos) < 1
            or groups < max(2, min_groups) or k < 2):
        # Fallback: not enough labelled data for a model — score with the base rate.
        model = PrevalenceBaseline().fit(ds.X, ds.y)
        scores = model.predict_proba(every.X)
        gate, name = None, PREVALENCE_FALLBACK_NAME
        result.update(model=name, fallback=True)
    else:
        if model_kind == "auto":
            oof_by = {k2: _oof_scores(ds, f, k) for k2, f in _MODELS.items()}
            praucs = {k2: pr_auc(ds.y, s) for k2, s in oof_by.items()}
            name = max(praucs, key=lambda m: praucs[m])   # deploy the OOF winner
            oof, prauc = oof_by[name], praucs[name]
            result["model_selection"] = {k2: round(v, 6) for k2, v in praucs.items()}
        else:
            name = model_kind if model_kind in _MODELS else "logistic"
            oof = _oof_scores(ds, _MODELS[name], k)
            prauc = pr_auc(ds.y, oof)
        prevalence = pr_auc(ds.y, _oof_scores(ds, PrevalenceBaseline, k))
        sigma = pr_auc(ds.y, _oof_scores(ds, SigmaBaseline, k))
        gate = ConformalGate.calibrate(oof, ds.y, alpha=alpha)
        model = _MODELS[name]()
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
    for cid, s in zip(every.ids, scores):
        store.conn.execute("UPDATE candidate SET score=? WHERE id=?", (round(s, 6), cid))

    if gate is not None:
        calibration.update(t_lo=gate.t_lo, t_hi=gate.t_hi)
    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration) VALUES (?,?,?,?)",
        (name, version, ds.feature_version, json.dumps(calibration)))
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
                           calibration=calibration, gate=gate)
