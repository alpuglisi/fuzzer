"""Train the detection classifier on the store, write advisory scores, persist (T5.3).

Honest evaluation with out-of-fold GroupKFold (never scoring a point with a model that
saw its endpoint), compared to both dumb baselines. When the data is too thin the
classifier falls back to the prevalence baseline. Writes advisory `candidate.score`
(never labels), persists a `model` row with the conformal calibration, and records the
evaluation in `run_metrics`.
"""

from __future__ import annotations

import json

from fuzzlab.ml.baselines import PrevalenceBaseline, SigmaBaseline
from fuzzlab.ml.conformal import ConformalGate
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.gbt import GradientBoostedTrees
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.metrics import group_kfold, pr_auc

_MODELS = {"logistic": LogisticRegression, "gbt": GradientBoostedTrees}


def _oof_scores(ds, model_factory, k: int) -> list[float]:
    oof = [0.0] * len(ds)
    for train, test in group_kfold(ds.groups, k=k, seed=0):
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
                    alpha: float = 0.1, hybrid: bool = False) -> dict:
    """Train and write advisory scores. ``model_kind``: ``logistic``, ``gbt``, or
    ``auto`` (out-of-fold-select the better of the two). ``hybrid=True`` appends the
    unsupervised ECOD anomaly score as an extra feature (XGBOD-style; label-free, so no
    leakage). Falls back to the prevalence baseline on thin data."""
    ds = build_dataset(store, run_id)
    if hybrid and len(ds):
        from fuzzlab.ml.anomaly import ECOD, augment
        ds.X = augment(ds.X, ECOD().fit(ds.X))       # append anomaly score (no labels used)
        ds.feature_names = list(ds.feature_names) + ["anomaly_ecod"]
    n, pos = len(ds), ds.positives
    result: dict = {"rows": n, "positives": pos, "hybrid": hybrid}

    if n < min_rows or pos < min_positives or (n - pos) < 1:
        # Fallback: not enough labelled data for a model — score with the base rate.
        model = PrevalenceBaseline().fit(ds.X, ds.y)
        scores = model.predict_proba(ds.X)
        gate, name = None, "prevalence-fallback"
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
        model = _MODELS[name]().fit(ds.X, ds.y)          # deploy: fit on all data
        scores = model.predict_proba(ds.X)
        result.update(model=name, fallback=False, pr_auc=prauc,
                      baseline_prevalence=prevalence, baseline_sigma=sigma,
                      beats_baselines=prauc > prevalence and prauc > sigma)
        if run_id is not None:
            for key, val in (("ml_pr_auc", prauc), ("ml_pr_auc_prevalence", prevalence),
                             ("ml_pr_auc_sigma", sigma)):
                store.conn.execute(
                    "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                    (run_id, key, float(val)))

    # Advisory scores onto the candidate rows (never labels).
    for cid, s in zip(ds.ids, scores):
        store.conn.execute("UPDATE candidate SET score=? WHERE id=?", (round(s, 6), cid))

    calibration = {"alpha": alpha, "feature_version": ds.feature_version}
    if gate is not None:
        calibration.update(t_lo=gate.t_lo, t_hi=gate.t_hi)
    version = _next_version(store, name)
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration) VALUES (?,?,?,?)",
        (name, version, ds.feature_version, json.dumps(calibration)))
    store.conn.commit()
    result.update(version=version, scored=len(scores))
    return result
