"""Read-only ML tab data (component #12, U4/CC-UI-0031 + CC-ML-0010, R-06).

Surfaces model internals **already in the store** for the advisory ML tab: classifier
PR curve + reliability/ECE, the ranker's nDCG@k / precision@k + score distributions,
the conformal flag/abstain/drop split, the anomaly (ECOD) tripwire, active-learning
committee disagreement, the Thompson-bandit Beta posteriors, and mutation-engine
variants. Every function here **reads** the store; none writes a row (that stays each
subsystem's own training/scoring job). A couple of panels (anomaly, committee
disagreement) recompute a lightweight, deterministic derivation of already-stored
feature vectors on the fly — legitimate "read" work, same as a SQL aggregate, and
never persisted back.

Advisory framing (R-06): every function returns raw numbers only; the *presentation*
layer (`js/ml.js` + `sections/ml.html`) is responsible for categorical bands, verb
hygiene ("scored/ranked/flagged", never "detected/vulnerable/confirmed"), and the
non-dismissible advisory banner. This module never labels anything a finding.
"""

from __future__ import annotations

import math
from typing import Any, Sequence

from functools import lru_cache, wraps
from types import SimpleNamespace

from fuzzlab.plugins.optional import ML_UNAVAILABLE, import_ml


@lru_cache(maxsize=1)
def _ml() -> SimpleNamespace | None:
    """The `fuzzlab.ml` functions this view reads through, or ``None`` when the ML
    package is not installed (FR-ML-6, CC-UI-0041) — never a module-level import, so
    the web app starts without it. Only the ML-backed panels need it."""
    mods = {"dataset": import_ml("fuzzlab.ml.dataset"),
            "metrics": import_ml("fuzzlab.ml.metrics"),
            "rank_train": import_ml("fuzzlab.ml.rank_train"),
            "ranking": import_ml("fuzzlab.ml.ranking"),
            "train": import_ml("fuzzlab.ml.train"),
            "anomaly": import_ml("fuzzlab.ml.anomaly"),
            "active": import_ml("fuzzlab.ml.active"),
            "persist": import_ml("fuzzlab.ml.persist")}
    if any(m is None for m in mods.values()):
        return None
    return SimpleNamespace(**mods)


def _ml_panel(fn):
    """An ML-backed panel: reports `ML_UNAVAILABLE` instead of failing without ML."""
    @wraps(fn)
    def panel(*args, **kwargs):
        if _ml() is None:
            return {"available": False, "reason": ML_UNAVAILABLE}
        return fn(*args, **kwargs)
    return panel

#: LEGACY rows (no `score_source`): stored `candidate.score` / `rank_score` are the deploy
#: fit's scores on its own training rows, so metrics recomputed from them are in-sample —
#: labelled as such, beside the scoring model's own out-of-fold numbers (BUG-0062,
#: CC-UI-0035). Run-mode rows since CC-ML-0018 are recomputed from `score_oof` instead.
IN_SAMPLE = "in-sample (deploy fit)"
#: Scores written by a model trained on earlier runs (`train_on="earlier"`, CC-ML-0016):
#: this run's labels were never read — but its endpoints may recur (see `seen_fraction`),
#: so this is deliberately not called "out-of-sample" (CC-UI-0040).
NOT_TRAINED_ON_RUN = "not trained on this run's labels (trained on earlier runs)"
#: Scores from a saved earlier model applied without training (CC-ML-0018).
NOT_TRAINED_SAVED = "not trained on this run's labels (saved model {id})"
#: Run-mode models since CC-ML-0018: the metrics are recomputed from each labelled row's
#: stored out-of-fold score (`score_oof` / `rank_score_oof`), not the deploy score.
OUT_OF_FOLD = "out-of-fold (labelled rows)"
#: All-runs view pooling runs scored both ways (PA-0064(2)): no single label is true.
MIXED = "mixed"


def _earlier_trained(calibration: dict | None) -> bool:
    """A model that never read this run's labels: trained on earlier runs, or a saved
    earlier model applied as is."""
    return bool(calibration) and calibration.get("trained_on") in ("earlier", "saved")


def _evaluation_kind(calibration: dict | None) -> str:
    if _earlier_trained(calibration):
        return "not-trained"
    if calibration and calibration.get("score_source") == "oof-labelled":
        return "oof"
    return "in-sample"


def _evaluation(store, run_id: int | None, column: str, reader) -> str:
    """How the numbers recomputed for ``run_id`` relate to their model's training data.

    Per run: from that run's scoring model. All runs: from every pooled run's scoring
    model — one label only when they all agree, else `MIXED`."""
    if run_id is not None:
        runs = [run_id]
    else:
        runs = [int(r["run_id"]) for r in store.conn.execute(
            f"SELECT DISTINCT run_id FROM candidate WHERE {column} IS NOT NULL")]
    calibrations = [reader(store, r) for r in runs]
    kinds = {_evaluation_kind(c) for c in calibrations}
    if len(kinds) > 1:
        return MIXED
    kind = kinds.pop() if kinds else "in-sample"
    if kind == "oof":
        return OUT_OF_FOLD
    if kind == "not-trained":
        saved = {c.get("source_model_id") for c in calibrations
                 if c and c.get("trained_on") == "saved"}
        if saved and len(calibrations) == len(saved) == 1:
            return NOT_TRAINED_SAVED.format(id=f"#{saved.pop()}")
        return NOT_TRAINED_ON_RUN if not saved else \
            "not trained on this run's labels (earlier runs / saved models)"
    return IN_SAMPLE


def _clf_calibration(store, run_id):
    clf = _ml().train.latest_classifier(store, run_id)
    return clf.calibration if clf is not None else None


def _rank_calibration(store, run_id):
    found = _ml().rank_train.latest_ranker(store, run_id)
    return found[1] if found is not None else None


def _oof_extras(c: dict, prefix_keys: tuple[str, ...]) -> dict:
    """`scope`, plus — for an earlier-trained model — its forward evaluation on this
    run's own labels (or why there is none) and `seen_fraction`."""
    out: dict = {"scope": c.get("oof_scope", "this run")}
    if _earlier_trained(c):
        forward = {k: c[f"forward_{k}"] for k in prefix_keys if f"forward_{k}" in c}
        out.update(forward=forward or None,
                   forward_skipped_reason=c.get("forward_skipped_reason"),
                   seen_fraction=c.get("seen_fraction"),
                   train_run_ids=c.get("train_run_ids"))
    return out


def _oof_source(calibration: dict, run_id: int | None) -> bool:
    """Whether a model row's stored OOF numbers describe the scores shown for ``run_id``:
    always for a per-run view (the row was selected for that run); in the all-runs view
    only for a store-wide train, the one model that scored every run."""
    return run_id is not None or calibration.get("run_id", 0) is None


def _classifier_oof(store, run_id: int | None) -> dict | None:
    clf = _ml().train.latest_classifier(store, run_id)
    if clf is None or "oof_pr_auc" not in clf.calibration \
            or not _oof_source(clf.calibration, run_id):
        return None                       # no model / fallback / legacy row / mixed runs
    c = clf.calibration
    return {"pr_auc": c["oof_pr_auc"], "pr_auc_prevalence": c.get("oof_pr_auc_prevalence"),
            "pr_auc_sigma": c.get("oof_pr_auc_sigma"),
            **_oof_extras(c, ("pr_auc", "pr_auc_prevalence"))}


def _ranker_oof(store, run_id: int | None) -> dict | None:
    found = _ml().rank_train.latest_ranker(store, run_id)
    if found is None:
        return None
    c = found[1]
    if "oof_ndcg" not in c or not _oof_source(c, run_id):
        return None
    return {"at_k": c.get("at_k"), "ndcg": c["oof_ndcg"],
            "precision": c.get("oof_precision"), "ndcg_random": c.get("oof_ndcg_random"),
            "precision_random": c.get("oof_precision_random"),
            **_oof_extras(c, ("ndcg", "precision", "ndcg_random", "precision_random"))}

# Committee disagreement is O(n_members * n) to fit; cap the dataset so the read route
# stays fast even against a large store (deterministic stride sample, not random).
_COMMITTEE_CAP = 300


def _histogram(values: Sequence[float], bins: int = 12,
               lo: float | None = None, hi: float | None = None) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"edges": [], "counts": []}
    lo = min(vals) if lo is None else lo
    hi = max(vals) if hi is None else hi
    if hi <= lo:
        hi = lo + 1.0
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in vals:
        idx = int((v - lo) / width) if width > 0 else 0
        counts[min(bins - 1, max(0, idx))] += 1
    edges = [round(lo + i * width, 6) for i in range(bins + 1)]
    return {"edges": edges, "counts": counts}


def _stride_sample(points: list, max_points: int) -> list:
    if len(points) <= max_points:
        return points
    stride = len(points) / max_points
    sampled = [points[int(round(k * stride))] for k in range(max_points)]
    sampled[-1] = points[-1]
    return sampled


def _pr_curve(labels: Sequence[int], scores: Sequence[float], max_points: int = 100) -> list[dict]:
    """Step-interpolated PR curve points (recall, precision), downsampled for the chart."""
    total_pos = sum(labels)
    if total_pos == 0:
        return []
    pairs = sorted(zip(scores, labels), key=lambda t: t[0], reverse=True)
    points: list[dict] = []
    tp = fp = 0
    i, n = 0, len(pairs)
    while i < n:
        s = pairs[i][0]
        while i < n and pairs[i][0] == s:
            if pairs[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        points.append({"recall": round(recall, 4), "precision": round(precision, 4)})
    return _stride_sample(points, max_points)


def _reliability(labels: Sequence[int], scores: Sequence[float], bins: int = 10) -> dict:
    """Binned reliability diagram (mean predicted vs observed frequency) + ECE."""
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for s, y in zip(scores, labels):
        idx = min(bins - 1, max(0, int(s * bins)))
        buckets[idx].append((s, y))
    n = len(scores)
    out_bins = []
    ece = 0.0
    for i, b in enumerate(buckets):
        if not b:
            out_bins.append({"bin": i, "mean_pred": None, "observed": None, "count": 0})
            continue
        mean_pred = sum(x[0] for x in b) / len(b)
        observed = sum(x[1] for x in b) / len(b)
        count = len(b)
        ece += (count / n) * abs(mean_pred - observed)
        out_bins.append({"bin": i, "mean_pred": round(mean_pred, 4),
                         "observed": round(observed, 4), "count": count})
    return {"bins": out_bins, "ece": round(ece, 4)}


def _scored_pairs(store, ds, run_id: int | None, column: str = "score",
                  oof_column: str = "score_oof") -> tuple[list[float], list[int]]:
    """Join the dataset's labels back onto the stored scores: a labelled row's
    out-of-fold score where the trainer stored one (CC-ML-0018), else its deploy score —
    so a run-mode model's recomputed metrics are honest out-of-fold numbers."""
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()
    rows = store.conn.execute(
        f"SELECT id, {column} AS s, {oof_column} AS o FROM candidate {where}",
        args).fetchall()
    scored = {r["id"]: (r["o"] if r["o"] is not None else r["s"]) for r in rows
              if r["s"] is not None}
    scores, labels = [], []
    for cid, y in zip(ds.ids, ds.y):
        if cid in scored:
            scores.append(scored[cid])
            labels.append(y)
    return scores, labels


@_ml_panel
def classifier_panel(store, run_id: int | None = None) -> dict[str, Any]:
    """PR curve + operating point, reliability diagram + ECE (the advisory anchor)."""
    ds = _ml().dataset.build_dataset(store, run_id)
    if not len(ds):
        return {"available": False, "reason": "no candidates in the store yet", "n": 0}
    scores, labels = _scored_pairs(store, ds, run_id)
    if not scores:
        return {"available": False, "reason": "no classifier scores yet (run training)",
                "n": len(ds)}
    n = len(scores)
    positives = sum(labels)
    return {
        "available": True, "n": n, "positives": positives,
        "evaluation": _evaluation(store, run_id, "score", _clf_calibration),
        "oof": _classifier_oof(store, run_id),
        "baseline_prevalence": round(positives / n, 4) if n else 0.0,
        "pr_auc": _ml().metrics.pr_auc(labels, scores),
        "pr_curve": _pr_curve(labels, scores),
        "reliability": _reliability(labels, scores),
    }


@_ml_panel
def ranker_panel(store, run_id: int | None = None, k: int = 10,
                 max_scatter: int = 500) -> dict[str, Any]:
    """nDCG@k / precision@k vs a random baseline + rank score/uncertainty distributions."""
    ds = _ml().dataset.build_dataset(store, run_id)
    if not len(ds):
        return {"available": False, "reason": "no candidates in the store yet"}
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()
    rows = store.conn.execute(
        f"SELECT id, rank_score, rank_uncertainty, rank_score_oof FROM candidate {where}",
        args).fetchall()
    # metrics judge a labelled row's out-of-fold rank score where stored (CC-ML-0018)
    rank_map = {r["id"]: (r["rank_score_oof"] if r["rank_score_oof"] is not None
                          else r["rank_score"], r["rank_uncertainty"])
               for r in rows if r["rank_score"] is not None}
    scores, uncertainties, labels, groups = [], [], [], []
    for cid, y, g in zip(ds.ids, ds.y, ds.groups):
        if cid in rank_map:
            s, u = rank_map[cid]
            scores.append(s)
            uncertainties.append(u if u is not None else 0.0)
            labels.append(y)
            groups.append(g)
    if not scores:
        return {"available": False, "reason": "no ranker scores yet (run ranking)", "n": len(ds)}
    prevalence = sum(labels) / len(labels) if labels else 0.0
    scatter = [{"score": round(s, 4), "uncertainty": round(u, 4), "label": y}
              for s, u, y in zip(scores, uncertainties, labels)]
    return {
        "available": True, "n": len(scores), "k": k,
        "evaluation": _evaluation(store, run_id, "rank_score", _rank_calibration),
        "oof": _ranker_oof(store, run_id),
        "ndcg_at_k": _ml().ranking.mean_ndcg_at_k(labels, scores, groups, k=k),
        "precision_at_k": _ml().ranking.mean_precision_at_k(labels, scores, groups, k=k),
        "random_baseline_precision_at_k": round(prevalence, 4),
        "score_hist": _histogram(scores, bins=12),
        "uncertainty_hist": _histogram(uncertainties, bins=12),
        "scatter": _stride_sample(scatter, max_scatter),
    }


def _threshold(t: float) -> float | None:
    """A gate threshold for display: rounded to 4 dp, ``None`` when it lies outside
    [0, 1] — a "never flags / never drops" sentinel (BUG-0070), which the panel's notes
    explain — and never ``-0.0``."""
    if t < 0 or t > 1:
        return None
    return round(t, 4) + 0.0


@_ml_panel
def conformal_panel(store, run_id: int | None = None) -> dict[str, Any]:
    """Flag/abstain/drop split (tab summary) + the nonconformity histogram + thresholds.

    Each candidate is gated by **its own run's** classifier (`latest_classifier`,
    BUG-0061) and judges only the score that gate was calibrated for
    (`train.gate_input`, BUG-0067): a labelled run-mode row's out-of-fold score, or a
    score the model never trained on. A row with no such score (an in-sample legacy
    score, or a run whose classifier has no gate) is counted as ``n/a``, never decided.
    The thresholds shown are the selected model's; the all-runs view says when runs'
    gates differ (``per_run_gates``)."""
    train = _ml().train
    clf = train.latest_classifier(store, run_id)
    if clf is None:
        return {"available": False, "reason": "no trained classifier yet"}
    if clf.gate is None:
        return {"available": False, "reason": "latest classifier has no conformal calibration"}
    calib = clf.calibration
    row = {"name": clf.name, "version": clf.version}
    where = "WHERE score IS NOT NULL" + (" AND run_id=?" if run_id is not None else "")
    args: tuple = (run_id,) if run_id is not None else ()
    rows = store.conn.execute(
        f"SELECT run_id, score, score_oof, oracle_status FROM candidate {where}",
        args).fetchall()
    if not rows:
        return {"available": False, "reason": "no scored candidates yet",
                "model": {"name": row["name"], "version": row["version"]}}
    gates: dict = {}
    counts = {"flag": 0, "abstain": 0, "drop": 0, "n/a": 0}
    judged_scores = []
    for r in rows:
        if r["run_id"] not in gates:
            gates[r["run_id"]] = train.latest_classifier(store, r["run_id"])
        owner = gates[r["run_id"]]
        judged = (None if owner is None or owner.gate is None else
                  train.gate_input(owner.calibration, r["oracle_status"], r["score"],
                                   r["score_oof"]))
        if judged is None:
            counts["n/a"] += 1
            continue
        counts[owner.gate.decide(judged)] += 1
        judged_scores.append(judged)
    distinct = {(g.name, g.version) for g in gates.values() if g is not None}
    notes = train.gate_notes(calib)
    # the pooled all-runs view: say so when ANY run's gate used the earlier rule
    if any(g is not None and g.gate is not None and "gate_rule" not in g.calibration
           for g in gates.values()) and train.OLD_GATE_NOTE not in notes:
        notes.append(train.OLD_GATE_NOTE)
    return {
        "available": True, "n": len(rows), "judged": len(judged_scores),
        "model": {"name": row["name"], "version": row["version"]},
        "t_lo": _threshold(calib["t_lo"]), "t_hi": _threshold(calib["t_hi"]),
        "notes": notes,
        "per_run_gates": len(distinct) > 1,
        "counts": counts,
        "nonconformity_hist": _histogram(judged_scores, bins=20, lo=0.0, hi=1.0),
    }


@_ml_panel
def anomaly_panel(store, run_id: int | None = None, contamination: float = 0.1) -> dict[str, Any]:
    """ECOD outlier score histogram + threshold/flagged-rate. 'unusual != malicious'.

    Fits ECOD over the already-stored candidate feature vectors on the fly (pure read —
    unlike `fuzzlab.ml.anomaly.detect_anomalies`, this never writes to `run_metrics`).
    Label-free, so it covers every candidate — the same population `detect_anomalies`
    scores, budget-skipped ones included.
    """
    ds = _ml().dataset.build_dataset(store, run_id, include_unlabelled=True)
    if len(ds) < 5:
        return {"available": False, "reason": "not enough candidates to fit an anomaly model"}
    anomaly = _ml().anomaly
    ecod = anomaly.ECOD().fit(ds.X)
    scores = ecod.scores(ds.X)
    flags = anomaly.flag_top(scores, contamination)        # whole tie groups (BUG-0070)
    flagged = sum(flags)
    threshold = min((s for s, f in zip(scores, flags) if f), default=None)
    return {
        "available": True, "n": len(scores), "flagged": flagged,
        "flag_budget": anomaly.flag_budget(len(scores), contamination),
        "flagged_rate": round(flagged / len(scores), 4) if scores else 0.0,
        "threshold": None if threshold is None else round(threshold, 4),
        "reason": anomaly.flag_reason(scores, flags, contamination),
        "hist": _histogram(scores, bins=15),
    }


@_ml_panel
def disagreement_panel(store, run_id: int | None = None, n_members: int = 5,
                       top_n: int = 10) -> dict[str, Any]:
    """Committee (bootstrap ranker ensemble) disagreement histogram + top-N query queue.

    The committee is fit on labelled candidates only; the queue covers every candidate,
    including ones the oracle skipped for budget — the ones actually left to query."""
    ds = _ml().dataset.build_dataset(store, run_id, include_unlabelled=True)
    if len(ds) < 10:
        return {"available": False, "reason": "not enough candidates to train a committee"}
    n = len(ds)
    if n > _COMMITTEE_CAP:
        stride = n / _COMMITTEE_CAP
        idxs = [int(round(i * stride)) for i in range(_COMMITTEE_CAP)]
    else:
        idxs = list(range(n))
    ids_sub = [ds.ids[i] for i in idxs]
    X_sub = [ds.X[i] for i in idxs]
    y_sub = [ds.y[i] for i in idxs]
    Committee, disagreement = _ml().active.Committee, _ml().active.disagreement
    _candidate_texts = _ml().rank_train._candidate_texts
    texts = _candidate_texts(store, run_id, ids_sub)
    fit_idx = [j for j, i in enumerate(idxs) if ds.labelled[i]]      # never fit on a
    if len(fit_idx) < 10:                                            # placeholder label
        return {"available": False, "reason": "not enough labelled candidates to train a committee"}
    try:
        com = Committee(n_members=n_members, seed=0).fit(
            [X_sub[j] for j in fit_idx], [texts[j] for j in fit_idx],
            [y_sub[j] for j in fit_idx])
        member_scores = com.member_scores(X_sub, texts)
    except Exception:  # noqa: BLE001 - degrade to an empty panel, never break the tab
        return {"available": False, "reason": "committee fit failed on this dataset"}
    dis = disagreement(member_scores)
    order = sorted(range(len(dis)), key=lambda i: dis[i], reverse=True)[:top_n]
    queue = [{"candidate_id": ids_sub[i], "disagreement": round(dis[i], 4)} for i in order]
    return {
        "available": True, "n": len(dis), "sampled": n > _COMMITTEE_CAP,
        "hist": _histogram(dis, bins=12), "queue": queue,
    }


def _beta_density(a: float, b: float, n: int = 200) -> tuple[list[float], list[float]]:
    """Beta(a, b) pdf over an n-point grid, via lgamma (pure stdlib; no numpy/scipy)."""
    xs = [i / (n - 1) for i in range(n)]
    xs[0], xs[-1] = 1e-6, 1 - 1e-6           # avoid log(0) at the boundary
    log_norm = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    dens = [math.exp((a - 1) * math.log(x) + (b - 1) * math.log(1 - x) - log_norm) for x in xs]
    return xs, dens


def _beta_ci(xs: list[float], dens: list[float], lo_q: float = 0.05,
            hi_q: float = 0.95) -> tuple[float, float]:
    """Trapezoid-integrated CDF off the same grid -> (lo_q, hi_q) quantiles."""
    cum = 0.0
    cdf = [0.0] * len(xs)
    for i in range(1, len(xs)):
        cum += 0.5 * (dens[i] + dens[i - 1]) * (xs[i] - xs[i - 1])
        cdf[i] = cum
    total = cdf[-1] or 1.0
    cdf = [c / total for c in cdf]
    lo = next((x for x, c in zip(xs, cdf) if c >= lo_q), xs[0])
    hi = next((x for x, c in zip(xs, cdf) if c >= hi_q), xs[-1])
    return lo, hi


def bandit_panel(store) -> dict[str, Any]:
    """Overlaid Beta posterior density per arm + a mean/CI/pulls/cost forest table."""
    rows = store.conn.execute(
        "SELECT context, arm, alpha, beta, cost_sum, cost_n FROM bandit_posteriors "
        "ORDER BY context, arm").fetchall()
    if not rows:
        return {"available": False, "reason": "no bandit posteriors recorded yet"}
    arms = []
    for r in rows:
        a, b = float(r["alpha"]), float(r["beta"])
        xs, dens = _beta_density(a, b)
        lo, hi = _beta_ci(xs, dens)
        pulls = max(0, round((a - 1.0) + (b - 1.0)))  # prior is Beta(1,1); pulls = a+b-2
        cost_n = r["cost_n"] or 0
        mean_cost = (r["cost_sum"] / cost_n) if cost_n else None
        arms.append({
            "context": r["context"], "arm": r["arm"],
            "alpha": round(a, 4), "beta": round(b, 4),
            "mean": round(a / (a + b), 4) if (a + b) else 0.0,
            "ci_low": round(lo, 4), "ci_high": round(hi, 4),
            "pulls": pulls, "mean_cost": round(mean_cost, 4) if mean_cost is not None else None,
            "density": {"x": [round(x, 4) for x in xs], "y": [round(d, 6) for d in dens]},
        })
    return {"available": True, "arms": arms}


def _truncate(s: str | None, n: int = 140) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def mutation_panel(store, run_id: int | None = None, limit: int = 100) -> dict[str, Any]:
    """Mutation-engine variants killed/survived table + score (semantics-validator verdict:
    'survived' = passed semantics validation and is a viable, still-live variant;
    'killed' = the semantics validator rejected it, same sense as mutation testing)."""
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()
    rows = store.conn.execute(
        f"SELECT id, vuln_class, variant, bypassed_rule, semantics_ok, coverage_gain, "
        f"created_at FROM payload_variant {where} ORDER BY id DESC LIMIT ?",
        args + (limit,)).fetchall()
    if not rows:
        return {"available": False, "reason": "no mutation variants recorded yet"}
    survived = killed = 0
    variants = []
    for r in rows:
        status = "survived" if r["semantics_ok"] else "killed"
        survived += status == "survived"
        killed += status == "killed"
        variants.append({
            "id": r["id"], "vuln_class": r["vuln_class"],
            "variant": _truncate(r["variant"]),
            "bypassed_rule": r["bypassed_rule"], "status": status,
            "coverage_gain": r["coverage_gain"], "created_at": r["created_at"],
        })
    return {"available": True, "n": len(rows), "survived": survived, "killed": killed,
            "variants": variants}


@_ml_panel
def weights_panel(store, run_id: int | None = None) -> dict[str, Any]:
    """The saved logistic classifier's coefficients (CC-UI-0038). Read-only.

    These are **standardised** log-odds coefficients — per standard deviation of each
    feature, other features held fixed. They are not feature importance: correlated
    features share weight under L2, and "per SD" reads oddly for 0/1 features."""
    ModelIncompatibleError = _ml().persist.ModelIncompatibleError
    ModelParamsError = _ml().persist.ModelParamsError
    load_classifier = _ml().train.load_classifier
    clf = _ml().train.latest_classifier(store, run_id)
    if clf is None:
        return {"available": False, "reason": "no trained classifier yet"}
    model_info = {"name": clf.name, "version": clf.version,
                  "params_sha256": clf.params_sha256}
    try:
        loaded = load_classifier(store, clf)
    except ModelParamsError as exc:
        return {"available": False, "model": model_info,
                "reason": f"saved model is unreadable: {exc}"}
    if loaded is None:
        return {"available": False, "model": model_info,
                "reason": "this classifier was trained before models were saved"}
    if loaded.kind == "gbt":
        return {"available": False, "model": model_info,
                "reason": "tree model — no linear coefficients"}
    if loaded.kind != "logistic":
        return {"available": False, "model": model_info,
                "reason": "fallback model — no features were learned"}
    try:
        loaded.check_compatible()
    except ModelIncompatibleError as exc:
        return {"available": False, "model": model_info, "reason": str(exc)}
    params = loaded.model.to_params()
    weights = [{"feature": "anomaly score (ECOD)" if name == "anomaly_ecod" else name,
                "weight": w} for name, w in zip(loaded.feature_names, params["w"])]
    weights.sort(key=lambda r: abs(r["weight"]), reverse=True)
    return {"available": True, "model": model_info, "weights": weights,
            "bias": params["b"],
            "note": "standardised log-odds coefficients (per SD, other features held "
                    "fixed); not feature importance"}


def ml_overview(store, run_id: int | None = None) -> dict[str, Any]:
    """Every ML panel in one read-only payload for `/api/ml/data` (R-06's full list)."""
    return {
        "run_id": run_id,
        "classifier": classifier_panel(store, run_id),
        "weights": weights_panel(store, run_id),
        "ranker": ranker_panel(store, run_id),
        "conformal": conformal_panel(store, run_id),
        "anomaly": anomaly_panel(store, run_id),
        "disagreement": disagreement_panel(store, run_id),
        "bandit": bandit_panel(store),
        "mutation": mutation_panel(store, run_id),
    }
