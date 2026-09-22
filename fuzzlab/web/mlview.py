"""Read-only, store-backed ML tab data (U4; feature Phase 3).

Mirrors `web/results.py` / `web/proxyview.py`: pure functions over the shared store, no
writes, no training, no fuzzing-loop influence — this module only *reads* what
`fuzzlab/ml/`, `fuzzlab/oracle/`, `fuzzlab/scheduler/`, and `fuzzlab/mutation/` already
computed and persisted (``run_metrics``, ``metric_series`` (B0), ``model``,
``candidate``, ``bandit_posteriors``, ``payload_variant``). It never presents a score as
a label and never invents a metric no emitter actually writes: a family with nothing
stored yet reports ``available: False`` instead of a fabricated chart (see
docs/UI_IMPLEMENTATION_PLAN.md §U4 / the R-06 resolved note).

``build_dataset`` (from `fuzzlab.ml.dataset`) is reused here to correlate a run's
persisted `candidate.score` with its `finding`-derived label for the PR-curve/
reliability-diagram panels — this is a *read* over already-written rows (it trains
nothing), the same function `fuzzlab.ml.train.train_and_score` itself uses to build the
honest OOF fit.
"""

from __future__ import annotations

import json
import math
from typing import Any

_CLASSIFIER_MODEL_NAMES = ("logistic", "gbt", "prevalence-fallback")
_RANKER_MODEL_NAMES = ("ranker", "rank-prevalence-fallback")
_CLASSIFIER_SOURCE = {"logistic": "logreg", "gbt": "gbt"}


def _latest_run_with_key(store, key: str) -> int | None:
    row = store.conn.execute(
        "SELECT run_id FROM run_metrics WHERE key=? ORDER BY run_id DESC LIMIT 1",
        (key,)).fetchone()
    return int(row["run_id"]) if row else None


def _latest_run_with_series(store, source: str) -> int | None:
    row = store.conn.execute(
        "SELECT run_id FROM metric_series WHERE source=? ORDER BY run_id DESC LIMIT 1",
        (source,)).fetchone()
    return int(row["run_id"]) if row else None


def _run_metrics(store, run_id: int) -> dict[str, float]:
    rows = store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,)).fetchall()
    return {r["key"]: r["value"] for r in rows}


def _series(store, run_id: int, source: str, key: str) -> dict[str, list]:
    rows = store.conn.execute(
        "SELECT step, value FROM metric_series WHERE run_id=? AND source=? AND key=? "
        "ORDER BY step", (run_id, source, key)).fetchall()
    return {"steps": [int(r["step"]) for r in rows],
            "values": [round(float(r["value"]), 6) for r in rows]}


def _latest_model(store, names: tuple[str, ...]) -> dict[str, Any] | None:
    placeholders = ",".join("?" for _ in names)
    row = store.conn.execute(
        f"SELECT name, version, feature_version, calibration FROM model "
        f"WHERE name IN ({placeholders}) ORDER BY id DESC LIMIT 1", names).fetchone()
    if row is None:
        return None
    try:
        calib = json.loads(row["calibration"] or "{}")
    except (ValueError, TypeError):
        calib = {}
    return {"name": row["name"], "version": row["version"],
            "feature_version": row["feature_version"], "calibration": calib}


def _histogram(values: list[float], *, bins: int = 12, lo: float = 0.0,
              hi: float = 1.0) -> dict[str, list]:
    """Fixed-range histogram (advisory scores live in [0, 1]); read-only summary math,
    not a trained artifact. Empty input yields empty edges/counts (nothing to draw)."""
    if not values:
        return {"edges": [], "counts": []}
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in values:
        idx = int((v - lo) / width) if width else 0
        idx = 0 if idx < 0 else bins - 1 if idx >= bins else idx
        counts[idx] += 1
    edges = [round(lo + i * width, 4) for i in range(bins + 1)]
    return {"edges": edges, "counts": counts}


# --- classifier ---------------------------------------------------------------

def _classifier(store) -> dict[str, Any]:
    run_id = _latest_run_with_key(store, "ml_pr_auc")
    model = _latest_model(store, _CLASSIFIER_MODEL_NAMES)
    if run_id is None or model is None:
        return {"available": False}
    rm = _run_metrics(store, run_id)
    out: dict[str, Any] = {
        "available": True, "run_id": run_id, "model": model["name"],
        "version": model["version"], "feature_version": model["feature_version"],
        "pr_auc": rm.get("ml_pr_auc"), "baseline_prevalence": rm.get("ml_pr_auc_prevalence"),
        "baseline_sigma": rm.get("ml_pr_auc_sigma"),
    }
    source = _CLASSIFIER_SOURCE.get(model["name"])
    out["training_curve"] = _series(store, run_id, source, "train/loss") if source else \
        {"steps": [], "values": []}

    # PR-curve / reliability inputs: correlate this run's persisted candidate.score
    # with its finding-derived label via build_dataset (a read, not a re-fit).
    from fuzzlab.ml.dataset import build_dataset
    ds = build_dataset(store, run_id)
    scores_by_id = dict(store.conn.execute(
        "SELECT id, score FROM candidate WHERE run_id=? AND score IS NOT NULL",
        (run_id,)).fetchall())
    pairs = [(scores_by_id[i], y) for i, y in zip(ds.ids, ds.y) if i in scores_by_id]
    out["score_label_pairs"] = len(pairs)
    out["score_histogram"] = _histogram([s for s, _ in pairs])
    out["reliability"] = _reliability(pairs)
    return out


def _reliability(pairs: list[tuple[float, int]], *, bins: int = 10) -> dict[str, list]:
    """Binned reliability diagram (mean predicted score vs. observed rate per bin) + ECE
    — read-only summary math over already-persisted (score, label) pairs, never a
    re-fit. Empty/too-thin input yields empty arrays (nothing to draw, no fabrication)."""
    if not pairs:
        return {"bin_mean_score": [], "bin_observed_rate": [], "bin_count": [], "ece": None}
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for s, y in pairs:
        idx = min(bins - 1, max(0, int(s * bins)))
        buckets[idx].append((s, y))
    mean_score, observed, count = [], [], []
    ece = 0.0
    n = len(pairs)
    for b in buckets:
        if not b:
            mean_score.append(None)
            observed.append(None)
            count.append(0)
            continue
        ms = sum(s for s, _ in b) / len(b)
        obs = sum(y for _, y in b) / len(b)
        mean_score.append(round(ms, 4))
        observed.append(round(obs, 4))
        count.append(len(b))
        ece += (len(b) / n) * abs(ms - obs)
    return {"bin_mean_score": mean_score, "bin_observed_rate": observed,
            "bin_count": count, "ece": round(ece, 4)}


# --- ranker --------------------------------------------------------------------

def _ranker(store) -> dict[str, Any]:
    run_id = _latest_run_with_key(store, "rank_ndcg")
    model = _latest_model(store, _RANKER_MODEL_NAMES)
    if run_id is None or model is None:
        return {"available": False}
    rm = _run_metrics(store, run_id)
    rows = store.conn.execute(
        "SELECT rank_score, rank_uncertainty FROM candidate WHERE run_id=? "
        "AND rank_score IS NOT NULL", (run_id,)).fetchall()
    scores = [r["rank_score"] for r in rows]
    uncert = [r["rank_uncertainty"] for r in rows if r["rank_uncertainty"] is not None]
    return {
        "available": True, "run_id": run_id, "model": model["name"],
        "version": model["version"], "ndcg": rm.get("rank_ndcg"),
        "precision": rm.get("rank_precision"), "ndcg_random": rm.get("rank_ndcg_random"),
        "precision_random": rm.get("rank_precision_random"),
        "score_histogram": _histogram(scores),
        "uncertainty_histogram": _histogram(uncert),
        "scored": len(rows),
    }


# --- conformal triage ------------------------------------------------------------

def _conformal(store) -> dict[str, Any]:
    model = _latest_model(store, ("logistic", "gbt"))
    calib = (model or {}).get("calibration") or {}
    if model is None or "t_lo" not in calib or "t_hi" not in calib:
        return {"available": False}
    run_id = _latest_run_with_key(store, "ml_pr_auc")
    if run_id is None:
        return {"available": False}
    from fuzzlab.ml.conformal import ConformalGate
    gate = ConformalGate(t_lo=calib["t_lo"], t_hi=calib["t_hi"])
    rows = store.conn.execute(
        "SELECT score FROM candidate WHERE run_id=? AND score IS NOT NULL",
        (run_id,)).fetchall()
    scores = [r["score"] for r in rows]
    counts = {"flag": 0, "abstain": 0, "drop": 0}
    for s in scores:
        counts[gate.decide(s)] += 1
    return {
        "available": True, "run_id": run_id, "t_lo": calib["t_lo"], "t_hi": calib["t_hi"],
        "alpha": calib.get("alpha"), "counts": counts, "total": len(scores),
        "score_histogram": _histogram(scores),
    }


# --- anomaly (ECOD) --------------------------------------------------------------

def _anomaly(store) -> dict[str, Any]:
    run_id = _latest_run_with_key(store, "anomaly_flagged")
    if run_id is None:
        return {"available": False}
    rm = _run_metrics(store, run_id)
    flagged = rm.get("anomaly_flagged")
    rows = store.conn.execute(
        "SELECT COUNT(*) c FROM candidate WHERE run_id=?", (run_id,)).fetchone()["c"]
    return {
        "available": True, "run_id": run_id, "flagged": flagged, "rows": rows,
        "flagged_rate": round(flagged / rows, 4) if rows and flagged is not None else None,
        # ECOD per-point scores are not persisted anywhere (fuzzlab/ml/anomaly.py only
        # writes the flagged COUNT to run_metrics) — no score histogram to show; the
        # per-point tripwire output would need its own storage to chart honestly.
        "score_histogram_available": False,
    }


# --- active learning --------------------------------------------------------------

def _active_learning(store) -> dict[str, Any]:
    # fuzzlab/ml/active.py proposes queries but persists nothing (no run_metrics, no
    # metric_series) — the only stored signal an advisory dashboard can read honestly
    # is the ranker's already-persisted `rank_uncertainty` (the same field the
    # "uncertainty" query strategy itself reads). Query-by-committee disagreement is
    # computed in-memory only and never stored, so that panel stays unavailable.
    run_id = _latest_run_with_key(store, "rank_ndcg")
    if run_id is None:
        return {"available": False, "committee_available": False}
    rows = store.conn.execute(
        "SELECT id, evidence, rank_uncertainty FROM candidate WHERE run_id=? "
        "AND rank_uncertainty IS NOT NULL ORDER BY rank_uncertainty DESC LIMIT 20",
        (run_id,)).fetchall()
    queue = []
    for r in rows:
        try:
            ev = json.loads(r["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        queue.append({"id": r["id"], "url": ev.get("url", ""), "param": ev.get("param", ""),
                     "uncertainty": round(r["rank_uncertainty"], 4)})
    return {"available": True, "committee_available": False, "run_id": run_id,
            "queue": queue}


# --- bandit (Thompson posteriors) --------------------------------------------------

def _quantile_normal_approx(alpha: float, beta: float, p: float) -> float:
    """Beta quantile via a mean/variance normal approximation — good enough for a
    display CI band on an advisory dashboard (no scipy dependency in this toolkit)."""
    mean = alpha / (alpha + beta)
    var = (alpha * beta) / (((alpha + beta) ** 2) * (alpha + beta + 1))
    sd = math.sqrt(max(var, 0.0))
    # inverse-normal-CDF via Acklam's rational approximation would be overkill here;
    # a fixed z for the two-sided 90% interval (p=0.05/0.95) is all this panel needs.
    z = 1.6448536269514722 if p >= 0.5 else -1.6448536269514722
    return max(0.0, min(1.0, mean + z * sd))


def _bandit(store) -> dict[str, Any]:
    rows = store.conn.execute(
        "SELECT context, arm, alpha, beta, cost_sum, cost_n FROM bandit_posteriors "
        "ORDER BY context, arm").fetchall()
    if not rows:
        return {"available": False}
    arms = []
    for r in rows:
        a, b = float(r["alpha"]), float(r["beta"])
        pulls = int(r["cost_n"])
        arms.append({
            "context": r["context"], "arm": r["arm"], "alpha": a, "beta": b,
            "mean": round(a / (a + b), 4),
            "ci_lo": round(_quantile_normal_approx(a, b, 0.05), 4),
            "ci_hi": round(_quantile_normal_approx(a, b, 0.95), 4),
            "pulls": pulls,
            "cost": round(r["cost_sum"] / pulls, 4) if pulls else None,
        })
    run_id = _latest_run_with_series(store, "bandit")
    regret = _series(store, run_id, "bandit", "regret/cumulative") if run_id is not None \
        else {"steps": [], "values": []}
    return {"available": True, "arms": arms, "run_id": run_id, "regret": regret}


# --- mutation variants --------------------------------------------------------------

def _mutation(store) -> dict[str, Any]:
    run_id = _latest_run_with_series(store, "mutation")
    rows = store.conn.execute(
        "SELECT base_payload, variant, operators, vuln_class, bypassed_rule, "
        "semantics_ok, coverage_gain FROM payload_variant "
        + ("WHERE run_id=? " if run_id is not None else "")
        + "ORDER BY id DESC LIMIT 50", (run_id,) if run_id is not None else ()).fetchall()
    variants = []
    for r in rows:
        try:
            ops = json.loads(r["operators"] or "[]")
        except (ValueError, TypeError):
            ops = []
        variants.append({
            "base_payload": r["base_payload"], "variant": r["variant"], "operators": ops,
            "vuln_class": r["vuln_class"], "bypassed_rule": r["bypassed_rule"],
            "semantics_ok": bool(r["semantics_ok"]), "coverage_gain": r["coverage_gain"],
        })
    if run_id is None and not variants:
        return {"available": False}
    reward = _series(store, run_id, "mutation", "reward") if run_id is not None \
        else {"steps": [], "values": []}
    novelty = _series(store, run_id, "mutation", "novelty") if run_id is not None \
        else {"steps": [], "values": []}
    return {
        "available": True, "run_id": run_id, "variants": variants,
        "reward": reward, "novelty": novelty,
        # payload_variant only ever records an ACCEPTED (evaded + semantics-preserving)
        # variant (fuzzlab/mutation/run.py writes a row only on `bypass`); a variant the
        # filter caught ("killed") is never persisted, so there is no killed count to
        # show here — labelled honestly in the template rather than inferred/guessed.
        "killed_tracked": False,
    }


def empty_context() -> dict[str, Any]:
    return {
        "classifier": {"available": False}, "ranker": {"available": False},
        "conformal": {"available": False}, "anomaly": {"available": False},
        "active_learning": {"available": False, "committee_available": False},
        "bandit": {"available": False}, "mutation": {"available": False},
    }


def ml_context(store) -> dict[str, Any]:
    """Everything the ML tab renders, in one read-only pass over the store."""
    return {
        "classifier": _classifier(store),
        "ranker": _ranker(store),
        "conformal": _conformal(store),
        "anomaly": _anomaly(store),
        "active_learning": _active_learning(store),
        "bandit": _bandit(store),
        "mutation": _mutation(store),
    }
