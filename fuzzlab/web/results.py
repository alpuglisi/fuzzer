"""Read run results from the store for the control panel (pure, dependency-light).

The panel reviews what the tools wrote — runs, oracle findings, negatives, the target
fingerprint, request metrics, and the score — straight from the unified store. Kept
separate from the web layer so it is testable without FastAPI and never sends traffic.
"""

from __future__ import annotations

import json
from pathlib import Path

from fuzzlab.core.urls import to_path

# Score keys the harness records (report.as_dict); surfaced as a group in the UI.
_SCORE_KEYS = ("tp", "fp", "tn", "fn", "precision", "recall", "mcc")


def _scored_candidates(store, run_id: int, limit: int = 10) -> tuple[dict | None, list[dict]]:
    """The latest model + this run's top advisory-scored candidates (with the conformal
    decision). Advisory only — these are scores, never findings."""
    row = store.conn.execute(
        "SELECT name, version, calibration FROM model ORDER BY id DESC LIMIT 1").fetchone()
    model = gate = None
    if row is not None:
        try:
            calib = json.loads(row["calibration"] or "{}")
        except (ValueError, TypeError):
            calib = {}
        model = {"name": row["name"], "version": row["version"], "calibration": calib}
        if "t_lo" in calib and "t_hi" in calib:
            from fuzzlab.ml.conformal import ConformalGate
            gate = ConformalGate(t_lo=calib["t_lo"], t_hi=calib["t_hi"])
    scored = []
    for c in store.conn.execute(
        "SELECT evidence, score FROM candidate WHERE run_id=? AND score IS NOT NULL "
        "ORDER BY score DESC LIMIT ?", (run_id, limit)).fetchall():
        try:
            ev = json.loads(c["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        scored.append({"url": to_path(ev.get("url", "")), "param": ev.get("param", ""),
                       "category": ev.get("category", ""), "score": round(c["score"], 4),
                       "decision": gate.decide(c["score"]) if gate else "n/a"})
    return model, scored


def store_exists(store_path: str | Path) -> bool:
    return Path(store_path).exists()


def list_runs(store) -> list[dict]:
    """All runs, newest first, each with its oracle-finding count."""
    rows = store.conn.execute(
        "SELECT id, tool, config_hash, started_at, notes FROM run ORDER BY id DESC"
    ).fetchall()
    out = []
    for r in rows:
        findings = store.conn.execute(
            "SELECT COUNT(*) c FROM finding WHERE run_id=?", (r["id"],)).fetchone()["c"]
        out.append({"id": r["id"], "tool": r["tool"], "target": r["config_hash"],
                    "started_at": r["started_at"], "findings": findings})
    return out


def _count(store, table: str, run_id: int) -> int:
    return store.conn.execute(
        f"SELECT COUNT(*) c FROM {table} WHERE run_id=?", (run_id,)).fetchone()["c"]


def run_detail(store, run_id: int) -> dict | None:
    """Findings, dataset counts, target fingerprint, metrics, and score for one run."""
    run = store.conn.execute(
        "SELECT id, tool, config_hash, started_at FROM run WHERE id=?", (run_id,)
    ).fetchone()
    if run is None:
        return None

    findings = []
    for f in store.conn.execute(
        "SELECT vuln_class, url, method, param, confidence, evidence FROM finding "
        "WHERE run_id=? ORDER BY id", (run_id,)
    ).fetchall():
        try:
            evidence = json.loads(f["evidence"]) if f["evidence"] else {}
        except (ValueError, TypeError):
            evidence = {"raw": f["evidence"]}
        findings.append({"vuln_class": f["vuln_class"], "url": f["url"],
                         "method": f["method"], "param": f["param"],
                         "confidence": f["confidence"], "evidence": evidence})

    fired = {r["fired"]: r["c"] for r in store.conn.execute(
        "SELECT fired, COUNT(*) c FROM evaluation WHERE run_id=? GROUP BY fired",
        (run_id,)).fetchall()}
    metrics = {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,)).fetchall()}
    target = store.conn.execute(
        "SELECT base_url, dbms, framework, waf FROM target WHERE run_id=?", (run_id,)
    ).fetchone()

    score = {k: metrics[k] for k in _SCORE_KEYS if k in metrics} or None
    model, scored = _scored_candidates(store, run_id)

    return {
        "id": run["id"], "tool": run["tool"], "target": run["config_hash"],
        "started_at": run["started_at"],
        "findings": findings,
        "counts": {
            "candidates": _count(store, "candidate", run_id),
            "attempts": _count(store, "attempt", run_id),
            "evaluations": (fired.get(0, 0) + fired.get(1, 0)),
            "negatives": fired.get(0, 0),
            "pages": _count(store, "page", run_id),
        },
        "target_fingerprint": dict(target) if target else None,
        "metrics": metrics,
        "score": score,
        "model": model,
        "scored": scored,
    }
