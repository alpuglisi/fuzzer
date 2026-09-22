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
_SCORE_KEYS = ("tp", "fp", "tn", "fn", "precision", "recall", "mcc", "f1")


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


def overview_summary(store, recent_limit: int = 10) -> dict:
    """Read-only aggregate for the Overview dashboard (R1, FR-UI-9): counts, a
    findings-by-category breakdown (the store has no severity taxonomy yet — see
    FR-UI-9), the latest run, the latest scored run's detection quality, the latest
    run with an efficiency metric, and a bounded recent-runs slice. One query pass;
    no result-table writes (NFR-UI-read-only)."""
    from datetime import datetime, timedelta, timezone

    runs = list_runs(store)
    total_findings = sum(r["findings"] for r in runs)

    def _parse(ts):
        if not ts:
            return None
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    runs_7d = sum(1 for r in runs if (dt := _parse(r["started_at"])) and dt >= cutoff)

    cat_rows = store.conn.execute(
        "SELECT COALESCE(vuln_class, 'unknown') AS vuln_class, COUNT(*) AS c "
        "FROM finding GROUP BY vuln_class ORDER BY c DESC"
    ).fetchall()
    findings_by_category = [{"category": r["vuln_class"], "count": r["c"]} for r in cat_rows]

    quality = None
    efficiency = None
    for r in runs:  # newest first
        metrics = {row["key"]: row["value"] for row in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (r["id"],)).fetchall()}
        if quality is None and "f1" in metrics:
            quality = {"run_id": r["id"], "f1": metrics["f1"], "mcc": metrics.get("mcc")}
        if efficiency is None and "requests_per_finding" in metrics:
            efficiency = {"run_id": r["id"],
                          "requests_per_finding": metrics["requests_per_finding"],
                          "pipeline_requests": metrics.get("pipeline_requests")}
        if quality is not None and efficiency is not None:
            break

    return {
        "total_runs": len(runs),
        "runs_7d": runs_7d,
        "total_findings": total_findings,
        "findings_by_category": findings_by_category,
        "last_run": runs[0] if runs else None,
        "quality": quality,
        "efficiency": efficiency,
        "recent_runs": runs[:recent_limit],
    }


def _candidate_category(cand_evidence_json: str | None) -> str | None:
    """The audit rule category from a joined candidate's evidence JSON, if any
    (``{"rule_id": ..., "category": ...}`` — see ``audit/engine.py``). ``None`` when
    the finding has no linked candidate or its evidence carries no category."""
    if not cand_evidence_json:
        return None
    try:
        return json.loads(cand_evidence_json).get("category")
    except (ValueError, TypeError, AttributeError):
        return None


def list_findings(store, *, run_id: int | None = None, vuln_class: str | None = None,
                  confidence: str | None = None, category: str | None = None,
                  has_evidence: bool | None = None, limit: int = 1000) -> list[dict]:
    """Findings for the R2 Findings workbench, newest first, with the facets
    ``docs/UI_LAYOUT_REDESIGN.md`` #6/#9 call for: ``vuln_class``, ``confidence``,
    ``category`` (derived — the store has no category column on `finding` itself, so
    it is read from the linked attempt's candidate's audit evidence, when there is
    one), ``run_id``, and ``has_evidence``. Read-only; never writes.

    Filtering is done in Python (not SQL) because ``category`` is derived from JSON,
    not a column — acceptable at the lab's scale (a run's findings are tens to a few
    hundred rows, not a production-scale table).
    """
    rows = store.conn.execute(
        "SELECT f.id, f.run_id, f.vuln_class, f.confidence, f.url, f.method, f.param, "
        "f.evidence, f.created_at, c.evidence AS cand_evidence "
        "FROM finding f LEFT JOIN attempt a ON f.attempt_id = a.id "
        "LEFT JOIN candidate c ON a.candidate_id = c.id "
        "ORDER BY f.id DESC"
    ).fetchall()
    out = []
    for r in rows:
        if run_id is not None and r["run_id"] != run_id:
            continue
        if vuln_class and r["vuln_class"] != vuln_class:
            continue
        if confidence and r["confidence"] != confidence:
            continue
        cat = _candidate_category(r["cand_evidence"])
        if category and cat != category:
            continue
        try:
            evidence = json.loads(r["evidence"]) if r["evidence"] else {}
        except (ValueError, TypeError):
            evidence = {"raw": r["evidence"]}
        has_ev = bool(evidence)
        if has_evidence is not None and has_ev != bool(has_evidence):
            continue
        out.append({
            "id": r["id"], "run_id": r["run_id"], "vuln_class": r["vuln_class"],
            "confidence": r["confidence"], "url": r["url"], "method": r["method"],
            "param": r["param"], "evidence": evidence, "category": cat,
            "has_evidence": has_ev, "created_at": r["created_at"],
        })
        if len(out) >= limit:
            break
    return out


def finding_facets(store) -> dict:
    """Distinct filter values for the Findings workbench's facet plane: the
    vuln_classes and confidences findings actually carry, the categories present on
    their linked candidates' audit evidence, and the runs that have findings at all
    (so a run picker never lists a run with nothing to show)."""
    vuln_classes = [r["vuln_class"] for r in store.conn.execute(
        "SELECT DISTINCT vuln_class FROM finding WHERE vuln_class IS NOT NULL "
        "AND vuln_class != '' ORDER BY vuln_class").fetchall()]
    confidences = [r["confidence"] for r in store.conn.execute(
        "SELECT DISTINCT confidence FROM finding WHERE confidence IS NOT NULL "
        "AND confidence != '' ORDER BY confidence").fetchall()]
    runs = [{"id": r["id"], "tool": r["tool"]} for r in store.conn.execute(
        "SELECT DISTINCT r.id, r.tool FROM run r JOIN finding f ON f.run_id = r.id "
        "ORDER BY r.id DESC").fetchall()]
    categories: set[str] = set()
    for r in store.conn.execute(
        "SELECT c.evidence FROM finding f JOIN attempt a ON f.attempt_id = a.id "
        "JOIN candidate c ON a.candidate_id = c.id WHERE c.evidence IS NOT NULL"
    ).fetchall():
        cat = _candidate_category(r["evidence"])
        if cat:
            categories.add(cat)
    return {"vuln_classes": vuln_classes, "confidences": confidences,
            "categories": sorted(categories), "runs": runs}


def finding_detail(store, finding_id: int) -> dict | None:
    """One finding with its linked attempt/candidate context (payload family,
    reward/score, the audit rule and sink context) and its run's target base URL —
    everything the detail pane and the "send to Repeater" pivot need. ``None`` if the
    finding does not exist."""
    row = store.conn.execute(
        "SELECT f.id, f.run_id, f.attempt_id, f.vuln_class, f.confidence, f.url, "
        "f.method, f.param, f.evidence, f.created_at, "
        "a.candidate_id, a.payload_family, a.reward, a.score AS attempt_score, "
        "c.rule, c.sink_context, c.evidence AS cand_evidence, "
        "r.tool AS run_tool, r.started_at AS run_started_at, "
        "t.base_url AS target_base_url "
        "FROM finding f LEFT JOIN attempt a ON f.attempt_id = a.id "
        "LEFT JOIN candidate c ON a.candidate_id = c.id "
        "LEFT JOIN run r ON f.run_id = r.id "
        "LEFT JOIN target t ON t.run_id = f.run_id "
        "WHERE f.id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    try:
        evidence = json.loads(row["evidence"]) if row["evidence"] else {}
    except (ValueError, TypeError):
        evidence = {"raw": row["evidence"]}
    return {
        "id": row["id"], "run_id": row["run_id"], "run_tool": row["run_tool"],
        "run_started_at": row["run_started_at"], "vuln_class": row["vuln_class"],
        "confidence": row["confidence"], "url": row["url"], "method": row["method"],
        "param": row["param"], "evidence": evidence,
        "category": _candidate_category(row["cand_evidence"]),
        "created_at": row["created_at"],
        "attempt": None if row["attempt_id"] is None else {
            "id": row["attempt_id"], "payload_family": row["payload_family"],
            "reward": row["reward"], "score": row["attempt_score"]},
        "candidate": None if row["candidate_id"] is None else {
            "id": row["candidate_id"], "rule": row["rule"],
            "sink_context": row["sink_context"]},
        "target_base_url": row["target_base_url"],
    }


def build_finding_raw_request(url: str | None, method: str | None, param: str | None,
                              payload: str, target_base_url: str | None) -> tuple[str, str, int, bool]:
    """Synthesize a raw HTTP/1.1 request for a finding's location (send-to-Repeater,
    R2). The store keeps no raw bytes for a finding — only its ``url``/``method``/
    ``param`` and the oracle's ``evidence`` — so this reconstructs a replayable
    request from those: the payload comes from ``evidence['payload']`` when the
    confirming strategy recorded one (most do — see ``oracle/strategies.py``), else
    an empty value (still a valid request against the same location, just without the
    reproduced payload — some mechanisms, e.g. timing-based, do not record one).
    Returns ``(raw_text, host, port, use_tls)`` for :meth:`RepeaterController.create_tab`.
    """
    from urllib.parse import quote, urlparse

    parsed = urlparse(target_base_url or "")
    host = parsed.hostname or "127.0.0.1"
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    method = (method or "GET").upper()
    path = url or "/"
    if not path.startswith("/"):
        path = "/" + path
    value = quote(payload or "", safe="")
    if method != "GET" and param:
        body = f"{param}={value}"
        body_bytes = body.encode("utf-8")
        raw = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
              f"Content-Type: application/x-www-form-urlencoded\r\n"
              f"Content-Length: {len(body_bytes)}\r\n\r\n{body}")
    elif method != "GET":
        raw = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    else:
        target = path
        if param:
            sep = "&" if "?" in path else "?"
            target = f"{path}{sep}{param}={value}"
        raw = f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    return raw, host, port, use_tls


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
