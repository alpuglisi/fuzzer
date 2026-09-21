"""Build a deterministic report dict from a stored run (Phase 10 T10.4).

Pure reads over the store; every list is sorted by a stable key so the output is
byte-identical for the same (store, run). The report captures what a run needs to be
reproduced and compared: the run/config identity, the target fingerprint, the pipeline
counts, the confirmed findings, the honest metrics (`run_metrics`), the models trained,
and the active plugin set (migration 10). ``format_json`` renders canonical JSON
(sorted keys); ``format_text`` a human-readable summary.
"""

from __future__ import annotations

import json


def _one(store, sql, args=()):
    row = store.conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def _count(store, sql, args) -> int:
    return int(store.conn.execute(sql, args).fetchone()["c"])


def latest_run_id(store) -> int | None:
    row = store.conn.execute("SELECT MAX(id) AS id FROM run").fetchone()
    return int(row["id"]) if row and row["id"] is not None else None


def build_report(store, run_id: int | None = None) -> dict:
    """Assemble the deterministic report for ``run_id`` (default: the latest run)."""
    if run_id is None:
        run_id = latest_run_id(store)
    if run_id is None:
        return {"run": None}

    run = _one(store, "SELECT id, tool, started_at, config_hash, env_profile, notes "
                      "FROM run WHERE id=?", (run_id,))
    target = _one(store, "SELECT base_url, dbms, framework, waf FROM target "
                         "WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,))

    fired = {int(r["fired"]): int(r["c"]) for r in store.conn.execute(
        "SELECT fired, COUNT(*) c FROM evaluation WHERE run_id=? GROUP BY fired",
        (run_id,))}
    counts = {
        "pages": _count(store, "SELECT COUNT(*) c FROM page WHERE run_id=?", (run_id,)),
        "endpoints": _count(store, "SELECT COUNT(*) c FROM endpoint WHERE run_id=?", (run_id,)),
        "candidates": _count(store, "SELECT COUNT(*) c FROM candidate WHERE run_id=?", (run_id,)),
        "evaluations": fired.get(0, 0) + fired.get(1, 0),
        "evaluations_fired": fired.get(1, 0),
        "evaluations_negative": fired.get(0, 0),
        "attempts": _count(store, "SELECT COUNT(*) c FROM attempt WHERE run_id=?", (run_id,)),
        "findings": _count(store, "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)),
    }

    findings = [dict(r) for r in store.conn.execute(
        "SELECT vuln_class, url, method, param, confidence FROM finding WHERE run_id=? "
        "ORDER BY vuln_class, url, param, method", (run_id,))]

    metrics = {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=? ORDER BY key", (run_id,))}

    # Latest version per model name (the deployed models), for reproducibility.
    models = [dict(r) for r in store.conn.execute(
        "SELECT name, MAX(version) AS version, feature_version FROM model "
        "GROUP BY name ORDER BY name")]

    plugins = [dict(r) for r in store.conn.execute(
        "SELECT name, version, priority FROM run_plugin WHERE run_id=? "
        "ORDER BY priority, name", (run_id,))]

    feature_versions = sorted({int(r["feature_version"]) for r in store.conn.execute(
        "SELECT DISTINCT feature_version FROM candidate WHERE run_id=? "
        "AND feature_version IS NOT NULL", (run_id,))})

    return {
        "run": run,
        "target": target,
        "counts": counts,
        "findings": findings,
        "metrics": metrics,
        "models": models,
        "plugins": plugins,
        "reproducibility": {
            "config_hash": run.get("config_hash") if run else None,
            "feature_versions": feature_versions,
            "model_versions": {m["name"]: m["version"] for m in models},
            "plugins": {p["name"]: p["version"] for p in plugins},
            "schema_version": store.schema_version(),
        },
    }


def format_json(report: dict) -> str:
    """Canonical JSON — sorted keys, stable — for diffing/reproducibility."""
    return json.dumps(report, sort_keys=True, indent=2, default=str)


def format_text(report: dict) -> str:
    run = report.get("run")
    if run is None:
        return "no runs in the store"
    lines = [f"fuzzlab run #{run['id']} ({run['tool']}, {run['started_at']})",
             f"  config_hash: {run.get('config_hash')}   schema: "
             f"{report['reproducibility']['schema_version']}"]
    tgt = report.get("target")
    if tgt:
        lines.append(f"  target: {tgt['base_url']}  dbms={tgt['dbms']} "
                     f"framework={tgt['framework']} waf={tgt['waf']}")
    c = report["counts"]
    lines.append(f"  counts: {c['candidates']} candidate(s), "
                 f"{c['evaluations_fired']}/{c['evaluations']} evaluations fired, "
                 f"{c['findings']} finding(s)")
    for key in sorted(report["metrics"]):
        lines.append(f"  metric {key} = {report['metrics'][key]}")
    if report["models"]:
        lines.append("  models: " + ", ".join(
            f"{m['name']} v{m['version']}" for m in report["models"]))
    if report["plugins"]:
        lines.append("  plugins: " + ", ".join(
            f"{p['name']} v{p['version']}" for p in report["plugins"]))
    if report["findings"]:
        lines.append("  findings:")
        for f in report["findings"]:
            lines.append(f"    - {f['vuln_class']} {f['method']} {f['url']} "
                         f"[{f['param']}] ({f['confidence']})")
    return "\n".join(lines)
