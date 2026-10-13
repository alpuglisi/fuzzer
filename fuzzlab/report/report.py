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


def _training(calibration: dict) -> dict:
    """What a model was trained on (CC-UI-0040): ``earlier`` runs (listed) or this
    ``run``'s own labels — the default for a legacy or run-mode row without the key."""
    if calibration.get("trained_on") == "earlier":
        return {"trained_on": "earlier", "train_run_ids": calibration.get("train_run_ids")}
    return {"trained_on": "run", "train_run_ids": None}


def _run_models(store, run_id: int) -> tuple[list[dict], dict[str, str | None], dict]:
    """The classifier and ranker whose scope covers ``run_id`` (FR-ML-10), plus each
    one's saved-params sha (None: trained before models were saved, migration 14) and
    what it was trained on."""
    from fuzzlab.ml.model_registry import params_sha256_for
    from fuzzlab.ml.rank_train import latest_ranker
    from fuzzlab.ml.train import latest_classifier
    found = []
    clf = latest_classifier(store, run_id)
    if clf is not None:
        found.append(({"name": clf.name, "version": clf.version,
                       "feature_version": clf.feature_version}, clf.params_sha256,
                      _training(clf.calibration)))
    ranked = latest_ranker(store, run_id)
    if ranked is not None:
        row, calibration = ranked
        found.append(({"name": row["name"], "version": row["version"],
                       "feature_version": row["feature_version"]},
                      params_sha256_for(store, row["id"]), _training(calibration)))
    found.sort(key=lambda entry: entry[0]["name"])
    return ([m for m, _, _ in found], {m["name"]: sha for m, sha, _ in found},
            {m["name"]: t for m, _, t in found})


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

    # The models THIS run used (classifier + ranker), for reproducibility — read through
    # the run-scoped readers, never "the newest version of each name" store-wide, which
    # would cite a later run's model in an earlier run's report (BUG-0066).
    models, model_shas, model_training = _run_models(store, run_id)

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
            "model_params_sha256": model_shas,
            "model_training": model_training,
            "plugins": {p["name"]: p["version"] for p in plugins},
            "schema_version": store.schema_version(),
        },
    }


def _trained_note(training: dict | None) -> str:
    if not training or training.get("trained_on") != "earlier":
        return ""
    runs = ", ".join(str(r) for r in training.get("train_run_ids") or [])
    return f" (trained on earlier runs {runs})"


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
        training = report["reproducibility"].get("model_training", {})
        lines.append("  models: " + ", ".join(
            f"{m['name']} v{m['version']}" + _trained_note(training.get(m["name"]))
            for m in report["models"]))
    if report["plugins"]:
        lines.append("  plugins: " + ", ".join(
            f"{p['name']} v{p['version']}" for p in report["plugins"]))
    if report["findings"]:
        lines.append("  findings:")
        for f in report["findings"]:
            lines.append(f"    - {f['vuln_class']} {f['method']} {f['url']} "
                         f"[{f['param']}] ({f['confidence']})")
    return "\n".join(lines)
