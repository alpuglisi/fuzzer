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

from fuzzlab.core.modelinfo import trained_on
from fuzzlab.core.runtarget import run_target


def _one(store, sql, args=()):
    row = store.conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def _count(store, sql, args) -> int:
    return int(store.conn.execute(sql, args).fetchone()["c"])


def latest_run_id(store) -> int | None:
    row = store.conn.execute("SELECT MAX(id) AS id FROM run").fetchone()
    return int(row["id"]) if row and row["id"] is not None else None


def _training(calibration: dict) -> dict:
    """What a model was trained on (CC-UI-0040, CC-UI-0042): ``earlier`` runs (listed),
    a ``saved`` earlier model applied as is (its original row and training runs), or
    this ``run``'s own labels — the default for a legacy or run-mode row."""
    kind = trained_on(calibration)
    if kind == "earlier":
        return {"trained_on": "earlier", "train_run_ids": calibration.get("train_run_ids")}
    if kind == "saved":
        return {"trained_on": "saved", "train_run_ids": calibration.get("train_run_ids"),
                "source_model_id": calibration.get("source_model_id")}
    return {"trained_on": kind or "unknown", "train_run_ids": None}


#: Stage metrics that record the candidate / flow feature version a stage read on a run
#: without saving a `model` row (BUG-0069, CC-UI-0047).
_CANDIDATE_VERSION_METRICS = ("anomaly_feature_version", "pipeline_budget_feature_version")
_FLOW_VERSION_METRICS = ("flow_anomaly_feature_version",)


def _feature_versions(store, run_id: int, models: list[dict], metrics: dict) -> dict:
    """The feature versions this run's results were computed from, per counter
    (BUG-0069): ``candidate`` — stored `candidate.feature_version` values, the run's
    pinned models' `feature_version`, and every stage that read candidate features
    without saving a model (anomaly tripwire, budget prioritizer); ``flow`` — the flow
    tripwire's. An empty list means no stage computed that vector on this run. (The
    response extractor's counter is not listed: nothing records it on a run yet.)"""
    candidate = {int(r["feature_version"]) for r in store.conn.execute(
        "SELECT DISTINCT feature_version FROM candidate WHERE run_id=? "
        "AND feature_version IS NOT NULL", (run_id,))}
    candidate |= {int(m["feature_version"]) for m in models
                  if m.get("feature_version") is not None}
    candidate |= {int(metrics[k]) for k in _CANDIDATE_VERSION_METRICS if k in metrics}
    flow = {int(metrics[k]) for k in _FLOW_VERSION_METRICS if k in metrics}
    return {"candidate": sorted(candidate), "flow": sorted(flow)}


def _run_models(store, run_id: int) -> tuple[list[dict], dict[str, str | None], dict] | None:
    """The classifier and ranker whose scope covers ``run_id`` (FR-ML-10), plus each
    one's saved-params sha (None: trained before models were saved, migration 14) and
    what it was trained on. ``None`` when the ML package is not installed (FR-ML-6): the
    models cannot be read, which is not the same as "this run used none"."""
    from fuzzlab.plugins.optional import import_ml
    registry = import_ml("fuzzlab.ml.model_registry")
    rank_train = import_ml("fuzzlab.ml.rank_train")
    train = import_ml("fuzzlab.ml.train")
    if registry is None or rank_train is None or train is None:
        return None
    params_sha256_for = registry.params_sha256_for
    latest_ranker, latest_classifier = rank_train.latest_ranker, train.latest_classifier
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
    # the run's first target row, through the one reader (CC-UI-0501, PA-0063(1))
    row = run_target(store.conn, run_id)
    target = None if row is None else {k: row[k] for k in ("base_url", "dbms",
                                                           "framework", "waf")}

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
    run_models = _run_models(store, run_id)
    models, model_shas, model_training = run_models if run_models is not None else ([], {}, {})

    # the attached plugins — the ML stages included (FR-ML-6) — with their recorded
    # options and outcome (migration 15; NULL on legacy rows)
    plugins = [dict(r) for r in store.conn.execute(
        "SELECT name, version, priority, config, status, error FROM run_plugin "
        "WHERE run_id=? ORDER BY priority, name", (run_id,))]

    feature_versions = _feature_versions(store, run_id, models, metrics)

    report = {
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
            "plugin_config": {p["name"]: p["config"] for p in plugins},
            "plugin_status": {p["name"]: p["status"] for p in plugins},
            "schema_version": store.schema_version(),
        },
    }
    if run_models is None:
        # never claim "no models" when they merely cannot be read (PA-0064(1))
        from fuzzlab.plugins.optional import ML_UNAVAILABLE
        report["models_unavailable"] = ML_UNAVAILABLE
        report["reproducibility"]["models_unavailable"] = ML_UNAVAILABLE
    return report


def _trained_note(training: dict | None) -> str:
    if not training or training.get("trained_on") not in ("earlier", "saved"):
        return ""
    runs = ", ".join(str(r) for r in training.get("train_run_ids") or [])
    if training["trained_on"] == "saved":
        return f" (saved model #{training.get('source_model_id')}, trained on runs {runs})"
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
             f"{report['reproducibility']['schema_version']}",
             "  feature versions: candidate "
             f"{report['reproducibility']['feature_versions']['candidate'] or '—'}, flow "
             f"{report['reproducibility']['feature_versions']['flow'] or '—'}"]
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
    if report.get("models_unavailable"):
        lines.append(f"  models: unavailable ({report['models_unavailable']})")
    if report["plugins"]:
        lines.append("  plugins: " + ", ".join(
            f"{p['name']} v{p['version']}"
            + (" (FAILED)" if p.get("status") == "failed" else "")
            for p in report["plugins"]))
    if report["findings"]:
        lines.append("  findings:")
        for f in report["findings"]:
            lines.append(f"    - {f['vuln_class']} {f['method']} {f['url']} "
                         f"[{f['param']}] ({f['confidence']})")
    return "\n".join(lines)
