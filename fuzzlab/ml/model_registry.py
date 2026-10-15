"""The one reader of the shared `model` table (CC-ML-0011, BUG-0061, PA-0063).

Two model families write rows to `model` with no family column: the detection classifier
(`train.py`: `logistic` / `gbt` / `prevalence-fallback`) and the candidate ranker
(`rank_train.py`: `ranker` / `rank-prevalence-fallback`). "Which row is the deployed model
of a family for a run" is therefore a convention every reader must apply identically, so
it lives here, in exactly one function (PA-0003/PA-0021) — never as an inline
"newest row" query at a read site.

Scope: a trainer records the `run_id` it trained on in the row's `calibration` JSON
(null for a store-wide train, which re-scores every run's candidates present at the
time). A row covers a run when its `run_id` equals it; a store-wide row (null) covers the
runs it recorded in `scored_run_ids` — never a later run it never scored (BUG-0074,
PA-0075). A store-wide row without that list, or a legacy row with no `run_id` key (its
scope is unknowable), covers a run only when that run holds a stored score in the
family's column — a provenance claim backed by a recorded fact about the run.
"""

from __future__ import annotations

import json
from typing import Sequence

_ABSENT = object()


#: The candidate column each family writes its advisory score to (`select_latest`'s
#: ``score_column``): a legacy store-wide row covers only runs with a value there.
SCORE_COLUMNS = ("score", "rank_score")


def _has_scores(store, run_id: int, score_column: str) -> bool:
    if score_column not in SCORE_COLUMNS:
        raise ValueError(f"score_column must be one of {SCORE_COLUMNS}, got {score_column!r}")
    return store.conn.execute(
        f"SELECT 1 FROM candidate WHERE run_id=? AND {score_column} IS NOT NULL LIMIT 1",
        (run_id,)).fetchone() is not None


def _covers(store, calibration: dict, run_id: int | None, score_column: str) -> bool:
    if run_id is None:
        return True
    scope = calibration.get("run_id", _ABSENT)
    if scope is not _ABSENT and scope is not None:
        return scope == run_id
    scored = calibration.get("scored_run_ids")
    if isinstance(scored, list):
        return run_id in scored
    return _has_scores(store, run_id, score_column)       # legacy: back it with a fact


def params_for(store, model_id: int) -> tuple[str, str] | None:
    """The saved model of one `model` row as ``(params_text, params_sha256)``, or
    ``None`` for a row trained before models were saved (migration 14). Fetched by id
    on its own so `select_latest`'s scan never pulls every row's params."""
    row = store.conn.execute(
        "SELECT params, params_sha256 FROM model WHERE id=?", (model_id,)).fetchone()
    if row is None or row["params"] is None:
        return None
    return row["params"], row["params_sha256"]


def params_sha256_for(store, model_id: int) -> str | None:
    row = store.conn.execute(
        "SELECT params_sha256 FROM model WHERE id=?", (model_id,)).fetchone()
    return row["params_sha256"] if row else None


def select_latest(store, names: Sequence[str], run_id: int | None = None, *,
                  score_column: str):
    """The newest `model` row named in ``names`` whose scope covers ``run_id``.
    ``score_column`` is the family's candidate score column (`SCORE_COLUMNS`), required
    so no caller can omit the fact a legacy store-wide row's coverage rests on.

    Returns ``(row, calibration)`` — the row (`id, name, version, feature_version,
    calibration`) and its parsed calibration (``{}`` when absent or malformed) — or
    ``None`` when no row of the family covers the run.
    """
    if score_column not in SCORE_COLUMNS:
        raise ValueError(f"score_column must be one of {SCORE_COLUMNS}, got {score_column!r}")
    names = list(names)
    if not names:
        return None
    marks = ",".join("?" * len(names))
    rows = store.conn.execute(
        f"SELECT id, name, version, feature_version, calibration FROM model "
        f"WHERE name IN ({marks}) ORDER BY id DESC", names).fetchall()
    for row in rows:
        try:
            calibration = json.loads(row["calibration"] or "{}")
        except (ValueError, TypeError):
            calibration = {}
        if not isinstance(calibration, dict):
            calibration = {}
        if _covers(store, calibration, run_id, score_column):
            return row, calibration
    return None


def _int_scope(calibration: dict) -> int | None:
    scope = calibration.get("run_id")
    return scope if isinstance(scope, int) and not isinstance(scope, bool) else None


def _row(store, model_id: int, names: Sequence[str]):
    marks = ",".join("?" * len(names))
    row = store.conn.execute(
        f"SELECT id, name, version, feature_version, calibration, params IS NOT NULL AS has "
        f"FROM model WHERE name IN ({marks}) AND id=?", [*names, model_id]).fetchone()
    if row is None:
        return None, {}
    try:
        calibration = json.loads(row["calibration"] or "{}")
    except (ValueError, TypeError):
        calibration = {}
    return row, (calibration if isinstance(calibration, dict) else {})


def saved_source(store, names: Sequence[str], run_id: int, earlier_runs, *,
                 model_id: int | None = None):
    """The saved model to score ``run_id`` with, without retraining (FR-ML-15).

    Returns ``(row, calibration, None)`` for the ORIGINAL trained row, or
    ``(None, None, reason)``. A row qualifies only if it has saved params and its scope
    (``calibration["run_id"]``) is an ``int`` in ``earlier_runs`` (earlier runs against
    this run's target) — so it never read this run's labels: every model-writing mode
    trains only on runs at or below its scope (the FR-ML-15 invariant). Store-wide
    (``None``), legacy (absent) and non-int scopes never qualify. Copies written by
    saved mode itself (``trained_on == "saved"``) are never chosen; a pinned copy
    resolves through ``source_model_id`` to its original. Newest = highest scope run,
    then highest id.
    """
    earlier = set(earlier_runs)
    names = list(names)

    def qualifies(row, calibration) -> str | None:
        if row is None:
            return "no saved model with that id in this model family"
        if not row["has"]:
            return f"model #{row['id']} has no saved params (trained before migration 14)"
        scope = _int_scope(calibration)
        if scope is None:
            return f"model #{row['id']} is not scoped to a single earlier run"
        if scope not in earlier:
            return (f"model #{row['id']} was trained for run {scope}, not an earlier run "
                    "against this target")
        return None

    if model_id is not None:
        row, calibration = _row(store, model_id, names)
        seen: set[int] = set()
        while row is not None and calibration.get("trained_on") == "saved":
            src = calibration.get("source_model_id")
            if not isinstance(src, int) or src in seen:
                return None, None, f"model #{model_id} is a copy with no usable source"
            seen.add(src)
            row, calibration = _row(store, src, names)
        reason = qualifies(row, calibration)
        return (row, calibration, None) if reason is None else (None, None, reason)

    if not names:
        return None, None, "no model family"
    marks = ",".join("?" * len(names))
    best = None
    for r in store.conn.execute(
            f"SELECT id FROM model WHERE name IN ({marks}) AND params IS NOT NULL",
            names).fetchall():
        row, calibration = _row(store, r["id"], names)
        if calibration.get("trained_on") == "saved" or qualifies(row, calibration):
            continue
        key = (_int_scope(calibration), row["id"])
        if best is None or key > best[0]:
            best = (key, row, calibration)
    if best is None:
        return None, None, "no saved model from an earlier run against this target"
    return best[1], best[2], None


#: The `calibration` keys `list_models` may read — label-free provenance only. Everything
#: else in that JSON (metrics, thresholds, `holdout.*` whose `rows` equals a sealed number)
#: is never read for a listing (FR-ML-400, PA-0092).
LISTING_KEYS = ("trained_on", "run_id", "source_model_id", "scored_run_ids")


def list_models(store) -> list[dict]:
    """Every saved model row, oldest first, with label-free facts only (`fuzzlab train
    models`). A listing, not a selection: it never picks a "current" row (that is
    `select_latest`'s job). A calibration that does not parse is reported as unreadable,
    never filled with defaults (PA-0108)."""
    out: list[dict] = []
    for row in store.conn.execute(
            "SELECT id, name, version, feature_version, created_at, calibration, "
            "params IS NOT NULL AS has_params FROM model ORDER BY id ASC").fetchall():
        item = {"id": int(row["id"]), "name": row["name"], "version": int(row["version"]),
                "feature_version": row["feature_version"], "created_at": row["created_at"],
                "has_params": bool(row["has_params"]), "unreadable": False,
                "trained_on": None, "scope": "unknown", "source_model_id": None,
                "scored_runs": None}
        try:
            calibration = json.loads(row["calibration"] or "{}")
        except (ValueError, TypeError):
            calibration = None
        if not isinstance(calibration, dict):
            item["unreadable"] = True
            out.append(item)
            continue
        picked = {k: calibration[k] for k in LISTING_KEYS if k in calibration}
        trained_on = picked.get("trained_on")
        item["trained_on"] = trained_on if isinstance(trained_on, str) else None
        if "run_id" in picked:
            scope = _int_scope(picked)
            item["scope"] = "all runs" if picked["run_id"] is None else (
                f"run {scope}" if scope is not None else "unknown")
        source = picked.get("source_model_id")
        item["source_model_id"] = source if isinstance(source, int) and \
            not isinstance(source, bool) else None
        scored = picked.get("scored_run_ids")
        item["scored_runs"] = len(scored) if isinstance(scored, list) else None
        out.append(item)
    return out
