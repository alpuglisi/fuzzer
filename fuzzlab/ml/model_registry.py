"""The one reader of the shared `model` table (CC-ML-0011, BUG-0061, PA-0063).

Two model families write rows to `model` with no family column: the detection classifier
(`train.py`: `logistic` / `gbt` / `prevalence-fallback`) and the candidate ranker
(`rank_train.py`: `ranker` / `rank-prevalence-fallback`). "Which row is the deployed model
of a family for a run" is therefore a convention every reader must apply identically, so
it lives here, in exactly one function (PA-0003/PA-0021) — never as an inline
"newest row" query at a read site.

Scope: a trainer records the `run_id` it trained on in the row's `calibration` JSON
(null for a store-wide train, which re-scores every run's candidates). A row covers a run
when its `run_id` equals it, is null, or is absent (a legacy row written before the key
existed — its scope is unknowable, so the old "newest row" behavior is kept).
"""

from __future__ import annotations

import json
from typing import Sequence

_ABSENT = object()


def _covers(calibration: dict, run_id: int | None) -> bool:
    if run_id is None:
        return True
    scope = calibration.get("run_id", _ABSENT)
    return scope is _ABSENT or scope is None or scope == run_id


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


def select_latest(store, names: Sequence[str], run_id: int | None = None):
    """The newest `model` row named in ``names`` whose scope covers ``run_id``.

    Returns ``(row, calibration)`` — the row (`id, name, version, feature_version,
    calibration`) and its parsed calibration (``{}`` when absent or malformed) — or
    ``None`` when no row of the family covers the run.
    """
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
        if _covers(calibration, run_id):
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
