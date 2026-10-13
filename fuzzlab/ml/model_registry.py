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
