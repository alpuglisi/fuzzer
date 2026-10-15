"""A run's recorded target -- the one reader of the ``target`` table (CC-CORE-0500).

The pipeline records where a run sent its traffic as a ``target`` row
(``harness/pipeline.py``; at most one per run today, since a run calls the pipeline
once). "A run's target" is its **first** target row by id, and "its origin" is that
row's ``base_url`` canonicalised by `core.urls.canonical_origin` -- so ``localhost``
and ``127.0.0.1`` on one port are one origin. A run with no target row (crawler,
auditor, fuzzer, proxy runs) has no recorded target: nothing is inferred from
``run.config_hash`` or a hostname (PA-0075).

Row selection is a convention (PA-0063(1)), so it lives here once and every reader
goes through it; `tests/test_core_runtarget.py` fails on any other ``FROM target`` /
``JOIN target`` in ``fuzzlab/`` (the shipped migration post-step that predates this
module is allowlisted, with its reason).
"""

from __future__ import annotations

import sqlite3
from typing import Iterable

from fuzzlab.core.urls import canonical_origin

#: The columns a target row carries, in the order every reader receives them.
TARGET_COLUMNS = ("id", "run_id", "base_url", "dbms", "framework", "waf", "fingerprint")


def run_target_rows(conn: sqlite3.Connection,
                    run_ids: Iterable[int] | None = None) -> dict[int, dict]:
    """``{run_id: first target row (as a dict)}`` for every run that has one, or only
    for ``run_ids`` when given. Runs without a target row are absent."""
    wanted = None if run_ids is None else {int(r) for r in run_ids}
    out: dict[int, dict] = {}
    for r in conn.execute(
            f"SELECT {', '.join(TARGET_COLUMNS)} FROM target "
            "WHERE run_id IS NOT NULL ORDER BY id").fetchall():
        rid = int(r[1])
        if wanted is not None and rid not in wanted:
            continue
        out.setdefault(rid, dict(zip(TARGET_COLUMNS, tuple(r))))
    return out


def run_target(conn: sqlite3.Connection, run_id: int | None) -> dict | None:
    """The run's first target row as a dict, or ``None`` (no run id, or no row)."""
    if run_id is None:
        return None
    row = conn.execute(
        f"SELECT {', '.join(TARGET_COLUMNS)} FROM target WHERE run_id=? "
        "ORDER BY id LIMIT 1", (int(run_id),)).fetchone()
    return dict(zip(TARGET_COLUMNS, tuple(row))) if row else None


def origin_of(base_url) -> str | None:
    """A stored ``base_url``'s canonical origin, or ``None`` -- total (BUG-0500):
    `canonical_origin` documents ``None`` for an unusable URL but raises ``ValueError``
    on a malformed authority (``http://[::1``, an NFKC-invalid host), so one bad stored
    row used to take every origin reader down. Its own fix is in `core/urls.py`."""
    if not isinstance(base_url, str):
        return None
    try:
        return canonical_origin(base_url)
    except ValueError:                   # urlsplit's malformed-authority errors only
        return None


def run_origins(conn: sqlite3.Connection) -> dict[int, str | None]:
    """``{run_id: canonical origin of its first target row}`` -- ``None`` when that
    row's ``base_url`` has no usable host or port, or is malformed (`origin_of`). Runs
    without a target row are absent."""
    return {rid: origin_of(row["base_url"]) for rid, row in run_target_rows(conn).items()}
