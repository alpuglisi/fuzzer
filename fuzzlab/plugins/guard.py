"""Advisory write guard for the plugin hooks that receive the store (FR-PLUG-6).

`after_run` plugins and a contributed budget prioritizer get the live `Store`, so the
oracle/advisory split (FR-PLUG-5) can no longer rest on "observation returns are
ignored". While they run, an **allowlist** SQLite authorizer is installed on the shared
connection:

- **read-only** (a prioritizer): reads, functions, transactions/savepoints only;
- **advisory** (`after_run`): the same, plus exactly the writes in `ADVISORY_WRITES` —
  INSERT into the advisory output tables and UPDATE of the advisory `candidate`
  columns. Everything else is denied: any write to `finding`, to label-defining
  `candidate` state (`oracle_status`, `evidence`, `run_id`, inserting or deleting
  candidates), every CREATE/DROP/ALTER (closes rename round-trips, persistent triggers,
  temp shadow tables), ATTACH/DETACH, and PRAGMA assignment.

Scope, stated honestly: this prevents *accidental* label writes through the shared
connection. It is not a trust boundary — an in-process plugin can open its own
connection or unset the authorizer (PLUG §8). It checks tables and columns, not rows: a
plugin may still overwrite another run's advisory scores. DDL is denied even as
``CREATE … IF NOT EXISTS``, so `Store.schema_version()` cannot be called inside a guarded
hook.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

#: The only writes an `after_run` plugin may make (one declaration, PA-0003). The
#: built-in ML stages' measured footprint is exactly this (CC-ML-0017).
ADVISORY_WRITES: dict[str, frozenset] = {
    "insert": frozenset({"model", "run_metrics", "metric_series",
                         "holdout_metric"}),                     # CC-PLUG-0007
    "update_candidate": frozenset({"score", "rank_score", "rank_uncertainty",
                                   "anomaly_score", "anomaly_flag",
                                   "score_oof", "rank_score_oof"}),     # CC-PLUG-0006
}

READ_ONLY = "read-only"
ADVISORY = "advisory"

_READ_ACTIONS = frozenset({sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                           sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE,
                           sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT})


def authorizer(mode: str):
    """The SQLite authorizer callback for ``mode`` (`READ_ONLY` or `ADVISORY`)."""
    if mode not in (READ_ONLY, ADVISORY):
        raise ValueError(f"unknown guard mode {mode!r}")
    advisory = mode == ADVISORY

    def check(action, arg1, arg2, db_name, _source):
        if action in _READ_ACTIONS:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and arg2 is None:
            return sqlite3.SQLITE_OK                      # reading a pragma
        if advisory and db_name == "main":
            if action == sqlite3.SQLITE_INSERT and arg1 in ADVISORY_WRITES["insert"]:
                return sqlite3.SQLITE_OK
            if (action == sqlite3.SQLITE_UPDATE and arg1 == "candidate"
                    and arg2 in ADVISORY_WRITES["update_candidate"]):
                return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return check


@contextmanager
def guarded(conn: sqlite3.Connection, mode: str):
    """Install the ``mode`` authorizer on ``conn`` for the block; always removed."""
    conn.set_authorizer(authorizer(mode))
    try:
        yield
    finally:
        conn.set_authorizer(None)
