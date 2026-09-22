"""The project store: one SQLite database that is the integration bus (D5).

Tools do not call each other; they read and write tables here. This module owns
connection setup (WAL, sensible pragmas, foreign keys) and a thin ``Store``
helper for the handful of operations Phase 0 needs (open a run, store a
content-addressed body). Schema creation lives in ``migrations``.

``open_store()`` is the CENTRAL connection helper every process and test should
route through (B0 / R-08): it pins WAL + the busy-timeout/synchronous/foreign-key
pragmas the whole toolkit relies on for safe multi-writer, single-host,
local-disk concurrency (metric-series writers, the UI reader, labgen, …). Setting
``journal_mode=WAL`` on an already-WAL store is a harmless no-op, so calling it
repeatedly (once per connection) is always safe. ``connect()`` is kept as a thin
alias for existing call sites.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
import warnings
from pathlib import Path
from typing import Any

from fuzzlab.core import migrations


def open_store(path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection with the pragmas every writer/reader must share.

    - ``journal_mode=WAL`` (persistent on the database file; re-asserting it on an
      already-WAL store is a harmless no-op) so readers never block writers.
    - ``busy_timeout=10000`` (ms) so a brief writer/writer contention retries
      instead of raising ``SQLITE_BUSY`` immediately.
    - ``synchronous=NORMAL`` (safe under WAL; drops the per-commit fsync).
    - ``foreign_keys=ON`` (the store uses FK constraints throughout).
    - ``sqlite3.connect(path, timeout=10.0)`` — the driver's own busy retry window,
      matched to the pragma above.

    Callers doing a read-then-write on this connection must still use
    ``BEGIN IMMEDIATE`` for that transaction; ``busy_timeout`` alone does not
    rescue a DEFERRED-to-write upgrade (that is an instant ``SQLITE_BUSY``).
    """
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def connect(path: str | Path) -> sqlite3.Connection:
    """Open the store with WAL and the pragmas the whole toolkit relies on.

    Thin alias for :func:`open_store` kept for existing call sites/tests.
    """
    return open_store(path)


class Store:
    """A small, dependency-light wrapper over a migrated SQLite connection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.conn = connect(self.path)
        migrations.migrate(self.conn)

    # -- runs -------------------------------------------------------------
    def start_run(self, tool: str, config_hash: str, env_profile: str | None = None,
                  notes: str | None = None) -> int:
        """Record a run and return its id. Every result row references a run."""
        cur = self.conn.execute(
            "INSERT INTO run (tool, config_hash, env_profile, notes) VALUES (?,?,?,?)",
            (tool, config_hash, env_profile, notes),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    # -- content-addressed bodies ----------------------------------------
    def put_body(self, data: bytes) -> str:
        """Store a response/request body once, keyed by sha256. Returns the hash."""
        digest = hashlib.sha256(data).hexdigest()
        self.conn.execute(
            "INSERT OR IGNORE INTO body (sha256, length, data) VALUES (?,?,?)",
            (digest, len(data), data),
        )
        self.conn.commit()
        return digest

    def get_body(self, digest: str) -> bytes | None:
        row = self.conn.execute(
            "SELECT data FROM body WHERE sha256=?", (digest,)
        ).fetchone()
        return bytes(row["data"]) if row else None

    # -- session state (NON-SECRET only; never cookies/tokens/creds) ------
    def upsert_session_state(self, state: dict[str, Any]) -> None:
        """Persist one identity's non-secret session metadata (upsert by host+identity)."""
        self.conn.execute(
            "INSERT INTO session_state (host, identity, kind, valid, login_url, "
            "logout_url, token_exp, updated_at) VALUES (?,?,?,?,?,?,?, datetime('now')) "
            "ON CONFLICT(host, identity) DO UPDATE SET "
            "kind=excluded.kind, valid=excluded.valid, login_url=excluded.login_url, "
            "logout_url=excluded.logout_url, token_exp=excluded.token_exp, "
            "updated_at=excluded.updated_at",
            (state.get("host"), state.get("identity"), state.get("kind"),
             int(bool(state.get("valid"))), state.get("login_url"),
             state.get("logout_url"), state.get("token_exp")),
        )
        self.conn.commit()

    def get_session_state(self, host: str, identity: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT host, identity, kind, valid, login_url, logout_url, token_exp, "
            "updated_at FROM session_state WHERE host=? AND identity=?",
            (host, identity),
        ).fetchone()
        return dict(row) if row else None

    def all_session_states(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT host, identity, kind, valid, login_url, logout_url, token_exp, "
            "updated_at FROM session_state ORDER BY host, identity"
        ).fetchall()
        return [dict(r) for r in rows]

    # -- misc -------------------------------------------------------------
    def schema_version(self) -> int:
        return migrations.current_version(self.conn)

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        self.conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# -- metric_series (B0): per-step time-series metrics -------------------------
#
# One row per (run, source, key, step). Values must be finite: a non-finite value
# (NaN/inf) is dropped and warned about at emit time rather than stored — there is
# deliberately no ``is_nan`` column and no NaN read-branch anywhere downstream.
# ``key`` is a bounded, slash-delimited path (e.g. ``train/loss``,
# ``posterior/arm_3/mean``); never a per-example/per-feature key or free text.


def _conn_of(store: Any) -> sqlite3.Connection:
    """Accept either a :class:`Store` or a raw ``sqlite3.Connection``."""
    return store.conn if hasattr(store, "conn") else store


def log_scalar(store: Any, run_id: int, source: str, key: str, step: int,
               value: float, ts: float | None = None) -> bool:
    """Validate and insert one ``metric_series`` point.

    Non-finite ``value`` (NaN/inf) is dropped (not stored) and a warning is
    emitted; returns ``True`` if the point was written, ``False`` if dropped.
    This is the single write path every emitter (loop or ``MetricLogger``) goes
    through, per PA-0003 (one shared function for a cross-writer convention).
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        warnings.warn(
            f"log_scalar: non-numeric value for {source}/{key} step={step} "
            f"dropped: {value!r}", stacklevel=2)
        return False
    if not math.isfinite(v):
        warnings.warn(
            f"log_scalar: non-finite value for {source}/{key} step={step} "
            f"dropped: {v!r}", stacklevel=2)
        return False
    conn = _conn_of(store)
    conn.execute(
        "INSERT INTO metric_series (run_id, source, key, step, ts, value) "
        "VALUES (?,?,?,?,?,?)",
        (run_id, source, key, int(step), float(ts if ts is not None else time.time()), v),
    )
    conn.commit()
    return True


class MetricLogger:
    """Buffered ``metric_series`` writer for hot loops (GBT rounds, logistic
    epochs, bandit pulls, coverage steps, mutation-search steps, …).

    Buffers ``log`` calls and flushes them via ``executemany`` inside a single
    ``BEGIN IMMEDIATE ... COMMIT`` transaction every ``flush_every`` rows or
    ``flush_interval`` seconds (whichever comes first), so the write lock is
    never held across a compute step. Always flushes on ``__exit__``, including
    when the ``with`` block raises. Non-finite values are dropped (+ warned) at
    ``log()`` time, same as :func:`log_scalar`, so nothing non-finite is ever
    buffered.
    """

    def __init__(self, store: Any, run_id: int, source: str, *,
                 flush_every: int = 200, flush_interval: float = 1.0):
        self._conn = _conn_of(store)
        self.run_id = run_id
        self.source = source
        self.flush_every = flush_every
        self.flush_interval = flush_interval
        self._buf: list[tuple[int, str, str, int, float, float]] = []
        self._last_flush = time.monotonic()

    def log(self, key: str, step: int, value: float, ts: float | None = None) -> None:
        try:
            v = float(value)
        except (TypeError, ValueError):
            warnings.warn(
                f"MetricLogger: non-numeric value for {self.source}/{key} "
                f"step={step} dropped: {value!r}", stacklevel=2)
            return
        if not math.isfinite(v):
            warnings.warn(
                f"MetricLogger: non-finite value for {self.source}/{key} "
                f"step={step} dropped: {v!r}", stacklevel=2)
            return
        self._buf.append((self.run_id, self.source, key, int(step),
                          float(ts if ts is not None else time.time()), v))
        due = (len(self._buf) >= self.flush_every
              or (time.monotonic() - self._last_flush) >= self.flush_interval)
        if due:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            self._last_flush = time.monotonic()
            return
        rows, self._buf = self._buf, []
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.executemany(
                "INSERT INTO metric_series (run_id, source, key, step, ts, value) "
                "VALUES (?,?,?,?,?,?)", rows)
        except Exception:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()
        self._last_flush = time.monotonic()

    def __enter__(self) -> "MetricLogger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.flush()
