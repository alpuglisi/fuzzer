"""The project store: one SQLite database that is the integration bus (D5).

Tools do not call each other; they read and write tables here. This module owns
connection setup (WAL, sensible pragmas, foreign keys) and a thin ``Store``
helper for the handful of operations Phase 0 needs (open a run, store a
content-addressed body). Schema creation lives in ``migrations``.
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
    """Open the store connection, the one central place the whole toolkit routes
    through (R-08). Every process *and test* that opens the SQLite file directly
    (rather than via ``Store``) should call this, not ``sqlite3.connect``.

    WAL is right for this multi-process, single-host, local layout: readers
    (UI charts) never block a writer (a running loop). Single-writer still
    holds, so the pragmas below are tuned to keep write locks brief:

    - ``journal_mode=WAL`` — persistent once set; re-asserting on an
      already-WAL store is harmless.
    - ``busy_timeout=10000`` (ms) — let a brief writer-lock contest resolve
      instead of raising immediately. Note this does NOT rescue a
      DEFERRED-transaction upgrade to a write (instant ``SQLITE_BUSY``);
      callers doing read-then-write must use ``BEGIN IMMEDIATE``.
    - ``synchronous=NORMAL`` — WAL-safe; drops a per-commit fsync.
    - ``foreign_keys=ON`` — enforced wherever a migration declares a
      ``REFERENCES``.
    - connect-time ``timeout=10.0`` (seconds) — the driver-level lock-wait
      ceiling backing ``busy_timeout``.
    """
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def connect(path: str | Path) -> sqlite3.Connection:
    """Back-compat alias for :func:`open_store` — same central connection."""
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


# -- cross-run scalar series (B0 / CC-CORE-0018, R-05) -----------------------
#
# One generic sink for per-step scalars from any subsystem (GBT/logistic
# training curves, the bandit loop's posterior/regret, coverage-frontier
# growth, MutationSearch reward/novelty, stage wall-clock/throughput, ...).
# See ``migrations._M0011`` for the schema and the module docstring above for
# the WAL/connection design (R-08). Individual per-component emitters (the
# GBT/logistic, bandit-loop, coverage-frontier, and MutationSearch writers)
# are separate, later lanes — this module only provides the shared write path.

_NON_FINITE_WARNING = (
    "fuzzlab.core.store.log_scalar: dropped non-finite value for "
    "{source}/{key} at step={step} (run_id={run_id})"
)


def log_scalar(
    store: "Store | sqlite3.Connection",
    run_id: int,
    source: str,
    key: str,
    step: int,
    value: float,
    ts: str | None = None,
) -> bool:
    """Write one ``metric_series`` row. Non-finite ``value`` (NaN/inf) is
    rejected: dropped, with a warning, rather than stored (R-05) — there is no
    ``is_nan`` column and no NaN read-branch on the query side. Returns True
    if a row was written, False if the value was dropped.

    Accepts either a :class:`Store` or a raw ``sqlite3.Connection`` (e.g. one
    opened via :func:`open_store`) so per-component emitters that hold their
    own long-lived writer connection (per R-08's "one dedicated connection per
    loop") don't need to go through the full ``Store`` wrapper.
    """
    if not math.isfinite(value):
        warnings.warn(
            _NON_FINITE_WARNING.format(source=source, key=key, step=step, run_id=run_id),
            stacklevel=2,
        )
        return False

    conn = store.conn if isinstance(store, Store) else store
    if ts is None:
        conn.execute(
            "INSERT INTO metric_series (run_id, source, key, step, value) "
            "VALUES (?,?,?,?,?)",
            (run_id, source, key, step, value),
        )
    else:
        conn.execute(
            "INSERT INTO metric_series (run_id, source, key, step, ts, value) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, source, key, step, ts, value),
        )
    conn.commit()
    return True


class MetricLogger:
    """A buffered, batched writer for :func:`log_scalar`, for hot per-step
    loops (GBT rounds, logistic iters, bandit pulls, coverage steps) that
    would otherwise commit once per step. Buffers rows and flushes with a
    single ``executemany`` inside one transaction every ``flush_every`` rows
    (matching R-08's "buffer + executemany in BEGIN IMMEDIATE...COMMIT every
    ~200 rows or ~1s" writer design; the time-based half of that policy is the
    caller loop's job — this class provides the row-count half plus an
    explicit/context-manager flush for "on exit/exception").

    Non-finite values are dropped (with a warning) at ``log`` time, same as
    :func:`log_scalar`, so they never reach the buffer.
    """

    def __init__(
        self,
        store: "Store | sqlite3.Connection",
        run_id: int,
        source: str,
        flush_every: int = 200,
    ) -> None:
        self.conn = store.conn if isinstance(store, Store) else store
        self.run_id = run_id
        self.source = source
        self.flush_every = flush_every
        self._buffer: list[tuple[int, str, str, int, str, float]] = []

    def log(self, key: str, step: int, value: float, ts: str | None = None) -> bool:
        """Buffer one scalar. Returns True if buffered, False if dropped
        (non-finite value)."""
        if not math.isfinite(value):
            warnings.warn(
                _NON_FINITE_WARNING.format(
                    source=self.source, key=key, step=step, run_id=self.run_id
                ),
                stacklevel=2,
            )
            return False
        row_ts = ts if ts is not None else time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        self._buffer.append((self.run_id, self.source, key, step, row_ts, value))
        if len(self._buffer) >= self.flush_every:
            self.flush()
        return True

    def flush(self) -> None:
        """Write and commit any buffered rows now. Never holds the write
        transaction across a compute step — call this, or let it happen via
        ``flush_every``/context-manager exit, rather than batching an entire
        run's worth of rows in memory."""
        if not self._buffer:
            return
        with self.conn:  # BEGIN...COMMIT as one transaction
            self.conn.executemany(
                "INSERT INTO metric_series (run_id, source, key, step, ts, value) "
                "VALUES (?,?,?,?,?,?)",
                self._buffer,
            )
        self._buffer.clear()

    def __enter__(self) -> "MetricLogger":
        return self

    def __exit__(self, *exc: object) -> None:
        # Flush on exit/exception alike (R-08: "flush on exit/exception").
        self.flush()
