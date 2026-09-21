"""The project store: one SQLite database that is the integration bus (D5).

Tools do not call each other; they read and write tables here. This module owns
connection setup (WAL, sensible pragmas, foreign keys) and a thin ``Store``
helper for the handful of operations Phase 0 needs (open a run, store a
content-addressed body). Schema creation lives in ``migrations``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from fuzzlab.core import migrations


def connect(path: str | Path) -> sqlite3.Connection:
    """Open the store with WAL and the pragmas the whole toolkit relies on."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


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
