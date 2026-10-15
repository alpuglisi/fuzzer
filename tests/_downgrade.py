"""Undo migrations in tests that build an older store from a fresh one.

A test that deletes ``schema_version`` rows to fake an older store must also undo what
each of those migrations created, or reopening re-runs a migration on a schema that
already has it (``duplicate column``). Each later migration adds its undo here, newest
first, so every downgrade helper stays correct as the schema grows (CC-CORE-0450).
"""

from __future__ import annotations


def undo_after(conn, version: int) -> None:
    """Undo every migration above ``version`` that this module knows, newest first.
    The caller still undoes the older ones it deletes ``schema_version`` rows for."""
    if version < 22:                                 # migration 22: project files
        conn.execute("ALTER TABLE run DROP COLUMN launch_id")
        conn.execute("DROP TABLE IF EXISTS launch")
        conn.execute("DROP TABLE IF EXISTS project")
        conn.execute("PRAGMA application_id = 0")
