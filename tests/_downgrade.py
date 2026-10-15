"""Undo migrations in tests that build an older store from a fresh one.

A test that deletes ``schema_version`` rows to fake an older store must also undo what
each of those migrations created, or reopening re-runs a migration on a schema that
already has it (``duplicate column``). Each later migration adds its undo here, newest
first, so every downgrade helper stays correct as the schema grows (CC-CORE-0450).
"""

from __future__ import annotations


def _undo_endpoint_op_key(conn) -> None:
    """Undo migration 24 (CC-CORE-0060): put back migration 1's ``endpoint`` table and
    index **by their exact original text** (the project allowlist compares definitions
    byte for byte), keeping the rows and their ids, with foreign keys off for it."""
    from fuzzlab.core import migrations
    original = [s for s in migrations.split_statements(migrations._M0001)
                if s.startswith(("CREATE TABLE endpoint ", "CREATE INDEX idx_endpoint_run"))]
    assert len(original) == 2, original
    conn.commit()
    fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("CREATE TABLE endpoint_undo AS SELECT id, run_id, url, method, source "
                     "FROM endpoint")
        conn.execute("DROP TABLE endpoint")
        for stmt in original:
            conn.execute(stmt)
        conn.execute("INSERT INTO endpoint (id, run_id, url, method, source) "
                     "SELECT id, run_id, url, method, source FROM endpoint_undo")
        conn.execute("DROP TABLE endpoint_undo")
        conn.commit()
    finally:
        conn.execute(f"PRAGMA foreign_keys={'ON' if fk else 'OFF'}")


def undo_after(conn, version: int) -> None:
    """Undo every migration above ``version`` that this module knows, newest first.
    The caller still undoes the older ones it deletes ``schema_version`` rows for."""
    if version < 24:                                 # migration 24: endpoint.op_key
        _undo_endpoint_op_key(conn)
    if version == 22:                                # migration 23: project identity
        for col in ("copy_kind", "copied_at", "origin_uuid", "uuid"):
            conn.execute(f"ALTER TABLE project DROP COLUMN {col}")
    if version < 22:                                 # migration 22: project files
        conn.execute("ALTER TABLE run DROP COLUMN launch_id")
        conn.execute("DROP TABLE IF EXISTS launch")
        conn.execute("DROP TABLE IF EXISTS project")
        conn.execute("PRAGMA application_id = 0")
