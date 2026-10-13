"""Migrations are atomic and safe when two processes open a fresh store at once
(BUG-0087, FR-CORE-24, PA-0088).

`migrate` used `executescript` inside `with conn:`. But `executescript` commits first and
runs in autocommit, so a failing migration left its earlier statements applied with no
version row (its rerun then failed), and two first opens raced (13 of 20 runs failed).
"""

from __future__ import annotations

import multiprocessing as mp
import sqlite3

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store, open_store


def _schema(conn) -> list[tuple]:
    return sorted((r[0], r[1], r[2]) for r in conn.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))


def test_a_failing_migration_leaves_nothing_behind(tmp_path, monkeypatch):
    conn = open_store(tmp_path / "a.db")
    monkeypatch.setattr(migrations, "MIGRATIONS",
                        [(1, "CREATE TABLE a(x); CREATE TABLE b(y); SELECT no_such_fn();")])
    with pytest.raises(sqlite3.OperationalError):
        migrations.migrate(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == {"schema_version"} and migrations.current_version(conn) == 0
    monkeypatch.setattr(migrations, "MIGRATIONS",
                        [(1, "CREATE TABLE a(x); CREATE TABLE b(y);")])
    assert migrations.migrate(conn) == 1                     # the fixed migration applies
    assert conn.isolation_level == ""                        # restored


def test_the_split_keeps_trigger_bodies_and_final_statements_whole():
    script = ("CREATE TABLE t(x); -- a comment; with a semicolon\n"
              "CREATE TRIGGER tr AFTER INSERT ON t BEGIN\n  INSERT INTO t VALUES (1);\nEND;\n"
              "INSERT INTO t VALUES ('a;b');\nCREATE INDEX i ON t(x)")
    parts = migrations.split_statements(script)
    assert len(parts) == 4
    assert parts[1].startswith("-- a comment") or "TRIGGER" in parts[1]
    assert parts[-1] == "CREATE INDEX i ON t(x)"


def test_the_schema_equals_the_reference_build(tmp_path):
    """Statement-by-statement application builds exactly what the scripts declare."""
    with Store(tmp_path / "new.db") as store:
        built = _schema(store.conn)
    ref = sqlite3.connect(tmp_path / "ref.db")
    ref.executescript("CREATE TABLE schema_version (  version INTEGER PRIMARY KEY,"
                      "  applied_at TEXT NOT NULL DEFAULT (datetime('now')))")
    for _v, sql in sorted(migrations.MIGRATIONS):
        ref.executescript(sql)
    assert built == _schema(ref)


def _open(path, barrier, q):
    barrier.wait()
    try:
        Store(path).close()
        q.put("ok")
    except Exception as exc:                     # noqa: BLE001 - reported to the parent
        q.put(f"{type(exc).__name__}: {exc}")


def test_concurrent_first_opens_never_fail(tmp_path):
    ctx = mp.get_context("spawn")
    failures = []
    for i in range(10):
        path = str(tmp_path / f"race{i}.db")
        barrier, q = ctx.Barrier(4), ctx.Queue()
        procs = [ctx.Process(target=_open, args=(path, barrier, q)) for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
        failures += [r for r in (q.get(timeout=10) for _ in procs) if r != "ok"]
        with Store(path) as store:
            assert migrations.current_version(store.conn) == max(
                v for v, _ in migrations.MIGRATIONS)
    assert failures == []
