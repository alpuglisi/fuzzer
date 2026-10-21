"""The one read-only opener of a SQLite file (FR-CORE-508, CC-CORE-0071, BUG-0535).

`core.store.open_read_only` opens an existing file only, with a private cache,
``query_only`` and ``trusted_schema=OFF``; whether a file is SQLite at all is asked of
SQLite (``SQLITE_NOTADB``), never by reading its bytes, because a raw open and close of a
store in a process that holds SQLite connections drops their locks (BUG-0535).
"""

from __future__ import annotations

import ast
import builtins
import os
import sqlite3
from pathlib import Path

import pytest

from fuzzlab.core import project as core_project
from fuzzlab.core.store import Store

REPO = Path(__file__).resolve().parent.parent


def _store(tmp_path) -> Path:
    path = tmp_path / "s.db"
    with Store(path) as s:
        s.start_run("t", "h")
    return path


def test_the_read_only_opener_never_creates_writes_or_migrates(tmp_path):
    from fuzzlab.core.store import open_read_only
    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        open_read_only(missing, timeout=0.05)
    assert not missing.exists()
    path = _store(tmp_path)
    for fold in (False, True):
        conn = open_read_only(path, timeout=0.05, fold_on_close=fold)
        try:
            assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
            assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("INSERT INTO run (tool, config_hash) VALUES ('w', 'h')")
        finally:
            conn.close()
    old = tmp_path / "old.db"                          # an older-schema store is not migrated
    plain = sqlite3.connect(old)
    plain.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    plain.execute("INSERT INTO schema_version VALUES (1)")
    plain.commit()
    plain.close()
    conn = open_read_only(old, timeout=0.05, fold_on_close=True)
    conn.execute("SELECT * FROM schema_version").fetchall()
    conn.close()
    plain = sqlite3.connect(old)
    assert plain.execute("SELECT version FROM schema_version").fetchall() == [(1,)]
    assert plain.execute("PRAGMA journal_mode").fetchone()[0] == "delete"   # never set WAL
    plain.close()


def test_the_read_only_opener_pins_a_private_cache(tmp_path):
    """Measured (C9): in shared-cache mode a read meets a same-process writer's table lock
    at once (SQLITE_LOCKED_SHAREDCACHE, no busy wait); a private cache reads."""
    from fuzzlab.core.store import open_read_only
    path = _store(tmp_path)
    shared = sqlite3.connect(path.resolve().as_uri() + "?mode=rw&cache=shared", uri=True,
                             isolation_level=None)
    try:
        shared.execute("BEGIN IMMEDIATE")
        shared.execute("INSERT INTO run (tool, config_hash) VALUES ('w', 'h')")
        reader = open_read_only(path, timeout=0.05)
        try:
            assert reader.execute("SELECT count(*) FROM run").fetchone()[0] == 1
        finally:
            reader.close()
        shared.execute("ROLLBACK")
    finally:
        shared.close()


@pytest.fixture
def no_raw_open(monkeypatch):
    """Fail any open of ``watched`` paths outside SQLite (builtins.open, os.open)."""
    watched: set[str] = set()
    real_open, real_os_open = builtins.open, os.open

    def _check(p):
        try:
            name = os.fspath(p)
        except TypeError:
            return
        if isinstance(name, bytes):
            name = name.decode()
        if os.path.abspath(name) in watched:
            raise AssertionError(f"a raw open of {name}")

    def guarded_open(file, *a, **kw):
        _check(file)
        return real_open(file, *a, **kw)

    def guarded_os_open(path, *a, **kw):
        _check(path)
        return real_os_open(path, *a, **kw)
    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    return watched


def test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw(tmp_path, no_raw_open):
    """`inspect` and `summary` refuse a non-SQLite file, and read a store, with no raw
    open of the file or its side files (BUG-0535: the Projects listing's magic read)."""
    junk = tmp_path / "junk.fuzzlab"
    junk.write_bytes(b'{"not": "sqlite"}' * 50)
    path = _store(tmp_path)
    no_raw_open |= {os.path.abspath(str(p) + s) for p in (junk, path)
                    for s in ("", "-wal", "-shm", "-journal")}
    with pytest.raises(core_project.ProjectError, match="is not an SQLite database"):
        core_project.inspect(junk)
    core_project._SUMMARY_CACHE.clear()
    assert core_project.summary(junk) == {"readable": False}
    assert core_project.inspect(path).state == "ok"
    assert core_project.summary(path)["readable"] is True
    assert not [s for s in ("-wal", "-shm", "-journal") if os.path.exists(str(junk) + s)]


#: A SQLite URI's open mode: built in `core/store.py` only.
_MODE = ("mode=ro", "mode=rw", "query_only")


def read_only_opens(src: str) -> list[str]:
    """Functions that build a SQLite open mode themselves (a string constant naming one)."""
    out = []

    def visit(node, where):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(ch, f"{where}.{ch.name}" if where else ch.name)
                continue
            if isinstance(ch, ast.Constant) and isinstance(ch.value, str) \
                    and any(m in ch.value for m in _MODE):
                out.append(where or "<module>")
            visit(ch, where)

    visit(ast.parse(src), "")
    return out


def test_every_read_only_open_goes_through_the_opener():
    """FR-CORE-508: no module but `core/store.py` builds a read-only SQLite open
    (`mode=ro`, `mode=rw`, `query_only`); each goes through `open_read_only`."""
    offenders = []
    for path in sorted((REPO / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if rel == "fuzzlab/core/store.py":
            continue
        offenders += [f"{rel}::{f}" for f in read_only_opens(path.read_text("utf-8"))]
    assert offenders == []


def test_the_read_only_open_guard_catches_synthetic_offenders():
    src = ('def a(p):\n    return sqlite3.connect(p.as_uri() + "?mode=ro", uri=True)\n'
           'def b(p):\n    c = sqlite3.connect(f"file:{p}?mode=rw", uri=True)\n'
           'def c(conn):\n    conn.execute("PRAGMA query_only=1")\n'
           'def near_miss(p):\n    return sqlite3.connect(p)  # a mode-less open\n')
    assert read_only_opens(src) == ["a", "b", "c"]
