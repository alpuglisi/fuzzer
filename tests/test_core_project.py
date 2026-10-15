"""Project files at the store level (CC-CORE-0450; FR-CORE-450..452): migration 22,
project metadata, launch provenance, typed inspection, the backup-API copy, the
migration offer, the record-boundary redactor, and BUG-0450 (CC-FUZZ-0450)."""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
import stat
import threading
import time

import pytest

from fuzzlab.core import migrations, project
from fuzzlab.core.project import ProjectError
from fuzzlab.core.redaction import PLACEHOLDER, redact_for_record
from fuzzlab.core.store import LAUNCH_TOKEN_ENV, Store, is_aborted
from tests._downgrade import undo_after

HEAD = migrations.head_version()


def _v21(path):
    """A store as the build before migration 22 left it."""
    with Store(path) as store:
        store.start_run("auto", "h")
        undo_after(store.conn, 21)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 22")
        store.conn.commit()


# --- migration 22 ---------------------------------------------------------------------

def test_migration_22_adds_project_tables_and_marks_the_file(tmp_path):
    with Store(tmp_path / "s.db") as store:
        assert store.schema_version() == HEAD >= 22
        tables = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"project", "launch"} <= tables
        assert "launch_id" in {r[1] for r in store.conn.execute("PRAGMA table_info(run)")}
        assert store.conn.execute("PRAGMA application_id").fetchone()[0] == \
            migrations.APPLICATION_ID
        # the migration never writes the metadata row (the UI's first open does)
        assert store.conn.execute("SELECT COUNT(*) FROM project").fetchone()[0] == 0


def test_a_legacy_store_upgrades_and_keeps_its_runs(tmp_path):
    path = tmp_path / "old.db"
    _v21(path)
    assert project.inspect(path).state == "older"
    with Store(path) as store:
        assert store.schema_version() == HEAD
        row = store.conn.execute("SELECT tool, launch_id FROM run").fetchone()
        assert row["tool"] == "auto" and row["launch_id"] is None


def test_migration_22_is_atomic_under_an_injected_failure(tmp_path, monkeypatch):
    """PA-0088(1): a failure inside migration 22 leaves the store at v21, unmarked."""
    path = tmp_path / "old.db"
    _v21(path)

    def boom(conn):
        raise RuntimeError("injected")
    monkeypatch.setitem(migrations.POST_STEPS, 22, boom)
    with pytest.raises(RuntimeError, match="injected"):
        Store(path)
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 21
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name IN "
                        "('project','launch')").fetchone()[0] == 0
    assert conn.execute("PRAGMA application_id").fetchone()[0] == 0
    conn.close()


def test_a_newer_store_is_refused_before_any_write_and_the_handle_is_closed(tmp_path,
                                                                           monkeypatch):
    path = tmp_path / "new.db"
    Store(path).close()
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (HEAD + 5,))
    conn.commit()
    conn.close()
    before = path.read_bytes()
    closed = []
    real_close = sqlite3.Connection.close

    class Tracking(sqlite3.Connection):
        def close(self):
            closed.append(True)
            real_close(self)
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect",
                        lambda *a, **k: real_connect(*a, factory=Tracking, **k))
    with pytest.raises(migrations.SchemaTooNew) as err:
        Store(path)
    assert err.value.found == HEAD + 5 and err.value.head == HEAD
    assert closed == [True]                       # never leaks the connection
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert project.inspect(path).state == "newer"


# --- metadata -----------------------------------------------------------------------

def test_first_open_creates_metadata_from_the_stores_real_creation_time(tmp_path):
    path = tmp_path / "legacy.db"
    _v21(path)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE schema_version SET applied_at='2026-01-02 03:04:05' WHERE version=1")
    conn.commit()
    conn.close()
    with Store(path) as store:
        meta = project.ensure_metadata(store, "legacy")
        assert meta["name"] == "legacy"
        assert meta["created_at"] == "2026-01-02 03:04:05"
        assert meta["created_schema_version"] == HEAD
        assert meta["targets"] == [] and meta["notes"] == ""
        first_opened = meta["opened_at"]
    time.sleep(1.1)
    with Store(path) as store:
        meta = project.ensure_metadata(store, "renamed?")
        assert meta["name"] == "legacy"                     # the row is created once
        assert meta["opened_at"] > first_opened
        assert store.conn.execute("SELECT COUNT(*) FROM project").fetchone()[0] == 1


def test_open_marks_orphaned_running_launches_unknown(tmp_path):
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        lid, _tok = project.insert_launch(store, "auto", [("", "fuzzlab")], None)
        project.ensure_metadata(store, "s")                 # the UI that ran it is gone
        assert store.conn.execute("SELECT status FROM launch WHERE id=?",
                                  (lid,)).fetchone()[0] == "unknown"


def _ensure_in_child(path, barrier):
    barrier.wait()
    with Store(path) as store:
        project.ensure_metadata(store, "p")


def test_two_first_opens_at_once_create_one_row(tmp_path):
    """PA-0088(3): the check-then-insert holds the write lock (two processes)."""
    path = tmp_path / "s.db"
    Store(path).close()
    ctx = multiprocessing.get_context("fork")
    barrier = ctx.Barrier(2)
    procs = [ctx.Process(target=_ensure_in_child, args=(str(path), barrier))
             for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert [p.exitcode for p in procs] == [0, 0]
    with Store(path) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM project").fetchone()[0] == 1


def test_metadata_bounds_and_targets_are_redacted_and_deduplicated(tmp_path):
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        project.set_meta(store, notes="hello", targets=[
            "http://admin:pw@127.0.0.1:8080/app/", "http://admin:pw@127.0.0.1:8080/app/",
            "  ", "http://127.0.0.1:9000/?token=abc"])
        meta = project.read_metadata(store)
        assert meta["notes"] == "hello"
        assert meta["targets"] == ["http://***@127.0.0.1:8080/app/",
                                   f"http://127.0.0.1:9000/?token={PLACEHOLDER}"]
        with pytest.raises(ValueError):
            project.set_meta(store, notes="x" * (project.MAX_NOTES_CHARS + 1))
        with pytest.raises(ValueError):
            project.set_meta(store, targets=[f"http://h/{i}" for i in range(51)])
        project.add_target(store, "http://127.0.0.1:7000/")
        assert project.read_metadata(store)["targets"][-1] == "http://127.0.0.1:7000/"


def test_malformed_stored_targets_read_empty_and_flagged_never_fabricated(tmp_path):
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        for bad in ("{not json", '{"a": 1}', '[1, 2]', "null"):
            store.conn.execute("UPDATE project SET targets=?", (bad,))
            meta = project.read_metadata(store)
            assert meta["targets"] == [] and meta["targets_malformed"] is True


# --- launches and run linkage ---------------------------------------------------------

def test_runs_link_to_the_launch_whose_token_the_child_carries(tmp_path, monkeypatch):
    a, b = tmp_path / "a.db", tmp_path / "b.db"
    with Store(a) as store:
        lid, token = project.insert_launch(store, "auto", [("", "fuzzlab")], None)
        monkeypatch.setenv(LAUNCH_TOKEN_ENV, token)
        r1 = store.start_run("auto", "h")                 # nested stages of one job
        r2 = store.start_run("crawl", "h")
        rows = dict(store.conn.execute("SELECT id, launch_id FROM run").fetchall())
        assert rows[r1] == rows[r2] == lid
    with Store(b) as other:                               # another store: no such launch
        r3 = other.start_run("auto", "h")
        project.insert_launch(other, "auto", [("", "x")], None)   # id 1 exists here too
        assert other.conn.execute("SELECT launch_id FROM run WHERE id=?",
                                  (r3,)).fetchone()[0] is None
    for garbage in ("", "1", "x" * 32, token.upper(), token + "0", "' OR 1=1 --"):
        monkeypatch.setenv(LAUNCH_TOKEN_ENV, garbage)
        with Store(a) as store:
            r = store.start_run("auto", "h")
            assert store.conn.execute("SELECT launch_id FROM run WHERE id=?",
                                      (r,)).fetchone()[0] is None, garbage
    monkeypatch.delenv(LAUNCH_TOKEN_ENV)
    with Store(a) as store:
        r = store.start_run("auto", "h")
        assert store.conn.execute("SELECT launch_id FROM run WHERE id=?",
                                  (r,)).fetchone()[0] is None


def test_status_precedence():
    assert project.status_for(0, True) == "stopped"
    assert project.status_for(None, False) == "unknown"
    assert project.status_for(0, False) == "succeeded"
    assert project.status_for(2, False) == "failed"
    assert project.status_for(-15, False) == "failed"


def test_finish_launch_never_recreates_a_project_that_is_gone(tmp_path):
    path = tmp_path / "gone.fuzzlab"
    project.create(path)
    with Store(path, create=False) as store:
        lid, _ = project.insert_launch(store, "auto", [("", "x")], None)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(str(path) + suffix):
            os.unlink(str(path) + suffix)
    with pytest.raises(sqlite3.OperationalError):
        project.finish_launch(path, lid, "succeeded", 0)
    assert not path.exists()


def test_run_history_rows(tmp_path, monkeypatch):
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        cli = store.start_run("crawl", "h")
        store.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                           (cli, "http://127.0.0.1:8080"))
        lid, tok = project.insert_launch(
            store, "auto", [("", "fuzzlab"), ("", "auto"), ("", "--base-url"),
                            ("base_url", "http://u:pw@127.0.0.1:8080")],
            "http://u:pw@127.0.0.1:8080")
        monkeypatch.setenv(LAUNCH_TOKEN_ENV, tok)
        ui = store.start_run("auto", "h")
        aborted = store.start_run("auto", "h")
        monkeypatch.delenv(LAUNCH_TOKEN_ENV)
        store.mark_aborted(aborted, SystemExit(2))
        store.conn.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, "
                           "evidence) VALUES (?,?,?,?,?)", (ui, "sqli", 1, "x", "{}"))
        store.conn.commit()
        lonely, _ = project.insert_launch(store, "fuzz", [("", "fuzzlab")], None)
        project.finish_launch(store.path, lid, "succeeded", 0)

        rows = project.run_history(store)
        by_run = {r["run_id"]: r for r in rows}
        assert by_run[cli]["source"] == "cli" and by_run[cli]["command"] == "crawl"
        assert by_run[cli]["target"] == "http://127.0.0.1:8080"
        assert by_run[cli]["status"] == "recorded"
        assert by_run[ui]["status"] == "succeeded" and by_run[ui]["findings"] == 1
        assert by_run[ui]["target"] == "http://***@127.0.0.1:8080"
        assert "u:pw" not in " ".join(by_run[ui]["argv"])
        assert by_run[aborted]["status"] == "aborted"          # the run's own note wins
        assert is_aborted(store.conn.execute("SELECT notes FROM run WHERE id=?",
                                             (aborted,)).fetchone()[0])
        lone = [r for r in rows if r["launch_id"] == lonely and r["run_id"] is None]
        assert len(lone) == 1 and lone[0]["status"] == "unknown"   # not live here
        live = project.run_history(store, live_launch_ids=[lonely])
        assert [r for r in live if r["launch_id"] == lonely][0]["status"] == "running"


# --- inspection ---------------------------------------------------------------------

def test_inspect_is_read_only_on_the_main_file(tmp_path):
    path = tmp_path / "s.fuzzlab"
    project.create(path)
    before, mtime = path.read_bytes(), os.stat(path).st_mtime_ns
    info = project.inspect(path)
    assert info.state == "ok" and info.application_id == migrations.APPLICATION_ID
    assert info.metadata["name"] == "s" and info.quick_checked
    assert path.read_bytes() == before and os.stat(path).st_mtime_ns == mtime
    for side in ("-wal", "-shm"):                     # may appear; never wider than main
        p = tmp_path / f"s.fuzzlab{side}"
        if p.exists():
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


@pytest.mark.parametrize("kind", ["garbage", "symlink", "fifo", "directory", "trigger",
                                  "view", "foreign-sqlite", "missing", "same-name-trigger",
                                  "virtual-table", "empty-schema-version",
                                  "commented-virtual-table", "foreign-version-3",
                                  "negative-version", "text-version", "foreign-app-id",
                                  "TRIGGER-row", "Trigger-row", "extra-table",
                                  "changed-index"])
def test_inspect_refuses_what_is_not_a_fuzzlab_store(tmp_path, kind):
    path = tmp_path / "x.fuzzlab"
    if kind == "garbage":
        path.write_bytes(b"\x00" * 4096)
    elif kind == "symlink":
        real = tmp_path / "real.fuzzlab"
        Store(real).close()
        path.symlink_to(real)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind in ("trigger", "view"):
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("CREATE TRIGGER t AFTER INSERT ON run BEGIN DELETE FROM finding; END"
                     if kind == "trigger" else "CREATE VIEW v AS SELECT 1")
        conn.commit()
        conn.close()
    elif kind == "same-name-trigger":                 # code review B: own namespace
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("CREATE TRIGGER schema_version AFTER INSERT ON finding "
                     "BEGIN DELETE FROM finding; END")
        conn.commit()
        conn.close()
    elif kind == "virtual-table":
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("CREATE VIRTUAL TABLE x USING fts5(a)")
        conn.commit()
        conn.close()
    elif kind == "commented-virtual-table":           # code review A, round 2
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("CREATE VIRTUAL TABLE evil USING fts4(x)")
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute("UPDATE sqlite_master SET sql='CREATE /*x*/ VIRTUAL TABLE evil USING "
                     "fts4(x)' WHERE name='evil'")
        conn.commit()
        conn.close()
    elif kind in ("foreign-version-3", "negative-version", "text-version"):
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE schema_version (version)")
        conn.execute("INSERT INTO schema_version VALUES (?)",
                     ({"foreign-version-3": 3, "negative-version": -5,
                       "text-version": "x"}[kind],))
        conn.execute("CREATE TABLE accounts (x)")
        conn.commit()
        conn.close()
    elif kind in ("TRIGGER-row", "Trigger-row"):     # BUG-0451: type is not lowercase
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute("INSERT INTO sqlite_master VALUES (?,?,?,?,?)",
                     (kind.split("-")[0], "evil", "project", 0,
                      "CREATE TRIGGER evil AFTER UPDATE ON project BEGIN "
                      "DELETE FROM finding; END"))
        conn.commit()
        conn.close()
    elif kind == "extra-table":
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE notes_of_someone_else (x)")
        conn.commit()
        conn.close()
    elif kind == "changed-index":
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX ix_form_endpoint")
        conn.execute("CREATE INDEX ix_form_endpoint ON form(run_id)")
        conn.commit()
        conn.close()
    elif kind == "foreign-app-id":
        Store(path).close()
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA application_id = 1234")
        conn.commit()
        conn.close()
    elif kind == "empty-schema-version":              # another app's db, version table empty
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE accounts (x)")
        conn.commit()
        conn.close()
    elif kind == "foreign-sqlite":
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE other (x)")
        conn.commit()
        conn.close()
    with pytest.raises(ProjectError):
        project.inspect(path)


def test_inspect_an_empty_file_is_a_new_project(tmp_path):
    path = tmp_path / "e.fuzzlab"
    path.touch()
    assert project.inspect(path).state == "ok" and project.inspect(path).schema_version == 0


def test_inspect_lets_an_unexpected_error_propagate(tmp_path, monkeypatch):
    """PA-0106: only the named errors become a refusal."""
    path = tmp_path / "s.fuzzlab"
    project.create(path)

    def boom(*a, **k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(project.sqlite3, "connect", boom)
    with pytest.raises(RuntimeError):
        project.inspect(path)


# --- creation and copying -------------------------------------------------------------

def test_create_is_private_exclusive_and_never_follows_a_link(tmp_path):
    path = tmp_path / "p.fuzzlab"
    project.create(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with pytest.raises(FileExistsError):
        project.create(path)
    target = tmp_path / "elsewhere"
    link = tmp_path / "l.fuzzlab"
    link.symlink_to(target)
    with pytest.raises(OSError):
        project.create(link)
    assert not target.exists()


def test_side_files_inherit_the_private_mode(tmp_path):
    old = os.umask(0o022)
    try:
        path = tmp_path / "p.fuzzlab"
        project.create(path)
        with Store(path, create=False) as store:
            store.start_run("x", "h")
            for side in ("-wal", "-shm"):
                assert stat.S_IMODE(os.stat(str(path) + side).st_mode) == 0o600
    finally:
        os.umask(old)


def test_copy_is_complete_under_a_live_writer_and_private(tmp_path):
    src, dst = tmp_path / "src.fuzzlab", tmp_path / "dst.fuzzlab"
    project.create(src)
    stop = threading.Event()

    def writer():
        with Store(src, create=False) as store:
            while not stop.is_set():
                store.start_run("w", "h")
    t = threading.Thread(target=writer)
    t.start()
    try:
        time.sleep(0.2)
        holder = Store(src, create=False)             # keep the source open throughout
        project.copy_to(src, dst)
        # the copy is readable on its own, while the source connection is still open
        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        n = conn.execute("SELECT COUNT(*) FROM run").fetchone()[0]
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        conn.close()
        holder.close()
    finally:
        stop.set()
        t.join()
    assert n > 0
    assert stat.S_IMODE(os.stat(dst).st_mode) == 0o600
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".copy-")]
    with pytest.raises(FileExistsError):
        project.copy_to(src, dst)


def test_copy_refuses_to_publish_a_copy_with_data_left_in_a_side_file(tmp_path, monkeypatch):
    """G2: a hard link carries the main file only, so data left in the copy's ``-wal``
    (as a WAL-journaled destination still open elsewhere would leave it) must stop the
    publish. Injected: the destination's close leaves a non-empty ``-wal`` behind."""
    src, dst = tmp_path / "src.fuzzlab", tmp_path / "dst.fuzzlab"
    project.create(src)
    real = sqlite3.connect

    class LeavesWal(sqlite3.Connection):
        def close(self):
            super().close()
            with open(self.target + "-wal", "wb") as fh:
                fh.write(b"\x37" * 4096)

    def connect(target, *a, **k):
        if ".copy-" in str(target) and not k.get("uri"):
            conn = real(target, *a, factory=LeavesWal, **k)
            conn.target = str(target)
            return conn
        return real(target, *a, **k)
    monkeypatch.setattr(project.sqlite3, "connect", connect)
    with pytest.raises(OSError, match="non-empty -wal"):
        project.copy_to(src, dst)
    assert not dst.exists()
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".copy-")]


def test_a_failed_copy_leaves_no_file_under_the_final_name(tmp_path, monkeypatch):
    src, dst = tmp_path / "src.fuzzlab", tmp_path / "dst.fuzzlab"
    project.create(src)

    def no_link(a, b):
        raise OSError("injected: no hard links here")
    monkeypatch.setattr(project.os, "link", no_link)
    with pytest.raises(OSError, match="injected"):
        project.copy_to(src, dst)
    assert not dst.exists()
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".copy-")]


def test_migration_offer_backs_up_first_then_migrates(tmp_path):
    path = tmp_path / "old.fuzzlab"
    _v21(path)
    backup, version = project.migrate_with_backup(path)
    assert version == HEAD and project.inspect(path).state == "ok"
    assert backup.parent == project.sidecar_dir(path) / "backups"
    assert stat.S_IMODE(os.stat(backup.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
    binfo = project.inspect(backup)
    assert binfo.schema_version == 21 and binfo.runs == 1


def test_a_failed_backup_migrates_nothing(tmp_path, monkeypatch):
    path = tmp_path / "old.fuzzlab"
    _v21(path)
    before = path.read_bytes()

    def fail(src, dst):
        raise OSError("injected backup failure")
    monkeypatch.setattr(project, "copy_to", fail)
    with pytest.raises(OSError, match="injected"):
        project.migrate_with_backup(path)
    assert path.read_bytes() == before and project.inspect(path).schema_version == 21


def test_a_failed_migration_keeps_the_backup_and_names_the_version(tmp_path, monkeypatch):
    path = tmp_path / "old.fuzzlab"
    _v21(path)

    def boom(conn):
        raise RuntimeError("injected migration failure")
    monkeypatch.setitem(migrations.POST_STEPS, 22, boom)
    with pytest.raises(ProjectError, match=r"now at schema v21; the backup is at"):
        project.migrate_with_backup(path)
    backups = list((project.sidecar_dir(path) / "backups").iterdir())
    assert len(backups) == 1 and project.inspect(backups[0]).schema_version == 21


def test_make_private(tmp_path):
    path = tmp_path / "legacy.db"
    Store(path).close()
    os.chmod(path, 0o644)
    assert not project.is_private(path)
    project.make_private(path)
    assert project.is_private(path)


# --- the record-boundary redactor -------------------------------------------------------

@pytest.mark.parametrize("dest,value,secret", [
    ("base_url", "http://admin:hunter2@127.0.0.1:8080/app/", "hunter2"),
    ("base_url", "https://admin:hunter2@h/", "admin"),
    ("url", "http://127.0.0.1/p.php?token=s3cr3tval&id=1", "s3cr3tval"),
    ("url", "http://127.0.0.1/p.php?access_token=s3cr3tval", "s3cr3tval"),
    ("start", "admin:hunter2@127.0.0.1:8080", "hunter2"),
    ("categories", "x http://u:hunter2@h/ y", "hunter2"),
    ("password", "hunter2", "hunter2"),
    # code review B: a password with `@`, a fragment token, a matrix parameter, and
    # scheme-relative userinfo (PA-0091(1): name forms x value shapes)
    ("base_url", "http://admin:p@ssw0rd@127.0.0.1:8080/?id=1", "ssw0rd"),
    ("start", "admin:p@ss@127.0.0.1:8080/x", "p@ss"),
    ("url", "http://h/#access_token=s3cr3tval&x=1", "s3cr3tval"),
    ("url", "http://h/#/search?q=1&token=s3cr3tval", "s3cr3tval"),
    ("url", "http://h/p;jsessionid=s3cr3tval?x=1", "s3cr3tval"),
    ("url", "//u:hunter2@h/", "hunter2"),
    ("url", "http://h/?api_key=s3cr3tval&apiKeys=s3cr3tval2", "s3cr3tval"),
    ("api_key", "abc123def", "abc123def"),
])
def test_redact_for_record_removes_every_planted_secret_shape(dest, value, secret):
    assert secret not in redact_for_record(dest, value)


@pytest.mark.parametrize("dest,value", [
    ("base_url", "http://127.0.0.1:8080/app/"), ("param", "id"), ("author", "bob"),
    ("url", "http://127.0.0.1/p.php?id=1&page=2"), ("header_points", "User-Agent,Referer"),
    ("identity", "alice"), ("method", "GET"),
    ("url", "http://h/#/search?q=apple"), ("url", "http://h/p;v=1?x=1"),
    ("categories", "x@y.com"),
])
def test_redact_for_record_keeps_benign_values(dest, value):
    assert redact_for_record(dest, value) == value


# --- BUG-0450: the fuzzer imports only its own run's CSV --------------------------------

def test_fuzz_never_imports_a_stale_csv_when_its_run_collected_nothing(tmp_path, monkeypatch):
    from fuzzlab import oracle
    from fuzzlab.tools import blind_sqli_fuzzer, probesender
    stale = tmp_path / "fuzz.csv"
    stale.write_text("payload,time_delay_detected\n' OR SLEEP(5)--,1\n")
    monkeypatch.setattr(blind_sqli_fuzzer, "establish_baseline",
                        lambda *a, **k: {"avg_latency": 0.1, "avg_size": 10})
    monkeypatch.setattr(blind_sqli_fuzzer, "run_fuzzing_cycle", lambda *a, **k: [])
    monkeypatch.setattr(probesender, "make_probe_sender", lambda *a, **k: _NoProbe())

    class _Oracle:
        def __init__(self, **kw):
            pass

        def confirm(self, cand, probe):
            return None
    monkeypatch.setattr(oracle, "Oracle", _Oracle)
    store = tmp_path / "s.db"
    blind_sqli_fuzzer.main(["--url", "http://127.0.0.1:8080/p.php", "--param", "id",
                            "--output", str(stale), "--store", str(store), "--authorized"])
    with Store(store) as s:
        assert s.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert s.conn.execute("SELECT COUNT(*) FROM attempt").fetchone()[0] == 0


class _NoProbe:
    def allow_explicit(self, urls):
        pass



def test_a_case_variant_trigger_never_fires_on_open(tmp_path):
    """BUG-0451: the trigger row a denylist missed fired during the UI's own open."""
    path = tmp_path / "evil.fuzzlab"
    project.create(path)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE marker (x)")
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute("INSERT INTO sqlite_master VALUES ('TRIGGER','evil','project',0,"
                 "'CREATE TRIGGER evil AFTER UPDATE ON project BEGIN "
                 "INSERT INTO marker VALUES (1); END')")
    conn.commit()
    conn.close()
    with pytest.raises(ProjectError, match="refused as untrusted"):
        project.inspect(path)


def test_the_allowlist_accepts_every_real_store_shape(tmp_path):
    """Non-vacuity: a fresh store, a legacy (v21) store, a store with ANALYZE stats and
    a store with recorded flows (FTS shadow rows) all pass."""
    fresh = tmp_path / "fresh.fuzzlab"
    project.create(fresh)
    legacy = tmp_path / "legacy.fuzzlab"
    _v21(legacy)
    stats = tmp_path / "stats.fuzzlab"
    project.create(stats)
    with Store(stats, create=False) as store:
        store.conn.execute("ANALYZE")
        store.conn.commit()
    for p in (fresh, legacy, stats):
        assert project.inspect(p).state in ("ok", "older"), p
    assert project.reference_schema(migrations.head_version())


def test_record_redaction_is_linear_and_bounded():
    """Code review B, round 2 (PA-0095/0096): the userinfo pattern was quadratic, and it
    ran under the project lock; values are also capped before any work."""
    import time
    from fuzzlab.core import redaction
    for pat in (redaction._URL_USERINFO, redaction._BARE_USERINFO, redaction._MATRIX_PARAM):
        for v in ("a+" * 64000, "a." * 64000, "a:" * 64000, ";a=" * 40000):
            t = time.perf_counter()
            pat.sub("", v)
            assert time.perf_counter() - t < 0.5, (pat.pattern, v[:4])
    out = redact_for_record("start", "x" * 100_000)
    assert len(out) <= redaction.MAX_RECORD_CHARS + 20


def test_deep_json_in_the_recent_list_is_malformed_not_a_crash(tmp_path):
    from fuzzlab.web import projects as web_projects
    p = tmp_path / "recent.json"
    p.write_text("[" * 100000 + "]" * 100000)
    assert web_projects._parse_recent(p) == ([], 1)


# --- code review round 3 --------------------------------------------------------------

#: An expression that costs real time in SQLite's own built-ins (no application function
#: is needed, so `trusted_schema=OFF` does not stop it): ~25 MB built and measured, many
#: times over — seconds per evaluation, unbounded in depth.
_HEAVY = "length(replace(printf('%.*c', 25000000, 'x'), 'x', 'yy'))"


def _rewrite_definition(path, name, rewrite):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=DELETE")
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute("UPDATE sqlite_master SET sql=? WHERE name=?", (rewrite(sql), name))
    conn.commit()
    conn.close()


def _add_before_close(extra):
    return lambda sql: sql.rstrip().rstrip(")") + f", {extra})"


@pytest.mark.parametrize("name,rewrite", [
    ("project", _add_before_close(f"g INTEGER GENERATED ALWAYS AS ({_HEAVY}) VIRTUAL")),
    ("project", _add_before_close(f"CHECK (length(name) + 0*{_HEAVY} >= 0)")),
    ("launch", _add_before_close(f"extra INTEGER DEFAULT ({_HEAVY})")),
    ("schema_version", lambda sql: sql.replace(
        "version INTEGER PRIMARY KEY",
        f"v0 INTEGER, version INTEGER GENERATED ALWAYS AS (v0 + 0*{_HEAVY})")),
], ids=["generated-column", "check", "default", "generated-version"])
def test_an_allowed_table_with_a_changed_definition_is_refused_before_any_row_is_read(
        tmp_path, name, rewrite):
    """BUG-0453: a table matched by name alone kept an added generated column, CHECK or
    DEFAULT, which ran SQLite's built-ins without bound on open, listing and migrate."""
    path = tmp_path / "evil.fuzzlab"
    project.create(path)
    with Store(path, create=False) as store:
        store.start_run("x", "h")
    _rewrite_definition(path, name, rewrite)
    if name != "schema_version":                        # non-vacuity: it does run
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA trusted_schema=OFF")
        t = time.perf_counter()
        if name == "project":                           # a read, and the UI's write
            conn.execute("SELECT * FROM project").fetchall()
            conn.execute("UPDATE project SET name='t'")
        else:
            conn.execute("INSERT INTO launch (command, argv, started_at, status, token) "
                         "VALUES ('c','[]','t','running','tok')")
        assert time.perf_counter() - t > 0.05            # built-in work, not refused
        conn.close()
    t = time.perf_counter()
    with pytest.raises(ProjectError, match="untrusted"):
        project.inspect(path)
    assert project.summary(path) == {"readable": False}
    assert time.perf_counter() - t < 0.5                 # refused from sqlite_master alone


def test_a_newer_file_is_refused_without_reading_its_tables(tmp_path):
    """BUG-0453: a newer build's definitions cannot be checked, so nothing past its
    version is read (its project row's generated column never runs)."""
    path = tmp_path / "newer.fuzzlab"
    project.create(path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (HEAD + 1,))
    conn.commit()
    conn.close()
    _rewrite_definition(path, "project", _add_before_close(
        f"g INTEGER GENERATED ALWAYS AS ({_HEAVY}) VIRTUAL"))
    t = time.perf_counter()
    info = project.inspect(path)
    assert info.state == "newer" and info.metadata is None and info.runs == 0
    assert time.perf_counter() - t < 0.5


def test_sqlite_statistics_tables_must_have_sqlites_own_definition(tmp_path):
    path = tmp_path / "stat.fuzzlab"
    project.create(path)
    with Store(path, create=False) as store:
        store.conn.execute("ANALYZE")
        store.conn.commit()
    assert project.inspect(path).state == "ok"
    _rewrite_definition(path, "sqlite_stat1", _add_before_close(
        f"g INTEGER GENERATED ALWAYS AS ({_HEAVY}) VIRTUAL"))
    with pytest.raises(ProjectError, match="sqlite_stat1"):
        project.inspect(path)


def test_the_allowlist_accepts_a_v22_store_migrated_to_head_and_one_with_flows(tmp_path):
    """Code review round 3 (C10): the legacy shape PA-0451(2) names, and real FTS rows."""
    v22 = tmp_path / "v22.fuzzlab"
    with Store(v22) as store:
        project.ensure_metadata(store, "v22")
        store.conn.execute("UPDATE project SET uuid=NULL")
        undo_after(store.conn, 22)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 23")
        store.conn.commit()
    assert project.inspect(v22).state == "older"
    project.migrate_with_backup(v22)
    info = project.inspect(v22)
    assert info.state == "ok"
    # migration 23's backfill gave the existing row an identity (FR-CORE-453)
    assert project._HEX32.fullmatch(info.metadata["uuid"])
    flows = tmp_path / "flows.fuzzlab"
    project.create(flows)
    with Store(flows, create=False) as store:
        for i in range(50):
            store.conn.execute("INSERT INTO flow_fts (url, method, host, req_head, "
                               "resp_head, flow_id) VALUES (?,?,?,?,?,?)",
                               (f"http://h/{i}", "GET", "h", "a", "b", i))
        store.conn.commit()
    assert project.inspect(flows).state == "ok"
    assert project.summary(flows)["readable"] is True


@pytest.mark.parametrize("column", ["targets", "argv"])
def test_deep_json_in_a_project_file_reads_as_malformed(tmp_path, column):
    """BUG-0454: a RecursionError from a deeply nested value escaped every handler."""
    path = tmp_path / "deep.fuzzlab"
    project.create(path)
    deep = "[" * 200000 + "]" * 200000
    with Store(path, create=False) as store:
        if column == "targets":
            store.conn.execute("UPDATE project SET targets=?", (deep,))
        else:
            project.insert_launch(store, "crawl", [("", "fuzzlab")], None)
            store.conn.execute("UPDATE launch SET argv=?", (deep,))
        store.conn.commit()
    info = project.inspect(path)
    with Store(path, create=False) as store:
        if column == "targets":
            assert info.metadata["targets"] == [] and info.metadata["targets_malformed"]
        else:
            assert project.run_history(store)[0]["argv"] == []


def test_odd_types_in_a_project_file_are_never_a_crash(tmp_path):
    """BUG-0454: every value of an untrusted store is typed before use — a BLOB where
    text belongs, an unknown status, a non-string argv element."""
    path = tmp_path / "odd.fuzzlab"
    project.create(path)
    with Store(path, create=False) as store:
        a = store.start_run("crawl", "h")
        b = store.start_run("crawl", "h")
        lid, _tok = project.insert_launch(store, "crawl", [("", "fuzzlab")], None)
        store.conn.execute("UPDATE run SET started_at=X'41', notes=X'42' WHERE id=?", (a,))
        store.conn.execute("UPDATE run SET tool=X'47' WHERE id=?", (b,))
        store.conn.execute("UPDATE launch SET status='<b>', command=X'43', "
                           "argv='[1, [2]]', started_at=5, exit_code='x' WHERE id=?", (lid,))
        store.conn.execute("UPDATE project SET name=X'44', notes=X'46', created_at=X'45', "
                           "created_schema_version='v'")
        store.conn.commit()
    info = project.inspect(path)
    meta = info.metadata
    assert meta["name"] is None and meta["notes"] is None and meta["created_at"] is None
    assert meta["created_schema_version"] is None
    with Store(path, create=False) as store:
        rows = project.run_history(store)
    by_run = {r["run_id"]: r for r in rows}
    assert by_run[a]["started_at"] is None and by_run[a]["status"] == "recorded"
    assert by_run[b]["command"] == ""
    launch = [r for r in rows if r["run_id"] is None][0]
    assert launch["status"] == "unknown" and launch["argv"] == [] and launch["command"] == ""


def test_malformed_lineage_is_flagged_never_fabricated(tmp_path):
    """Code review round 3 (C5, PA-0108): a bad copy_kind or copied_at is flagged."""
    path = tmp_path / "lin.fuzzlab"
    project.create(path)
    for kind, copied, flagged in [("snapshot", "2026-01-01 00:00:00", False),
                                  ("Snapshot", "2026-01-01 00:00:00", True),
                                  ("snapshot", "x" * 5000, True),
                                  ("snapshot", 7, True), (None, None, False)]:
        with Store(path, create=False) as store:
            store.conn.execute("UPDATE project SET copy_kind=?, copied_at=?",
                               (kind, copied))
            store.conn.commit()
            meta = project.read_metadata(store)
        assert meta["identity_malformed"] is flagged, (kind, copied)
        if flagged:
            assert meta["copy_kind"] is None or meta["copied_at"] is None


def test_a_credential_straddling_the_record_cut_is_still_removed():
    """BUG-0455: the cut ran before userinfo redaction, leaving a password unmatched."""
    from fuzzlab.core.redaction import MAX_RECORD_CHARS
    long_pw = "http://admin:" + "S3cr3t!" * 600 + "@lab.local/"
    straddle = "x" * (MAX_RECORD_CHARS - 16) + " http://user:secretpw@h"
    bare = "x" * (MAX_RECORD_CHARS - 16) + " user:secretpw@host"
    for value, secret in ((long_pw, "S3cr3t"), (straddle, "secr"), (bare, "secr")):
        out = redact_for_record("target", value)
        assert secret not in out and len(out) <= MAX_RECORD_CHARS + 20


def test_run_history_labels_an_unknown_exit(tmp_path):
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        lid, _tok = project.insert_launch(store, "auto", [("", "fuzzlab")], None)
    project.finish_launch(tmp_path / "s.db", lid, "unknown", None)
    with Store(tmp_path / "s.db", create=False) as store:
        assert project.run_history(store)[0]["label"] == "unknown exit"


@pytest.mark.parametrize("table,column,rewrite", [
    ("launch", "argv", lambda sql: sql.replace("    argv ", " argv ", 1)),
    ("page", "template_cluster_id", lambda sql: sql.replace(
        "-- 'link' | 'xhr' | ...\n    template_cluster_id TEXT,\n",
        "-- 'link' | 'xhr' | ... template_cluster_id TEXT,\n\n", 1)),
], ids=["non-ascii-space", "comment-shift"])
def test_a_definition_that_only_normalises_equal_is_refused(tmp_path, table, column, rewrite):
    """BUG-0456 (code review round 4): whitespace normalisation that is not SQLite's
    grammar let a column vanish — U+00A0 is an identifier character to SQLite, and a
    newline is where a `--` comment ends."""
    path = tmp_path / "shifted.fuzzlab"
    project.create(path)
    conn = sqlite3.connect(path)
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
    conn.close()
    new = rewrite(sql)
    assert new != sql and " ".join(new.split()) == " ".join(sql.split())   # equal once normalised
    _rewrite_definition(path, table, lambda _old: new)
    conn = sqlite3.connect(path)                          # non-vacuity: the column is gone
    with pytest.raises(sqlite3.OperationalError, match="no such column"):
        conn.execute(f"SELECT {column} FROM {table}")
    conn.close()
    with pytest.raises(ProjectError, match=rf"table {table} \(definition changed\)"):
        project.inspect(path)
    assert project.summary(path) == {"readable": False}
