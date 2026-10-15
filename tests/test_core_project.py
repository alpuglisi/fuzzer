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
                                  "view", "foreign-sqlite", "missing"])
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
    ("api_key", "abc123def", "abc123def"),
])
def test_redact_for_record_removes_every_planted_secret_shape(dest, value, secret):
    assert secret not in redact_for_record(dest, value)


@pytest.mark.parametrize("dest,value", [
    ("base_url", "http://127.0.0.1:8080/app/"), ("param", "id"), ("author", "bob"),
    ("url", "http://127.0.0.1/p.php?id=1&page=2"), ("header_points", "User-Agent,Referer"),
    ("identity", "alice"), ("method", "GET"),
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
