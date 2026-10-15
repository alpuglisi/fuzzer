"""Project files: a fuzzlab store opened as a Burp/ZAP-style project (CC-CORE-0450).

A **project file is one fuzzlab store** — the SQLite file every tool already writes —
with the ``.fuzzlab`` extension and the fuzzlab ``application_id`` (migration 22). This
module is the store-level model; the web UI's lifecycle (new / open / temporary /
save as / close, the recent list, path rules) lives in ``fuzzlab.web.projects``.

- `inspect` looks at a file **without writing it** (a read-only connection: the main
  file's bytes and mtime are unchanged; on a WAL file SQLite may create the ``-wal`` /
  ``-shm`` side files, with the main file's mode). It refuses — with a typed
  `ProjectError` — anything that is not a fuzzlab store: not a regular file, not
  SQLite, no ``schema_version``, a trigger or view (migrations create none; a project
  file from someone else is untrusted input), or a failed ``quick_check``. Only the
  named errors in `_REFUSED_ERRORS` become a refusal (PA-0106).
- `version_state` compares the file's schema with this build's: ``ok``, ``older``
  (opened only after the operator accepts the migration, which `migrate_with_backup`
  does behind a verified backup) or ``newer`` (refused; ``migrations.SchemaTooNew``).
- `ensure_metadata` is the one writer of the ``project`` row (created on the first UI
  open; ``created_at`` is the store's real creation time) and `read_metadata` its one
  parser (PA-0108).
- `insert_launch` / `finish_launch` are the one writer of ``launch``; every recorded
  value goes through ``core.redaction.redact_for_record`` (PA-0100).
- `copy_to` is the only way a project is copied: the SQLite **backup API** into a
  private temporary file, verified, then hard-linked into place (never a raw copy of a
  live WAL database, never a partial file under the final name).
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from fuzzlab import __version__
from fuzzlab.core import migrations
from fuzzlab.core.redaction import redact_for_record
from fuzzlab.core.store import Store, is_aborted

PROJECT_EXT = ".fuzzlab"
#: A project's own directory (`sidecar_dir`): intermediates the pinned tools write
#: (crawl / audit databases, the fuzz CSV) and pre-migration backups. 0700.
SIDECAR_SUFFIX = ".d"
SQLITE_MAGIC = b"SQLite format 3\x00"
#: ``quick_check`` reads the whole file; above this size it is skipped (and said so).
QUICK_CHECK_MAX_BYTES = 512 * 1024 * 1024
MAX_NOTES_CHARS = 10_000
MAX_TARGETS = 50
MAX_TARGET_CHARS = 2048
MAX_NAME_CHARS = 200
#: Launch statuses (`status_for`). ``unknown``: the UI ended before the job did, or the
#: exit status could not be read.
LAUNCH_STATUSES = ("running", "succeeded", "failed", "stopped", "unknown")

#: The only errors `inspect` turns into a refusal; anything else propagates (PA-0106).
_REFUSED_ERRORS = (sqlite3.DatabaseError, FileNotFoundError, PermissionError,
                   IsADirectoryError, NotADirectoryError)


class ProjectError(Exception):
    """A file cannot be opened as a project; ``str()`` says why, for the operator."""


@dataclass
class ProjectInfo:
    """What `inspect` found (read-only)."""

    path: Path
    size: int
    schema_version: int                      # 0 for a new, empty file
    head_version: int
    application_id: int = 0
    metadata: dict[str, Any] | None = None
    runs: int = 0
    quick_checked: bool = False              # False when skipped (empty or too large)
    notes: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        return version_state(self.schema_version, self.head_version)


def version_state(found: int, head: int) -> str:
    """``ok`` (same, or a new empty file), ``older`` or ``newer``."""
    if found == 0 or found == head:
        return "ok"
    return "older" if found < head else "newer"


def sidecar_dir(path: str | Path) -> Path:
    """The project's own directory: ``<file>.d`` beside it."""
    p = Path(path)
    return p.with_name(p.name + SIDECAR_SUFFIX)


def _ro_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro"


def inspect(path: str | Path) -> ProjectInfo:
    """Look at ``path`` without writing it; `ProjectError` if it is not a fuzzlab store."""
    p = Path(path)
    try:
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            raise ProjectError(f"{p} is a symbolic link; open the file itself")
        if not stat.S_ISREG(st.st_mode):
            raise ProjectError(f"{p} is not a regular file")
        head = migrations.head_version()
        if st.st_size == 0:
            return ProjectInfo(p, 0, 0, head, notes=["new, empty file"])
        with open(p, "rb") as fh:
            magic = fh.read(len(SQLITE_MAGIC))
        if magic != SQLITE_MAGIC:
            raise ProjectError(f"{p} is not an SQLite database")
        conn = sqlite3.connect(_ro_uri(p), uri=True, timeout=10.0)
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
            return _inspect_open(conn, p, st.st_size, head)
        finally:
            conn.close()
    except _REFUSED_ERRORS as exc:
        raise ProjectError(f"{p} cannot be opened as a project: {exc}") from exc


def _inspect_open(conn: sqlite3.Connection, p: Path, size: int, head: int) -> ProjectInfo:
    kinds = {r[0]: r[1] for r in conn.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','trigger','view')")}
    active = sorted(n for n, t in kinds.items() if t in ("trigger", "view"))
    if active:
        raise ProjectError(f"{p} contains schema objects fuzzlab never creates "
                           f"({', '.join(active)}); refused as untrusted")
    if "schema_version" not in kinds:
        raise ProjectError(f"{p} is an SQLite database but not a fuzzlab store "
                           "(no schema_version table)")
    found = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
    info = ProjectInfo(p, size, int(found), head,
                       application_id=int(conn.execute("PRAGMA application_id").fetchone()[0]))
    if size <= QUICK_CHECK_MAX_BYTES:
        result = conn.execute("PRAGMA quick_check").fetchone()[0]
        if result != "ok":
            raise ProjectError(f"{p} failed SQLite's quick_check: {result}")
        info.quick_checked = True
    else:
        info.notes.append("quick_check skipped (file larger than 512 MiB)")
    if "run" in kinds:
        info.runs = int(conn.execute("SELECT COUNT(*) FROM run").fetchone()[0])
    if "project" in kinds:
        row = conn.execute("SELECT * FROM project WHERE id=1").fetchone()
        if row is not None:
            cols = [d[0] for d in conn.execute("SELECT * FROM project LIMIT 0").description]
            info.metadata = _parse_metadata(dict(zip(cols, row)))
    return info


# --- creation and metadata -------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def create(path: str | Path, name: str | None = None) -> None:
    """Create a new project file at ``path``: 0600 from the first byte, ``O_EXCL``
    (refuses an existing path), ``O_NOFOLLOW``; then migrate and write its metadata.
    A failure removes what it created."""
    p = Path(path)
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    try:
        with Store(p, create=False) as store:
            ensure_metadata(store, name or p.stem)
    except BaseException:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.unlink(str(p) + suffix)
            except FileNotFoundError:
                pass
        raise


def ensure_metadata(store: Store, name: str) -> dict[str, Any]:
    """Create the ``project`` row on the first UI open, else record this open; and mark
    every ``running`` launch ``unknown`` — no job of this UI is live in a project it is
    only now opening, so such a row is one whose UI ended first (FR-UI-455). One
    ``BEGIN IMMEDIATE`` transaction, re-checked inside (PA-0088(2))."""
    conn = store.conn
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT id FROM project WHERE id=1").fetchone()
        now = _now()
        if row is None:
            created = conn.execute(
                "SELECT MIN(applied_at) FROM schema_version").fetchone()[0] or now
            conn.execute(
                "INSERT INTO project (id, name, created_at, opened_at, notes, targets, "
                "created_by_version, opened_by_version, created_schema_version) "
                "VALUES (1,?,?,?,'','[]',?,?,?)",
                (str(name)[:MAX_NAME_CHARS], created, now, __version__, __version__,
                 migrations.current_version(conn)))
        else:
            conn.execute("UPDATE project SET opened_at=?, opened_by_version=? WHERE id=1",
                         (now, __version__))
        conn.execute("UPDATE launch SET status='unknown' WHERE status='running'")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return read_metadata(store) or {}


def _parse_metadata(row: dict[str, Any]) -> dict[str, Any]:
    """The one parser of a ``project`` row (PA-0108): ``targets`` must be a JSON list of
    strings; anything else reads as ``[]`` with ``targets_malformed`` set — never a
    fabricated value."""
    out = {k: row.get(k) for k in ("name", "created_at", "opened_at", "notes",
                                    "created_by_version", "opened_by_version",
                                    "created_schema_version")}
    out["targets_malformed"] = False
    try:
        targets = json.loads(row.get("targets") or "[]")
    except (ValueError, TypeError):
        targets = None
    if not (isinstance(targets, list) and all(isinstance(t, str) for t in targets)):
        out["targets_malformed"] = True
        targets = []
    out["targets"] = targets
    return out


def read_metadata(store: Store) -> dict[str, Any] | None:
    cur = store.conn.execute("SELECT * FROM project WHERE id=1")
    row = cur.fetchone()
    if row is None:
        return None
    return _parse_metadata(dict(row))


def rename(store: Store, name: str) -> None:
    """Set the project's display name (a saved copy takes its new file's name)."""
    with store.conn:
        store.conn.execute("UPDATE project SET name=? WHERE id=1",
                           (str(name)[:MAX_NAME_CHARS],))


def _clean_target(url: str) -> str | None:
    url = (url or "").strip()
    if not url:
        return None
    if len(url) > MAX_TARGET_CHARS:
        raise ValueError(f"a target is at most {MAX_TARGET_CHARS} characters")
    return redact_for_record("target", url)


def set_meta(store: Store, *, notes: str | None = None,
             targets: Sequence[str] | None = None) -> None:
    """Replace the notes and/or the target list (bounded; targets redacted, deduplicated
    by exact string, order kept). ``ValueError`` on an oversized value."""
    if notes is not None and len(notes) > MAX_NOTES_CHARS:
        raise ValueError(f"notes are at most {MAX_NOTES_CHARS} characters")
    cleaned: list[str] | None = None
    if targets is not None:
        cleaned = []
        for t in targets:
            c = _clean_target(t)
            if c is not None and c not in cleaned:
                cleaned.append(c)
        if len(cleaned) > MAX_TARGETS:
            raise ValueError(f"at most {MAX_TARGETS} targets")
    with store.conn:
        if notes is not None:
            store.conn.execute("UPDATE project SET notes=? WHERE id=1", (notes,))
        if cleaned is not None:
            store.conn.execute("UPDATE project SET targets=? WHERE id=1",
                               (json.dumps(cleaned),))


def add_target(store: Store, url: str) -> None:
    """Append ``url`` (redacted) to the project's targets unless already there or full —
    a read-modify-write under ``BEGIN IMMEDIATE`` (PA-0088(2))."""
    target = _clean_target(url)
    if target is None:
        return
    conn = store.conn
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT targets FROM project WHERE id=1").fetchone()
        if row is not None:
            current = _parse_metadata({"targets": row[0]})["targets"]
            if target not in current and len(current) < MAX_TARGETS:
                conn.execute("UPDATE project SET targets=? WHERE id=1",
                             (json.dumps(current + [target]),))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# --- launches ----------------------------------------------------------------

def insert_launch(store: Store, command: str, argv: Iterable[tuple[str, str]],
                  target: str | None) -> tuple[int, str]:
    """Record a job the UI is about to start; returns ``(launch_id, token)``. ``argv`` is
    ``(dest, text)`` pairs (``dest`` is ``""`` for a flag or the program name): each text
    is recorded through `redact_for_record` (the one boundary)."""
    token = secrets.token_hex(16)
    recorded = [redact_for_record(dest, text) for dest, text in argv]
    cur = store.conn.execute(
        "INSERT INTO launch (token, command, argv, target, status) VALUES (?,?,?,?,?)",
        (token, command, json.dumps(recorded),
         None if target is None else redact_for_record("target", target), "running"))
    store.conn.commit()
    return int(cur.lastrowid), token


def status_for(returncode: int | None, stopping: bool) -> str:
    """A finished job's status: a requested stop wins, then an unknown exit status, then
    the exit code (FR-UI-455)."""
    if stopping:
        return "stopped"
    if returncode is None:
        return "unknown"
    return "succeeded" if returncode == 0 else "failed"


def finish_launch(path: str | Path, launch_id: int, status: str,
                  exit_code: int | None) -> None:
    """Record a job's end in the project it was **pinned** to. Opens without creating:
    a project that is gone is an error the caller reports, never recreated."""
    if status not in LAUNCH_STATUSES:
        raise ValueError(f"unknown launch status {status!r}")
    with Store(path, create=False) as store:
        with store.conn:
            store.conn.execute(
                "UPDATE launch SET status=?, exit_code=?, finished_at=? WHERE id=?",
                (status, exit_code, _now(), launch_id))


def run_history(store: Store, live_launch_ids: Iterable[int] = ()) -> list[dict[str, Any]]:
    """The project's run history, newest first (FR-UI-455): one row per run, plus each
    launch that recorded no run. ``running`` is shown only for a launch that is live in
    this UI (``live_launch_ids``); any other ``running`` row reads ``unknown``."""
    live = set(live_launch_ids)
    launches = {r["id"]: dict(r) for r in store.conn.execute(
        "SELECT id, command, argv, target, started_at, finished_at, status, exit_code "
        "FROM launch")}
    for row in launches.values():
        try:
            argv = json.loads(row["argv"])
        except (ValueError, TypeError):
            argv = None
        row["argv"] = argv if isinstance(argv, list) else []
        if row["status"] == "running" and row["id"] not in live:
            row["status"] = "unknown"
    out: list[dict[str, Any]] = []
    linked: set[int] = set()
    for r in store.conn.execute(
            "SELECT r.id, r.tool, r.started_at, r.notes, r.launch_id, "
            "(SELECT base_url FROM target t WHERE t.run_id = r.id ORDER BY t.id LIMIT 1) "
            "AS base_url, "
            "(SELECT COUNT(*) FROM finding f WHERE f.run_id = r.id) AS findings, "
            "(SELECT COUNT(*) FROM candidate c WHERE c.run_id = r.id) AS candidates "
            "FROM run r ORDER BY r.id DESC"):
        launch = launches.get(r["launch_id"]) if r["launch_id"] is not None else None
        if launch is not None:
            linked.add(launch["id"])
        status = ("aborted" if is_aborted(r["notes"]) else
                  launch["status"] if launch is not None else "recorded")
        out.append({
            "run_id": r["id"], "launch_id": None if launch is None else launch["id"],
            "command": launch["command"] if launch else r["tool"],
            "argv": launch["argv"] if launch else [],
            "source": "ui" if launch else "cli",
            "target": (launch["target"] if launch and launch["target"] else
                       r["base_url"]) or "",
            "started_at": r["started_at"], "status": status,
            "findings": r["findings"], "candidates": r["candidates"],
        })
    for lid, launch in sorted(launches.items(), reverse=True):
        if lid in linked:
            continue
        out.append({"run_id": None, "launch_id": lid, "command": launch["command"],
                    "argv": launch["argv"], "source": "ui", "target": launch["target"] or "",
                    "started_at": launch["started_at"], "status": launch["status"],
                    "findings": 0, "candidates": 0})
    out.sort(key=lambda h: (h["started_at"] or "", h["run_id"] or 0), reverse=True)
    return out


# --- copying and migrating ----------------------------------------------------

def copy_to(src: str | Path, dst: str | Path) -> None:
    """Copy the project at ``src`` to the new file ``dst`` with SQLite's backup API.

    The copy goes into a hidden 0600 temporary file in ``dst``'s directory, opened in
    rollback-journal mode (the one stated exception to the central ``open_store``
    connection: a WAL destination would leave the data in a ``-wal`` that a hard link
    does not carry), is closed, checked to leave no side file, ``quick_check``\\ ed,
    fsynced, then **hard-linked** to ``dst`` — ``FileExistsError`` if ``dst`` exists —
    and the directory fsynced. A failure at any step leaves no file under ``dst``."""
    src, dst = Path(src), Path(dst)
    if dst.exists() or dst.is_symlink():
        raise FileExistsError(f"{dst} already exists")
    need = src.stat().st_size + (os.path.getsize(str(src) + "-wal")
                                 if os.path.exists(str(src) + "-wal") else 0)
    import shutil
    if shutil.disk_usage(dst.parent).free < int(need * 1.1) + 1:
        raise OSError(f"not enough free space in {dst.parent} to copy {src}")
    tmp = dst.with_name(f".copy-{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    try:
        source = sqlite3.connect(_ro_uri(src), uri=True, timeout=10.0)
        try:
            dest = sqlite3.connect(str(tmp))
            try:
                dest.execute("PRAGMA journal_mode=DELETE")
                source.backup(dest, pages=-1)
            finally:
                dest.close()
        finally:
            source.close()
        for side in ("-wal", "-journal"):
            side_path = Path(str(tmp) + side)
            if side_path.exists() and side_path.stat().st_size > 0:
                raise OSError(f"copy left a non-empty {side} file; refusing to publish it")
        check = sqlite3.connect(str(tmp))   # read-write: removes its side files on close
        try:
            result = check.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            check.close()
        if result != "ok":
            raise OSError(f"the copy failed quick_check: {result}")
        for side in ("-wal", "-shm", "-journal"):
            _unlink_if_present(Path(str(tmp) + side))
        fd = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, dst)                    # never clobbers (EEXIST)
    finally:
        for side in ("", "-wal", "-shm", "-journal"):
            _unlink_if_present(Path(str(tmp) + side))
    _fsync_dir(dst.parent)


def _unlink_if_present(p: Path) -> None:
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass


def _fsync_dir(directory: Path) -> None:
    from fuzzlab.core.secretfile import _fsync_dir as fsync_dir
    fsync_dir(directory)


def backup_path(path: str | Path, schema_version: int) -> Path:
    """Where `migrate_with_backup` writes its backup: inside the project's own directory,
    named so it is never listed as a project."""
    p = Path(path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (sidecar_dir(p) / "backups" /
            f"{p.stem}.pre-v{schema_version}-{stamp}-{secrets.token_hex(4)}.fuzzlab")


def migrate_with_backup(path: str | Path) -> tuple[Path, int]:
    """Accept the migration offer for an ``older`` project: a verified backup first
    (`copy_to`), then the migration. Returns ``(backup, new_version)``. If the backup
    fails nothing is migrated; if the migration fails the error names the version the
    file is now at and the backup (each migration is its own transaction)."""
    info = inspect(path)
    if info.state != "older":
        raise ProjectError(f"{path} is not an older-schema project ({info.state})")
    dest = backup_path(path, info.schema_version)
    for d in (dest.parent.parent, dest.parent):
        _private_dir(d)
    copy_to(path, dest)
    try:
        with Store(path, create=False) as store:
            return dest, store.schema_version()
    except Exception as exc:
        now = inspect(path).schema_version
        raise ProjectError(f"migration of {path} failed ({exc}); it is now at schema "
                           f"v{now}; the backup is at {dest}") from exc


def _private_dir(d: Path) -> None:
    """Create ``d`` 0700 if missing; refuse one that is a symlink, not a directory, not
    ours, or open to group/other."""
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ProjectError(f"{d} is not a directory")
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ProjectError(f"{d} must be owned by this user and private (mode 0700)")


def is_private(path: str | Path) -> bool:
    """Whether the main file is readable by this user only (no group/other bits)."""
    return not (os.stat(path).st_mode & 0o077)


def make_private(path: str | Path) -> None:
    """``chmod 0600`` the main file and its present side files (an explicit operator
    action for a legacy store; never done silently)."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = Path(str(path) + suffix)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode):
            os.chmod(p, 0o600)
