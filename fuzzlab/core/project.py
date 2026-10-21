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
- This module is the one writer of ``launch`` (`insert_launch`, `finish_launch`, and
  `ensure_metadata`'s orphan reconciliation) and of ``project``; every recorded value
  goes through ``core.redaction.redact_for_record`` (PA-0100).
- `copy_to` is the only way a project is copied: the SQLite **backup API** into a
  private temporary file, verified, then hard-linked into place (never a raw copy of a
  live WAL database, never a partial file under the final name).
"""

from __future__ import annotations

import functools
import json
import os
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from fuzzlab import __version__
from fuzzlab.core import migrations
from fuzzlab.core.redaction import redact_for_record
from fuzzlab.core.runtarget import run_target_rows
from fuzzlab.core.store import Store, is_aborted, is_sqlite, open_read_only

PROJECT_EXT = ".fuzzlab"
#: A project's own directory (`sidecar_dir`): intermediates the pinned tools write
#: (crawl / audit databases, the fuzz CSV) and pre-migration backups. 0700.
SIDECAR_SUFFIX = ".d"
#: The directory inside a project's own directory that `migrate_with_backup` writes to.
BACKUPS_DIRNAME = "backups"
#: ``quick_check`` reads the whole file; above this size it is skipped (and said so).
QUICK_CHECK_MAX_BYTES = 512 * 1024 * 1024
MAX_NOTES_CHARS = 10_000
MAX_TARGETS = 50
MAX_TARGET_CHARS = 2048
MAX_NAME_CHARS = 200
#: Launch statuses (`status_for`). ``unknown``: the UI ended before the job did, or the
#: exit status could not be read.
LAUNCH_STATUSES = ("running", "succeeded", "failed", "stopped", "unknown")

def _exact_sql(sql: str | None) -> str | None:
    """A schema object's stored definition, compared **byte for byte** (BUG-0456): any
    normalisation that is not SQLite's own grammar lets two definitions that differ to
    SQLite compare equal (a U+00A0 Python reads as a space is an identifier character to
    SQLite; a newline ends a ``--`` comment). SQLite stores the ``CREATE`` text as written
    and ``ALTER … ADD COLUMN`` appends deterministically, so a legitimate store's text
    equals the reference's exactly."""
    return sql


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
        # Whether the file is SQLite is asked of SQLite (SQLITE_NOTADB), never by reading
        # its bytes: in the web process a raw open/close of a store drops every SQLite
        # lock the process holds on it (BUG-0535, FR-CORE-508).
        conn = open_read_only(p, timeout=10.0)
        try:
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, INSPECT_LENGTH_LIMIT)
            if not is_sqlite(conn):
                raise ProjectError(f"{p} is not an SQLite database")
            return _inspect_open(conn, p, st.st_size, head)
        finally:
            conn.close()
    except _REFUSED_ERRORS as exc:
        raise ProjectError(f"{p} cannot be opened as a project: {exc}") from exc


#: SQLite's own statistics tables a legitimate store may gain (``ANALYZE``), each with the
#: one definition SQLite writes for it. ``sqlite_sequence`` and ``sqlite_autoindex_*``
#: are already in the reference schema.
_SQLITE_STAT_TABLES = {
    "sqlite_stat1": "CREATE TABLE sqlite_stat1(tbl,idx,stat)",
    "sqlite_stat4": "CREATE TABLE sqlite_stat4(tbl,idx,neq,nlt,ndlt,sample)",
}

#: Bound on any string or blob an inspecting or summarising connection may build
#: (defence in depth behind the definition check, BUG-0453): the metadata row is
#: capped far below this, and counting never materialises a value.
INSPECT_LENGTH_LIMIT = 4 * 1024 * 1024
SUMMARY_LENGTH_LIMIT = 1024 * 1024


@functools.lru_cache(maxsize=None)
def reference_schema(version: int) -> dict[tuple[str, str, str], str]:
    """Every schema object fuzzlab's migrations create up to ``version``, as
    ``{(type, name, tbl_name): sql}`` (the exact stored text) — built by running those migrations in
    memory, so the allowlist is derived from the one source of truth (PA-0001)."""
    conn = sqlite3.connect(":memory:")
    try:
        # The migrations' own bootstrap: with byte-exact comparison a second copy of
        # this text would refuse every store the moment either drifted (PA-0001).
        migrations._ensure_version_table(conn)
        for v, sql in sorted(migrations.MIGRATIONS):
            if v > version:
                break
            for stmt in migrations.split_statements(sql):
                conn.execute(stmt)
        return {(t, n, tb): _exact_sql(q) for t, n, tb, q in conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master")}
    finally:
        conn.close()


def _foreign_objects(conn: sqlite3.Connection, version: int) -> list[str]:
    """Schema objects in the file that fuzzlab's migrations (at ``version``) never
    create: an **allowlist** check (BUG-0451). A row counts only if its exact
    ``(type, name, tbl_name)`` — type compared case-sensitively, as written — is in the
    reference schema **and** its definition matches the reference's byte for byte
    (BUG-0456: no normalisation), for every object including ordinary tables (BUG-0453):
    ``trusted_schema=OFF`` stops application-defined functions only, so a generated
    column, ``CHECK`` or ``DEFAULT`` added to an allowed table would otherwise run
    SQLite's own functions — without bound — on every read. Matching every definition
    is safe for legitimate stores because migrations only ``CREATE`` and
    ``ALTER … ADD COLUMN``, whose stored text is deterministic (every past version of
    the migrations was checked to build the same schema). Missing objects are fine."""
    ref = reference_schema(version)
    out = []
    for t, n, tb, q in conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master"):
        if t == "table" and n in _SQLITE_STAT_TABLES and tb == n:
            if _exact_sql(q) != _SQLITE_STAT_TABLES[n]:
                out.append(f"{t} {n} (definition changed)")
            continue
        key = (t, n, tb)
        if key not in ref:
            out.append(f"{t} {n}")
        elif _exact_sql(q) != ref[key]:
            out.append(f"{t} {n} (definition changed)")
    return sorted(out)


def _version_table_trusted(conn: sqlite3.Connection) -> bool:
    """``schema_version`` exists with exactly fuzzlab's definition — checked from
    ``sqlite_master`` alone, **before** any row of it is read (BUG-0453: a generated
    ``version`` column would otherwise run on that first read). Its definition has
    never changed, so the reference at any version holds it."""
    rows = conn.execute("SELECT type, tbl_name, sql FROM sqlite_master "
                        "WHERE name='schema_version'").fetchall()
    want = reference_schema(1)[("table", "schema_version", "schema_version")]
    return len(rows) == 1 and rows[0][0] == "table" and rows[0][1] == "schema_version" \
        and _exact_sql(rows[0][2]) == want


def _inspect_open(conn: sqlite3.Connection, p: Path, size: int, head: int) -> ProjectInfo:
    has_version_table = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='schema_version'").fetchone()[0]
    if not has_version_table:
        raise ProjectError(f"{p} is an SQLite database but not a fuzzlab store "
                           "(no schema_version table)")
    if not _version_table_trusted(conn):
        raise ProjectError(f"{p} has a schema_version table fuzzlab never creates; "
                           "refused as untrusted")
    bad = conn.execute("SELECT COUNT(*) FROM schema_version WHERE typeof(version) != "
                       "'integer' OR version < 1").fetchone()[0]
    if bad:
        raise ProjectError(f"{p} records a schema version fuzzlab never writes; "
                           "not a fuzzlab store")
    found = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
    kinds = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    if found > head:
        # A newer build's file: refused by its version, and nothing else of it is read
        # (its definitions cannot be checked against this build's migrations, BUG-0453).
        return ProjectInfo(p, size, int(found), head, application_id=app_id)
    foreign = _foreign_objects(conn, found)
    if foreign:
        raise ProjectError(
            f"{p} contains schema objects fuzzlab never creates at schema v{found} "
            f"({', '.join(foreign[:5])}{' …' if len(foreign) > 5 else ''}); "
            "refused as untrusted")
    if found and ("run" not in kinds or app_id not in (0, migrations.APPLICATION_ID)
                  or (found >= 22 and app_id != migrations.APPLICATION_ID)):
        raise ProjectError(f"{p} is another application's database (its schema or "
                           "SQLite application id is not fuzzlab's)")
    info = ProjectInfo(p, size, int(found), head, application_id=app_id)
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
                "SELECT MIN(applied_at) FROM schema_version").fetchone()[0]
            created = _text(created, 32) or now          # an untrusted value (BUG-0454)
            conn.execute(
                "INSERT INTO project (id, name, created_at, opened_at, notes, targets, "
                "created_by_version, opened_by_version, created_schema_version, uuid) "
                "VALUES (1,?,?,?,'','[]',?,?,?,?)",
                (str(name)[:MAX_NAME_CHARS], created, now, __version__, __version__,
                 migrations.current_version(conn), secrets.token_hex(16)))
        else:
            conn.execute("UPDATE project SET opened_at=?, opened_by_version=? WHERE id=1",
                         (now, __version__))
        conn.execute("UPDATE launch SET status='unknown' WHERE status='running'")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return read_metadata(store) or {}


#: The longest text any value read back from a project file is shown at: a file may
#: hold anything, of any type and size (BUG-0454).
MAX_SHOWN_CHARS = 10_000
_JSON_ERRORS = (ValueError, TypeError, RecursionError)


def _text(v: Any, cap: int = MAX_SHOWN_CHARS) -> str | None:
    """A value read from an untrusted store as text for display: a ``str`` (capped) or
    ``None`` — a BLOB, number or anything else is not fabricated into text (BUG-0454)."""
    return v[:cap] if isinstance(v, str) else None


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


_STAMP = __import__("re").compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d")


def _parse_metadata(row: dict[str, Any]) -> dict[str, Any]:
    """The one parser of a ``project`` row (PA-0108). The file is untrusted, so every
    value is typed here (BUG-0454): text fields are text or ``None``; ``targets`` must be
    a JSON list of strings, else ``[]`` with ``targets_malformed``; identity and lineage
    must have their exact shapes, else ``None`` with ``identity_malformed`` — never a
    fabricated value, never an exception."""
    out: dict[str, Any] = {k: _text(row.get(k)) for k in (
        "name", "created_at", "opened_at", "notes", "created_by_version",
        "opened_by_version")}
    out["created_schema_version"] = _int(row.get("created_schema_version"))
    out["targets_malformed"] = False
    raw = row.get("targets")
    try:
        targets = json.loads(raw) if isinstance(raw, str) and raw else \
            ([] if raw in (None, "") else None)
    except _JSON_ERRORS:
        targets = None
    if not (isinstance(targets, list) and all(isinstance(t, str) for t in targets)):
        out["targets_malformed"] = True
        targets = []
    out["targets"] = targets
    # Identity and lineage (migration 23): display only. A malformed value reads as
    # malformed (None plus a flag), never fabricated.
    out["identity_malformed"] = False
    for key in ("uuid", "origin_uuid"):
        v = row.get(key)
        if v is not None and not (isinstance(v, str) and _HEX32.fullmatch(v)):
            out["identity_malformed"] = True
            v = None
        out[key] = v
    kind, copied = row.get("copy_kind"), row.get("copied_at")
    if kind is not None and kind not in COPY_KINDS:
        out["identity_malformed"] = True
        kind = None
    if copied is not None and not (isinstance(copied, str) and _STAMP.fullmatch(copied)):
        out["identity_malformed"] = True
        copied = None
    out["copy_kind"] = kind
    out["copied_at"] = copied if kind else None
    return out


COPY_KINDS = ("snapshot", "save-as")
_HEX32 = __import__("re").compile(r"[0-9a-f]{32}")


def mark_copy(store: Store, *, kind: str, name: str, keep_identity: bool) -> None:
    """Record on a freshly published copy what it is (FR-CORE-453), in one transaction:
    its name, and — unless ``keep_identity`` (a temporary project saved: the same
    project) — a new ``uuid`` with ``origin_uuid`` (the source's), ``copied_at`` and
    ``copy_kind``."""
    if kind not in COPY_KINDS:
        raise ValueError(f"unknown copy kind {kind!r}")
    conn = store.conn
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        if keep_identity:
            conn.execute("UPDATE project SET name=? WHERE id=1", (str(name)[:MAX_NAME_CHARS],))
        else:
            conn.execute(
                "UPDATE project SET name=?, origin_uuid=uuid, uuid=?, copied_at=?, "
                "copy_kind=? WHERE id=1",
                (str(name)[:MAX_NAME_CHARS], secrets.token_hex(16), _now(), kind))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


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


def _status_label(status: str, finished_at: str | None) -> str:
    """The run history's wording for a launch status (one definition). ``unknown`` with
    no end recorded is a job whose UI ended before it did ("interrupted"); with an end
    recorded, its exit status could not be read. Residual: a second UI opening the same
    file reads a job the first UI still runs as interrupted."""
    if status == "unknown":
        return "interrupted" if finished_at is None else "unknown exit"
    return status


def run_history(store: Store, live_launch_ids: Iterable[int] = ()) -> list[dict[str, Any]]:
    """The project's run history, newest first (FR-UI-455): one row per run, plus each
    launch that recorded no run. ``running`` is shown only for a launch that is live in
    this UI (``live_launch_ids``); any other ``running`` row reads ``unknown``."""
    live = set(live_launch_ids)
    # The file is untrusted: every value is typed before use (BUG-0454) — a BLOB where
    # text belongs, a deep or odd JSON argv, an unknown status — never a 500.
    launches: dict[int, dict[str, Any]] = {}
    for r in store.conn.execute(
            "SELECT id, command, argv, target, started_at, finished_at, status, exit_code "
            "FROM launch"):
        lid = _int(r["id"])
        if lid is None:
            continue
        try:
            argv = json.loads(r["argv"]) if isinstance(r["argv"], str) else None
        except _JSON_ERRORS:
            argv = None
        if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
            argv = []
        status = r["status"] if r["status"] in LAUNCH_STATUSES else "unknown"
        if status == "running" and lid not in live:
            status = "unknown"
        finished_at = _text(r["finished_at"])
        launches[lid] = {
            "id": lid, "command": _text(r["command"]) or "", "argv": argv,
            "target": _text(r["target"]), "started_at": _text(r["started_at"]),
            "finished_at": finished_at, "status": status,
            "exit_code": _int(r["exit_code"]),
            "label": _status_label(status, finished_at)}
    out: list[dict[str, Any]] = []
    linked: set[int] = set()
    # A run's target is read through the one reader (core.runtarget, CC-UI-0501), once
    # per listing.
    targets = run_target_rows(store.conn)
    for r in store.conn.execute(
            "SELECT r.id, r.tool, r.started_at, r.notes, r.launch_id, "
            "(SELECT COUNT(*) FROM finding f WHERE f.run_id = r.id) AS findings, "
            "(SELECT COUNT(*) FROM candidate c WHERE c.run_id = r.id) AS candidates "
            "FROM run r ORDER BY r.id DESC"):
        run_id = _int(r["id"])
        if run_id is None:
            continue
        launch = launches.get(_int(r["launch_id"]))
        if launch is not None:
            linked.add(launch["id"])
        notes = _text(r["notes"])
        status = ("aborted" if notes is not None and is_aborted(notes) else
                  launch["status"] if launch is not None else "recorded")
        label = launch["label"] if launch is not None and status == launch["status"] \
            else status
        out.append({
            "run_id": run_id, "launch_id": None if launch is None else launch["id"],
            "command": launch["command"] if launch else (_text(r["tool"]) or ""),
            "argv": launch["argv"] if launch else [],
            "source": "ui" if launch else "cli",
            "target": (launch["target"] if launch and launch["target"] else
                       _text((targets.get(run_id) or {}).get("base_url"))) or "",
            "started_at": _text(r["started_at"]), "status": status, "label": label,
            "finished_at": launch["finished_at"] if launch else None,
            "findings": r["findings"], "candidates": r["candidates"],
        })
    for lid, launch in sorted(launches.items(), reverse=True):
        if lid in linked:
            continue
        out.append({"run_id": None, "launch_id": lid, "command": launch["command"],
                    "argv": launch["argv"], "source": "ui", "target": launch["target"] or "",
                    "started_at": launch["started_at"], "status": launch["status"],
                    "label": launch["label"], "finished_at": launch["finished_at"],
                    "findings": 0, "candidates": 0})
    out.sort(key=lambda h: (h["started_at"] or "", h["run_id"] or 0), reverse=True)
    return out


# --- cheap facts for listings (FR-UI-452/454) ---------------------------------------

def file_facts(path: str | Path) -> dict[str, Any]:
    """Size and last write of a project file, from ``stat`` only: size is the main file
    plus a non-empty ``-wal``; ``written_at`` is the later of the main file's mtime and a
    non-empty ``-wal``'s (never ``-shm``, which readers touch). It is the last write to
    the file — an open records its open time, and a checkpoint can show a later time,
    never an earlier one."""
    st = os.stat(path)
    size, mtime = st.st_size, st.st_mtime
    try:
        wst = os.stat(str(path) + "-wal")
        if wst.st_size > 0:
            size += wst.st_size
            mtime = max(mtime, wst.st_mtime)
    except FileNotFoundError:
        pass
    return {"size": size,
            "written_at": datetime.fromtimestamp(mtime, timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")}


#: Work a listing's summary may do per file (SQLite VM steps) before it gives up.
SUMMARY_STEP_BUDGET = 2_000_000
#: A cached summary older than this is recomputed whatever its stat key (CC-CORE-0071):
#: a commit inside the WAL's old extent within one coarse mtime tick keeps the key.
SUMMARY_MAX_AGE_S = 2.0
_summary_clock = time.monotonic                 # injectable: tests never wait on wall time
_SUMMARY_CACHE: dict[tuple, tuple[float, dict[str, Any]]] = {}
_SUMMARY_ERRORS = (sqlite3.DatabaseError, OSError)


def _stat_key(path: Path) -> tuple:
    keys = []
    for suffix in ("", "-wal"):
        try:
            st = os.stat(str(path) + suffix)
            keys.append((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns))
        except FileNotFoundError:
            keys.append(None)
    return (str(path), *keys)


def summary(path: str | Path) -> dict[str, Any]:
    """Run and finding counts for a listing row, read-only and bounded: the same
    untrusted-file allowlist as `inspect` (no ``quick_check``), a near-zero lock wait,
    and a VM-step budget; anything that fails reads ``{"readable": False}``. Cached by
    the file's and its ``-wal``'s identity, size and mtime, for at most
    `SUMMARY_MAX_AGE_S` (a coarse mtime tick can hide a commit from the key).
    Whether the file is SQLite is asked of SQLite, never read raw (BUG-0535)."""
    p = Path(path)
    try:
        key = _stat_key(p)
    except OSError:
        return {"readable": False}
    now = _summary_clock()
    cached = _SUMMARY_CACHE.get(key)
    if cached is not None and 0 <= now - cached[0] <= SUMMARY_MAX_AGE_S:
        return cached[1]
    out: dict[str, Any] = {"readable": False}
    try:
        conn = open_read_only(p, timeout=0.05)
        try:
            steps = [0]

            def budget():
                steps[0] += 100
                return steps[0] > SUMMARY_STEP_BUDGET      # non-zero aborts
            conn.set_progress_handler(budget, 100)
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, SUMMARY_LENGTH_LIMIT)
            if not is_sqlite(conn):                       # SQLITE_NOTADB: unreadable
                raise sqlite3.DatabaseError("not an SQLite database")
            if not _version_table_trusted(conn):          # before any row is read
                raise sqlite3.DatabaseError("not a fuzzlab store this build can read")
            version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            if not isinstance(version, int) or version > migrations.head_version() or \
                    _foreign_objects(conn, version):
                raise sqlite3.DatabaseError("not a fuzzlab store this build can read")
            out = {"readable": True, "schema_version": version,
                   "runs": conn.execute("SELECT COUNT(*) FROM run").fetchone()[0],
                   "findings": conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]}
        finally:
            conn.close()
    except _SUMMARY_ERRORS:
        out = {"readable": False}
    if len(_SUMMARY_CACHE) > 1000:
        _SUMMARY_CACHE.clear()
    _SUMMARY_CACHE[key] = (now, out)
    return out


# --- copying and migrating ----------------------------------------------------

def copy_to(src: str | Path, dst: str | Path, *, timeout: float = 10.0) -> None:
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
        source = open_read_only(src, timeout=timeout)    # SQLite's backup API reads it
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
    return (sidecar_dir(p) / BACKUPS_DIRNAME /
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
