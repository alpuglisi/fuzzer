"""Project files in the web UI: new, open, temporary, save as, snapshot, close, the
recent list, and jobs pinned to the open project (component #12, CC-UI-0450,
FR-UI-450..458).

A project is one fuzzlab store (``fuzzlab.core.project``). This module owns the UI's
lifecycle around it:

- **One open project at a time** (`ProjectManager.current`). It is set only for a file
  whose schema matches this build's (FR-UI-457): an older file is offered for migration
  (behind a verified backup) and never touched until the operator accepts; a newer or
  invalid file is refused. At startup an explicitly configured ``store_path`` (or an
  existing ``./fuzzlab.db``) is that project, so existing setups keep working; with only
  the built-in default and no such file, nothing is open and the start screen offers it
  (FR-UI-458).
- **Every existing reader follows it with no change at its call site**:
  `ProjectBoundConfig` answers ``cfg.get("store_path")`` with the open project's path, or
  ``None`` when none is open (never the caller's default, so a closed UI never writes
  ``./fuzzlab.db``). No web module opens a store that can create one: readers use
  `open_reader`, and the single creation site is `ProjectManager._create_locked`
  (``tests/test_web_projects.py`` guards this by AST).
- **Paths are confined** (NFR-UI-project-paths-confined). The browser names a project,
  never a path: a name from `NAME_RE` (or a listed file name from `FILE_RE`), placed
  directly in the projects directory, which must be owned by this user and private. The
  only other path is the operator's own configured ``store_path``. A recent-list entry is
  re-validated against those rules on every reopen.
- **Private** (NFR-UI-project-private): project files 0600, directories 0700, and
  pinned jobs run with ``umask 077`` so what a tool writes into the project's directory
  is private too.
- **Jobs pin to the project** (FR-UI-456). `pin_values` overrides every launched
  command's ``--store`` with the project and every intermediate file with the project's
  own directory, from the exhaustive `OPTION_CLASS` table. A job is recorded in the
  project's ``launch`` table and links the runs it creates (``FUZZLAB_LAUNCH_TOKEN``).
- **No switching while the project is written** (NFR-UI-project-switch-safe). One
  ``asyncio.Lock`` covers every transition and every launch, from the busy check to the
  act; a job counts as writing until its end is recorded in the project. A temporary
  project is deleted only on an explicit discard, by an exact list of the files it owns.

The projects directory is ``cfg["projects_dir"]``, else ``$FUZZLAB_PROJECTS_DIR``, else
``~/.local/share/fuzzlab/projects`` (deliberately not a ``Config`` default, which would
change every run's config hash). It is created only by an operation that needs it, never
at startup.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import re
import secrets
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from fuzzlab.core import project as core_project
from fuzzlab.core.config import Config
from fuzzlab.core.project import BACKUPS_DIRNAME, PROJECT_EXT, ProjectError, sidecar_dir
from fuzzlab.core.store import LAUNCH_TOKEN_ENV, Store

try:                                                # POSIX only
    import fcntl
except ImportError:                                 # pragma: no cover - non-POSIX
    fcntl = None

if TYPE_CHECKING:
    from fuzzlab.web.commandspec import CommandSpec
    from fuzzlab.web.runner import Runner

PROJECTS_DIR_ENV = "FUZZLAB_PROJECTS_DIR"
DEFAULT_PROJECTS_DIR = "~/.local/share/fuzzlab/projects"
TEMP_DIRNAME = ".temporary"
RECENT_FILE = "recent.json"
RECENT_MAX = 10
#: Files the Open list shows (each gets a bounded summary).
LIST_MAX = 200

#: A project name typed in the browser: ASCII letters/digits first and last, then
#: letters, digits, ``. _ -`` and spaces; at most 64 characters; no ``..``. Never a path.
NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,62}[A-Za-z0-9_-])?")
#: A file in the projects directory offered for opening: a name plus a store suffix.
FILE_RE = re.compile(NAME_RE.pattern + r"\.(?:fuzzlab|db)")
#: A temporary project's file name.
TEMP_RE = re.compile(r"tmp-\d{8}T\d{6}Z-[0-9a-f]{8}\.fuzzlab")
OWNER_LOCK = ".owner.lock"

# --- option classification (FR-UI-456; exhaustive, guarded by discovery) -------------

PIN_STORE = "pin-store"            # := the open project
PIN_SIDECAR = "pin-sidecar"        # := a file in the project's own directory
INPUT_PATH = "input-path"          # a path the operator chooses; read, not project data
OUTPUT_ELSEWHERE = "output-elsewhere"  # writes outside any project, on purpose
NOT_PATH = "not-path"

#: Every ``str`` option of every launchable spec (subcommands as ``"spec:sub"``), by
#: ``(spec, dest)``: ``(class, detail)``. ``detail`` is the sidecar file name for
#: `PIN_SIDECAR`, else the reason. ``tests/test_web_projects.py`` fails on any ``str``
#: option missing here, so a new path flag cannot silently write outside the project.
OPTION_CLASS: dict[tuple[str, str], tuple[str, str]] = {
    **{(s, "store"): (PIN_STORE, "the project") for s in (
        "crawl", "audit", "fuzz", "auto", "greybox-run", "proxy", "mutate-run", "report",
        "flow-anomaly")},
    ("crawl", "db"): (PIN_SIDECAR, "spider.db"),
    ("audit", "spider_db"): (PIN_SIDECAR, "spider.db"),
    ("auto", "spider_db"): (PIN_SIDECAR, "spider.db"),
    ("greybox-run", "spider_db"): (PIN_SIDECAR, "spider.db"),
    ("audit", "out"): (PIN_SIDECAR, "audit.db"),
    ("fuzz", "output"): (PIN_SIDECAR, "fuzz.csv"),
    ("audit", "indicator_db"): (INPUT_PATH, "packaged indicator rules, shared by design"),
    ("auto", "ground_truth"): (INPUT_PATH, "lab ground-truth directory"),
    ("auto", "disco_run"): (INPUT_PATH, "a disco capture run directory, read only"),
    ("greybox-run", "ground_truth"): (INPUT_PATH, "lab ground-truth directory"),
    ("auto", "greybox_coverage_file"): (INPUT_PATH, "the lab shim's coverage side channel"),
    ("auto", "greybox_dbfault_file"): (INPUT_PATH, "the lab shim's DB-fault side channel"),
    ("greybox-run", "cov_dir"): (INPUT_PATH, "the lab shim's coverage side channel"),
    ("mutate-run", "cov_dir"): (INPUT_PATH, "the lab shim's coverage side channel"),
    ("greybox-run", "labctl"): (INPUT_PATH, "the lab's control script"),
    ("proxy", "ca_dir"): (INPUT_PATH, "the operator's local CA, shared by design"),
    ("lab-generate", "manifest"): (INPUT_PATH, "a lab manifest"),
    ("lab-generate", "out"): (OUTPUT_ELSEWHERE, "a lab source tree, not project data"),
    ("lab-generate", "corpus_report"): (OUTPUT_ELSEWHERE, "an authoring report"),
    ("greybox-run", "app_root"): (NOT_PATH, "a path inside the lab container"),
    ("mutate-run", "app_root"): (NOT_PATH, "a path inside the lab container"),
    **{(s, d): (NOT_PATH, "") for s, d in (
        ("crawl", "start"), ("crawl", "identity"), ("crawl", "follow_selector_forms"),
        ("crawl", "submit_spa_forms"), ("audit", "identity"), ("audit", "base_url"),
        ("fuzz", "url"), ("fuzz", "param"), ("fuzz", "identity"), ("auto", "base_url"),
        ("auto", "categories"), ("auto", "identity"), ("auto", "header_points"),
        ("greybox-run", "base_url"), ("greybox-run", "identity"), ("proxy", "host"),
        ("proxy", "scope"), ("proxy", "identity"), ("mutate-run", "url"),
        ("mutate-run", "param"), ("mutate-run", "method"), ("mutate-run", "base"),
        ("mutate-run", "identity"), ("report", "run"),
        ("session:set-credential", "host"), ("session:set-credential", "identity"),
        # an origin (URL) the session may also be sent to (FR-SESS-20): not a path
        ("crawl", "auth_origin"), ("auto", "auth_origin"), ("greybox-run", "auth_origin"),
        ("session:print", "auth_origin"),
        ("session:set-credential", "username"), ("session:print", "host"),
        ("session:print", "identity"), ("session:print", "base_url"))},
}

#: The options whose value names the job's target, in preference order (recorded on the
#: launch row and added to the project's targets, redacted).
TARGET_DESTS = ("base_url", "start", "url")


def is_pinned(spec: "CommandSpec") -> bool:
    """A spec whose runs write a store: it is launched into the open project."""
    return any(OPTION_CLASS.get((spec.name, o.dest), ("",))[0] == PIN_STORE
               for o in spec.options)


def pin_values(spec: "CommandSpec", values: dict[str, Any],
               project: str | Path) -> dict[str, Any]:
    """``values`` with every `PIN_STORE` option set to ``project`` and every
    `PIN_SIDECAR` option set to its file in the project's own directory — overriding
    whatever the form sent (FR-UI-456). Other values pass through unchanged."""
    out = dict(values)
    for opt in spec.options:
        cls, detail = OPTION_CLASS.get((spec.name, opt.dest), (NOT_PATH, ""))
        if cls == PIN_STORE:
            out[opt.dest] = str(project)
        elif cls == PIN_SIDECAR:
            out[opt.dest] = str(sidecar_dir(project) / detail)
    return out


def target_of(values: dict[str, Any]) -> str | None:
    for dest in TARGET_DESTS:
        v = values.get(dest)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def record_argv(spec: "CommandSpec", values: dict[str, Any]) -> list[tuple[str, str]]:
    """The display argv as ``(dest, text)`` pairs for ``core.project.insert_launch``
    (which redacts each text by its dest): mirrors ``runner.build_flags``."""
    from fuzzlab.web.runner import build_flags
    flags = build_flags(spec, values)
    by_name = {o.name: o.dest for o in spec.options}
    out: list[tuple[str, str]] = [("", "fuzzlab"), ("", spec.name)]
    prev_dest = ""
    for item in flags:
        if item in by_name and prev_dest == "":
            out.append(("", item))
            opt = next(o for o in spec.options if o.name == item)
            prev_dest = "" if opt.type == "bool" else opt.dest
        else:
            out.append((prev_dest, item))
            prev_dest = ""
    return out


# --- the store-path view every existing reader uses ---------------------------------

@dataclass(frozen=True)
class ProjectBoundConfig(Config):
    """A `Config` whose ``store_path`` is the open project (CC-UI-0450). Its ``values``
    never hold a store path, so nothing can read a stale one."""

    manager: "ProjectManager | None" = field(default=None, compare=False, repr=False)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "store_path":
            return None if self.manager is None else self.manager.store_path()
        return super().get(key, default)

    def __getitem__(self, key: str) -> Any:
        if key == "store_path":
            return self.get("store_path")
        return super().__getitem__(key)


def open_reader(path: str | Path | None) -> Store | None:
    """A `Store` on the existing file ``path``, or ``None`` when there is none (no project,
    a project not yet created, or one just discarded). Never creates a file."""
    if path is None:
        return None
    try:
        return Store(path, create=False)
    except sqlite3.OperationalError:
        if not os.path.lexists(path):          # gone: "no store"; any other fault raises
            return None
        raise


# --- errors -----------------------------------------------------------------------

class ProjectBusy(Exception):
    """The open project is being written; it cannot be switched, saved as or closed."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("the open project is being written by: " + "; ".join(reasons))
        self.reasons = reasons


class NeedsDiscard(Exception):
    """Leaving a temporary project deletes it; the operator must say so (``discard``)."""


class NoProject(Exception):
    """No project is open (none, or one waiting for its migration to be accepted)."""


# --- state --------------------------------------------------------------------------

@dataclass
class OpenProject:
    path: Path
    kind: str = "file"                      # file | temporary
    exists: bool = True
    inode: tuple[int, int] | None = None    # temporary: (st_dev, st_ino) at creation
    owner_fd: int | None = None             # temporary: flock held while open


@dataclass
class Pending:
    """A file waiting on the operator: an older schema to migrate, or a refusal."""

    path: Path
    kind: str                               # older | refused
    detail: str
    schema_version: int = 0
    project_kind: str = "file"              # file | temporary: what it opens as


#: What `_refusal` turns into a message: file trouble and a database that cannot be read
#: (busy, locked, corrupt, not a database, a value too big) …
_REFUSAL_ERRORS = (OSError, sqlite3.OperationalError, sqlite3.DataError,
                   sqlite3.DatabaseError)
#: … but never these subclasses, which are defects in fuzzlab's own use of SQLite.
_DEFECT_ERRORS = (sqlite3.ProgrammingError, sqlite3.InterfaceError,
                  sqlite3.InternalError, sqlite3.IntegrityError, sqlite3.NotSupportedError)


def _refusal(what: str):
    """Decorate a project operation's worker: an OS or SQLite error from its file work
    (a file removed after the page rendered, no space, a corrupt database) becomes a
    `ProjectError` naming the operation — shown to the operator, never a bare 500
    (code review A, round 2). Only these two families are converted (PA-0106); any other
    exception is a defect and propagates — including SQLite's own defect classes
    (`ProgrammingError`, `InterfaceError`, `InternalError`, `IntegrityError`,
    `NotSupportedError`: a misused API or a broken invariant of ours; code review round
    3)."""
    import functools

    def wrap(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            try:
                return fn(*a, **k)
            except _REFUSAL_ERRORS as exc:
                if isinstance(exc, _DEFECT_ERRORS):
                    raise
                if isinstance(exc, FileNotFoundError):
                    detail = f"{Path(exc.filename).name if exc.filename else 'a file'} " \
                             "no longer exists (reload the page)"
                else:
                    detail = str(exc) or type(exc).__name__
                raise ProjectError(f"{what} failed: {detail}") from exc
        return inner
    return wrap


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ProjectManager:
    """The UI's one open project and its lifecycle (see the module docstring)."""

    def __init__(self, cfg: Config, runner: "Runner | None" = None) -> None:
        self.runner = runner
        configured = cfg.get("projects_dir") or os.environ.get(PROJECTS_DIR_ENV) or \
            DEFAULT_PROJECTS_DIR
        self.projects_dir = Path(os.path.abspath(os.path.expanduser(str(configured))))
        start = cfg.get("store_path")
        self.startup_path: Path | None = (Path(os.path.abspath(start)) if start else None)
        # FR-UI-458: the built-in default store (`config.DEFAULTS`) counts as configured
        # only when that file already exists; otherwise the UI starts on the start
        # screen, which offers it ("Use ./fuzzlab.db"). Any other value is the
        # operator's choice and is bound as before. `startup_path` keeps the default
        # either way (the recent list and migration rules rely on it).
        from fuzzlab.core.config import DEFAULTS
        self.default_offer: Path | None = None
        if start and start == DEFAULTS["store_path"] and not os.path.lexists(start):
            self.default_offer = self.startup_path
        self.current: OpenProject | None = None
        self.pending: Pending | None = None
        self.extra_busy: dict[str, str] = {}     # e.g. {"proxy": "the in-process proxy"}
        self.flash: list[tuple[str, str]] = []   # (level, text) for the next projects page
        self._launches: dict[str, int] = {}      # runner token -> launch id
        self._lock: asyncio.Lock | None = None
        if self.startup_path is not None and self.default_offer is None:
            self._bind_startup(self.startup_path)

    # -- basics ----------------------------------------------------------------------
    @property
    def lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def store_path(self) -> str | None:
        return None if self.current is None else str(self.current.path)

    def _bind_startup(self, path: Path) -> None:
        if not os.path.lexists(path):
            self.current = OpenProject(path, exists=False)
            return
        try:
            info = core_project.inspect(path)
        except ProjectError as exc:
            self.pending = Pending(path, "refused", str(exc))
            return
        self.current = self._prepare(path, info, kind="file")

    def _prepare(self, path: Path, info, *, kind: str, inode=None,
                 owner_fd=None) -> OpenProject | None:
        """An `OpenProject` for ``path`` if its schema is this build's (its metadata is
        then created or touched); else ``None``, with the offer or refusal recorded in
        ``pending``. Never changes ``current``."""
        if info.state == "older":
            self.pending = Pending(path, "older", "", info.schema_version,
                                   project_kind=kind)
            return None
        if info.state == "newer":
            self.pending = Pending(path, "refused",
                                   f"schema v{info.schema_version} is newer than this "
                                   f"fuzzlab's v{info.head_version}; open it with a newer "
                                   "fuzzlab", info.schema_version)
            return None
        with Store(path, create=False) as store:
            core_project.ensure_metadata(store, path.stem)
        self.pending = None
        return OpenProject(path, kind=kind, inode=inode, owner_fd=owner_fd)

    def _switch(self, new: OpenProject | None, discard: bool) -> list[str]:
        """Leave the open project (deleting a temporary one only when ``discard``; the
        caller checked busy and the discard rule), then make ``new`` current — even if
        leaving raised. Anything a discard could not remove is reported (FR-UI-453); a
        file error while leaving is reported the same way, never as a failure of the
        action that opened ``new`` (code review round 3: that action succeeded). A defect
        still propagates."""
        leave_error = None
        try:
            problems = self._leave(discard_temporary=discard)
        except _REFUSAL_ERRORS as exc:
            if isinstance(exc, _DEFECT_ERRORS):
                raise
            problems, leave_error = [], exc
        finally:
            self.current = new
        if leave_error is not None:
            self.flash.append(("warn", f"Leaving the previous project failed: {leave_error}; "
                               "check its files on the projects page."))
            return [f"leaving the previous project failed: {leave_error}"]
        if problems:
            self.flash.append(("warn", "The temporary project was discarded, but: "
                               + "; ".join(problems)))
        return problems

    def busy_reasons(self) -> list[str]:
        """What is writing the open project now (empty when nothing is)."""
        if self.current is None:
            return []
        reasons = list(self.extra_busy.values())
        if self.runner is not None:
            reasons += [f"job {cmd}" for cmd in self.runner.pinned_jobs(str(self.current.path))]
        return reasons

    def _fresh_target(self, path: Path, name: str) -> None:
        """Refuse a new project's path when anything a project owns is already there —
        its file, a SQLite side file, or its own directory (a stale ``<file>.d`` would be
        adopted, and its crawl read as this project's: PA-0450)."""
        if os.path.lexists(path):
            raise ProjectError(f"a project named {name!r} already exists; open it instead")
        for suffix in ("-wal", "-shm", "-journal"):
            if os.path.lexists(str(path) + suffix):
                raise ProjectError(f"{path.name}{suffix} is left over in the projects "
                                   "directory; remove it or choose another name")
        if os.path.lexists(sidecar_dir(path)):
            raise ProjectError(f"{sidecar_dir(path).name} already exists in the projects "
                               "directory (left by an earlier project of that name); "
                               "remove it or choose another name")

    def _check_leave(self, discard: bool) -> None:
        busy = self.busy_reasons()
        if busy:
            raise ProjectBusy(busy)
        if self.current is not None and self.current.kind == "temporary" and not discard:
            raise NeedsDiscard("leaving a temporary project deletes it")

    # -- the projects directory --------------------------------------------------------
    def _ensure_dir(self, d: Path) -> Path:
        """Create ``d`` if missing — it and each missing parent with mode 0700 — and refuse
        one that is not a private directory owned by this user (NFR-UI-project-private).
        Existing parents are left as they are."""
        missing = []
        p = d
        while not os.path.lexists(p) and p != p.parent:
            missing.append(p)
            p = p.parent
        try:
            for m in reversed(missing):
                try:
                    os.mkdir(m, 0o700)
                except FileExistsError:
                    pass
        except OSError as exc:                    # incl. ELOOP, EROFS, EACCES
            raise ProjectError(f"cannot create {d}: {exc.strerror or exc}") from exc
        if not _private_dir_ok(d):
            raise ProjectError(f"{d} must be a directory owned by this user with mode 0700")
        return d

    def _checked_dir(self) -> Path | None:
        """The projects directory if it exists and is safe to read; never creates it."""
        return self.projects_dir if _private_dir_ok(self.projects_dir) else None

    def _temp_dir(self) -> Path | None:
        """``.temporary`` if it exists and is a private directory of ours (never a link)."""
        d = self._checked_dir()
        return d / TEMP_DIRNAME if d is not None and _private_dir_ok(d / TEMP_DIRNAME) \
            else None

    def _named_path(self, name: str) -> Path:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or ".." in name:
            raise ProjectError("a project name is 1-64 letters, digits, spaces and . _ - "
                               "(starting and ending with a letter or digit)")
        return self.projects_dir / (name + PROJECT_EXT)

    def _listed_path(self, filename: str) -> Path:
        if not isinstance(filename, str) or not FILE_RE.fullmatch(filename) or \
                ".." in filename:
            raise ProjectError("not a project file name")
        return self.projects_dir / filename

    def _validate_file(self, path: Path) -> Path:
        """A path the UI may open: the operator's configured store, or a regular file of
        this user named by `FILE_RE` directly in the projects directory (neither the
        directory nor the file may be a symlink)."""
        if self.startup_path is not None and os.path.abspath(path) == str(self.startup_path):
            return self.startup_path
        if not FILE_RE.fullmatch(path.name):
            raise ProjectError("not a project file name")
        d = self._checked_dir()
        if d is None or os.path.realpath(path.parent) != os.path.realpath(d) or \
                path.parent != d:
            raise ProjectError("only files in the projects directory can be opened")
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise ProjectError(f"{path.name} is not a regular file")
        if st.st_uid != os.getuid():
            raise ProjectError(f"{path.name} is not owned by this user")
        return path

    def list_files(self) -> list[dict[str, Any]]:
        """Project files directly in the projects directory (no recursion, no links)."""
        d = self._checked_dir()
        if d is None:
            return []
        out = []
        for entry in sorted(os.scandir(d), key=lambda e: e.name.lower()):
            if not FILE_RE.fullmatch(entry.name) or not entry.is_file(follow_symlinks=False):
                continue
            if len(out) >= LIST_MAX:
                break
            try:                    # the file plus a non-empty -wal (as the chip)
                facts = core_project.file_facts(entry.path)
            except OSError:         # removed while listing
                continue
            out.append({"file": entry.name, "size": facts["size"],
                        "summary": core_project.summary(entry.path),
                        "modified": facts["written_at"],
                        "current": self.current is not None
                        and Path(entry.path) == self.current.path})
        return out

    def leftover_temporaries(self) -> list[str]:
        tdir = self._temp_dir()
        if tdir is None:
            return []
        cur = self.current.path.name if self.current and self.current.kind == "temporary" \
            else None
        return sorted(e.name for e in os.scandir(tdir)
                      if TEMP_RE.fullmatch(e.name) and e.is_file(follow_symlinks=False)
                      and e.name != cur)

    # -- the recent list -------------------------------------------------------------
    def _recent_path(self) -> Path:
        return self.projects_dir / RECENT_FILE

    def _recent_entry_path(self, recent_id, recent_path) -> Path | None:
        """The path of recent entry ``recent_id`` if it still names ``recent_path``
        (only to recognise the already-open project before the busy check); else
        ``None``. Reads the list only — never validates or opens anything."""
        if self._checked_dir() is None or not isinstance(recent_id, int):
            return None
        try:
            entries, _bad = _parse_recent(self._recent_path())
        except OSError:                    # unreadable: the worker reports it properly
            return None
        if 0 <= recent_id < len(entries) and entries[recent_id]["path"] == recent_path:
            return Path(recent_path)
        return None

    def recent(self) -> list[dict[str, Any]]:
        """The recent list, newest first; an entry whose file is gone is kept, marked."""
        d = self._checked_dir()
        if d is None:
            return []
        entries, _bad = _parse_recent(self._recent_path())
        for i, e in enumerate(entries):
            e["id"] = i
            e["exists"] = os.path.isfile(e["path"]) and not os.path.islink(e["path"])
            e["where"], e["summary"] = None, None
            if e["exists"]:
                try:
                    self._validate_file(Path(e["path"]))
                    e["summary"] = core_project.summary(e["path"])
                except (ProjectError, OSError):
                    e["where"] = "outside the projects directory"
        return entries

    def _add_recent(self, path: Path) -> None:
        from fuzzlab.core.secretfile import locked, replace_secret
        self._ensure_dir(self.projects_dir)
        rp = self._recent_path()
        with locked(rp):
            entries, _bad = _parse_recent(rp)
            try:
                st = os.stat(path)
                key = (st.st_dev, st.st_ino)
            except OSError:
                key = None
            kept = []
            for e in entries:
                try:
                    est = os.stat(e["path"])
                    same = key is not None and (est.st_dev, est.st_ino) == key
                except OSError:
                    same = False
                if not same and e["path"] != str(path):
                    kept.append(e)
            kept.insert(0, {"path": str(path), "name": path.stem,
                            "opened_at": datetime.now(timezone.utc)
                            .strftime("%Y-%m-%d %H:%M:%S")})
            data = {"version": 1, "entries": kept[:RECENT_MAX]}
            replace_secret(rp, json.dumps(data, indent=1).encode("utf-8"))

    # -- creation (the one site that may create a store) -------------------------------
    def _create_locked(self, path: Path) -> None:
        """Create a new project file: called only with the lock held (FR-UI-451)."""
        core_project.create(path, path.stem)

    @_refusal("creating the project file")
    def _ensure_created(self) -> str:
        """The open project's path, created (0600, metadata) if it does not exist yet."""
        if self.current is None:
            raise NoProject("no project is open")
        cur = self.current
        if not cur.exists:
            created = False
            if not os.path.lexists(cur.path):
                try:
                    self._create_locked(cur.path)
                    created = True
                except FileExistsError:         # created meanwhile, outside the UI
                    pass
            if created:
                cur.exists = True
            else:                               # created meanwhile (e.g. by the CLI)
                info = core_project.inspect(cur.path)
                op = self._prepare(cur.path, info, kind=cur.kind)
                self.current = op
                if op is None:
                    raise NoProject("the project file changed under the UI; see the "
                                    "projects page")
        return str(self.current.path)

    async def require_writable(self) -> str:
        """For a UI write (a saved view, a Repeater tab, the proxy's history): the open
        project's path, created first if needed. `NoProject` when none is open."""
        async with self.lock:
            return await asyncio.to_thread(self._ensure_created)

    # -- the default store (FR-UI-458) ----------------------------------------------------
    async def use_default(self, *, discard: bool = False) -> bool:
        """Open the built-in default store the start screen offers (its path comes from
        the server, never the form). Returns whether it is now the open project."""
        async with self.lock:
            self._check_leave(discard)
            return await asyncio.to_thread(self._use_default, discard)

    @_refusal("opening the default project")
    def _use_default(self, discard: bool) -> bool:
        path = self.default_offer or self.startup_path
        if path is None:
            raise ProjectError("no default project is configured")
        if not os.path.lexists(path):
            self._switch(OpenProject(path, exists=False), discard)
            self.pending = None
            return True
        op = self._prepare(path, core_project.inspect(path), kind="file")
        if op is None:
            return False
        self._switch(op, discard)
        return True

    def adopt_default(self) -> None:
        """For ``--with-proxy``: with nothing open or pending, bind the offered default
        store. The lifespan then calls `require_writable`, which **creates it at
        start-up** — the one place a built-in default is written without the start
        screen, because the operator asked for the in-process proxy, which needs a store
        before any page is opened (PA-0452(1)'s stated exception; FR-UI-458)."""
        if self.current is None and self.pending is None and self.default_offer is not None:
            self.current = OpenProject(self.default_offer, exists=False)

    # -- transitions (every one under the lock, after the busy check) ------------------
    async def new(self, name: str, *, discard: bool = False) -> bool:
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(self._new, name, discard)
            return True

    @_refusal("creating the project")
    def _new(self, name: str, discard: bool) -> None:
        path = self._named_path(name)
        self._ensure_dir(self.projects_dir)
        self._fresh_target(path, name)
        try:
            self._create_locked(path)
        except FileExistsError as exc:             # created meanwhile, outside the UI
            raise ProjectError(f"a project named {name!r} already exists") from exc
        self._switch(OpenProject(path), discard)
        self.pending = None
        self._add_recent(path)

    async def temporary(self, *, discard: bool = False) -> bool:
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(self._temporary, discard)
            return True

    @_refusal("starting a temporary project")
    def _temporary(self, discard: bool) -> None:
        tdir = self._ensure_dir(self._ensure_dir(self.projects_dir) / TEMP_DIRNAME)
        path = tdir / f"tmp-{_utc_stamp()}-{secrets.token_hex(4)}{PROJECT_EXT}"
        self._create_locked(path)
        st = os.stat(path)
        fd = None
        try:
            if os.path.lexists(sidecar_dir(path)):  # not ours (random name): refuse
                raise ProjectError(f"{sidecar_dir(path).name} already exists")
            fd = _acquire_owner(self._ensure_dir(sidecar_dir(path)))
            op = OpenProject(path, kind="temporary", inode=(st.st_dev, st.st_ino),
                             owner_fd=fd)
        except BaseException:
            _release_owner(fd)
            left = _remove_project_files(tdir, path.name, expect=(st.st_dev, st.st_ino))
            if left:
                self.flash.append(("warn", "A failed start left: " + "; ".join(left)))
            raise
        self._switch(op, discard)
        self.pending = None

    async def open(self, *, file: str | None = None, recent_id: int | None = None,
                   recent_path: str | None = None, temporary: str | None = None,
                   discard: bool = False) -> bool:
        """Open a listed file, a recent entry (its index **and** path must still match)
        or a leftover temporary. Returns whether it is now the open project (False: an
        offer or refusal is pending, or it was already open)."""
        async with self.lock:
            cur = self.current
            if cur is not None and (
                    (temporary is not None and cur.kind == "temporary"
                     and cur.path.name == temporary)
                    or (file is not None and cur.path.name == file
                        and cur.path.parent == self.projects_dir)
                    or (recent_id is not None
                        and self._recent_entry_path(recent_id, recent_path) == cur.path)):
                return False                         # already open: never a discard
            self._check_leave(discard)
            return await asyncio.to_thread(self._open, file, recent_id, recent_path,
                                           temporary, discard)

    @_refusal("opening the project")
    def _open(self, file, recent_id, recent_path, temporary, discard) -> bool:
        kind, owner_fd, inode = "file", None, None
        if temporary is not None:
            if not isinstance(temporary, str) or not TEMP_RE.fullmatch(temporary):
                raise ProjectError("not a temporary project name")
            tdir = self._temp_dir()
            if tdir is None:
                raise ProjectError("no private .temporary directory")
            path = tdir / temporary
            if self.current is not None and path == self.current.path:
                return False                        # already open
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                raise ProjectError(f"{temporary} is not a regular file of this user")
            owner_fd = _acquire_owner(self._ensure_dir(sidecar_dir(path)))
            kind, inode = "temporary", (st.st_dev, st.st_ino)
        elif recent_id is not None:
            entries = self.recent()
            if not isinstance(recent_id, int) or not 0 <= recent_id < len(entries):
                raise ProjectError("no such recent project")
            if not isinstance(recent_path, str) or entries[recent_id]["path"] != recent_path:
                raise ProjectError("the recent list changed; reload the page")
            path = self._validate_file(Path(entries[recent_id]["path"]))
        else:
            path = self._validate_file(self._listed_path(file))
        if self.current is not None and path == self.current.path:
            _release_owner(owner_fd)
            return False                            # already open
        try:
            op = self._prepare(path, core_project.inspect(path), kind=kind, inode=inode,
                               owner_fd=owner_fd)
        except BaseException:
            _release_owner(owner_fd)
            raise
        if op is None:                              # an offer or a refusal: stay put
            _release_owner(owner_fd)
            assert self.pending is not None
            self.flash.append(("warn", (
                f"{path.name} uses schema v{self.pending.schema_version}; this fuzzlab is "
                f"v{_head()}. It was not opened: review the migration offer below.")
                if self.pending.kind == "older" else
                f"{path.name} was not opened: {self.pending.detail}"))
            return False
        self._switch(op, discard)
        if kind == "file":
            self._add_recent(path)
        return True

    async def save_as(self, name: str) -> None:
        async with self.lock:
            busy = self.busy_reasons()
            if busy:
                raise ProjectBusy(busy)
            await asyncio.to_thread(self._save_as, name)

    @_refusal("save as")
    def _save_as(self, name: str) -> None:
        if self.current is None or not self.current.exists:
            raise NoProject("no project with data is open")
        dest = self._named_path(name)
        self._ensure_dir(self.projects_dir)
        self._fresh_target(dest, name)            # so everything at dest is ours below
        src = self.current.path
        try:
            core_project.copy_to(src, dest)
        except OSError as exc:                    # incl. no space, no hard links, EEXIST
            raise ProjectError(f"save as failed: {exc}") from exc
        temporary_source = self.current.kind == "temporary"
        try:
            self._copy_sidecars(src, dest)
            with Store(dest, create=False) as store:
                core_project.ensure_metadata(store, dest.stem)
                # A saved temporary project is the same project (keeps its uuid); a
                # saved copy of a file is a new one that records its origin.
                core_project.mark_copy(store, kind="save-as", name=dest.stem,
                                       keep_identity=temporary_source)
        except BaseException:
            left = _remove_project_files(dest.parent, dest.name)
            if left:
                self.flash.append(("warn", "A failed save as left: " + "; ".join(left)))
            raise
        self._switch(OpenProject(dest), True)    # a temporary source is now saved
        self._add_recent(dest)

    @staticmethod
    def _copy_sidecars(src: Path, dest: Path, *, while_busy: bool = False) -> list[str]:
        """Copy the project directory's known files (plain, singly linked files of ours)
        into the copy's own directory. ``while_busy`` (a snapshot during a job): each
        database waits at most briefly for a lock, and the fuzz CSV — possibly half
        written — is skipped; returns what was skipped."""
        skipped: list[str] = []
        sd = sidecar_dir(src)
        if not _private_dir_ok(sd):
            return skipped
        names = sorted({d for c, d in OPTION_CLASS.values() if c == PIN_SIDECAR})
        present = [n for n in names if _regular_of_ours(sd / n, single=True)]
        if not present:
            return skipped
        dd = sidecar_dir(dest)
        os.mkdir(dd, 0o700)
        for n in present:
            if n.endswith(".db"):
                try:
                    core_project.copy_to(sd / n, dd / n,
                                         timeout=0.5 if while_busy else 10.0)
                except sqlite3.OperationalError:
                    if not while_busy:
                        raise
                    skipped.append(f"{n} (in use)")
            elif while_busy:
                skipped.append(f"{n} (may be half-written while a job runs)")
            else:
                from fuzzlab.core.secretfile import create_secret
                create_secret(dd / n, (sd / n).read_bytes())
        return skipped

    # -- snapshot (FR-UI-451; research §12.2) --------------------------------------------
    async def snapshot(self) -> str:
        """A timestamped, verified copy of the open project in the projects directory;
        the project stays open. Allowed while a job runs (see `_copy_sidecars`)."""
        async with self.lock:
            return await asyncio.to_thread(self._snapshot)

    @_refusal("snapshot")
    def _snapshot(self) -> str:
        if self.current is None or not self.current.exists:
            raise NoProject("no project with data is open")
        cur = self.current
        busy = bool(self.busy_reasons())
        self._ensure_dir(self.projects_dir)
        stem = "temporary" if cur.kind == "temporary" else _grammar_stem(cur.path.stem)
        stamp = _utc_stamp()
        for n in range(1, 100):
            suffix = "" if n == 1 else f"-{n}"
            room = 64 - len(f"-snapshot-{stamp}{suffix}")
            name = f"{_trim_stem(stem, room)}-snapshot-{stamp}{suffix}"
            dest = self._named_path(name)
            try:
                self._fresh_target(dest, name)
                core_project.copy_to(cur.path, dest)
            except (ProjectError, FileExistsError):
                continue                            # taken (also by another UI): next
            break
        else:
            raise ProjectError("could not find a free snapshot name")
        try:
            skipped = self._copy_sidecars(cur.path, dest, while_busy=busy)
            with Store(dest, create=False) as store:
                core_project.ensure_metadata(store, dest.stem)
                core_project.mark_copy(store, kind="snapshot", name=dest.stem,
                                       keep_identity=False)
        except BaseException:
            left = _remove_project_files(dest.parent, dest.name)
            if left:
                self.flash.append(("warn", "A failed snapshot left: " + "; ".join(left)))
            raise
        if skipped:
            self.flash.append(("warn", f"Snapshot {dest.name}: a job is running, so it "
                               "is the project file at this moment; not copied: "
                               + ", ".join(skipped)))
        return dest.name

    # -- the recent list: remove an entry (FR-UI-452) --------------------------------------
    async def forget(self, recent_id: int, recent_path: str) -> None:
        """Remove one recent entry — matched by index **and** path, under the list's lock;
        never touches the file, never creates the projects directory."""
        async with self.lock:
            await asyncio.to_thread(self._forget, recent_id, recent_path)

    @_refusal("removing the entry")
    def _forget(self, recent_id: int, recent_path: str) -> None:
        from fuzzlab.core.secretfile import locked, replace_secret
        if self._checked_dir() is None:
            raise ProjectError("no recent list")
        rp = self._recent_path()
        with locked(rp):
            entries, _bad = _parse_recent(rp)
            if not 0 <= recent_id < len(entries) or entries[recent_id]["path"] != recent_path:
                raise ProjectError("the recent list changed; reload the page")
            del entries[recent_id]
            replace_secret(rp, json.dumps({"version": 1, "entries": entries},
                                          indent=1).encode("utf-8"))

    async def close(self, *, discard: bool = False) -> None:
        """Close the open project (a discard's leftovers are reported by `_switch`)."""
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(_refusal("closing the project")(self._switch),
                                    None, discard)

    async def discard_leftover(self, name: str, *, confirm: bool = False) -> list[str]:
        if not confirm:
            raise ProjectError(f"Tick 'delete it and its runs' to discard {name}.")
        async with self.lock:
            return await asyncio.to_thread(self._discard_leftover, name)

    @_refusal("discarding the temporary project")
    def _discard_leftover(self, name: str) -> list[str]:
        if not isinstance(name, str) or not TEMP_RE.fullmatch(name):
            raise ProjectError("not a temporary project name")
        if self.current is not None and self.current.path.name == name:
            raise ProjectError("that temporary project is open; close it instead")
        tdir = self._temp_dir()
        if tdir is None:
            raise ProjectError("no private .temporary directory")
        sd = sidecar_dir(tdir / name)
        fd = None
        if _private_dir_ok(sd):
            fd = _acquire_owner(sd)              # refuses one another UI holds open
        try:                                     # held until the files are gone
            return _remove_project_files(tdir, name)
        finally:
            _release_owner(fd)

    def _leave(self, discard_temporary: bool = False) -> list[str]:
        """Close the open project (the lock is held). A temporary one is deleted when
        ``discard_temporary`` (the caller checked the operator said so); ``current`` is
        cleared **before** any file is removed, so no reader is handed a vanishing path."""
        cur = self.current
        self.current = None
        if cur is None or cur.kind != "temporary":
            return []
        try:                     # the owner lock is held until the files are gone
            if not discard_temporary:
                return []
            return _remove_project_files(cur.path.parent, cur.path.name, expect=cur.inode)
        finally:
            _release_owner(cur.owner_fd)

    async def migrate_pending(self, *, discard: bool = False) -> str:
        """Accept the migration offer: verified backup, migrate, then open the file."""
        async with self.lock:
            if self.pending is None or self.pending.kind != "older":
                raise ProjectError("no migration is waiting")
            self._check_leave(discard)
            return await asyncio.to_thread(self._migrate_pending, discard)

    @_refusal("migrating the project")
    def _migrate_pending(self, discard: bool) -> str:
        pending = self.pending
        if pending is None or pending.kind != "older":
            raise ProjectError("no migration is waiting")
        path = pending.path
        # A leftover temporary stays temporary (code review round 3): its owner lock is
        # taken **before** anything is written, so a second UI can neither discard it
        # nor migrate it meanwhile, and it never joins the recent list.
        kind, owner_fd, inode = pending.project_kind, None, None
        if kind == "temporary":
            tdir = self._temp_dir()
            if tdir is None or path.parent != tdir or not TEMP_RE.fullmatch(path.name):
                raise ProjectError("the temporary project is no longer in .temporary")
            owner_fd = _acquire_owner(self._ensure_dir(sidecar_dir(path)))
        try:
            backup, _version = core_project.migrate_with_backup(path)
            if kind == "temporary":
                st = os.lstat(path)
                inode = (st.st_dev, st.st_ino)
            op = self._prepare(path, core_project.inspect(path), kind=kind, inode=inode,
                               owner_fd=owner_fd)
            if op is None:
                raise ProjectError(f"{path} could not be opened after migrating")
        except BaseException:
            _release_owner(owner_fd)
            raise
        self._switch(op, discard)
        if kind == "file" and path != self.startup_path:
            self._add_recent(path)
        return str(backup)

    async def dismiss_pending(self) -> None:
        """Not now / Dismiss — under the lock, so it never races a migration."""
        async with self.lock:
            self.pending = None

    async def set_meta(self, notes: str | None, targets: list[str] | None) -> None:
        async with self.lock:
            await asyncio.to_thread(self._set_meta, notes, targets)

    @_refusal("saving")
    def _set_meta(self, notes, targets) -> None:
        store = open_reader(self.store_path())
        if store is None:
            raise NoProject("the project has no data yet")
        with store:
            try:
                core_project.set_meta(store, notes=notes, targets=targets)
            except ValueError as exc:            # a bound (notes / targets length)
                raise ProjectError(str(exc)) from exc

    async def make_private(self) -> None:
        async with self.lock:
            if self.current is None or not self.current.exists:
                raise NoProject("no project file is open")
            await asyncio.to_thread(_refusal("making the file private")(
                core_project.make_private), self.current.path)

    # -- launching into the project (FR-UI-456) ---------------------------------------
    async def launch(self, spec: "CommandSpec", values: dict[str, Any],
                     argv_builder: Callable[[Any, dict], list[str]]) -> tuple[str, list[str]]:
        """Launch ``spec`` pinned to the open project; returns ``(token, argv)``. Under the
        lock from pinning to the job's registration, so no transition can interleave."""
        assert self.runner is not None
        async with self.lock:
            if self.current is None:
                raise NoProject("open or create a project first")
            path = await asyncio.to_thread(self._ensure_created)
            pinned = pin_values(spec, values, path)
            await asyncio.to_thread(self._check_sidecars, spec, pinned)
            launch_id, token_value = await asyncio.to_thread(
                self._record_launch, path, spec, pinned)

            def on_done(returncode, stopping, _path=path, _lid=launch_id):
                core_project.finish_launch(_path, _lid,
                                           core_project.status_for(returncode, stopping),
                                           returncode)
            try:
                argv = argv_builder(spec, pinned)
                env = {**os.environ, LAUNCH_TOKEN_ENV: token_value}
                token = await self.runner.launch(argv, env=env, project=path,
                                                 command=spec.name, on_done=on_done,
                                                 umask=0o077)
            except BaseException:
                await asyncio.to_thread(core_project.finish_launch, path, launch_id,
                                        "failed", None)
                raise
            self._launches[token] = launch_id
            return token, argv

    @_refusal("starting the job")
    def _check_sidecars(self, spec, pinned: dict[str, Any]) -> None:
        """Before a pinned job starts: its project directory is private and ours, and each
        intermediate file it will write (with its SQLite side files) is absent or a
        regular, singly linked file of ours — never a symlink a tool's ``open()`` would
        follow out of the project (code review B)."""
        self._ensure_dir(sidecar_dir(self.store_path() or pinned["store"]))
        for opt in spec.options:
            cls, _detail = OPTION_CLASS.get((spec.name, opt.dest), (NOT_PATH, ""))
            if cls != PIN_SIDECAR:
                continue
            for suffix in ("", "-wal", "-shm", "-journal"):
                target = Path(str(pinned[opt.dest]) + suffix)
                if os.path.lexists(target) and not _regular_of_ours(target, single=True):
                    raise ProjectError(f"{target.name} in the project directory is not a "
                                       "plain file of this user; refusing to write it")

    def live_launch_ids(self) -> list[int]:
        """Launch ids of jobs this UI is still running (or has not yet recorded)."""
        if self.runner is None:
            return []
        return [lid for tok, lid in list(self._launches.items())   # snapshot (threads)
                if self.runner.unrecorded(tok)]

    def history(self) -> list[dict[str, Any]] | None:
        """The open project's run history, or None when it has no data yet."""
        store = open_reader(self.store_path())
        if store is None:
            return None
        with store:
            return core_project.run_history(store, self.live_launch_ids())

    def metadata(self) -> dict[str, Any] | None:
        store = open_reader(self.store_path())
        if store is None:
            return None
        with store:
            meta = core_project.read_metadata(store)
            if meta is not None:
                meta["schema_version"] = store.schema_version()
            return meta

    @staticmethod
    @_refusal("recording the job")
    def _record_launch(path: str, spec, pinned: dict[str, Any]) -> tuple[int, str]:
        target = target_of(pinned)
        if target is not None and len(target) > core_project.MAX_TARGET_CHARS:
            raise ProjectError(f"the target is longer than {core_project.MAX_TARGET_CHARS} "
                               "characters")             # checked before anything is written
        with Store(path, create=False) as store:
            launch_id, token = core_project.insert_launch(
                store, spec.name, record_argv(spec, pinned), target)
            if target:
                core_project.add_target(store, target)
            return launch_id, token

    # -- views ----------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        """What every page shows about the open project (the topbar chip, banners)."""
        cur = self.current
        out: dict[str, Any] = {
            "status": "open" if cur else ("pending" if self.pending else "none"),
            "name": None, "path": None, "kind": None, "exists": False, "private": None,
            "busy": self.busy_reasons(),
            "pending": None if self.pending is None else {
                "path": str(self.pending.path), "kind": self.pending.kind,
                "detail": self.pending.detail,
                "schema_version": self.pending.schema_version,
                "head_version": _head()},
        }
        out["default_offer"] = (str(self.default_offer)
                                if cur is None and self.pending is None
                                and self.default_offer is not None else None)
        out["default_exists"] = bool(out["default_offer"]) and \
            os.path.lexists(self.default_offer)
        out["size"] = out["written_at"] = None
        if cur is not None:
            out.update(name=cur.path.stem if cur.kind == "file" else "Temporary project",
                       path=str(cur.path), kind=cur.kind, exists=cur.exists)
            if cur.exists and os.path.exists(cur.path):
                out["private"] = core_project.is_private(cur.path)
                try:
                    out.update(core_project.file_facts(cur.path))
                except OSError:
                    pass
        return out


def _head() -> int:
    from fuzzlab.core.migrations import head_version
    return head_version()


# --- the recent list's one parser (PA-0108) ----------------------------------------

RECENT_MAX_BYTES = 1_000_000


def _parse_recent(path: Path) -> tuple[list[dict[str, Any]], int]:
    """``(entries, malformed_count)``. A missing file is empty; a malformed one — not a
    regular file (a symlink is never followed), larger than `RECENT_MAX_BYTES` (never
    read past it), not JSON — or a malformed entry is skipped and counted, never
    fabricated."""
    try:
        # O_NONBLOCK: a FIFO planted at the path must not hang the page (it is refused
        # by the regular-file check below, never read).
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return [], 0
    except OSError as exc:
        if exc.errno == errno.ELOOP:              # a symlink: refused, counted
            return [], 1
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return [], 1
        raw = os.read(fd, RECENT_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > RECENT_MAX_BYTES:
        return [], 1
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):   # RecursionError: too deep
        return [], 1
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return [], 1
    out, bad = [], 0
    for e in data["entries"][:RECENT_MAX]:
        if (isinstance(e, dict) and isinstance(e.get("path"), str)
                and isinstance(e.get("name"), str) and isinstance(e.get("opened_at"), str)
                and os.path.isabs(e["path"])):
            out.append({"path": e["path"], "name": e["name"][:200],
                        "opened_at": e["opened_at"][:32]})
        else:
            bad += 1
    return out, bad


# --- temporary-project ownership and deletion ---------------------------------------

def _acquire_owner(sd: Path) -> int | None:
    """Hold an exclusive, non-blocking ``flock`` on ``<project>.d/.owner.lock`` while a
    temporary project is open, so a second UI sharing the directory cannot discard it."""
    if fcntl is None:
        return None
    fd = os.open(sd / OWNER_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise ProjectError("that temporary project is in use by another fuzzlab web")
    return fd


def _grammar_stem(stem: str) -> str:
    """A stem rewritten into `NAME_RE`'s alphabet: other characters and ``..`` runs
    become ``-``; it starts with a letter or digit; ``project`` if nothing is left."""
    out = re.sub(r"[^A-Za-z0-9._ -]+", "-", stem)
    out = re.sub(r"\.{2,}", "-", out)
    out = re.sub(r"^[^A-Za-z0-9]+", "", out)
    return out or "project"


def _trim_stem(stem: str, room: int) -> str:
    """``stem`` cut to ``room`` characters, ending with a letter, digit, ``_`` or ``-``."""
    out = stem[:max(room, 1)]
    out = re.sub(r"[^A-Za-z0-9_-]+$", "", out)
    return out or "p"


def _private_dir_ok(d: Path) -> bool:
    """``d`` is a directory (not a symlink) owned by this user with no group/other bits."""
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        return False
    return (stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)
            and st.st_uid == os.getuid() and not st.st_mode & 0o077)


def _regular_of_ours(p: Path, *, single: bool = False) -> bool:
    """``p`` is a regular file (not a symlink) owned by this user; ``single``: and has
    exactly one hard link (a second name could be outside the project)."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
            and (not single or st.st_nlink == 1))


def _release_owner(fd: int | None) -> None:
    if fd is not None:
        os.close(fd)


_SIDE = ("", "-wal", "-shm", "-journal")


def _remove_project_files(directory: Path, name: str,
                          expect: tuple[int, int] | None = None) -> list[str]:
    """Delete exactly the files a project owns — its file, that file's SQLite side
    files, and the known files of its own directory — and nothing else. Every name is
    ``lstat``-ed relative to a directory descriptor opened with ``O_NOFOLLOW``; only a
    regular file owned by this user is unlinked (a symlink or anything else is left and
    reported). ``expect`` is the main file's ``(st_dev, st_ino)`` recorded at creation.
    Returns the problems (empty when everything is gone); only a missing optional file
    is a no-op (PA-0106, PA-0110)."""
    problems: list[str] = []
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None:
            if expect is not None and (st.st_dev, st.st_ino) != expect:
                return [f"{name} is not the file this UI created; left in place"]
        for suffix in _SIDE:
            problems += _unlink_owned(dfd, name + suffix)
        sd_name = name + core_project.SIDECAR_SUFFIX
        try:
            sst = os.stat(sd_name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            sst = None
        if sst is not None:
            if not stat.S_ISDIR(sst.st_mode):
                problems.append(f"{sd_name} is not a directory; left in place")
            else:
                sfd = os.open(sd_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=dfd)
                try:
                    known = {d for c, d in OPTION_CLASS.values() if c == PIN_SIDECAR}
                    for base in sorted(known):
                        for suffix in _SIDE:
                            problems += _unlink_owned(sfd, base + suffix)
                    problems += _unlink_owned(sfd, OWNER_LOCK)
                    problems += _remove_own_backups(sfd, name)
                    leftover = os.listdir(sfd)
                finally:
                    os.close(sfd)
                if leftover:
                    problems.append(f"{sd_name} still holds {len(leftover)} unknown "
                                    "file(s); left in place")
                else:
                    os.rmdir(sd_name, dir_fd=dfd)
    finally:
        os.close(dfd)
    return problems


def _remove_own_backups(sfd: int, name: str) -> list[str]:
    """The project's own pre-migration backups (`core.project.backup_path`: exactly
    ``backups/<stem>.pre-v<N>-<UTC>-<hex8>.fuzzlab`` and its side files) — removed with
    the project, by the same owned-regular-file rule, so a discarded temporary leaves no
    copy of its data behind (code review round 4). Anything else in ``backups/`` is left,
    and the directory is removed only when empty."""
    try:
        st = os.stat(BACKUPS_DIRNAME, dir_fd=sfd, follow_symlinks=False)
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(st.st_mode):
        return [f"{BACKUPS_DIRNAME} is not a directory; left in place"]
    stem = name[:-len(PROJECT_EXT)] if name.endswith(PROJECT_EXT) else name
    own = re.compile(re.escape(stem) + r"\.pre-v\d+-\d{8}T\d{6}Z-[0-9a-f]{8}"
                     + re.escape(PROJECT_EXT) + r"(-wal|-shm|-journal)?")
    problems: list[str] = []
    bfd = os.open(BACKUPS_DIRNAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sfd)
    try:
        for entry in os.listdir(bfd):
            if own.fullmatch(entry):
                problems += _unlink_owned(bfd, entry)
        empty = not os.listdir(bfd)
    finally:
        os.close(bfd)
    if empty:
        os.rmdir(BACKUPS_DIRNAME, dir_fd=sfd)
    return problems


def _unlink_owned(dfd: int, name: str) -> list[str]:
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return []                                  # the documented no-op
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        return [f"{name} is not a regular file of this user; left in place"]
    os.unlink(name, dir_fd=dfd)
    return []

