"""Project files in the web UI: new, open, temporary, save as, close, the recent list,
and jobs pinned to the open project (component #12, CC-UI-0450, FR-UI-450..457).

A project is one fuzzlab store (``fuzzlab.core.project``). This module owns the UI's
lifecycle around it:

- **One open project at a time** (`ProjectManager.current`). It is set only for a file
  whose schema matches this build's (FR-UI-457): an older file is offered for migration
  (behind a verified backup) and never touched until the operator accepts; a newer or
  invalid file is refused. At startup the configured ``store_path`` is that project, so
  existing setups keep working.
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
from fuzzlab.core.project import PROJECT_EXT, ProjectError, sidecar_dir
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


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ProjectManager:
    """The UI's one open project and its lifecycle (see the module docstring)."""

    def __init__(self, cfg: Config, runner: "Runner | None" = None) -> None:
        self.runner = runner
        configured = cfg.get("projects_dir") or os.environ.get(PROJECTS_DIR_ENV) or \
            DEFAULT_PROJECTS_DIR
        self.projects_dir = Path(os.path.expanduser(str(configured)))
        start = cfg.get("store_path")
        self.startup_path: Path | None = (Path(os.path.abspath(start)) if start else None)
        self.current: OpenProject | None = None
        self.pending: Pending | None = None
        self.extra_busy: dict[str, str] = {}     # e.g. {"proxy": "the in-process proxy"}
        self.flash: list[tuple[str, str]] = []   # (level, text) for the next projects page
        self._launches: dict[str, int] = {}      # runner token -> launch id
        self._lock: asyncio.Lock | None = None
        if self.startup_path is not None:
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
            self.pending = Pending(path, "older", "", info.schema_version)
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
        caller checked busy and the discard rule), then make ``new`` current."""
        problems = self._leave(discard_temporary=discard)
        self.current = new
        return problems

    def busy_reasons(self) -> list[str]:
        """What is writing the open project now (empty when nothing is)."""
        if self.current is None:
            return []
        reasons = list(self.extra_busy.values())
        if self.runner is not None:
            reasons += [f"job {cmd}" for cmd in self.runner.pinned_jobs(str(self.current.path))]
        return reasons

    def _check_leave(self, discard: bool) -> None:
        busy = self.busy_reasons()
        if busy:
            raise ProjectBusy(busy)
        if self.current is not None and self.current.kind == "temporary" and not discard:
            raise NeedsDiscard("leaving a temporary project deletes it")

    # -- the projects directory --------------------------------------------------------
    def _ensure_dir(self, d: Path) -> Path:
        """Create ``d`` 0700 (and its parents, 0700) if missing; refuse one that is not a
        private directory owned by this user (NFR-UI-project-private)."""
        if not os.path.lexists(d):
            os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.lstat(d)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise ProjectError(f"{d} is not a directory")
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ProjectError(f"{d} must be owned by this user with mode 0700")
        return d

    def _checked_dir(self) -> Path | None:
        """The projects directory if it exists and is safe to read; never creates it."""
        d = self.projects_dir
        if not os.path.lexists(d):
            return None
        st = os.lstat(d)
        if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
                or st.st_uid != os.getuid() or st.st_mode & 0o077):
            return None
        return d

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
        """A path the UI may open: a regular file of ours directly in the projects
        directory (no symlink anywhere in it), or the operator's configured store."""
        if self.startup_path is not None and os.path.abspath(path) == str(self.startup_path):
            return self.startup_path
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
            st = entry.stat(follow_symlinks=False)
            out.append({"file": entry.name, "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc)
                        .strftime("%Y-%m-%d %H:%M:%S"),
                        "current": self.current is not None
                        and Path(entry.path) == self.current.path})
        return out

    def leftover_temporaries(self) -> list[str]:
        d = self._checked_dir()
        if d is None or not os.path.isdir(d / TEMP_DIRNAME):
            return []
        cur = self.current.path.name if self.current and self.current.kind == "temporary" \
            else None
        return sorted(e.name for e in os.scandir(d / TEMP_DIRNAME)
                      if TEMP_RE.fullmatch(e.name) and e.is_file(follow_symlinks=False)
                      and e.name != cur)

    # -- the recent list -------------------------------------------------------------
    def _recent_path(self) -> Path:
        return self.projects_dir / RECENT_FILE

    def recent(self) -> list[dict[str, Any]]:
        """The recent list, newest first; an entry whose file is gone is kept, marked."""
        d = self._checked_dir()
        if d is None:
            return []
        entries, _bad = _parse_recent(self._recent_path())
        for i, e in enumerate(entries):
            e["id"] = i
            e["exists"] = os.path.isfile(e["path"]) and not os.path.islink(e["path"])
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

    def _ensure_created(self) -> str:
        """The open project's path, created (0600, metadata) if it does not exist yet."""
        if self.current is None:
            raise NoProject("no project is open")
        cur = self.current
        if not cur.exists:
            if os.path.lexists(cur.path):       # created meanwhile (e.g. by the CLI)
                info = core_project.inspect(cur.path)
                op = self._prepare(cur.path, info, kind=cur.kind)
                self.current = op
                if op is None:
                    raise NoProject("the project file changed under the UI; see the "
                                    "projects page")
            else:
                self._create_locked(cur.path)
                cur.exists = True
        return str(self.current.path)

    async def require_writable(self) -> str:
        """For a UI write (a saved view, a Repeater tab, the proxy's history): the open
        project's path, created first if needed. `NoProject` when none is open."""
        async with self.lock:
            return await asyncio.to_thread(self._ensure_created)

    # -- transitions (every one under the lock, after the busy check) ------------------
    async def new(self, name: str, *, discard: bool = False) -> None:
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(self._new, name, discard)

    def _new(self, name: str, discard: bool) -> None:
        path = self._named_path(name)
        self._ensure_dir(self.projects_dir)
        if os.path.lexists(path):
            raise ProjectError(f"a project named {name!r} already exists; open it instead")
        self._create_locked(path)
        self._switch(OpenProject(path), discard)
        self.pending = None
        self._add_recent(path)

    async def temporary(self, *, discard: bool = False) -> None:
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(self._temporary, discard)

    def _temporary(self, discard: bool) -> None:
        tdir = self._ensure_dir(self._ensure_dir(self.projects_dir) / TEMP_DIRNAME)
        path = tdir / f"tmp-{_utc_stamp()}-{secrets.token_hex(4)}{PROJECT_EXT}"
        self._create_locked(path)
        sd = self._ensure_dir(sidecar_dir(path))
        fd = _acquire_owner(sd)
        st = os.stat(path)
        self._switch(OpenProject(path, kind="temporary", inode=(st.st_dev, st.st_ino),
                                 owner_fd=fd), discard)
        self.pending = None

    async def open(self, *, file: str | None = None, recent_id: int | None = None,
                   temporary: str | None = None, discard: bool = False) -> None:
        async with self.lock:
            self._check_leave(discard)
            await asyncio.to_thread(self._open, file, recent_id, temporary, discard)

    def _open(self, file, recent_id, temporary, discard) -> None:
        kind, owner_fd, inode = "file", None, None
        if temporary is not None:
            if not isinstance(temporary, str) or not TEMP_RE.fullmatch(temporary):
                raise ProjectError("not a temporary project name")
            d = self._checked_dir()
            if d is None:
                raise ProjectError("no projects directory")
            path = d / TEMP_DIRNAME / temporary
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                raise ProjectError(f"{temporary} is not a regular file of this user")
            owner_fd = _acquire_owner(self._ensure_dir(sidecar_dir(path)))
            kind, inode = "temporary", (st.st_dev, st.st_ino)
        elif recent_id is not None:
            entries = self.recent()
            if not isinstance(recent_id, int) or not 0 <= recent_id < len(entries):
                raise ProjectError("no such recent project")
            path = self._validate_file(Path(entries[recent_id]["path"]))
        else:
            path = self._validate_file(self._listed_path(file))
        if self.current is not None and path == self.current.path:
            _release_owner(owner_fd)
            return                                  # already open
        try:
            op = self._prepare(path, core_project.inspect(path), kind=kind, inode=inode,
                               owner_fd=owner_fd)
        except BaseException:
            _release_owner(owner_fd)
            raise
        if op is None:                              # an offer or a refusal: stay put
            _release_owner(owner_fd)
            return
        self._switch(op, discard)
        if kind == "file":
            self._add_recent(path)

    async def save_as(self, name: str) -> None:
        async with self.lock:
            busy = self.busy_reasons()
            if busy:
                raise ProjectBusy(busy)
            await asyncio.to_thread(self._save_as, name)

    def _save_as(self, name: str) -> None:
        if self.current is None or not self.current.exists:
            raise NoProject("no project with data is open")
        dest = self._named_path(name)
        self._ensure_dir(self.projects_dir)
        if os.path.lexists(dest):
            raise ProjectError(f"a project named {name!r} already exists")
        src = self.current.path
        core_project.copy_to(src, dest)
        try:
            self._copy_sidecars(src, dest)
            with Store(dest, create=False) as store:
                core_project.ensure_metadata(store, dest.stem)
                core_project.rename(store, dest.stem)
        except BaseException:
            _remove_project_files(dest.parent, dest.name)
            raise
        self._switch(OpenProject(dest), True)    # a temporary source is now saved
        self._add_recent(dest)

    @staticmethod
    def _copy_sidecars(src: Path, dest: Path) -> None:
        sd = sidecar_dir(src)
        if not os.path.isdir(sd) or os.path.islink(sd):
            return
        names = sorted({d for c, d in OPTION_CLASS.values() if c == PIN_SIDECAR})
        present = [n for n in names if os.path.isfile(sd / n) and not os.path.islink(sd / n)]
        if not present:
            return
        dd = sidecar_dir(dest)
        os.mkdir(dd, 0o700)
        for n in present:
            if n.endswith(".db"):
                core_project.copy_to(sd / n, dd / n)
            else:
                from fuzzlab.core.secretfile import create_secret
                create_secret(dd / n, (sd / n).read_bytes())

    async def close(self, *, discard: bool = False) -> list[str]:
        """Close the open project; returns any files a discard could not remove."""
        async with self.lock:
            self._check_leave(discard)
            return await asyncio.to_thread(self._switch, None, discard)

    async def discard_leftover(self, name: str) -> list[str]:
        async with self.lock:
            return await asyncio.to_thread(self._discard_leftover, name)

    def _discard_leftover(self, name: str) -> list[str]:
        if not isinstance(name, str) or not TEMP_RE.fullmatch(name):
            raise ProjectError("not a temporary project name")
        if self.current is not None and self.current.path.name == name:
            raise ProjectError("that temporary project is open; close it instead")
        d = self._checked_dir()
        if d is None:
            raise ProjectError("no projects directory")
        tdir = d / TEMP_DIRNAME
        sd = sidecar_dir(tdir / name)
        fd = None
        if os.path.isdir(sd) and not os.path.islink(sd):
            fd = _acquire_owner(sd)              # refuses one another UI holds open
        _release_owner(fd)
        return _remove_project_files(tdir, name)

    def _leave(self, discard_temporary: bool = False) -> list[str]:
        """Close the open project (the lock is held). A temporary one is deleted when
        ``discard_temporary`` (the caller checked the operator said so); ``current`` is
        cleared **before** any file is removed, so no reader is handed a vanishing path."""
        cur = self.current
        self.current = None
        if cur is None or cur.kind != "temporary":
            return []
        _release_owner(cur.owner_fd)
        if not discard_temporary:
            return []
        return _remove_project_files(cur.path.parent, cur.path.name, expect=cur.inode)

    async def migrate_pending(self, *, discard: bool = False) -> str:
        """Accept the migration offer: verified backup, migrate, then open the file."""
        async with self.lock:
            if self.pending is None or self.pending.kind != "older":
                raise ProjectError("no migration is waiting")
            self._check_leave(discard)
            return await asyncio.to_thread(self._migrate_pending, discard)

    def _migrate_pending(self, discard: bool) -> str:
        assert self.pending is not None
        path = self.pending.path
        backup, _version = core_project.migrate_with_backup(path)
        op = self._prepare(path, core_project.inspect(path), kind="file")
        if op is None:
            raise ProjectError(f"{path} could not be opened after migrating")
        self._switch(op, discard)
        if path != self.startup_path:
            self._add_recent(path)
        return str(backup)

    def dismiss_pending(self) -> None:
        self.pending = None

    async def set_meta(self, notes: str | None, targets: list[str] | None) -> None:
        async with self.lock:
            await asyncio.to_thread(self._set_meta, notes, targets)

    def _set_meta(self, notes, targets) -> None:
        store = open_reader(self.store_path())
        if store is None:
            raise NoProject("the project has no data yet")
        with store:
            core_project.set_meta(store, notes=notes, targets=targets)

    async def make_private(self) -> None:
        async with self.lock:
            if self.current is None or not self.current.exists:
                raise NoProject("no project file is open")
            await asyncio.to_thread(core_project.make_private, self.current.path)

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
            await asyncio.to_thread(self._ensure_dir, sidecar_dir(path))
            launch_id, token_value = await asyncio.to_thread(
                self._record_launch, path, spec, pinned)
            argv = argv_builder(spec, pinned)
            env = {**os.environ, LAUNCH_TOKEN_ENV: token_value}

            def on_done(returncode, stopping, _path=path, _lid=launch_id):
                core_project.finish_launch(_path, _lid,
                                           core_project.status_for(returncode, stopping),
                                           returncode)
            try:
                token = await self.runner.launch(argv, env=env, project=path,
                                                 command=spec.name, on_done=on_done,
                                                 umask=0o077)
            except BaseException:
                await asyncio.to_thread(core_project.finish_launch, path, launch_id,
                                        "failed", None)
                raise
            self._launches[token] = launch_id
            return token, argv

    def live_launch_ids(self) -> list[int]:
        """Launch ids of jobs this UI is still running (or has not yet recorded)."""
        if self.runner is None:
            return []
        return [lid for tok, lid in self._launches.items() if self.runner.unrecorded(tok)]

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
    def _record_launch(path: str, spec, pinned: dict[str, Any]) -> tuple[int, str]:
        with Store(path, create=False) as store:
            target = target_of(pinned)
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
        if cur is not None:
            out.update(name=cur.path.stem if cur.kind == "file" else "Temporary project",
                       path=str(cur.path), kind=cur.kind, exists=cur.exists)
            if cur.exists and os.path.exists(cur.path):
                out["private"] = core_project.is_private(cur.path)
        return out


def _head() -> int:
    from fuzzlab.core.migrations import head_version
    return head_version()


# --- the recent list's one parser (PA-0108) ----------------------------------------

def _parse_recent(path: Path) -> tuple[list[dict[str, Any]], int]:
    """``(entries, malformed_count)``. A missing file is empty; a malformed one, or a
    malformed entry, is skipped and counted — never fabricated."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return [], 0
    if len(raw) > 1_000_000:
        return [], 1
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
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


def _unlink_owned(dfd: int, name: str) -> list[str]:
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return []                                  # the documented no-op
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        return [f"{name} is not a regular file of this user; left in place"]
    os.unlink(name, dir_fd=dfd)
    return []

