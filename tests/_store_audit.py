"""A test-time audit hook: no production code opens a store's file outside SQLite
(PA-0535, BUG-0535, FR-CORE-508).

On POSIX the close of any descriptor of a file releases every ``fcntl`` lock the process
holds on it, SQLite's WAL protection included, so a raw ``open()`` of a store's main
file, ``-wal`` or ``-shm`` in a process that holds SQLite connections can let another
process delete the side files under them (DRAFT-AU-SITETREE §1.7).
`tests/test_web_store_locks.py`'s static guard reads the source; this hook watches the
process while the web tests run, so it also sees what the static guard cannot: an open
through a library, an alias, ``getattr``, a plugin or a path handed over at run time.

How it decides:

- **Which files are stores.** Every database SQLite opened in this process (the
  ``sqlite3.connect`` audit event, URIs included), and any file that has a ``-wal`` or
  ``-shm`` beside it at the time of the open (a live WAL store; ``os.path.exists`` is a
  ``stat``, never an open). A store's ``-wal``, ``-shm`` and ``-journal`` count as the store.
- **Who opened it.** The ``open`` audit event (``open()``, ``io.open``, ``os.open``,
  ``Path.open``/``read_*``/``write_*``, ``shutil``, ``zipfile``, Starlette's
  ``FileResponse``: every Python-level open) is charged to the innermost frame of the
  production package on the stack. An open with no production frame on the stack is the
  test's own (a fixture writing a corrupt file) and is not counted.
- **Reasoned allowances** are by ``(file, function)``, the same as the static guard's for
  a new inode created ``O_EXCL`` (`core.project.create`, `copy_to`).

Audit hooks cannot be removed, so one hook is installed per process (the first time a
monitor is armed) and dispatches to the monitors armed at the moment. What it cannot
see: an open in another process (a launched tool, the cross-process writers), an open by
C code that raises no audit event (SQLite's own, which is the point), and a store this
process never connected to whose side files do not exist at the time.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "fuzzlab"
SIDE = ("-wal", "-shm", "-journal")

#: ``(file relative to the repository, function)`` whose open of a store-named file is a
#: new inode it created ``O_EXCL``: no SQLite connection of any process can hold it.
ALLOWED = {
    ("fuzzlab/core/project.py", "create"),
    ("fuzzlab/core/project.py", "copy_to"),
}

_install_lock = threading.Lock()
_installed = False
_monitors: list["StoreOpenAudit"] = []
#: every database SQLite opened in this process since the hook was installed
_stores: set[str] = set()


def _real(path) -> str | None:
    try:
        name = os.fspath(path)
    except TypeError:
        return None                                   # a descriptor number
    if isinstance(name, bytes):
        name = os.fsdecode(name)
    if not name or name == ":memory:":
        return None
    return os.path.realpath(name)


def _database_path(database) -> str | None:
    """The file a ``sqlite3.connect`` argument names (a path, or a ``file:`` URI)."""
    try:
        name = os.fspath(database)
    except TypeError:
        return None
    if isinstance(name, bytes):
        name = os.fsdecode(name)
    if name.startswith("file:"):
        parts = urlsplit(name)
        name = unquote(parts.path)
        if not name or "mode=memory" in parts.query:
            return None
    return _real(name)


class StoreOpenAudit:
    """One monitor: the stores this process opened through SQLite, and every open of
    one of their files charged to production code under ``roots``."""

    def __init__(self, roots=(PACKAGE,), allowed=ALLOWED, repo=REPO):
        self.roots = tuple(str(Path(r).resolve()) + os.sep for r in roots)
        self.allowed = set(allowed)
        self.repo = str(Path(repo).resolve()) + os.sep
        self.stores: set[str] = set()
        self.found: list[str] = []

    def known(self, path: str) -> bool:
        """A store this monitor or this process opened through SQLite (two lookups, never
        a union built per open: the hook runs on every open of the test session)."""
        return path in self.stores or path in _stores

    def store_of(self, path: str) -> str | None:
        """The store ``path`` belongs to (itself, or the main file of a side file)."""
        for suffix in SIDE:
            if path.endswith(suffix) and self.known(path[: -len(suffix)]):
                return path[: -len(suffix)]
        if self.known(path):
            return path
        if any(os.path.exists(path + s) for s in ("-wal", "-shm")):
            return path                               # a live WAL store
        for suffix in ("-wal", "-shm"):
            if path.endswith(suffix) and os.path.exists(path[: -len(suffix)]):
                return path[: -len(suffix)]
        return None

    def producer(self, frame) -> tuple[str, str] | None:
        """``(file, function)`` of the innermost production frame on the stack."""
        while frame is not None:
            name = os.path.realpath(frame.f_code.co_filename)
            if name.startswith(self.roots):
                rel = name[len(self.repo):] if name.startswith(self.repo) else name
                return rel.replace(os.sep, "/"), frame.f_code.co_name
            frame = frame.f_back
        return None

    def on_open(self, path, frame) -> None:
        real = _real(path)
        if real is None:
            return
        store = self.store_of(real)
        if store is None:
            return
        who = self.producer(frame)
        if who is None or who in self.allowed:
            return
        self.found.append(f"{who[0]}::{who[1]} opened {real} outside SQLite "
                          f"(a store's file: {store})")


def _hook(event: str, args) -> None:
    if event == "open":
        if not _monitors:
            return
        frame = sys._getframe(1)
        for m in list(_monitors):
            m.on_open(args[0], frame)
    elif event == "sqlite3.connect":
        path = _database_path(args[0])
        if path is not None:
            _stores.add(path)


def install() -> None:
    """Install the process's one hook (idempotent): from then on every database SQLite
    opens is recorded, whether or not a monitor is armed."""
    global _installed
    with _install_lock:
        if not _installed:
            sys.addaudithook(_hook)
            _installed = True


def arm(monitor: StoreOpenAudit | None = None) -> StoreOpenAudit:
    """Start watching with ``monitor`` (a new production-package monitor by default)."""
    install()
    monitor = monitor or StoreOpenAudit()
    _monitors.append(monitor)
    return monitor


def disarm(monitor: StoreOpenAudit) -> list[str]:
    """Stop ``monitor``; returns what it found."""
    if monitor in _monitors:
        _monitors.remove(monitor)
    return list(monitor.found)


#: The test files the hook is armed for: the web UI's (one process holds the server, its
#: connections and the Projects listing) and the store-opening core's.
def applies(nodeid: str) -> bool:
    name = nodeid.split("::", 1)[0].rsplit("/", 1)[-1]
    return name.startswith("test_web_") or name in (
        "test_core_project.py", "test_core_store_read_only.py")
