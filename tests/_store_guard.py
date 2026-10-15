"""The default store never leaks out of a test (FR-CORE-400, design §8).

`--store` is optional, so a test that forgets it would open ``./fuzzlab.db`` — at the
repository root that is a developer's real store (the web UI's, when started from the
checkout). Two guards:

* the session runs with ``FUZZLAB_STORE`` / ``FUZZLAB_STORE_PATH`` unset
  (:func:`pytest_configure`, before any fixture), and every test again
  (:func:`isolate_store_env`, undoing a test's own ``setenv``), so the host's settings
  never steer a test and child processes inherit the cleared environment;
* the session snapshots every ``fuzzlab.db`` (and its ``-wal``/``-shm``/``-journal``
  sidecars) in the repository tree -- minus pytest's own temp base -- and, when pytest
  runs from outside the repository, the invocation cwd's own store files (stat only,
  never a walk; BUG-0402) -- existence, size, mtime, inode -- and fails the run on any
  change: a new store anywhere in the tree, or a write to one that was already there
  (:func:`default_store_untouched`).

Tests that exercise the default ``chdir`` into ``tmp_path``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fuzzlab.core.storepath import DEFAULT_STORE, ENV_NAMES

ROOT = Path(__file__).resolve().parents[1]
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", ".pytest_cache"}
_SIDECARS = ("", "-wal", "-shm", "-journal")


def _stat(path: str):
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_size, st.st_mtime_ns, st.st_ino)


def store_files(tree, *, exclude=(), cwd=None) -> dict[str, tuple]:
    """``{path: (size, mtime_ns, inode)}`` of every default-named store file in the
    repository ``tree`` (recursive, minus ``exclude`` -- pytest's own temp base when it
    lies inside), plus ``cwd``'s own store files when given (never a walk: a cwd outside
    the repository is not ours to scan; BUG-0402). Pure; tested on its own."""
    names = {DEFAULT_STORE + s for s in _SIDECARS}
    skip = {os.path.abspath(e) for e in exclude}
    found: dict[str, tuple] = {}
    for d, dirs, files in os.walk(tree):
        dirs[:] = [x for x in dirs if x not in _SKIP_DIRS
                   and os.path.abspath(os.path.join(d, x)) not in skip]
        for f in files:
            if f in names:
                path = os.path.abspath(os.path.join(d, f))
                st = _stat(path)
                if st is not None:
                    found[path] = st
    if cwd is not None:
        for name in names:
            path = os.path.abspath(os.path.join(cwd, name))
            st = _stat(path)
            if st is not None:
                found[path] = st
    return found


def _outside_cwd() -> Path | None:
    """The invocation cwd when it is outside the repository (else None)."""
    cwd = Path.cwd().resolve()
    return None if ROOT in (cwd, *cwd.parents) else cwd


def pytest_configure(config):
    """Clear the store variables for the whole session, before any fixture (module- and
    session-scoped ones included) or child process can read them."""
    for name in ENV_NAMES:
        os.environ.pop(name, None)


@pytest.fixture(autouse=True)
def isolate_store_env(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def guard_kwargs(basetemp) -> dict:
    """What the session guard watches besides the repository tree: pytest's basetemp is
    excluded, and an outside cwd's own store files are checked (tested on its own)."""
    return {"exclude": [str(basetemp)], "cwd": _outside_cwd()}


@pytest.fixture(autouse=True, scope="session")
def default_store_untouched(tmp_path_factory):
    kwargs = guard_kwargs(tmp_path_factory.getbasetemp())
    before = store_files(ROOT, **kwargs)
    yield
    after = store_files(ROOT, **kwargs)
    changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
    if changed:
        pytest.fail("a test created or wrote a default store outside tmp_path "
                    f"(forgot --store, or did not chdir): {changed}", pytrace=False)
