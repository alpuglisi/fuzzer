"""The default store never leaks out of a test (FR-CORE-400, design §8).

`--store` is optional, so a test that forgets it would open ``./fuzzlab.db`` — at the
repository root that is a developer's real store (the web UI's, when started from the
checkout). Two guards:

* every test runs with ``FUZZLAB_STORE`` / ``FUZZLAB_STORE_PATH`` unset
  (:func:`isolate_store_env`), so the host's settings never steer a test, and child
  processes inherit the cleared environment;
* the session snapshots every ``fuzzlab.db`` (and its ``-wal``/``-shm``/``-journal``
  sidecars) in the repository tree and the invocation cwd — existence, size, mtime,
  inode — and fails the run on any change: a new store anywhere in the tree, or a write
  to one that was already there (:func:`default_store_untouched`).

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


def store_files(roots) -> dict[str, tuple]:
    """``{path: (size, mtime_ns, inode)}`` of every default-named store file under
    ``roots`` (pure; tested on its own)."""
    names = {DEFAULT_STORE + s for s in _SIDECARS}
    found: dict[str, tuple] = {}
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in _SKIP_DIRS]
            for f in files:
                if f in names:
                    path = os.path.join(d, f)
                    try:
                        st = os.stat(path)
                    except FileNotFoundError:
                        continue
                    found[os.path.abspath(path)] = (st.st_size, st.st_mtime_ns, st.st_ino)
    return found


def _roots() -> list[Path]:
    roots = [ROOT]
    cwd = Path.cwd().resolve()
    if ROOT not in (cwd, *cwd.parents):
        roots.append(cwd)
    return roots


@pytest.fixture(autouse=True)
def isolate_store_env(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True, scope="session")
def default_store_untouched():
    roots = _roots()
    before = store_files(roots)
    yield
    after = store_files(roots)
    changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
    if changed:
        pytest.fail("a test created or wrote a default store outside tmp_path "
                    f"(forgot --store, or did not chdir): {changed}", pytrace=False)
