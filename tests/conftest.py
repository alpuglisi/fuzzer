"""Suite-wide pytest hooks.

BUG-0125: the session-end safety net that stops, and fails the run on, any server a
test started through ``fuzzlab.procutil`` and left running (see ``tests/_leak_guard.py``).

FR-CORE-400: no test reads or writes a default store outside ``tmp_path`` (see
``tests/_store_guard.py``).

BUG-0532: one pytest session at a time on this host; the session's controller takes the
host pytest lock before anything else (see ``tests/_pytest_lock.py``).

BUG-0535 (PA-0535): while a web test runs, no production code opens a store's file
outside SQLite (an audit hook, see ``tests/_store_audit.py``); and the site map's held
store watch (CC-UI-0068) is released after every test.
"""

import pytest

from tests import _pytest_lock
from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401
from tests._pytest_lock import pytest_unconfigure  # noqa: F401
from tests._store_guard import default_store_untouched, isolate_store_env  # noqa: F401
from tests._store_guard import pytest_configure as _clear_store_env


def pytest_configure(config):
    """First the host pytest lock (BUG-0532: waits, or refuses, while another session
    runs; xdist workers and nested sessions skip it), then the store variables are
    cleared for the whole session (FR-CORE-400)."""
    _pytest_lock.pytest_configure(config)
    _clear_store_env(config)


# --- no test creates the default store in the working directory (BUG-0452) ----------------

def _default_store_state(path: str) -> dict[str, tuple | None]:
    """``(inode, size, mtime_ns)`` of the default store, each side file and its project
    directory — ``None`` for one that does not exist."""
    import os
    out: dict[str, tuple | None] = {}
    for name in (path, path + "-wal", path + "-shm", path + "-journal", path + ".d"):
        try:
            st = os.lstat(name)
        except FileNotFoundError:
            out[name] = None
        else:
            out[name] = (st.st_ino, st.st_size, st.st_mtime_ns)
    return out


@pytest.fixture(scope="session", autouse=True)
def _no_default_store_in_the_working_directory():
    """The UI pins launched jobs to its project, and the built-in default project is
    `./fuzzlab.db`: a default-config test that launched a job created it in the repo
    (BUG-0452). Every test must use a private store; this fails the run if one created,
    changed or removed the default store, a side file of it, or its project directory —
    also when one already existed before the run (code review round 3)."""
    import os
    from fuzzlab.core.config import DEFAULTS
    path = os.path.abspath(DEFAULTS["store_path"])
    before = _default_store_state(path)
    yield
    after = _default_store_state(path)
    changed = sorted(n for n in before if before[n] != after[n])
    if changed:
        pytest.fail("a test created or changed the default store in the working "
                    f"directory ({', '.join(changed)}; BUG-0452): give it an explicit, "
                    "private store_path", pytrace=False)


# --- no store file is opened outside SQLite in a web test (BUG-0535, PA-0535) -----------

@pytest.fixture(scope="session", autouse=True)
def _store_audit_hook():
    """Install the process's audit hook before any fixture opens a store, so every
    database SQLite opens in this session is known to it (``tests/_store_audit.py``)."""
    from tests import _store_audit
    _store_audit.install()
    yield


@pytest.fixture(autouse=True)
def _no_raw_store_open(request):
    """PA-0535 at run time: for the web tests (`_store_audit.applies`), fail a test during
    which production code opened a store's main file, ``-wal`` or ``-shm`` outside SQLite
    -- through any call, library or alias the static guard
    (`tests/test_web_store_locks.py`) cannot see."""
    from tests import _store_audit
    if not _store_audit.applies(request.node.nodeid):
        yield
        return
    monitor = _store_audit.arm()
    try:
        yield
    finally:
        found = _store_audit.disarm(monitor)
    if found:
        pytest.fail("a store's file was opened outside SQLite (BUG-0535, PA-0535): "
                    + "; ".join(sorted(set(found))), pytrace=False)


# --- the site map's held store watch (CC-UI-0068) ------------------------------------------

@pytest.fixture(autouse=True)
def _release_store_watches():
    """Release the store version's held watch after every test, so no test hands the next
    one a held connection (or a descriptor on its files). Only when the web package is
    already loaded: this fixture never imports it."""
    yield
    import sys
    sitetree = sys.modules.get("fuzzlab.web.sitetree")
    if sitetree is not None:
        sitetree.release_watches()
