"""Suite-wide pytest hooks.

BUG-0125: the session-end safety net that stops, and fails the run on, any server a
test started through ``fuzzlab.procutil`` and left running (see ``tests/_leak_guard.py``).

FR-CORE-400: no test reads or writes a default store outside ``tmp_path`` (see
``tests/_store_guard.py``).

BUG-0532: one pytest session at a time on this host; the session's controller takes the
host pytest lock before anything else (see ``tests/_pytest_lock.py``).
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
