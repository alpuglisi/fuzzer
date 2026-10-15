"""Suite-wide pytest hooks.

BUG-0125: the session-end safety net that stops, and fails the run on, any server a
test started through ``fuzzlab.procutil`` and left running (see ``tests/_leak_guard.py``).
"""

import pytest

from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401



# --- no test creates the default store in the working directory (BUG-0452) ----------------

@pytest.fixture(scope="session", autouse=True)
def _no_default_store_in_the_working_directory():
    """The UI pins launched jobs to its project, and the built-in default project is
    `./fuzzlab.db`: a default-config test that launched a job created it in the repo
    (BUG-0452). Every test must use a private store; this fails the run if one did not."""
    import os
    from fuzzlab.core.config import DEFAULTS
    path = os.path.abspath(DEFAULTS["store_path"])
    before = os.path.lexists(path)
    yield
    if not before and os.path.lexists(path):
        pytest.fail(f"a test created the default store {path} in the working directory "
                    "(BUG-0452): give it an explicit, private store_path", pytrace=False)
