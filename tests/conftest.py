"""Suite-wide pytest hooks.

BUG-0125: the session-end safety net that stops, and fails the run on, any server a
test started through ``fuzzlab.procutil`` and left running (see ``tests/_leak_guard.py``).

FR-CORE-400: no test reads or writes a default store outside ``tmp_path`` (see
``tests/_store_guard.py``).
"""

from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401
from tests._store_guard import (default_store_untouched, isolate_store_env,  # noqa: F401
                                pytest_configure)
