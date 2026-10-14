"""Suite-wide pytest hooks.

BUG-0125: the session-end safety net that stops, and fails the run on, any server a
test started through ``fuzzlab.procutil`` and left running (see ``tests/_leak_guard.py``).
"""

from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401
