"""Session-end safety net for test-launched servers (BUG-0125, PA-0125, NFR-LAB-cleanup).

Every server a test starts goes through :func:`fuzzlab.procutil.start_server`, which
records it in an in-process registry. At the end of the session this plugin stops any
registered server that is still live -- identity-checked by pid and ``/proc`` start
time, never by name or pattern (the operator's own labs run on the same machine) -- and
**fails the session**, naming each leaked server's argv, pid and age. A leak is then a
visible failure at the end of the run that caused it, not a silent OOM hours later.

Loaded by ``tests/conftest.py``; ``tests/test_procutil.py`` proves it on a deliberately
leaked server in a separate pytest process.
"""

from __future__ import annotations

import pytest

from fuzzlab import procutil

_LEAKS: list[procutil.Leak] = []


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    leaks = procutil.reap_registered()
    if leaks:
        _LEAKS.extend(leaks)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus: int, config: pytest.Config) -> None:
    if not _LEAKS:
        return
    terminalreporter.section("BUG-0125: servers left running at session end (stopped now)",
                             sep="!", red=True, bold=True)
    for leak in _LEAKS:
        terminalreporter.write_line(f"LEAKED SERVER {leak.describe()}")
