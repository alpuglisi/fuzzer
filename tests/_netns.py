"""Run a deliberately exposed test server inside a private network namespace
(BUG-0130 follow-up).

A test that must prove a wildcard listener is caught (`0.0.0.0`, `::`) never binds it
in the host's network namespace -- CLAUDE.md: the lab is never exposed, however
briefly. `private_netns(argv)` prefixes `unshare -rn` (a new user namespace, so no
privilege is needed, and a new network namespace whose only interface is its own
loopback): nothing in it can be reached from outside.

If `unshare -rn` does not work here, the test skips -- or, with
`FUZZLAB_REQUIRE_NETNS=1`, fails. It never falls back to a host-namespace bind.
`tests/test_loopback_listeners.py` enforces that every wildcard bind in `tests/` goes
through this helper.
"""

from __future__ import annotations

import functools
import os
import subprocess

import pytest

from fuzzlab import procutil

UNSHARE = ("unshare", "-rn")


@functools.lru_cache(maxsize=1)
def netns_available() -> bool:
    """Probe the real operation (PA-0035): run a program under `unshare -rn` and check
    it really is in a different network namespace."""
    try:
        r = procutil.run_bounded(
            [*UNSHARE, "readlink", "/proc/self/ns/net"], timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() not in ("", os.readlink("/proc/self/ns/net"))


def private_netns(argv: list[str]) -> list[str]:
    """``argv`` run inside a private network namespace; skips (or fails under
    ``FUZZLAB_REQUIRE_NETNS=1``) when that is not possible."""
    if not netns_available():
        reason = "unshare -rn (an unprivileged private network namespace) is unavailable"
        if os.environ.get("FUZZLAB_REQUIRE_NETNS"):
            pytest.fail(f"{reason} (FUZZLAB_REQUIRE_NETNS=1)")
        pytest.skip(reason)
    return [*UNSHARE, *argv]
