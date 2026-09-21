"""Deterministic lab reset between iterations: the seam and its fake.

Stateful cases (stored XSS, state-changing payloads) and coverage-novelty accounting
only stay reproducible if the lab returns to a known baseline between iterations.
`LabControl` is the seam the harness calls; the live implementation drives a fast DB
snapshot/restore via `labctl.sh` on the instrumented host (on-host, T3.5). Tests use
`FakeLabControl`, which records the calls so the harness's reset *sequencing* is
verifiable offline without a lab.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LabControl(Protocol):
    def snapshot(self, name: str = "baseline") -> None:
        """Pin the current DB state as a named baseline."""
        ...

    def reset(self, name: str = "baseline") -> None:
        """Restore the named baseline (fast; not a container rebuild)."""
        ...


class FakeLabControl:
    """Test/offline fake: records snapshot/reset calls in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def snapshot(self, name: str = "baseline") -> None:
        self.calls.append(("snapshot", name))

    def reset(self, name: str = "baseline") -> None:
        self.calls.append(("reset", name))

    @property
    def reset_count(self) -> int:
        return sum(1 for op, _ in self.calls if op == "reset")
