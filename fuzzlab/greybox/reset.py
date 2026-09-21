"""Deterministic lab reset between iterations: the seam and its fake.

Stateful cases (stored XSS, state-changing payloads) and coverage-novelty accounting
only stay reproducible if the lab returns to a known baseline between iterations.
`LabControl` is the seam the harness calls; the live implementation drives a fast DB
snapshot/restore via `labctl.sh` on the instrumented host (on-host, T3.5). Tests use
`FakeLabControl`, which records the calls so the harness's reset *sequencing* is
verifiable offline without a lab.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Protocol, runtime_checkable


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


class LabControlError(RuntimeError):
    """Raised when the labctl snapshot/restore command fails (fail loud)."""


class ScriptLabControl:
    """Live control: drives `labctl.sh snapshot`/`restore` on the instrumented host.

    ``snapshot(name)`` runs ``<script> snapshot <name>`` and ``reset(name)`` runs
    ``<script> restore <name>`` — a fast DB snapshot/restore, not a container rebuild
    (T3.5). The subprocess runner is injectable so the sequencing is unit-testable
    without a shell; the default uses ``subprocess.run(check=True)`` and raises
    :class:`LabControlError` on a non-zero exit so a failed reset never silently
    leaves a dirty DB.
    """

    def __init__(self, script_path: str | Path,
                 runner: Callable[[list[str]], object] | None = None):
        self._script = str(Path(script_path))
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(cmd: list[str]) -> object:
        import subprocess
        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def _run(self, *args: str) -> None:
        cmd = [self._script, *args]
        try:
            self._runner(cmd)
        except Exception as exc:  # noqa: BLE001 - surface any runner failure uniformly
            raise LabControlError(f"labctl command failed: {' '.join(cmd)}: {exc}") from exc

    def snapshot(self, name: str = "baseline") -> None:
        self._run("snapshot", name)

    def reset(self, name: str = "baseline") -> None:
        self._run("restore", name)
