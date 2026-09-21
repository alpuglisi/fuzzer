"""Subprocess runner for the launcher (Phase 0.3).

Turns a :class:`~fuzzlab.web.commandspec.CommandSpec` plus user-supplied flag
values into an argv, and runs it as a child process with its output streamed over
SSE. Two safety properties by construction:

* **Only declared flags reach argv.** ``build_flags`` emits a flag only for an
  option the spec declares; unknown keys in ``values`` are ignored, so the UI
  cannot inject arbitrary arguments.
* **No shell.** The child is launched with ``create_subprocess_exec`` (argv list,
  never a shell string), so values are passed as literal arguments — no shell
  interpolation.

Traffic gating (``authorized`` / ``sends_traffic``) is enforced by the caller (the
route), mirroring automatic mode; a dry run builds the argv but never executes.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
from typing import TYPE_CHECKING, Any

from fuzzlab.web.sse import format_event

if TYPE_CHECKING:
    from fuzzlab.web.commandspec import CommandSpec


# --- argv construction (pure) ----------------------------------------------

def build_flags(spec: "CommandSpec", values: dict[str, Any]) -> list[str]:
    """Build the flag portion of argv from ``values``, keyed by option ``dest``.

    - bool option → the flag appears iff the value is truthy;
    - repeatable (``append``) option → one ``--flag value`` per list item;
    - other options → ``--flag value`` unless the value is ``None``/empty (then
      the tool's own default applies).
    Only options declared by the spec are considered.
    """
    args: list[str] = []
    for opt in spec.options:
        if opt.dest not in values:
            continue
        val = values[opt.dest]
        if opt.type == "bool":
            if val:
                args.append(opt.name)
        elif opt.multiple:
            items = val if isinstance(val, (list, tuple)) else [val]
            for item in items:
                if item is None or item == "":
                    continue
                args += [opt.name, str(item)]
        else:
            if val is None or val == "":
                continue
            args += [opt.name, str(val)]
    return args


def build_argv(spec: "CommandSpec", values: dict[str, Any],
               *, python: str | None = None) -> list[str]:
    """Full argv: ``python -m fuzzlab.cli <name> <flags>`` (mirrors the real CLI)."""
    return [python or sys.executable, "-m", "fuzzlab.cli", spec.name,
            *build_flags(spec, values)]


def display_command(spec: "CommandSpec", values: dict[str, Any]) -> str:
    """Human-readable command for the dry-run preview (``fuzzlab <name> <flags>``)."""
    return " ".join(["fuzzlab", spec.name, *build_flags(spec, values)])


# --- live execution --------------------------------------------------------

class _Run:
    def __init__(self, token: str, argv: list[str]) -> None:
        self.token = token
        self.argv = argv
        self.proc: asyncio.subprocess.Process | None = None
        self.queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self.returncode: int | None = None


class Runner:
    """Owns running child processes for one app instance (local, single-user)."""

    def __init__(self) -> None:
        self._runs: dict[str, _Run] = {}

    async def launch(self, argv: list[str]) -> str:
        """Start ``argv`` as a child process; return its run token."""
        token = secrets.token_hex(8)
        run = _Run(token, argv)
        self._runs[token] = run
        run.proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.create_task(self._pump(run))
        return token

    async def _pump(self, run: _Run) -> None:
        assert run.proc is not None and run.proc.stdout is not None
        async for raw in run.proc.stdout:
            await run.queue.put(("output", raw.decode(errors="replace").rstrip("\n")))
        run.returncode = await run.proc.wait()
        await run.queue.put(("done", run.returncode))

    async def stream(self, token: str):
        """Yield SSE events for a run: ``output`` lines, then a ``done`` event."""
        run = self._runs.get(token)
        if run is None:
            yield format_event({"error": "unknown run"}, event="error")
            return
        while True:
            kind, payload = await run.queue.get()
            if kind == "output":
                yield format_event(payload, event="output")
            else:  # done
                yield format_event({"returncode": payload}, event="done")
                return

    def stop(self, token: str) -> bool:
        """Terminate a still-running child; return whether a signal was sent."""
        run = self._runs.get(token)
        if run and run.proc is not None and run.returncode is None:
            run.proc.terminate()
            return True
        return False

    def known(self, token: str) -> bool:
        return token in self._runs
