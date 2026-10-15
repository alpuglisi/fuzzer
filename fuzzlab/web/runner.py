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

**Lifetime (BUG-0125, CC-UI-0053; decision BUG-0125 D18).** A launched job is tied to the UI's
life. Each child runs under :mod:`fuzzlab.procutil`'s supervisor in its own session,
so *Stop* takes its whole tree (a crawl's Playwright driver and browser, a
``labctl.sh`` compose call) and not only the direct child; the UI's shutdown stops
every live job (:meth:`Runner.shutdown`); and if the UI process dies, the supervisor
(PR_SET_PDEATHSIG, a changed parent, EOF on its control pipe) stops the job too. The
job's output is streamed to the UI over a pipe, so a job that outlived its UI would
run blind and die on its next write; an operator who wants a job to outlive the UI
runs the same command from the CLI (the dry-run preview shows it).

``allow_thread=True`` is correct only because the spawn runs on the event-loop thread
and that thread lives as long as the UI: under ``fuzzlab.web.app.serve`` the loop is
``uvicorn.run``'s, on the process's **main thread**. PR_SET_PDEATHSIG fires when the
forking thread exits, so a host that runs this loop on a shorter-lived thread (e.g.
Starlette's ``TestClient`` portal thread, which ends with the client) stops its jobs
when that thread ends -- loudly, as a ``[fuzzlab]`` line on the job's stream
(``ServerLost``), never silently (BUG-0125 D17/D18, review nit 4).
"""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
import sys
from typing import TYPE_CHECKING, Any, Callable

from fuzzlab import procutil
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

#: What a job's completion hook may raise that is reported on its stream (PA-0106).
_RECORD_ERRORS = (sqlite3.OperationalError,)        # the project file gone, or locked


class _Run:
    def __init__(self, token: str, argv: list[str], command: str = "") -> None:
        self.token = token
        self.argv = argv
        self.command = command or (argv[3] if len(argv) > 3 else "")
        # CC-UI-0450: the project a job writes (set only once its spawn succeeded) and
        # whether its end is recorded there; until then it keeps the project busy.
        self.project: str | None = None
        self.on_done: Callable[[int | None, bool], None] | None = None
        self.recorded = False
        self.pump: asyncio.Task | None = None
        self.proc: asyncio.subprocess.Process | None = None
        self.handle: procutil.ServerHandle | None = None
        self.stopping = False
        self.queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self.returncode: int | None = None  # None while running, or status unknown
        self.finished = False


class Runner:
    """Owns running child processes for one app instance (local, single-user)."""

    #: Seconds to keep reading a job's output after its supervisor exited.
    DRAIN_S = 2.0

    def __init__(self) -> None:
        self._runs: dict[str, _Run] = {}

    async def launch(self, argv: list[str], *, env: dict[str, str] | None = None,
                     project: str | None = None, command: str = "",
                     on_done: Callable[[int | None, bool], None] | None = None,
                     umask: int | None = None) -> str:
        """Start ``argv`` as a child process; return its run token.

        ``env`` is the child's complete environment (``None`` inherits this process's);
        the Lab page uses it to hand ``PFF_PROFILE`` to ``labctl.sh``.

        A job launched into a project (CC-UI-0450) passes ``project`` (it keeps that
        project busy until its end is recorded: `pinned_jobs`), ``on_done(returncode,
        stopping)`` (run off the event loop before the ``done`` event, which is always
        sent) and ``umask`` (the whole tree's file-creation mask).
        """
        token = secrets.token_hex(8)
        run = _Run(token, argv, command)
        run.on_done = on_done
        self._runs[token] = run
        run.handle = await procutil.astart_server(
            argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            allow_thread=True,  # the event-loop thread: lives as long as the UI (BUG-0125 D18)
            umask=umask,
        )
        run.project = project            # only after a successful spawn (design round 2)
        run.proc = run.handle.proc
        run.pump = asyncio.create_task(self._pump(run))
        return token

    async def _pump(self, run: _Run) -> None:
        assert run.proc is not None and run.proc.stdout is not None and run.handle is not None

        async def lines() -> None:
            async for raw in run.proc.stdout:
                await run.queue.put(("output", raw.decode(errors="replace").rstrip("\n")))

        # The output pipe is inherited by the job's descendants, so EOF can lag the
        # supervisor's exit -- forever if a descendant survives SIGKILL (D state).
        # Read until the supervisor has exited, then drain for at most DRAIN_S
        # (BUG-0125 review round 2).
        reader = asyncio.ensure_future(lines())
        try:
            code = await run.proc.wait()
            if code == procutil.CODE_UNKNOWN:  # never shown as if it were a real status
                await run.queue.put(("output", "[fuzzlab] exit status unknown: the job's "
                                               "supervisor was reaped outside fuzzlab"))
                code = None
            run.returncode = code
            run.finished = True
            try:
                await asyncio.wait_for(asyncio.shield(reader), self.DRAIN_S)
            except asyncio.TimeoutError:
                reader.cancel()
                await run.queue.put(("output", "[fuzzlab] output still held open by a "
                                               "process that outlived the job; stopped "
                                               "reading it"))
            try:
                await procutil.astop_server(run.handle)  # collects the exited supervisor
            except procutil.ServerLost as exc:  # stopped without a request: say so (loud)
                await run.queue.put(("output", f"[fuzzlab] {exc}"))
            if run.on_done is not None:
                try:
                    await asyncio.to_thread(run.on_done, run.returncode, run.stopping)
                except _RECORD_ERRORS as exc:  # the named list; anything else propagates
                    await run.queue.put(("output", "[fuzzlab] could not record the job's "
                                                   f"end in its project: {exc}"))
        finally:
            # Whatever happened above (an error, a cancellation), the job no longer
            # writes its project's record and its stream ends (code review A).
            run.finished = True
            run.recorded = True
            run.queue.put_nowait(("done", run.returncode))

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
        """Stop a still-running child's whole process tree; return whether a stop
        was requested. Non-blocking: the supervisor stops the tree, and a watchdog
        task falls back to a direct, identity-checked group kill if it does not."""
        run = self._runs.get(token)
        if run and run.handle is not None and not run.finished and not run.stopping:
            run.stopping = True
            # BUG-0130: a job's tree must never listen beyond loopback; checked while it
            # still runs, reported on its stream (the tools gate their own listeners).
            # (The report names pid and address only; the job's argv carries no secrets
            # (D12: credentials live in the keyring) -- revisit if a secret-bearing flag
            # is ever added.)
            for lst in procutil.exposed_listeners(run.handle):
                run.queue.put_nowait(("output", f"[fuzzlab] exposed beyond loopback: {lst.describe()}"))
            procutil.request_stop(run.handle)
            asyncio.get_running_loop().create_task(self._enforce_stop(run))
            return True
        return False

    async def _enforce_stop(self, run: _Run) -> None:
        assert run.handle is not None and run.proc is not None
        try:
            await asyncio.wait_for(asyncio.shield(run.proc.wait()),
                                   run.handle.grace + procutil.STOP_MARGIN_S)
        except asyncio.TimeoutError:
            try:
                await procutil.astop_server(run.handle, timeout=0.1)
            except procutil.ProcUtilError as exc:  # lost / exposed: say so on its stream
                await run.queue.put(("output", f"[fuzzlab] {exc}"))

    #: Seconds `shutdown` waits for stopped jobs to record their end in their project.
    RECORD_WAIT_S = 10.0

    async def shutdown(self) -> None:
        """Stop every live job (the UI is shutting down; BUG-0125 D18), then wait up to
        `RECORD_WAIT_S` for each to record its end (``stopped``) in its project; a job
        that does not is left ``running`` and read as ``unknown`` on the next open."""
        for run in list(self._runs.values()):
            if run.handle is not None and not run.finished:
                run.stopping = True          # its project records "stopped"
                try:
                    await procutil.astop_server(run.handle)
                except procutil.NonLoopbackListener as exc:  # BUG-0130 (ExposedAndLost too)
                    await run.queue.put(("output", f"[fuzzlab] {exc}"))
                except procutil.ServerLost:
                    pass  # already stopped without a request; reported on its stream
                except procutil.ProcUtilError as exc:  # e.g. ListenerCheckFailed: loud
                    await run.queue.put(("output", f"[fuzzlab] {exc}"))
        pumps = [r.pump for r in list(self._runs.values())
                 if r.pump is not None and not r.pump.done()]
        if pumps:
            await asyncio.wait(pumps, timeout=self.RECORD_WAIT_S)

    def known(self, token: str) -> bool:
        return token in self._runs

    def pinned_jobs(self, project: str) -> list[str]:
        """The commands of jobs still writing ``project``: spawned into it and their end
        not yet recorded there (CC-UI-0450)."""
        return [r.command for r in list(self._runs.values())     # snapshot: read from
                if r.project == project and not r.recorded]      # worker threads too

    def unrecorded(self, token: str) -> bool:
        """Whether the job ``token`` is still running or its end is not yet recorded."""
        run = self._runs.get(token)
        return run is not None and not run.recorded
