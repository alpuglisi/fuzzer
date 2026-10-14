"""Process-tree ownership for every long-lived process the toolkit or its tests start
(``BUG-0125``, ``PA-0125``, ``FR-CORE-38``).

**Why this exists.** A live-boot harness started ``php artisan serve``, which spawns a
child ``php -S``; ``close()`` killed only the ``artisan`` parent, so the child was
re-parented to init and kept its port and memory. Nothing tied any test-launched
server (or its grandchildren: ``go run``, ``bundle exec``/puma, ``mvn``, artisan) to
its owner's life either, so a killed pytest left everything it started running. 429
orphaned servers (~14 GB) OOM-killed later suite runs.

**The model.** :func:`start_server` never starts the real program as its own child.
It starts a small **supervisor** (this file, run as a script by
``sys.executable -I -S``; stdlib only) in a **new session**, and the supervisor:

1. sets ``PR_SET_PDEATHSIG(SIGTERM)`` and ``PR_SET_CHILD_SUBREAPER`` on itself
   (``prctl`` through ``ctypes``; Linux only -- unavailable is a loud
   :class:`SupervisorUnavailable`, never a silent downgrade);
2. re-checks ``os.getppid()`` against the owner pid it was given and exits if the
   owner already died (closes the owner-died-before-``prctl`` race);
3. starts the real program in a **new process group** (pgid == the server's pid),
   raising the server's ``oom_score_adj`` above its own (an unprivileged increase), so
   a cgroup OOM picks servers before their supervisors (BUG-0125 D16);
4. on a stop request, an unrequested ``SIGTERM`` (handler idempotent), owner death
   (PDEATHSIG, a changed ``getppid()``, or EOF on the owner's control pipe), or the
   server's own exit: signals the server's group, then every descendant re-parented to
   it (it is a subreaper, so double-forked grandchildren land on it), waits a grace
   period, ``SIGKILL``\\ s whatever is left, reaps, and exits.

The supervisor is single-threaded, so it may use ``preexec_fn`` for the server
(``setpgid`` + ``PDEATHSIG(SIGKILL)`` + ``oom_score_adj``). The **owner** never does:
``preexec_fn`` is unsafe in a threaded process.

**Identity.** Nothing here kills by name or pattern -- the operator's own labs (bWAPP,
Juice Shop) run on the same machine. Every signal goes to a process we recorded, by a
``pidfd`` where the platform has one, after re-reading ``/proc/<pid>/stat`` and
matching its start time (field 22) against the value recorded at start; a process
group or session is signalled member by member, only when its leader pid is absent or
still has the recorded start time, and only members started no earlier than the
leader. A reused pid is therefore never signalled.

**Threads (BUG-0125 D12; allow_thread, D17).** ``PR_SET_PDEATHSIG`` fires when the *thread* that forked the
supervisor exits, not only when the owner process does. :func:`start_server` therefore
refuses to run off the main thread unless ``allow_thread=True``. With
``allow_thread=True`` the server **dies when the forking thread ends**; that is loud,
not silent: the supervisor writes a ``fuzzlab.procutil:`` line to its stderr and
records ``reason=signal``, and :func:`stop_server` / :func:`finish` raise
:class:`ServerLost`. Use it only where the forking thread lives as long as the server
must (an event-loop thread that owns its children, or a call that blocks until the
child ends, as :func:`run_bounded` does).

This module is a stdlib-only leaf: it imports nothing from ``fuzzlab`` (so labgen,
whose import guard allows exactly this one module beyond itself and the label
contract, may use it) and nothing outside the standard library.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno as _errno
import os
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

__all__ = [
    "DEFAULT_GRACE_S",
    "ProcStat",
    "ProcUtilError",
    "ServerHandle",
    "ServerLost",
    "SupervisorUnavailable",
    "Leak",
    "arun_bounded",
    "astart_server",
    "astop_server",
    "finish",
    "group_members",
    "kill_process_group",
    "is_live",
    "read_stat",
    "reap_registered",
    "registered",
    "request_stop",
    "run_bounded",
    "session_members",
    "start_server",
    "stop_server",
]

#: Seconds the supervisor waits after SIGTERM before SIGKILL.
DEFAULT_GRACE_S = 5.0
#: Seconds the owner waits for the supervisor's ``ready`` line.
READY_TIMEOUT_S = 20.0
#: Seconds the supervisor keeps re-sending SIGKILL before giving up on a descendant.
KILL_BOUND_S = 5.0
#: Extra seconds :func:`stop_server` allows beyond the grace before its fallback (BUG-0125 D15).
STOP_MARGIN_S = KILL_BOUND_S + 2.0
#: How much the server's ``oom_score_adj`` is raised above the supervisor's (BUG-0125 D16).
OOM_SCORE_ADJ_RAISE = 500

PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36

_SUPERVISOR_SCRIPT = os.path.abspath(__file__)
_STOP_TOKEN = b"stop\n"


class ProcUtilError(RuntimeError):
    """A process could not be started or stopped as this module promises."""


class SupervisorUnavailable(ProcUtilError):
    """The platform lacks a capability the supervisor requires (``prctl``)."""


class ServerLost(ProcUtilError):
    """The supervisor stopped its server without a stop request from its owner
    (``reason=signal``): e.g. PDEATHSIG after the forking thread exited
    (``allow_thread=True``), or an external SIGTERM."""


# --- /proc ------------------------------------------------------------------

@dataclass(frozen=True)
class ProcStat:
    pid: int
    ppid: int
    pgid: int
    sid: int
    #: ``/proc/<pid>/stat`` field 22: start time in clock ticks since boot.
    start: int
    state: str


def read_stat(pid: int) -> ProcStat | None:
    """Parse ``/proc/<pid>/stat``; ``None`` if the process does not exist."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except (FileNotFoundError, ProcessLookupError):  # gone, or vanished mid-read
        return None
    # comm (field 2) may contain spaces and parentheses: split after the last ')'.
    rest = data[data.rindex(b")") + 2:].split()
    return ProcStat(pid=pid, ppid=int(rest[1]), pgid=int(rest[2]), sid=int(rest[3]),
                    start=int(rest[19]), state=rest[0].decode("ascii", "replace"))


def _iter_stats() -> Iterator[ProcStat]:
    for name in os.listdir("/proc"):
        if name.isdigit():
            st = read_stat(int(name))
            if st is not None:
                yield st


def _signal_checked(pid: int, start: int, sig: int) -> bool:
    """Send ``sig`` to ``pid`` only if it is still the process that started at
    ``start``. Opens a pidfd first (where available), so the identity check and the
    signal refer to the same process even if the pid is reused in between."""
    fd: int | None = None
    if hasattr(os, "pidfd_open"):
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            return False
        except OSError as exc:  # kernel without pidfd: fall back to kill(2) below
            if exc.errno != _errno.ENOSYS:
                raise
    try:
        st = read_stat(pid)
        if st is None or st.start != start:
            return False
        try:
            if fd is not None:
                signal.pidfd_send_signal(fd, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError:
            return False
        return True
    finally:
        if fd is not None:
            os.close(fd)


def _members(kind: str, ident: int, leader_start: int) -> list[ProcStat]:
    """Live members of process group (``kind="pgid"``) or session (``"sid"``)
    ``ident`` that belong to the recorded leader: empty when the leader pid now names
    a different process (its start time differs), and only members started no earlier
    than the leader. A pgid/sid stays allocated while any member uses it, so when the
    leader pid is absent every member still carrying it is a leftover of ours."""
    leader = read_stat(ident)
    if leader is not None and leader.start != leader_start:
        return []
    out = []
    for st in _iter_stats():
        key = st.pgid if kind == "pgid" else st.sid
        if key == ident and st.start >= leader_start and st.state != "Z":
            out.append(st)
    return out


def session_members(sid: int, leader_start: int) -> list[ProcStat]:
    """Live processes in the session a supervisor led (identity-checked)."""
    return _members("sid", sid, leader_start)


def group_members(pgid: int, leader_start: int) -> list[ProcStat]:
    """Live processes in the process group a server led (identity-checked)."""
    return _members("pgid", pgid, leader_start)


def _signal_members(kind: str, ident: int, leader_start: int, sig: int) -> int:
    n = 0
    for st in _members(kind, ident, leader_start):
        if _signal_checked(st.pid, st.start, sig):
            n += 1
    return n


def kill_process_group(pgid: int, leader_start: int, sig: int = signal.SIGKILL) -> int:
    """Signal every live member of process group ``pgid`` whose leader started at
    ``leader_start`` (identity-checked, member by member); returns how many were
    signalled. For a caller that must own its child's lifecycle itself (e.g. the
    corpus sandbox, which attaches ``runsc`` to cgroups by pid) but started it with
    ``start_new_session=True``."""
    return _signal_members("pgid", pgid, leader_start, sig)


# --- prctl --------------------------------------------------------------------

def _libc() -> Any:
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        libc.prctl  # noqa: B018 -- AttributeError off Linux
    except (OSError, AttributeError) as exc:
        raise SupervisorUnavailable(f"prctl(2) is not available here: {exc}") from exc
    return libc


def _prctl(libc: Any, option: int, arg: int) -> None:
    if libc.prctl(option, arg, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise SupervisorUnavailable(f"prctl({option}, {arg}) failed: {os.strerror(err)}")


def _read_oom(pid: int | str) -> int | None:
    try:
        with open(f"/proc/{pid}/oom_score_adj") as fh:
            return int(fh.read().strip())
    except (FileNotFoundError, ProcessLookupError):  # no /proc, or the pid is gone
        return None


# --- the supervisor (runs as ``python -I -S procutil.py ...``) ------------------

class _Supervisor:
    def __init__(self, argv: list[str], owner: int, grace: float,
                 status_fd: int, control_fd: int) -> None:
        self.argv = argv
        self.owner = owner
        self.grace = grace
        self.status_fd = status_fd
        self.control_fd = control_fd
        self.me = os.getpid()
        self.signals = 0            # SIGTERM/SIGINT/SIGHUP received (counted, acted on once)
        self.stop_requested = False  # the owner wrote the stop token before signalling
        self.owner_gone = False
        self.child: subprocess.Popen | None = None
        self.child_status: int | None = None

    # status pipe: one line per event; the owner may be gone (BrokenPipeError).
    def report(self, line: str) -> None:
        try:
            os.write(self.status_fd, (line + "\n").encode("utf-8", "replace"))
        except BrokenPipeError:
            pass

    def loud(self, msg: str) -> None:
        try:
            sys.stderr.write(f"fuzzlab.procutil: supervisor {self.me}: {msg}\n")
            sys.stderr.flush()
        except BrokenPipeError:
            pass

    def _on_signal(self, signum: int, frame: Any) -> None:
        # Idempotent: count it; the main loop shuts down exactly once.
        self.signals += 1

    def _drain_control(self) -> None:
        while True:
            try:
                data = os.read(self.control_fd, 64)
            except BlockingIOError:
                return
            if not data:
                self.owner_gone = True  # every owner copy of the write end is closed
                return
            if _STOP_TOKEN.strip() in data:
                self.stop_requested = True

    def run(self) -> int:
        try:
            libc = _libc()
            _prctl(libc, PR_SET_PDEATHSIG, signal.SIGTERM)
            _prctl(libc, PR_SET_CHILD_SUBREAPER, 1)
        except SupervisorUnavailable as exc:
            self.report(f"error kind=capability errno=0 msg={exc}")
            return 125
        if os.getppid() != self.owner:
            self.report("error kind=owner-gone errno=0 msg=owner exited before the supervisor armed")
            return 125

        wake_r, wake_w = os.pipe()
        os.set_blocking(wake_r, False)
        os.set_blocking(wake_w, False)
        os.set_blocking(self.control_fd, False)
        signal.set_wakeup_fd(wake_w)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self._on_signal)
        signal.signal(signal.SIGCHLD, lambda s, f: None)  # wake the loop on child exit

        own_oom = _read_oom("self")
        oom_target = None if own_oom is None or own_oom >= 1000 else min(1000, own_oom + OOM_SCORE_ADJ_RAISE)

        def child_setup() -> None:  # in the forked child; the supervisor has no threads
            os.setpgid(0, 0)
            libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
            if oom_target is not None:
                try:
                    with open("/proc/self/oom_score_adj", "w") as fh:
                        fh.write(str(oom_target))
                except (PermissionError, FileNotFoundError):  # refused / no /proc: reported below
                    pass

        try:
            self.child = subprocess.Popen(self.argv, preexec_fn=child_setup)  # noqa: S603
        except OSError as exc:
            self.report(f"error kind=exec errno={exc.errno or 0} msg={exc.strerror or exc}")
            return 127
        child_stat = read_stat(self.child.pid)
        child_start = child_stat.start if child_stat else 0
        self.report(f"ready child={self.child.pid} start={child_start} "
                    f"oom_supervisor={own_oom} oom_child={_read_oom(self.child.pid)}")

        reason = self._wait(wake_r)
        if reason == "signal":
            self.loud(f"SIGTERM without a stop request from owner {self.owner} (if the server "
                      "was started with allow_thread=True, the forking thread probably exited: "
                      f"PR_SET_PDEATHSIG fires on thread exit); stopping {self.argv!r}")
        elif reason == "owner":
            self.loud(f"owner {self.owner} is gone; stopping {self.argv!r}")
        self._terminate_tree()
        code = self._exit_code()
        self.report(f"exit reason={reason} code={code} signals={self.signals}")
        return code

    def _stop_reason(self) -> str | None:
        """Why to stop now, if at all (the child's own exit is checked separately)."""
        self._drain_control()
        if self.stop_requested:
            return "stop"
        # Owner death first: PDEATHSIG arrives after re-parenting, and the control
        # pipe hits EOF when the owner's files close, so both are visible here.
        if self.owner_gone or os.getppid() != self.owner:
            return "owner"
        if self.signals:
            # The owner writes its stop token *before* it signals, but the signal's
            # handler may have run after the drain above: drain again before calling
            # the stop unrequested (a race seen under load during BUG-0125's checks).
            self._drain_control()
            return "stop" if self.stop_requested else "signal"
        return None

    def _wait(self, wake_r: int) -> str:
        assert self.child is not None
        while True:
            reason = self._stop_reason()
            if reason is not None:
                return reason
            if self._child_exited():
                return "child"
            try:
                select.select([wake_r, self.control_fd], [], [], 0.5)
            except InterruptedError:
                pass
            try:
                while os.read(wake_r, 512):
                    pass
            except BlockingIOError:
                pass

    def _child_exited(self) -> bool:
        """Peek (WNOWAIT) so the server stays unreaped -- its pid, which is also its
        pgid, cannot be reused while we still signal the group. Orphans re-parented to
        us (we are a subreaper) are reaped here."""
        assert self.child is not None
        while True:
            try:
                info = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                return True
            if info is None:
                return False
            if info.si_pid == self.child.pid:
                return True
            os.waitpid(info.si_pid, 0)

    def _descendants(self) -> list[ProcStat]:
        stats = list(_iter_stats())
        kids: dict[int, list[ProcStat]] = {}
        for st in stats:
            kids.setdefault(st.ppid, []).append(st)
        out, todo = [], [self.me]
        while todo:
            for st in kids.get(todo.pop(), []):
                out.append(st)
                todo.append(st.pid)
        return out

    def _reap(self) -> None:
        assert self.child is not None
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            if pid == self.child.pid:
                self.child_status = status

    def _terminate_tree(self) -> None:
        assert self.child is not None
        group = self.child.pid
        signalled: set[tuple[int, int]] = set()
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for st in self._descendants():
            signalled.add((st.pid, st.start))
            if st.pgid != group and st.state != "Z":
                _signal_checked(st.pid, st.start, signal.SIGTERM)
        deadline = time.monotonic() + self.grace
        while True:
            self._reap()
            live = [st for st in self._descendants() if st.state != "Z"]
            if not live:
                return
            if time.monotonic() >= deadline:
                break
            for st in live:  # newly re-parented descendants get one SIGTERM each
                if (st.pid, st.start) not in signalled:
                    signalled.add((st.pid, st.start))
                    _signal_checked(st.pid, st.start, signal.SIGTERM)
            time.sleep(0.05)
        kill_deadline = time.monotonic() + KILL_BOUND_S
        while True:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            live = [st for st in self._descendants() if st.state != "Z"]
            for st in live:
                _signal_checked(st.pid, st.start, signal.SIGKILL)
            self._reap()
            if not live or time.monotonic() >= kill_deadline:
                if live:
                    self.loud(f"descendants survived SIGKILL: {[st.pid for st in live]}")
                return
            time.sleep(0.02)

    def _exit_code(self) -> int:
        self._reap()
        if self.child_status is None:
            return 0
        code = os.waitstatus_to_exitcode(self.child_status)
        return 128 - code if code < 0 else code


def _supervisor_main(args: list[str]) -> int:
    opts: dict[str, str] = {}
    while args and args[0] != "--":
        opts[args[0]] = args[1]
        args = args[2:]
    sup = _Supervisor(args[1:], owner=int(opts["--owner"]), grace=float(opts["--grace"]),
                      status_fd=int(opts["--status-fd"]), control_fd=int(opts["--control-fd"]))
    return sup.run()


# --- the owner side ---------------------------------------------------------

class _LineReader:
    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.buf = b""
        self.eof = False

    def readline(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buf and not self.eof:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready, _, _ = select.select([self.fd], [], [], left)
            if ready:
                chunk = os.read(self.fd, 4096)
                if chunk:
                    self.buf += chunk
                else:
                    self.eof = True
        if b"\n" not in self.buf:
            return None
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace")


def _parse(line: str) -> tuple[str, dict[str, str]]:
    kind, _, rest = line.partition(" ")
    fields: dict[str, str] = {}
    if " msg=" in rest:
        rest, msg = rest.split(" msg=", 1)
        fields["msg"] = msg
    for tok in rest.split():
        k, _, v = tok.partition("=")
        fields[k] = v
    return kind, fields


@dataclass
class ServerHandle:
    """What this process started: the supervisor (its pid is also the session id)
    and the server (its pid is also its process-group id), each with its recorded
    ``/proc`` start time."""

    argv: tuple[str, ...]
    pid: int
    start_time: int
    child_pid: int
    child_start_time: int
    started_at: float = field(default_factory=time.time)
    grace: float = DEFAULT_GRACE_S
    proc: Any = None              # subprocess.Popen or asyncio.subprocess.Process
    pidfd: int | None = None
    oom_supervisor: int | None = None
    oom_child: int | None = None
    #: The supervisor's own account of why it stopped: ``child`` (the server
    #: exited), ``stop`` (requested), ``signal`` (an unrequested SIGTERM), ``owner``
    #: (the owner died), or ``killed`` (no account: the supervisor was killed).
    exit_reason: str | None = None
    exit_code: int | None = None
    #: How many stop signals the supervisor received (it acts on the first only).
    exit_signals: int | None = None
    _status: _LineReader | None = None
    _control: int | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def age(self) -> float:
        return time.time() - self.started_at


_REGISTRY: dict[int, ServerHandle] = {}
_REGISTRY_LOCK = threading.Lock()


def registered() -> list[ServerHandle]:
    """Every handle this process started and has not finished yet."""
    with _REGISTRY_LOCK:
        return list(_REGISTRY.values())


def _register(h: ServerHandle) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY[h.pid] = h


def _unregister(h: ServerHandle) -> None:
    with _REGISTRY_LOCK:
        if _REGISTRY.get(h.pid) is h:
            del _REGISTRY[h.pid]


def _check_thread(allow_thread: bool) -> None:
    if not allow_thread and threading.current_thread() is not threading.main_thread():
        raise ProcUtilError(
            "start_server called off the main thread: PR_SET_PDEATHSIG fires when the "
            "forking thread exits, so the server would die with this thread. Pass "
            "allow_thread=True only if this thread lives as long as the server must.")


def _supervisor_argv(argv: Sequence[str], grace: float, status_w: int, control_r: int) -> list[str]:
    return [sys.executable, "-I", "-S", _SUPERVISOR_SCRIPT,
            "--owner", str(os.getpid()), "--grace", repr(float(grace)),
            "--status-fd", str(status_w), "--control-fd", str(control_r), "--", *argv]


def _pipes() -> tuple[int, int, int, int]:
    status_r, status_w = os.pipe()
    control_r, control_w = os.pipe()
    return status_r, status_w, control_r, control_w


def _complete_start(h: ServerHandle, reader: _LineReader, ready_timeout: float,
                    kill_supervisor) -> ServerHandle:
    line = reader.readline(ready_timeout)
    if line is None:
        kill_supervisor()
        raise ProcUtilError(f"supervisor for {list(h.argv)!r} sent no ready line within {ready_timeout}s")
    kind, f = _parse(line)
    if kind == "error":
        kill_supervisor()
        _close_fds(h)
        if f.get("kind") == "capability":
            raise SupervisorUnavailable(f.get("msg", ""))
        if f.get("kind") == "exec":
            err = int(f.get("errno", "0") or 0)
            raise OSError(err, f"{f.get('msg', '')}: {h.argv[0]!r}")
        raise ProcUtilError(f"supervisor refused to start {list(h.argv)!r}: {line}")
    h.child_pid = int(f["child"])
    h.child_start_time = int(f["start"])
    h.oom_supervisor = None if f.get("oom_supervisor") in (None, "None") else int(f["oom_supervisor"])
    h.oom_child = None if f.get("oom_child") in (None, "None") else int(f["oom_child"])
    _register(h)
    return h


def start_server(argv: Sequence[str], *, cwd: Any = None, env: dict[str, str] | None = None,
                 stdin: Any = subprocess.DEVNULL, stdout: Any = None, stderr: Any = None,
                 text: bool = False, grace: float = DEFAULT_GRACE_S, allow_thread: bool = False,
                 ready_timeout: float = READY_TIMEOUT_S) -> ServerHandle:
    """Start ``argv`` under a supervisor tied to this process's life (see the module
    docstring). ``handle.proc`` is the supervisor's :class:`subprocess.Popen`: its
    ``stdout``/``stderr`` carry the server's output, and it exits (with the server's
    exit code) when the server does. Stop it with :func:`stop_server`."""
    _check_thread(allow_thread)
    status_r, status_w, control_r, control_w = _pipes()
    try:
        proc = subprocess.Popen(  # noqa: S603 -- the one sanctioned Popen (procutil)
            _supervisor_argv(argv, grace, status_w, control_r), cwd=cwd, env=env,
            stdin=stdin, stdout=stdout, stderr=stderr, text=text,
            start_new_session=True, pass_fds=(status_w, control_r))
    finally:
        os.close(status_w)
        os.close(control_r)
    st = read_stat(proc.pid)
    h = ServerHandle(argv=tuple(str(a) for a in argv), pid=proc.pid,
                     start_time=st.start if st else 0, child_pid=0, child_start_time=0,
                     grace=grace, proc=proc, pidfd=_open_pidfd(proc.pid),
                     _status=_LineReader(status_r), _control=control_w)

    def kill_supervisor() -> None:
        _send(h, signal.SIGKILL)
        proc.wait()
        _close_fds(h)

    return _complete_start(h, h._status, ready_timeout, kill_supervisor)


def _open_pidfd(pid: int) -> int | None:
    if not hasattr(os, "pidfd_open"):
        return None
    try:
        return os.pidfd_open(pid)
    except OSError as exc:  # ENOSYS: old kernel; ESRCH: already gone
        if exc.errno in (_errno.ENOSYS, _errno.ESRCH):
            return None
        raise


def _send(h: ServerHandle, sig: int) -> bool:
    """Signal the supervisor: through its pidfd (cannot hit a reused pid), else after
    a start-time check."""
    if h.pidfd is not None:
        try:
            signal.pidfd_send_signal(h.pidfd, sig)
            return True
        except ProcessLookupError:
            return False
    return _signal_checked(h.pid, h.start_time, sig)


def request_stop(h: ServerHandle) -> bool:
    """Ask the supervisor to stop its server (non-blocking): write the stop token on
    the control pipe, then SIGTERM it. Returns whether a signal was delivered."""
    if h._control is not None:
        try:
            os.write(h._control, _STOP_TOKEN)
        except BrokenPipeError:
            pass
    return _send(h, signal.SIGTERM)


def _fallback_kill(h: ServerHandle) -> None:
    """BUG-0125 D15: the supervisor did not exit within its grace (wedged, stopped, or
    ignoring TERM). Kill the server's own process group directly -- identity-checked
    by pgid and start time -- then the supervisor, then anything left in its
    session."""
    if h.child_pid:
        _signal_members("pgid", h.child_pid, h.child_start_time, signal.SIGTERM)
        deadline = time.monotonic() + min(h.grace, 2.0)
        while time.monotonic() < deadline and _members("pgid", h.child_pid, h.child_start_time):
            time.sleep(0.05)
        _signal_members("pgid", h.child_pid, h.child_start_time, signal.SIGKILL)
    _send(h, signal.SIGKILL)


def _sweep_session(h: ServerHandle) -> list[ProcStat]:
    """SIGKILL anything still in the supervisor's session (identity-checked);
    returns what was found."""
    left = session_members(h.pid, h.start_time)
    for st in left:
        _signal_checked(st.pid, st.start, signal.SIGKILL)
    return left


def _close_fds(h: ServerHandle) -> None:
    for attr in ("pidfd", "_control"):
        fd = getattr(h, attr)
        if fd is not None:
            os.close(fd)
            setattr(h, attr, None)
    if h._status is not None:
        os.close(h._status.fd)
        h._status = None


def _collect(h: ServerHandle) -> None:
    """Read the supervisor's final ``exit`` line (it has exited), sweep its session,
    close fds, unregister. Safe to call from two tasks at once (a stop watchdog and
    the output pump both collect)."""
    with h._lock:
        _collect_locked(h)


def _collect_locked(h: ServerHandle) -> None:
    if h._status is not None:
        while True:
            line = h._status.readline(0.5)
            if line is None:
                break
            kind, f = _parse(line)
            if kind == "exit":
                h.exit_reason = f.get("reason")
                h.exit_code = int(f.get("code", "0"))
                h.exit_signals = int(f.get("signals", "0"))
    if h.exit_reason is None:
        h.exit_reason = "killed"  # no exit line: the supervisor itself was killed
    _sweep_session(h)
    _close_fds(h)
    _unregister(h)


def _raise_if_lost(h: ServerHandle) -> None:
    if h.exit_reason == "signal":
        raise ServerLost(
            f"the supervisor of {list(h.argv)!r} (pid {h.pid}) stopped its server without a "
            "stop request (an unrequested SIGTERM: with allow_thread=True, the forking "
            "thread exited)")


def finish(h: ServerHandle) -> str:
    """Collect a handle whose supervisor has already exited (the server ended on its
    own, or was stopped). Raises :class:`ServerLost` for an unrequested stop."""
    _collect(h)
    _raise_if_lost(h)
    return h.exit_reason or ""


def stop_server(h: ServerHandle, *, timeout: float | None = None) -> str:
    """Stop the server and its whole tree, and reap the supervisor. Idempotent.
    Returns the supervisor's exit reason (``stop``, ``child``, ...); raises
    :class:`ServerLost` if the server had already been stopped without a request."""
    if h.proc is None:
        raise ProcUtilError("stop_server needs a handle returned by start_server")
    if h.exit_reason is not None and h._status is None:
        return h.exit_reason
    wait = h.grace + STOP_MARGIN_S if timeout is None else timeout
    if h.proc.poll() is None:
        request_stop(h)
        try:
            h.proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            _fallback_kill(h)
            h.proc.wait(timeout=KILL_BOUND_S)
    _collect(h)
    _raise_if_lost(h)
    return h.exit_reason or ""


def is_live(h: ServerHandle) -> bool:
    """True when the recorded supervisor (start time matching) or any member of its
    session is still alive."""
    st = read_stat(h.pid)
    if st is not None and st.start == h.start_time and st.state != "Z":
        return True
    return bool(session_members(h.pid, h.start_time))


@dataclass(frozen=True)
class Leak:
    argv: tuple[str, ...]
    pid: int
    age_s: float

    def describe(self) -> str:
        return f"pid {self.pid}, age {self.age_s:.1f}s: {list(self.argv)!r}"


def reap_registered() -> list[Leak]:
    """The session-end safety net: stop every registered server that is still live
    (identity-checked) and return what was found. A record whose pid now names a
    different process (start time differs) is dropped, never signalled."""
    leaks: list[Leak] = []
    for h in registered():
        if not is_live(h):
            _unregister(h)
            continue
        leaks.append(Leak(argv=h.argv, pid=h.pid, age_s=h.age()))
        if h.proc is not None and isinstance(h.proc, subprocess.Popen):
            try:
                stop_server(h)
            except ServerLost:
                pass  # reported as a leak either way
        else:
            if not _send(h, signal.SIGTERM):
                pass
            deadline = time.monotonic() + h.grace + STOP_MARGIN_S
            while time.monotonic() < deadline and is_live(h):
                time.sleep(0.05)
            if is_live(h):
                _fallback_kill(h)
            _sweep_session(h)
            if h.pidfd is not None or h._status is not None or h._control is not None:
                _close_fds(h)
            _unregister(h)
    return leaks


def run_bounded(argv: Sequence[str], *, timeout: float, cwd: Any = None,
                env: dict[str, str] | None = None, input: str | bytes | None = None,
                text: bool = True, grace: float = 2.0) -> subprocess.CompletedProcess:
    """``subprocess.run(argv, capture_output=True, timeout=...)`` for a tool that forks
    (npm, go, mvn, composer, bundle): the tool runs under a supervisor in its own
    session, so a timeout -- or the tool's own exit -- takes its whole tree down, not
    just the direct child. Raises :class:`subprocess.TimeoutExpired` (with the output
    so far) on timeout, like ``subprocess.run``. Callable from any thread: this call
    blocks the forking thread until the tool has ended."""
    h = start_server(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text, grace=grace,
                     allow_thread=True)
    try:
        out, err = h.proc.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            stop_server(h)
        except ServerLost:
            pass
        out, err = h.proc.communicate()
        raise subprocess.TimeoutExpired(list(argv), timeout, output=out, stderr=err) from None
    except BaseException:
        stop_server(h)
        raise
    finish(h)
    return subprocess.CompletedProcess(list(argv), h.proc.returncode, out, err)


# --- asyncio ----------------------------------------------------------------

async def astart_server(argv: Sequence[str], *, env: dict[str, str] | None = None,
                        stdin: Any = subprocess.DEVNULL, stdout: Any = None, stderr: Any = None,
                        grace: float = DEFAULT_GRACE_S, allow_thread: bool = False,
                        ready_timeout: float = READY_TIMEOUT_S) -> ServerHandle:
    """:func:`start_server` for asyncio: ``handle.proc`` is an
    :class:`asyncio.subprocess.Process`. The forking thread is the event loop's."""
    import asyncio

    _check_thread(allow_thread)
    status_r, status_w, control_r, control_w = _pipes()
    try:
        proc = await asyncio.create_subprocess_exec(  # the one sanctioned asyncio spawn
            *_supervisor_argv(argv, grace, status_w, control_r), env=env,
            stdin=stdin, stdout=stdout, stderr=stderr,
            start_new_session=True, pass_fds=(status_w, control_r))
    finally:
        os.close(status_w)
        os.close(control_r)
    st = read_stat(proc.pid)
    h = ServerHandle(argv=tuple(str(a) for a in argv), pid=proc.pid,
                     start_time=st.start if st else 0, child_pid=0, child_start_time=0,
                     grace=grace, proc=proc, pidfd=_open_pidfd(proc.pid),
                     _status=_LineReader(status_r), _control=control_w)

    def kill_supervisor() -> None:
        _send(h, signal.SIGKILL)
        _close_fds(h)

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _complete_start, h, h._status, ready_timeout,
                                      kill_supervisor)


async def astop_server(h: ServerHandle, *, timeout: float | None = None) -> str:
    """:func:`stop_server` for a handle from :func:`astart_server`."""
    import asyncio

    if h.exit_reason is not None and h._status is None:
        return h.exit_reason
    wait = h.grace + STOP_MARGIN_S if timeout is None else timeout
    if h.proc.returncode is None:
        request_stop(h)
        try:
            await asyncio.wait_for(h.proc.wait(), wait)
        except asyncio.TimeoutError:
            _fallback_kill(h)
            await asyncio.wait_for(h.proc.wait(), KILL_BOUND_S)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _collect, h)
    _raise_if_lost(h)
    return h.exit_reason or ""


async def arun_bounded(argv: Sequence[str], *, timeout: float,
                       env: dict[str, str] | None = None) -> tuple[int | None, bytes, bytes, bool]:
    """Async bounded run for a forking tool: ``(returncode, stdout, stderr,
    timed_out)``. On timeout the tool's whole tree is stopped."""
    import asyncio

    h = await astart_server(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            grace=2.0, allow_thread=True)
    try:
        out, err = await asyncio.wait_for(h.proc.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            await astop_server(h)
        except ServerLost:
            pass
        return None, b"", b"", True
    except BaseException:
        await astop_server(h)
        raise
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _collect, h)
    _raise_if_lost(h)
    return h.proc.returncode, out, err, False


if __name__ == "__main__":
    sys.exit(_supervisor_main(sys.argv[1:]))
