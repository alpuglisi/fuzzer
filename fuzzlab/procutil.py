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
matching its start time (field 22) against the value recorded at start. A process
group or session id is trusted **only while its leader pid is held** -- alive, or a
zombie nobody has reaped -- with the recorded start time (pids wrap within minutes:
pid_max is 32768 here): the supervisor reaps its server only after its last
``killpg``, the owner sweeps the supervisor's session before it reaps the supervisor,
and a group whose leader is gone is signalled only inside a still-held supervisor's
session. A start time of 0 means "identity unknown" and matches nothing (BUG-0125
review). A reused pid is therefore never signalled.

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
import ipaddress
import os
import select
import signal
import socket
import struct
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
    "CODE_UNKNOWN",
    "finish",
    "ListenerCheckFailed",
    "ExposedAndLost",
    "listeners",
    "exposed_listeners",
    "assert_loopback_only",
    "NonLoopbackListener",
    "Listener",
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


class NonLoopbackListener(ProcUtilError):
    """A process this module started listened on a non-loopback address (BUG-0130):
    the lab is loopback-only and must never be exposed."""


class ServerLost(ProcUtilError):
    """The supervisor stopped its server without a stop request from its owner
    (``reason=signal``): e.g. PDEATHSIG after the forking thread exited
    (``allow_thread=True``), or an external SIGTERM."""


class ExposedAndLost(NonLoopbackListener, ServerLost):
    """Both at once (review B1): the server listened beyond loopback *and* had been
    stopped without a request. Caught by a handler of either."""


class ListenerCheckFailed(ProcUtilError):
    """The listener check itself failed while the server was up (review A-M1). The
    stop still ran in full; this is raised afterwards, never instead of stopping."""


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


def _held(pid: int, start: int) -> bool:
    """``pid`` still names the process that started at ``start`` -- alive, or a zombie
    nobody has reaped -- so the pid (and any group or session id equal to it) cannot
    have been reused."""
    st = read_stat(pid)
    return start > 0 and st is not None and st.start == start


def _members(kind: str, ident: int, leader_start: int, *,
             anchor: tuple[int, int] | None = None) -> list[ProcStat]:
    """Live members of process group (``kind="pgid"``) or session (``"sid"``)
    ``ident``, trusted only while that id cannot have been reused.

    Pids wrap quickly (pid_max 32768 here); an id is only trusted while its leader pid
    is held. So members are returned only when the leader pid still names the recorded
    leader (alive or an unreaped zombie), or -- for a group whose leader is gone -- when
    ``anchor`` (a ``(session id, its leader's start time)`` pair whose leader *is*
    held) is given, and then only members of that anchored session. A start time of 0
    means "identity unknown": nothing is returned (BUG-0125 review, B2 / A-M2). Only
    members started no earlier than the leader are kept."""
    if leader_start <= 0 or (anchor is not None and anchor[1] <= 0):
        return []
    leader = read_stat(ident)
    if leader is None:
        if anchor is None or not _held(*anchor):
            return []
    elif leader.start != leader_start:
        return []
    out = []
    for st in _iter_stats():
        key = st.pgid if kind == "pgid" else st.sid
        if key == ident and st.start >= leader_start and st.state != "Z" and (
                anchor is None or st.sid == anchor[0]):
            out.append(st)
    return out


def session_members(sid: int, leader_start: int) -> list[ProcStat]:
    """Live processes in the session a supervisor led, while its leader pid is held."""
    return _members("sid", sid, leader_start)


def group_members(pgid: int, leader_start: int, *,
                  anchor: tuple[int, int] | None = None) -> list[ProcStat]:
    """Live processes in the process group a server led (see :func:`_members`)."""
    return _members("pgid", pgid, leader_start, anchor=anchor)


def _signal_members(kind: str, ident: int, leader_start: int, sig: int, *,
                    anchor: tuple[int, int] | None = None) -> int:
    n = 0
    for st in _members(kind, ident, leader_start, anchor=anchor):
        if _signal_checked(st.pid, st.start, sig):
            n += 1
    return n


def kill_process_group(pgid: int, leader_start: int, sig: int = signal.SIGKILL, *,
                       anchor: tuple[int, int] | None = None) -> int:
    """Signal every live member of process group ``pgid`` whose leader started at
    ``leader_start`` (identity-checked, member by member; only while the leader pid,
    or ``anchor``'s, is held); returns how many were signalled. For a caller that owns
    its child's lifecycle itself (e.g. the corpus sandbox, which attaches ``runsc`` to
    cgroups by pid) and started it with ``start_new_session=True``: call it before
    reaping that child."""
    return _signal_members("pgid", pgid, leader_start, sig, anchor=anchor)


def _descendants_of(root: int) -> list[ProcStat]:
    """Every process whose parent chain leads to ``root`` (one /proc scan)."""
    kids: dict[int, list[ProcStat]] = {}
    for st in _iter_stats():
        kids.setdefault(st.ppid, []).append(st)
    out, todo = [], [root]
    while todo:
        for st in kids.get(todo.pop(), []):
            out.append(st)
            todo.append(st.pid)
    return out

# --- listening sockets (BUG-0130) ---------------------------------------------

@dataclass(frozen=True)
class Listener:
    """A listening TCP socket held by a process of a server's tree."""

    pid: int
    address: str
    port: int
    #: The network namespace the socket lives in (``net:[inode]``): each process's
    #: own table is read, so a server in a private namespace is seen too.
    netns: str = ""

    def is_loopback(self) -> bool:
        ip = ipaddress.ip_address(self.address)
        mapped = getattr(ip, "ipv4_mapped", None)
        return ip.is_loopback or (mapped is not None and mapped.is_loopback)

    def describe(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        ns = f" (netns {self.netns})" if self.netns else ""
        return f"pid {self.pid} listens on {host}:{self.port}{ns}"


_TCP_LISTEN = "0A"


def _decode_proc_net_address(hex_addr: str) -> tuple[str, int]:
    """``/proc/net/tcp{,6}`` ``local_address`` (``ADDR:PORT``, the address as 32-bit
    words in host byte order) to ``(address, port)``."""
    addr, port = hex_addr.split(":")
    words = [int(addr[i:i + 8], 16) for i in range(0, len(addr), 8)]
    raw = b"".join(struct.pack("=I", w) for w in words)
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw), int(port, 16)


def _listen_table(pid: int) -> dict[int, tuple[str, int]]:
    """``{socket inode: (address, port)}`` of every LISTEN socket in ``pid``'s network
    namespace (``/proc/<pid>/net/tcp`` and ``tcp6``; a missing file -- no IPv6 -- is
    an empty table)."""
    table: dict[int, tuple[str, int]] = {}
    for name in ("tcp", "tcp6"):
        try:
            with open(f"/proc/{pid}/net/{name}") as fh:
                table.update(_parse_tcp_table(fh.read()))
        except (FileNotFoundError, ProcessLookupError, PermissionError):  # gone / no IPv6 / hidden
            continue
    return table


def _parse_tcp_table(text: str) -> dict[int, tuple[str, int]]:
    """LISTEN rows only (``st`` 0A) of one ``/proc/net/tcp{,6}`` file: an established
    connection (an outbound fetch, a client) is not a listener, wherever it is bound."""
    table: dict[int, tuple[str, int]] = {}
    for row in text.splitlines()[1:]:
        cols = row.split()
        if len(cols) > 9 and cols[3] == _TCP_LISTEN:
            try:
                table[int(cols[9])] = _decode_proc_net_address(cols[1])
            except (ValueError, OSError, struct.error):  # an unparseable row is skipped
                continue
    return table


def _socket_inodes(pid: int) -> set[int]:
    out: set[int] = set()
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return out
    for fd in fds:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if target.startswith("socket:["):
            out.add(int(target[8:-1]))
    return out


def listeners(h: "ServerHandle") -> list[Listener]:
    """Every listening TCP socket held by the server's process tree: the supervisor
    and its descendants (escaped ones included -- it is their subreaper), mapped
    through ``/proc/<pid>/fd`` socket inodes to the LISTEN rows of **that process's
    own** ``/proc/<pid>/net/tcp{,6}`` -- per network namespace, so a server in a
    private namespace (``unshare -n``) is seen as well. Identity-checked: only while
    the supervisor pid is held with its recorded start time (BUG-0130, PA-0130;
    probes the real sockets, PA-0035)."""
    if not _held(h.pid, h.start_time):
        return []
    sup = read_stat(h.pid)
    procs = ([sup] if sup is not None else []) + _descendants_of(h.pid)
    tables: dict[str, dict[int, tuple[str, int]]] = {}
    out = []
    for st in procs:
        inodes = _socket_inodes(st.pid)
        if not inodes:
            continue
        ns = _netns(st.pid)
        key = ns or f"pid:{st.pid}"  # one read per namespace; an unreadable one per process
        if key not in tables:
            tables[key] = _listen_table(st.pid)
        for inode in inodes:
            if inode in tables[key]:
                address, port = tables[key][inode]
                out.append(Listener(pid=st.pid, address=address, port=port, netns=ns))
    return out


def _netns(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/ns/net")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return ""


def _host_netns() -> str:
    """This process's network namespace: the one a listener is exposed from."""
    return _netns(os.getpid())


def _is_exposed(lst: Listener, host_netns: str) -> bool:
    """A non-loopback listener in the host's network namespace. One in a private
    namespace (``unshare -n``: its only interface is its own loopback) is not
    reachable from outside, whatever its address (review B2 / A-S2)."""
    return not lst.is_loopback() and (not lst.netns or lst.netns == host_netns)


def exposed_listeners(h: "ServerHandle", *, host_netns: str | None = None) -> list[Listener]:
    """The server tree's listeners reachable beyond loopback: a non-loopback address in
    the host's network namespace (``host_netns``, default this process's)."""
    ns = _host_netns() if host_netns is None else host_netns
    return [lst for lst in listeners(h) if _is_exposed(lst, ns)]


def assert_loopback_only(h: "ServerHandle", *, host_netns: str | None = None) -> list[Listener]:
    """Raise :class:`NonLoopbackListener` if any process of the server's tree is
    exposed beyond loopback; return its listeners otherwise. The rule: **checked
    after boot, and at stop while live** -- the harnesses call this right after boot;
    every stop re-checks while the server still runs."""
    found = listeners(h)
    ns = _host_netns() if host_netns is None else host_netns
    exposed = [lst for lst in found if _is_exposed(lst, ns)]
    if exposed:
        raise NonLoopbackListener(
            f"{list(h.argv)!r} is exposed beyond loopback: "
            + "; ".join(lst.describe() for lst in exposed))
    return found



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

        sup = os.getpid()

        def child_setup() -> None:  # in the forked child; the supervisor has no threads
            os.setpgid(0, 0)
            libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
            if os.getppid() != sup:  # the supervisor died between fork and prctl
                os._exit(1)
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
        return _descendants_of(self.me)

    def _reap(self) -> None:
        """Reap every exited child *except the server*: its pid is its group id, and
        the group may be signalled only while that pid is held (BUG-0125 review M1).
        The server is reaped by :meth:`_reap_server`, after the last ``killpg``."""
        assert self.child is not None
        for st in _iter_stats():
            if st.ppid == self.me and st.state == "Z" and st.pid != self.child.pid:
                try:
                    os.waitpid(st.pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    def _reap_server(self) -> None:
        assert self.child is not None
        deadline = time.monotonic() + KILL_BOUND_S
        while self.child_status is None:
            pid, status = os.waitpid(self.child.pid, os.WNOHANG)
            if pid:
                self.child_status = status
            elif time.monotonic() >= deadline:  # unkillable (D state): say so, do not hang
                self.loud(f"server {self.child.pid} could not be reaped")
                break
            else:
                time.sleep(0.02)
        self._reap()

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
        self._reap_server()
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
    proc: Any = None              # subprocess.Popen, or _AsyncSupervisorProc (asyncio)
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
                    kill_supervisor, abandon) -> ServerHandle:
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
    if h.start_time <= 0 or h.child_start_time <= 0:
        # Without a start time nothing can be identity-checked later (BUG-0125 review
        # B2): refuse loudly, after the supervisor has stopped what it started.
        abandon()
        raise ProcUtilError(
            f"could not record the /proc start time of the supervisor ({h.start_time}) or the "
            f"server ({h.child_start_time}) for {list(h.argv)!r}; refusing to run a server "
            "whose identity cannot be checked")
    _register(h)
    return h


def _popen_of(h: ServerHandle) -> subprocess.Popen | None:
    if isinstance(h.proc, subprocess.Popen):
        return h.proc
    return getattr(h.proc, "_popen", None)


def _exited(h: ServerHandle) -> bool:
    """Has the supervisor exited? Never reaps it (``waitid(WNOWAIT)``): its pid -- also
    its session id -- stays held until the session sweep is done (BUG-0125 review M2)."""
    p = _popen_of(h)
    if p is None or p.returncode is not None:
        return True
    try:
        info = os.waitid(os.P_PID, h.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:  # reaped by someone else
        return True
    return info is not None


#: The exit status of a supervisor that was reaped behind its ``Popen``'s back (code
#: lost). Not a valid ``Popen.returncode`` (no signal is 256), so it cannot be mistaken
#: for a real exit status or signal.
CODE_UNKNOWN = -256


def _peek_code(h: ServerHandle) -> int | None:
    """The exited supervisor's status, without reaping it; ``CODE_UNKNOWN`` if someone
    else already reaped it (consistent with :func:`_exited`: it has exited), ``None``
    while it runs."""
    p = _popen_of(h)
    if p is not None and p.returncode is not None:
        return p.returncode
    try:
        info = os.waitid(os.P_PID, h.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return CODE_UNKNOWN
    if info is None:
        return None
    return info.si_status if info.si_code == os.CLD_EXITED else -info.si_status


def _wait_exited(h: ServerHandle, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not _exited(h):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def _owner_loud(msg: str) -> None:
    try:
        sys.stderr.write(f"fuzzlab.procutil: {msg}\n")
        sys.stderr.flush()
    except (BrokenPipeError, ValueError):  # stderr closed or gone
        pass


def _reap_supervisor(h: ServerHandle) -> bool:
    """Reap the supervisor, waiting at most ``KILL_BOUND_S`` (review round 3: one stuck
    in D state must not hang its owner). Returns False -- after a loud line -- if it
    could not be reaped; the caller then leaves the handle registered, so the session
    safety net reports it."""
    p = _popen_of(h)
    if p is None or p.returncode is not None:
        return True
    try:
        p.wait(timeout=KILL_BOUND_S)  # an already-reaped child (ECHILD) maps to 0
    except subprocess.TimeoutExpired:
        _owner_loud(f"supervisor {h.pid} of {list(h.argv)!r} could not be reaped within "
                    f"{KILL_BOUND_S}s (stuck in D state?); left registered for the safety net")
        return False
    return True


def start_server(argv: Sequence[str], *, cwd: Any = None, env: dict[str, str] | None = None,
                 stdin: Any = subprocess.DEVNULL, stdout: Any = None, stderr: Any = None,
                 text: bool = False, grace: float = DEFAULT_GRACE_S, allow_thread: bool = False,
                 ready_timeout: float = READY_TIMEOUT_S) -> ServerHandle:
    """Start ``argv`` under a supervisor tied to this process's life (see the module
    docstring). ``handle.proc`` is the supervisor's :class:`subprocess.Popen`: its
    ``stdout``/``stderr`` carry the server's output, and it exits (with the server's
    exit code) when the server does. Stop it with :func:`stop_server`."""
    _check_thread(allow_thread)
    h, proc = _spawn_supervisor(argv, grace, cwd=cwd, env=env, stdin=stdin, stdout=stdout,
                                stderr=stderr, text=text)
    return _complete_start(h, h._status, ready_timeout, *_start_failure_paths(h, proc))


def _spawn_supervisor(argv: Sequence[str], grace: float, **popen_kw: Any) -> tuple[ServerHandle, subprocess.Popen]:
    status_r, status_w, control_r, control_w = _pipes()
    try:
        proc = subprocess.Popen(  # noqa: S603 -- the one sanctioned owner-side spawn
            _supervisor_argv(argv, grace, status_w, control_r),
            start_new_session=True, pass_fds=(status_w, control_r), **popen_kw)
    except BaseException:
        os.close(status_r)
        os.close(control_w)
        raise
    finally:
        os.close(status_w)
        os.close(control_r)
    st = read_stat(proc.pid)
    h = ServerHandle(argv=tuple(str(a) for a in argv), pid=proc.pid,
                     start_time=st.start if st else 0, child_pid=0, child_start_time=0,
                     grace=grace, proc=proc, pidfd=_open_pidfd(proc.pid),
                     _status=_LineReader(status_r), _control=control_w)
    return h, proc


def _start_failure_paths(h: ServerHandle, proc: subprocess.Popen):
    """What a failed start does with the supervisor (no ready line in time, an error
    line, or an identity that cannot be recorded). The server may already have forked
    (a slow artisan or ``go run`` boot that missed ``ready_timeout``), so this is a full
    stop in :func:`_collect_locked`'s order (review round 2): request a stop, fall back
    if the supervisor does not exit, wait for it *without reaping*, sweep its session
    while its pid is held, and only then reap."""

    def abandon() -> None:
        request_stop(h)
        if not _wait_exited(h, h.grace + STOP_MARGIN_S):
            _fallback_kill(h)
            _wait_exited(h, KILL_BOUND_S)
        _sweep_session(h)
        if not _reap_supervisor(h):  # bounded; loud; left for the safety net
            _register(h)
            return
        _close_fds(h)

    return abandon, abandon


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
    ignoring TERM). It is still alive and unreaped, so its pid -- the session id -- is
    held and anchors everything below (review M2(b)):

    1. the server's own process group, SIGTERM then SIGKILL, members of the
       supervisor's session only (the server's pgid is usually free by now);
    2. every other descendant of the supervisor and every other member of its session
       (identity-checked, SIGKILL);
    3. the supervisor itself (pidfd)."""
    anchor = (h.pid, h.start_time)
    if not _held(*anchor):
        _send(h, signal.SIGKILL)
        return
    if h.child_pid:
        _signal_members("pgid", h.child_pid, h.child_start_time, signal.SIGTERM, anchor=anchor)
        deadline = time.monotonic() + min(h.grace, 2.0)
        while time.monotonic() < deadline and _members("pgid", h.child_pid, h.child_start_time,
                                                       anchor=anchor):
            time.sleep(0.05)
        _signal_members("pgid", h.child_pid, h.child_start_time, signal.SIGKILL, anchor=anchor)
    seen = set()
    for st in _descendants_of(h.pid) + session_members(h.pid, h.start_time):
        if st.pid != h.pid and st.state != "Z" and st.start >= h.start_time and st.pid not in seen:
            seen.add(st.pid)
            _signal_checked(st.pid, st.start, signal.SIGKILL)
    _send(h, signal.SIGKILL)


def _sweep_session(h: ServerHandle) -> list[ProcStat]:
    """SIGKILL anything still in the supervisor's session -- only while the supervisor
    is exited but **unreaped** by us (its pid, the session id, is held); a reaped or
    unknown supervisor's session is never swept (review M2(a)). Returns what was
    found. (The guarantee is :func:`session_members`' leader-held rule; the owner's part
    is never to reap the supervisor before calling this.)"""
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
    """For an exited supervisor: sweep its session while it is still held, reap it,
    read its final ``exit`` line, close fds, unregister. Safe to call from two tasks
    at once (a stop watchdog and the output pump both collect)."""
    with h._lock:
        _collect_locked(h)


def _collect_locked(h: ServerHandle) -> None:
    _sweep_session(h)
    if not _reap_supervisor(h):
        h.exit_reason = "unreaped"  # stays registered with its fds: a later stop retries
        return
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


def _stop_core(h: ServerHandle, timeout: float | None) -> str:
    """Request a stop, wait for the supervisor to exit *without reaping it*, fall back
    if it is wedged, then sweep (held), reap and collect."""
    if _popen_of(h) is None:
        raise ProcUtilError("stop_server needs a handle returned by start_server")
    with h._lock:
        if h.exit_reason is not None and h.exit_reason != "unreaped" and h._status is None:
            return h.exit_reason
        h.exit_reason = None if h.exit_reason == "unreaped" else h.exit_reason
        wait = h.grace + STOP_MARGIN_S if timeout is None else timeout
        exposed: list[Listener] = []
        check_failed = ""
        if not _exited(h):
            # BUG-0130: every server is checked while still up, at the one choke point
            # every site goes through. The check is total (review A-M1): whatever it
            # raises is recorded, and the stop, sweep and collect always run; the
            # finding is raised only afterwards.
            try:
                exposed = exposed_listeners(h)
            except Exception as exc:  # noqa: BLE001 -- recorded, re-raised after the stop
                check_failed = f"{type(exc).__name__}: {exc}"
            request_stop(h)
            if not _wait_exited(h, wait):
                _fallback_kill(h)
                _wait_exited(h, KILL_BOUND_S)
        _collect_locked(h)
        if exposed:
            msg = (f"{list(h.argv)!r} was exposed beyond loopback while it ran (stopped now): "
                   + "; ".join(lst.describe() for lst in exposed))
            if h.exit_reason == "signal":  # review B1: do not mask a lost server
                raise ExposedAndLost(msg + "; it had also been stopped without a stop request")
            raise NonLoopbackListener(msg)
        if check_failed:
            raise ListenerCheckFailed(
                f"listener check failed for {list(h.argv)!r} (the tree was stopped anyway): "
                f"{check_failed}")
        return h.exit_reason or ""


def stop_server(h: ServerHandle, *, timeout: float | None = None) -> str:
    """Stop the server and its whole tree, and reap the supervisor. Idempotent.
    Returns the supervisor's exit reason (``stop``, ``child``, ...); raises
    :class:`ServerLost` if the server had already been stopped without a request."""
    _stop_core(h, timeout)
    _raise_if_lost(h)
    return h.exit_reason or ""


def is_live(h: ServerHandle) -> bool:
    """True when the recorded supervisor (start time matching) or any member of its
    session (while its pid is held) is still alive."""
    st = read_stat(h.pid)
    if h.start_time > 0 and st is not None and st.start == h.start_time and st.state != "Z":
        return True
    return bool(session_members(h.pid, h.start_time))


@dataclass(frozen=True)
class Leak:
    argv: tuple[str, ...]
    pid: int
    age_s: float
    note: str = ""

    def describe(self) -> str:
        note = f" ({self.note})" if self.note else ""
        return f"pid {self.pid}, age {self.age_s:.1f}s: {list(self.argv)!r}{note}"


def reap_registered() -> list[Leak]:
    """The session-end safety net: stop every registered server that is still live
    (identity-checked) and return what was found. A record whose pid now names a
    different process (start time differs) is dropped, never signalled; a record with
    no recorded start time is reported, never signalled."""
    leaks: list[Leak] = []
    for h in registered():
        if h.start_time <= 0:
            leaks.append(Leak(argv=h.argv, pid=h.pid, age_s=h.age(),
                              note="identity unknown: not signalled"))
            _unregister(h)
            continue
        if not is_live(h):
            _unregister(h)
            continue
        leaks.append(Leak(argv=h.argv, pid=h.pid, age_s=h.age()))
        if _popen_of(h) is not None:
            try:
                _stop_core(h, None)  # sync and asyncio handles alike; never reaps before the sweep
            except (NonLoopbackListener, ListenerCheckFailed) as exc:
                leaks[-1] = Leak(argv=h.argv, pid=h.pid, age_s=leaks[-1].age_s, note=str(exc))
            continue
        # A record without a process object (not our child): signal the recorded
        # supervisor (identity-checked); its session only while its pid is held.
        _send(h, signal.SIGTERM)
        deadline = time.monotonic() + h.grace + STOP_MARGIN_S
        while time.monotonic() < deadline and is_live(h):
            time.sleep(0.05)
        if is_live(h):
            _fallback_kill(h)
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
    blocks the forking thread until the tool has ended. If a timed-out tool's tree was
    listening beyond loopback, the stop raises :class:`NonLoopbackListener` (a
    :class:`ProcUtilError`) **instead of** ``TimeoutExpired``; a caller that catches
    only ``TimeoutExpired`` lets it through, as it should (BUG-0130)."""
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

class _AsyncSupervisorProc:
    """An asyncio view of the supervisor's :class:`subprocess.Popen` that never reaps
    it: asyncio's own child watcher would reap ``create_subprocess_exec`` children as
    soon as they exit, freeing the session id before the owner's sweep (BUG-0125
    review M2(a)). Exit is observed with ``waitid(WNOWAIT)``; the owner reaps it after
    the sweep (:func:`astop_server`)."""

    def __init__(self, h: ServerHandle, popen: subprocess.Popen,
                 stdout: Any, stderr: Any) -> None:
        self._h = h
        self._popen = popen
        self.pid = popen.pid
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None

    async def wait(self) -> int:
        import asyncio

        while self.returncode is None:
            code = _peek_code(self._h)
            if code is not None:
                self.returncode = code
                break
            await asyncio.sleep(0.05)
        return self.returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        import asyncio

        async def read(stream: Any) -> bytes:
            return b"" if stream is None else await stream.read()

        out, err = await asyncio.gather(read(self.stdout), read(self.stderr))
        await self.wait()
        return out, err


async def _stream_reader(loop: Any, pipe: Any) -> Any:
    import asyncio

    if pipe is None:
        return None
    reader = asyncio.StreamReader(loop=loop)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader, loop=loop), pipe)
    return reader


async def astart_server(argv: Sequence[str], *, env: dict[str, str] | None = None,
                        stdin: Any = subprocess.DEVNULL, stdout: Any = None, stderr: Any = None,
                        grace: float = DEFAULT_GRACE_S, allow_thread: bool = False,
                        ready_timeout: float = READY_TIMEOUT_S,
                        umask: int | None = None) -> ServerHandle:
    """:func:`start_server` for asyncio: ``handle.proc`` offers ``stdout`` / ``stderr``
    (:class:`asyncio.StreamReader` for ``PIPE``), ``wait()``, ``communicate()`` and
    ``returncode`` -- and never reaps the supervisor before the owner's sweep. The
    forking thread is the event loop's.

    ``umask`` (CC-CORE-0450): set on the supervisor, so the whole tree inherits it -- the
    web UI starts project-pinned jobs with ``0o077`` so every file a tool creates in a
    project's directory is private. ``None`` keeps this process's umask."""
    import asyncio

    _check_thread(allow_thread)
    loop = asyncio.get_running_loop()
    h, popen = _spawn_supervisor(argv, grace, env=env, stdin=stdin, stdout=stdout, stderr=stderr,
                                 umask=-1 if umask is None else umask)
    h.proc = _AsyncSupervisorProc(h, popen, await _stream_reader(loop, popen.stdout),
                                  await _stream_reader(loop, popen.stderr))
    return await loop.run_in_executor(None, _complete_start, h, h._status, ready_timeout,
                                      *_start_failure_paths(h, popen))


async def astop_server(h: ServerHandle, *, timeout: float | None = None) -> str:
    """:func:`stop_server` for a handle from :func:`astart_server` (same steps, run off
    the event loop)."""
    import asyncio

    await asyncio.get_running_loop().run_in_executor(None, _stop_core, h, timeout)
    _raise_if_lost(h)
    return h.exit_reason or ""


async def arun_bounded(argv: Sequence[str], *, timeout: float,
                       env: dict[str, str] | None = None) -> tuple[int | None, bytes, bytes, bool]:
    """Async bounded run for a forking tool: ``(returncode, stdout, stderr,
    timed_out)``. On timeout the tool's whole tree is stopped. ``returncode`` is None on
    a timeout, and also when the exit status is unknown (the supervisor was reaped
    outside fuzzlab) -- never ``CODE_UNKNOWN``."""
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
    await astop_server(h)  # exited: sweep (held), reap, collect
    code = h.proc.returncode
    return (None if code == CODE_UNKNOWN else code), out, err, False


if __name__ == "__main__":
    sys.exit(_supervisor_main(sys.argv[1:]))
