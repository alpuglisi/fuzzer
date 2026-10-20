"""One pytest session at a time on this host (BUG-0532, PA-0532).

"One pytest at a time" was prose plus a lock that only ``scripts/verify_change.py``
took, and ad-hoc runs broke it six times in two days (F-092..F-102). This plugin makes
every pytest session in this repository's test tree take one host-wide lock. The root
``tests/conftest.py`` calls :func:`pytest_configure` first in its own configure hook,
and :func:`pytest_unconfigure`.

Who takes the lock
  * The session's controller. It takes an exclusive ``fcntl.flock`` on
    :func:`default_lock_path` (``/tmp/fuzzlab-pytest.lock``, whatever ``TMPDIR`` says)
    at ``pytest_configure``, and holds it until ``pytest_unconfigure`` or process exit
    (the kernel drops it if the process dies).
  * Never an xdist worker (``config.workerinput``, which xdist sets in every worker
    before its configure). Its controller holds the lock. ``PYTEST_XDIST_WORKER``
    alone is not trusted: xdist exports it to every process a worker's test starts,
    and anyone can set it.
  * Never a process nested in the holder. Such a process carries the holder's token,
    ``FUZZLAB_PYTEST_LOCK_HELD=<pid>``: the holder sets it in its environment, so its
    workers and children inherit it. The pid must be in the process's ancestor chain,
    and must be the lock's real holder (the kernel's ``/proc/locks``; without it, the
    side file's pid and ``/proc`` start time). A token copied into another shell, or
    set to the shell's own pid, does not pass.
  * A session nested in this same process (``pytest.main`` from a test) reuses the
    hold.

Everyone else waits, naming the holder (pid, argv, cwd and start time, from the side
file ``<lock>.holder``), for up to ``FUZZLAB_PYTEST_LOCK_WAIT`` seconds. The default is
1800, the same as ``verify_change.py --wait-other``; 0 means refuse at once if busy.
Then the session exits with a usage error (exit code 4) and runs nothing. A
descendant of the holder without its token fails at once: it would otherwise wait for
its own ancestor, a deadlock. Its parent must pass the environment on.

There is no off switch. ``FUZZLAB_PYTEST_LOCK_PATH`` (another lock file) is honoured
only inside a session that holds the host lock. It exists for this plugin's own tests
(``tests/test_pytest_lock.py``) and is refused anywhere else.
``FUZZLAB_PYTEST_LOCK_TRACE=<file>`` appends one JSON line per decision; it is for
measurement only. Without ``fcntl`` (not POSIX) the session warns and runs unlocked.

Known limit: ``pytest --noconftest`` turns off every conftest guard, this one
included. It is never a routine invocation.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import sys
import tempfile
import time
import warnings
from pathlib import Path

import pytest

from fuzzlab.procutil import read_stat

try:
    import fcntl
except ImportError:  # not POSIX: warn and run unlocked
    fcntl = None  # type: ignore[assignment]

LOCK_NAME = "fuzzlab-pytest.lock"
ENV_TOKEN = "FUZZLAB_PYTEST_LOCK_HELD"
ENV_WAIT = "FUZZLAB_PYTEST_LOCK_WAIT"
ENV_PATH = "FUZZLAB_PYTEST_LOCK_PATH"
ENV_TRACE = "FUZZLAB_PYTEST_LOCK_TRACE"
DEFAULT_WAIT_S = 1800.0
POLL_S = 0.5
RULE = "one pytest session at a time on this host, BUG-0532"

_STATE = pytest.StashKey[dict]()
#: The locks this process holds: path -> {"fd": int, "previous_token": str | None}.
_HELD: dict[str, dict] = {}
_AT_EXIT: list[bool] = []


# --------------------------------------------------------------------- facts


def default_lock_path() -> str:
    """The host lock. Under ``/tmp`` rather than ``tempfile.gettempdir()``: a process
    with its own ``TMPDIR`` would otherwise take a lock nobody else sees."""
    base = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()
    return os.path.join(base, LOCK_NAME)


def holder_file(path: str) -> str:
    return path + ".holder"


def ancestors(pid: int | None = None) -> list[int]:
    """``pid`` (default: this process) and its ancestors, nearest first, from ``/proc``."""
    chain: list[int] = []
    cur = os.getpid() if pid is None else pid
    while cur > 0 and cur not in chain:
        chain.append(cur)
        st = read_stat(cur)
        if st is None:
            break
        cur = st.ppid
    return chain


def _argv(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return list(sys.argv) if pid == os.getpid() else []
    return [a.decode(errors="replace") for a in raw.split(b"\0") if a]


def kernel_holder(path: str) -> int | None:
    """The pid the kernel records for the exclusive ``flock`` on ``path`` (from
    ``/proc/locks``), or None when no such lock is listed or the table is unreadable."""
    try:
        st = os.stat(path)
        rows = Path("/proc/locks").read_text().splitlines()
    except OSError:
        return None
    ident = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
    for row in rows:
        f = row.split()
        # "N: FLOCK  ADVISORY  WRITE <pid> <maj:min:inode> 0 EOF"; a blocked waiter has "->"
        if len(f) >= 6 and f[1] == "FLOCK" and f[3] == "WRITE" and f[5] == ident:
            with contextlib.suppress(ValueError):
                return int(f[4])
    return None


def read_holder(path: str) -> dict:
    try:
        info = json.loads(Path(holder_file(path)).read_text())
    except (OSError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}


def current_holder(path: str) -> tuple[int | None, dict]:
    """``(pid, info)`` of the process holding ``path``. The pid is the kernel's when
    ``/proc/locks`` lists one; otherwise it is the side file's, trusted only while that
    process lives with the recorded start time. ``info`` describes the holder for
    messages."""
    info = read_holder(path)
    pid = kernel_holder(path)
    if pid is None:
        p, start = info.get("pid"), info.get("start")
        st = read_stat(p) if isinstance(p, int) else None
        if st is not None and start is not None and st.start == start:
            pid = p
    if pid is not None and info.get("pid") != pid:  # side file stale or not yet written
        info = {"pid": pid, "argv": _argv(pid)}
    return pid, info


def nested_verdict(holder: int | None) -> str | None:
    """``"nested"`` when this process descends from ``holder`` and carries its token;
    ``"tokenless"`` when it descends from it without the token (waiting would
    deadlock); None when ``holder`` is not an ancestor (another session: wait)."""
    if holder is None or holder not in ancestors():
        return None
    return "nested" if os.environ.get(ENV_TOKEN, "") == str(holder) else "tokenless"


def host_lock_held_by_ancestor() -> bool:
    """Does an ancestor of this process (or this process) hold the host lock?"""
    pid, _ = current_holder(default_lock_path())
    return pid is not None and pid in ancestors()


def decision(config) -> str | None:
    """What this session decided (``acquired``, ``worker``, ``nested``, ...), or None
    if the hook never ran in it."""
    state = config.stash.get(_STATE, None)
    return None if state is None else state.get("decision")


# ------------------------------------------------------------------ helpers


def _describe(info: dict) -> str:
    pid = info.get("pid")
    argv = " ".join(info.get("argv") or []) or "(argv unknown)"
    if len(argv) > 300:
        argv = argv[:297] + "..."
    who = f"pid {pid}" if pid is not None else "an unidentified process"
    extra = []
    if info.get("since"):
        extra.append(f"since {info['since']}")
    if info.get("cwd"):
        extra.append(f"cwd {info['cwd']}")
    return f"{who}: {argv}" + (f" ({', '.join(extra)})" if extra else "")


def _trace(event: str, path: str | None, **extra) -> None:
    target = os.environ.get(ENV_TRACE)
    if not target:
        return
    st = read_stat(os.getpid())
    line = json.dumps({"event": event, "pid": os.getpid(), "ppid": st.ppid if st else None,
                       "path": path, "worker": os.environ.get("PYTEST_XDIST_WORKER"),
                       "t": time.time(), **extra})
    with contextlib.suppress(OSError):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
        try:
            os.write(fd, (line + "\n").encode())
        finally:
            os.close(fd)


def _say(config, text: str) -> None:
    capman = config.pluginmanager.getplugin("capturemanager")
    ctx = capman.global_and_fixture_disabled() if capman is not None else contextlib.nullcontext()
    with ctx:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()


def _wait_seconds() -> float:
    raw = os.environ.get(ENV_WAIT)
    if raw is None or raw.strip() == "":
        return DEFAULT_WAIT_S
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not value >= 0 or value == float("inf"):
        raise pytest.UsageError(f"{ENV_WAIT}={raw!r} is not a number of seconds >= 0")
    return value


def lock_path() -> str:
    """The lock this session takes: the host lock, or ``FUZZLAB_PYTEST_LOCK_PATH`` when
    an ancestor holds the host lock (this plugin's own tests); refused otherwise."""
    default = default_lock_path()
    custom = os.environ.get(ENV_PATH)
    if not custom or os.path.abspath(custom) == default:
        return default
    custom = os.path.abspath(custom)
    if not host_lock_held_by_ancestor():
        raise pytest.UsageError(
            f"{ENV_PATH}={custom} is honoured only inside a pytest session that holds the "
            f"host lock {default} (this lock's own tests; {RULE}). It is not a way to run "
            f"beside another session: unset it.")
    return custom


def _open(path: str) -> int:
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, os.O_RDWR | os.O_CREAT | cloexec, 0o666)
    except PermissionError:  # another user's lock file: a read-only fd locks just as well
        return os.open(path, os.O_RDONLY | cloexec)


def _write_holder(path: str) -> None:
    st = read_stat(os.getpid())
    info = {"pid": os.getpid(), "start": st.start if st else None, "argv": _argv(os.getpid()),
            "cwd": os.getcwd(), "lock": path,
            "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    tmp = f"{holder_file(path)}.{os.getpid()}.tmp"
    try:
        Path(tmp).write_text(json.dumps(info))
        os.replace(tmp, holder_file(path))
    except OSError as exc:  # the lock still holds; only the waiters' message is poorer
        warnings.warn(f"could not write the pytest lock's holder file: {exc}", stacklevel=2)
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _acquire(config, path: str, wait: float) -> int | None:
    """Hold ``path`` and return its fd; None when this process is nested in the holder.
    Raises ``pytest.UsageError`` on timeout, or for a holder's descendant without its
    token."""
    fd = _open(path)
    deadline = time.monotonic() + wait
    shown: object = object()
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    raise
            else:
                _write_holder(path)
                return fd
            pid, info = current_holder(path)
            verdict = nested_verdict(pid)
            if verdict == "nested":
                os.close(fd)
                return None
            if verdict == "tokenless":
                _trace("refused-tokenless", path, holder=pid)
                raise pytest.UsageError(
                    f"this pytest descends from the holder of the pytest lock {path} "
                    f"({_describe(info)}) but does not carry its token {ENV_TOKEN}={pid} "
                    f"(it has {os.environ.get(ENV_TOKEN)!r}), so waiting would deadlock. The "
                    f"process that started it stripped or changed its environment: pass "
                    f"os.environ on ({RULE}).")
            if pid != shown:
                shown = pid
                _trace("waiting", path, holder=pid)
                _say(config, f"fuzzlab: waiting for the pytest lock {path} ({RULE}).\n"
                             f"  held by {_describe(info)}\n"
                             f"  this session runs nothing until it is free; it gives up "
                             f"after {wait:.0f} s ({ENV_WAIT}).")
            if time.monotonic() >= deadline:
                _trace("refused-timeout", path, holder=pid)
                raise pytest.UsageError(
                    f"the pytest lock {path} is still held by {_describe(info)} after "
                    f"{wait:.0f} s ({ENV_WAIT}). Refusing to run beside it ({RULE}); "
                    f"nothing was run.")
            time.sleep(max(0.05, min(POLL_S, deadline - time.monotonic())))
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def _release_path(path: str) -> None:
    hold = _HELD.pop(path, None)
    if hold is None:
        return
    if read_holder(path).get("pid") == os.getpid():  # side file first, while still held
        with contextlib.suppress(OSError):
            os.unlink(holder_file(path))
    _trace("released", path)  # still held: no waiter's "acquired" can precede this line
    with contextlib.suppress(OSError):
        os.close(hold["fd"])
    if os.environ.get(ENV_TOKEN) == str(os.getpid()):
        if hold["previous_token"] is None:
            os.environ.pop(ENV_TOKEN, None)
        else:
            os.environ[ENV_TOKEN] = hold["previous_token"]


def _release_all_at_exit() -> None:
    for path in list(_HELD):
        _release_path(path)


# -------------------------------------------------------------------- hooks


def _decide(state: dict, what: str, path: str | None = None) -> str:
    state["decision"] = what
    _trace(what, path)
    return what


def pytest_configure(config) -> None:
    """Take the host lock for this session, or record why this process need not."""
    state: dict = {"decision": None, "path": None, "owner": False}
    config.stash[_STATE] = state
    if hasattr(config, "workerinput"):
        _decide(state, "worker")
        return
    if getattr(config.option, "help", False) or getattr(config.option, "markers", False):
        _decide(state, "no-session")  # prints static text, runs and collects nothing
        return
    if fcntl is None:
        warnings.warn("fcntl is unavailable on this platform: this pytest session runs "
                      f"WITHOUT the host pytest lock ({RULE})", stacklevel=2)
        _say(config, f"fuzzlab: WARNING: no fcntl here; running WITHOUT the pytest lock ({RULE}).")
        _decide(state, "unlocked-no-fcntl")
        return
    try:
        path = lock_path()
    except pytest.UsageError:
        _trace("refused-path", os.environ.get(ENV_PATH))
        raise
    state["path"] = path
    if path in _HELD:
        _decide(state, "nested-in-process", path)
        return
    fd = _acquire(config, path, _wait_seconds())
    if fd is None:
        _decide(state, "nested", path)
        return
    if not _AT_EXIT:
        import atexit
        atexit.register(_release_all_at_exit)
        _AT_EXIT.append(True)
    _HELD[path] = {"fd": fd, "previous_token": os.environ.get(ENV_TOKEN)}
    os.environ[ENV_TOKEN] = str(os.getpid())
    state["owner"] = True
    _decide(state, "acquired", path)


def pytest_unconfigure(config) -> None:
    state = config.stash.get(_STATE, None)
    if state is None or not state.get("owner"):
        return
    state["owner"] = False
    _release_path(state["path"])
