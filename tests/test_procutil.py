"""Real-process tests for ``fuzzlab.procutil`` (BUG-0125, PA-0125, FR-CORE-38,
NFR-LAB-cleanup): a process the toolkit or its tests start owns its whole tree,
grandchildren included; nothing survives ``stop_server`` or the owner's death; a
reused pid is never signalled.

Every process here is a local ``sh``/``python``/``sleep``/``go run`` child bound to
loopback at most; nothing sends traffic anywhere. The owner processes these tests
start with ``subprocess.Popen`` are deliberately SIGKILLed and reaped by the test
itself (the one allowlisted use, see ``tests/test_procutil_guard.py``).
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from fuzzlab import procutil
from tests._procs import raw_members

REPO = Path(__file__).resolve().parent.parent
BOUND_S = 10.0

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="procutil's supervisor is Linux-only (prctl)")


@pytest.fixture(autouse=True)
def _no_registered_leftovers():
    """Each test stops what it starts: a handle still registered afterwards is
    stopped here and fails the test that leaked it (not a later one)."""
    before = set(map(id, procutil.registered()))
    yield
    left = [h for h in procutil.registered() if id(h) not in before]
    for h in left:
        try:
            procutil.stop_server(h)
        except procutil.ProcUtilError:
            pass
    assert not left, f"test left registered servers: {[h.argv for h in left]}"


def _alive(pid: int, start: int) -> bool:
    st = procutil.read_stat(pid)
    return st is not None and st.start == start and st.state != "Z"


def _wait_gone(pids: list[tuple[int, int]], bound: float = BOUND_S) -> list[int]:
    deadline = time.monotonic() + bound
    while time.monotonic() < deadline:
        left = [pid for pid, start in pids if _alive(pid, start)]
        if not left:
            return []
        time.sleep(0.05)
    return [pid for pid, start in pids if _alive(pid, start)]


def _tree(h: procutil.ServerHandle) -> list[tuple[int, int]]:
    return [(st.pid, st.start) for st in procutil.session_members(h.pid, h.start_time)]


def _wait_members(h: procutil.ServerHandle, n: int) -> list[tuple[int, int]]:
    deadline = time.monotonic() + BOUND_S
    while time.monotonic() < deadline:
        tree = _tree(h)
        if len(tree) >= n:
            return tree
        time.sleep(0.05)
    raise AssertionError(f"expected {n} processes in the server's session, saw {_tree(h)}")


#: A server that forks a grandchild which escapes the group *and* the session
#: (setsid + double fork) -- the hardest shape a supervisor must still catch.
ESCAPING_PROGRAM = textwrap.dedent("""
    import os, sys, time
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            print("GRAND", os.getpid(), flush=True)
            time.sleep(300)
        os._exit(0)
    print("CHILD", os.getpid(), flush=True)
    time.sleep(300)
""")


# --- stop_server ---------------------------------------------------------------

def test_stop_server_takes_the_whole_tree_and_reaps() -> None:
    h = procutil.start_server(["sh", "-c", "sleep 300 & sleep 300 & wait"])
    tree = _wait_members(h, 4)  # supervisor, sh, two sleeps
    assert procutil.stop_server(h) == "stop"
    assert _wait_gone(tree, bound=0.5) == []
    assert h.proc.returncode is not None  # reaped
    assert h not in procutil.registered()
    assert procutil.stop_server(h) == "stop"  # idempotent


def test_stop_server_catches_a_grandchild_that_escaped_group_and_session() -> None:
    h = procutil.start_server([sys.executable, "-c", ESCAPING_PROGRAM],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _escaped_grandchild_checks(h)
    except AssertionError as exc:
        procutil.stop_server(h)
        raise AssertionError(f"{exc}\n--- supervisor stderr ---\n{h.proc.stderr.read()}") from exc


def _escaped_grandchild_checks(h: procutil.ServerHandle) -> None:
    pids: dict[str, int] = {}
    for _ in range(6):  # two processes share the pipe: parse tokens, not line shapes
        import re

        for kind, pid in re.findall(r"(CHILD|GRAND) (\d+)", h.proc.stdout.readline()):
            pids[kind] = int(pid)
        if len(pids) == 2:
            break
    assert set(pids) == {"CHILD", "GRAND"}, pids
    grand = procutil.read_stat(pids["GRAND"])
    assert grand is not None and grand.sid != h.pid  # it really left the session
    targets = [(pids["CHILD"], procutil.read_stat(pids["CHILD"]).start), (grand.pid, grand.start)]
    procutil.stop_server(h)
    # deterministic: the supervisor exits only once no descendant is left alive
    assert [pid for pid, start in targets if _alive(pid, start)] == []


def test_a_server_that_exits_on_its_own_is_collected_with_its_code() -> None:
    h = procutil.start_server(["sh", "-c", "sleep 300 & exit 7"])
    assert h.proc.wait(timeout=BOUND_S) == 7
    assert procutil.finish(h) == "child"
    assert raw_members("sid", h.pid, h.start_time) == []  # the orphaned sleep too


def test_exec_failure_is_the_real_oserror() -> None:
    with pytest.raises(FileNotFoundError):
        procutil.start_server(["/nonexistent/fuzzlab-bug-0125"])


# --- owner death ----------------------------------------------------------------

OWNER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    from fuzzlab import procutil
    h = procutil.start_server(sys.argv[2:])
    print("SUP", h.pid, h.start_time, flush=True)
    time.sleep(300)
""")


def _run_owner(argv: list[str]) -> tuple[subprocess.Popen, int, int]:
    owner = subprocess.Popen([sys.executable, "-c", OWNER, str(REPO), *argv],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _, pid, start = owner.stdout.readline().split()
    return owner, int(pid), int(start)


def _kill_owner_and_check(owner: subprocess.Popen, tree: list[tuple[int, int]]) -> None:
    owner.kill()
    owner.wait()
    assert _wait_gone(tree) == [], "a server outlived its SIGKILLed owner"
    # the supervisor (which shares the owner's stderr) knew why it stopped
    assert f"owner {owner.pid} is gone" in owner.stderr.read()


def test_owner_sigkill_takes_child_and_escaped_grandchild() -> None:
    owner, sup, start = _run_owner([sys.executable, "-c", ESCAPING_PROGRAM])
    _kill_on_failure(owner)
    deadline = time.monotonic() + BOUND_S
    tree: list[tuple[int, int]] = []
    while time.monotonic() < deadline:
        # the escaped grandchild is no longer in the supervisor's session, but it is
        # still its descendant (subreaper): collect the whole ppid tree.
        stats = {st.pid: st for st in procutil._iter_stats()}
        mine = [st for p, st in stats.items() if _descends(p, sup, stats)]
        tree = [(st.pid, st.start) for st in mine]
        if len(mine) >= 2 and any(st.sid != sup for st in mine):  # the escaped grandchild is up
            break
        time.sleep(0.05)
    assert len(tree) >= 2, tree
    _kill_owner_and_check(owner, tree + [(sup, start)])


_OWNERS: list[subprocess.Popen] = []


def _kill_on_failure(owner: subprocess.Popen) -> None:
    """Owners are SIGKILLed by the test; if it fails first, the fixture below does it
    (its supervisor then stops the server: the property under test)."""
    _OWNERS.append(owner)


@pytest.fixture(autouse=True)
def _reap_owners():
    yield
    while _OWNERS:
        owner = _OWNERS.pop()
        if owner.poll() is None:
            owner.kill()
        owner.wait()


def _descends(pid: int, ancestor: int, stats: dict) -> bool:
    seen = 0
    while pid in stats and seen < 64:
        pid = stats[pid].ppid
        if pid == ancestor:
            return True
        seen += 1
    return False


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain not on PATH")
def test_owner_sigkill_takes_go_run_and_its_built_binary(tmp_path: Path) -> None:
    main_go = tmp_path / "main.go"
    main_go.write_text(textwrap.dedent("""
        package main

        import (
            "fmt"
            "net"
            "os"
            "time"
        )

        func main() {
            ln, err := net.Listen("tcp", "127.0.0.1:0")
            if err != nil {
                panic(err)
            }
            fmt.Println(ln.Addr().String())
            os.Stdout.Sync()
            time.Sleep(300 * time.Second)
        }
    """))
    owner, sup, start = _run_owner(["go", "run", str(main_go)])
    _kill_on_failure(owner)
    deadline = time.monotonic() + 120
    tree: list[tuple[int, int]] = []
    while time.monotonic() < deadline:
        members = procutil.session_members(sup, start)
        if any("/exe/main" in _cmdline(st.pid) for st in members):
            tree = [(st.pid, st.start) for st in members]
            break
        time.sleep(0.2)
    assert tree, "go run never started its built binary"
    _kill_owner_and_check(owner, tree)


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
    except (FileNotFoundError, ProcessLookupError):
        return ""


def test_supervisor_refuses_to_start_when_its_owner_is_not_its_parent() -> None:
    """The startup re-check that closes the owner-died-before-prctl race: a
    supervisor whose parent is not the owner it was given exits without ever
    starting the server."""
    status_r, status_w = os.pipe()
    control_r, control_w = os.pipe()
    sup = subprocess.Popen(  # noqa: S603 -- drives the supervisor entry point directly
        [sys.executable, "-I", "-S", procutil.__file__, "--owner", "1", "--grace", "1.0",
         "--status-fd", str(status_w), "--control-fd", str(control_r), "--", "sleep", "300"],
        pass_fds=(status_w, control_r), start_new_session=True)
    os.close(status_w)
    os.close(control_r)
    try:
        assert sup.wait(timeout=BOUND_S) == 125
        with os.fdopen(status_r) as fh:
            assert fh.read().startswith("error kind=owner-gone")
        assert raw_members("sid", sup.pid, 0) == []  # no server was started
    finally:
        os.close(control_w)


# --- identity -----------------------------------------------------------------

def test_a_stale_record_whose_pid_was_reused_is_never_signalled() -> None:
    """A registry record outlived its supervisor; its pid now belongs to a fresh
    ``sleep`` in its own session. The safety net and the group/session sweeps must
    leave that process alone (start time differs)."""
    old = procutil.start_server(["sleep", "300"])
    stale_start, stale_child_start = old.start_time, old.child_start_time
    procutil.stop_server(old)
    victim = _bystander(["sleep", "300"])
    try:
        vstat = procutil.read_stat(victim.pid)
        assert vstat is not None and vstat.start != stale_start
        record = procutil.ServerHandle(argv=("sleep", "300"), pid=victim.pid, start_time=stale_start,
                                       child_pid=victim.pid, child_start_time=stale_child_start)
        procutil._register(record)
        assert procutil.is_live(record) is False
        assert procutil.reap_registered() == []  # dropped, not reported, not signalled
        assert procutil.kill_process_group(victim.pid, stale_child_start, signal.SIGKILL) == 0
        assert procutil._signal_checked(victim.pid, stale_start, signal.SIGKILL) is False
        assert procutil.session_members(victim.pid, stale_start) == []
        time.sleep(0.2)
        assert victim.poll() is None, "a reused pid was signalled"
    finally:
        victim.kill()
        victim.wait()


def _bystander(argv: list[str], **kw) -> subprocess.Popen:
    """A process the test starts in its own session that procutil must NOT treat as
    one of its servers (the one place these tests use a bare Popen for it)."""
    return subprocess.Popen(argv, start_new_session=True, **kw)  # noqa: S603


def _with_fake_proc_entries(monkeypatch, extra: list, hidden: frozenset = frozenset()) -> None:
    """Make /proc show ``extra`` ProcStat rows (and hide ``hidden`` pids from
    ``read_stat``) -- a reused pid, group or session, without waiting for pid wrap."""
    real_iter, real_read = procutil._iter_stats, procutil.read_stat
    monkeypatch.setattr(procutil, "_iter_stats", lambda: iter([*real_iter(), *extra]))
    monkeypatch.setattr(procutil, "read_stat",
                        lambda pid: None if pid in hidden else real_read(pid))


def test_a_reaped_supervisors_session_is_never_swept(monkeypatch) -> None:
    """BUG-0125 review M2: once the supervisor is reaped its session id is free; a
    process that later carries that sid (faked here) is not ours and is never
    signalled -- not by the sweep, not by the session enumeration."""
    h = procutil.start_server(["sleep", "300"])
    procutil.stop_server(h)
    victim = _bystander(["sleep", "300"])
    try:
        vst = procutil.read_stat(victim.pid)
        fake = procutil.ProcStat(pid=victim.pid, ppid=1, pgid=victim.pid, sid=h.pid,
                                 start=vst.start, state="S")
        _with_fake_proc_entries(monkeypatch, [fake], hidden=frozenset({h.pid}))
        assert procutil.session_members(h.pid, h.start_time) == []
        assert procutil._sweep_session(h) == []
        assert procutil.is_live(h) is False
        monkeypatch.undo()
        time.sleep(0.2)
        assert victim.poll() is None, "a process in a reused session was signalled"
    finally:
        victim.kill()
        victim.wait()


def test_the_fallback_never_signals_a_reused_server_group_outside_the_session(monkeypatch) -> None:
    """BUG-0125 review M2(b): the server's pgid is usually free by fallback time; a
    process that carries it (faked) but is not in the still-held supervisor's session
    is never signalled, while the real tree is stopped."""
    h = procutil.start_server(["sh", "-c", "sleep 300 & wait"], grace=0.5)
    tree = _wait_members(h, 3)
    victim = _bystander(["sleep", "300"])
    try:
        vst = procutil.read_stat(victim.pid)
        fake = procutil.ProcStat(pid=victim.pid, ppid=1, pgid=h.child_pid, sid=victim.pid,
                                 start=vst.start, state="S")
        os.kill(h.pid, signal.SIGSTOP)  # wedged
        _with_fake_proc_entries(monkeypatch, [fake], hidden=frozenset({h.child_pid}))  # leader "gone"
        procutil._fallback_kill(h)
        monkeypatch.undo()
        assert h.proc.wait(timeout=BOUND_S) == -signal.SIGKILL
        assert procutil.finish(h) == "killed"
        assert _wait_gone(tree) == []
        time.sleep(0.2)
        assert victim.poll() is None, "a process outside the supervisor's session was signalled"
    finally:
        victim.kill()
        victim.wait()


def test_a_killed_supervisors_leftovers_are_swept_while_its_pid_is_held() -> None:
    """The owner's sweep runs before it reaps the supervisor (its pid, the session id,
    is still held): a supervisor SIGKILLed from outside leaves a background child,
    which the sweep stops."""
    h = procutil.start_server(["sh", "-c", "sleep 300 & echo $!; wait"], stdout=subprocess.PIPE,
                              text=True)
    sleeper = int(h.proc.stdout.readline())
    sst = procutil.read_stat(sleeper)
    os.kill(h.pid, signal.SIGKILL)  # the supervisor dies without cleaning up
    deadline = time.monotonic() + BOUND_S
    while _alive(h.child_pid, h.child_start_time):
        assert time.monotonic() < deadline
        time.sleep(0.02)  # sh dies of its PDEATHSIG(SIGKILL); the sleep is left
    assert _alive(sleeper, sst.start)
    assert procutil.stop_server(h) == "killed"
    assert _wait_gone([(sleeper, sst.start)]) == []


def test_an_async_handle_is_swept_before_it_is_reaped() -> None:
    """Same, through the asyncio path: astart_server's process view never lets
    asyncio reap the supervisor before astop_server's sweep."""
    import asyncio

    async def go():
        h = await procutil.astart_server(["sh", "-c", "sleep 300 & echo $!; wait"],
                                         stdout=subprocess.PIPE, allow_thread=True)
        sleeper = int((await h.proc.stdout.readline()).decode())
        sst = procutil.read_stat(sleeper)
        os.kill(h.pid, signal.SIGKILL)
        assert await asyncio.wait_for(h.proc.wait(), BOUND_S) == -signal.SIGKILL
        assert procutil.read_stat(h.pid) is not None  # exited, not reaped: still held
        reason = await procutil.astop_server(h)
        return reason, sleeper, sst

    reason, sleeper, sst = asyncio.run(go())
    assert reason == "killed"
    assert _wait_gone([(sleeper, sst.start)]) == []


def test_an_unknown_start_time_never_signals_anything() -> None:
    """BUG-0125 review B2: a start time of 0 means "identity unknown", never "match
    anything". A group whose leader is gone has a live member; a record with start 0
    naming it signals nothing and is reported."""
    sh = _bystander(["sh", "-c", "sleep 300 & echo $!"], stdout=subprocess.PIPE, text=True)
    sleeper = int(sh.stdout.readline())
    sh.wait()
    sst = procutil.read_stat(sleeper)
    try:
        assert sst is not None and sst.pgid == sh.pid
        assert procutil.group_members(sh.pid, 0) == []
        assert procutil.kill_process_group(sh.pid, 0, signal.SIGKILL) == 0
        assert procutil.group_members(sh.pid, 1) == []  # leader not held, no anchor
        record = procutil.ServerHandle(argv=("x",), pid=sh.pid, start_time=0,
                                       child_pid=sh.pid, child_start_time=0)
        procutil._register(record)
        leaks = procutil.reap_registered()
        assert [leak.note for leak in leaks if leak.pid == sh.pid] == ["identity unknown: not signalled"]
        time.sleep(0.2)
        assert _alive(sleeper, sst.start), "an unknown identity was signalled"
    finally:
        procutil._signal_checked(sleeper, sst.start, signal.SIGKILL)


def test_start_server_refuses_a_server_whose_identity_cannot_be_recorded(monkeypatch) -> None:
    """Loud, not silent (B2): with no /proc start time for the supervisor, start_server
    stops what it started and raises."""
    real, seen = procutil.read_stat, []

    def first_unknown(pid: int):
        if not seen:
            seen.append(pid)
            return None
        return real(pid)

    monkeypatch.setattr(procutil, "read_stat", first_unknown)
    with pytest.raises(procutil.ProcUtilError, match="identity cannot be checked"):
        procutil.start_server(["sleep", "300"])
    monkeypatch.undo()
    assert raw_members("sid", seen[0], 0) == []


SPY = textwrap.dedent("""
    import importlib.util, os, sys
    log, path = sys.argv[1], sys.argv[2]
    spec = importlib.util.spec_from_file_location("procutil_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    real_killpg = os.killpg

    def spy(pgid, sig):
        with open(log, "a") as fh:
            fh.write(f"{pgid} {sig} {int(mod.read_stat(pgid) is not None)}\\n")
        return real_killpg(pgid, sig)

    os.killpg = spy
    sys.exit(mod._supervisor_main(sys.argv[3:]))
""")


def test_the_supervisor_signals_the_servers_group_only_while_its_leader_is_held(
        tmp_path: Path, monkeypatch) -> None:
    """BUG-0125 review M1: the supervisor must not reap its server mid-termination and
    then keep calling killpg on the freed group id. The server exits on SIGTERM; its
    child setsid()s and ignores SIGTERM, so the SIGKILL phase runs. Every killpg is
    spied on (in the real supervisor process) and must find the leader pid held."""
    spy, log = tmp_path / "spy.py", tmp_path / "killpg.log"
    spy.write_text(SPY)
    real_argv = procutil._supervisor_argv

    def spied(argv, grace, status_w, control_r):
        full = real_argv(argv, grace, status_w, control_r)
        i = full.index(procutil._SUPERVISOR_SCRIPT)
        return [*full[:i], str(spy), str(log), procutil._SUPERVISOR_SCRIPT, *full[i + 1:]]

    monkeypatch.setattr(procutil, "_supervisor_argv", spied)
    prog = textwrap.dedent("""
        import os, signal, time
        if os.fork() == 0:
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            print(os.getpid(), flush=True)
            time.sleep(300)
            os._exit(0)
        time.sleep(300)
    """)
    h = procutil.start_server([sys.executable, "-c", prog], stdout=subprocess.PIPE, text=True,
                              grace=0.5)
    escaped = int(h.proc.stdout.readline())
    est = procutil.read_stat(escaped)
    assert procutil.stop_server(h) == "stop"
    calls = [line.split() for line in log.read_text().splitlines()]
    assert any(sig == str(int(signal.SIGKILL)) for _, sig, _ in calls), calls  # non-vacuous
    assert all(held == "1" for _, _, held in calls), f"killpg on a freed group id: {calls}"
    assert _wait_gone([(escaped, est.start)]) == []


SLOW_READY = textwrap.dedent("""
    import importlib.util, sys, time
    delay, path = float(sys.argv[1]), sys.argv[2]
    spec = importlib.util.spec_from_file_location("procutil_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    real_report = mod._Supervisor.report

    def slow(self, line):
        if line.startswith("ready"):
            time.sleep(delay)  # the server is up, but its ready line is late
        return real_report(self, line)

    mod._Supervisor.report = slow
    sys.exit(mod._supervisor_main(sys.argv[3:]))
""")

RECORDING_SERVER = textwrap.dedent("""
    import os, sys, time

    def record():
        data = open("/proc/self/stat", "rb").read()
        start = int(data[data.rindex(b")") + 2:].split()[19])
        with open(sys.argv[1], "a") as fh:
            fh.write(f"{os.getpid()} {start} {os.getsid(0)}\\n")

    record()
    if os.fork() == 0:  # stays in the session
        record()
        time.sleep(300)
        os._exit(0)
    if os.fork() == 0:  # escapes group and session
        os.setsid()
        record()
        time.sleep(300)
        os._exit(0)
    time.sleep(300)
""")


def _wrap_supervisor(monkeypatch, wrapper: Path, *extra: str) -> None:
    """Run the real supervisor entry point under ``wrapper`` (a test-only shim)."""
    real_argv = procutil._supervisor_argv

    def wrapped(argv, grace, status_w, control_r):
        full = real_argv(argv, grace, status_w, control_r)
        i = full.index(procutil._SUPERVISOR_SCRIPT)
        return [*full[:i], str(wrapper), *extra, procutil._SUPERVISOR_SCRIPT, *full[i + 1:]]

    monkeypatch.setattr(procutil, "_supervisor_argv", wrapped)


def test_a_server_that_misses_its_ready_timeout_leaves_nothing(tmp_path: Path, monkeypatch) -> None:
    """Review round 2 (A): a slow boot (artisan, ``go run``) whose ready line misses
    ``ready_timeout`` after the server has forked: the failed start stops the whole
    tree -- the in-session child and an escaped grandchild included -- sweeping the
    session before it reaps the supervisor."""
    shim, log = tmp_path / "slow_ready.py", tmp_path / "pids"
    shim.write_text(SLOW_READY)
    _wrap_supervisor(monkeypatch, shim, "2.0")
    with pytest.raises(procutil.ProcUtilError, match="no ready line"):
        procutil.start_server([sys.executable, "-c", RECORDING_SERVER, str(log)], ready_timeout=0.8)
    monkeypatch.undo()
    rows = [tuple(int(x) for x in line.split()) for line in log.read_text().splitlines()]
    try:
        assert len(rows) == 3, rows  # server, its in-session child, the escaped grandchild
        assert _wait_gone([(pid, start) for pid, start, _ in rows]) == []
        server_sid = rows[0][2]
        assert raw_members("sid", server_sid, 0) == []
    finally:
        for pid, start, _ in rows:
            procutil._signal_checked(pid, start, signal.SIGKILL)


DYING_BEFORE_READY = textwrap.dedent("""
    import importlib.util, os, signal, sys, time
    path = sys.argv[1]
    spec = importlib.util.spec_from_file_location("procutil_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    real_report = mod._Supervisor.report

    def die(self, line):
        if line.startswith("ready"):
            time.sleep(0.5)  # let the server fork
            os.kill(os.getpid(), signal.SIGKILL)  # killed from outside, no clean-up
        return real_report(self, line)

    mod._Supervisor.report = die
    sys.exit(mod._supervisor_main(sys.argv[2:]))
""")


def test_a_supervisor_killed_before_ready_is_swept_before_it_is_reaped(tmp_path: Path, monkeypatch) -> None:
    """Review round 2 (A): the failed-start path sweeps the supervisor's session
    *before* reaping it. Here the supervisor is SIGKILLed after the server forked but
    before its ready line: the server dies of its PDEATHSIG, its in-session child does
    not -- only the sweep (the supervisor still held, unreaped) stops it."""
    shim, log = tmp_path / "dying.py", tmp_path / "pids"
    shim.write_text(DYING_BEFORE_READY)
    _wrap_supervisor(monkeypatch, shim)
    server = RECORDING_SERVER.split("if os.fork() == 0:  # escapes")[0] + "time.sleep(300)\n"
    assert "setsid" not in server
    with pytest.raises(procutil.ProcUtilError, match="no ready line"):
        procutil.start_server([sys.executable, "-c", server, str(log)], ready_timeout=BOUND_S)
    monkeypatch.undo()
    rows = [tuple(int(x) for x in line.split()) for line in log.read_text().splitlines()]
    try:
        assert len(rows) == 2, rows  # the server and its in-session child
        assert _wait_gone([(pid, start) for pid, start, _ in rows]) == []
        assert raw_members("sid", rows[0][2], 0) == []
    finally:
        for pid, start, _ in rows:
            procutil._signal_checked(pid, start, signal.SIGKILL)


def test_an_async_wait_returns_when_the_supervisor_was_reaped_elsewhere() -> None:
    """Review round 2 (B): a supervisor reaped behind its Popen's back must not leave
    ``await handle.proc.wait()`` spinning forever."""
    import asyncio

    async def go():
        h = await procutil.astart_server(["sleep", "300"], allow_thread=True)
        child = (h.child_pid, h.child_start_time)
        os.kill(h.pid, signal.SIGKILL)
        os.waitpid(h.pid, 0)  # reaped out from under the handle
        code = await asyncio.wait_for(h.proc.wait(), BOUND_S)
        reason = await procutil.astop_server(h)
        return code, reason, child

    code, reason, child = asyncio.run(go())
    assert code == procutil.CODE_UNKNOWN
    assert reason == "killed"
    assert _wait_gone([child]) == []  # the server died of its PDEATHSIG(SIGKILL)


def test_arun_bounded_never_returns_code_unknown_as_a_status(monkeypatch) -> None:
    """Review round 3 (B): an unknown exit status reaches arun_bounded's caller as
    None, never as CODE_UNKNOWN (-256)."""
    import asyncio

    monkeypatch.setattr(procutil, "_peek_code", lambda h: procutil.CODE_UNKNOWN)
    code, out, err, timed_out = asyncio.run(procutil.arun_bounded(["true"], timeout=BOUND_S))
    assert (code, timed_out) == (None, False)


def test_reaping_a_stuck_supervisor_is_bounded_and_loud(monkeypatch, capsys) -> None:
    """Review round 3 (A nit): a supervisor that will not exit (D state, simulated by
    a process that ignores SIGTERM) cannot hang its owner: the reap gives up after
    KILL_BOUND_S with a loud line."""
    stuck = _bystander([sys.executable, "-c",
                        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        "time.sleep(30)"])  # self-ending even if a hung run is killed
    try:
        st = procutil.read_stat(stuck.pid)
        h = procutil.ServerHandle(argv=("stuck",), pid=stuck.pid, start_time=st.start,
                                  child_pid=0, child_start_time=0, proc=stuck)
        monkeypatch.setattr(procutil, "KILL_BOUND_S", 0.3)
        t0 = time.monotonic()
        assert procutil._reap_supervisor(h) is False
        assert time.monotonic() - t0 < BOUND_S
        assert "could not be reaped" in capsys.readouterr().err
    finally:
        stuck.kill()
        stuck.wait()


def test_a_failed_start_that_cannot_reap_leaves_the_handle_for_the_safety_net(monkeypatch) -> None:
    """Review round 3 (A nit): when the failed-start path cannot reap its supervisor,
    it does not hang; it leaves the handle registered, so the session-end safety net
    reports it."""
    stuck = _bystander(["sleep", "300"])
    st = procutil.read_stat(stuck.pid)
    h = procutil.ServerHandle(argv=("stuck",), pid=stuck.pid, start_time=st.start,
                              child_pid=0, child_start_time=0, proc=stuck)
    monkeypatch.setattr(procutil, "request_stop", lambda h: True)
    monkeypatch.setattr(procutil, "_wait_exited", lambda h, t: True)
    monkeypatch.setattr(procutil, "_sweep_session", lambda h: [])
    monkeypatch.setattr(procutil, "_reap_supervisor", lambda h: False)
    try:
        abandon, _ = procutil._start_failure_paths(h, stuck)
        abandon()
        assert h in procutil.registered()
    finally:
        procutil._unregister(h)
        stuck.kill()
        stuck.wait()


#: Binds HOST:0, prints the port, never accepts (nothing is served), and -- with
#: "fork" -- does it in a forked grandchild-level process instead of the server itself.
LISTENING_PROGRAM = textwrap.dedent("""
    import os, socket, sys, time
    host, where = sys.argv[1], sys.argv[2]
    if where == "fork" and os.fork() != 0:
        time.sleep(30)
        sys.exit(0)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    s.bind((host, 0))
    s.listen()
    print(s.getsockname()[1], flush=True)
    time.sleep(30)
""")


def _listening_server(host: str, where: str = "self") -> tuple[procutil.ServerHandle, int]:
    h = procutil.start_server([sys.executable, "-c", LISTENING_PROGRAM, host, where],
                              stdout=subprocess.PIPE, text=True)
    return h, int(h.proc.stdout.readline())


@pytest.mark.parametrize("where", ["self", "fork"])
def test_a_server_listening_beyond_loopback_is_caught(where: str) -> None:
    """BUG-0130 (PA-0035: probe the real sockets): a server tree that listens on all
    interfaces -- itself or a process it forked -- is caught by the listener check and
    by stop_server, which stops the tree first and then raises."""
    h, port = _listening_server("0.0.0.0", where)
    tree = _tree(h)
    found = procutil.listeners(h)
    assert [(lst.address, lst.port) for lst in found] == [("0.0.0.0", port)]
    assert found[0].pid != h.pid and not found[0].is_loopback()
    with pytest.raises(procutil.NonLoopbackListener, match=f"0.0.0.0:{port}"):
        procutil.assert_loopback_only(h)
    with pytest.raises(procutil.NonLoopbackListener, match="stopped now"):
        procutil.stop_server(h)
    assert [pid for pid, start in tree if _alive(pid, start)] == []
    assert h not in procutil.registered()


def test_a_loopback_only_server_passes() -> None:
    h, port = _listening_server("127.0.0.1")
    found = procutil.assert_loopback_only(h)
    assert [(lst.address, lst.port, lst.is_loopback()) for lst in found] == [("127.0.0.1", port, True)]
    assert procutil.stop_server(h) == "stop"


def test_the_safety_net_reports_an_exposed_server() -> None:
    h, port = _listening_server("0.0.0.0")
    leaks = procutil.reap_registered()
    assert [leak.pid for leak in leaks] == [h.pid]
    assert f"0.0.0.0:{port}" in leaks[0].note


def test_proc_net_tcp_decoding_covers_ipv4_and_ipv6() -> None:
    """``/proc/net/tcp{,6}`` addresses (host-order 32-bit words). IPv6 is decoded from
    synthetic rows: this sandbox has no ``/proc/net/tcp6``."""
    decode = procutil._decode_proc_net_address
    assert decode("0100007F:1F90") == ("127.0.0.1", 8080)
    assert decode("00000000:0050") == ("0.0.0.0", 80)
    assert decode("00000000000000000000000001000000:0050") == ("::1", 80)
    assert decode("00000000000000000000000000000000:0050") == ("::", 80)
    assert decode("0000000000000000FFFF00000100007F:0050") == ("::ffff:127.0.0.1", 80)
    # only LISTEN rows count: an established connection bound to a non-loopback
    # address (a server's outbound fetch) is not a listener
    table = procutil._parse_tcp_table(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1\n"
        "   1: 0201A8C0:C350 0101A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 222 1\n")
    assert table == {111: ("127.0.0.1", 8080)}
    loop = procutil.Listener(pid=1, address="::ffff:127.0.0.1", port=1)
    assert loop.is_loopback()
    assert not procutil.Listener(pid=1, address="::", port=1).is_loopback()
    assert procutil.Listener(pid=1, address="127.0.0.2", port=1).is_loopback()


def test_kill_process_group_kills_exactly_the_recorded_group() -> None:
    """The mechanism the corpus sandbox's timeout uses (BUG-0125 D14): every member of the
    recorded group, identity-checked, and nothing else."""
    h = procutil.start_server(["sh", "-c", "sleep 300 & sleep 300 & wait"])
    members = _wait_members(h, 4)
    group = [(p, st) for p, st in members if p != h.pid]
    assert procutil.kill_process_group(h.child_pid, h.child_start_time, signal.SIGKILL) == 3
    assert _wait_gone(group) == []
    assert h.proc.wait(timeout=BOUND_S) == 128 + signal.SIGKILL  # the server's own status
    assert procutil.finish(h) == "child"


# --- threads (BUG-0125 D12) and allow_thread (D17) -----------------------------------------------

def test_start_server_off_the_main_thread_raises_without_allow_thread() -> None:
    errors: list[BaseException] = []

    def body() -> None:
        try:
            procutil.start_server(["sleep", "300"])
        except BaseException as exc:  # noqa: BLE001 -- captured for the assertion
            errors.append(exc)

    t = threading.Thread(target=body)
    t.start()
    t.join()
    assert errors and isinstance(errors[0], procutil.ProcUtilError)
    assert "main thread" in str(errors[0])


def test_allow_thread_server_dies_with_its_thread_and_says_so() -> None:
    """With ``allow_thread=True`` PR_SET_PDEATHSIG fires when the forking thread
    exits: the server stops -- loudly (a stderr line and ``ServerLost``), never
    silently."""
    box: dict = {}

    def body() -> None:
        box["h"] = procutil.start_server(["sleep", "300"], stderr=subprocess.PIPE, text=True,
                                         allow_thread=True)

    t = threading.Thread(target=body)
    t.start()
    t.join()
    h = box["h"]
    assert h.proc.wait(timeout=BOUND_S) is not None
    assert not _alive(h.child_pid, h.child_start_time)
    assert "fuzzlab.procutil: supervisor" in h.proc.stderr.read()
    with pytest.raises(procutil.ServerLost):
        procutil.stop_server(h)
    assert h.exit_reason == "signal"


def test_supervisor_sigterm_handler_is_idempotent(tmp_path: Path) -> None:
    """Two SIGTERMs: one shutdown. The server sees exactly one SIGTERM (from the
    group kill) and exits by itself inside the grace period -- no second TERM, no
    SIGKILL."""
    log = tmp_path / "log"
    prog = textwrap.dedent(f"""
        import signal, sys, time
        log = open({str(log)!r}, "a", buffering=1)
        def on_term(s, f):
            log.write("TERM\\n")
        signal.signal(signal.SIGTERM, on_term)
        log.write("READY\\n")
        signal.pause()
        time.sleep(0.5)
        log.write("EXIT\\n")
        sys.exit(0)
    """)
    h = procutil.start_server([sys.executable, "-c", prog], grace=5.0)
    deadline = time.monotonic() + BOUND_S
    while "READY" not in (log.read_text() if log.exists() else ""):
        assert time.monotonic() < deadline
        time.sleep(0.02)
    signal.pidfd_send_signal(h.pidfd, signal.SIGTERM)
    time.sleep(0.05)
    signal.pidfd_send_signal(h.pidfd, signal.SIGTERM)
    assert h.proc.wait(timeout=BOUND_S) == 0  # the server's own clean exit code
    with pytest.raises(procutil.ServerLost):  # unrequested: reported, not silent
        procutil.finish(h)
    assert log.read_text().splitlines() == ["READY", "TERM", "EXIT"]
    assert h.exit_signals == 2


def test_a_stop_token_that_lands_before_its_signal_is_never_misread_as_unrequested() -> None:
    """The owner writes the stop token, then signals. If the signal's handler runs
    between the supervisor's control-pipe drain and its signal check, the stop must
    still read as requested (seen under load: a clean stop raised ServerLost)."""
    control_r, control_w = os.pipe()
    try:
        sup = procutil._Supervisor(["true"], owner=os.getppid(), grace=1.0,
                                   status_fd=-1, control_fd=control_r)
        os.set_blocking(control_r, False)
        real_drain = sup._drain_control
        calls = []

        def drain_then_race() -> None:
            real_drain()
            if not calls:  # after the first drain: token written, then the handler ran
                os.write(control_w, procutil._STOP_TOKEN)
                sup._on_signal(signal.SIGTERM, None)
            calls.append(1)

        sup._drain_control = drain_then_race
        assert sup._stop_reason() == "stop"
        unrequested = procutil._Supervisor(["true"], owner=os.getppid(), grace=1.0,
                                           status_fd=-1, control_fd=control_r)
        unrequested._on_signal(signal.SIGTERM, None)
        assert unrequested._stop_reason() == "signal"  # no token: really unrequested
    finally:
        os.close(control_r)
        os.close(control_w)


# --- BUG-0125 D15: a wedged supervisor ------------------------------------------------------

def test_wedged_supervisor_falls_back_to_a_direct_identity_checked_group_kill(tmp_path: Path) -> None:
    """The supervisor is stopped (SIGSTOP), so it cannot act on SIGTERM -- the same
    as one that ignores it. stop_server signals the server's own process group
    directly (the server sees that SIGTERM: a graceful stop, not only the final
    SIGKILL sweep), then kills the supervisor; nothing survives."""
    log = tmp_path / "log"
    prog = textwrap.dedent(f"""
        import os, signal, sys, time
        log = open({str(log)!r}, "a", buffering=1)
        def on_term(s, f):
            log.write("TERM\\n")
            sys.exit(0)
        signal.signal(signal.SIGTERM, on_term)
        if os.fork() == 0:
            time.sleep(300)
            os._exit(0)
        log.write("READY\\n")
        time.sleep(300)
    """)
    h = procutil.start_server([sys.executable, "-c", prog], grace=0.5)
    tree = _wait_members(h, 3)
    deadline = time.monotonic() + BOUND_S
    while "READY" not in (log.read_text() if log.exists() else ""):
        assert time.monotonic() < deadline
        time.sleep(0.02)
    os.kill(h.pid, signal.SIGSTOP)
    t0 = time.monotonic()
    assert procutil.stop_server(h, timeout=1.0) == "killed"
    assert time.monotonic() - t0 < BOUND_S
    assert _wait_gone(tree) == []
    assert h.proc.returncode == -signal.SIGKILL
    assert "TERM" in log.read_text().splitlines()  # reached through its own group


# --- BUG-0125 D16: oom_score_adj ------------------------------------------------------------

def test_the_server_is_a_likelier_oom_victim_than_its_supervisor() -> None:
    h = procutil.start_server(["sleep", "300"])
    try:
        if h.oom_supervisor is None or h.oom_supervisor >= 1000:
            pytest.skip(f"cannot raise above the supervisor's oom_score_adj ({h.oom_supervisor})")
        sup = int(Path(f"/proc/{h.pid}/oom_score_adj").read_text())
        child = int(Path(f"/proc/{h.child_pid}/oom_score_adj").read_text())
        assert child > sup
        assert (h.oom_supervisor, h.oom_child) == (sup, child)
    finally:
        procutil.stop_server(h)


# --- run_bounded -------------------------------------------------------------------

def test_run_bounded_returns_like_subprocess_run() -> None:
    r = procutil.run_bounded(["sh", "-c", "echo out; echo err >&2; exit 4"], timeout=BOUND_S)
    assert (r.returncode, r.stdout, r.stderr) == (4, "out\n", "err\n")
    r = procutil.run_bounded(["cat"], timeout=BOUND_S, input="piped")
    assert r.stdout == "piped"


def test_run_bounded_timeout_kills_the_whole_tree(tmp_path: Path) -> None:
    pidfile = tmp_path / "pid"
    with pytest.raises(subprocess.TimeoutExpired) as info:
        procutil.run_bounded(["sh", "-c", f"echo started; sleep 300 & echo $! > {pidfile}; wait"],
                             timeout=1.0)
    assert "started" in (info.value.stdout or "")
    grand = int(pidfile.read_text())
    st = procutil.read_stat(grand)  # killed and reaped by the supervisor before the raise
    assert st is None or st.state == "Z", st


def test_run_bounded_from_a_worker_thread() -> None:
    out: list = []
    t = threading.Thread(target=lambda: out.append(procutil.run_bounded(["true"], timeout=BOUND_S)))
    t.start()
    t.join()
    assert out[0].returncode == 0


# --- the session-end safety net -----------------------------------------------------

def test_reap_registered_stops_and_reports_a_leaked_server() -> None:
    h = procutil.start_server(["sh", "-c", "sleep 300 & wait"])
    tree = _wait_members(h, 3)
    leaks = procutil.reap_registered()
    assert [leak.pid for leak in leaks] == [h.pid]
    assert leaks[0].argv == ("sh", "-c", "sleep 300 & wait")
    assert _wait_gone(tree, bound=1.0) == []


def test_the_conftest_safety_net_fails_the_session_and_kills_the_leak(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        "from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401\n")
    pidfile = tmp_path / "leak.pid"
    (tmp_path / "test_leaky.py").write_text(textwrap.dedent(f"""
        from fuzzlab import procutil

        def test_leaks_a_server():
            h = procutil.start_server(["sleep", "300"])
            open({str(pidfile)!r}, "w").write(f"{{h.pid}} {{h.start_time}} {{h.child_pid}} {{h.child_start_time}}")
    """))
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    result = subprocess.run(  # a separate pytest process; bounded
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tmp_path),
         str(tmp_path / "test_leaky.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    sup, sup_start, child, child_start = (int(x) for x in pidfile.read_text().split())
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert "1 passed" in result.stdout
    assert f"LEAKED SERVER pid {sup}" in result.stdout and "'sleep', '300'" in result.stdout
    assert "age " in result.stdout
    assert _wait_gone([(sup, sup_start), (child, child_start)]) == []


def test_a_clean_session_passes_the_safety_net(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        "from tests._leak_guard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401\n")
    (tmp_path / "test_clean.py").write_text(textwrap.dedent("""
        from fuzzlab import procutil

        def test_stops_its_server():
            procutil.stop_server(procutil.start_server(["sleep", "300"]))
    """))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tmp_path),
         str(tmp_path / "test_clean.py")],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True,
        timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "LEAKED" not in result.stdout


# --- a real listener: the port refuses after stop -----------------------------------

def test_a_stopped_server_releases_its_port() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    h = procutil.start_server([sys.executable, "-m", "http.server", "--bind", "127.0.0.1", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + BOUND_S
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            assert time.monotonic() < deadline
            time.sleep(0.05)
    tree = _tree(h)
    procutil.stop_server(h)
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", port), timeout=1.0).close()
    assert _wait_gone(tree, bound=0.5) == []
