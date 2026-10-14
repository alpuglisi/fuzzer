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
                              stdout=subprocess.PIPE, text=True)
    lines = [h.proc.stdout.readline().split() for _ in range(2)]
    pids = {kind: int(pid) for kind, pid in lines}
    grand = procutil.read_stat(pids["GRAND"])
    assert grand is not None and grand.sid != h.pid  # it really left the session
    targets = [(pids["CHILD"], procutil.read_stat(pids["CHILD"]).start), (grand.pid, grand.start)]
    procutil.stop_server(h)
    assert _wait_gone(targets, bound=0.5) == []


def test_a_server_that_exits_on_its_own_is_collected_with_its_code() -> None:
    h = procutil.start_server(["sh", "-c", "sleep 300 & exit 7"])
    assert h.proc.wait(timeout=BOUND_S) == 7
    assert procutil.finish(h) == "child"
    assert procutil.session_members(h.pid, h.start_time) == []  # the orphaned sleep too


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
        assert procutil.session_members(sup.pid, 0) == []  # no server was started
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
    victim = subprocess.Popen(["sleep", "300"], start_new_session=True)  # noqa: S603 -- the bystander
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
