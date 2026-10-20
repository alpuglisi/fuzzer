"""The host-wide pytest lock (BUG-0532, PA-0532): one pytest session at a time.

Each test runs real pytest sessions on tiny trees under ``tmp_path``. They take a
private lock file (``FUZZLAB_PYTEST_LOCK_PATH``, honoured because the session running
these tests holds the host lock), so they never take, or wait for, the host lock
itself. Proven on synthetic offenders (PA-0034(2)):
* a second session (it waits, then runs);
* a session past its wait (it refuses and runs nothing);
* a sibling's, an ancestor's and its own pid as a forged token;
* a holder's descendant without the token;
* a private lock path outside a locked session;
* a conftest without the hook (``tests/test_pytest_lock_wiring.py``, the always-run guard).
xdist workers and nested sessions skip the lock; the trace file shows who took it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
import types
from pathlib import Path

import pytest

from fuzzlab import procutil
from tests import _pytest_lock as lock

REPO = Path(__file__).resolve().parent.parent
PY = sys.executable
#: A smoke alarm for one child session, never a timing claim.
BOUND_S = 120.0
CHILD_CONFTEST = "from tests._pytest_lock import pytest_configure, pytest_unconfigure  # noqa: F401\n"


class Lab:
    """Tiny pytest trees sharing one private lock and one trace file; every session it
    starts in the background is stopped at the end."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.lock = str(tmp / "private.lock")
        self.trace = tmp / "trace.jsonl"
        self.held = tmp / "held"
        self.release = tmp / "release"
        self.ran = tmp / "ran"
        self.handles: list[procutil.ServerHandle] = []
        self.logs: dict[int, Path] = {}

    def env(self, **kw: str | None) -> dict[str, str]:
        env = dict(os.environ, PYTHONPATH=str(REPO), FUZZLAB_PYTEST_LOCK_PATH=self.lock,
                   FUZZLAB_PYTEST_LOCK_TRACE=str(self.trace))
        env.pop(lock.ENV_TOKEN, None)  # each session here starts as a stranger to the lock
        for key, value in kw.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return env

    def tree(self, name: str, body: str) -> Path:
        d = self.tmp / name
        d.mkdir()
        (d / "conftest.py").write_text(CHILD_CONFTEST)
        (d / f"test_{name}.py").write_text(textwrap.dedent(body))
        return d

    def hold_tree(self) -> Path:
        """A session that holds the lock until ``release`` exists."""
        return self.tree("hold", f"""
            import time
            from pathlib import Path

            def test_hold():
                Path({str(self.held)!r}).write_text("held")
                end = time.monotonic() + {BOUND_S}
                while not Path({str(self.release)!r}).exists():
                    assert time.monotonic() < end, "never released"
                    time.sleep(0.05)
        """)

    def quick_tree(self) -> Path:
        """A session whose one test records that it ran."""
        return self.tree("quick", f"""
            import os
            from pathlib import Path

            def test_quick():
                with open({str(self.ran)!r}, "a") as fh:
                    fh.write(f"{{os.getpid()}}\\n")
        """)

    @staticmethod
    def argv(tree: Path, *args: str) -> list[str]:
        return [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tree),
                *args, str(tree)]

    def start(self, tree: Path, *args: str, **env: str | None) -> procutil.ServerHandle:
        log = self.tmp / f"{tree.name}-{len(self.handles)}.log"
        with open(log, "wb") as out:
            h = procutil.start_server(self.argv(tree, *args), cwd=tree, env=self.env(**env),
                                      stdout=out, stderr=subprocess.STDOUT)
        self.handles.append(h)
        self.logs[h.child_pid] = log
        return h

    def run(self, tree: Path, *args: str, **env: str | None) -> subprocess.CompletedProcess:
        return procutil.run_bounded(self.argv(tree, *args), timeout=BOUND_S, cwd=tree,
                                    env=self.env(**env))

    def finish(self, h: procutil.ServerHandle) -> int:
        h.proc.wait(timeout=BOUND_S)
        procutil.finish(h)
        return h.proc.returncode

    def output(self, h: procutil.ServerHandle) -> str:
        return self.logs[h.child_pid].read_text(errors="replace")

    def events(self) -> list[dict]:
        if not self.trace.exists():
            return []
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def wait_for(self, check, what: str) -> None:
        end = time.monotonic() + BOUND_S
        while not check():
            assert time.monotonic() < end, f"never saw {what}; trace: {self.events()}"
            time.sleep(0.05)

    def holding(self) -> procutil.ServerHandle:
        """Start the holder and return once its test runs (so it holds the lock)."""
        a = self.start(self.hold_tree())
        self.wait_for(self.held.exists, "the holder's test start")
        return a

    def close(self) -> None:
        self.release.write_text("go")
        for h in self.handles:
            try:
                procutil.stop_server(h)
            except procutil.ProcUtilError:
                pass


@pytest.fixture
def lab(tmp_path):
    if lock.fcntl is None:
        pytest.skip("no fcntl: the lock degrades to a warning (tested on its own)")
    assert lock.host_lock_held_by_ancestor(), (
        "this session holds no host pytest lock: tests/conftest.py did not take it "
        "(BUG-0532), so the private lock paths these tests use would be refused")
    lab = Lab(tmp_path)
    yield lab
    lab.close()


def _events(lab: Lab, pid: int) -> list[str]:
    return [e["event"] for e in lab.events() if e["pid"] == pid]


# ------------------------------------------------------------- two sessions


def test_a_second_session_waits_for_the_first_and_then_runs(lab):
    a = lab.holding()
    b = lab.start(lab.quick_tree(), FUZZLAB_PYTEST_LOCK_WAIT="600")
    lab.wait_for(lambda: "waiting" in _events(lab, b.child_pid), "the second session waiting")
    assert not lab.ran.exists()  # it runs nothing while the first holds the lock
    lab.release.write_text("go")
    assert lab.finish(a) == 0, lab.output(a)
    assert lab.finish(b) == 0, lab.output(b)
    assert lab.ran.read_text().split() == [str(b.child_pid)]
    order = [(e["event"], e["pid"]) for e in lab.events() if e["event"] in ("acquired", "released")]
    assert order == [("acquired", a.child_pid), ("released", a.child_pid),
                     ("acquired", b.child_pid), ("released", b.child_pid)]
    out = lab.output(b)
    assert f"held by pid {a.child_pid}: " in out and "-m pytest" in out, out
    assert "FUZZLAB_PYTEST_LOCK_WAIT" in out


@pytest.mark.parametrize("wait", ["0", "1"])
def test_a_session_refuses_after_its_wait_and_runs_nothing(lab, wait):
    a = lab.holding()
    r = lab.run(lab.quick_tree(), FUZZLAB_PYTEST_LOCK_WAIT=wait)
    out = r.stdout + r.stderr
    assert r.returncode == pytest.ExitCode.USAGE_ERROR, out
    assert not lab.ran.exists()
    assert f"still held by pid {a.child_pid}: " in out and "nothing was run" in out, out
    assert [e["event"] for e in lab.events() if e["pid"] != a.child_pid][-1] == "refused-timeout"
    lab.release.write_text("go")
    assert lab.finish(a) == 0


# ------------------------------------------------------------------- xdist


def test_xdist_takes_the_lock_once_and_its_workers_skip_it(lab):
    pytest.importorskip("xdist")
    out = lab.tmp / "records"
    out.mkdir()
    tree = lab.tree("xd", f"""
        import json, os
        from pathlib import Path
        import pytest
        from tests import _pytest_lock

        @pytest.mark.parametrize("i", range(9))
        def test_record(request, i):
            Path({str(out)!r}, f"{{i}}.json").write_text(json.dumps(
                {{"pid": os.getpid(), "decision": _pytest_lock.decision(request.config)}}))
    """)
    r = lab.run(tree, "-n", "3")
    assert r.returncode == 0, r.stdout + r.stderr
    events = lab.events()
    assert [e["event"] for e in events] == ["acquired", "worker", "worker", "worker", "released"]
    controller = events[0]["pid"]
    workers = {e["pid"] for e in events if e["event"] == "worker"}
    assert len(workers) == 3
    assert {e["ppid"] for e in events if e["event"] == "worker"} == {controller}
    records = [json.loads(p.read_text()) for p in out.glob("*.json")]
    assert len(records) == 9
    assert {rec["decision"] for rec in records} == {"worker"}
    assert {rec["pid"] for rec in records} <= workers


# -------------------------------------------------------- nested sessions


@pytest.mark.parametrize("workers", [[], ["-n", "2"]], ids=["plain", "xdist"])
def test_a_nested_session_with_the_holders_token_runs(lab, workers):
    if workers:
        pytest.importorskip("xdist")
    quick = lab.quick_tree()
    tree = lab.tree("parent", f"""
        import os, subprocess, sys

        def test_spawns_a_nested_pytest():
            env = dict(os.environ, FUZZLAB_PYTEST_LOCK_WAIT="600")  # waiting would hang
            r = subprocess.run({Lab.argv(quick)!r}, cwd={str(quick)!r}, env=env,
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stdout + r.stderr
    """)
    r = lab.run(tree, *workers)
    assert r.returncode == 0, r.stdout + r.stderr
    events = lab.events()
    holder = next(e["pid"] for e in events if e["event"] == "acquired")
    nested = [e for e in events if e["event"] == "nested"]
    assert len(nested) == 1 and [e["event"] for e in events].count("acquired") == 1
    parents = {e["pid"]: e["ppid"] for e in events}  # recorded while each process lived
    chain = [nested[0]["ppid"]]
    while chain[-1] in parents and parents[chain[-1]] not in chain:
        chain.append(parents[chain[-1]])
    assert holder in chain  # the nested session descends from the holder (via its worker)
    assert lab.ran.read_text().split() == [str(nested[0]["pid"])]


@pytest.mark.parametrize("token", ["stripped", "wrong"])
def test_a_holders_descendant_without_its_token_fails_at_once(lab, token):
    quick = lab.quick_tree()
    report = lab.tmp / "child.txt"
    # "wrong": the holder's own parent (an ancestor of the child, but not the holder)
    change = ('env.pop("FUZZLAB_PYTEST_LOCK_HELD")' if token == "stripped"
              else 'env["FUZZLAB_PYTEST_LOCK_HELD"] = str(os.getppid())')
    tree = lab.tree("parent", f"""
        import os, subprocess, sys
        from pathlib import Path

        def test_spawns_a_pytest_with_a_changed_environment():
            env = dict(os.environ, FUZZLAB_PYTEST_LOCK_WAIT="600")
            {change}
            r = subprocess.run({Lab.argv(quick)!r}, cwd={str(quick)!r}, env=env,
                               capture_output=True, text=True, timeout=60)
            Path({str(report)!r}).write_text(r.stdout + r.stderr)
            assert r.returncode == 4
    """)
    r = lab.run(tree)
    assert r.returncode == 0, r.stdout + r.stderr + report.read_text()
    assert "would deadlock" in report.read_text() and "pass os.environ on" in report.read_text()
    assert not lab.ran.exists()
    child = [e for e in lab.events() if e["event"] not in ("acquired", "released")]
    assert [e["event"] for e in child] == ["refused-tokenless"]  # it never waited


def test_a_token_without_ancestry_does_not_bypass_the_lock(lab):
    a = lab.holding()
    quick = lab.quick_tree()
    # a sibling with the holder's own pid, as a token copied into another shell
    sibling = lab.run(quick, FUZZLAB_PYTEST_LOCK_WAIT="1", FUZZLAB_PYTEST_LOCK_HELD=str(a.child_pid))
    # a true ancestor's pid (this test's process) that does not hold the lock
    ancestor = lab.run(quick, FUZZLAB_PYTEST_LOCK_WAIT="1", FUZZLAB_PYTEST_LOCK_HELD=str(os.getpid()))
    # the shell's own pid, `FUZZLAB_PYTEST_LOCK_HELD=$$ pytest`
    own = procutil.run_bounded(
        ["sh", "-c", 'FUZZLAB_PYTEST_LOCK_HELD=$$ exec "$@"', "sh", *Lab.argv(quick)],
        timeout=BOUND_S, cwd=quick, env=lab.env(FUZZLAB_PYTEST_LOCK_WAIT="1"))
    for name, r in (("sibling", sibling), ("ancestor", ancestor), ("own pid", own)):
        assert r.returncode == pytest.ExitCode.USAGE_ERROR, (name, r.stdout + r.stderr)
        assert f"still held by pid {a.child_pid}" in r.stdout + r.stderr, name
    assert not lab.ran.exists()
    others = [e["event"] for e in lab.events() if e["pid"] != a.child_pid]
    assert others.count("refused-timeout") == 3 and "nested" not in others
    lab.release.write_text("go")
    assert lab.finish(a) == 0


# ------------------------------------------------------------- private path


@pytest.fixture
def quiet(monkeypatch):
    """In-process tests leave any outer measurement trace alone."""
    monkeypatch.delenv(lock.ENV_TRACE, raising=False)


def _config():
    return types.SimpleNamespace(stash=pytest.Stash(),
                                 option=types.SimpleNamespace(help=False, markers=False),
                                 pluginmanager=types.SimpleNamespace(getplugin=lambda name: None))


def _needs_fcntl():
    if lock.fcntl is None:
        pytest.skip("no fcntl: nothing can hold a lock here (the warning is tested below)")


def test_a_private_lock_path_is_refused_outside_a_locked_session(tmp_path, monkeypatch, quiet):
    _needs_fcntl()
    host = tmp_path / "host.lock"
    monkeypatch.setattr(lock, "default_lock_path", lambda: str(host))
    monkeypatch.setenv(lock.ENV_PATH, str(tmp_path / "mine.lock"))
    host.touch()
    with pytest.raises(pytest.UsageError, match="honoured only inside a pytest session"):
        lock.lock_path()  # nobody holds the (stand-in) host lock
    with pytest.raises(pytest.UsageError, match="honoured only inside a pytest session"):
        lock.pytest_configure(_config())  # and the session refuses before running anything
    fd = os.open(host, os.O_RDWR)
    try:
        lock.fcntl.flock(fd, lock.fcntl.LOCK_EX)  # now this process (in its own ancestry) holds it
        assert lock.lock_path() == str(tmp_path / "mine.lock")
    finally:
        os.close(fd)


def test_an_in_process_nested_session_reuses_the_hold(tmp_path, monkeypatch, quiet):
    _needs_fcntl()
    host = tmp_path / "host.lock"
    monkeypatch.setattr(lock, "default_lock_path", lambda: str(host))
    monkeypatch.delenv(lock.ENV_PATH, raising=False)
    monkeypatch.delenv(lock.ENV_TOKEN, raising=False)
    monkeypatch.setenv(lock.ENV_WAIT, "0")  # a re-lock would refuse, never hang
    outer, inner = _config(), _config()
    lock.pytest_configure(outer)
    try:
        assert lock.decision(outer) == "acquired"
        assert os.environ[lock.ENV_TOKEN] == str(os.getpid())
        assert lock.read_holder(str(host))["pid"] == os.getpid()
        lock.pytest_configure(inner)  # pytest.main() from a test: same process
        assert lock.decision(inner) == "nested-in-process"
        lock.pytest_unconfigure(inner)
        assert lock.kernel_holder(str(host)) == os.getpid()
        assert str(host) in lock._HELD  # the inner session did not release the outer hold
    finally:
        lock.pytest_unconfigure(outer)
    assert str(host) not in lock._HELD
    assert lock.ENV_TOKEN not in os.environ
    assert not os.path.exists(lock.holder_file(str(host)))


# ----------------------------------------------------------------- settings


def test_the_host_lock_lives_in_tmp_whatever_tmpdir_says(monkeypatch, tmp_path):
    if not os.path.isdir("/tmp"):
        pytest.skip("no /tmp on this host: the lock falls back to tempfile.gettempdir()")
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert lock.default_lock_path() == "/tmp/fuzzlab-pytest.lock"


def test_the_wait_defaults_to_1800_s_and_rejects_nonsense(monkeypatch):
    monkeypatch.delenv(lock.ENV_WAIT, raising=False)
    assert lock._wait_seconds() == 1800.0
    monkeypatch.setenv(lock.ENV_WAIT, "0")
    assert lock._wait_seconds() == 0.0
    for bad in ("soon", "-1", "nan", "inf"):
        monkeypatch.setenv(lock.ENV_WAIT, bad)
        with pytest.raises(pytest.UsageError):
            lock._wait_seconds()


def test_without_fcntl_the_session_warns_and_runs_unlocked(monkeypatch, quiet):
    monkeypatch.setattr(lock, "fcntl", None)
    config = _config()
    with pytest.warns(UserWarning, match="WITHOUT the host pytest lock"):
        lock.pytest_configure(config)
    assert lock.decision(config) == "unlocked-no-fcntl"
    lock.pytest_unconfigure(config)


# ---------------------------------------------------------------- real tree


def test_a_session_of_the_real_test_tree_takes_the_lock(lab):
    """The real ``tests/conftest.py`` takes the (private) lock in a child session."""
    r = procutil.run_bounded(
        [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--co", "tests/test_pytest_lock.py"],
        timeout=BOUND_S, cwd=REPO, env=lab.env())
    assert r.returncode == 0, r.stdout + r.stderr
    assert [(e["event"], e["path"]) for e in lab.events()] == [
        ("acquired", lab.lock), ("released", lab.lock)]
    assert lab.events()[0]["pid"] != os.getpid()
