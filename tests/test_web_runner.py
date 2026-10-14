"""Tests for the launcher runner (`fuzzlab/web/runner.py`) and its routes."""

from __future__ import annotations

import asyncio
import sys

import pytest

from fuzzlab.web import commandspec
from fuzzlab.web.runner import Runner, build_argv, build_flags, display_command


# --- argv construction (pure) ----------------------------------------------

def test_build_flags_maps_types():
    spec = commandspec.spec("proxy")
    flags = build_flags(spec, {"port": 9999, "scope": ["a", "b"],
                               "authorized": True, "no_tls": False, "host": ""})
    assert "--port" in flags and flags[flags.index("--port") + 1] == "9999"
    # repeatable → one --scope per item
    assert flags.count("--scope") == 2
    # bool true present, bool false absent, empty string skipped (tool default applies)
    assert "--authorized" in flags
    assert "--no-tls" not in flags
    assert "--host" not in flags


def test_build_flags_ignores_unknown_keys():
    # Safety: only options the spec declares can reach argv.
    spec = commandspec.spec("report")
    flags = build_flags(spec, {"store": "x.db", "rm_rf": "/", "--evil": "1"})
    assert flags == ["--store", "x.db"]


def test_build_argv_targets_the_real_cli():
    spec = commandspec.spec("report")
    argv = build_argv(spec, {"store": "x.db"}, python="/usr/bin/python3")
    assert argv == ["/usr/bin/python3", "-m", "fuzzlab.cli", "report", "--store", "x.db"]


def test_display_command_is_readable():
    spec = commandspec.spec("crawl")
    assert display_command(spec, {"start": "http://localhost"}) == \
        "fuzzlab crawl --start http://localhost"


# --- live execution (real child process, no traffic) -----------------------

def test_runner_streams_output_and_exit_code():
    async def go():
        r = Runner()
        token = await r.launch(
            [sys.executable, "-c", "print('hello-world')\nimport sys; sys.exit(3)"])
        return [ev async for ev in r.stream(token)]

    events = asyncio.run(go())
    assert any("data: hello-world" in e for e in events)
    done = [e for e in events if "event: done" in e]
    assert done and '"returncode":3' in done[-1]


def _gone(pid: int, start: int, bound: float = 10.0) -> bool:
    import time

    from fuzzlab import procutil
    deadline = time.monotonic() + bound
    while time.monotonic() < deadline:
        st = procutil.read_stat(pid)
        if st is None or st.start != start or st.state == "Z":
            return True
        time.sleep(0.05)
    return False


def test_runner_stop_takes_the_jobs_whole_tree():
    """BUG-0125 / D17: Stop ends the job's grandchildren too (a crawl's browser, a
    compose call), not only the direct child."""
    from fuzzlab import procutil

    async def go():
        r = Runner()
        token = await r.launch(["sh", "-c", "sleep 300 & echo $!; wait"])
        run = r._runs[token]
        kind, line = await asyncio.wait_for(run.queue.get(), 10)
        assert kind == "output"
        grand = procutil.read_stat(int(line))
        assert r.stop(token) is True
        assert r.stop(token) is False  # one stop request per run
        events = [ev async for ev in r.stream(token)]
        return grand, events, run.handle

    grand, events, handle = asyncio.run(go())
    assert grand is not None and _gone(grand.pid, grand.start)
    assert any("event: done" in e for e in events)
    assert handle.exit_reason == "stop"
    assert handle not in procutil.registered()


def test_runner_shutdown_stops_every_live_job():
    from fuzzlab import procutil

    async def go():
        r = Runner()
        tokens = [await r.launch(["sleep", "300"]) for _ in range(2)]
        handles = [r._runs[t].handle for t in tokens]
        await r.shutdown()
        return handles

    handles = asyncio.run(go())
    for h in handles:
        assert _gone(h.child_pid, h.child_start_time)
        assert h not in procutil.registered()


def test_runner_stops_reading_output_a_survivor_holds_open(monkeypatch):
    """Review round 2 (B nit): the job's output pipe is inherited by its descendants;
    if one outlives the job (e.g. stuck in D state), the stream still ends -- after
    the supervisor's exit plus a bounded drain -- with a line saying so."""
    from fuzzlab import procutil

    class _Proc:
        def __init__(self):
            self.stdout = asyncio.StreamReader()  # never fed EOF: a survivor holds it
            self.stdout.feed_data(b"started\n")
            self.returncode = None

        async def wait(self):
            self.returncode = 0
            return 0

    class _Handle:
        def __init__(self):
            self.proc = _Proc()

    async def fake_start(argv, **kw):
        return _Handle()

    async def fake_stop(h, **kw):
        return "child"

    monkeypatch.setattr(procutil, "astart_server", fake_start)
    monkeypatch.setattr(procutil, "astop_server", fake_stop)
    monkeypatch.setattr(Runner, "DRAIN_S", 0.2)

    async def go():
        r = Runner()
        token = await r.launch(["anything"])
        return [ev async for ev in r.stream(token)]

    events = asyncio.run(asyncio.wait_for(go(), 10))
    assert any("data: started" in e for e in events)
    assert any("still held open" in e for e in events)
    assert "event: done" in events[-1]


def test_runner_done_event_carries_null_for_an_unknown_exit_status():
    """Review round 3 (B): a job whose supervisor was reaped outside fuzzlab ends with
    ``returncode: null`` and a line saying the status is unknown -- never -256."""
    import os
    import signal

    from fuzzlab import procutil

    async def go():
        r = Runner()
        token = await r.launch(["sleep", "300"])
        h = r._runs[token].handle
        os.kill(h.pid, signal.SIGKILL)
        os.waitpid(h.pid, 0)  # reaped behind the handle's back
        events = await asyncio.wait_for(_collect(r.stream(token)), 10)
        return events, h

    async def _collect(gen):
        return [ev async for ev in gen]

    events, h = asyncio.run(go())
    done = [e for e in events if "event: done" in e]
    assert done and '"returncode":null' in done[-1].replace(" ", ""), events
    assert not any("-256" in e for e in events)
    assert any("exit status unknown" in e for e in events)
    assert h not in procutil.registered()


def test_lab_states_report_an_unknown_exit_status_plainly(monkeypatch):
    """Review round 3 (B): ``labctl.sh ps`` with an unknown exit status says so."""
    from fuzzlab import procutil
    from fuzzlab.web import labcontrol

    async def unknown(argv, *, timeout, env=None):
        return None, b"", b"", False

    monkeypatch.setattr(labcontrol, "available", lambda: True)
    monkeypatch.setattr(procutil, "arun_bounded", unknown)
    states, error = asyncio.run(labcontrol.fetch_states())
    assert states == {} and "exit status unknown" in error and "-256" not in error


def test_runner_stop_reports_a_job_listening_beyond_loopback(monkeypatch):
    """BUG-0130: a job whose tree listens on all interfaces is reported on its stream
    when it is stopped (checked while it still runs). The job runs in a private network
    namespace, so the wildcard bind exposes nothing."""
    from tests._netns import private_netns
    prog = ("import socket, time; s = socket.socket(); s.bind(('0.0.0.0', 0)); s.listen(); "
            "print(s.getsockname()[1], flush=True); time.sleep(30)")

    async def go():
        r = Runner()
        token = await r.launch(private_netns([sys.executable, "-c", prog]))  # never the host's netns
        run = r._runs[token]
        kind, port = await asyncio.wait_for(run.queue.get(), 10)
        assert kind == "output"
        from fuzzlab import procutil
        ns = procutil.listeners(run.handle)[0].netns  # the job's private namespace,
        monkeypatch.setattr(procutil, "_host_netns", lambda: ns)  # treated as the host's
        assert r.stop(token) is True
        events = await asyncio.wait_for(_events(r.stream(token)), 10)
        return port, events

    async def _events(gen):
        return [ev async for ev in gen]

    port, events = asyncio.run(go())
    assert any("exposed beyond loopback" in e and f"0.0.0.0:{port}" in e for e in events), events


def test_runner_stream_unknown_token():
    async def go():
        r = Runner()
        return [ev async for ev in r.stream("nope")]
    events = asyncio.run(go())
    assert len(events) == 1 and "event: error" in events[0]


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def _client(authorized=False):
    cfg = load_config(overrides={"authorized": authorized,
                                 "target_base_url": "http://localhost"}, environ={})
    return web_client(create_app(cfg))


def test_dry_run_previews_argv_without_executing():
    r = _client().post("/api/launch/dry-run",
                       json={"command": "auto", "values": {"base_url": "http://localhost",
                                                           "store": "s.db"}})
    assert r.status_code == 200
    data = r.json()
    assert data["display"].startswith("fuzzlab auto ")
    assert "--base-url" in data["argv"] and "http://localhost" in data["argv"]
    assert data["sends_traffic"] is True
    # unauthorized client: a traffic tool would be blocked from executing
    assert data["would_execute"] is False


def test_dry_run_unknown_command_400():
    r = _client().post("/api/launch/dry-run", json={"command": "nope", "values": {}})
    assert r.status_code == 400


def test_launch_blocks_traffic_tool_without_authorization():
    r = _client(authorized=False).post(
        "/api/launch", json={"command": "auto", "values": {"base_url": "http://localhost"}})
    assert r.status_code == 403


def test_launch_unknown_command_400():
    r = _client(authorized=True).post("/api/launch", json={"command": "nope", "values": {}})
    assert r.status_code == 400


def test_launch_readonly_tool_returns_token():
    # `report` sends no traffic and needs no authorization, so it launches without the
    # gate; the endpoint spawns the child and returns its token + argv immediately.
    # (Streaming correctness is covered by test_runner_streams_output_and_exit_code;
    # reading an SSE body synchronously through TestClient is intentionally avoided.)
    with _client(authorized=False) as client:
        data = client.post("/api/launch", json={"command": "report", "values": {}}).json()
        assert "token" in data
        assert data["argv"][:4] == [sys.executable, "-m", "fuzzlab.cli", "report"]
        # tidy: ask the child to stop so teardown doesn't outlive it
        client.post(f"/api/launch/{data['token']}/stop")


def test_launch_stop_unknown_token_is_false():
    r = _client().post("/api/launch/deadbeef/stop")
    assert r.status_code == 200 and r.json()["stopped"] is False


def test_the_ui_event_loop_runs_on_the_main_thread(monkeypatch):
    """BUG-0125 review nit 4: the launcher spawns with ``allow_thread=True`` because the
    event-loop thread lives as long as the UI. ``serve`` hands the app to ``uvicorn.run``
    on the calling (main) thread, which runs the loop there."""
    import threading

    uvicorn = pytest.importorskip("uvicorn")
    from fuzzlab.web.app import serve
    seen = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.append(threading.current_thread()))
    serve(load_config(overrides={"web_host": "127.0.0.1"}, environ={}))
    assert seen == [threading.main_thread()]
