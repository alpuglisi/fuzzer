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


def test_runner_stream_unknown_token():
    async def go():
        r = Runner()
        return [ev async for ev in r.stream("nope")]
    events = asyncio.run(go())
    assert len(events) == 1 and "event: error" in events[0]


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _client(authorized=False):
    cfg = load_config(overrides={"authorized": authorized,
                                 "target_base_url": "http://localhost"}, environ={})
    return TestClient(create_app(cfg))


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
