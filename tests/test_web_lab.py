"""Tests for the control panel's Lab page (CC-UI-0033) and the per-service
``labctl.sh`` subcommands behind it (CC-LAB-0250).

Offline: no compose provider or container engine is needed. The one function that
runs a process (``labcontrol.fetch_states``) and the launcher's ``Runner.launch`` are
replaced with fakes in the route tests; the compose parsing and ``ps`` parsing are
exercised directly; ``labctl.sh``'s own service-name check is executed in a real bash
subshell via its sentinel block (the same pattern as
``tests/test_lab_labctl_profile_parsing.py``, PA-0027).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web import labcontrol  # noqa: E402
from fuzzlab.web.app import NAV, create_app  # noqa: E402
from tests._webclient import WEB_BASE_URL, web_client  # noqa: E402

COMPOSE = Path("lab/compose.yaml")
LABCTL = Path("lab/labctl.sh")


def _cfg():
    return load_config(overrides={"target_base_url": "http://localhost"}, environ={})


def _client():
    return web_client(create_app(_cfg()))


# --- compose-derived service list (PA-0059(2): no hand-kept duplicate) -----------

def test_services_are_exactly_the_compose_services():
    expected = list((yaml.safe_load(COMPOSE.read_text()) or {})["services"].keys())
    assert [s.name for s in labcontrol.load_services(COMPOSE, environ={})] == expected


def test_every_published_port_binds_loopback_only():
    # The lab's standing safety invariant (compose.yaml header): the deliberately
    # vulnerable apps are never published off loopback.
    published = [s for s in labcontrol.load_services(COMPOSE, environ={}) if s.host_port]
    assert published, "expected at least the web service to publish a port"
    assert {s.bind_host for s in published} == {"127.0.0.1"}
    for s in published:
        assert s.url == f"http://127.0.0.1:{s.host_port}/"


def test_profiled_services_carry_their_compose_profile():
    raw = (yaml.safe_load(COMPOSE.read_text()) or {})["services"]
    for s in labcontrol.load_services(COMPOSE, environ={}):
        profiles = raw[s.name].get("profiles") or []
        assert s.profile == (profiles[0] if profiles else None)


@pytest.mark.parametrize("spec, environ, expected", [
    ("127.0.0.1:${PFF_WEB_PORT:-8080}:80", {}, ("127.0.0.1", 8080)),
    ("127.0.0.1:${PFF_WEB_PORT:-8080}:80", {"PFF_WEB_PORT": "9000"}, ("127.0.0.1", 9000)),
    ("127.0.0.1:8085:8000", {}, ("127.0.0.1", 8085)),
    ("8085:8000", {}, (None, 8085)),
    ("8085:8000/tcp", {}, (None, 8085)),
    ("not a port", {}, (None, None)),
])
def test_parse_port(spec, environ, expected):
    assert labcontrol.parse_port(spec, environ) == expected


def test_project_name_comes_from_the_compose_file():
    assert labcontrol.project_name(COMPOSE) == (yaml.safe_load(COMPOSE.read_text()))["name"]


# --- engine state parsing, both providers' naming schemes ------------------------

_KNOWN = {"db", "web", "frontend", "pictrail", "huddlehub"}


@pytest.mark.parametrize("name, expected", [
    ("pff-lab_web_1", "web"),            # podman-compose
    ("pff-lab-web-1", "web"),            # docker compose
    ("pff-lab_pictrail_2", "pictrail"),
    ("pff-lab-huddlehub-1", "huddlehub"),
    ("other-project_web_1", None),
    ("pff-lab_unknownsvc_1", None),
])
def test_service_of(name, expected):
    assert labcontrol.service_of(name, "pff-lab", _KNOWN) == expected


def test_parse_ps_prefers_a_running_container_and_ignores_strangers():
    text = (
        "pff-lab_web_1\trunning\tUp 3 minutes\n"
        "pff-lab_web_2\texited\tExited (0) 2 days ago\n"
        "pff-lab-db-1\texited\tExited (137) 1 hour ago\n"
        "somebody_else_1\trunning\tUp 1 minute\n"
        "\n"
    )
    states = labcontrol.parse_ps(text, "pff-lab", _KNOWN)
    assert states["web"] == {"state": "running", "status": "Up 3 minutes",
                             "container": "pff-lab_web_1"}
    assert states["db"]["state"] == "exited"
    assert set(states) == {"web", "db"}


def test_state_for_marks_missing_containers_absent():
    svc = labcontrol.LabService("web", "PFF", None, "127.0.0.1", 8080, "http://127.0.0.1:8080/")
    assert labcontrol.state_for(svc, {}) == {"state": "absent", "status": "",
                                             "container": None, "running": False}
    assert labcontrol.state_for(svc, {"web": {"state": "running", "status": "Up"}})["running"]


# --- action argv/env (D18: argv list, declared values only, no shell) -------------

def test_control_argv_and_env():
    apps = labcontrol.LabService("pictrail", "PicTrail", "apps", "127.0.0.1", 8085, None)
    plain = labcontrol.LabService("web", "PFF", None, "127.0.0.1", 8080, None)
    assert labcontrol.control_argv("start", apps) == \
        ["bash", str(labcontrol.LABCTL_PATH), "start", "pictrail"]
    assert labcontrol.control_env(apps, base={"PATH": "/bin"}) == \
        {"PATH": "/bin", "PFF_PROFILE": "apps"}
    # A default-profile service must not inherit a stray PFF_PROFILE from the panel's
    # own environment (it would enable profiles the user did not switch on).
    assert labcontrol.control_env(plain, base={"PATH": "/bin", "PFF_PROFILE": "apps"}) == \
        {"PATH": "/bin"}
    with pytest.raises(ValueError):
        labcontrol.control_argv("down", plain)


# --- routes ----------------------------------------------------------------------

def test_lab_is_in_the_sidebar_nav():
    ids = [link["id"] for grp in NAV for link in grp["links"]]
    assert "lab" in ids


def test_lab_page_renders_one_row_per_service():
    r = _client().get("/lab")
    assert r.status_code == 200
    for s in labcontrol.services():
        assert f'data-service="{s.name}"' in r.text
    assert 'aria-current="page"' in r.text   # the Lab link is marked active


def test_api_services_merges_engine_state(monkeypatch):
    async def fake_states(timeout=20.0):
        return {"web": {"state": "running", "status": "Up 9 minutes",
                        "container": "pff-lab_web_1"}}, None
    monkeypatch.setattr(labcontrol, "fetch_states", fake_states)
    data = _client().get("/api/lab/services").json()
    assert data["error"] is None
    rows = {s["name"]: s for s in data["services"]}
    assert rows["web"]["running"] is True and rows["web"]["status"] == "Up 9 minutes"
    assert rows["db"]["state"] == "absent" and rows["db"]["running"] is False


def test_api_services_reports_engine_errors_instead_of_guessing(monkeypatch):
    async def fake_states(timeout=20.0):
        return {}, "no container engine (podman/docker) on PATH"
    monkeypatch.setattr(labcontrol, "fetch_states", fake_states)
    data = _client().get("/api/lab/services").json()
    assert "no container engine" in data["error"]
    assert all(s["state"] == "absent" for s in data["services"])


def test_start_runs_labctl_for_the_service_with_its_profile(monkeypatch):
    calls = []

    async def fake_launch(self, argv, *, env=None):
        calls.append((argv, env))
        return "tok123"
    from fuzzlab.web.runner import Runner
    monkeypatch.setattr(Runner, "launch", fake_launch)
    r = _client().post("/api/lab/pictrail/start")
    assert r.status_code == 200
    assert r.json() == {"token": "tok123", "service": "pictrail", "action": "start",
                        "argv": ["bash", str(labcontrol.LABCTL_PATH), "start", "pictrail"]}
    (argv, env), = calls
    assert argv[-2:] == ["start", "pictrail"] and env["PFF_PROFILE"] == "apps"


def test_stop_runs_labctl_stop(monkeypatch):
    calls = []

    async def fake_launch(self, argv, *, env=None):
        calls.append((argv, env))
        return "tok456"
    from fuzzlab.web.runner import Runner
    monkeypatch.setattr(Runner, "launch", fake_launch)
    r = _client().post("/api/lab/web/stop")
    assert r.status_code == 200
    (argv, env), = calls
    assert argv[-2:] == ["stop", "web"] and "PFF_PROFILE" not in env


@pytest.mark.parametrize("path", [
    "/api/lab/nosuchservice/start",
    "/api/lab/web/restart",            # only start/stop exist
    "/api/lab/..%2Fweb/start",         # a path-shaped name never reaches argv
])
def test_unknown_service_or_action_is_refused(monkeypatch, path):
    async def fake_launch(self, argv, *, env=None):  # pragma: no cover - must not run
        raise AssertionError("launch must not be called")
    from fuzzlab.web.runner import Runner
    monkeypatch.setattr(Runner, "launch", fake_launch)
    assert _client().post(path).status_code == 404


def test_cross_origin_start_is_rejected_by_the_control_plane_gate():
    # Same gate as every other state-changing /api/* route (CC-UI-0026): a hostile page
    # cannot flip lab containers from another origin.
    bare = TestClient(create_app(_cfg()), base_url=WEB_BASE_URL)
    r = bare.post("/api/lab/web/start", headers={"Origin": "http://evil.example",
                                                 "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_page_loading_does_not_touch_containers(monkeypatch):
    # No-auto-run (D11) for the lab too: rendering /lab runs nothing.
    async def fake_launch(self, argv, *, env=None):  # pragma: no cover
        raise AssertionError("launch must not be called")
    from fuzzlab.web.runner import Runner
    monkeypatch.setattr(Runner, "launch", fake_launch)
    assert _client().get("/lab").status_code == 200


# --- labctl.sh's own side --------------------------------------------------------

def test_labctl_parses_and_documents_the_new_subcommands():
    subprocess.run(["bash", "-n", str(LABCTL)], check=True)
    text = LABCTL.read_text(encoding="utf-8")
    for sub in ("start)", "stop)", "ps)"):
        assert sub in text
    usage = [ln for ln in text.splitlines() if ln.startswith("#   ./labctl.sh")]
    assert any("start <service>" in ln for ln in usage)
    assert any("stop <service>" in ln for ln in usage)
    assert any("ps " in ln for ln in usage)


def _run_name_check(name: str) -> int:
    text = LABCTL.read_text(encoding="utf-8")
    begin = text.index("# SERVICE_NAME_CHECK_BLOCK_BEGIN")
    end = text.index("# SERVICE_NAME_CHECK_BLOCK_END") + len("# SERVICE_NAME_CHECK_BLOCK_END")
    script = text[begin:end] + '\n_check_service_name "$1"\n'
    return subprocess.run(["bash", "-c", script, "bash", name],
                          capture_output=True, text=True).returncode


@pytest.mark.parametrize("name", ["web", "pictrail", "huddle_hub", "web-2"])
def test_labctl_accepts_plain_service_names(name):
    assert _run_name_check(name) == 0


@pytest.mark.parametrize("name", ["web; rm -rf /", "../web", "$(id)", "Web", "", "-f"])
def test_labctl_rejects_anything_but_a_plain_service_name(name):
    assert _run_name_check(name) != 0


def test_fetch_states_timeout_stops_labctls_whole_tree(monkeypatch, tmp_path):
    """BUG-0125 sweep: a `labctl.sh ps` that hangs is stopped with its children (the
    container engine it forks), not only `bash`. A stand-in script; no engine, no
    traffic."""
    import asyncio
    import time

    from fuzzlab import procutil

    pidfile = tmp_path / "engine.pid"
    script = tmp_path / "labctl.sh"
    script.write_text(f"sleep 300 &\necho $! > {pidfile}\nwait\n")
    monkeypatch.setattr(labcontrol, "LABCTL_PATH", script)
    monkeypatch.setattr(labcontrol, "available", lambda: True)
    states, error = asyncio.run(labcontrol.fetch_states(timeout=1.0))
    assert states == {} and "did not answer within 1s" in error
    st = procutil.read_stat(int(pidfile.read_text()))
    deadline = time.monotonic() + 10
    while st is not None and st.state != "Z" and time.monotonic() < deadline:
        time.sleep(0.05)
        st = procutil.read_stat(st.pid)
    assert st is None or st.state == "Z", "labctl.sh's child outlived the timeout"
