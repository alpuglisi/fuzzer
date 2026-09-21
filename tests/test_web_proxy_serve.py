"""Tests for the unified serve mode / in-process proxy controller (Phase 0.4)."""

from __future__ import annotations

import asyncio

import pytest

from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController


# --- controller lifecycle (real loopback listener, ephemeral port) ---------

def test_controller_start_status_stop():
    async def go():
        ctrl = ProxyController(ProxyConfig(port=0, scope_hosts=("127.0.0.1",)))
        assert ctrl.running is False
        await ctrl.start()
        st = ctrl.status()
        assert st["configured"] is True and st["running"] is True
        assert st["port"] > 0                       # OS-assigned ephemeral port
        assert st["scope_hosts"] == ["127.0.0.1"]
        await ctrl.stop()
        assert ctrl.running is False
    asyncio.run(go())


def test_controller_intercept_toggle():
    ctrl = ProxyController(ProxyConfig(port=0, intercept=False))
    ctrl.build()                                    # no bind needed to toggle
    assert ctrl.status()["intercept"] is False
    assert ctrl.set_intercept(True) is True
    assert ctrl.status()["intercept"] is True
    assert ctrl.interceptor.enabled is True         # the live engine's interceptor


# --- app wiring ------------------------------------------------------------

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app, serve, web_main  # noqa: E402


def _cfg(**over):
    return load_config(overrides={"target_base_url": "http://localhost", **over}, environ={})


def test_proxy_status_dormant_without_proxy():
    r = TestClient(create_app(_cfg())).get("/api/proxy/status").json()
    assert r == {"configured": False, "running": False}


def test_proxy_intercept_409_without_proxy():
    r = TestClient(create_app(_cfg())).post("/api/proxy/intercept", json={"on": True})
    assert r.status_code == 409


def test_lifespan_starts_and_stops_the_proxy():
    ctrl = ProxyController(ProxyConfig(port=0))
    app = create_app(_cfg(), proxy=ctrl)
    # lifespan runs only under the context manager: startup binds, shutdown stops.
    with TestClient(app) as client:
        st = client.get("/api/proxy/status").json()
        assert st["running"] is True and st["port"] > 0
        assert client.post("/api/proxy/intercept", json={"on": True}).json()["intercept"] is True
    assert ctrl.running is False                     # stopped on shutdown


# --- serve() / CLI gating --------------------------------------------------

def test_serve_refuses_non_loopback_proxy_host():
    ctrl = ProxyController(ProxyConfig(host="0.0.0.0", port=0))
    with pytest.raises(ValueError):
        serve(_cfg(), proxy=ctrl)


def test_web_main_requires_authorized_for_proxy():
    # --with-proxy without --authorized must exit non-zero and never serve.
    with pytest.raises(SystemExit) as exc:
        web_main(["--with-proxy"])
    assert exc.value.code != 0
