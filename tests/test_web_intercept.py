"""Tests for the intercept control surface (Phase 2.2): controller + routes."""

from __future__ import annotations

import asyncio

import pytest

from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController


def _controller():
    ctrl = ProxyController(ProxyConfig(port=0, scope_hosts=("h",), intercept=True))
    ctrl.build()                     # engine + interceptor, no sockets bound
    return ctrl


def test_controller_pending_view_forward_roundtrip():
    async def go():
        ctrl = _controller()
        seen = {}

        def fake(host, port, tls, raw):
            seen["req"] = raw
            return b"HTTP/1.1 200 OK\r\n\r\n"

        ctrl.engine.sender = fake     # avoid a real upstream socket
        task = asyncio.create_task(
            ctrl.engine.handle_request(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", "h", 80))
        for _ in range(200):
            await asyncio.sleep(0)
            if ctrl.pending_view():
                break
        pv = ctrl.pending_view()
        assert len(pv) == 1 and pv[0]["direction"] == "request"
        assert pv[0]["method"] == "GET" and pv[0]["target"] == "/"
        assert ctrl.forward(pv[0]["id"], "GET /x HTTP/1.1\r\nHost: h\r\n\r\n") is True
        await task
        assert b"/x" in seen["req"]
        assert ctrl.forward(999999) is False      # unknown id
        assert ctrl.drop(999999) is False
    asyncio.run(go())


def test_controller_set_intercept_responses():
    ctrl = _controller()
    assert ctrl.status()["intercept_responses"] is False
    assert ctrl.set_intercept_responses(True) is True
    assert ctrl.status()["intercept_responses"] is True


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _cfg():
    return load_config(overrides={"target_base_url": "http://localhost"}, environ={})


def test_intercept_routes_409_without_proxy():
    c = TestClient(create_app(_cfg()))
    assert c.get("/api/proxy/intercept/pending").status_code == 409
    assert c.post("/api/proxy/intercept/1/forward", json={}).status_code == 409
    assert c.post("/api/proxy/intercept/1/drop").status_code == 409


def test_intercept_routes_with_prebuilt_proxy():
    ctrl = _controller()
    c = TestClient(create_app(_cfg(), proxy=ctrl))   # no lifespan → no socket, engine ready
    assert c.get("/api/proxy/intercept/pending").json() == {"pending": []}
    # toggling responses reflects in status
    st = c.post("/api/proxy/intercept", json={"on": True, "responses": True}).json()
    assert st["intercept"] is True and st["intercept_responses"] is True
    # forward/drop of an unknown held flow is benign
    assert c.post("/api/proxy/intercept/424242/forward", json={}).json() == {"forwarded": False}
    assert c.post("/api/proxy/intercept/424242/drop").json() == {"dropped": False}
