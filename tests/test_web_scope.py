"""Tests for Scope + Match-Replace controls (Phase 2.4)."""

from __future__ import annotations

import pytest

from fuzzlab.proxy.message import RawMessage
from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController


def _controller():
    ctrl = ProxyController(ProxyConfig(port=0, scope_hosts=("127.0.0.1",)))
    ctrl.build()
    return ctrl


# --- controller: scope -----------------------------------------------------

def test_scope_view_add_remove_and_effect():
    ctrl = _controller()
    view = ctrl.scope_view()
    assert len(view) == 1 and view[0]["host"] == "127.0.0.1" and view[0]["exclude"] is False
    ctrl.scope_add("evil.example", exclude=True)
    ctrl.scope_add("10.0.0.5")
    assert ctrl.engine.scope.in_scope("10.0.0.5") is True
    assert ctrl.engine.scope.in_scope("evil.example") is False   # exclude wins
    # remove the exclude rule (index 1) → evil no longer excluded (but still not included)
    assert ctrl.scope_remove(1) is True
    assert len(ctrl.scope_view()) == 2
    assert ctrl.scope_remove(99) is False


# --- controller: match-replace --------------------------------------------

def test_matchreplace_add_view_toggle_remove_and_effect():
    ctrl = _controller()
    assert ctrl.matchreplace_view() == []
    ctrl.matchreplace_add("request_line", "/a", "/b")
    v = ctrl.matchreplace_view()
    assert len(v) == 1 and v[0]["target"] == "request_line" and v[0]["enabled"] is True
    # the rule actually rewrites the request line
    out = ctrl.engine.matchreplace.apply(
        RawMessage.from_bytes(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
    assert b"GET /b HTTP/1.1" in out.raw
    # disable it → no rewrite
    ctrl.matchreplace_toggle(0, False)
    out2 = ctrl.engine.matchreplace.apply(
        RawMessage.from_bytes(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
    assert b"GET /a HTTP/1.1" in out2.raw
    assert ctrl.matchreplace_remove(0) is True and ctrl.matchreplace_view() == []


def test_matchreplace_add_validates():
    ctrl = _controller()
    with pytest.raises(ValueError):
        ctrl.matchreplace_add("bogus", "x", "y")            # bad target
    with pytest.raises(ValueError):
        ctrl.matchreplace_add("header", "x", "y")           # header needs header_name


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

from tests._web_client import web_client  # noqa: E402


def _cfg():
    return load_config(overrides={"target_base_url": "http://localhost"}, environ={})


def test_scope_and_mr_routes_409_without_proxy():
    c = web_client(create_app(_cfg()))
    assert c.get("/api/proxy/scope").status_code == 409
    assert c.get("/api/proxy/matchreplace").status_code == 409
    assert c.post("/api/proxy/scope", json={"host": "x"}).status_code == 409


def test_scope_routes_with_proxy():
    c = web_client(create_app(_cfg(), proxy=_controller()))
    assert len(c.get("/api/proxy/scope").json()["scope"]) == 1
    assert c.post("/api/proxy/scope", json={}).status_code == 400        # host required
    added = c.post("/api/proxy/scope", json={"host": "10.0.0.9", "exclude": True}).json()
    assert len(added["scope"]) == 2 and added["scope"][1]["exclude"] is True
    out = c.delete("/api/proxy/scope/1").json()
    assert out["removed"] is True and len(out["scope"]) == 1


def test_matchreplace_routes_with_proxy():
    c = web_client(create_app(_cfg(), proxy=_controller()))
    assert c.get("/api/proxy/matchreplace").json()["rules"] == []
    ok = c.post("/api/proxy/matchreplace",
                json={"target": "body", "match": "a", "replace": "b"}).json()
    assert len(ok["rules"]) == 1 and ok["rules"][0]["target"] == "body"
    bad = c.post("/api/proxy/matchreplace", json={"target": "nope", "match": "x"})
    assert bad.status_code == 400
    tg = c.post("/api/proxy/matchreplace/0/toggle", json={"enabled": False}).json()
    assert tg["rules"][0]["enabled"] is False
    rm = c.delete("/api/proxy/matchreplace/0").json()
    assert rm["removed"] is True and rm["rules"] == []
