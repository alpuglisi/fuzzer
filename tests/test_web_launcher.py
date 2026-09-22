"""Tests for the local web launcher (T0.9, D11): no-auto-run + mode selection."""

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app, serve  # noqa: E402

from tests._web_client import web_client  # noqa: E402


def _client(authorized=False, pipeline=None):
    cfg = load_config(overrides={"authorized": authorized,
                                 "target_base_url": "http://localhost"}, environ={})
    return web_client(create_app(cfg, pipeline=pipeline))


def test_index_offers_both_modes_and_does_not_run():
    client = _client()
    r = client.get("/")
    assert r.status_code == 200
    body = r.text.lower()
    assert "automatic" in body and "manual" in body
    # No-auto-run: status stays idle just from loading the panel.
    assert client.get("/api/status").json()["mode"] == "idle"


def test_status_reports_never_auto_run():
    status = _client().get("/api/status").json()
    assert status["auto_run"] is False
    assert "localhost" in status["scope_hosts"] or "127.0.0.1" in status["scope_hosts"]


def test_automatic_blocked_without_authorization():
    r = _client(authorized=False).post("/api/run/automatic")
    assert r.status_code == 403


def test_automatic_runs_injected_pipeline_when_authorized():
    calls = []

    def fake_pipeline(cfg):
        calls.append(cfg.get("target_base_url"))
        return {"tp": 8, "fp": 0, "passed": True}

    client = _client(authorized=True, pipeline=fake_pipeline)
    # Loading the page must NOT trigger the pipeline.
    client.get("/")
    assert calls == []
    # Only an explicit POST does.
    r = client.post("/api/run/automatic")
    assert r.status_code == 200
    assert r.json()["result"]["passed"] is True
    assert calls == ["http://localhost"]


def test_manual_mode_lists_prewired_commands():
    data = _client().get("/api/manual").json()
    assert data["mode"] == "manual"
    names = {c["name"] for c in data["commands"]}
    assert {"crawler", "auditor", "fuzzer"} <= names


def test_serve_refuses_non_loopback():
    cfg = load_config(overrides={"web_host": "0.0.0.0"}, environ={})
    with pytest.raises(ValueError):
        serve(cfg)
