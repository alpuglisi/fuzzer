"""Tests for the Phase 0.2 frontend foundation: static assets + tab shell.

Covers the new structure without weakening the launcher/results invariants those
suites already protect (no-auto-run, loopback-only, read-only over the store).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _client():
    cfg = load_config(overrides={"target_base_url": "http://localhost"}, environ={})
    return TestClient(create_app(cfg))


def test_static_css_is_served():
    r = _client().get("/static/app.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert ".card" in r.text and "nav.tabs" in r.text


def test_static_js_is_served():
    r = _client().get("/static/app.js")
    assert r.status_code == 200
    assert "subscribe" in r.text and "initTabs" in r.text


def test_index_renders_the_tab_shell():
    body = _client().get("/").text
    assert '<nav class="tabs">' in body
    for tab in ("launcher", "proxy", "results", "ml", "diagnostics"):
        assert f'data-tab="{tab}"' in body
        assert f'id="tab-{tab}"' in body
    # the shared stylesheet + module script are linked
    assert '/static/app.css' in body
    assert '/static/app.js' in body


def test_index_previews_activities_from_the_command_spec():
    body = _client().get("/").text
    # activities come from the command-spec registry (Phase 0.1), rendered read-only
    assert "greybox-run" in body and "mutate-run" in body
    # gate pills surface which activities send traffic / need authorization
    assert "sends traffic" in body and "--authorized" in body


def test_index_has_no_run_controls_yet_beyond_automatic():
    # Phase 0.2 is a read-only preview: the only POST form is automatic mode.
    body = _client().get("/").text
    assert body.count("<form") == 1
    assert 'action="/api/run/automatic"' in body
