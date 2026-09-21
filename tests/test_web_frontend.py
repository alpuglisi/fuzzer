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


def _client(authorized=False):
    cfg = load_config(overrides={"target_base_url": "http://localhost",
                                 "authorized": authorized}, environ={})
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
    # activities come from the command-spec registry (Phase 0.1)
    assert "greybox-run" in body and "mutate-run" in body
    # gate pills surface which activities send traffic / need authorization
    assert "sends traffic" in body and "--authorized" in body


# --- Phase 1: interactive launcher forms -----------------------------------

def test_launcher_renders_a_form_per_activity():
    body = _client().get("/").text
    # one form per non-subcommand activity (session is subcommand-only → note, no form)
    assert body.count('class="launch-form"') >= 8
    assert 'data-command="auto"' in body
    # auto's fields are rendered from its parser, keyed by argparse dest
    assert 'data-dest="base_url"' in body       # required text field
    assert 'data-dest="mode"' in body           # choice → <select>
    assert 'data-dest="bandit"' in body         # bool → checkbox
    # each form has dry-run / run / stop controls
    assert 'data-action="dry-run"' in body and 'data-action="run"' in body
    # the automatic-mode form still exists alongside the launcher forms
    assert 'action="/api/run/automatic"' in body


def test_run_buttons_gated_by_authorization():
    # unauthorized: traffic tools' Run is disabled; read-only tools stay enabled
    unauth = _client(authorized=False).get("/").text
    assert unauth.count('data-action="run"\n            disabled') == 7
    auth = _client(authorized=True).get("/").text
    assert 'data-action="run"\n            disabled' not in auth


def test_category_picker_rendered_for_auto():
    body = _client().get("/").text
    assert 'data-catgroup="categories"' in body
    # populated from the known injection categories
    assert 'class="cat"' in body


def test_plugins_panel_and_endpoint():
    client = _client()
    assert "Plugins" in client.get("/").text
    data = client.get("/api/plugins").json()
    assert "plugins" in data and isinstance(data["plugins"], list)


def test_session_is_subcommand_note_not_a_form():
    body = _client().get("/").text
    # session has subparsers → rendered as a CLI note, not a launch form
    assert 'data-command="session"' not in body
    assert "fuzzlab session &lt;sub&gt;" in body
