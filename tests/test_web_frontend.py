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
    assert "subscribe" in r.text and "initLaunchNav" in r.text


def test_static_tokens_css_is_served():
    # R0 design tokens: one source of truth for color/elevation/density.
    r = _client().get("/static/tokens.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    # light default + explicit dark override + system-preference dark + density
    assert "--accent" in r.text
    assert '[data-theme="dark"]' in r.text
    assert "prefers-color-scheme: dark" in r.text
    assert '[data-density="compact"]' in r.text


def test_index_renders_the_app_shell():
    # R0 shell: left sidebar (nav.tabs) + top context bar, tokens linked before app.css,
    # and a no-FOUC head script that applies the persisted theme before first paint.
    body = _client().get("/").text
    assert 'class="sidebar"' in body and 'class="topbar"' in body
    assert '/static/tokens.css' in body
    assert body.index('/static/tokens.css') < body.index('/static/app.css')
    assert 'id="theme-toggle"' in body and 'id="density-toggle"' in body
    assert 'id="proxy-chip"' in body
    assert 'localStorage.getItem("fl-theme")' in body  # no-FOUC inline script
    # the context bar reflects config (authorization state) server-side
    assert "not authorized" in body


def test_shell_context_on_run_and_not_found_pages():
    # every page carries the same shell chrome (topbar chips need the shell context)
    client = _client()
    nf = client.get("/runs/999999")   # no store → not found, still framed by the shell
    assert nf.status_code == 404
    assert 'class="sidebar"' in nf.text and 'class="topbar"' in nf.text


def test_nav_has_real_routes_and_marks_active_section():
    # R1: the hash-tab shell is retired — the sidebar links to real, deep-linkable
    # routes and the active item is marked server-side (no client router).
    body = _client().get("/").text
    assert '<nav class="tabs"' in body
    routes = {
        "overview": "/", "launcher": "/launch", "proxy": "/proxy",
        "results": "/runs", "ml": "/ml", "diagnostics": "/diagnostics",
    }
    for tab, href in routes.items():
        assert f'data-tab="{tab}" href="{href}"' in body or f'href="{href}" data-tab="{tab}"' in body
    # the current section (Overview, on "/") is marked active server-side
    assert 'data-tab="overview" class="active" aria-current="page"' in body
    assert 'data-tab="launcher" class="active"' not in body
    # the shared stylesheet + module script are linked
    assert '/static/app.css' in body
    assert '/static/app.js' in body


def test_each_section_route_resolves_with_the_shell_and_marks_itself_active():
    # Deep-linkable routes (R1): every section is reachable at its own URL and the
    # shell frames it, with that section's nav item marked current.
    client = _client()
    for path, tab in (("/", "overview"), ("/launch", "launcher"), ("/proxy", "proxy"),
                      ("/runs", "results"), ("/ml", "ml"), ("/diagnostics", "diagnostics")):
        r = client.get(path)
        assert r.status_code == 200, path
        assert 'class="sidebar"' in r.text and 'class="topbar"' in r.text
        assert f'data-tab="{tab}" class="active" aria-current="page"' in r.text


def test_index_previews_activities_from_the_command_spec():
    body = _client().get("/launch").text
    # activities come from the command-spec registry (Phase 0.1)
    assert "greybox-run" in body and "mutate-run" in body
    # gate pills surface which activities send traffic / need authorization
    assert "sends traffic" in body and "--authorized" in body


# --- Phase 1: interactive launcher forms -----------------------------------

def test_launcher_renders_a_form_per_activity():
    body = _client().get("/launch").text
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
    # unauthorized: traffic tools' Run is disabled; read-only tools stay enabled.
    # Matched on the (whitespace-independent) gate title so the layout can evolve.
    gate = 'title="set authorized:true to run traffic tools"'
    unauth = _client(authorized=False).get("/launch").text
    assert unauth.count(gate) == 7
    auth = _client(authorized=True).get("/launch").text
    assert gate not in auth


def test_category_picker_rendered_for_auto():
    body = _client().get("/launch").text
    assert 'data-catgroup="categories"' in body
    # populated from the known injection categories
    assert 'class="cat"' in body


def test_plugins_panel_and_endpoint():
    client = _client()
    assert "Plugins" in client.get("/launch").text
    data = client.get("/api/plugins").json()
    assert "plugins" in data and isinstance(data["plugins"], list)


def test_session_is_subcommand_note_not_a_form():
    body = _client().get("/launch").text
    # session has subparsers → rendered as a CLI note, not a launch form
    assert 'data-command="session"' not in body
    assert "fuzzlab session &lt;sub&gt;" in body
