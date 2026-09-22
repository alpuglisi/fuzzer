"""Tests for the app shell + MPA section routes (U0: MPA routes + asset split).

Covers the new per-section-route structure without weakening the launcher/results
invariants those suites already protect (no-auto-run, loopback-only, read-only over
the store). U0 retired the hash-tab shell (`initTabs`, `.panel`/`data-tab`): each
sidebar section is now a real route rendering its own template, with the active nav
item computed server-side (`response.context["active"]`) rather than switched by
client JS. Starlette's `TestClient` runs no JS, so every assertion here doubles as
the no-JS check (R-09 test strategy, docs/UI_IMPLEMENTATION_PLAN.md §7).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import NAV, create_app  # noqa: E402

from tests._web_client import web_client  # noqa: E402

# (route, section id, template name) — the single parametrization covering
# routing + deep-link + template + active-nav for every sidebar section (R-09).
# Derived from app.py's NAV (the single source of truth the nav loop itself uses,
# PA-0001) rather than a hand-maintained duplicate; the template name follows the
# `sections/<id>.html` convention every route in app.py wires up.
SECTIONS = [(item["href"], item["id"], f"sections/{item['id']}.html") for item in NAV]


def _client(authorized=False):
    cfg = load_config(overrides={"target_base_url": "http://localhost",
                                 "authorized": authorized}, environ={})
    return web_client(create_app(cfg))


def test_static_css_partials_are_served():
    client = _client()
    r = client.get("/static/tokens.css")
    assert r.status_code == 200 and "text/css" in r.headers["content-type"]
    r = client.get("/static/css/shell.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert ".card" in r.text and "nav.tabs" in r.text
    r = client.get("/static/css/launcher.css")
    assert r.status_code == 200 and ".launch" in r.text
    r = client.get("/static/css/proxy.css")
    assert r.status_code == 200 and "#flow-table" in r.text


def test_static_js_modules_are_served():
    client = _client()
    r = client.get("/static/js/shell.js")
    assert r.status_code == 200
    assert "initShell" in r.text
    assert "function initTabs" not in r.text  # U0 retired the hash-tab shell
    r = client.get("/static/js/launcher.js")
    assert r.status_code == 200 and "initLaunchForms" in r.text
    r = client.get("/static/js/proxy.js")
    assert r.status_code == 200 and "initIntercept" in r.text
    r = client.get("/static/js/http.js")
    assert r.status_code == 200 and "subscribe" in r.text


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


@pytest.mark.parametrize("route,section_id,template", SECTIONS)
def test_section_route_renders_with_active_nav(route, section_id, template):
    # Routing + deep-link + template + server-rendered active-nav, in one place
    # (R-09): every sidebar section is reachable at its own URL, renders the right
    # template, and marks itself current via `active` (compared to NAV in the nav
    # loop, never guessed from the request path).
    r = _client().get(route)
    assert r.status_code == 200
    assert r.template.name == template
    assert r.context["active"] == section_id
    body = r.text
    assert f'data-section="{section_id}"' in body
    assert f'aria-current="page"' in body
    # every page carries the shared shell chrome
    assert 'class="sidebar"' in body and 'class="topbar"' in body
    assert '/static/tokens.css' in body
    assert '/static/css/shell.css' in body
    assert body.index('/static/tokens.css') < body.index('/static/css/shell.css')
    assert '/static/js/shell.js' in body
    assert 'id="theme-toggle"' in body and 'id="density-toggle"' in body
    assert 'id="proxy-chip"' in body
    assert 'localStorage.getItem("fl-theme")' in body  # no-FOUC inline script


def test_sidebar_links_are_real_hrefs_to_every_section():
    # No hash-tab switching left: the sidebar nav is plain <a href> per section, so
    # deep-linking, back/forward, and no-JS all come free from the browser.
    body = _client().get("/").text
    for route, section_id, _ in SECTIONS:
        assert f'href="{route}" data-section="{section_id}"' in body
    assert 'data-tab=' not in body   # the retired hash-tab attribute is gone


def test_only_the_current_sections_nav_link_is_marked_active():
    import re
    for route, section_id, _ in SECTIONS:
        body = _client().get(route).text
        assert body.count('aria-current="page"') == 1
        # the <a> carrying aria-current="page" is the one for this route's own section
        anchors = re.findall(r'<a href="[^"]*" data-section="([^"]+)"[^>]*>', body)
        current = [sec for sec in anchors
                   if re.search(rf'data-section="{sec}"[^>]*aria-current="page"', body)]
        assert current == [section_id]


def test_shell_context_on_run_and_not_found_pages():
    # every page carries the same shell chrome (topbar chips need the shell context)
    client = _client()
    nf = client.get("/runs/999999")   # no store → not found, still framed by the shell
    assert nf.status_code == 404
    assert 'class="sidebar"' in nf.text and 'class="topbar"' in nf.text
    # a run detail is reached from Results, so Results stays highlighted in the nav
    assert nf.context["active"] == "results"


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
    # unauthorized: traffic tools' Run is disabled; read-only tools stay enabled.
    # Matched on the (whitespace-independent) gate title so the layout can evolve.
    gate = 'title="set authorized:true to run traffic tools"'
    unauth = _client(authorized=False).get("/").text
    assert unauth.count(gate) == 7
    auth = _client(authorized=True).get("/").text
    assert gate not in auth


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
