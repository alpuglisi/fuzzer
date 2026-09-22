"""Tests for the frontend foundation: static assets + the MPA app shell.

Covers the new structure without weakening the launcher/results invariants those
suites already protect (no-auto-run, loopback-only, read-only over the store).

U0 (CC-UI-0025) replaced the hash-switched single page with real per-section
routes (`/`, `/proxy`, `/results`, `/ml`, `/diagnostics`) and split
`templates/index.html` / `static/app.js` / `static/app.css` into per-section
templates, ES modules, and CSS partials. This module covers the route/no-JS
layer of the R-09 test strategy: `TestClient` runs no JS, so its body *is* the
no-JS assertion.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402

# Every section route, its nav id, and one string that must appear only when the
# section actually rendered (not just the shared shell chrome).
SECTIONS = [
    ("/", "launcher", "Activities"),
    ("/proxy", "proxy", "Proxy workbench"),
    ("/results", "results", "Review runs"),
    ("/ml", "ml", "Machine learning"),
    ("/diagnostics", "diagnostics", "Diagnostics"),
]


def _client(authorized=False):
    cfg = load_config(overrides={"target_base_url": "http://localhost",
                                 "authorized": authorized}, environ={})
    return web_client(create_app(cfg))


# --- static assets (split per D3: per-section CSS partials + JS modules) --------

def test_static_shell_css_is_served():
    r = _client().get("/static/css/shell.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert ".card" in r.text and "nav.tabs" in r.text


def test_static_section_css_is_served():
    for path, needle in [
        ("/static/css/launcher.css", ".launch"),
        ("/static/css/proxy.css", "#flow-table"),
        ("/static/css/results.css", "Results section"),
    ]:
        r = _client().get(path)
        assert r.status_code == 200, path
        assert "text/css" in r.headers["content-type"]
        assert needle in r.text


def test_static_shell_js_is_served():
    r = _client().get("/static/js/shell.js")
    assert r.status_code == 200
    assert "initShell" in r.text
    # the old hash-based tab router is retired, not just moved
    assert "function initTabs" not in r.text


def test_static_section_js_modules_are_served():
    for path, needle in [
        ("/static/js/common.js", "export function subscribe"),
        ("/static/js/launcher.js", "initLaunchForms"),
        ("/static/js/proxy.js", "initRepeater"),
    ]:
        r = _client().get(path)
        assert r.status_code == 200, path
        assert needle in r.text


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


# --- app shell: every section route, deep-linked, no-JS ------------------------

@pytest.mark.parametrize("path, section, needle", SECTIONS)
def test_section_route_renders_the_app_shell(path, section, needle):
    body = _client().get(path).text
    assert 'class="sidebar"' in body and 'class="topbar"' in body
    assert '/static/tokens.css' in body
    assert body.index('/static/tokens.css') < body.index('/static/css/shell.css')
    assert 'id="theme-toggle"' in body and 'id="density-toggle"' in body
    assert 'id="proxy-chip"' in body
    assert 'localStorage.getItem("fl-theme")' in body  # no-FOUC inline script
    # the context bar reflects config (authorization state) server-side
    assert "not authorized" in body
    # the section itself rendered, not just the shared shell
    assert needle in body


@pytest.mark.parametrize("path, section, needle", SECTIONS)
def test_section_route_is_deep_linkable_and_marks_active_nav(path, section, needle):
    # Deep-linking: each section is reachable directly, no client router needed
    # (this is exactly what TestClient's single GET proves — no JS runs here).
    r = _client().get(path)
    assert r.status_code == 200
    body = r.text
    # server-rendered active state (R-01): the matching sidebar link carries
    # `aria-current="page"`; the <main> content region is tagged with the
    # section id (a stable hook for the browser-smoke layer, R-09).
    assert f'<main class="content" id="main" tabindex="-1" data-section="{section}">' in body
    link_start = body.index(f'href="{path}" data-section="{section}"')
    link_chunk = body[link_start:link_start + 200]
    assert 'aria-current="page"' in link_chunk
    # no other sidebar link claims aria-current on this page
    assert body.count('aria-current="page"') == 1


def test_sidebar_links_are_real_hrefs_not_hashes():
    body = _client().get("/").text
    assert '<nav class="tabs"' in body
    for path in ("/", "/proxy", "/results", "/ml", "/diagnostics"):
        assert f'href="{path}"' in body
    # no hash-based nav left
    assert 'href="/#' not in body


def test_shell_context_on_run_and_not_found_pages():
    # every page carries the same shell chrome (topbar chips need the shell context)
    client = _client()
    nf = client.get("/runs/999999")   # no store → not found, still framed by the shell
    assert nf.status_code == 404
    assert 'class="sidebar"' in nf.text and 'class="topbar"' in nf.text
    # a run/not-found page is a sub-page of Results — the sidebar reflects that
    assert 'data-section="results"' in nf.text


# --- Launcher section content (unchanged behavior, now on its own route) -------

def test_launcher_previews_activities_from_the_command_spec():
    body = _client().get("/").text
    # activities come from the command-spec registry (Phase 0.1)
    assert "greybox-run" in body and "mutate-run" in body
    # gate pills surface which activities send traffic / need authorization
    assert "sends traffic" in body and "--authorized" in body


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


# --- R-07: the "send to Repeater" pivot is real PRG + 303 ----------------------

def test_repeater_pivot_is_a_post_form_not_a_url_seed():
    body = _client().get("/proxy").text
    assert '<form method="post" action="/proxy/repeater/from-flow"' in body
    assert 'name="flow_id"' in body
    # never seed request bytes in the URL/query string
    assert "raw_request=" not in body


def test_repeater_pivot_redirects_303_and_carries_only_the_tab_id(tmp_path):
    from fuzzlab.core.store import Store
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter

    path = tmp_path / "p.db"
    with Store(path) as store:
        rid = store.start_run("proxy", "127.0.0.1")
        hw = HistoryWriter(store, rid, batch_size=1)
        hw.record(FlowRecord(method="GET", url="http://127.0.0.1:8080/p.php",
                             host="127.0.0.1:8080",
                             raw_request=b"GET /p.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
                             raw_response=b"HTTP/1.1 200 OK\r\n\r\n"))
        hw.flush()
        fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]

    cfg = load_config(overrides={"store_path": str(path)}, environ={})
    client = web_client(create_app(cfg), follow_redirects=False)
    r = client.post("/proxy/repeater/from-flow", data={"flow_id": str(fid)})
    assert r.status_code == 303
    assert r.headers["location"].startswith("/proxy?repeater_tab=")
    # an unknown flow id degrades to the default view rather than 404ing the pivot
    r2 = client.post("/proxy/repeater/from-flow", data={"flow_id": "999999"})
    assert r2.status_code == 303 and r2.headers["location"] == "/proxy"
