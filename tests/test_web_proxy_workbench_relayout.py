"""Tests for R3 (docs/UI_LAYOUT_REDESIGN.md #9): the Proxy workbench re-lay onto the
shared sub-nav + message-editor pattern.

These are template/route-rendering tests (JS behavior itself -- tab switching, the
Pretty/Hex derivation, the split-pane resizer -- is browser-only and covered by
`tests/test_web_repeater_browser.py`'s real-browser smoke, which also exercises the
sub-nav click needed to reach the Repeater panel). What is checked here: the sub-nav
and message-editor markup exist, every id the pre-existing `initProxy`/`initIntercept`/
`initRepeater`/`initScope` JS (unchanged by this rebuild) depends on is still present,
and the four workbench panels are wired to the sub-nav's data-tab/data-panel contract
with exactly one visible by default.
"""

from __future__ import annotations

import re

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _client(**over):
    cfg = load_config(overrides={"target_base_url": "http://localhost", **over}, environ={})
    return TestClient(create_app(cfg))


def test_proxy_page_has_a_subnav_with_four_tabs():
    r = _client().get("/proxy")
    assert r.status_code == 200
    body = r.text
    assert 'class="subnav proxy-subnav"' in body
    for tab in ("history", "intercept", "repeater", "scope"):
        assert f'data-tab="{tab}"' in body


def test_subnav_panels_match_the_tabs_and_history_is_the_default():
    body = _client().get("/proxy").text
    panels = dict(re.findall(r'data-panel="([a-z]+)"[^>]*?(hidden)?>', body))
    # every tab has a matching panel
    for tab in ("history", "intercept", "repeater", "scope"):
        assert tab in panels, f"no subnav-panel for tab {tab!r}"
    # exactly one panel ships visible (server-rendered default, before JS runs) --
    # history, matching app.js's initProxySubnav() default.
    hist_idx = body.index('data-panel="history"')
    hist_tag_end = body.index(">", hist_idx)
    assert "hidden" not in body[hist_idx:hist_tag_end]
    for tab in ("intercept", "repeater", "scope"):
        idx = body.index(f'data-panel="{tab}"')
        tag_end = body.index(">", idx)
        assert "hidden" in body[idx:tag_end], f"{tab} panel should be hidden by default"


def test_proxy_workbench_ids_the_existing_js_depends_on_are_preserved():
    """R3 re-lays the DOM, it must not silently drop an id `app.js`'s pre-existing
    initProxy/initIntercept/initRepeater/initScope (unchanged by this rebuild) query
    for -- that would silently break those handlers on every page load."""
    body = _client().get("/proxy").text
    required_ids = [
        "flow-table", "flow-search", "flow-refresh", "flow-empty", "flow-detail",
        "flow-detail-id", "flow-req", "flow-resp", "flow-to-repeater",
        "intercept-card", "intercept-unavailable", "intercept-controls",
        "intercept-on", "intercept-resp", "intercept-count", "pending-table",
        "pending-empty", "pending-detail", "pending-raw", "pending-id",
        "pending-forward", "pending-drop",
        "repeater-card", "rep-tab-select", "rep-refresh", "rep-new-name",
        "rep-new-host", "rep-new-port", "rep-new-tls", "rep-new-raw", "rep-create",
        "rep-editor", "rep-raw", "rep-send", "rep-resp",
        "scope-card", "scope-unavailable", "scope-controls", "scope-table",
        "scope-host", "scope-path", "scope-exclude", "scope-add",
        "mr-table", "mr-target", "mr-header", "mr-match", "mr-replace", "mr-regex",
        "mr-add", "mr-error",
    ]
    for elem_id in required_ids:
        assert f'id="{elem_id}"' in body, f"missing #{elem_id}"


def test_message_editor_markup_present_for_every_raw_surface():
    """The shared Pretty/Raw/Hex message editor wraps each raw-bytes surface, and the
    canonical raw element (same id the JS already reads/writes) is inside it."""
    body = _client().get("/proxy").text
    assert body.count('class="msg-editor"') >= 5   # flow-req/resp, pending-raw, rep-raw/resp
    for raw_id in ("flow-req", "flow-resp", "pending-raw", "rep-raw", "rep-resp"):
        idx = body.index(f'id="{raw_id}"')
        # walk backwards to the nearest enclosing msg-editor open tag
        editor_idx = body.rindex('class="msg-editor"', 0, idx)
        assert editor_idx < idx
        assert 'data-mv="pretty"' in body[editor_idx:idx]
        assert 'data-mv="hex"' in body[editor_idx:idx]


def test_split_panes_present_for_history_and_intercept():
    body = _client().get("/proxy").text
    assert body.count("split-resizer") >= 2
    assert 'data-split-id="history"' in body
    assert 'data-split-id="intercept"' in body


def test_app_js_ships_the_new_shared_primitives():
    r = _client().get("/static/app.js")
    for fn in ("initProxySubnav", "initMessageEditors", "initSplitResizers",
              "wireMsgEditor", "hexDump", "renderPretty", "selectProxyTab"):
        assert fn in r.text
