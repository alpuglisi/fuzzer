"""Live-boot conformance check for `ruby_rails` (Phase A --
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §2/§9.4a/§9.5,
`CC-LAB-0071`/`FR-LAB-65`).

Same bar `php_laravel`'s very first live-boot test set (see
`tests/test_labgen_conformance_live_boot.py`'s own module docstring): a real,
on-host integration test that assembles a real Rails 8.1 project from the
checked-in skeleton plus a real `RailsEmitter`-rendered cell, runs a real
`bundle install`, migrates a real per-run SQLite database, boots a real
`bin/rails server` process, and makes real HTTP requests against it -- torn
down on every exit path, never left running.

Skip-guarded (PA-0005/PA-0035) on `rails_boot_available()` -- ruby + bundle
on PATH and RubyGems actually reachable through Bundler's own real,
proxy-aware HTTP client (`fuzzlab.labgen.conformance.rails_live_boot.
_bundle_network_probe`) -- so this SKIPS cleanly, not fails, in any
environment without them. Marked `@pytest.mark.slow` (a real `bundle
install` + boot round trip).

This dispatch's own illustrative cell is a plain reflected value: a query
parameter read via `params[:q]` and echoed, unescaped, into the response
body (`("xss", "html_body")`, the one shape `RailsEmitter` renders in Phase
A) -- it does not need to be a real vulnerability to prove the pipeline
works end to end, per this dispatch's own explicit scope (the real Rails-
idiom CWE-915/502/webhook-signature modules are a separate, later lane).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter, url_path_for
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

pytestmark = pytest.mark.skipif(
    not rails_boot_available(),
    reason=(
        "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
        "network reachability (PA-0005/PA-0035) -- see "
        "rails_live_boot.rails_boot_available()"
    ),
)


def _illustrative_cell(cell_id: str) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="xss",
        stack_profile="ruby_rails",
        route=Route(method="GET", path=url_path_for(cell_id)),
        sink_context=SinkContext(family="html_body"),
        transform=Pipeline(),
    )


@pytest.mark.slow
def test_live_boot_illustrative_reflected_cell_serves_real_page() -> None:
    """Assemble + boot + serve a single trivial illustrative cell (a
    reflected request-param -> response-body echo). Proves a real HTTP round
    trip end to end: the real app boots, a real request reaches the real
    generated controller/view, and the response body actually contains the
    unescaped payload -- not a hand-written test double standing in for any
    part of this."""
    cell = _illustrative_cell("LABGEN-RR-0001")
    emitter = RailsEmitter()
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    with RailsLiveBootHarness(emitter, [cell]) as harness:
        resp = harness.get(url_path_for(cell.cell_id), params={"q": "<b>hi-from-rails</b>"})
        assert resp.status == 200
        assert "<b>hi-from-rails</b>" in resp.body

        health = harness.get("/up")
        assert health.status == 200
