"""Tests for `sink_endpoint` (L-P2.3, `docs/LAB_IMPLEMENTATION_PLAN.md` §3.3):
a `Cell` field distinct from `route` (the injection point), naming the
endpoint where a stored/second-order payload actually reaches its sink and
executes.

Covers:
- a hand-built stored-XSS cell (write endpoint != sink endpoint) round-trips
  through `schema.py`'s loader and renders correctly via `php_current`
  (composing cleanly with the existing `read_stored_field` source module
  from CC-LAB-0022, per this task's "extend, don't rebuild" mandate); and
- a regression proving every existing manifest still loads and renders
  identically with `sink_endpoint` defaulting to `None`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Cell, Manifest, Route, load_manifest

_EXISTING_MANIFESTS = (
    "lab/manifests/example_phase0_scaffold.yaml",
    "lab/manifests/phase0_real_pages_sample.yaml",
)


def _stored_xss_cell_dict() -> dict:
    """A hand-built stored-XSS cell whose injection point (`route`, a
    profile-bio *write*) is a different real page from its sink
    (`sink_endpoint`, the profile *view* page that echoes the stored bio)."""
    return {
        "cell_id": "T-SINK-0001",
        "class": "xss",
        "stack_profile": "php_current",
        "route": {"method": "POST", "path": "/edit_profile.php"},
        "sink_endpoint": {"method": "GET", "path": "/profile.php"},
        "sink_context": {
            "family": "html_body",
            "required_neutralizations": ["html_tag_break"],
        },
        "transform": [],
    }


def test_sink_endpoint_defaults_to_none() -> None:
    data = _stored_xss_cell_dict()
    del data["sink_endpoint"]
    cell = Cell.from_dict(data)
    assert cell.sink_endpoint is None


def test_sink_endpoint_round_trips_through_the_schema_loader() -> None:
    # "schema.py's loader" here is Manifest.from_dict, which every YAML
    # manifest ultimately goes through (load_manifest = jsonschema validate
    # + Manifest.from_dict) -- validate=False exercises the dataclass
    # resolution path directly, the same as load_manifest does after its own
    # jsonschema.validate() call succeeds.
    raw = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "cells": [_stored_xss_cell_dict()],
    }
    manifest = Manifest.from_dict(raw, validate=False)
    cell = manifest.cells[0]
    assert cell.route == Route(method="POST", path="/edit_profile.php")
    assert cell.sink_endpoint == Route(method="GET", path="/profile.php")
    # Distinct from route -- the whole point of this field (§3.3).
    assert cell.sink_endpoint != cell.route


def test_sink_endpoint_validates_through_the_full_jsonschema_loader() -> None:
    """CC-LAB-0038 merge-time addendum: `sink_endpoint` must validate through
    the real `load_manifest()` path (`jsonschema.validate()` +
    `Manifest.from_dict()`), not only via `Manifest.from_dict(...,
    validate=False)` -- the cell schema's `additionalProperties: false`
    would otherwise silently reject any manifest that actually declares it."""
    raw = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "cells": [_stored_xss_cell_dict()],
    }
    manifest = Manifest.from_dict(raw, validate=True)
    assert manifest.cells[0].sink_endpoint == Route(method="GET", path="/profile.php")


def test_stored_xss_cell_with_distinct_sink_endpoint_renders_via_php_current() -> None:
    # Confirms php_current's existing read_stored_field source (CC-LAB-0022)
    # composes cleanly with a sink_endpoint cell -- render() must render the
    # *sink* page (/profile.php), never the injection-point page
    # (/edit_profile.php, which php_current has no page profile for at all).
    cell = Cell.from_dict(_stored_xss_cell_dict())
    emitter = PhpCurrentEmitter()
    assert emitter.supports(cell.vuln_class, cell.sink_context) is True

    files = emitter.render(cell)
    assert len(files) == 1
    content = files[0].content.decode("utf-8")

    assert "// Real page: /profile.php" in content
    assert "$currentUser['bio']" in content
    assert "echo '<div class=\"bio\">' . $bio . '</div>';" in content
    # Never renders anything from the injection-point page.
    assert "edit_profile" not in content


def test_render_ignores_injection_route_page_profile_gap() -> None:
    # Without sink_endpoint routing, rendering this cell would fail because
    # php_current has no page profile for /edit_profile.php (the injection
    # point) -- proving render() truly dispatches on sink_endpoint, not on
    # route, once sink_endpoint is set.
    cell = Cell.from_dict(_stored_xss_cell_dict())
    assert cell.route.path == "/edit_profile.php"
    emitter = PhpCurrentEmitter()
    # Renders without raising, despite /edit_profile.php having no profile.
    emitter.render(cell)


@pytest.mark.parametrize("manifest_path", _EXISTING_MANIFESTS)
def test_existing_manifest_cells_default_sink_endpoint_to_none(manifest_path: str) -> None:
    manifest = load_manifest(manifest_path)
    assert len(manifest.cells) > 0
    for cell in manifest.cells:
        assert cell.sink_endpoint is None


@pytest.mark.parametrize("manifest_path", _EXISTING_MANIFESTS)
def test_existing_manifest_cells_render_identically_with_sink_endpoint_field_present(
    manifest_path: str,
) -> None:
    # Regression: adding sink_endpoint to the Cell dataclass must not change
    # a single byte of output for the entire pre-existing corpus (None means
    # same-endpoint, i.e. today's behavior, unconditionally).
    manifest = load_manifest(manifest_path)
    emitter = PhpCurrentEmitter()
    rendered = 0
    for cell in manifest.cells:
        if not emitter.supports(cell.vuln_class, cell.sink_context):
            continue
        files = emitter.render(cell)
        assert len(files) == 1
        content = files[0].content.decode("utf-8")
        # render() must have used `route`, not some new sink_endpoint-only
        # path, for every pre-existing cell (sink_endpoint is None).
        assert f"// Real page: {cell.route.path}" in content
        rendered += 1
    assert rendered > 0
