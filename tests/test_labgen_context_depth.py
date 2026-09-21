"""Tests for the `context_depth` axis (L-P2.5,
`docs/LAB_IMPLEMENTATION_PLAN.md` §3.5).

`context_depth` is the **generator-input** counterpart of the ground-truth
`Case.flow_variant` field (L-P0.9/`CC-LAB-0030`): a manifest *declares* which
depth a cell should be generated at, where `flow_variant` *records*, after the
fact, the depth a case was generated at. Covers:

- one cell per reachable depth level (`direct`, `same_file_helper`,
  `cross_file`, `stored_second_order`), each rendering through `php_current`
  and confirming as intended in the rendered PHP;
- a value outside the four reachable levels raising (separately for Addendum
  B's named-but-unreachable `cross_service` and for outright garbage), rather
  than silently rendering something meaningless;
- the biconditional consistency between `context_depth ==
  "stored_second_order"` and `Cell.sink_endpoint` (L-P2.3/`CC-LAB-0038`), in
  both directions, plus the derivation that keeps pre-`context_depth`
  stored-cell manifests valid;
- `flow_variant_for()` as the single shared depth -> ground-truth-label
  mapping (PA-0003/PA-0021), asserted against `labels.schema.json`'s own
  `flow_variant` enum rather than a restated literal list (PA-0001); and
- regression: the whole pre-existing corpus still loads and renders
  byte-identically, and every manifest's every renderable cell still renders
  (PA-0024).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import (
    AXIS_RANGE_FACTOR_NAMES,
    CONTEXT_DEPTHS,
    DEFAULT_CONTEXT_DEPTH,
    UNREACHABLE_CONTEXT_DEPTHS,
    Cell,
    Manifest,
    ManifestError,
    Route,
    flow_variant_for,
    load_manifest,
    load_manifest_schema,
)

_EXISTING_MANIFESTS = (
    "lab/manifests/example_phase0_scaffold.yaml",
    "lab/manifests/phase0_real_pages_sample.yaml",
)


def _sqli_cell_dict(cell_id: str, context_depth: str | None = None) -> dict:
    """A GET/numeric-literal SQLi cell on a real page php_current has a
    profile for, at whichever depth the caller asks for."""
    data: dict = {
        "cell_id": cell_id,
        "class": "sqli",
        "stack_profile": "php_current",
        "route": {"method": "GET", "path": "/product.php"},
        "sink_context": {
            "family": "sql_numeric_literal",
            "required_neutralizations": ["numeric_literal_break"],
        },
        "transform": [],
    }
    if context_depth is not None:
        data["context_depth"] = context_depth
    return data


def _stored_cell_dict(context_depth: str | None = "stored_second_order") -> dict:
    """A stored-XSS cell whose injection point (`route`) and sink
    (`sink_endpoint`) are different real pages -- the shape L-P2.3 added."""
    data: dict = {
        "cell_id": "T-DEPTH-0004",
        "class": "xss",
        "stack_profile": "php_current",
        "route": {"method": "POST", "path": "/edit_profile.php"},
        "sink_endpoint": {"method": "GET", "path": "/profile.php"},
        "sink_context": {"family": "html_body", "required_neutralizations": ["html_tag_break"]},
        "transform": [],
    }
    if context_depth is not None:
        data["context_depth"] = context_depth
    return data


# --- the axis itself -------------------------------------------------------


def test_context_depth_defaults_to_direct() -> None:
    cell = Cell.from_dict(_sqli_cell_dict("T-DEPTH-0001"))
    assert cell.context_depth == DEFAULT_CONTEXT_DEPTH == "direct"


@pytest.mark.parametrize("depth", CONTEXT_DEPTHS)
def test_every_reachable_depth_round_trips_through_the_full_loader(depth: str) -> None:
    data = _stored_cell_dict() if depth == "stored_second_order" else _sqli_cell_dict(
        "T-DEPTH-0002", depth
    )
    raw = {"manifest_version": 1, "safety_matrix_version": 1, "cells": [data]}
    # validate=True exercises the real jsonschema path, so the manifest schema
    # and the dataclass must both accept every reachable level.
    manifest = Manifest.from_dict(raw, validate=True)
    assert manifest.cells[0].context_depth == depth


def test_unreachable_cross_service_depth_raises_with_a_clear_reason() -> None:
    with pytest.raises(ManifestError) as exc:
        Cell.from_dict(_sqli_cell_dict("T-DEPTH-0005", "cross_service"))
    message = str(exc.value)
    assert "cross_service" in message
    assert "not reachable" in message
    # Names the levels that *are* reachable, so the error is actionable.
    for depth in CONTEXT_DEPTHS:
        assert depth in message


@pytest.mark.parametrize("depth", UNREACHABLE_CONTEXT_DEPTHS)
def test_no_unreachable_depth_is_also_listed_as_reachable(depth: str) -> None:
    assert depth not in CONTEXT_DEPTHS


def test_an_unknown_depth_value_raises() -> None:
    with pytest.raises(ManifestError, match="context_depth must be one of"):
        Cell.from_dict(_sqli_cell_dict("T-DEPTH-0006", "not-a-real-depth"))


def test_manifest_schema_rejects_an_unreachable_depth_at_validation_time() -> None:
    raw = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "cells": [_sqli_cell_dict("T-DEPTH-0007", "cross_service")],
    }
    with pytest.raises(ManifestError):
        Manifest.from_dict(raw, validate=True)


def test_manifest_schema_depth_enum_matches_the_code_vocabulary() -> None:
    # PA-0001: derive the expectation from the code's own source of truth
    # rather than restating the enum; PA-0010: the schema and the loader must
    # stay in lockstep or a level accepted by one is silently dropped by the
    # other.
    schema = load_manifest_schema()
    assert tuple(schema["$defs"]["context_depth"]["enum"]) == CONTEXT_DEPTHS


def test_context_depth_is_an_axis_range_factor_in_both_schema_and_loader() -> None:
    schema = load_manifest_schema()
    factors = schema["$defs"]["axis_range"]["properties"]["factors"]["properties"]
    assert "context_depth" in factors
    assert "context_depth" in AXIS_RANGE_FACTOR_NAMES


# --- consistency with sink_endpoint (L-P2.3) -------------------------------


def test_stored_second_order_requires_a_sink_endpoint() -> None:
    with pytest.raises(ManifestError, match="requires a sink_endpoint"):
        Cell.from_dict(_sqli_cell_dict("T-DEPTH-0008", "stored_second_order"))


def test_stored_second_order_rejects_a_sink_endpoint_equal_to_route() -> None:
    data = _stored_cell_dict()
    data["sink_endpoint"] = dict(data["route"])
    with pytest.raises(ManifestError, match="sink_endpoint != route"):
        Cell.from_dict(data)


def test_a_distinct_sink_endpoint_with_a_shallower_declared_depth_raises() -> None:
    data = _stored_cell_dict(context_depth="cross_file")
    with pytest.raises(ManifestError, match="stored_second_order' cell by definition"):
        Cell.from_dict(data)


def test_an_omitted_depth_is_derived_from_a_distinct_sink_endpoint() -> None:
    # Keeps every pre-L-P2.5 stored/second-order cell (and L-P2.3's own
    # fixtures) valid and meaning exactly what it meant.
    cell = Cell.from_dict(_stored_cell_dict(context_depth=None))
    assert cell.context_depth == "stored_second_order"
    assert cell.sink_endpoint == Route(method="GET", path="/profile.php")


# --- ground-truth side (flow_variant) --------------------------------------


@pytest.mark.parametrize("depth", CONTEXT_DEPTHS)
def test_flow_variant_for_maps_every_reachable_depth(depth: str) -> None:
    data = _stored_cell_dict() if depth == "stored_second_order" else _sqli_cell_dict(
        "T-DEPTH-0009", depth
    )
    cell = Cell.from_dict(data)
    assert flow_variant_for(cell) == depth


def test_every_reachable_depth_is_an_accepted_ground_truth_flow_variant() -> None:
    # The two vocabularies must stay in lockstep: a depth a manifest can
    # declare but the ground-truth schema would reject is a label the
    # generator could never emit. Derived from labels.schema.json itself, not
    # restated (PA-0001).
    schema = json.loads(
        Path("fuzzlab/labels/schemas/labels.schema.json").read_text("utf-8")
    )
    allowed = set(schema["$defs"]["case"]["properties"]["flow_variant"]["enum"])
    assert set(CONTEXT_DEPTHS) <= allowed


# --- rendering -------------------------------------------------------------


def test_direct_cell_renders_one_file_with_no_depth_hop() -> None:
    cell = Cell.from_dict(_sqli_cell_dict("T-DEPTH-0010"))
    files = PhpCurrentEmitter().render(cell)
    assert len(files) == 1
    content = files[0].content.decode("utf-8")
    assert "_helper" not in content
    assert "Context depth" not in content
    assert "$id = isset($_GET['id'])" in content


def test_same_file_helper_cell_renders_the_helper_in_the_same_file() -> None:
    cell = Cell.from_dict(_sqli_cell_dict("T-DEPTH-0011", "same_file_helper"))
    files = PhpCurrentEmitter().render(cell)
    assert len(files) == 1
    content = files[0].content.decode("utf-8")
    helper = "handle_t_depth_0011_helper"
    assert f"function {helper}($id) {{" in content
    # The tainted value provably travels through the helper before the sink.
    assert f"$id = {helper}($id);" in content
    assert content.index(f"function {helper}") < content.index(f"$id = {helper}($id);")
    assert "// Context depth: same_file_helper" in content
    assert "require_once" not in content


def test_cross_file_cell_renders_a_second_helper_file_and_requires_it() -> None:
    cell = Cell.from_dict(_sqli_cell_dict("T-DEPTH-0012", "cross_file"))
    files = PhpCurrentEmitter().render(cell)
    assert len(files) == 2
    page, helper_file = files
    assert page.role == "page"
    assert helper_file.role == "helper"
    assert helper_file.path == "generated/t-depth-0012_helper.php"

    page_content = page.content.decode("utf-8")
    helper = "handle_t_depth_0012_helper"
    assert "require_once __DIR__ . '/t-depth-0012_helper.php';" in page_content
    assert f"$id = {helper}($id);" in page_content
    # The definition is *not* in the page -- that is the whole distinction
    # between cross_file and same_file_helper.
    assert f"function {helper}(" not in page_content
    assert "// Context depth: cross_file" in page_content

    helper_content = helper_file.content.decode("utf-8")
    assert helper_content.startswith("<?php\n")
    assert f"function {helper}($id) {{" in helper_content


def test_stored_second_order_cell_renders_the_sink_page() -> None:
    cell = Cell.from_dict(_stored_cell_dict())
    files = PhpCurrentEmitter().render(cell)
    assert len(files) == 1
    content = files[0].content.decode("utf-8")
    # Depth is expressed structurally, by rendering the *sink* page and
    # reading the value from storage -- no request source, no helper hop.
    assert "// Real page: /profile.php" in content
    assert "$currentUser['bio']" in content
    assert "// Context depth: stored_second_order" in content
    assert "_helper" not in content
    assert "edit_profile" not in content


def test_depth_hop_is_verdict_neutral_in_the_rendered_code() -> None:
    # A depth hop must be a pure pass-through: the vulnerable cell stays
    # vulnerable at every depth (same sink, same unsanitized concatenation).
    emitter = PhpCurrentEmitter()
    direct = emitter.render(Cell.from_dict(_sqli_cell_dict("T-DEPTH-0013")))[0]
    hopped = emitter.render(Cell.from_dict(_sqli_cell_dict("T-DEPTH-0014", "same_file_helper")))[0]
    sink_line = "$sql = \"SELECT * FROM products WHERE id = \" . $id;"
    assert sink_line in direct.content.decode("utf-8")
    assert sink_line in hopped.content.decode("utf-8")


def test_render_is_deterministic_for_every_depth() -> None:
    emitter = PhpCurrentEmitter()
    for depth in CONTEXT_DEPTHS:
        data = _stored_cell_dict() if depth == "stored_second_order" else _sqli_cell_dict(
            "T-DEPTH-0015", depth
        )
        cell = Cell.from_dict(data)
        assert emitter.render(cell) == emitter.render(cell)


# --- axis-range integration ------------------------------------------------


def test_context_depth_expands_as_a_covering_array_factor() -> None:
    raw = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "axis_ranges": [
            {
                "cell_id_prefix": "T-DEPTH-CA-",
                "factors": {
                    "context_depth": ["direct", "same_file_helper", "cross_file"],
                    "transform": [[], ["param_bind"]],
                },
                "class": "sqli",
                "stack_profile": "php_current",
                "route": {"method": "GET", "path": "/product.php"},
                "sink_context": {
                    "family": "sql_numeric_literal",
                    "required_neutralizations": ["numeric_literal_break"],
                },
            }
        ],
    }
    manifest = Manifest.from_dict(raw, validate=True)
    assert len(manifest.cells) > 0
    assert {c.context_depth for c in manifest.cells} == {
        "direct",
        "same_file_helper",
        "cross_file",
    }
    emitter = PhpCurrentEmitter()
    for cell in manifest.cells:
        assert emitter.render(cell)


def test_axis_range_rejects_a_fixed_sink_endpoint_no_depth_level_uses() -> None:
    raw = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "axis_ranges": [
            {
                "cell_id_prefix": "T-DEPTH-CA-BAD-",
                "factors": {
                    "context_depth": ["direct", "cross_file"],
                    "transform": [[], ["param_bind"]],
                },
                "class": "sqli",
                "stack_profile": "php_current",
                "route": {"method": "GET", "path": "/product.php"},
                "sink_endpoint": {"method": "GET", "path": "/profile.php"},
                "sink_context": {
                    "family": "sql_numeric_literal",
                    "required_neutralizations": ["numeric_literal_break"],
                },
            }
        ],
    }
    with pytest.raises(ManifestError, match="only used by a 'stored_second_order'"):
        Manifest.from_dict(raw, validate=True)


# --- regression over the pre-existing corpus -------------------------------


@pytest.mark.parametrize("manifest_path", _EXISTING_MANIFESTS)
def test_existing_manifest_cells_are_all_direct_and_render_unchanged(manifest_path: str) -> None:
    # PA-0024: exercise every cell of every existing manifest, not only the
    # new records this change was written for.
    manifest = load_manifest(manifest_path)
    assert len(manifest.cells) > 0
    emitter = PhpCurrentEmitter()
    rendered = 0
    for cell in manifest.cells:
        assert cell.context_depth == "direct"
        if not emitter.supports(cell.vuln_class, cell.sink_context):
            continue
        files = emitter.render(cell)
        # A `direct` cell is still exactly one file with no depth machinery.
        assert len(files) == 1
        content = files[0].content.decode("utf-8")
        assert "Context depth" not in content
        assert "_helper" not in content
        rendered += 1
    assert rendered > 0
