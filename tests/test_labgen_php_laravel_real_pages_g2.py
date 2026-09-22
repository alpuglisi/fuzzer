"""Lane L-P3.3c-G2: the real catalog listing and its JSON feed --
`products.php` (`PFF-1001`) and `api/products.php` (`PFF-1003`) -- plus the
`json_view` module category (`fuzzlab.labgen.emitters.php_laravel.modules`)
that endpoint needed, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G2.

Rewritten during the L-P3.3c consolidation pass: this lane's own
`_URL_PATH_KEY` page-profile key (and its `DuplicateRouteError`
whole-file-scan guard) are superseded by the unified
`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` mechanism; `DuplicateRouteError`
itself survives in `route_accumulator.py` as the shared, method-aware
duplicate-URL guard every lane's fragments now go through. The `json_view`
module category (`JSON_FIELD_CASTS`, `VIEWS`) is unchanged -- it addresses a
different axis (presentation) than URL pinning.
"""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labels import contract
from fuzzlab.labgen import regression_gate
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    _VIEW_CATEGORY_KEY,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.emitters.php_laravel.modules import JSON_FIELD_CASTS, VIEWS
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import DuplicateRouteError, assemble_routes_file
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_g2.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth"

CELL_TO_CASE = {
    "LABGEN-PLRP-G2-0001": "PFF-1001",
    "LABGEN-PLRP-G2-0002": "PFF-1003",
}


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture(scope="module")
def cases() -> dict[str, contract.Case]:
    return {c.case_id: c for c in contract.load_labels(GROUND_TRUTH_DIR)}


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


def test_the_manifest_covers_exactly_this_groups_two_pages(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == set(CELL_TO_CASE)


def test_both_cells_reproduce_their_pff_cases_page_method_and_parameter(manifest, cases) -> None:
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        assert cell.route.path == case.url
        assert cell.route.method == case.method
        assert _PAGE_PROFILES[cell.route.path]["param_name"] == case.param


def test_both_cells_derive_secure_matching_their_true_negative_labels(manifest, cases, matrix) -> None:
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        assert case.expected_vulnerable is False
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert derived.verdict == "SECURE", cell.cell_id


def test_both_real_pages_declare_themselves_as_such_and_own_their_url(manifest) -> None:
    for cell in manifest.cells:
        profile = _PAGE_PROFILES[cell.route.path]
        assert profile[_REAL_PAGE_KEY] is True
        assert profile[_CANONICAL_CELL_KEY] == cell.cell_id
        assert served_url_for(cell) == cell.route.path


def test_only_the_json_feed_names_a_view_category(manifest) -> None:
    products = _PAGE_PROFILES["/products.php"]
    api_products = _PAGE_PROFILES["/api/products.php"]
    assert _VIEW_CATEGORY_KEY not in products
    assert api_products[_VIEW_CATEGORY_KEY] == "json_view"
    assert api_products[_VIEW_CATEGORY_KEY] in VIEWS


def test_the_json_view_emits_an_eloquent_api_resource_with_the_real_field_shape(emitter, manifest) -> None:
    cell = _cell(manifest, "LABGEN-PLRP-G2-0002")
    files = {f.role: f for f in emitter.render(cell)}
    resource = next(f for f in emitter.render(cell) if "Resource" in f.path)
    content = resource.content.decode("utf-8")
    assert "class LabgenPlrpG20002Resource extends JsonResource" in content
    assert "public static $wrap = null;" in content
    for field, cast in _PAGE_PROFILES["/api/products.php"]["json_fields"]:
        assert f"'{field}' =>" in content
    assert "(int) $this->id" in content
    assert "(float) $this->price" in content
    controller = files["controller"].content.decode("utf-8")
    assert "LabgenPlrpG20002Resource::collection($rows)" in controller
    # products.php has no view category, so its controller returns rows raw.
    other_controller = next(
        f.content.decode("utf-8") for f in emitter.render(_cell(manifest, "LABGEN-PLRP-G2-0001")) if f.role == "controller"
    )
    assert "Resource::collection" not in other_controller


def test_json_field_casts_are_a_closed_validated_set() -> None:
    assert set(JSON_FIELD_CASTS) == {None, "int", "float", "string"}
    with pytest.raises(ValueError, match="json_fields"):
        VIEWS["json_view"].render({"resource_class": "X"})


def test_the_regression_gate_accepts_the_real_urls_and_rejects_idiomatic_ones(manifest, cases) -> None:
    baseline = contract.GroundTruth(
        target="puppy-fort-factory", cases=[cases[cid] for cid in sorted(CELL_TO_CASE.values())]
    )

    def candidate_for(url_of: dict[str, str]) -> contract.GroundTruth:
        return contract.GroundTruth(
            target="generated-lab",
            cases=[dataclasses.replace(cases[CELL_TO_CASE[c.cell_id]], url=url_of[c.cell_id]) for c in manifest.cells],
        )

    served = {c.cell_id: served_url_for(c) for c in manifest.cells}
    assert regression_gate.assert_no_regression(baseline, candidate_for(served)).is_clean

    idiomatic = {cid: url.removesuffix(".php") for cid, url in served.items()}
    with pytest.raises(regression_gate.RegressionGateError, match="page changed"):
        regression_gate.assert_no_regression(baseline, candidate_for(idiomatic))


def test_a_hypothetical_url_collision_is_refused_by_the_accumulator(emitter, manifest) -> None:
    """The shared route_accumulator guard this lane contributed, now serving
    every lane: two cells (real or synthetic) claiming the identical URL fail
    loud rather than silently shadowing one route."""
    cell = _cell(manifest, "LABGEN-PLRP-G2-0001")
    colliding = dataclasses.replace(cell, cell_id="LABGEN-PLRP-G2-9999")
    fragments = {
        cell.cell_id: emitter.route_fragment_for(cell),
        colliding.cell_id: emitter.route_fragment_for(cell).replace(cell.cell_id, colliding.cell_id),
    }
    with pytest.raises(DuplicateRouteError, match="/products.php"):
        assemble_routes_file(fragments)


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_minimal_pair_holds_against_each_cells_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        assert cell.transform.ops
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_tier3_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, list(manifest.cells))  # must not raise


def test_cli_check_passes_end_to_end(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0
