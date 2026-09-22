"""Lane L-P3.3c-G1: the two real numeric-literal-SQLi pages of
`puppy-fort-factory/` reproduced as `php_laravel` cells -- `product.php`
(`PFF-0001`) and `blog_post.php` (`PFF-0006`), plus each page's authored
bound-parameter twin, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G1.

Rewritten during the L-P3.3c consolidation pass to use the single unified
URL-pinning mechanism (`php_laravel._REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`,
`served_url_for`) that replaced this lane's own `_GROUND_TRUTH_CASE_KEY`/
`served_url_for` pair -- the *name* `served_url_for` survives unchanged (it
was this lane's own contribution to the consolidated design), but its
implementation, and the profile keys behind it, are now shared with every
other L-P3.3c sub-lane. See `fuzzlab/labgen/emitters/php_laravel/__init__.py`
and `docs/components/01-target-lab/change-control.md`'s consolidation entry.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from fuzzlab.labels import contract
from fuzzlab.labgen import regression_gate
from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _GROUND_TRUTH_CASE_KEY,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.schema import Cell, Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_numeric.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth"

#: The `PFF-` case each real (non-twin) cell of this manifest reproduces.
CELL_TO_CASE = {
    "LABGEN-RPL-PRODUCT": "PFF-0001",
    "LABGEN-RPL-BLOGPOST": "PFF-0006",
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


def test_the_manifest_covers_both_real_pages_and_their_twins(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == {
        "LABGEN-RPL-PRODUCT",
        "LABGEN-RPL-PRODUCT-BOUND",
        "LABGEN-RPL-BLOGPOST",
        "LABGEN-RPL-BLOGPOST-BOUND",
    }


def test_the_canonical_cells_reproduce_their_pff_cases_page_and_method(manifest, cases) -> None:
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        assert cell.route.path == case.url
        assert cell.route.method == case.method
        assert _PAGE_PROFILES[cell.route.path]["param_name"] == case.param


def test_each_canonical_cells_derived_verdict_matches_the_label(manifest, cases, matrix) -> None:
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert derived.verdict == ("VULNERABLE" if case.expected_vulnerable else "SECURE"), cell_id


def test_every_real_page_profile_declares_itself_as_such(manifest) -> None:
    """§4.3.6.6a for real, at the source: every profile a cell of this
    manifest renders against carries `real_page` and names the one cell that
    owns the page's real URL -- the unified mechanism that replaced this
    lane's own `_GROUND_TRUTH_URL_CELL_ID_KEY`."""
    for cell in manifest.cells:
        profile = _PAGE_PROFILES[cell.route.path]
        assert profile[_REAL_PAGE_KEY] is True
        assert profile[_CANONICAL_CELL_KEY] in CELL_TO_CASE


def test_ground_truth_case_ids_never_leak_into_a_generated_file(manifest) -> None:
    """The naming-safety finding this lane's original design contributed
    (recorded for `L-P3.3c` more broadly): a page profile's own
    `_GROUND_TRUTH_CASE_KEY` metadata is popped before any template renders,
    so a case ID like `PFF-0001` never reaches a generated controller/view
    (FR-LAB-2 keeps emitted artifacts' provenance opaque about which
    ground-truth case they reproduce)."""
    emitter = LaravelEmitter()
    for cell in manifest.cells:
        profile = _PAGE_PROFILES[cell.route.path]
        case_id = profile.get(_GROUND_TRUTH_CASE_KEY)
        if case_id is None:
            continue
        for f in emitter.render(cell):
            assert case_id.encode("ascii") not in f.content, (cell.cell_id, f.path)


def test_served_url_for_matches_what_route_fragment_for_registers(emitter, manifest) -> None:
    """PA-0003/PA-0021: one shared derivation. A twin (the bound-parameter
    cells this lane authors alongside each real page) never claims the real
    URL -- it gets its own, still-`.php`-suffixed variant."""
    for cell in manifest.cells:
        url = served_url_for(cell)
        assert f"'{url}'" in emitter.route_fragment_for(cell)
        if cell.cell_id not in CELL_TO_CASE:
            # An authored twin: distinct from, but still suffixed like, the
            # real page's own URL.
            assert url != cell.route.path
            assert url.endswith(".php")


def test_the_regression_gate_accepts_the_real_urls_and_rejects_idiomatic_ones(emitter, manifest, cases) -> None:
    baseline = contract.GroundTruth(
        target="php_laravel",
        cases=[cases[case_id] for case_id in sorted(CELL_TO_CASE.values())],
    )

    def candidate_for(url_of: dict[str, str]) -> contract.GroundTruth:
        return contract.GroundTruth(
            target="generated-lab",
            cases=[
                dataclasses.replace(cases[CELL_TO_CASE[cid]], url=url_of[cid]) for cid in CELL_TO_CASE
            ],
        )

    served = {cid: served_url_for(_cell(manifest, cid)) for cid in CELL_TO_CASE}
    assert regression_gate.assert_no_regression(baseline, candidate_for(served)).is_clean  # must not raise

    idiomatic = {cid: url.removesuffix(".php") for cid, url in served.items()}
    with pytest.raises(regression_gate.RegressionGateError, match="page changed"):
        regression_gate.assert_no_regression(baseline, candidate_for(idiomatic))


def test_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_tier3_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, list(manifest.cells))  # must not raise


def test_cli_check_passes_end_to_end(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0
