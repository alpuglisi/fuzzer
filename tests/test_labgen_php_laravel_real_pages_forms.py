"""Lane L-P3.3c-G5: the two real escaped-echo form pages of
`puppy-fort-factory/` reproduced as `php_laravel` cells --
`contact.php` (`PFF-1005`) and `newsletter.php` (`PFF-1006`),
`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G5.

Everything here is real and offline: the real manifest, the real safety
matrix, the real emitter and its real Jinja2 fragments, the real
`lab/ground-truth/labels.json`, the real T-LAB0.9 regression gate, and
(skip-guarded per PA-0005) a real `php -l` of every generated file.

The oracle for "reproduced" is §4.3.6.6 point 2's per-page acceptance
criterion, and every part of it is asserted from a source of truth rather than
a literal (PA-0001/PA-0027(b)): the expected verdict comes from the `PFF-`
case `labels.json` already carries, the migrated pages come from the emitter's
own page profiles, and the Tier-0/Tier-3 sweeps compute their cell set from
`Emitter.supports()` over every committed manifest.
"""

from __future__ import annotations

import dataclasses
import shutil
from pathlib import Path

import pytest

from fuzzlab.labels import contract
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    LaravelEmitter,
)
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.regression_gate import RegressionGateError, assert_no_regression
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_laravel_real_pages_forms.yaml"
ALL_MANIFEST_PATHS = sorted(str(p) for p in Path("lab/manifests").glob("*.yaml"))
GROUND_TRUTH_DIR = "lab/ground-truth"

#: The `PFF-` case each cell of this manifest reproduces. This is the one
#: mapping a test cannot derive -- it is the lane's *claim* about which real
#: page a cell is a reproduction of (the one thing PA-0001 reserves literals
#: for: a fixed external contract). Everything else about the pair (URL,
#: method, parameter location, expected verdict) is then read out of
#: `labels.json` rather than restated here.
CELL_TO_CASE = {
    "LABGEN-PLRP-1005": "PFF-1005",
    "LABGEN-PLRP-1006": "PFF-1006",
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


def _rendered(emitter, cell: Cell) -> dict[str, str]:
    return {f.role: f.content.decode("utf-8") for f in emitter.render(cell)}


def _php_laravel_cells(emitter) -> list[Cell]:
    """Every cell of every committed manifest this emitter declares support
    for -- computed from `supports()` itself, never a hand-kept roster
    (PA-0027(b)), so a cell a sibling lane adds is swept automatically."""
    return [
        cell
        for path in ALL_MANIFEST_PATHS
        for cell in load_manifest(path).cells
        if cell.stack_profile == "php_laravel" and emitter.supports(cell.vuln_class, cell.sink_context)
    ]


# ---------------------------------------------------------------------------
# The cells: they load, and they say about each page what labels.json says
# ---------------------------------------------------------------------------


def test_the_manifest_covers_exactly_this_groups_two_real_pages(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == set(CELL_TO_CASE)


def test_every_cell_reproduces_its_pff_cases_page_method_and_parameter(manifest, cases) -> None:
    """A reproduction must agree with the ground truth it reproduces on *where*
    the case lives, not only on its verdict: same URL, same method, same
    parameter in the same location."""
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        assert cell.route.path == case.url, cell.cell_id
        assert cell.route.method == case.method, cell.cell_id
        assert cell.param.location == case.location, cell.cell_id
        # The parameter name is the emitter's render-only page-profile metadata
        # (the Cell IR deliberately does not carry it), so it is checked there.
        assert _PAGE_PROFILES[cell.route.path]["param_name"] == case.param, cell.cell_id


def test_every_cells_derived_verdict_matches_the_label_ground_truth_carries(manifest, cases, matrix) -> None:
    """§4.3.6.6 point 2's load-bearing criterion: `verdict()` returns the label
    `labels.json` already carries for that `PFF-` case. Both of this group's
    cases are true negatives (`expected_vulnerable: false`), so both must
    derive SECURE -- read from the ground truth rather than hardcoded, so a
    relabelled case fails here instead of drifting."""
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert derived.verdict == ("VULNERABLE" if case.expected_vulnerable else "SECURE"), cell.cell_id
        assert case.expected_vulnerable is False, (
            f"{case.case_id} is no longer a true negative; this group's cells are secure-only "
            "(§4.3.6.3) and would need a vulnerable twin"
        )


def test_the_real_pages_security_mechanism_is_the_one_modelled(manifest, cases) -> None:
    """The real pages are secure because they reflect through `e()` and write
    nothing to the database (`puppy-fort-factory/contact.php`,
    `newsletter.php`). The Laravel reproduction must be secure for the *same*
    reason -- an escape in the transform region, no SQL at all -- not for an
    incidental one."""
    for cell in manifest.cells:
        assert cell.transform.ops == ("html_entity_escape",), cell.cell_id
        rendered = _rendered(LaravelEmitter(), cell)
        var = _PAGE_PROFILES[cell.route.path]["var_name"]
        # The escape is real, applied in the controller (modules.py decision 2)...
        assert f"['value' => e(${var})]" in rendered["controller"]
        # ...the value comes from the POST body, as labels.json's `location` says...
        assert f"${var} = $request->input(" in rendered["controller"]
        assert cases[CELL_TO_CASE[cell.cell_id]].location == "body"
        # ...the Blade view echoes raw (the sink never escapes anything itself)...
        assert "{!! $value !!}" in rendered["view"]
        # ...and neither page touches the database, like the real ones.
        for content in rendered.values():
            assert "DB::" not in content and "whereRaw" not in content, cell.cell_id


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


# ---------------------------------------------------------------------------
# §4.3.6.6a: the routes keep the real app's `.php` URL
# ---------------------------------------------------------------------------


def test_each_migrated_page_pins_the_real_apps_exact_url(manifest) -> None:
    for cell in manifest.cells:
        profile = _PAGE_PROFILES[cell.route.path]
        assert profile[_REAL_PAGE_KEY] is True
        assert profile[_CANONICAL_CELL_KEY] == cell.cell_id
        assert cell.route.path.endswith(".php")


def test_the_routes_file_registers_the_real_php_suffixed_paths(emitter, manifest, cases) -> None:
    """`Route::post('/contact.php', ...)`, not Laravel's idiomatic
    extension-less style: the URL (and, per the unified mechanism, the real
    HTTP method) the generated app serves is what `labels.json` labels the
    case at."""
    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        assert f"Route::{case.method.lower()}('{case.url}'," in content, cell.cell_id
        # ...and *not* at this stack's default cell-ID-derived URL.
        assert f"/cell/{cell.cell_id.lower()}" not in content, cell.cell_id


def test_the_regression_gate_accepts_the_migrated_urls_and_rejects_idiomatic_ones(
    emitter, manifest, cases
) -> None:
    """Why §4.3.6.6a exists, demonstrated against the real gate rather than
    asserted in prose: T-LAB0.9 treats a case served at a different URL as a
    build-breaking *relocation*, so the idiomatic extension-less route Laravel
    would otherwise use fails the gate for every migrated case."""
    baseline = contract.GroundTruth(
        target="puppy-fort-factory",
        cases=[cases[case_id] for case_id in sorted(CELL_TO_CASE.values())],
    )

    def candidate_for(url_of: dict[str, str]) -> contract.GroundTruth:
        return contract.GroundTruth(
            target="generated-lab",
            cases=[
                dataclasses.replace(cases[CELL_TO_CASE[c.cell_id]], url=url_of[c.cell_id])
                for c in manifest.cells
            ],
        )

    served = {}
    for cell in manifest.cells:
        fragment = emitter.route_fragment_for(cell)
        served[cell.cell_id] = fragment.split("'")[1]
    assert_no_regression(baseline, candidate_for(served)).is_clean  # must not raise

    idiomatic = {cid: url.removesuffix(".php") for cid, url in served.items()}
    with pytest.raises(RegressionGateError, match="page changed"):
        assert_no_regression(baseline, candidate_for(idiomatic))


def test_a_twin_added_later_to_a_pinned_page_gets_a_distinct_suffixed_url(emitter, manifest) -> None:
    """The unified mechanism (consolidating L-P3.3c-G1..G6, generalizing
    G3's design) does not need a page to stay a single-cell page forever: a
    pinned page is owned by exactly one *canonical* cell (this manifest's
    `LABGEN-PLRP-1005`), and any other cell of that page -- a vulnerable twin
    added later -- coexists as its own, still-`.php`-suffixed route rather
    than colliding with it or being refused outright. This is the trivial
    (single-cell) case of the same mechanism `/login.php`'s vulnerable cell
    and secure twin already exercise for real (lane G3)."""
    cell = _cell(manifest, "LABGEN-PLRP-1005")
    canonical_fragment = emitter.route_fragment_for(cell)
    assert "'/contact.php'" in canonical_fragment

    twin = dataclasses.replace(cell, cell_id="LABGEN-PLRP-9999")
    twin_fragment = emitter.route_fragment_for(twin)
    assert "'/contact.labgen-plrp-9999.php'" in twin_fragment
    assert "'/contact.php'" not in twin_fragment

    fragments = {cell.cell_id: canonical_fragment, twin.cell_id: twin_fragment}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    assert content.count("'/contact.php'") == 1


def test_a_cell_on_an_unpinned_page_still_gets_its_cell_id_derived_url(emitter) -> None:
    """The pre-L-P3.3c behavior is untouched for illustrative pages -- which is
    what lets a vulnerable cell and its secure twin coexist as two routes."""
    cell = Cell(
        cell_id="LABGEN-PL-0006",
        vuln_class="xss",
        stack_profile="php_laravel",
        route=Route(method="GET", path="/example/profile"),
        sink_context=SinkContext(family="html_body", required_neutralizations=("html_tag_break",)),
        transform=Pipeline.from_list(["html_entity_escape"]),
    )
    assert "'/cell/labgen-pl-0006'" in emitter.route_fragment_for(cell)


# ---------------------------------------------------------------------------
# Conformance: minimal pair, Tier 0, Tier 3 -- over EVERY manifest's cells
# ---------------------------------------------------------------------------


def test_the_supports_derived_sweep_really_covers_this_groups_cells(emitter, manifest) -> None:
    """Guard the sweeps below: if the `supports()`-derived cell set ever stopped
    including this manifest, the whole-collection tests would pass vacuously."""
    swept = {c.cell_id for c in _php_laravel_cells(emitter)}
    assert {c.cell_id for c in manifest.cells} <= swept
    assert len(swept) > len(manifest.cells), "the sweep must span more than this one manifest"


def test_tier3_regeneration_is_byte_identical_for_every_php_laravel_cell_of_every_manifest(
    emitter,
) -> None:
    """§4.3.6.6 point 1 (the BUG-0022/PA-0024 pattern), widened as this lane
    owes: the whole-manifest regenerate-and-diff covers every cell of every
    manifest this emitter supports, not only the two cells this group added --
    so a later group's page profile or module change that breaks an earlier
    group's page fails loudly here."""
    cells = _php_laravel_cells(emitter)
    assert cells
    tier3.regenerate_and_diff_emitter(emitter, cells)  # must not raise


def test_tier3_renders_one_unique_path_per_emitted_file_across_every_manifest(emitter) -> None:
    cells = _php_laravel_cells(emitter)
    tree = tier3.render_whole_sample(emitter, cells)
    assert len(tree) == sum(len(emitter.render(cell)) for cell in cells)


def test_minimal_pair_holds_between_each_migrated_cell_and_its_weakened_twin(emitter, manifest) -> None:
    """A secure-only cell still gets the minimal-pair invariant checked, against
    the same cell with its pipeline emptied (`fuzzlab.labgen.cli`'s own
    `_weakened_twin` convention) -- §4.3.6.3a's hazard: the whole
    security-relevant difference must sit in the declared transform region."""
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        assert cell.transform.ops, cell.cell_id
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_php_laravel_cell_of_every_manifest(emitter) -> None:
    for cell in _php_laravel_cells(emitter):
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_cli_check_passes_end_to_end_on_the_real_page_manifest(tmp_path) -> None:
    """The real build gate over this manifest: name-leak scanner, secret
    scanner, determinism, minimal pair, Tier 0 and Tier 3."""
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0
