"""Lane L-P3.3c-DOM: the DOM-based XSS sink class explicitly deferred out of
the L-P3.3c-G1..G6 cutover's scope (D-open-2,
`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.7 -- "a new client-side sink class,
not a migration; it remains backlog, not something L-P3.3c-CUT waits on"),
now built for real as its own, separately-prioritized lane -- `reviews.php`
(`PFF-0007`) and `feedback.php` (`PFF-0008`).

Same rigor as the G1-G6 lanes' own test files (this file mirrors
`tests/test_labgen_php_laravel_real_pages_numeric.py`'s shape): everything is
real and offline -- the real manifest, the real safety matrix, the real
emitter and its real Jinja2 fragments, the real `lab/ground-truth/
labels.json`, the real T-LAB0.9 regression gate, and (skip-guarded per
PA-0005) a real `php -l` of every generated file. The one genuinely new
property this shape has, and that every test below is built to demonstrate
for real rather than assert in prose: the tainted value never reaches the
server at all, so it never appears in the generated *controller*, only in
the client-side `<script>` block of the generated Blade *view*.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from fuzzlab.labels import contract
from fuzzlab.labgen import regression_gate
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.schema import Cell, Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_dom.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth"

#: The `PFF-` case each canonical (non-twin) cell of this manifest reproduces.
CELL_TO_CASE = {
    "LABGEN-PLRP-DOM-0001": "PFF-0007",
    "LABGEN-PLRP-DOM-0002": "PFF-0008",
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


# ---------------------------------------------------------------------------
# The cells: they load, and they say about each page what labels.json says
# ---------------------------------------------------------------------------


def test_the_manifest_covers_both_real_pages_and_their_authored_twins(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == {
        "LABGEN-PLRP-DOM-0001",
        "LABGEN-PLRP-DOM-0001-SAFE",
        "LABGEN-PLRP-DOM-0002",
        "LABGEN-PLRP-DOM-0002-SAFE",
    }


def test_the_canonical_cells_reproduce_their_pff_cases_page_and_method(manifest, cases) -> None:
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        assert cell.route.path == case.url, cell_id
        assert cell.route.method == case.method, cell_id
        # The parameter name is the emitter's render-only page-profile
        # metadata (the Cell IR carries no concept of a client-only source at
        # all -- it never reaches the server), so it is checked against the
        # page profile, exactly like every other real-page group checks its
        # own render-only metadata.
        profile = _PAGE_PROFILES[cell.route.path]
        assert profile["dom_param_name"] == case.param, cell_id
        # `case.location` uses labels.json's URL-parts vocabulary
        # ("fragment"/"query"); `dom_location` uses the DOM API property name
        # the generated <script> actually reads (`location.hash`/
        # `location.search`) -- two vocabularies for the same concept, mapped
        # explicitly here rather than asserted equal.
        assert {"fragment": "hash", "query": "query"}[case.location] == profile["dom_location"], cell_id


def test_each_canonical_cells_derived_verdict_matches_the_label(manifest, cases, matrix) -> None:
    """§4.3.6.6 point 2's load-bearing criterion, for the shape this lane
    adds: `verdict()` returns the label `labels.json` already carries. Both
    PFF-0007/PFF-0008 are true positives (`expected_vulnerable: true`)."""
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert derived.verdict == ("VULNERABLE" if case.expected_vulnerable else "SECURE"), cell_id
        assert case.expected_vulnerable is True, cell_id


def test_the_authored_secure_twins_derive_secure(manifest, matrix) -> None:
    """Neither PFF- case has a secure counterpart in labels.json (like G1's
    numeric twins) -- both `-SAFE` cells are this lane's own authored twin,
    using the new `dom_text_content` op."""
    for cell_id in ("LABGEN-PLRP-DOM-0001-SAFE", "LABGEN-PLRP-DOM-0002-SAFE"):
        cell = _cell(manifest, cell_id)
        assert cell.transform.ops == ("dom_text_content",), cell_id
        assert verdict(cell.transform, cell.sink_context, matrix).verdict == "SECURE", cell_id


def test_every_real_page_profile_declares_itself_as_such(manifest) -> None:
    for path in ("/reviews.php", "/feedback.php"):
        profile = _PAGE_PROFILES[path]
        assert profile[_REAL_PAGE_KEY] is True
        assert profile[_CANONICAL_CELL_KEY] in CELL_TO_CASE


def test_ground_truth_case_ids_never_leak_into_a_generated_file(manifest, emitter) -> None:
    """FR-LAB-2: an emitted artifact must not disclose the out-of-band
    `PFF-` case id it reproduces."""
    for cell in manifest.cells:
        for content in _rendered(emitter, cell).values():
            for case_id in CELL_TO_CASE.values():
                assert case_id not in content, (cell.cell_id, case_id)


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        status = static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)
        # A PHP taint checker has nothing to analyze here at all (see
        # static_precheck.py's own comment) -- UNINFORMATIVE, more sharply
        # than every other XSS shape.
        assert status is static_precheck.StaticPrecheckStatus.UNINFORMATIVE


# ---------------------------------------------------------------------------
# The genuinely new property: the value never reaches the server
# ---------------------------------------------------------------------------


def test_the_tainted_value_never_appears_in_the_generated_controller(emitter, manifest) -> None:
    """The defining property of this shape (VULNERABILITIES.md: "the server
    never uses `ref`" / the fragment "never reaches the server"): the
    controller has no `$request->query(...)`/`$request->input(...)` read of
    the tainted parameter at all -- only the Blade view's `<script>` block
    does, client-side."""
    for cell in manifest.cells:
        rendered = _rendered(emitter, cell)
        profile = _PAGE_PROFILES[_cell(manifest, cell.cell_id).route.path]
        param = profile["dom_param_name"]
        assert f"query('{param}')" not in rendered["controller"], cell.cell_id
        assert f"input('{param}')" not in rendered["controller"], cell.cell_id
        assert "DB::" not in rendered["controller"], cell.cell_id


def test_the_vulnerable_view_reads_the_right_location_and_writes_innerhtml(manifest, emitter) -> None:
    reviews = _rendered(emitter, _cell(manifest, "LABGEN-PLRP-DOM-0001"))["view"]
    assert "location.hash" in reviews
    assert "author=([^&]*)" in reviews
    assert ".innerHTML =" in reviews
    assert ".textContent =" not in reviews

    feedback = _rendered(emitter, _cell(manifest, "LABGEN-PLRP-DOM-0002"))["view"]
    assert "location.search" in feedback
    assert "URLSearchParams(location.search).get('ref')" in feedback
    assert ".innerHTML =" in feedback
    assert ".textContent =" not in feedback


def test_the_secure_twin_view_writes_textcontent_not_innerhtml(manifest, emitter) -> None:
    for cell_id in ("LABGEN-PLRP-DOM-0001-SAFE", "LABGEN-PLRP-DOM-0002-SAFE"):
        rendered = _rendered(emitter, _cell(manifest, cell_id))["view"]
        assert ".textContent =" in rendered, cell_id
        assert ".innerHTML =" not in rendered, cell_id


# ---------------------------------------------------------------------------
# §4.3.6.6a: the routes keep the real app's `.php` URL
# ---------------------------------------------------------------------------


def test_served_url_for_matches_what_route_fragment_for_registers(emitter, manifest) -> None:
    for cell in manifest.cells:
        fragment = emitter.route_fragment_for(cell)
        assert f"'{served_url_for(cell)}'" in fragment, cell.cell_id


def test_the_canonical_cells_get_the_real_url_and_twins_get_a_distinct_one(emitter, manifest) -> None:
    reviews_url = served_url_for(_cell(manifest, "LABGEN-PLRP-DOM-0001"))
    reviews_twin_url = served_url_for(_cell(manifest, "LABGEN-PLRP-DOM-0001-SAFE"))
    assert reviews_url == "/reviews.php"
    assert reviews_twin_url == "/reviews.labgen-plrp-dom-0001-safe.php"

    feedback_url = served_url_for(_cell(manifest, "LABGEN-PLRP-DOM-0002"))
    feedback_twin_url = served_url_for(_cell(manifest, "LABGEN-PLRP-DOM-0002-SAFE"))
    assert feedback_url == "/feedback.php"
    assert feedback_twin_url == "/feedback.labgen-plrp-dom-0002-safe.php"

    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    assert content.count("'/reviews.php'") == 1
    assert content.count("'/feedback.php'") == 1


def test_the_regression_gate_accepts_the_real_urls_and_rejects_idiomatic_ones(emitter, manifest, cases) -> None:
    baseline = contract.GroundTruth(
        target="puppy-fort-factory",
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


# ---------------------------------------------------------------------------
# Conformance: minimal pair, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_tier3_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, list(manifest.cells))  # must not raise


@pytest.mark.skipif(
    __import__("shutil").which("php") is None,
    reason="php CLI not available on this build host (PA-0005 pattern)",
)
def test_tier0_lint_passes_for_every_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_cli_check_passes_end_to_end(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert (
        labgen_cli.main(
            ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
        )
        == 0
    )
