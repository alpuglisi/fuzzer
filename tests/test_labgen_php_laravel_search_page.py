"""Lane L-P3.3c-G6: `puppy-fort-factory/search.php` -- one `?q=` reaching
three sinks (a `LIKE '%q%'` SQL string literal, an HTML body reflection, and
a quoted attribute reflection) across six cells, `docs/LAB_IMPLEMENTATION_PLAN
.md` §4.3.6 group G6. Also the lane that added the
`(raw_concat, html_attribute_quoted)` safety-matrix row and the
`sink_override_by_family`/`html_attribute_quoted` module-set mechanism.

**Still open for L-P3.3c-CUT** (unchanged by the consolidation pass, which
preserves this lane's flag verbatim rather than resolving it): `search.php`
is deliberately left with no canonical cell -- see
`fuzzlab.labgen.emitters.php_laravel._CANONICAL_CELL_KEY`'s docstring. Every
cell here is served at its illustrative, cell-ID-derived URL, exactly as if
the page were not "real" for routing purposes; only `cell.route.path` (which
the regression gate diffs by `case_id`, not by what a route actually serves)
carries the real `/search.php` string.
"""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _MODULE_SET_BY_SHAPE,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.emitters.php_laravel.modules import SINKS
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.schema import Pipeline, SinkContext, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_search.yaml"


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def test_the_manifest_covers_all_six_search_php_cells(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == {
        "LABGEN-PL-RP-0001",
        "LABGEN-PL-RP-0002",
        "LABGEN-PL-RP-0003",
        "LABGEN-PL-RP-0004",
        "LABGEN-PL-RP-0005",
        "LABGEN-PL-RP-0006",
    }
    assert {c.route.path for c in manifest.cells} == {"/search.php"}


def test_search_php_is_deliberately_left_with_no_canonical_cell(manifest) -> None:
    """The flag this lane raised, preserved verbatim by the consolidation
    pass rather than resolved: `real_page` is set (it IS a real page), but
    `canonical_cell_id` is explicitly `None` -- still open for
    `L-P3.3c-CUT`."""
    profile = _PAGE_PROFILES["/search.php"]
    assert profile[_REAL_PAGE_KEY] is True
    assert _CANONICAL_CELL_KEY in profile
    assert profile[_CANONICAL_CELL_KEY] is None


def test_every_cell_therefore_keeps_its_illustrative_cell_id_derived_url(emitter, manifest) -> None:
    for cell in manifest.cells:
        url = served_url_for(cell)
        assert url == f"/cell/{cell.cell_id.lower()}"
        assert "'/search.php'" not in emitter.route_fragment_for(cell)


def test_the_routes_file_registers_six_distinct_cell_id_urls_no_collision(emitter, manifest) -> None:
    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    assert content.count("Route::get(") == 6
    for cell in manifest.cells:
        assert f"/cell/{cell.cell_id.lower()}" in content


def test_the_quoted_attribute_shape_is_registered_and_scores_correctly(matrix) -> None:
    assert ("xss", "html_attribute_quoted") in _MODULE_SET_BY_SHAPE
    assert "html_attribute_quoted_echo" in SINKS
    raw = verdict(Pipeline.from_list([]), SinkContext(family="html_attribute_quoted", required_neutralizations=("html_tag_break",)), matrix)
    escaped = verdict(
        Pipeline.from_list(["html_entity_escape"]),
        SinkContext(family="html_attribute_quoted", required_neutralizations=("html_tag_break",)),
        matrix,
    )
    assert raw.verdict == "VULNERABLE"
    assert escaped.verdict == "SECURE"


def test_the_sql_sink_is_the_like_rendering_not_the_login_style_equality(emitter, manifest) -> None:
    vulnerable = next(c for c in manifest.cells if c.cell_id == "LABGEN-PL-RP-0001")
    controller = next(f for f in emitter.render(vulnerable) if f.role == "controller").content.decode("utf-8")
    assert "LIKE '%" in controller
    assert "password" not in controller  # login.php's boilerplate must not leak in


def test_every_pair_derives_both_verdicts(manifest, matrix) -> None:
    by_family: dict[str, set[str]] = {}
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        by_family.setdefault(cell.sink_context.family, set()).add(derived.verdict)
    for family, verdicts in by_family.items():
        assert verdicts == {"VULNERABLE", "SECURE"}, family


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_minimal_pair_holds_against_each_cells_weakened_twin(emitter, manifest) -> None:
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
