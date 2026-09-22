"""Lane L-P3.3c-G4: the stored second-order pair -- `edit_profile.php`
(write) -> `profile.php` (read/sink), reproducing the stored-XSS `bio` field
(`PFF-0005` vulnerable / `PFF-1007` secure), `docs/LAB_IMPLEMENTATION_PLAN.md`
§4.3.6 group G4. The first `stored_second_order` cells this emitter renders
(`SUPPORTED_CONTEXT_DEPTHS`) and the first **write** endpoint any emitter in
this project emits (`fuzzlab.labgen.emitters.php_laravel.modules.WRITES`).

Rewritten during the L-P3.3c consolidation pass: this lane's own
`_REAL_URL_ROUTES` hand-authored registry (mapping a real URL to the one
cell/method/role that serves it) is superseded by the unified
`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` page-profile mechanism, applied
*twice* per `stored_second_order` cell -- once for its read page
(`/profile.php`) and once for its write page (`/edit_profile.php`), each with
its own canonical cell. The non-owning cell of each page now gets the same
`.php`-suffixed twin-URL convention every other lane's twin gets, rather than
falling back to the plain cell-ID-derived `/cell/<slug>` this lane originally
used for it."""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen import identity as identity_module
from fuzzlab.labgen import verdict as verdict_module
from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    SUPPORTED_CONTEXT_DEPTHS,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.schema import CONTEXT_DEPTHS, Pipeline, load_manifest

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_g4.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth"

READ_PATH = "/profile.php"
WRITE_PATH = "/edit_profile.php"
CELL_TO_CASE = {"LABGEN-PLRP-0401": "PFF-0005", "LABGEN-PLRP-0402": "PFF-1007"}


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture(scope="module")
def cases() -> dict[str, labels_contract.Case]:
    return {c.case_id: c for c in labels_contract.load_labels(GROUND_TRUTH_DIR)}


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str):
    return next(c for c in manifest.cells if c.cell_id == cell_id)


def test_stored_second_order_is_supported(manifest) -> None:
    assert "stored_second_order" in SUPPORTED_CONTEXT_DEPTHS
    assert set(CONTEXT_DEPTHS) - set(SUPPORTED_CONTEXT_DEPTHS) == {"same_file_helper", "cross_file"}
    for cell in manifest.cells:
        assert cell.context_depth == "stored_second_order"
        assert cell.sink_endpoint is not None
        assert cell.sink_endpoint.path == READ_PATH
        assert cell.route.path == WRITE_PATH


def test_each_cell_reproduces_its_labelled_pff_case(manifest, cases) -> None:
    matrix = verdict_module.load_safety_matrix()
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        derived = verdict_module.verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict == "VULNERABLE") == case.expected_vulnerable, cell_id


def test_render_produces_three_files_read_view_and_write(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)
        roles = {f.role for f in files}
        assert roles == {"controller", "view", "write_controller"}


def test_the_write_controller_persists_the_field_verbatim_no_sqli(emitter, manifest) -> None:
    for cell in manifest.cells:
        (w,) = [f for f in emitter.render(cell) if f.role == "write_controller"]
        content = w.content.decode("utf-8")
        assert "->bio = $request->input('bio');" in content
        assert "->save();" in content
        assert "DB::" not in content and "whereRaw" not in content


def test_the_write_controllers_are_identical_between_twins(emitter, manifest) -> None:
    vulnerable = _cell(manifest, "LABGEN-PLRP-0401")
    secure = _cell(manifest, "LABGEN-PLRP-0402")

    def write_body(cell) -> str:
        files = emitter.render(cell)
        (w,) = [f for f in files if f.role == "write_controller"]
        return "\n".join(
            line
            for line in w.content.decode("utf-8").splitlines()
            if "labgen-plrp-04" not in line.lower()
            and "Labgen" not in line
            and "redirect(" not in line
            and not line.startswith("// Module composition:")
        )

    assert write_body(vulnerable) == write_body(secure)


def test_tier0_minimal_pair_holds_against_the_shared_checker(emitter, manifest) -> None:
    """The real (PHP-oriented) shared checker, over all three emitted files --
    including the write controller, which is why it carries the same
    `// Module composition:` provenance line the other two do."""
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


# --- routes: each cell's OWN read + write URL, canonical or twin -----------


def test_each_cell_registers_a_read_route_and_a_write_route(emitter, manifest) -> None:
    """Every cell answers both its read page and its write page -- the
    canonical cell of each page at the page's real URL, the other cell at a
    distinct, still-`.php`-suffixed twin URL (the unified mechanism, applied
    independently to `/profile.php` and `/edit_profile.php`)."""
    vulnerable = _cell(manifest, "LABGEN-PLRP-0401")
    secure = _cell(manifest, "LABGEN-PLRP-0402")

    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")

    # LABGEN-PLRP-0401 is /profile.php's canonical cell (PFF-0005 is labelled
    # there) and gets a twin write URL for /edit_profile.php.
    assert f"Route::get('{READ_PATH}'," in content
    assert "Route::post('/edit_profile.labgen-plrp-0401.php'," in content
    # LABGEN-PLRP-0402 is /edit_profile.php's canonical cell (PFF-1007) and
    # gets a twin read URL for /profile.php.
    assert f"Route::post('{WRITE_PATH}'," in content
    assert "Route::get('/profile.labgen-plrp-0402.php'," in content

    # Exactly one registration per real URL.
    assert content.count(f"'{READ_PATH}'") == 1
    assert content.count(f"'{WRITE_PATH}'") == 1

    for cell in (vulnerable, secure):
        assert f"'{served_url_for(cell)}'" in fragments[cell.cell_id]


def test_the_real_url_owners_match_the_labelled_case_pages(emitter, manifest, cases) -> None:
    """Which cell answers at which real URL is not arbitrary: the cell
    serving `PFF-0005`'s page must be the one whose verdict is vulnerable,
    and the cell serving `PFF-1007`'s page the secure one."""
    matrix = verdict_module.load_safety_matrix()
    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    for cell in manifest.cells:
        case = cases[CELL_TO_CASE[cell.cell_id]]
        derived = verdict_module.verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict == "VULNERABLE") == case.expected_vulnerable
        assert f"'{case.url}'" in fragments[cell.cell_id], (
            f"{cell.cell_id} reproduces {case.case_id}, whose labelled page is "
            f"{case.url} -- it must be the cell registered at that real URL"
        )


def test_route_registration_refuses_an_unknown_http_verb() -> None:
    """A verb with no `Route::` form must fail loud rather than degrade to a
    silent GET, which would relocate a reproduced page's method."""
    from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator

    with pytest.raises(ValueError, match="no Laravel Route helper"):
        RouteAccumulator().fragment_for_cell(
            cell_id="X", controller_class="XController", url_path="/x", method="TRACE"
        )


def test_identities_yaml_declares_the_owning_resource_for_the_stored_bio() -> None:
    graph = identity_module.load_identities("lab/identities/identities.yaml")
    resource = next(r for r in graph.resources if r.resource_id == "profile_bio_user_a")
    assert resource.owner == "user_a"
    assert set(resource.cell_ids) == set(CELL_TO_CASE)


def test_tier3_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, list(manifest.cells))  # must not raise


def test_cli_check_passes_end_to_end(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0
