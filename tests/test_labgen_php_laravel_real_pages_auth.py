"""Lane L-P3.3c-G3: the real auth pages -- `login.php` (`PFF-0004` vulnerable
/ `PFF-1008` true-negative password condition, plus an authored secure twin)
and `register.php` (`PFF-1004`, secure-only) -- reproduced as `php_laravel`
cells, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G3.

This is the lane whose design the L-P3.3c consolidation pass generalized:
`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`, the canonical-cell-per-page model, the
``.php``-suffixed twin-URL convention, and the HTTP-method-aware
`route_accumulator.fragment_for_cell` are this lane's own contribution,
unchanged in the unified mechanism (only the earlier, now-removed
`_url_path_for_cell`/`_route_method_for_cell` private names were folded into
the shared `served_url_for`). `auth_session.py` (the build-time login
adapter over `fuzzlab.labgen.identity_session`) is unchanged.
"""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labels import contract
from fuzzlab.labels.contract import Case, GroundTruth
from fuzzlab.labgen import minimal_pair
from fuzzlab.labgen import regression_gate
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _CANONICAL_CELL_KEY,
    _PAGE_PROFILES,
    _REAL_PAGE_KEY,
    LaravelEmitter,
    served_url_for,
)
from fuzzlab.labgen.emitters.php_laravel import auth_session
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.identity import Identity
from fuzzlab.labgen.identity_session import IdentitySessionStore
from fuzzlab.labgen.schema import Cell, Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_real_pages_auth.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth"

CELL_TO_CASE = {
    "LABGEN-PLA-0001": "PFF-0004",
    "LABGEN-PLA-0003": "PFF-1004",
}


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture(scope="module")
def cases() -> dict[str, Case]:
    return {c.case_id: c for c in contract.load_labels(GROUND_TRUTH_DIR)}


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


def test_the_manifest_covers_the_login_pair_plus_register(manifest) -> None:
    assert {c.cell_id for c in manifest.cells} == {"LABGEN-PLA-0001", "LABGEN-PLA-0002", "LABGEN-PLA-0003"}


def test_the_canonical_cells_reproduce_their_pff_cases(manifest, cases) -> None:
    for cell_id, case_id in CELL_TO_CASE.items():
        cell = _cell(manifest, cell_id)
        case = cases[case_id]
        assert cell.route.path == case.url
        assert cell.route.method == case.method
        derived_ok = (verdict(cell.transform, cell.sink_context, load_safety_matrix()).verdict == "VULNERABLE") == (
            case.expected_vulnerable
        )
        assert derived_ok, cell_id


def test_login_php_owns_its_url_because_the_vulnerable_case_is_labelled_there(manifest) -> None:
    profile = _PAGE_PROFILES["/login.php"]
    assert profile[_REAL_PAGE_KEY] is True
    assert profile[_CANONICAL_CELL_KEY] == "LABGEN-PLA-0001"
    vulnerable = _cell(manifest, "LABGEN-PLA-0001")
    secure_twin = _cell(manifest, "LABGEN-PLA-0002")
    assert served_url_for(vulnerable) == "/login.php"
    # The twin gets a distinct, still-`.php`-suffixed URL, never the real one
    # and never the plain illustrative `/cell/<slug>`.
    twin_url = served_url_for(secure_twin)
    assert twin_url == "/login.labgen-pla-0002.php"
    assert twin_url != "/login.php"


def test_the_login_twins_each_pass_minimal_pair_against_their_own_weakened_self(emitter, manifest) -> None:
    """`fuzzlab.labgen.minimal_pair` pairs strictly by file path, so it cannot
    directly compare two distinct, named cells (`LABGEN-PLA-0001` vs.
    `LABGEN-PLA-0002`) -- only a cell against its own weakened/emptied self,
    the same convention every other cell in this manifest is checked with
    (see `test_minimal_pair_holds_against_each_cells_weakened_twin` below).
    This lane's genuine finding -- that the two authored cells' declared
    difference must sit only in the transform region -- is what the shared
    checker verifies for each of them individually."""
    checker = tier0.get_minimal_pair_checker()
    for cell_id in ("LABGEN-PLA-0001", "LABGEN-PLA-0002"):
        cell = _cell(manifest, cell_id)
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_the_login_controller_establishes_a_session_and_redirects(emitter, manifest) -> None:
    cell = _cell(manifest, "LABGEN-PLA-0001")
    controller = next(f for f in emitter.render(cell) if f.role == "controller").content.decode("utf-8")
    assert "session()->put('user_id'" in controller
    assert "session()->put('username'" in controller
    assert "redirect('/profile.php')" in controller
    assert "Invalid username or password." in controller


def test_the_register_controller_inserts_after_the_duplicate_check(emitter, manifest) -> None:
    cell = _cell(manifest, "LABGEN-PLA-0003")
    controller = next(f for f in emitter.render(cell) if f.role == "controller").content.decode("utf-8")
    assert "DB::table('users')->insert(" in controller
    assert "That username is already taken." in controller
    assert "md5($request->input('password'))" in controller


def test_the_routes_file_registers_both_real_urls_and_the_twin(emitter, manifest) -> None:
    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    assert "Route::post('/login.php'," in content
    assert "Route::post('/login.labgen-pla-0002.php'," in content
    assert "Route::post('/register.php'," in content
    assert content.count("'/login.php'") == 1


def test_auth_session_adapter_posts_to_the_real_login_url(manifest) -> None:
    cell = _cell(manifest, "LABGEN-PLA-0001")
    assert auth_session.is_login_cell(cell)
    assert auth_session.login_url_for(cell) == "/login.php"
    fields = auth_session.login_fields_for(cell, username="user_a", password="secret")
    assert fields == {"username": "user_a", "password": "secret"}

    posted = []

    def fake_poster(url, form_fields):
        posted.append((url, dict(form_fields)))
        return {"Set-Cookie": "laravel_session=abc123; Path=/"}

    identities = [Identity(id="user_a", role="user")]
    store = auth_session.session_store_for(
        cell, identities, poster=fake_poster, password_for=lambda identity_id: "secret"
    )
    assert isinstance(store, IdentitySessionStore)
    refresh = auth_session.refresh_session_for_cell(
        cell, identities, "user_a", poster=fake_poster, password_for=lambda identity_id: "secret"
    )
    refresh()  # must not raise
    assert posted == [("/login.php", {"username": "user_a", "password": "secret"})]


def test_auth_session_refuses_a_non_login_cell(manifest) -> None:
    register_cell = _cell(manifest, "LABGEN-PLA-0003")
    assert not auth_session.is_login_cell(register_cell)
    with pytest.raises(auth_session.AuthSessionError):
        auth_session.login_url_for(register_cell)


def test_the_regression_gate_accepts_the_real_urls_and_rejects_idiomatic_ones(manifest, cases) -> None:
    baseline = GroundTruth(target="php_laravel", cases=[cases[cid] for cid in sorted(CELL_TO_CASE.values())])

    def candidate_for(url_of: dict[str, str]) -> GroundTruth:
        return GroundTruth(
            target="generated-lab",
            cases=[dataclasses.replace(cases[case_id], url=url_of[cid]) for cid, case_id in CELL_TO_CASE.items()],
        )

    served = {cid: served_url_for(_cell(manifest, cid)) for cid in CELL_TO_CASE}
    assert regression_gate.assert_no_regression(baseline, candidate_for(served)).is_clean

    idiomatic = {cid: url.removesuffix(".php") for cid, url in served.items()}
    with pytest.raises(regression_gate.RegressionGateError, match="page changed"):
        regression_gate.assert_no_regression(baseline, candidate_for(idiomatic))


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_minimal_pair_holds_against_each_cells_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        rendered_weak = emitter.render(weakened)
        rendered_full = emitter.render(cell)
        if rendered_weak == rendered_full:
            continue
        checker(rendered_weak, rendered_full)  # must not raise


def test_tier3_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, list(manifest.cells))  # must not raise


def test_cli_check_passes_end_to_end(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0
