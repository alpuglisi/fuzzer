"""Unit coverage for the `spring_boot` emitter's first `access_control`/IDOR
cell (`CC-LAB-0187`, `FR-LAB-142`): Netflix's fourth real page, an
account-billing-details lookup at `GET /api/account/billing`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_deserialization.py`'s own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/access_control_netflix_billing_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0007": "VULNERABLE",  # no_ownership_check: ignores X-Account-Id entirely
    "LABGEN-JV-0008": "SECURE",  # identity_match_before_fetch: requires account_id == X-Account-Id
}


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def test_manifest_loads_and_validates() -> None:
    assert set(_cells()) == set(_EXPECTED_VERDICTS)


def test_verdict_matches_expected() -> None:
    matrix = load_safety_matrix()
    for cell_id, cell in _cells().items():
        result = verdict(cell.transform, cell.sink_context, matrix)
        assert result.verdict == _EXPECTED_VERDICTS[cell_id], cell_id


def test_spring_boot_supports_every_sample_cell() -> None:
    emitter = SpringBootEmitter()
    for cell in _cells().values():
        assert emitter.supports(cell.vuln_class, cell.sink_context) is True


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = SpringBootEmitter()
    for cell in _cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_vulnerable_twin_ignores_caller_header_secure_twin_checks_it() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0007"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0008"])[0].content.decode("utf-8")

    # Both read the caller-identity header (the source is shared)...
    assert 'request.getHeader("X-Account-Id")' in vulnerable_src
    assert 'request.getHeader("X-Account-Id")' in secure_src
    # ...but only the secure twin actually compares it before returning data.
    assert "accountId.equals(callerAccountId)" not in vulnerable_src
    assert "accountId.equals(callerAccountId)" in secure_src
    assert "GetMapping" in vulnerable_src and "GetMapping" in secure_src
    assert "403" in secure_src and "403" not in vulnerable_src


def test_account_id_query_param_is_read_not_a_form_field() -> None:
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0007"])[0].content.decode("utf-8")
    assert 'request.getParameter("account_id")' in src


def test_response_body_is_json_and_echoes_the_requested_account_id() -> None:
    """The response shape `AccessControlIdorStrategy` (`fuzzlab.oracle.
    strategies`) needs: a 200, a non-empty body that echoes the requested id
    literally (never assumed -- checked directly against the rendered
    template)."""
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0007"])[0].content.decode("utf-8")
    assert '\\"account_id\\":\\"" + accountId +' in src
    assert "payment_method" in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's fourth cell must not collide with any of its other three
    real pages' generated class names/paths."""
    emitter = SpringBootEmitter()
    all_paths = set()
    for manifest_path in (
        "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
        "lab/manifests/xxe_netflix_sample.yaml",
        "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml",
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 10
