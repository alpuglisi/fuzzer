"""Unit coverage for the `spring_boot` emitter's first `mass_assignment`
cell (`CC-LAB-0192`, `FR-LAB-132`): Netflix's seventh real page, an
account-settings-update endpoint at `POST /api/account/settings`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_account_billing.py`'s own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/mass_assignment_netflix_settings_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0013": "VULNERABLE",  # unfiltered_object_assign: is_partner reaches the record
    "LABGEN-JV-0014": "SECURE",  # typed_schema_allowlist: is_partner never read from the body
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


def test_vulnerable_twin_assigns_is_partner_secure_twin_never_reads_it() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0013"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0014"])[0].content.decode("utf-8")

    # Both parse the whole raw body via the shared raw_body source...
    assert "request.getInputStream().readAllBytes()" in vulnerable_src
    assert "request.getInputStream().readAllBytes()" in secure_src
    # ...but only the vulnerable twin ever reads is_partner out of it.
    assert 'accountRoot.path("is_partner")' in vulnerable_src
    assert 'accountRoot.path("is_partner")' not in secure_src
    assert "PostMapping" in vulnerable_src and "PostMapping" in secure_src


def test_whole_body_is_read_not_a_single_named_field() -> None:
    """This shape's own point (`CC-LAB-0182`'s own design, ported): the
    ENTIRE JSON body reaches the sink, not one named field -- unlike every
    other spring_boot shape's own source."""
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0013"])[0].content.decode("utf-8")
    assert "request.getParameter(" not in src


def test_response_body_matches_the_mass_assignment_strategys_hardcoded_shape() -> None:
    """The response shape `MassAssignmentPrivilegedFieldStrategy`
    (`fuzzlab.oracle.strategies`, built for Twitch's `go_net_http` cell)
    needs to generalize with zero new code: a 200, JSON body echoing
    `display_name`/`bio`/`is_partner` as literal top-level keys."""
    emitter = SpringBootEmitter()
    for cell_id in ("LABGEN-JV-0013", "LABGEN-JV-0014"):
        src = emitter.render(_cells()[cell_id])[0].content.decode("utf-8")
        assert '\\"display_name\\":\\"' in src
        assert '\\"bio\\":\\"' in src
        assert '\\"is_partner\\":' in src
        assert "application/json" in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's seventh cell must not collide with any of its other six
    real pages' generated class names/paths."""
    emitter = SpringBootEmitter()
    all_paths: set[str] = set()
    for manifest_path in (
        "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
        "lab/manifests/xxe_netflix_sample.yaml",
        "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml",
        "lab/manifests/access_control_netflix_billing_sample.yaml",
        "lab/manifests/price_integrity_netflix_subscription_sample.yaml",
        "lab/manifests/unrestricted_file_upload_netflix_avatar_sample.yaml",
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 16
