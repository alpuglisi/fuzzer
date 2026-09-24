"""Unit coverage for the `spring_boot` emitter's first `weak_token_entropy`
cell (`CC-LAB-0195`, `FR-LAB-150`): Netflix's tenth real page, a
session/token-refresh endpoint at `POST /api/session/refresh`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_netflix_thumbnail_ssrf.py`'s own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/weak_token_entropy_netflix_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0019": "VULNERABLE",  # predictable_token_source: System.nanoTime()
    "LABGEN-JV-0020": "SECURE",      # csprng_token: java.security.SecureRandom
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


def test_module_composition_uses_the_new_no_op_source() -> None:
    """Zero tainted request material: this shape's source
    (`NoOpTokenRequestSource`) renders no code at all -- the vulnerability
    is entirely in how the sink generates its own output."""
    emitter = SpringBootEmitter()
    cells = _cells()
    vuln_src = emitter.render(cells["LABGEN-JV-0019"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0020"])[0].content.decode("utf-8")

    assert "Module composition: no_op_token_request -> predictable_token_source -> single_handler" in vuln_src
    assert (
        "Module composition: no_op_token_request -> csprng_token -> single_handler"
        in secure_src
    )
    assert "PostMapping" in vuln_src and "PostMapping" in secure_src
    # No request-derived material is ever read for this shape.
    assert "request.getParameter" not in vuln_src
    assert "request.getParameter" not in secure_src


def test_vulnerable_twin_uses_nanotime_secure_twin_uses_securerandom() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vuln_src = emitter.render(cells["LABGEN-JV-0019"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0020"])[0].content.decode("utf-8")

    assert "System.nanoTime()" in vuln_src
    assert "SecureRandom" not in vuln_src

    assert "java.security.SecureRandom" in secure_src
    assert "System.nanoTime()" not in secure_src
    assert "new byte[32]" in secure_src


def test_both_twins_respond_with_the_same_session_token_json_shape() -> None:
    """The response shape `PredictableTokenSourceStrategy`'s own
    `confirm()` (`fuzzlab.oracle.strategies`, already built for Twitch's
    `go_net_http` cell) needs to generalize with zero new code: a JSON
    body with a literal `session_token` field."""
    emitter = SpringBootEmitter()
    for cell_id in ("LABGEN-JV-0019", "LABGEN-JV-0020"):
        src = emitter.render(_cells()[cell_id])[0].content.decode("utf-8")
        assert '"{\\"session_token\\":\\"" + sessionToken + "\\"}"' in src
        assert '"Content-Type", "application/json"' in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's tenth cell must not collide with any of its other nine
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
        "lab/manifests/mass_assignment_netflix_settings_sample.yaml",
        "lab/manifests/jwt_alg_confusion_netflix_sample.yaml",
        "lab/manifests/ssrf_netflix_thumbnail_sample.yaml",
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 22
