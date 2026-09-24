"""Unit coverage for the `spring_boot` emitter's first `jwt_algorithm_
confusion` cell (`CC-LAB-0193`, `FR-LAB-148`): Netflix's eighth real page,
an account-level viewing-preferences lookup at `GET /api/account/
preferences`, gated by a Bearer JWT in the `Authorization` header.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_netflix_settings_mass_assignment.py`'s own
shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/jwt_alg_confusion_netflix_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0015": "VULNERABLE",  # jwt_alg_none_default: alg:none honored
    "LABGEN-JV-0016": "SECURE",  # jwt_none_alg_opt_in: HS256 + valid HMAC required
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


def test_vulnerable_twin_honors_alg_none_secure_twin_requires_hs256_and_hmac() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0015"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0016"])[0].content.decode("utf-8")

    # Both hand-parse the token off the Authorization header via the shared
    # source, JDK stdlib only -- no third-party JWT dependency.
    assert 'request.getHeader("Authorization")' in vulnerable_src
    assert 'request.getHeader("Authorization")' in secure_src
    assert "javax.crypto.Mac" in vulnerable_src and "javax.crypto.Mac" in secure_src
    assert "java.security.MessageDigest.isEqual" in vulnerable_src
    assert "java.security.MessageDigest.isEqual" in secure_src

    # ...but only the vulnerable twin's accepted-condition can be satisfied
    # by alg:none alone (jwtAlgIsNone || jwtHmacValid); the secure twin
    # requires jwtAlgIsHs256 && jwtHmacValid.
    assert "jwtAlgIsNone || jwtHmacValid" in vulnerable_src
    assert "jwtAlgIsHs256 && jwtHmacValid" in secure_src
    assert "jwtAlgIsNone || jwtHmacValid" not in secure_src
    assert "jwtAlgIsHs256 && jwtHmacValid" not in vulnerable_src
    assert "GetMapping" in vulnerable_src and "GetMapping" in secure_src


def test_no_third_party_jwt_dependency() -> None:
    """`CC-LAB-0180`'s own design constraint, ported: a hand-rolled parser
    using only JDK stdlib primitives, never a real JWT library."""
    emitter = SpringBootEmitter()
    for cell_id in ("LABGEN-JV-0015", "LABGEN-JV-0016"):
        src = emitter.render(_cells()[cell_id])[0].content.decode("utf-8")
        assert "io.jsonwebtoken" not in src
        assert "com.auth0" not in src
        assert "nimbusds" not in src


def test_response_body_echoes_claims_matching_the_jwt_strategys_hardcoded_shape() -> None:
    """The response shape `JwtAlgNoneConfusionStrategy`
    (`fuzzlab.oracle.strategies`, built for Twitch's `go_net_http` cell)
    needs to generalize with zero new code: a 200, JSON body echoing
    `channel_id`/`role` as literal top-level keys forged from the token's
    own claims."""
    emitter = SpringBootEmitter()
    for cell_id in ("LABGEN-JV-0015", "LABGEN-JV-0016"):
        src = emitter.render(_cells()[cell_id])[0].content.decode("utf-8")
        assert '\\"channel_id\\":\\"' in src
        assert '\\"role\\":\\"' in src
        assert "application/json" in src
        assert "401" in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's eighth cell must not collide with any of its other seven
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
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 18
