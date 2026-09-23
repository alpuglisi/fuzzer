"""Unit coverage for the `spring_boot` emitter's first
`unrestricted_file_upload` cell (`CC-LAB-0191`, `FR-LAB-131`): Netflix's
sixth real page, a per-profile avatar-image upload endpoint at
`POST /api/profiles/avatar`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_subscription_price_integrity.py`'s own
shape. The real, executed live-boot proof (both twins' HTTP behavior, and
the oracle-strategy generalization proof) lives in
`tests/test_labgen_spring_boot_netflix_avatar_upload_live_boot.py`.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/unrestricted_file_upload_netflix_avatar_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0011": "VULNERABLE",  # no_extension_check: extension-derived Content-Type
    "LABGEN-JV-0012": "SECURE",  # extension_allowlist_mime_check: allowlist + magic-byte sniff
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


def test_vulnerable_twin_derives_content_type_from_extension_secure_twin_sniffs_bytes() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0011"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0012"])[0].content.decode("utf-8")

    # Both parse the same three identifiers off the raw multipart Part...
    assert 'request.getPart("file")' in vulnerable_src
    assert 'request.getPart("file")' in secure_src
    # ...but only the vulnerable twin derives the served type from the
    # caller-supplied filename's extension via MediaTypeFactory, and writes
    # under the caller's own filename verbatim.
    assert "MediaTypeFactory" in vulnerable_src
    assert "MediaTypeFactory" not in secure_src
    assert "avatarUploadDir.resolve(uploadFilename)" in vulnerable_src
    assert "avatarUploadDir.resolve(uploadFilename)" not in secure_src
    # ...and only the secure twin allowlists the extension, sniffs the real
    # magic bytes, and writes under a fully server-chosen filename.
    assert "allowedExtension" in secure_src
    assert "allowedExtension" not in vulnerable_src
    assert '0x89' in secure_src and '0x47' in secure_src  # PNG magic-byte check
    assert 'avatarUploadDir.resolve("avatar" + serverChosenExt)' in secure_src
    assert "PostMapping" in vulnerable_src and "PostMapping" in secure_src
    # Both twins return ResponseEntity<byte[]>, not <String> -- the byte-
    # correctness this shape's own served-file-echo needs.
    assert "ResponseEntity<byte[]>" in vulnerable_src
    assert "ResponseEntity<byte[]>" in secure_src


def test_secure_twin_extension_allowlist_is_narrower_than_go_net_http_but_stated() -> None:
    """This entry's own deliberate, documented scoping: only the two
    formats this stack's minimal magic-byte sniff can actually recognize
    (.png/.jpg/.jpeg) are allowlisted -- .gif/.webp (which go_net_http's
    own secure twin does allowlist) are deliberately absent here, not
    silently forgotten."""
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0012"])[0].content.decode("utf-8")
    assert ".png" in src and ".jpg" in src and ".jpeg" in src
    assert ".gif" not in src
    assert ".webp" not in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's sixth cell must not collide with any of its other five
    real pages' generated class names/paths."""
    emitter = SpringBootEmitter()
    all_paths = set()
    for manifest_path in (
        "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
        "lab/manifests/xxe_netflix_sample.yaml",
        "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml",
        "lab/manifests/access_control_netflix_billing_sample.yaml",
        "lab/manifests/price_integrity_netflix_subscription_sample.yaml",
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 14
