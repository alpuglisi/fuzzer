"""Unit coverage for the `spring_boot` emitter's XXE cell (`CC-LAB-0131`,
TrackerNest's second cell).

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot.py`'s own shape for the SSTI cell.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/xxe_spring_boot_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-XXE-0001": "VULNERABLE",  # xml_external_entities_enabled: default-permissive parser
    "LABGEN-XXE-0002": "SECURE",  # xml_external_entities_disabled: disallow-doctype-decl set
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


def test_vulnerable_twin_has_no_doctype_guard_secure_twin_does() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-XXE-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-XXE-0002"])[0].content.decode("utf-8")
    assert "disallow-doctype-decl" not in vulnerable_src
    assert "disallow-doctype-decl" in secure_src
    assert "PostMapping" in vulnerable_src and "PostMapping" in secure_src


def test_xxe_and_ssti_controllers_have_disjoint_class_names() -> None:
    """Two different cells (different classes, `CC-LAB-0130`'s SSTI cell and
    this entry's XXE cell) must never collide on a generated file path/class
    name -- guaranteed by `_class_name_for()` deriving from each cell's own
    id, not a new naming decision (see `CC-LAB-0131`'s change-control
    entry)."""
    emitter = SpringBootEmitter()
    xxe_manifest = load_manifest(_MANIFEST_PATH)
    ssti_manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    xxe_paths = {emitter.render(c)[0].path for c in xxe_manifest.cells}
    ssti_paths = {emitter.render(c)[0].path for c in ssti_manifest.cells}
    assert xxe_paths.isdisjoint(ssti_paths)
