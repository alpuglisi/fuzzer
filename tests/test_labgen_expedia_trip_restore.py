"""Unit coverage for Expedia's second own cell (`CC-LAB-0220`) -- the
trip-restore insecure-deserialization shape at `/api/trips/restore`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spel_injection.py`'s own shape for its stack.
"""

from __future__ import annotations

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/expedia_trip_restore_sample.yaml"
_GROUND_TRUTH_DIR = "lab/ground-truth-expedia-clone"

_EXPECTED_VERDICTS = {
    "LABGEN-EXP-0003": "VULNERABLE",  # jackson_default_typing_deserialize
    "LABGEN-EXP-0004": "SECURE",  # jackson_typed_allowlist_deserialize
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


def test_the_verdict_agrees_with_this_apps_own_ground_truth() -> None:
    gt = labels_contract.load(_GROUND_TRUTH_DIR)
    case = gt.case_by_id("EXPD-0002")
    assert case is not None
    cells = _cells()
    vulnerable = cells["LABGEN-EXP-0003"]
    assert case.expected_vulnerable is True
    assert case.url == vulnerable.route.path
    assert case.param == "body"
    matrix = load_safety_matrix()
    result = verdict(vulnerable.transform, vulnerable.sink_context, matrix)
    assert result.verdict == "VULNERABLE"


def test_trip_restore_and_other_expedia_controllers_have_disjoint_class_names() -> None:
    emitter = SpringBootEmitter()
    trip_restore_manifest = load_manifest(_MANIFEST_PATH)
    spel_manifest = load_manifest("lab/manifests/expedia_spel_injection_sample.yaml")
    trip_restore_paths = {emitter.render(c)[0].path for c in trip_restore_manifest.cells}
    spel_paths = {emitter.render(c)[0].path for c in spel_manifest.cells}
    assert trip_restore_paths.isdisjoint(spel_paths)
