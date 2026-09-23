"""Unit coverage for the `spring_boot` emitter's SpEL-injection cell
(`CC-LAB-0214`, category 5 pilot's first Expedia-specific cell, CWE-917).

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_xxe.py`'s own shape for its stack.
"""

from __future__ import annotations

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen.conformance.static_precheck import (
    StaticPrecheckStatus,
    static_precheck_status,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/expedia_spel_injection_sample.yaml"
_GROUND_TRUTH_DIR = "lab/ground-truth-expedia-clone"

_EXPECTED_VERDICTS = {
    "LABGEN-EXP-0001": "VULNERABLE",  # standard_evaluation_context_unrestricted
    "LABGEN-EXP-0002": "SECURE",  # simple_evaluation_context_restricted
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


def test_static_precheck_is_uninformative() -> None:
    """Both twins call the identical parse/evaluate sequence -- only the
    EvaluationContext object differs -- so a generic taint checker has no
    call-shape or missing-sanitizer tell to key on (`CC-LAB-0214`'s
    adequacy review)."""
    assert (
        static_precheck_status("spel_injection", "spel_expression_evaluate")
        == StaticPrecheckStatus.UNINFORMATIVE
    )


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


def test_vulnerable_twin_uses_standard_context_secure_twin_uses_simple_context() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-EXP-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-EXP-0002"])[0].content.decode("utf-8")
    assert "new org.springframework.expression.spel.support.StandardEvaluationContext()" in vulnerable_src
    assert "SimpleEvaluationContext" not in vulnerable_src
    assert "SimpleEvaluationContext" in secure_src
    assert "forReadOnlyDataBinding()" in secure_src
    assert "new org.springframework.expression.spel.support.StandardEvaluationContext()" not in secure_src
    assert "GetMapping" in vulnerable_src and "GetMapping" in secure_src


def test_the_verdict_agrees_with_this_apps_own_ground_truth() -> None:
    """The one ground-truth case this increment authors (`EXPD-0001`)
    names the vulnerable cell's real served route/param and
    `expected_vulnerable: true` -- cross-checked here against the real
    `verdict()` derivation, not just asserted independently of it."""
    gt = labels_contract.load(_GROUND_TRUTH_DIR)
    case = gt.case_by_id("EXPD-0001")
    assert case is not None
    cells = _cells()
    vulnerable = cells["LABGEN-EXP-0001"]
    assert case.expected_vulnerable is True
    assert case.url == vulnerable.route.path
    assert case.param == "sortBy"
    matrix = load_safety_matrix()
    result = verdict(vulnerable.transform, vulnerable.sink_context, matrix)
    assert result.verdict == "VULNERABLE"


def test_expedia_ground_truth_directory_loads_independently_of_the_default_one() -> None:
    default_gt = labels_contract.load("lab/ground-truth")
    expedia_gt = labels_contract.load(_GROUND_TRUTH_DIR)

    assert expedia_gt.target == "spring_boot"
    assert expedia_gt.case_by_id("EXPD-0001") is not None
    assert "EXPD-0001" not in {c.case_id for c in default_gt.cases}
    assert not any(c.case_id.startswith("EXPD-") for c in default_gt.cases)
    assert default_gt.case_by_id("PFF-0001") is not None  # the default dir is unaffected


def test_spel_and_other_spring_boot_controllers_have_disjoint_class_names() -> None:
    """Guards against a class-name collision with this app's other cells,
    matching `CC-LAB-0131`'s own established precedent test."""
    emitter = SpringBootEmitter()
    spel_manifest = load_manifest(_MANIFEST_PATH)
    deser_manifest = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml")
    spel_paths = {emitter.render(c)[0].path for c in spel_manifest.cells}
    deser_paths = {emitter.render(c)[0].path for c in deser_manifest.cells}
    assert spel_paths.isdisjoint(deser_paths)
