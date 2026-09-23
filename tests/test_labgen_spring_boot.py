"""Unit coverage for the `spring_boot` emitter (`CC-LAB-0130`, TrackerNest).

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_node_express.py`'s own shape for its stack.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/ssti_spring_boot_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-SSTI-0001": "VULNERABLE",  # user_supplied_template_compile: OGNL-evaluates the tainted value
    "LABGEN-SSTI-0002": "SECURE",  # file_loaded_template_name: fixed macro-name lookup only
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


def test_spring_boot_does_not_support_an_unrelated_shape() -> None:
    from fuzzlab.labgen.schema import SinkContext

    emitter = SpringBootEmitter()
    assert emitter.supports("sqli", SinkContext(family="sql_numeric_literal")) is False


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = SpringBootEmitter()
    for cell in _cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_vulnerable_twin_calls_ognl_get_value_secure_twin_does_not() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-SSTI-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-SSTI-0002"])[0].content.decode("utf-8")
    assert "ognl.Ognl.getValue(" in vulnerable_src
    assert "ognl.Ognl.getValue(" not in secure_src
    assert "knownMacros.getOrDefault(" in secure_src


def test_render_raises_on_unsupported_cell() -> None:
    import pytest
    from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

    emitter = SpringBootEmitter()
    bogus = Cell(
        cell_id="BOGUS-0001",
        vuln_class="sqli",
        stack_profile="spring_boot",
        route=Route(method="GET", path="/nope"),
        sink_context=SinkContext(family="sql_numeric_literal"),
        transform=Pipeline(ops=()),
    )
    with pytest.raises(ValueError):
        emitter.render(bogus)
