"""Unit coverage for Netflix's eleventh real page (`CC-LAB-0197`,
`FR-LAB-152`): this stack's first `ssti`/`template_render` instance on THIS
app identity, `GET /api/support/template-preview?expr=`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot.py`'s own shape for TrackerNest's own
`ssti_spring_boot_sample.yaml` manifest.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/ssti_netflix_support_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0021": "VULNERABLE",  # user_supplied_template_compile: OGNL-evaluates the tainted value
    "LABGEN-JV-0022": "SECURE",  # file_loaded_template_name: fixed macro-name lookup only
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


def test_vulnerable_twin_calls_ognl_get_value_secure_twin_does_not() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0021"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0022"])[0].content.decode("utf-8")
    assert "ognl.Ognl.getValue(" in vulnerable_src
    assert "ognl.Ognl.getValue(" not in secure_src
    assert "knownMacros.getOrDefault(" in secure_src
    # Route-specific: the tainted material comes from the `expr` query
    # param via a distinct Java local variable name (`previewExpr`), never
    # colliding with TrackerNest's own `macroExpr` cell on this same
    # shared package.
    assert 'request.getParameter("expr")' in vulnerable_src
    assert "previewExpr" in vulnerable_src


def test_route_is_distinct_from_trackernest_own_ssti_cell() -> None:
    """This cell must never collide with TrackerNest's own
    `/wiki/pages/render` route on this same shared `spring_boot` package
    (the whole point of a *new* route for a *new* app identity)."""
    cells = _cells()
    for cell in cells.values():
        assert cell.route.path == "/api/support/template-preview"
        assert cell.route.path != "/wiki/pages/render"
