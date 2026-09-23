"""Unit coverage for `php_laravel`'s outbound-header-injection cell
(`CC-LAB-0135`, Huddle Hub's third and final designed cell).

No network/composer/php required -- pure Python emitter-output checks,
mirroring `tests/test_labgen_ssrf.py`'s own generated-source assertions.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/header_injection_huddlehub_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-HHB-0005": "VULNERABLE",  # raw_header_concat: no CRLF handling at all
    "LABGEN-HHB-0006": "SECURE",  # structured_http_client_headers
}


def _cells():
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def test_manifest_loads_and_validates() -> None:
    assert set(_cells()) == set(_EXPECTED_VERDICTS)


def test_verdict_matches_expected() -> None:
    matrix = load_safety_matrix()
    for cell_id, cell in _cells().items():
        result = verdict(cell.transform, cell.sink_context, matrix)
        assert result.verdict == _EXPECTED_VERDICTS[cell_id], cell_id


def test_supports_every_sample_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        assert emitter.supports(cell.vuln_class, cell.sink_context) is True


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_vulnerable_twin_concatenates_raw_secure_twin_uses_structured_headers() -> None:
    emitter = LaravelEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-HHB-0005"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-HHB-0006"])[0].content.decode("utf-8")
    assert "stream_context_create" in vulnerable_src
    assert "\\r\\n" in vulnerable_src
    assert "Http::withHeaders" not in vulnerable_src
    assert "Http::withHeaders" in secure_src
    assert "InvalidArgumentException" in secure_src
    # PA-0035 spirit: both twins must bound the outbound request, not just
    # the secure one.
    assert "'timeout' => 5" in vulnerable_src
    assert "->timeout(5)" in secure_src


def test_header_injection_and_ssrf_controllers_have_disjoint_paths() -> None:
    """Huddle Hub's three cells (`CC-LAB-0133`'s webhook-signature pair,
    `CC-LAB-0134`'s SSRF pair, this entry's header-injection pair) must
    never collide on a generated file path -- guaranteed by
    `_controller_class_for()` deriving from each cell's own id, not a new
    naming decision."""
    emitter = LaravelEmitter()
    header_paths = {emitter.render(c)[0].path for c in _cells().values()}
    ssrf_manifest = load_manifest("lab/manifests/ssrf_huddlehub_sample.yaml")
    ssrf_paths = {emitter.render(c)[0].path for c in ssrf_manifest.cells}
    webhook_manifest = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    webhook_paths = {emitter.render(c)[0].path for c in webhook_manifest.cells}
    assert header_paths.isdisjoint(ssrf_paths)
    assert header_paths.isdisjoint(webhook_paths)
