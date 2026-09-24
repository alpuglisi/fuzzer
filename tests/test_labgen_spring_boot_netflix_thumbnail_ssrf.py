"""Unit coverage for the `spring_boot` emitter's first `ssrf` cell
(`CC-LAB-0194`, `FR-LAB-149`): Netflix's ninth real page, a partner-content
thumbnail-import endpoint at `POST /api/content/thumbnail-import`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_netflix_jwt_preferences.py`'s own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/ssrf_netflix_thumbnail_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0017": "VULNERABLE",  # unchecked_url_fetch: no validation at all
    "LABGEN-JV-0018": "SECURE",      # scheme_and_resolved_ip_allowlist
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


def test_module_composition_reuses_query_param_source_verbatim() -> None:
    """Zero new source module: this shape reuses the pre-existing
    `query_param` source (already used by `ssti`/`spel_injection`)
    verbatim -- the same query-param-carried-URL contract `go_net_http`'s
    own `read_url_query_param` source established."""
    emitter = SpringBootEmitter()
    cells = _cells()
    vuln_src = emitter.render(cells["LABGEN-JV-0017"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0018"])[0].content.decode("utf-8")

    assert "Module composition: query_param -> unchecked_url_fetch -> single_handler" in vuln_src
    assert (
        "Module composition: query_param -> scheme_and_resolved_ip_allowlist -> single_handler"
        in secure_src
    )
    assert 'request.getParameter("thumbnail_url")' in vuln_src
    assert 'request.getParameter("thumbnail_url")' in secure_src
    assert "PostMapping" in vuln_src and "PostMapping" in secure_src


def test_vulnerable_twin_fetches_unconditionally_secure_twin_checks_scheme_and_resolved_ip() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vuln_src = emitter.render(cells["LABGEN-JV-0017"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0018"])[0].content.decode("utf-8")

    # Vulnerable twin: no scheme/IP check at all before fetching.
    assert "getScheme" not in vuln_src
    assert "InetAddress" not in vuln_src
    assert "java.net.http.HttpClient" in vuln_src

    # Secure twin: scheme must be https, and the RESOLVED address (not just
    # the hostname string) is checked against loopback/private/link-local
    # before ever attempting the fetch -- closing the DNS-rebinding gap.
    assert 'equalsIgnoreCase("https")' in secure_src
    assert "java.net.InetAddress.getAllByName" in secure_src
    assert "isLoopbackAddress()" in secure_src
    assert "isSiteLocalAddress()" in secure_src
    assert "isLinkLocalAddress()" in secure_src
    assert "isAnyLocalAddress()" in secure_src
    assert "java.net.http.HttpClient" in secure_src


def test_both_sinks_use_a_bounded_timeout_never_a_default_client() -> None:
    """`CC-LAB-0172`'s own convention, ported: a real `HttpClient`/
    `HttpRequest` has no default timeout and can hang indefinitely against
    a slow/unresponsive target -- both twins must set an explicit, bounded
    connect/request timeout."""
    emitter = SpringBootEmitter()
    for cell_id in ("LABGEN-JV-0017", "LABGEN-JV-0018"):
        src = emitter.render(_cells()[cell_id])[0].content.decode("utf-8")
        assert "connectTimeout(java.time.Duration.ofSeconds(5))" in src
        assert ".timeout(java.time.Duration.ofSeconds(5))" in src


def test_vulnerable_response_body_echoes_the_fetched_resource_verbatim() -> None:
    """The response shape `SsrfInBandMarkerStrategy`'s own `confirm()`
    (`fuzzlab.oracle.strategies`, already built for Twitch's `go_net_http`
    cells) needs to generalize with zero new code: the fetched resource's
    own body, byte-for-byte, mirroring `go_net_http`'s own `io.Copy(w,
    resp.Body)` shape -- never wrapped/escaped in a JSON envelope."""
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0017"])[0].content.decode("utf-8")
    assert "ResponseEntity.ok().body(fetchResponse.body())" in src


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's ninth cell must not collide with any of its other eight
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
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 20
