"""Module-composition unit tests for `java_spring_boot` (category 4 pilot,
`CC-LAB-0091`/`FR-LAB-65`).

Mirrors `tests/test_labgen_go_net_http_modules.py`'s convention exactly,
scoped to `fuzzlab.labgen.emitters.java_spring_boot.modules`'s own
registries and templates (a separate, self-contained module inventory).
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.java_spring_boot.modules import (
    COMPLEXITIES,
    SINKS,
    SOURCES,
    TRANSFORMS,
    _COMPLEXITY_ENV,
    _SINK_ENV,
    _SOURCE_ENV,
    _TRANSFORM_ENV,
)


def test_module_environments_set_determinism_flags_explicitly() -> None:
    for env in (_SOURCE_ENV, _TRANSFORM_ENV, _SINK_ENV, _COMPLEXITY_ENV):
        assert env.trim_blocks is True
        assert env.lstrip_blocks is True
        assert env.keep_trailing_newline is True


def test_read_playback_event_body_source_defaults_body_and_result_vars() -> None:
    result = SOURCES["read_playback_event_body"].render({})
    assert "request.getInputStream().readAllBytes()" in result.code
    assert "new ObjectMapper()" in result.code
    assert result.context["body_var"] == "requestBody"
    assert result.context["result_var"] == "event"


def test_jackson_default_typing_transform_uses_default_typing() -> None:
    ctx = {"body_var": "requestBody", "result_var": "event"}
    result = TRANSFORMS["jackson_default_typing_deserialize"].render(ctx)
    assert "activateDefaultTyping" in result.code
    assert "Object event = mapper.readValue(requestBody, Object.class);" in result.code


def test_jackson_typed_allowlist_transform_uses_fixed_dto() -> None:
    ctx = {"body_var": "requestBody", "result_var": "event"}
    result = TRANSFORMS["jackson_typed_allowlist_deserialize"].render(ctx)
    assert "activateDefaultTyping" not in result.code
    assert "PlaybackResumeRequest event = mapper.readValue(requestBody, PlaybackResumeRequest.class);" in result.code


def test_object_deserialization_sink_returns_ok() -> None:
    result = SINKS["object_deserialization"].render({"result_var": "event"})
    assert "ResponseEntity.ok" in result.code


def test_render_only_complexity_wraps_body_in_rest_controller() -> None:
    result = COMPLEXITIES["render_only"].render(
        {"body": "        doSomething();", "class_name": "CellTest", "path": "/generated/cell-test"}
    )
    assert "@RestController" in result.code
    assert "public class CellTest {" in result.code
    assert '@PostMapping("/generated/cell-test")' in result.code
    assert "doSomething();" in result.code
