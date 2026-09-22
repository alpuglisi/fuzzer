"""Composable Java rendering modules for the ``java_spring_boot`` emitter
(category 4 pilot, ``CC-LAB-0091``/``FR-LAB-65``).

Mirrors ``fuzzlab.labgen.emitters.go_net_http.modules``' module-composition
shape exactly, ported to Java/Spring MVC. Phase A scope only (one shape):
``insecure_deserialization`` / ``object_deserialization`` — the one
illustrative cell ``docs/research/site-architecture-survey-functionality-netflix.md``
§2 picked for this stack's first live-boot proof. Reuses
``lab/safety_matrix.yaml``'s existing ``object_deserialization`` sink family
(added by ``CC-LAB-0063``) but adds two new ops to it —
``jackson_default_typing_deserialize``/``jackson_typed_allowlist_deserialize``
— since none of that family's existing node/php/python ops names the
Jackson-polymorphic-typing idiom this pick is specifically about.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """Same determinism-relevant flags as every other stack's own
    ``_make_env``, set explicitly rather than left at Jinja2's defaults, so
    two renders of the same inputs are byte-identical
    (NFR-LAB-reproducible)."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_ROOT / subdir)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,
    )


_SOURCE_ENV = _make_env("sources")
_TRANSFORM_ENV = _make_env("transforms")
_SINK_ENV = _make_env("sinks")
_COMPLEXITY_ENV = _make_env("complexities")


@dataclass(frozen=True)
class RenderResult:
    """Same shape as every other stack's own ``RenderResult``: the rendered
    code plus the (possibly updated) assembly context passed to the next
    module."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Java rendering fragment. Every module
    in this inventory is ``cardinality="per_cell"`` -- this stack has no
    accumulator-cardinality module at all (see this package's
    ``__init__.py`` module docstring for why: Spring Boot's component
    scanning needs no shared route-registration file)."""

    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    """A module whose rendering is exactly one Jinja2 template call."""

    def __init__(self, name: str, category: str, env: Environment, template_name: str):
        self.name = name
        self.category = category
        self._env = env
        self._template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


class ReadPlaybackEventBodySource(TemplateModule):
    """Reads the raw request body and constructs a fresh Jackson
    ``ObjectMapper`` -- the deserialization call itself (and whether it is
    polymorphic) is left to the transform, matching every other stack's
    "source publishes raw material, transform decides the safe/unsafe
    shape" convention."""

    def __init__(self) -> None:
        super().__init__(
            "read_playback_event_body", "source", _SOURCE_ENV, "read_playback_event_body.java.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("body_var", "requestBody")
        result = super().render(render_ctx)
        new_ctx = dict(render_ctx)
        new_ctx.setdefault("result_var", "event")
        return RenderResult(code=result.code, context=new_ctx)


class JacksonDefaultTypingDeserializeTransform(TemplateModule):
    """The ``jackson_default_typing_deserialize`` op (new,
    ``lab/safety_matrix.yaml``, ``object_deserialization`` family,
    ``no_effect``): deserializes into a polymorphic ``Object`` via Jackson's
    ``activateDefaultTyping`` — CWE-502, the vulnerable twin."""

    def __init__(self) -> None:
        super().__init__(
            "jackson_default_typing_deserialize",
            "transform",
            _TRANSFORM_ENV,
            "jackson_default_typing_deserialize.java.j2",
        )


class JacksonTypedAllowlistDeserializeTransform(TemplateModule):
    """The ``jackson_typed_allowlist_deserialize`` op (new,
    ``lab/safety_matrix.yaml``, ``object_deserialization`` family,
    ``neutralises`` -- the secure twin): deserializes into a single, fixed,
    concrete DTO class, no polymorphism."""

    def __init__(self) -> None:
        super().__init__(
            "jackson_typed_allowlist_deserialize",
            "transform",
            _TRANSFORM_ENV,
            "jackson_typed_allowlist_deserialize.java.j2",
        )


class ObjectDeserializationSink(TemplateModule):
    """Acknowledges the deserialized value and returns ``200`` -- does not
    itself know or care whether the deserialization it received was
    polymorphic, matching every other stack's sink-is-transform-agnostic
    convention."""

    def __init__(self) -> None:
        super().__init__(
            "object_deserialization", "sink", _SINK_ENV, "object_deserialization.java.j2"
        )


class RenderOnlyComplexity(TemplateModule):
    """Wraps the composed source/transform/sink body as the entire body of
    one ``@RestController``/``@PostMapping`` handler method -- the Java
    analogue of every other stack's own ``RenderOnlyComplexity``."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], class_name=ctx["class_name"], path=ctx["path"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "read_playback_event_body": ReadPlaybackEventBodySource(),
}
TRANSFORMS: dict[str, Module] = {
    "jackson_default_typing_deserialize": JacksonDefaultTypingDeserializeTransform(),
    "jackson_typed_allowlist_deserialize": JacksonTypedAllowlistDeserializeTransform(),
}
SINKS: dict[str, Module] = {
    "object_deserialization": ObjectDeserializationSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "render_only": RenderOnlyComplexity(),
}
