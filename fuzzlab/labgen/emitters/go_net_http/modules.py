"""Composable Go rendering modules for the ``go_net_http`` emitter (category
4 pilot, ``CC-LAB-0170``/``FR-LAB-76``).

Mirrors ``fuzzlab.labgen.emitters.node_express.modules``' module-composition
shape (source/transform/sink/complexity categories, a ``Module``/
``TemplateModule`` base pair, an explicit-flags Jinja2 environment per
category) exactly, per this project's standing convention of reusing the
existing module *categories* as the porting template for a new stack. The
actual Go code is new: this module owns its own template directory and its
own registries, entirely inside
``fuzzlab/labgen/emitters/go_net_http/`` — it does not import from or
register into ``fuzzlab.labgen.modules`` or any other stack's registry.

Phase A scope only (one shape): ``webhook_signature`` /
``webhook_signature_verification`` — the one illustrative cell
``docs/research/site-architecture-survey-functionality-twitch.md`` §2
picked for this stack's first live-boot proof. The vulnerable/secure split
reuses ``lab/safety_matrix.yaml``'s existing ``webhook_signature_verification``
sink family and its existing ``naive_string_compare``/``constant_time_compare``
ops verbatim — no new safety-matrix entry was needed (a scope reduction
found during implementation of ``CC-LAB-0170``, which had drafted a new
``hmac_signature_check`` family before this family's prior existence, added
by ``CC-LAB-0063``, was found).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """Same determinism-relevant flags as every other stack's own
    ``_make_env`` (``node_express``, PHP's ``fuzzlab.labgen.modules``), set
    explicitly rather than left at Jinja2's defaults, so two renders of the
    same inputs are byte-identical (NFR-LAB-reproducible)."""
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
_ROUTE_ENV = _make_env(".")  # route.go.j2 lives directly under templates/


@dataclass(frozen=True)
class RenderResult:
    """Same shape as every other stack's own ``RenderResult``: the rendered
    code plus the (possibly updated) assembly context passed to the next
    module."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Go rendering fragment. ``cardinality``
    is ``"per_cell"`` for every module in this inventory except the route
    accumulator, which is rendered separately by
    :func:`render_route_line`/``GoEmitter.render_route_accumulator``
    (cardinality ``"accumulator"``) rather than through this per-cell
    registry."""

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


class ReadWebhookSignatureSource(TemplateModule):
    """Reads the raw request body, computes the expected HMAC-SHA256 digest
    over it with a fixed per-run shared secret, and reads the header
    carrying the caller-supplied digest. Publishes ``computed_var``/
    ``header_var`` (the two Go identifiers a comparison transform composes
    into ``value_expr``) rather than a single ``value_expr`` up front,
    since — unlike every SQLi/XSS source in this project's other stacks —
    this shape's "tainted value" is a boolean comparison outcome, not a
    single scalar the sink echoes/queries with."""

    def __init__(self) -> None:
        super().__init__(
            "read_webhook_signature", "source", _SOURCE_ENV, "read_webhook_signature.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("computed_var", "computed")
        render_ctx.setdefault("header_var", "headerSig")
        result = super().render(render_ctx)
        new_ctx = dict(render_ctx)
        # Vulnerable-by-default (no transform applied): a naive `==` --
        # matches every other stack's "identity transform" default of
        # publishing the least-safe rendering until a security op
        # overrides it (e.g. node_express's `bound=False` default).
        new_ctx["value_expr"] = f"{new_ctx['header_var']} == {new_ctx['computed_var']}"
        return RenderResult(code=result.code, context=new_ctx)


class NaiveStringCompareTransform(TemplateModule):
    """The ``naive_string_compare`` op (``lab/safety_matrix.yaml``,
    ``webhook_signature_verification`` family, ``partial`` effect --
    neutralizes nothing): renders a comment only, since the source already
    publishes the ``==`` comparison as ``value_expr`` by default -- this
    transform exists so a manifest can name the vulnerable path explicitly
    (never relying on "no transform" being silently equivalent to a named
    vulnerable op, per this project's own minimal-pair discipline)."""

    def __init__(self) -> None:
        super().__init__(
            "naive_string_compare", "transform", _TRANSFORM_ENV, "naive_string_compare.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"{ctx['header_var']} == {ctx['computed_var']}"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class ConstantTimeCompareTransform(TemplateModule):
    """The ``constant_time_compare`` op (``lab/safety_matrix.yaml``,
    ``webhook_signature_verification`` family, ``neutralises`` effect --
    the secure twin): rewrites ``value_expr`` to a ``crypto/hmac.Equal``
    call, constant-time regardless of where the two digests first differ."""

    def __init__(self) -> None:
        super().__init__(
            "constant_time_compare", "transform", _TRANSFORM_ENV, "constant_time_compare.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"hmac.Equal([]byte({ctx['header_var']}), []byte({ctx['computed_var']}))"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class WebhookSignatureVerificationSink(TemplateModule):
    """Branches on ``value_expr`` (the comparison a transform above
    published) and writes ``200``/``401`` -- does not itself know or care
    whether the comparison it received is constant-time, matching every
    other stack's sink-is-transform-agnostic convention (e.g.
    ``node_express``'s ``HtmlBodyEchoSink``)."""

    def __init__(self) -> None:
        super().__init__(
            "webhook_signature_verification",
            "sink",
            _SINK_ENV,
            "webhook_signature_verification.go.j2",
        )


class ReadUrlQueryParamSource(TemplateModule):
    """Reads one query-string parameter carrying the caller-supplied fetch
    target -- the SSRF shape's source (``CC-LAB-0172``). Publishes
    ``var_name`` unchanged from ``ctx`` (the route-profile table already
    names it), matching every other source's "publish the Go identifier
    the sink reads" convention."""

    def __init__(self) -> None:
        super().__init__("read_url_query_param", "source", _SOURCE_ENV, "read_url_query_param.go.j2")


class UncheckedUrlFetchSink(TemplateModule):
    """The ``unchecked_url_fetch`` op (``lab/safety_matrix.yaml``,
    ``server_side_http_fetch`` family, ``no_effect``): fetches the
    caller-supplied URL with a bounded-timeout ``http.Client`` and no
    other validation at all -- CWE-918, the vulnerable twin. A **sink**
    module, not a transform: see this package's own ``__init__.py``
    module docstring for why this shape's manifest op names a sink
    directly."""

    def __init__(self) -> None:
        super().__init__("unchecked_url_fetch", "sink", _SINK_ENV, "unchecked_url_fetch.go.j2")


class SchemeAndResolvedIpAllowlistSink(TemplateModule):
    """The ``scheme_and_resolved_ip_allowlist`` op (``lab/safety_matrix.yaml``,
    ``server_side_http_fetch`` family, ``neutralises`` -- the secure twin):
    rejects any scheme but ``https`` and rejects a resolved IP that is
    loopback/private/link-local/unspecified, checked against the
    *resolved* address (not just the hostname string), before fetching
    with the same bounded-timeout ``http.Client``."""

    def __init__(self) -> None:
        super().__init__(
            "scheme_and_resolved_ip_allowlist",
            "sink",
            _SINK_ENV,
            "scheme_and_resolved_ip_allowlist.go.j2",
        )


class RenderOnlyComplexity(TemplateModule):
    """Wraps the composed source/transform/sink body as the entire body of
    one ``net/http.HandlerFunc`` -- the Go analogue of every other stack's
    own ``RenderOnlyComplexity`` (used for a cell with no DB row to
    return)."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.go.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "read_webhook_signature": ReadWebhookSignatureSource(),
    "read_url_query_param": ReadUrlQueryParamSource(),
}
TRANSFORMS: dict[str, Module] = {
    "naive_string_compare": NaiveStringCompareTransform(),
    "constant_time_compare": ConstantTimeCompareTransform(),
}
SINKS: dict[str, Module] = {
    "webhook_signature_verification": WebhookSignatureVerificationSink(),
    "unchecked_url_fetch": UncheckedUrlFetchSink(),
    "scheme_and_resolved_ip_allowlist": SchemeAndResolvedIpAllowlistSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "render_only": RenderOnlyComplexity(),
}


def render_route_line(*, method: str, path: str, handler_name: str) -> str:
    """Render one ``net/http.ServeMux`` route-registration line (the
    ``route``-category accumulator fragment). Kept as a pure,
    single-purpose function -- not a class -- matching
    ``node_express.modules.render_route_line``'s own shape."""
    template = _ROUTE_ENV.get_template("route.go.j2")
    return template.render(method=method.upper(), path=path, handler_name=handler_name)
