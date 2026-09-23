"""``ruby_rails`` -- the Ruby-on-Rails :class:`~fuzzlab.labgen.emitter.Emitter`
(category 1 / e-commerce pilot, ``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md``
§2/§9.4a/§9.5). This project's first Ruby-on-Rails stack.

**Phase A** (``CC-LAB-0071``/``FR-LAB-65``) built the minimum real, working
emitter needed to prove the pipeline end to end: assemble a manifest cell
into real controller/view/route files, boot a real Rails app, and serve a
real HTTP request, via exactly one illustrative shape (``("xss",
"html_body")``).

**Phase B** (this delivery -- ``CC-LAB-0072``..``CC-LAB-0075``/
``FR-LAB-66``..``FR-LAB-68``) adds the three real Rails-idiom vulnerability
modules Shopify's own functionality/CWE research shortlisted
(``docs/research/site-architecture-survey-functionality-shopify.md`` /
plan §9.4a's "Decided" block):

- ``("webhook_signature", "webhook_signature_verification")`` -- naive
  ``==`` vs ``ActiveSupport::SecurityUtils.secure_compare`` over a real
  recomputed HMAC-SHA256.
- ``("mass_assignment", "orm_entity_bulk_assign")`` -- Rails' unrestricted
  ``permit!`` vs an explicit ``permit(:a, :b)`` strong-parameters
  allowlist, against the checked-in ``users`` table.
- ``("insecure_deserialization", "object_deserialization")`` -- Psych's
  ``YAML.unsafe_load`` vs ``YAML.safe_load``.

Every new shape uses the ``single_statement`` complexity (a JSON response
the sink itself renders) rather than ``render_only``'s separate view file,
and none of them need a view: :data:`_MODULE_SET_BY_SHAPE`'s
``renders_view`` flag on each entry decides which path :meth:`RailsEmitter.render`
takes -- see that method's own comments.

**Phase C** (``CC-LAB-0077``/``FR-LAB-81``) gives this app its own real,
coherent page/route identity -- "ForgeCart", a Shopify-style merchant
storefront + admin -- instead of every cell living at an illustrative
``/cell/<slug>`` URL. Five new real-page cells (``LABGEN-RR-RP-0001``..
``0005``, :data:`_REAL_PAGE_URL_BY_CELL_ID`) reuse the four shapes already
built above at real URLs (``/search``, two ``/webhooks/...`` topics, two
``/admin/...`` endpoints); a handful of inert surrounding pages (storefront
home/products/cart, admin dashboard/orders) are fixed, non-generated routes
declared in ``route_accumulator._STATIC_APP_ROUTES`` with their own
checked-in skeleton controllers (``StorefrontController``/
``AdminController``) -- see ``lab/manifests/shopify_forgecart_real_pages.yaml``
and ``lab/ground-truth-forgecart/`` for the manifest and out-of-band ground
truth this identity is scored against.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.emitters.ruby_rails.modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS
from fuzzlab.labgen.emitters.ruby_rails.route_accumulator import RouteAccumulator
from fuzzlab.labgen.schema import Cell, SinkContext

__all__ = ["RailsEmitter", "SUPPORTED_CONTEXT_DEPTHS", "controller_name_for", "url_path_for"]

#: The one ``Cell.context_depth`` this Phase A emitter renders. Widening this
#: (``stored_second_order``, the pass-through-helper depths) is Phase B/a
#: later lane's job, exactly like ``php_laravel``'s own
#: ``SUPPORTED_CONTEXT_DEPTHS`` was widened incrementally rather than built
#: complete on day one.
SUPPORTED_CONTEXT_DEPTHS: tuple[str, ...] = ("direct",)


class _ModuleSet(NamedTuple):
    source: str
    sink: str
    complexity: str
    #: The controller action name (also the route's ``to: '...#<action>'``
    #: and, for a ``renders_view`` shape, the view file's own stem). Phase
    #: A's one shape used a fixed ``"show"`` for all three roles; Phase B's
    #: JSON-responding shapes are write endpoints, so this is now per-shape
    #: rather than a single module-wide constant (PA-0003/PA-0021: the
    #: emitted route and the emitted controller method can never name two
    #: different things).
    action: str = "show"
    #: Whether this shape hands a value to a separate view file
    #: (``render_only``, Phase A's only shape) or the sink itself renders a
    #: complete JSON response with no view file at all (every Phase B
    #: shape, ``single_statement``).
    renders_view: bool = True


#: (vuln_class, sink_context.family) -> which modules render this shape.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("xss", "html_body"): _ModuleSet("get_param", "html_body_echo", "render_only"),
    # CC-LAB-0072: webhook-signature verification (naive `==` vs
    # ActiveSupport::SecurityUtils.secure_compare) over a real recomputed
    # HMAC-SHA256 -- a webhook delivery is always a POST.
    ("webhook_signature", "webhook_signature_verification"): _ModuleSet(
        "raw_request_body", "webhook_signature_verification", "single_statement",
        action="create", renders_view=False,
    ),
    # CC-LAB-0073: CWE-915 mass assignment (`permit!` vs an explicit
    # `permit(:a, :b)` allowlist) against the checked-in `users` table --
    # a merchant/customer profile-update endpoint, so PATCH.
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet(
        "all_params_nested", "orm_entity_bulk_assign", "single_statement",
        action="update", renders_view=False,
    ),
    # CC-LAB-0074: CWE-502 insecure deserialization (`YAML.unsafe_load` vs
    # `YAML.safe_load`) on a bulk-import-style POST body.
    ("insecure_deserialization", "object_deserialization"): _ModuleSet(
        "post_param", "object_deserialization", "single_statement",
        action="create", renders_view=False,
    ),
}

#: Per-shape static render-only metadata (param/variable names, the
#: mass-assignment allowlist, the webhook secret/header) -- none of this is
#: verdict-relevant (the same "render-only metadata" role
#: ``php_laravel``'s own ``_PAGE_PROFILES`` static fields play), so it lives
#: here rather than on :class:`_ModuleSet`, which only names *which*
#: modules render a shape, never their inputs.
_SHAPE_CTX: dict[tuple[str, str], dict[str, Any]] = {
    ("xss", "html_body"): {"var_name": "value", "param_name": "q"},
    ("webhook_signature", "webhook_signature_verification"): {
        "var_name": "body",
        "header_name": "X-Shopify-Hmac-SHA256",
        # A fixed, obviously-fake lab secret -- never a real credential
        # (D12/CLAUDE.md's "credentials in the OS keyring, never commit
        # secrets" rule does not apply to a synthetic app secret this
        # illustrative cell both signs and verifies with itself).
        "secret": "whsec_lab_lab_only_not_a_real_secret",
    },
    ("mass_assignment", "orm_entity_bulk_assign"): {
        "var_name": "attrs",
        "resource_name": "user",
        "allowed_fields": ("username", "bio"),
    },
    ("insecure_deserialization", "object_deserialization"): {
        "var_name": "raw_yaml",
        "param_name": "yaml_payload",
    },
}

#: A cell ID like ``LABGEN-RR-0001`` -> a Rails-legal, unique, lowercase
#: snake_case identifier (``labgen_rr_0001``) safe to use in both a
#: controller class name and a route/controller-path string. Anchored,
#: exact-charset (PA-0022): a cell ID this cannot losslessly slugify is a
#: caller bug, not silently coerced.
_CELL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def _slug_for(cell_id: str) -> str:
    if not _CELL_ID_RE.match(cell_id):
        raise ValueError(
            f"ruby_rails cannot slugify cell_id {cell_id!r} -- expected "
            f"{_CELL_ID_RE.pattern!r}"
        )
    return cell_id.lower().replace("-", "_")


def controller_name_for(cell_id: str) -> str:
    """The Rails controller path (after ``#`` in ``to: 'x#show'``, and the
    ``app/controllers/<this>_controller.rb`` file stem) for a cell -- the one
    place this mapping is computed, so the emitted route and the emitted
    controller file can never name two different things
    (PA-0003/PA-0021)."""
    return f"cell_{_slug_for(cell_id)}"


def _controller_class_for(cell_id: str) -> str:
    """The Ruby class name for :func:`controller_name_for`'s controller path
    -- ``cell_labgen_rr_0001`` -> ``CellLabgenRr0001Controller``, Rails'
    own ``String#camelize``-equivalent convention (applied here in Python,
    not by shelling out to Ruby, since this is pure, deterministic string
    logic the generator must be able to run without a Ruby runtime
    present)."""
    camel = "".join(part.capitalize() for part in controller_name_for(cell_id).split("_"))
    return f"{camel}Controller"


#: Real, coherent page URLs for "ForgeCart" (Phase C page/route identity,
#: `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4/§9.5 --
#: CC-LAB-0077/FR-LAB-81), one entry per real-page cell in
#: `lab/manifests/shopify_forgecart_real_pages.yaml`. Mirrors
#: `php_laravel`'s own real-page precedent (`_PAGE_PROFILES`'s URL keys,
#: `LABGEN-PLRP-*` cell IDs): a *new*, distinct cell ID per real page,
#: never reusing `LABGEN-RR-0001`..`0007`'s existing `/cell/<slug>` cells
#: (those stay exactly where Phase A/B's own already-passing tests expect
#: them -- see this module's own docstring). Every URL here also has a real,
#: checked-in controller/route registered for it: the four `RailsEmitter`
#: shapes render their own controller+route per cell as usual; the
#: surrounding inert pages (`/`, `/products`, `/cart`, `/admin`,
#: `/admin/orders`) are the fixed, non-generated routes in
#: `route_accumulator._STATIC_APP_ROUTES`, kept in this same module's
#: docstring cross-reference so the two lists can be read side by side.
_REAL_PAGE_URL_BY_CELL_ID: dict[str, str] = {
    # Storefront search -- reflects `?q=` into the results banner
    # (`("xss", "html_body")`, the one shape Phase A built). Real Shopify
    # storefront search internals are not independently confirmed beyond
    # "the surface exists" (see the Shopify functionality research doc
    # §1's own caveat); a `/search?q=` box is the standard shape every
    # storefront exposes regardless.
    "LABGEN-RR-RP-0001": "/search",
    # Webhook receiver for the `orders/create` topic -- vulnerable twin
    # (naive `==`), the real Shopify `X-Shopify-Hmac-SHA256` mechanism this
    # category's research names as its strongest-grounded finding.
    "LABGEN-RR-RP-0002": "/webhooks/orders/create",
    # Webhook receiver for the `customers/update` topic -- secure twin
    # (`ActiveSupport::SecurityUtils.secure_compare`). A second, real
    # Shopify webhook topic (not a second endpoint for the same topic),
    # matching the real ecosystem's "merchants subscribe per-topic"
    # design and giving this app's ground truth a genuine negative
    # (secure) real-page case alongside its four positive ones.
    "LABGEN-RR-RP-0003": "/webhooks/customers/update",
    # Merchant-admin customer-account update -- CWE-915 (`permit!`).
    "LABGEN-RR-RP-0004": "/admin/customers/update",
    # Merchant-admin product bulk-import -- CWE-502 (`YAML.unsafe_load`).
    "LABGEN-RR-RP-0005": "/admin/products/import",
}


def url_path_for(cell_id: str) -> str:
    """The URL a cell is served at. A Phase C real-page cell
    (:data:`_REAL_PAGE_URL_BY_CELL_ID`) gets its real, coherent app URL;
    every other cell (Phase A's illustrative shape, Phase B's
    module-conformance sample pairs) keeps the cell-ID-derived illustrative
    URL (``/cell/<slug>``), exactly like ``php_laravel``'s own illustrative
    (non-``real_page``) cells -- unchanged so those cells' own already-
    passing tests/manifests never have to move."""
    if cell_id in _REAL_PAGE_URL_BY_CELL_ID:
        return _REAL_PAGE_URL_BY_CELL_ID[cell_id]
    return f"/cell/{_slug_for(cell_id)}"


def _view_name_for(action: str) -> str:
    return action


class RailsEmitter(Emitter):
    """Renders a resolved :class:`~fuzzlab.labgen.schema.Cell` into a real
    Rails controller + view, plus a route fragment a caller accumulates into
    ``config/routes.rb`` via :class:`RouteAccumulator`
    (:meth:`route_fragment_for`) -- the same controller/view/route split
    ``LaravelEmitter`` uses, per ``CR-LAB-0001`` Addendum D."""

    def __init__(self) -> None:
        self._route_accumulator = RouteAccumulator()

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for ruby_rails "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        if cell.context_depth not in SUPPORTED_CONTEXT_DEPTHS:
            raise ValueError(
                f"{cell.cell_id}: ruby_rails renders context_depth "
                f"{list(SUPPORTED_CONTEXT_DEPTHS)} only (Phase A/B), got {cell.context_depth!r}"
            )

        shape = (cell.vuln_class, cell.sink_context.family)
        modules = _MODULE_SET_BY_SHAPE[shape]
        controller_name = controller_name_for(cell.cell_id)
        controller_class = _controller_class_for(cell.cell_id)
        view_name = _view_name_for(modules.action)

        ctx: dict[str, Any] = {
            "method_name": modules.action,
            "view_name": view_name,
            **_SHAPE_CTX[shape],
        }

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: ruby_rails has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)
        ctx = sink_result.context

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        # Zeitwerk (Rails' autoloader) expects exactly one top-level constant
        # per file, matching the file's own path -- this controller file
        # must define only `controller_class`, never a second
        # `ApplicationController` definition of its own; the skeleton's real
        # `app/controllers/application_controller.rb` already defines it.
        controller_header = (
            "# Generated by fuzzlab.labgen.emitters.ruby_rails. Do not edit by hand.\n"
            f"# Module composition: {composition}\n"
            f"# cell: {cell.cell_id}\n"
            f"class {controller_class} < ApplicationController\n"
        )
        controller_footer = "end\n"

        def _indent(raw: str) -> str:
            # Indent every emitted line under the controller method's own
            # `def`/`end` (cosmetic -- Ruby is whitespace-insensitive -- but
            # matches this project's other emitters' convention of emitting
            # source that reads like a human wrote it, not a diagnostic aid
            # to skip).
            return "\n".join(f"    {line}" if line else line for line in raw.splitlines()) + "\n"

        if modules.renders_view:
            # Phase A shape: the sink is a separate view file, not code in
            # the controller method -- the complexity template itself emits
            # the `render template: ...` call.
            raw_body = source_result.code + "".join(transform_code_blocks)
            body = _indent(raw_body)
            complexity_result = COMPLEXITIES[modules.complexity].render(
                {**ctx, "body": body, "view_template": f"{controller_name}/{view_name}"}
            )
            controller_content = controller_header + complexity_result.code + controller_footer
            view_dir = f"app/views/{controller_name}"
            view_content = (
                f"<%# Generated by fuzzlab.labgen.emitters.ruby_rails -- cell: {cell.cell_id} %>\n"
                + sink_result.code
            )
            return (
                EmittedFile(
                    path=f"app/controllers/{controller_name}_controller.rb",
                    content=controller_content.encode("utf-8"),
                    role="controller",
                ),
                EmittedFile(
                    path=f"{view_dir}/{view_name}.html.erb",
                    content=view_content.encode("utf-8"),
                    role="view",
                ),
            )

        # Phase B shapes: the sink itself renders a complete JSON response
        # inline in the controller method -- there is no view file at all.
        raw_body = source_result.code + "".join(transform_code_blocks) + sink_result.code
        body = _indent(raw_body)
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})
        controller_content = controller_header + complexity_result.code + controller_footer
        return (
            EmittedFile(
                path=f"app/controllers/{controller_name}_controller.rb",
                content=controller_content.encode("utf-8"),
                role="controller",
            ),
        )

    def route_fragment_for(self, cell: Cell) -> str:
        """One ``config/routes.rb`` fragment for ``cell`` -- accumulated
        across every cell of a build via :class:`RouteAccumulator`, mirroring
        ``LaravelEmitter.route_fragment_for``'s role exactly (Addendum D:
        the accumulator category lives outside a per-cell ``render()``
        return value)."""
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]
        return self._route_accumulator.fragment_for_cell(
            cell_id=cell.cell_id,
            controller_name=controller_name_for(cell.cell_id),
            url_path=url_path_for(cell.cell_id),
            method=cell.route.method,
            action=modules.action,
        )
