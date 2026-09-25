"""``django``: category 2's new-stack pick (Instagram/Python-Django,
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9), Phase A
(`CC-LAB-0090`) + Phase B (`CC-LAB-0091`).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Django by assembling
:mod:`fuzzlab.labgen.emitters.django.modules` fragments per cell, following
``fuzzlab.labgen.emitters.node_express``'s own port of ``php_current``'s
module-composition shape (Addendum C) as the closer structural template --
both are Tier-A-scoped ports, unlike ``php_laravel``'s full-depth build. The
actual Python/Django code is new.

**Scope, stated plainly:** Phase A (`CC-LAB-0090`) built exactly one
well-documented, value-context shape -- ``sqli``/``sql_numeric_literal`` --
the same first shape ``php_laravel``'s own L-P3.3a foundation lane and
``node_express``'s Phase A plan both picked, proving the scaffold renders
and passes Tier 0 + Tier 3 end to end. Phase B (`CC-LAB-0091`) widens this
to the same three-shape Tier-A bar ``node_express`` already proves --
``sqli``/``sql_string_literal`` (a login-style lookup) and ``xss``/
``html_body`` (a stored value echoed raw vs. escaped). The full
``php_laravel``-depth nine-shape inventory stays out of scope, as does the
researched, corpus-grounded Django-specific XSS footgun (Django template
autoescaping disabled via ``mark_safe()``/``|safe``/``{% autoescape off %}``
-- see ``docs/research/category2-social-ugc-functionality-and-cwe-
research.md`` §4) -- deliberately deferred to Phase C's own corpus-grounded
page design, per `CC-LAB-0091`'s own reasoning.

**Multi-file output, like ``node_express``.** Per Addendum D, a routed,
multi-file emitter needs a ``route``-category *accumulator* module
(``fuzlab_django_lab/urls.py``'s route-registration lines) fed by one
fragment per cell, sorted by cell ID at render time. :meth:`Emitter.render`
therefore returns **only** the per-cell view file for a cell -- never a
re-rendering of the shared ``urls.py`` -- exactly ``node_express``'s own
documented extension of the per-emitter contract
(:meth:`DjangoEmitter.render_route_accumulator` is called once, separately,
over the whole supported cell set).

**No separate Django "app" needed for this shape.** The one illustrative
shape uses a raw ``connection.cursor()`` sink on *both* twins (never the
ORM), so it needs no model/migration of its own -- views live directly in
the project package (``fuzlab_django_lab/views/``), a documented
simplification from `CC-LAB-0090`'s original draft sketch (see
``fuzzlab.labgen.emitters.django.stack_env`` module docstring for the
divergence note, reflected back per the pre-change review gate's own rule).
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS, render_route_import_line

__all__ = ["DjangoEmitter", "served_url_for"]

# A small, fixed helper every generated view includes unconditionally
# (CC-LAB-0091) -- present identically in every generated file regardless
# of whether that cell's own shape uses it, mirroring node_express's own
# `_ESCAPE_HTML_HELPER` convention (keeps the vulnerable/secure minimal-pair
# diff confined to the transform region, BUG-0027). Backs the
# `read_stored_field` source's `stored_expr` with a *real*, seedable value
# (a raw cursor SELECT against a table `DjangoLiveBootHarness` seeds) --
# deliberately not `request.session`-based: unlike `node_express` (which
# has no live-boot harness and never actually executes this code),
# `DjangoLiveBootHarness` genuinely boots and serves this file, so the
# stored value must be real and directly seedable, not an idealized
# property access on an undefined `currentUser`-style object.
_READ_STORED_BIO_HELPER = (
    "def _read_stored_bio():\n"
    "    with connection.cursor() as cursor:\n"
    "        cursor.execute(\"SELECT bio FROM profiles WHERE id = 1\")\n"
    "        row = cursor.fetchone()\n"
    "    return row[0] if row else \"\"\n"
)

# CC-LAB-0093: same convention as `_READ_STORED_BIO_HELPER` above -- a
# fixed, unconditional helper backing the `read_stored_field` source's
# `stored_expr` for the `/post/comments` page with a real, seedable value
# (a raw cursor SELECT against a `comments` table `DjangoLiveBootHarness`
# seeds).
_READ_STORED_COMMENT_HELPER = (
    "def _read_stored_comment():\n"
    "    with connection.cursor() as cursor:\n"
    "        cursor.execute(\"SELECT body FROM comments WHERE id = 1\")\n"
    "        row = cursor.fetchone()\n"
    "    return row[0] if row else \"\"\n"
)

# CC-LAB-0093: the companion template for the `django_template_render`
# sink -- a **fixed Python string constant, never a `.j2` file rendered
# through this emitter's own Jinja2 module-composition system**
# (`fuzzlab.labgen.emitters.django.modules`'s Jinja2 environments use the
# same `{{ }}` delimiter Django's own template engine uses for a context
# variable; a `.html.j2` generation template containing literal Django
# syntax like `{{ comment }}` would collide with this project's own
# generation-time Jinja2 pass -- exactly the collision `php_laravel`'s own
# Blade views avoid by using Blade's raw-echo `{!! $value !!}` syntax,
# never Blade's own `{{ $value }}` form, in its `.blade.php.j2` sink
# templates, for the identical reason). Since this content is identical
# between the vulnerable and secure twin (the differing behavior lives
# entirely in the transform, not the template), it needs no per-cell
# interpolation at generation time at all -- written byte-for-byte,
# untouched by Jinja2, so Django's own template engine is the only thing
# that ever evaluates `{{ comment }}`, at real request time.
#
# CC-LAB-0242 (FR-LAB-160, Browsable Labs Lane 2): the template now extends
# PicTrail's shared site layout (`templates/layouts/site.html`, a checked-in
# skeleton file) instead of being a bare `<div>` fragment -- the same fix
# shape Lane 1 applied to `php_laravel`'s `html_body_echo.blade.php.j2`. The
# `{{ comment }}` echo itself is unchanged, and the whole constant is still
# byte-identical between twins.
_COMMENT_TEMPLATE_HTML = (
    '{% extends "layouts/site.html" %}\n'
    "{% block title %}Comments · PicTrail{% endblock %}\n"
    "{% block content %}\n"
    "<h2>Comments</h2>\n"
    '<div class="comment">{{ comment }}</div>\n'
    '<p><a href="/post">Back to the post</a></p>\n'
    "{% endblock %}\n"
)

# CC-LAB-0095: fixed, unconditional constants backing the mass-assignment
# shape's two transforms. `_KNOWN_PROFILE_COLUMNS` is SQL-column-name
# hygiene only (every real column `profiles` has) -- not a security
# boundary, applied by the vulnerable twin's own transform.
# `_PUBLIC_SETTINGS_FIELDS` is the real settings form's own publicly-
# settable subset -- the actual security boundary, applied by the secure
# twin's transform. Present identically in every generated file
# regardless of whether that cell's own shape uses them, mirroring
# `_READ_STORED_BIO_HELPER`'s own convention (keeps the vulnerable/secure
# minimal-pair diff confined to the transform region, BUG-0027).
_KNOWN_PROFILE_COLUMNS = "_KNOWN_PROFILE_COLUMNS = {\"bio\", \"is_verified\"}\n"
_PUBLIC_SETTINGS_FIELDS = "_PUBLIC_SETTINGS_FIELDS = {\"bio\"}\n"

# CC-LAB-0096: fixed, unconditional constant backing the identifier-
# allowlist transform for the explore/search page -- maps every
# real, sortable sort key to its own (identical) real column name on
# `posts`. Present identically in every generated file regardless of
# whether that cell's own shape uses it, same convention as the other
# fixed constants above.
_ORDER_BY_ALLOWLIST = '_ORDER_BY_ALLOWLIST = {"id": "id", "name": "name"}\n'


class _ModuleSet(NamedTuple):
    """Same shape as ``php_current``'s/``node_express``'s ``_ModuleSet``:
    which source/sink/complexity module a ``(vuln_class,
    sink_context.family)`` shape renders with. The transform is never fixed
    here -- it always comes from the cell's own ``transform`` pipeline, per
    op."""

    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Tier-A scope only (Phase A + Phase B) -- any pair not listed here is
#: declared unsupported via supports().
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_param", "sql_numeric_lookup", "single_statement"),
    ("sqli", "sql_string_literal"): _ModuleSet("post_param", "sql_string_literal_lookup", "single_statement"),
    ("xss", "html_body"): _ModuleSet("read_stored_field", "html_body_echo", "render_only"),
    # CC-LAB-0093: a genuinely new shape, not a rendering of `html_body`
    # above -- see `lab/safety_matrix.yaml`'s own `html_body_template`
    # family comment for why this sink family inverts the usual
    # dangerous-by-default convention.
    ("xss", "html_body_template"): _ModuleSet(
        "read_stored_field", "django_template_render", "render_only"
    ),
    # CC-LAB-0094: a genuinely new sink *category* for this emitter --
    # outbound server-side HTTP fetch, not DB/template/string-response.
    # No new safety-matrix design needed: `lab/safety_matrix.yaml`
    # already has a real, corpus-grounded `server_side_http_fetch` sink
    # family. The sink is shared, byte-identical between twins; the
    # vulnerable/secure distinction lives entirely in the transform
    # (`unchecked_url_fetch` vs. `scheme_and_resolved_ip_allowlist`).
    ("ssrf", "server_side_http_fetch"): _ModuleSet(
        "get_param", "http_fetch_json_sink", "render_only"
    ),
    # CC-LAB-0095: mass assignment (CWE-915) -- a genuinely new source
    # shape too (the whole POST body as a dict, not one named param). No
    # new safety-matrix design: `lab/safety_matrix.yaml` already has a
    # real, corpus-grounded `orm_entity_bulk_assign` sink family. The
    # sink is shared, byte-identical between twins; the vulnerable/secure
    # distinction lives entirely in the transform (`unfiltered_body_update`
    # vs. `runtime_field_allowlist`).
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet(
        "post_body_dict", "profile_bulk_update_sink", "render_only"
    ),
    # CC-LAB-0096: identifier/ORDER-BY-position SQLi (CWE-89) -- reuses
    # lab/safety_matrix.yaml's existing `sql_order_by_clause` sink family
    # unchanged (this project's first real implementation of it, on any
    # stack). Sink shared between twins; the vulnerable/secure
    # distinction lives entirely in the transform
    # (`orm_order_by_unvalidated` vs. `identifier_allowlist`).
    ("sqli", "sql_order_by_clause"): _ModuleSet(
        "get_param", "explore_order_by_sink", "render_only"
    ),
    # CC-LAB-0097: insecure deserialization (CWE-502), modeling Django's
    # own real, documented PickleSerializer opt-in footgun as an inbox/DM
    # payload. Unlike every other shape in this emitter, the sink is
    # *not* shared byte-identical between twins -- the deserialize
    # mechanism itself (pickle vs. JSON) differs, flagged by the
    # transform via Jinja2-time interpolation (mirroring `ruby_rails`'s
    # own `yaml_unsafe_load`/`yaml_safe_load` convention).
    ("insecure_deserialization", "object_deserialization"): _ModuleSet(
        "post_param", "inbox_deserialize_sink", "render_only"
    ),
}

#: Per-route static context (table/column/param names, or the stored field
#: expression an HTML-sink cell reads) an emitter needs beyond the
#: verdict-relevant Cell IR -- same separation rationale as
#: ``php_current._PAGE_PARAMS``/``node_express._ROUTE_PARAMS``: table/column
#: naming is render-only information, not verdict-relevant, so it lives
#: here rather than growing the shared IR. Keyed by ``cell.route.path``,
#: since a vulnerable cell and its secure twin share one route profile.
#:
#: CC-LAB-0242 (FR-LAB-160, Browsable Labs Lane 2) adds optional, render-only
#: keys, each consumed by exactly one module template and identical on both
#: twins of a route (so every minimal pair still differs only in its
#: transform region, BUG-0027):
#:
#: * ``default_value`` (``get_param``): the page's absent-input default --
#:   ``request.GET.get(<param>) or "<default>"`` (PA-0053/BUG-0052).
#: * ``required_param`` (``get_param``): no safe default exists, so an
#:   absent/empty parameter returns a handled 400 *before* any transform or
#:   sink runs (PA-0053's "handled 4xx before the sink" branch).
#: * ``html_row_template`` (``single_statement``): render the found/not-found
#:   row through this Django template (inside the shared layout) instead of
#:   the default ``JsonResponse`` tail -- the Django analogue of
#:   ``php_laravel``'s ``html_row_view`` tail flag (CC-LAB-0239/0240).
#: * ``page_template`` (page sinks): the Django template a converted page's
#:   sink renders its result into.
#: * ``get_form_template``/``get_form_context`` (``render_only``): a
#:   POST-processing page answers any non-POST request by rendering its form
#:   page, before the source/transform/sink run at all.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    # CC-LAB-0242: an illustrative JSON API, left JSON; `default_value`
    # folded in from the PA-0053 bare-GET sweep (BUG-0052) -- its vulnerable
    # twin concatenated `str(None)` into SQL and 500'd on a bare GET.
    "/api/products": {
        "var_name": "id", "param_name": "id", "table": "products", "column": "id",
        "default_value": "1",
    },
    # PicTrail's real post-detail lookup (CC-LAB-0092, Phase C's first
    # real page) -- a distinct `posts` table, not a reuse of the
    # illustrative `/api/products` table above, per that entry's own
    # "thematically-accurate table" note. CC-LAB-0242: a real HTML page in
    # the shared layout (`pages/post_detail.html`, designed found/not-found
    # byte delta, R3), defaulting to post 1 when `?id=` is absent -- the
    # same `?? '1'` default Lane 1's `/product.php`/`/blog_post.php` got.
    "/post": {
        "var_name": "id", "param_name": "id", "table": "posts", "column": "id",
        "default_value": "1",
        "html_row_template": "pages/post_detail.html",
    },
    "/api/login": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    },
    "/api/profile": {"var_name": "bio", "stored_expr": "_read_stored_bio()", "css_class": "bio"},
    # PicTrail's real comments page (CC-LAB-0093, Phase C's second real
    # page) -- a distinct `comments` table.
    "/post/comments": {"var_name": "comment", "stored_expr": "_read_stored_comment()"},
    # PicTrail's real link-preview upload flow (CC-LAB-0094, Phase C's
    # third real page) -- ports docs/research/corpus-examples/ssrf/
    # python/{vulnerable,idiomatic}-oembed-unfurl-4.py almost verbatim.
    # CC-LAB-0242: stays a JSON `api` (its client page is the site layer's
    # `/upload`); `required_param` -- the corpus source
    # (`vulnerable-oembed-unfurl-4.py`'s `unfurl_link(message_url: str)`)
    # defines no default URL, and any default would make the vulnerable
    # twin fetch it, so a bare GET is a handled 400 before the sink (R4).
    "/upload/link-preview": {"var_name": "url", "param_name": "url", "required_param": True},
    # PicTrail's real account-settings page (CC-LAB-0095, Phase C's
    # fourth real page) -- the whole-POST-body mass-assignment shape
    # needs no `param_name` (the source reads the entire body, not one
    # named field). CC-LAB-0242: GET renders the real settings form (its
    # one publicly-settable field, `bio` -- `_PUBLIC_SETTINGS_FIELDS`);
    # POST processes it and re-renders the page with a saved notice.
    "/settings": {
        "var_name": "settings_fields",
        "page_template": "pages/settings.html",
        "get_form_template": "pages/settings.html",
        "get_form_context": '{"bio": _read_stored_bio(), "saved": False}',
    },
    # PicTrail's real explore/search page (CC-LAB-0096, Phase C's fifth
    # real page). CC-LAB-0242: a real listing page; defaults to sorting by
    # `id`, the same key the secure twin's allowlist already falls back to.
    # The page never echoes the `sort` value back (so the only
    # body-visible effect of the parameter is the row order, R1b/R6).
    "/explore": {
        "var_name": "sort", "param_name": "sort",
        "default_value": "id",
        "page_template": "pages/explore.html",
    },
    # PicTrail's real inbox/DM page (CC-LAB-0097, Phase C's sixth real
    # page) -- the payload param models the inbox message's own
    # serialized-cache-data field. CC-LAB-0242: GET renders the inbox with
    # its compose form; POST delivers the message and re-renders the page.
    "/inbox": {
        "var_name": "payload", "param_name": "payload",
        "page_template": "pages/inbox.html",
        "get_form_template": "pages/inbox.html",
        "get_form_context": "{}",
    },
}

#: Cell IDs that are **real, ground-truth-bearing pages** (`CC-LAB-0092`,
#: Phase C) rather than illustrative cells: served at their own
#: ``cell.route.path`` (stripped of the leading slash) instead of the
#: generic ``generated/{cell_slug}/`` pattern every illustrative cell
#: uses -- mirroring, at a much smaller scale, ``php_laravel``'s own "a
#: real page keeps its own exact URL" convention (``_served_route_for``),
#: without porting that mechanism's full generality (no
#: ``_CANONICAL_CELL_KEY``/twin-URL machinery -- this project's `django`
#: stack has exactly one real-URL-owning cell so far). A cell's *secure*
#: twin is deliberately not added here: ground truth only ever needs to
#: describe the one real, exploitable page, matching how a ``php_current``
#: secure twin does not necessarily get its own ``PFF-`` case either.
#: (CC-LAB-0242: the secure twin now gets its own twin-suffixed URL via
#: :data:`_REAL_PAGE_TWIN_CELL_IDS` -- still never this set's exact path.)
_REAL_PAGE_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-DJ-0007",
        "LABGEN-DJ-0009",
        "LABGEN-DJ-0011",
        "LABGEN-DJ-0013",
        "LABGEN-DJ-0015",
        "LABGEN-DJ-0017",
    }
)

#: CC-LAB-0242 (FR-LAB-160, R1 -- branch (a), see ``requirements.md``'s
#: FR-LAB-160 "R1 sign-off"): each real page's **secure twin**, served at a
#: twin-suffixed variant of the real page's own URL (:func:`_twin_url_for`,
#: ``/post`` -> ``/post.labgen-dj-0008``) instead of the generic
#: ``generated/{cell_slug}/`` pattern -- mirroring ``php_laravel``'s own
#: ``_twin_url_for`` convention (``/login.php`` ->
#: ``/login.labgen-pla-0002.php``), so both twins of a page live in the same
#: URL family and can be compared page-for-page (the shared layout's
#: byte-identical-across-twins contract). Superseding CC-LAB-0092's
#: "secure twin deliberately not pinned" note: ground truth still describes
#: only the vulnerable cell (the twin has no ground-truth case), exactly as
#: before -- only the twin's URL changed. Every entry must share its
#: ``route.path`` with exactly one :data:`_REAL_PAGE_CELL_IDS` cell (asserted
#: offline, `tests/test_labgen_django_browsable.py`).
_REAL_PAGE_TWIN_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-DJ-0008",
        "LABGEN-DJ-0010",
        "LABGEN-DJ-0012",
        "LABGEN-DJ-0014",
        "LABGEN-DJ-0016",
        "LABGEN-DJ-0018",
    }
)

#: CC-LAB-0242: the site layer's own fixed routes (hand-written views in the
#: checked-in skeleton's ``fuzlab_django_lab/views/site.py``), registered
#: ahead of every cell's route by :meth:`DjangoEmitter.render_route_accumulator`.
#: ``(url_path, view_name, route_name)``.
_SITE_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("", "home", "home"),
    ("catalog", "catalog", "catalog"),
    ("upload", "upload_client", "upload"),
)


def _twin_url_for(real_url: str, cell_id: str) -> str:
    """The twin-suffixed URL a real page's secure twin is served at, e.g.
    ``/post`` + ``LABGEN-DJ-0008`` -> ``/post.labgen-dj-0008`` -- the same
    shape ``php_laravel``'s own ``_twin_url_for`` produces for a
    suffix-less path (Django routes here carry no ``.php``-style suffix)."""
    return f"{real_url}.{cell_id.lower()}"


def served_url_for(cell: Cell) -> str:
    """The URL path ``cell`` is actually served at -- **the one shared
    derivation** of that fact (PA-0003/PA-0021), used by
    :meth:`DjangoEmitter.render_route_accumulator` and by tests alike:

    * a real page's vulnerable cell (:data:`_REAL_PAGE_CELL_IDS`): its own
      ``route.path`` (``/post``);
    * that page's secure twin (:data:`_REAL_PAGE_TWIN_CELL_IDS`):
      :func:`_twin_url_for` (``/post.labgen-dj-0008``);
    * every illustrative cell: ``/generated/{cell_slug}/``.
    """
    if cell.cell_id in _REAL_PAGE_CELL_IDS:
        return cell.route.path
    if cell.cell_id in _REAL_PAGE_TWIN_CELL_IDS:
        return _twin_url_for(cell.route.path, cell.cell_id)
    return f"/generated/{_snake_case(cell.cell_id)}/"


def _get_linkable(cell: Cell) -> bool:
    """Whether a plain ``GET`` of ``cell``'s served URL is a real page a
    visitor can follow a link to: a ``GET`` route, or a POST-processing
    page that renders its own form on ``GET`` (``get_form_template``). A
    POST-only illustrative API (``/api/login``) is not linked from
    ``/catalog``."""
    if cell.route.method.upper() == "GET":
        return True
    return "get_form_template" in _ROUTE_PARAMS.get(cell.route.path, {})


class DjangoEmitter(Emitter):
    """Renders a :class:`Cell` to a single Django view module via module
    composition, Tier-A scope (Phase A + Phase B).

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching ``php_current``'s/``node_express``'s "fail loud on
    an authoring gap" discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for django "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: django has no route profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        cell_slug = _snake_case(cell.cell_id)
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle_{cell_slug}"
        ctx["cell_slug"] = cell_slug

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: django has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        body = _indent_block(
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "    ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        # CC-LAB-0091: any cell whose real HTTP method is not GET gets
        # @csrf_exempt on its generated view. Gated on the cell's own
        # `route.method` (never on which complexity/shape renders it) so a
        # future POST-shaped cell on a *different* complexity than
        # single_statement cannot silently ship undecorated and hit a live
        # 403 -- see CC-LAB-0091's own change-control entry for the
        # php_laravel-precedent reasoning (its skeleton disables Laravel's
        # default CSRF middleware for the identical reason: the real pages
        # every stack here models have no CSRF framework of their own).
        view_code = complexity_result.code
        if cell.route.method.upper() != "GET":
            view_code = "@csrf_exempt\n" + view_code
        py_source = (
            f"# Generated by fuzzlab.labgen.emitters.django for cell {cell.cell_id}\n"
            f"# Route: {cell.route.method} {cell.route.path}\n"
            f"# Module composition: {composition}\n"
            "\n"
            "import base64\n"
            "import hashlib\n"
            "import ipaddress\n"
            "import json\n"
            "import pickle\n"
            "import socket\n"
            "from urllib.parse import urlparse\n"
            "\n"
            "import requests\n"
            "\n"
            "from django.db import connection\n"
            "from django.http import HttpResponse, JsonResponse\n"
            "from django.shortcuts import render\n"
            "from django.utils.html import escape\n"
            "from django.utils.safestring import mark_safe\n"
            "from django.views.decorators.csrf import csrf_exempt\n"
            "\n"
            "\n"
            f"{_READ_STORED_BIO_HELPER}"
            "\n"
            f"{_READ_STORED_COMMENT_HELPER}"
            "\n"
            f"{_KNOWN_PROFILE_COLUMNS}"
            f"{_PUBLIC_SETTINGS_FIELDS}"
            f"{_ORDER_BY_ALLOWLIST}"
            "\n"
            f"{view_code}"
        )
        path = f"fuzlab_django_lab/views/{cell_slug}.py"
        view_file = EmittedFile(path=path, content=py_source.encode("utf-8"), role="view")

        # CC-LAB-0093: a cell rendering through Django's real template
        # engine also emits its own companion template file -- the
        # template's content is a fixed, byte-identical constant (never
        # rendered through this emitter's own Jinja2 module-composition
        # system, which shares Django's own `{{ }}` delimiter -- see this
        # module's own `_COMMENT_TEMPLATE_HTML` docstring), so it is the
        # same for the vulnerable and secure twin alike, keeping the
        # minimal-pair diff confined to the transform region.
        if modules.sink == "django_template_render":
            template_path = f"fuzlab_django_lab/templates/{cell_slug}.html"
            template_file = EmittedFile(
                path=template_path,
                content=_COMMENT_TEMPLATE_HTML.encode("utf-8"),
                role="template",
            )
            return (view_file, template_file)

        return (view_file,)

    def render_route_accumulator(self, cells: list[Cell]) -> EmittedFile:
        """Build ``fuzlab_django_lab/urls.py`` -- the ``route``-category
        accumulator (cardinality ``accumulator`` per Addendum D) -- fed by
        one fragment per **supported** cell, sorted by ``cell_id`` at
        render time. Mirrors
        ``NodeExpressEmitter.render_route_accumulator`` exactly (deliberately
        not part of :meth:`render`, for the same reason that module's
        docstring gives: the accumulator's real cardinality is "one file,
        fed by every cell," which a single ``render(cell)`` call cannot
        express without either breaking the shared Tier-3 "no two cells
        emit the same path" invariant, or silently overwriting the file).
        Two calls with an equal ``cells`` sequence (as a set -- input order
        does not matter, only sorted ``cell_id`` does) produce
        byte-identical output.
        """
        supported = [c for c in cells if self.supports(c.vuln_class, c.sink_context)]
        by_id = sorted(supported, key=lambda c: c.cell_id)

        import_lines: list[str] = []
        urlpattern_lines: list[str] = []
        catalog_lines: list[str] = []
        for c in by_id:
            cell_slug = _snake_case(c.cell_id)
            handler_name = f"handle_{cell_slug}"
            import_lines.append(
                render_route_import_line(handler_module=cell_slug, handler_name=handler_name).rstrip("\n")
            )
            # CC-LAB-0092: a real, ground-truth-bearing cell is served at
            # its own declared route path, never the generic
            # `generated/{cell_slug}/` pattern -- so the URL a real page's
            # ground truth names is the URL that is actually served, not
            # a derived/guessed one. CC-LAB-0242 (R1, branch (a)): its
            # secure twin at the twin-suffixed variant of that path. One
            # shared derivation, `served_url_for` (PA-0003/PA-0021).
            served = served_url_for(c)
            url_path = served.lstrip("/")
            urlpattern_lines.append(
                f'    path("{url_path}", {handler_name}, name="{cell_slug}"),  # cell: {c.cell_id}\n'
            )
            catalog_lines.append(
                f'    ("{served}", "{c.cell_id}", "{c.route.method.upper()}", {_get_linkable(c)!r}),\n'
            )

        site_lines = "".join(
            f'    path("{url_path}", {view}, name="{name}"),  # site layer (CC-LAB-0242)\n'
            for url_path, view, name in _SITE_ROUTES
        )
        site_views = ", ".join(sorted(view for _, view, _ in _SITE_ROUTES))

        urls_py = (
            "# Generated by fuzzlab.labgen.emitters.django -- fuzlab_django_lab/urls.py\n"
            "# (route accumulator, CR-LAB-0001 Addendum D). Route lines below are sorted\n"
            "# by cell ID at render time, never by append/iteration order, so adding one\n"
            "# cell can never reshuffle this file (the whole-lab regeneration determinism\n"
            "# gate).\n"
            "\n"
            "from django.urls import path\n"
            f"from fuzlab_django_lab.views.site import {site_views}\n"
            + ("".join(f"{line}\n" for line in import_lines) if import_lines else "")
            + "\n"
            "# CC-LAB-0242: (served URL, cell ID, HTTP method, linked from /catalog)\n"
            "# for every generated cell -- read by the site layer's /catalog page.\n"
            "CATALOG = [\n"
            + "".join(catalog_lines)
            + "]\n"
            "\n"
            "urlpatterns = [\n"
            + site_lines
            + "".join(urlpattern_lines)
            + "]\n"
        )
        return EmittedFile(
            path="fuzlab_django_lab/urls.py", content=urls_py.encode("utf-8"), role="route"
        )


def _snake_case(cell_id: str) -> str:
    """``LABGEN-DJ-0001`` -> ``labgen_dj_0001`` -- a valid Python
    identifier/module-name fragment derived deterministically from the cell
    ID (Addendum D's "per-cell identifiers are derived from the cell ID"
    rule; Python module names cannot contain hyphens, unlike JS's
    ``_pascal_case``/PHP's class-name convention)."""
    return cell_id.lower().replace("-", "_")


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as ``php_current._indent_block``/
    ``node_express._indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
