"""``php_laravel``: the second PHP emitter, Laravel/Eloquent/Blade idiom
(``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.3).

Built in two lanes:

* **L-P3.3a (foundation, steps 1/3/4/5)** --
  :class:`~fuzzlab.labgen.emitters.php_laravel.stack_env.StackEnv` (pinned
  framework version, digest-pinned base image, ``is_multi_file``, a scaffold
  ``.env`` with debug mode forced off), the ``route``-category accumulator
  for ``routes/web.php``
  (:mod:`fuzzlab.labgen.emitters.php_laravel.route_accumulator`, sorted by
  cell ID per ``CR-LAB-0001`` Addendum D), and a deliberately minimal
  one-shape emitter proving the scaffold renders and passes Tier 0 + Tier 3.
* **L-P3.3b (this lane, step 2)** -- the **full-depth module inventory**.
  Laravel is the one stack that gets *every* shape ``php_current`` supports,
  per the plan's own reasoning ("Phase 1's hard-shape work on
  ``php_current`` is directly portable here once it exists"):

  =========================================  ======================================
  ``(vuln_class, sink_context.family)``      Laravel/Eloquent/Blade rendering
  =========================================  ======================================
  ``sqli`` / ``sql_numeric_literal``         ``DB::select`` raw vs. bound ``?``
  ``sqli`` / ``sql_string_literal``          builder ``whereRaw()`` vs. ``where()``
  ``sqli`` / ``sql_identifier``              ``orderByRaw()`` (identifier position)
  ``sqli`` / ``sql_join_alias``              alias substituted 3x in one statement
  ``xss``  / ``html_body``                   Blade view, raw echo
  ``xss``  / ``url_javascript_scheme``       Blade view, ``javascript:`` URL
  ``xss``  / ``html_attribute_unquoted``     Blade view, unquoted attribute
  =========================================  ======================================

  Rendering is **module composition**, per ``CR-LAB-0001`` Addendum C, over
  this emitter's *own* registries
  (:mod:`fuzzlab.labgen.emitters.php_laravel.modules`): nothing is imported
  from or added to :mod:`fuzzlab.labgen.modules` (``php_current``'s
  plain-PHP/PDO idiom, another lane's files) and nothing here touches
  :mod:`fuzzlab.labgen.emitters.php_current`. See that module's docstring for
  the two load-bearing decisions this port rests on -- why the registry
  *names* are the project's shared composition vocabulary (the shared
  minimal-pair checker classifies composition positions through
  ``fuzzlab.labgen.modules``' registries and raises for a name it cannot
  find), and why the HTML sinks echo raw in Blade while the
  ``html_entity_escape`` transform applies ``e()`` in the controller.

An HTML-sink cell is a **two-file cell** on this stack: a controller
(``role="controller"``) plus its own Blade view (``role="view"``), which is
what "ported to Laravel idiom" actually means for an XSS shape -- a Laravel
controller returns a view, it does not ``echo``. Both files carry the same
``// Module composition: ...`` provenance line, so
:mod:`fuzzlab.labgen.minimal_pair` can evaluate the pair invariant on each
of them (the view file's provenance block is a raw ``<?php`` comment header,
which Blade passes through, rather than a ``{{-- --}}`` Blade comment, since
that checker looks for a ``//`` comment line).

**Deliberately not carried by this lane, named rather than glossed over:**

* ``Cell.context_depth`` other than ``"direct"`` (``same_file_helper``,
  ``cross_file``, ``stored_second_order``) and, with it, ``sink_endpoint``.
  ``php_current`` renders those (``CC-LAB-0042``); porting the depth
  fragments to Laravel is a separate axis from this lane's shape inventory,
  so :meth:`LaravelEmitter.render` **raises** for a non-``direct`` cell
  rather than silently rendering it as ``direct`` and mislabelling the depth
  a corpus record claims. Tracked as an open question in
  ``docs/components/01-target-lab/requirements.md`` §8.
* Real ``puppy-fort-factory/`` page reproduction (§4.3 step 6) -- lane
  L-P3.3c, which depends on this one. Every route below is an *illustrative*
  Laravel page, and no ``lab/ground-truth/`` label claims otherwise.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.emitters.php_laravel.modules import (
    COMPLEXITIES,
    SINKS,
    SOURCES,
    TRANSFORMS,
    VIEW_SINKS,
)
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator
from fuzzlab.labgen.emitters.php_laravel.stack_env import PHP_LARAVEL_STACK_ENV, StackEnv
from fuzzlab.labgen.schema import Cell, SinkContext

__all__ = ["LaravelEmitter", "PHP_LARAVEL_STACK_ENV", "StackEnv"]


class _ModuleSet(NamedTuple):
    """Which source/sink/complexity module a ``(vuln_class,
    sink_context.family)`` shape renders with. The transform is never fixed
    here -- it always comes from the cell's own ``transform`` pipeline, per
    op, exactly like ``fuzzlab.labgen.verdict.verdict()``'s own ordered walk
    (and exactly like ``php_current``'s ``_MODULE_SET_BY_SHAPE``)."""

    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape. Any
#: pair not listed here is declared unsupported via :meth:`supports`. This is
#: the full-depth inventory (L-P3.3b): every shape ``php_current`` supports.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_param", "sql_numeric_lookup", "single_statement"),
    ("sqli", "sql_string_literal"): _ModuleSet("post_param", "sql_string_literal_lookup", "single_statement"),
    ("xss", "html_body"): _ModuleSet("read_stored_field", "html_body_echo", "render_only"),
    # Identifier/alias/connector-position SQL: the tainted value is a column
    # identifier or a JOIN alias, never a literal value (plan §2.2).
    ("sqli", "sql_identifier"): _ModuleSet("get_param", "sql_identifier_order_by", "single_statement"),
    ("sqli", "sql_join_alias"): _ModuleSet("get_param", "sql_join_alias_lookup", "single_statement"),
    # Escaping-context-mismatch HTML: correct escaping applied for the wrong
    # context -- an escaped value inside a `javascript:` URL, or inside an
    # unquoted attribute whose whitespace boundary escaping does not protect.
    ("xss", "url_javascript_scheme"): _ModuleSet("get_param", "html_js_url_echo", "render_only"),
    ("xss", "html_attribute_unquoted"): _ModuleSet("get_param", "html_attribute_unquoted_echo", "render_only"),
}

#: Page-profile key that **pins** the URL a cell of that page is served at,
#: instead of this stack's default cell-ID-derived ``/cell/<slug>`` URL.
#:
#: Exists for exactly one reason (``docs/LAB_IMPLEMENTATION_PLAN.md``
#: §4.3.6.6a, lane L-P3.3c): a *migrated* real ``puppy-fort-factory/`` page
#: must keep the real app's exact URL, ``.php`` suffix included, because
#: T-LAB0.9's additive-only regression gate
#: (:mod:`fuzzlab.labgen.regression_gate`) treats a ``PFF-`` case that moves to
#: a different ``url`` as a build-breaking *relocation*. Laravel routes are
#: arbitrary strings, so ``Route::get('/contact.php', ...)`` costs nothing
#: technically and keeps every URL in ``lab/ground-truth/labels.json``,
#: ``injection-points.json`` and ``expectedresults.csv`` valid unchanged.
#:
#: A pinned URL is only safe where one cell owns the page -- which is what
#: makes it usable for the secure-only migrated cells (§4.3.6.3's
#: "secure-only cells are legal" finding) and why
#: :meth:`LaravelEmitter.route_fragment_for` refuses a second cell claiming
#: the same pinned URL rather than emitting two ``Route::get`` lines for one
#: path. Illustrative pages pin nothing and keep the cell-ID-derived URL, so a
#: vulnerable cell and its secure twin still coexist as two distinct routes.
_URL_PATH_KEY = "url_path"

#: Page-profile key that overrides a shape's default *source* module -- the
#: same mechanism (and the same reasoning) as ``php_current``'s: one
#: ``(vuln_class, sink_context.family)`` shape can be reached by two
#: different taint origins on two different pages (a request parameter on
#: one, an already-stored field on another), and source origin is render-only
#: metadata that must never fork the verdict-relevant shape vocabulary
#: (``class`` x ``sink_context.family``) the safety matrix is keyed on.
_SOURCE_OVERRIDE_KEY = "source_override"

#: Per-page static context (table/column/parameter names, the stored-field
#: expression an HTML cell reads, the identifier allowlist and the two
#: value-differing columns the build-time identifier-SQLi oracle probes with)
#: that an emitter needs beyond the verdict-relevant Cell IR. Keyed by
#: ``cell.route.path``, since a vulnerable cell and its twins share one
#: logical page and therefore one profile.
#:
#: Two kinds of page live here, and the difference is deliberate:
#:
#: * **Illustrative pages** (the L-P3.3a/L-P3.3b inventory) use idiomatic,
#:   extension-less Laravel routes -- a Laravel app is router-dispatched, not
#:   filesystem-routed -- and are distinct from ``php_current``'s own
#:   ``/catalog.php``-style profiles, which this emitter deliberately does not
#:   read.
#: * **Migrated real ``puppy-fort-factory/`` pages** (lane L-P3.3c) keep the
#:   real app's exact ``.php``-suffixed path, both as the profile key and, via
#:   :data:`_URL_PATH_KEY`, as the URL the generated route serves -- because
#:   the ``PFF-`` ground-truth cases those cells reproduce are labelled at
#:   those URLs and T-LAB0.9's gate forbids relocating them (§4.3.6.6a).
_PAGE_PROFILES: dict[str, dict[str, Any]] = {
    # The original L-P3.3a illustrative pair (unchanged, kept rendering).
    "/example/product": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
    # POST string-literal lookup. `password_var`/`password_param` are sink
    # boilerplate (an already-hashed secret), not a second injection point.
    "/login": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    },
    # Stored value rendered into an HTML body -- the taint origin is storage,
    # so this profile overrides the shape's default `get_param` source.
    "/example/profile": {
        "var_name": "bio",
        "stored_model": "\\App\\Models\\User",
        "owner_param": "user",
        "stored_expr": "$storedOwner->bio",
        "css_class": "bio",
        "source_override": "read_stored_field",
    },
    # `?sort=` selects an ORDER BY *column identifier*. `allowed_identifiers`
    # is what the `identifier_allowlist` transform allows (its first entry
    # doubles as the safe fallback); `column_a`/`column_b` are the two real,
    # value-differing columns the build-time identifier-SQLi oracle probes
    # with (see `fuzzlab.labgen.emitters.php_laravel.identifier_sqli`).
    "/catalog": {
        "var_name": "sort",
        "param_name": "sort",
        "table": "products",
        "column": "name",
        "allowed_identifiers": ("id", "name", "price"),
        "column_a": "name",
        "column_b": "price",
    },
    # `?alias=` names a JOIN alias -- a connector position, substituted three
    # times in one statement.
    "/inventory": {
        "var_name": "alias",
        "param_name": "alias",
        "table": "inventory",
        "join_table": "inventory",
        "column": "sku",
        "join_column": "parent_id",
        "allowed_identifiers": ("i2", "i3"),
        "column_a": "i2",
        "column_b": "i3",
    },
    # `?url=` is echoed inside a `javascript:` URL.
    "/share-link": {"var_name": "link", "param_name": "url", "css_class": "share"},
    # `?theme=` is echoed into an unquoted HTML attribute.
    "/theme": {
        "var_name": "theme",
        "param_name": "theme",
        "css_class": "theme",
        "attr_name": "theme",
        "attr_default": "default",
    },
    # --- migrated real puppy-fort-factory pages (lane L-P3.3c-G5) ----------
    # The two secure-only escaped-echo form pages, reproduced in Laravel/Blade
    # idiom: `PFF-1005` (`contact.php`, POST `message`) and `PFF-1006`
    # (`newsletter.php`, POST `email`). Both real pages echo the submitted
    # value straight back through the app's `e()` helper and write nothing to
    # the database, so the shape is `xss`/`html_body` reached from a POST body
    # parameter -- hence the `post_param` source override (the shape's default
    # source, `read_stored_field`, is the stored-XSS origin, which neither page
    # has). They carry `url_path`, so each is served at the real app's exact
    # `.php` URL (see :data:`_URL_PATH_KEY`).
    "/contact.php": {
        "var_name": "message",
        "param_name": "message",
        # The real page wraps the reflected message in
        # `<blockquote class="bio">`; the sink fragment's element is a `div`,
        # which is not verdict-relevant (the sink *context family* -- an HTML
        # body position -- is what the safety matrix is keyed on).
        "css_class": "bio",
        "source_override": "post_param",
        "url_path": "/contact.php",
    },
    "/newsletter.php": {
        "var_name": "email",
        "param_name": "email",
        # Real page: `<p class="notice ok">Thanks! We'll send fort news to
        # <?= e($email) ?>.</p>`.
        "css_class": "notice ok",
        "source_override": "post_param",
        "url_path": "/newsletter.php",
    },
}

#: The one controller method name every generated controller uses. Stable
#: across a minimal pair's twins on purpose (``minimal_pair
#: .check_identifier_stability``'s rule): per-cell identity is carried by the
#: per-cell controller *class* and route URL, both derived from the cell ID.
_METHOD_NAME = "show"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _cell_slug(cell_id: str) -> str:
    """A lowercase, hyphen-joined slug derived from ``cell_id``, e.g.
    ``LABGEN-PL-0001`` -> ``labgen-pl-0001``. Used for the controller class
    name, the route URL and the Blade view name, so all three are traceable
    to the same cell and, per Addendum D's per-cell-identifier rule, never a
    generic/shared name -- every cell (including a secure twin, a distinct
    cell in its own right) gets its own slug from its own ID, the same
    precedent ``php_current``'s ``handler_name`` already sets."""
    return _SLUG_RE.sub("-", cell_id.lower()).strip("-")


def _controller_class_for(cell_id: str) -> str:
    """PascalCase controller class name derived from ``cell_id``, e.g.
    ``LABGEN-PL-0001`` -> ``LabgenPl0001Controller``."""
    parts = _cell_slug(cell_id).split("-")
    return "".join(p.capitalize() for p in parts if p) + "Controller"


def _url_path_for(cell_id: str, route_path: str | None = None) -> str:
    """The route URL this cell is served at.

    Derived from ``cell_id`` by default, not ``cell.route.path`` verbatim --
    see ``fuzzlab.labgen.emitters.php_laravel.route_accumulator``'s module
    docstring for why a twin needs its own URL to coexist in one build (and
    ``identifier_sqli.py`` for the one place that difference matters to an
    oracle).

    The one exception, and the reason ``route_path`` exists: a page profile may
    **pin** the URL via :data:`_URL_PATH_KEY`, which the migrated real pages do
    so their ``PFF-`` cases stay at the URLs ``lab/ground-truth/`` labels them
    at (§4.3.6.6a). Callers pass the cell's logical page so this function can
    look that pin up; passing nothing keeps the pre-L-P3.3c behavior exactly.
    """
    if route_path is not None:
        pinned = _PAGE_PROFILES.get(route_path, {}).get(_URL_PATH_KEY)
        if pinned is not None:
            return str(pinned)
    return f"/cell/{_cell_slug(cell_id)}"


def _view_name_for(cell_id: str) -> str:
    """The Blade view name (dot notation) for a view-rendering cell."""
    return f"cells.{_cell_slug(cell_id)}"


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free -- no reliance on a Jinja2 filter's own defaults."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)


class LaravelEmitter(Emitter):
    """Renders a :class:`Cell` to a Laravel controller (plus, for an
    HTML-sink cell, its own Blade view) by composing this stack's own
    module registries, and to a ``routes/web.php`` fragment for the
    accumulator.

    Like ``php_current``, :meth:`render` never falls back to a default
    shape/transform/page profile silently -- a shape, op, page or depth this
    emitter has no module or profile for raises, rather than guessing.
    """

    stack_env: StackEnv = PHP_LARAVEL_STACK_ENV

    def __init__(self) -> None:
        self._route_accumulator = RouteAccumulator()
        #: ``pinned url_path -> the cell_id that claimed it``, so two cells of
        #: one migrated real page cannot silently register two ``Route::get``
        #: lines at the same path (see :data:`_URL_PATH_KEY`). Cell-ID-derived
        #: URLs are unique by construction and are not tracked here.
        self._pinned_url_claims: dict[str, str] = {}

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for php_laravel "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        if cell.context_depth != "direct":
            raise ValueError(
                f"{cell.cell_id}: php_laravel renders context_depth 'direct' only, got "
                f"{cell.context_depth!r} -- the depth-hop fragments (pass-through helper, "
                "cross-file helper, stored/second-order routing) are not ported to Laravel "
                "idiom yet, and rendering this cell as 'direct' would mislabel the depth its "
                "corpus record claims (fail loud rather than silently flatten the axis)"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        # Mirrors php_current.render()'s own `render_route` choice: the page
        # the tainted value actually executes on. Since this emitter accepts
        # `direct` cells only, `sink_endpoint` is always None here (the schema
        # makes a distinct sink_endpoint biconditional with
        # `stored_second_order`); the expression is kept so the choice is made
        # in one place if/when the depth axis is ported.
        render_route = cell.sink_endpoint if cell.sink_endpoint is not None else cell.route

        if render_route.path not in _PAGE_PROFILES:
            raise ValueError(
                f"{cell.cell_id}: php_laravel has no page profile for route {render_route.path!r} "
                f"-- known routes: {sorted(_PAGE_PROFILES)}"
            )
        ctx: dict[str, Any] = dict(_PAGE_PROFILES[render_route.path])
        # Routing metadata, not rendering context: the pinned URL is consumed by
        # route_fragment_for(), never by a template (same reason
        # `source_override` is popped below).
        ctx.pop(_URL_PATH_KEY, None)
        ctx["method_name"] = _METHOD_NAME
        ctx["view_name"] = _view_name_for(cell.cell_id)

        source_name = ctx.pop(_SOURCE_OVERRIDE_KEY, modules.source)
        if source_name not in SOURCES:
            raise ValueError(
                f"{cell.cell_id}: php_laravel page profile for {render_route.path!r} names an "
                f"unknown source module {source_name!r} -- known sources: {sorted(SOURCES)}"
            )
        source_result = SOURCES[source_name].render(ctx)
        ctx = source_result.context

        # An empty transform pipeline means "identity" (the raw value is used
        # as-is); every op in a non-empty pipeline runs in order, each free to
        # publish new context keys for the next module/the sink -- the same
        # ordered walk fuzzlab.labgen.verdict.verdict() performs over
        # pipeline.ops. `identity` is *rendered* rather than skipped so a
        # cell and its transform-emptied twin occupy the same composition
        # positions (fuzzlab.labgen.minimal_pair compares them pairwise).
        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: php_laravel has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)
        renders_view = modules.sink in VIEW_SINKS

        composition = " -> ".join((source_name, *applied_ops, modules.sink, modules.complexity))
        provenance = (
            f"// Generated by fuzzlab.labgen.emitters.php_laravel for cell {cell.cell_id}\n"
            f"// Manifest cell.route.path: {cell.route.path}\n"
            f"// Module composition: {composition}\n"
        )

        # For a view-rendering cell the sink's code *is* the Blade view body,
        # so the controller body is source + transforms only and the
        # complexity module closes it by handing the value to that view.
        body_fragments = [source_result.code, *transform_code_blocks]
        if not renders_view:
            body_fragments.append(sink_result.code)
        body = _indent_block("\n".join(body_fragments), "        ")
        method_code = COMPLEXITIES[modules.complexity].render({**ctx, "body": body}).code

        controller_class = _controller_class_for(cell.cell_id)
        imports = ["use Illuminate\\Http\\Request;"]
        if not renders_view:
            imports.append("use Illuminate\\Support\\Facades\\DB;")
        controller_source = (
            "<?php\n"
            + provenance
            + "\n"
            "namespace App\\Http\\Controllers;\n"
            "\n"
            + "".join(f"{line}\n" for line in imports)
            + "\n"
            f"class {controller_class} extends Controller\n"
            "{\n"
            f"{method_code}"
            "}\n"
        )
        controller_path = self.stack_env.file_roles["controller"].format(
            cell_slug=controller_class[: -len("Controller")]
        )
        files = [
            EmittedFile(
                path=controller_path, content=controller_source.encode("utf-8"), role="controller"
            )
        ]
        if renders_view:
            # A raw `<?php ... ?>` provenance header rather than a Blade
            # `{{-- --}}` comment: Blade passes raw PHP tags through, and
            # fuzzlab.labgen.minimal_pair needs a `//` comment line to read
            # this file's composition from (see the class docstring).
            view_source = "<?php\n" + provenance + "?>\n" + sink_result.code
            view_path = self.stack_env.file_roles["view"].format(cell_slug=_cell_slug(cell.cell_id))
            files.append(
                EmittedFile(path=view_path, content=view_source.encode("utf-8"), role="view")
            )
        return tuple(files)

    def route_fragment_for(self, cell: Cell) -> str:
        """This cell's ``routes/web.php`` fragment (accumulator category, one
        per cell -- see ``route_accumulator.py``'s module docstring for why
        this is not part of :meth:`render`'s own return value)."""
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(f"{cell.cell_id}: unsupported for php_laravel -- see render() for the same check")
        controller_class = _controller_class_for(cell.cell_id)
        render_route = cell.sink_endpoint if cell.sink_endpoint is not None else cell.route
        url_path = _url_path_for(cell.cell_id, render_route.path)
        if url_path != f"/cell/{_cell_slug(cell.cell_id)}":
            claimant = self._pinned_url_claims.setdefault(url_path, cell.cell_id)
            if claimant != cell.cell_id:
                raise ValueError(
                    f"{cell.cell_id}: page profile for {render_route.path!r} pins the route URL "
                    f"{url_path!r}, which cell {claimant!r} already claims -- a pinned URL (a "
                    "migrated real page keeping its real `.php` URL, §4.3.6.6a) can be owned by "
                    "exactly one cell, so a page needing a vulnerable cell *and* a secure twin "
                    "must not pin one (both twins would register the same Route::get path)"
                )
        return self._route_accumulator.fragment_for_cell(
            cell_id=cell.cell_id,
            controller_class=controller_class,
            url_path=url_path,
        )

    def render_scaffold(self) -> EmittedFiles:
        """The per-stack scaffold files (rendered once per build, never per
        cell) -- ``StackEnv.scaffold_files`` names the paths; this method is
        what actually renders their content."""
        return (
            EmittedFile(path=".env", content=self.stack_env.env_file_content(), role="scaffold"),
            EmittedFile(path="public/index.php", content=self.stack_env.index_php_content(), role="scaffold"),
        )
