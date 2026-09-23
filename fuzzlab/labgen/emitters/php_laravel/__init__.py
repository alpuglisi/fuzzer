"""``php_laravel``: the second PHP emitter, Laravel/Eloquent/Blade idiom
(``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.3).

Built in four lanes:

* **L-P3.3a (foundation, steps 1/3/4/5)** --
  :class:`~fuzzlab.labgen.emitters.php_laravel.stack_env.StackEnv` (pinned
  framework version, digest-pinned base image, ``is_multi_file``, a scaffold
  ``.env`` with debug mode forced off), the ``route``-category accumulator
  for ``routes/web.php``
  (:mod:`fuzzlab.labgen.emitters.php_laravel.route_accumulator`, sorted by
  cell ID per ``CR-LAB-0001`` Addendum D), and a deliberately minimal
  one-shape emitter proving the scaffold renders and passes Tier 0 + Tier 3.
* **L-P3.3b (step 2)** -- the **full-depth module inventory**. Laravel is
  the one stack that gets *every* shape ``php_current`` supports, per the
  plan's own reasoning ("Phase 1's hard-shape work on ``php_current`` is
  directly portable here once it exists"):

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
  ``xss``  / ``html_attribute_quoted``       Blade view, quoted attribute
  ``xss-dom`` / ``dom_html_sink``             Blade view, client-only ``<script>`` read+write
  =========================================  ======================================

  The last two rows are not L-P3.3b's original set: ``html_attribute_quoted``
  is **L-P3.3c-G6**'s addition (its matrix pair ``(raw_concat,
  html_attribute_quoted)`` did not exist until that lane) and
  ``dom_html_sink`` is **L-P3.3c-DOM**'s (a brand-new family -- the tainted
  value never reaches the server at all). Neither shape exists on
  ``php_current``, so this stack's inventory is a strict superset of
  ``php_current``'s rather than equal to it. ``php_current`` is not the
  migration target (§4.3.6.6b).

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
* **L-P3.3c (step 6, migration) -- six concurrent sub-lanes (G1/G2/G3/G4/G5/G6)
  and one consolidation pass.** Real ``puppy-fort-factory/`` pages are
  reproduced through this emitter, each keeping the real app's exact
  ``.php``-suffixed URL (§4.3.6.6a: T-LAB0.9's additive-only regression gate,
  :mod:`fuzzlab.labgen.regression_gate`, treats a ``PFF-`` case that moves to
  a different URL as a build-breaking relocation). Because the six sub-lanes
  ran concurrently against the same two files, each built its own,
  mutually-incompatible URL-pinning mechanism; **this module now carries the
  one, unified mechanism** the consolidation pass replaced all five with --
  see :data:`_REAL_PAGE_KEY`/:data:`_CANONICAL_CELL_KEY` below and
  ``docs/components/01-target-lab/change-control.md``'s consolidation entry
  for the design choice and its rationale (a human reviewer may want to
  revisit the twin-URL naming convention specifically).

  * **G1** -- ``/product.php`` (PFF-0001), ``/blog_post.php`` (PFF-0006):
    the numeric-literal SQLi shape on two real tables.
  * **G2** -- ``/products.php`` (PFF-1001), ``/api/products.php`` (PFF-1003):
    the catalog listing and its JSON feed, and this emitter's ``view``
    module category (:data:`~fuzzlab.labgen.emitters.php_laravel.modules.VIEWS`,
    first member ``json_view``) for a response whose sink produces data
    rather than markup.
  * **G3** -- ``/login.php`` (PFF-0004 vulnerable / PFF-1008 true-negative),
    ``/register.php`` (PFF-1004): the real auth pages, the first two-cell
    (canonical + twin) real page and the session-establishing/insert-tail
    complexity flags (:data:`_SESSION_LOGIN_KEY`/:data:`_REGISTER_INSERT_KEY`).
  * **G4** -- ``/edit_profile.php`` -> ``/profile.php`` (PFF-0005/PFF-1007):
    the stored second-order pair, the first ``stored_second_order`` cells
    this emitter renders (:data:`SUPPORTED_CONTEXT_DEPTHS`) and the first
    **write** endpoint (:data:`~fuzzlab.labgen.emitters.php_laravel.modules.WRITES`)
    any emitter in this project emits.
  * **G5** -- ``/contact.php`` (PFF-1005), ``/newsletter.php`` (PFF-1006):
    the two secure-only escaped-echo form pages -- the trivial case of the
    unified mechanism (a page with exactly one cell, no twin).
  * **G6** -- ``/search.php`` (PFF-0002/PFF-0003): one ``?q=`` reaching three
    sinks across six cells. **Resolved by ``L-P3.3c-CUT`` (`CC-LAB-0058`/
    `FR-LAB-55`), Path B**: ``LABGEN-PL-RP-0001`` (the ``LIKE``-clause SQLi
    cell, ``PFF-0002``) is canonical at the real ``/search.php`` URL;
    ``PFF-0003`` (the two real XSS reflections at the same URL) is a genuine,
    documented downgrade to ``lab/ground-truth/migration-exemptions.yaml`` --
    see that page's own profile comment and the exemption entry for the full
    reasoning (a real multi-sink page composition was the alternative, ruled
    out as a disproportionate architecture change, not attempted here).

  * **L-P3.3c-DOM** -- ``/reviews.php`` (PFF-0007), ``/feedback.php``
    (PFF-0008): the DOM-based XSS sink class explicitly deferred out of the
    G1-G6 cutover's scope (D-open-2, ``docs/LAB_IMPLEMENTATION_PLAN.md``
    §4.3.6.7) and built here as its own, separately-prioritized lane. A
    genuinely new shape (``dom_html_sink``), not a rendering of any existing
    one: the tainted value (a URL fragment/query-string parameter) is read
    AND written entirely client-side by embedded JavaScript and never
    reaches the server at all (:data:`SOURCES`'s ``dom_url_source`` renders
    no PHP variable read). Now that this lane has landed, the two cases are
    no longer entries in ``lab/ground-truth/migration-exemptions.yaml``.

  Real ``puppy-fort-factory/`` page reproduction depends on L-P3.3b; every
  *other* route in :data:`_PAGE_PROFILES` remains an illustrative Laravel
  page, and no ``lab/ground-truth/`` label claims otherwise.
* **L-P3.3c-CUT prep (`CC-LAB-0053`/`FR-LAB-51`)** -- the parity/cutover
  coverage gate (plan §4.3.6.6 point 3) needs a per-cell ``PFF-`` case
  mapping derivable from this emitter's own metadata rather than doc-comment
  parsing. :func:`ground_truth_cases_for` reads it, extending (never
  duplicating) the existing :data:`_GROUND_TRUTH_CASE_KEY`/
  :data:`_CANONICAL_CELL_KEY` convention with two more page-profile keys for
  the two shapes that convention alone cannot express: one page reproducing
  more than one case by sink family (:data:`_GROUND_TRUTH_CASE_BY_FAMILY_KEY`,
  ``search.php``'s ``PFF-0002``/``PFF-0003``), and a page reproducing an
  extra, non-primary case as boilerplate on every cell rather than one
  canonical cell (:data:`_SECONDARY_GROUND_TRUTH_CASES_KEY`, ``login.php``'s
  ``PFF-1008`` password condition). See
  :mod:`fuzzlab.labgen.cutover_gate` for the gate itself.

**Deliberately not carried by this lane, named rather than glossed over:**

* ``Cell.context_depth`` ``"same_file_helper"``/``"cross_file"``.
  ``php_current`` renders those (``CC-LAB-0042``) with the pass-through-helper
  fragments in :data:`fuzzlab.labgen.modules.DEPTHS`; porting those fragments
  to Laravel idiom is a separate axis from this lane's shape inventory, so
  :meth:`LaravelEmitter.render` **raises** for either depth rather than
  silently rendering it as ``direct`` and mislabelling the depth a corpus
  record claims. See :data:`SUPPORTED_CONTEXT_DEPTHS`.
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
    VIEWS,
    WRITES,
)
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator
from fuzzlab.labgen.emitters.php_laravel.stack_env import PHP_LARAVEL_STACK_ENV, StackEnv
from fuzzlab.labgen.schema import Cell, Route, SinkContext

__all__ = [
    "LaravelEmitter",
    "PHP_LARAVEL_STACK_ENV",
    "SUPPORTED_CONTEXT_DEPTHS",
    "StackEnv",
    "ground_truth_cases_for",
    "served_url_for",
]

#: The ``Cell.context_depth`` levels this emitter renders (§3.5). Public and
#: read by tests rather than restated as a literal there, per PA-0001/PA-0027
#: ("when a predicate or registry in the code can compute the set a test
#: asserts on, the test computes it from that predicate"): the whole-manifest
#: regeneration test derives its cell set from :meth:`LaravelEmitter.supports`
#: *and* this tuple, so widening either one cannot leave that test asserting
#: on a stale subset.
#:
#: ``"stored_second_order"`` was added by lane L-P3.3c-G4 (``CC-LAB-0049``).
#: ``"same_file_helper"``/``"cross_file"`` are still refused: those two depths
#: need the pass-through-helper *fragments* ``php_current`` carries in
#: :data:`fuzzlab.labgen.modules.DEPTHS`, ported to Laravel idiom, which no
#: lane has done. ``stored_second_order`` needs no such fragment -- its depth
#: is expressed structurally, by ``sink_endpoint`` naming a second endpoint --
#: which is exactly why it could be carried here and they could not.
SUPPORTED_CONTEXT_DEPTHS: tuple[str, ...] = ("direct", "stored_second_order")


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
#: the full-depth inventory (L-P3.3b), widened once by L-P3.3c-G6.
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
    # L-P3.3c-G6 (search.php's third sink): a *quoted* HTML attribute. The
    # family existed since Phase 0 but only ever with an `html_entity_escape`
    # op; `lab/safety_matrix.yaml`'s new `(raw_concat, html_attribute_quoted)`
    # row is what makes the unescaped end of it scorable, and this is the
    # first module set on any stack to render it. This shape is the one place
    # php_laravel's inventory is a strict *superset* of php_current's rather
    # than equal to it (php_current is not the migration target; §4.3.6.6b).
    ("xss", "html_attribute_quoted"): _ModuleSet("get_param", "html_attribute_quoted_echo", "render_only"),
    # CC-LAB-0064: mass-assignment (orm_entity_bulk_assign), restoring the
    # "Laravel carries every shape php_current supports" full-depth
    # invariant after php_current gained this shape first.
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet(
        "all_post_params", "orm_entity_bulk_assign", "single_statement"
    ),
    # L-P3.3c-DOM (reviews.php/feedback.php): the tainted value never reaches
    # the server at all, so the source is a no-op (DomUrlSource) and the sink
    # (DomInnerhtmlEchoSink) does the client-side read AND write itself.
    # vuln_class is "xss-dom", not "xss": lab/ground-truth/labels.json labels
    # PFF-0007/PFF-0008 with their own distinct vuln_class (sink_context
    # "dom") precisely because this is not a server-rendered XSS reached
    # through a request parameter -- it is worth keeping the two classes
    # visibly distinct rather than conflating them under "xss".
    ("xss-dom", "dom_html_sink"): _ModuleSet("dom_url_source", "dom_innerhtml_echo", "render_only"),
    # CC-LAB-0133: Huddle Hub's (category 3's Slack pick) webhook-signature-
    # verification cell -- the first non-migration illustrative shape built
    # for a *different* app identity on this stack, per §9.2's ledger note
    # that Huddle Hub reuses php_laravel's paradigm rather than a separate
    # emitter.
    ("webhook_signature_bypass", "webhook_signature_verification"): _ModuleSet(
        "webhook_request", "webhook_signature_verification", "single_statement"
    ),
    # CC-LAB-0134: Huddle Hub's second cell, SSRF via link unfurling. The
    # op selects which transform gates the fixed sink (mirroring
    # CC-LAB-0133's own webhook-signature shape) -- the module composition
    # line's "sink" position is always `server_side_http_fetch`; whichever
    # fetch-validation transform ran decides whether it's ever reached.
    ("ssrf", "server_side_http_fetch"): _ModuleSet(
        "get_param", "server_side_http_fetch", "single_statement"
    ),
    # CC-LAB-0135: Huddle Hub's third and final designed cell, header
    # injection in outgoing-webhook delivery. Same "op selects which
    # transform gates the fixed sink" shape as CC-LAB-0133/0134.
    ("outbound_header_injection", "outbound_http_request_header_value"): _ModuleSet(
        "get_param", "outbound_webhook_delivery", "single_statement"
    ),
    # CC-LAB-0210 (category 5, Booking.com pilot): a server-issued HTTP
    # redirect whose target is a tainted query parameter -- the affiliate/
    # partner-continuation link Booking.com's real checkout flow uses
    # (docs/research/category5-travel-functionality-and-cwe-research.md
    # §1.1/§2.1). Neither `single_statement` nor `render_only` fits this
    # sink (see `HttpRedirectReturnSink`/`TerminalResponseComplexity`'s own
    # docstrings), which is why this was the first shape to name a third
    # complexity module (`redirect_response`, renamed `terminal_response`
    # by `CC-LAB-0211` once a second, unrelated sink family needed the
    # identical wrapper).
    ("open_redirect", "http_redirect_location"): _ModuleSet(
        "get_param", "http_redirect_return", "terminal_response"
    ),
    # CC-LAB-0211 (category 5, Booking.com pilot): a CSV/report export row
    # whose own code is likewise the method's terminal statement -- the
    # Extranet/partner-admin booking-list export view Booking.com's real
    # property-owner surface has (docs/research/category5-travel-
    # functionality-and-cwe-research.md §1.1/§2.1, CWE-1236).
    ("csv_formula_injection", "csv_cell_value"): _ModuleSet(
        "get_param", "csv_export_row", "terminal_response"
    ),
    # CC-LAB-0212 (category 5, Booking.com pilot): a checkout charge whose
    # amount must never be trusted from the client -- Booking.com's real
    # booking-total computation (docs/research/category5-travel-
    # functionality-and-cwe-research.md §1.1/§2.1; grounded in QloApps'
    # real Cart::getOrderTotal() pattern, docs/research/corpus-examples/
    # ecommerce-logic/php/manifest.yaml). Reuses the existing
    # `single_statement` complexity (PaymentChargeInsertSink sets `$rows`
    # rather than returning directly) -- the first of this category's three
    # shapes with no row/value-return complication.
    ("price_integrity_bypass", "payment_charge_amount"): _ModuleSet(
        "post_param", "payment_charge_insert", "single_statement"
    ),
    # CC-LAB-0216 (category 2, CircleFeed -- the Facebook pick, category 2's
    # second app on this emitter after PicTrail/django): a photo/tag detail
    # page, direct-primary-key access control (docs/research/category2-
    # social-ugc-functionality-and-cwe-research.md sec 3 item 4 / sec 6 row
    # 1). This stack's -- and this project's -- first implementation of
    # `lab/safety_matrix.yaml`'s `access_control` family. Sink shared
    # between twins; the vulnerable/secure distinction lives entirely in
    # the transform (`no_ownership_check` vs. `identity_match_before_fetch`).
    ("access_control", "db_row_by_id_lookup"): _ModuleSet(
        "get_param", "db_row_by_id_lookup", "single_statement"
    ),
}

# ---------------------------------------------------------------------------
# Page-profile keys
# ---------------------------------------------------------------------------

#: Page-profile key marking a profile as the reproduction of a **real**
#: ``puppy-fort-factory/`` page rather than an illustrative Laravel one.
#:
#: Its only effect is on route registration, and that effect is the single
#: most load-bearing constraint of the migration lane (plan §4.3.6.6a):
#: T-LAB0.9's additive-only regression gate
#: (:mod:`fuzzlab.labgen.regression_gate`) fails a candidate ground truth that
#: *relocates* an existing case, so a migrated page must be served at the real
#: app's exact URL -- ``.php`` suffix and real HTTP method included -- not at
#: the cell-ID-derived ``/cell/<slug>`` an illustrative cell gets. Laravel
#: routes are arbitrary strings, so this costs nothing technically and keeps
#: every ``PFF-`` URL in ``labels.json``/``injection-points.json``/
#: ``expectedresults.csv`` valid unchanged.
#:
#: **Consolidation history.** Six concurrent sub-lanes (L-P3.3c-G1..G6) each
#: built an independent URL-pinning mechanism against the same two files
#: before any of them could see the others' code. This key, together with
#: :data:`_CANONICAL_CELL_KEY`, is the *single* mechanism the consolidation
#: pass replaced all five with -- generalizing lane G3's design (the most
#: complete: canonical-cell-per-page, HTTP-method support, and an explicit
#: twin-URL convention), of which the already-merged G5 mechanism (a page
#: with exactly one cell) is simply the trivial case. See
#: ``docs/components/01-target-lab/change-control.md``'s consolidation entry
#: for the full rationale.
_REAL_PAGE_KEY = "real_page"

#: Page-profile key naming the one cell on a real page that owns that page's
#: exact URL: the cell whose verdict matches the ``PFF-`` case ``labels.json``
#: places there (the vulnerable cell for ``login.php``, the secure cell for
#: ``register.php``). Required on every ``real_page`` profile -- a profile
#: declaring :data:`_REAL_PAGE_KEY` but omitting this key entirely is a
#: authoring bug and :func:`_served_route_for` raises loud rather than
#: silently leaving the real URL unserved.
#:
#: Two legal values:
#:
#: * **A cell ID.** That cell is served at the page's exact URL and method.
#:   Every *other* cell on the same real page is an authored twin that no
#:   ``labels.json`` case refers to, and is served at a distinct, still-
#:   ``.php``-suffixed variant URL derived from its own cell ID (e.g.
#:   ``/login.labgen-pla-0002.php``) -- so twins coexist in one build without
#:   two routes claiming one path and without inventing a URL a ``PFF-`` case
#:   would then disagree with. This is the twin-URL convention a human
#:   reviewer may want to revisit (see the consolidation change-control
#:   entry); it was an autonomous call made to unblock four lanes' merges,
#:   not a settled design.
#: * **``None``, explicitly.** The page is real but the mechanism
#:   deliberately claims no cell for its exact URL yet. No current profile
#:   uses this value any more -- L-P3.3c-G6's ``search.php`` was the one
#:   example (six cells, three sink behaviors x vulnerable/secure, that
#:   cannot all answer ``GET /search.php``); ``L-P3.3c-CUT`` resolved it
#:   (`CC-LAB-0058`/`FR-LAB-55`) by naming ``LABGEN-PL-RP-0001`` canonical and
#:   exempting the other real case (``PFF-0003``) in
#:   ``lab/ground-truth/migration-exemptions.yaml`` rather than leaving the
#:   choice open -- see that page's own profile comment. ``None`` remains a
#:   legal value of this mechanism (fail-loud still requires the key to be
#:   present, never silently defaulted) for a future page that needs the same
#:   "still open" flag. Every cell of a page using it keeps the illustrative
#:   cell-ID-derived ``/cell/<slug>`` URL, exactly as if :data:`_REAL_PAGE_KEY`
#:   were absent.
_CANONICAL_CELL_KEY = "canonical_cell_id"

#: Page-profile key: the ``lab/ground-truth/`` case ID a real-page profile
#: reproduces (e.g. ``"PFF-0001"``). Purely descriptive provenance metadata --
#: never read by :func:`_served_route_for` or any other routing/rendering
#: decision -- kept here (rather than only in a manifest comment) so a test
#: can assert it never reaches a generated file (FR-LAB-2: emitted artifacts
#: must not leak ground-truth case IDs). Popped from the render context like
#: :data:`_SOURCE_OVERRIDE_KEY`, so no template ever sees it. Optional: an
#: illustrative page profile carries none.
_GROUND_TRUTH_CASE_KEY = "ground_truth_case"

#: Page-profile key (L-P3.3c-CUT prep, `CC-LAB-0053`/`FR-LAB-51`): the extra
#: ``PFF-`` case ids the same page also reproduces at a non-primary,
#: boilerplate position that no cell's own ``sink_context`` names -- e.g.
#: ``login.php``'s already-hashed password condition (``PFF-1008``), rendered
#: verbatim in both login cells' sink statement as the sink's *second*,
#: non-tainted condition (see ``password_var``/``password_param`` above), but
#: never itself a distinct injection point a cell targets. Attributed to
#: *every* cell of the page (canonical or twin), since the boilerplate is
#: structural and identical across them, unlike :data:`_GROUND_TRUTH_CASE_KEY`
#: (attributed only to the one cell :data:`_CANONICAL_CELL_KEY` names).
#: Same descriptive-metadata discipline as :data:`_GROUND_TRUTH_CASE_KEY`:
#: popped before any template renders (never a routing/rendering input), and
#: read only by :func:`ground_truth_cases_for` (the L-P3.3c-CUT coverage
#: gate, :mod:`fuzzlab.labgen.cutover_gate`). Optional: a page with no
#: secondary case carries none.
_SECONDARY_GROUND_TRUTH_CASES_KEY = "secondary_ground_truth_cases"

#: Page-profile key (L-P3.3c-CUT prep, `CC-LAB-0053`/`FR-LAB-51`): a
#: ``sink_context.family -> PFF- case id`` mapping for a real page whose
#: single profile is shared by cells of more than one family and therefore
#: cannot name one page-wide :data:`_GROUND_TRUTH_CASE_KEY` -- G6's
#: ``search.php`` (one ``?q=`` reaching three sink families across six
#: cells, two of which -- the HTML body reflection and the quoted-attribute
#: reflection -- fold into the same ``PFF-0003`` case per ``labels.json``).
#: Read only by :func:`ground_truth_cases_for`; never by
#: :func:`_served_route_for` or any routing/rendering decision, and popped
#: before any template renders, exactly like :data:`_GROUND_TRUTH_CASE_KEY`.
_GROUND_TRUTH_CASE_BY_FAMILY_KEY = "ground_truth_case_by_family"

#: Page-profile key that overrides a shape's default *source* module -- the
#: same mechanism (and the same reasoning) as ``php_current``'s: one
#: ``(vuln_class, sink_context.family)`` shape can be reached by two
#: different taint origins on two different pages (a request parameter on
#: one, an already-stored field on another), and source origin is render-only
#: metadata that must never fork the verdict-relevant shape vocabulary
#: (``class`` x ``sink_context.family``) the safety matrix is keyed on.
_SOURCE_OVERRIDE_KEY = "source_override"

#: Page-profile key that overrides a shape's default *sink* module, keyed by
#: ``sink_context.family`` (L-P3.3c-G6). Keyed by family rather than page-wide
#: because one page profile is shared by every cell of that page, which on
#: ``/search.php`` means three different families: a page-wide override would
#: redirect the HTML cells' sinks too.
#:
#: Same reasoning as :data:`_SOURCE_OVERRIDE_KEY`, applied to the other end of
#: the pipeline: one ``(vuln_class, sink_context.family)`` shape can be
#: *rendered* two ways on two real pages -- ``sql_string_literal`` is an
#: equality lookup with a password condition on ``login.php`` and a
#: ``LIKE '%...%'`` catalogue filter on ``search.php`` -- and which rendering a
#: page uses is render-only metadata that must never fork the verdict-relevant
#: shape vocabulary (``class`` x ``sink_context.family``) the safety matrix is
#: keyed on. Both renderings score against exactly the same matrix rows.
_SINK_OVERRIDE_KEY = "sink_override_by_family"

#: Page-profile key naming this page's ``view``-category module (see
#: :data:`fuzzlab.labgen.emitters.php_laravel.modules.VIEWS`). Optional: a page
#: whose sink already renders its own view body (the Blade HTML sinks), or
#: whose complexity returns the composed result directly, names no view
#: category. Selected per page rather than per shape for exactly the reason
#: :data:`_SOURCE_OVERRIDE_KEY` is: presentation is render-only metadata and
#: must never fork the verdict-relevant ``class`` x ``sink_context.family``
#: vocabulary the safety matrix is keyed on -- ``products.php`` and
#: ``api/products.php`` are the same shape at the same SQL position, and
#: differ only in how the result is presented.
_VIEW_CATEGORY_KEY = "view_category"

#: Page-profile key: render the real login page's session-establishment tail
#: in the controller method (``session()->put(...)`` + redirect on a matched
#: row, an error response otherwise) instead of the default
#: ``return response()->json($rows);``.
#:
#: This is what makes the emitted page a *login* page rather than a query that
#: happens to read the users table, and it is deliberately a flag on an
#: existing complexity module's template rather than a new module: the shared
#: minimal-pair checker classifies every name in a cell's ``// Module
#: composition:`` line through :mod:`fuzzlab.labgen.modules`' registries and
#: raises for a name it cannot find, so inventing a ``login_session`` module
#: name here would make this stack's own cells unclassifiable. Both twins of
#: the login pair render the identical tail, so the pair still differs only in
#: its transform region.
#:
#: The build-time (Python) side of "a login page establishes a session" is
#: **not** reinvented here either: it is
#: :mod:`fuzzlab.labgen.emitters.php_laravel.auth_session`, a thin adapter over
#: the LAB-owned :mod:`fuzzlab.labgen.identity_session` helper (lane L-P2.2),
#: per PA-0001/PA-0021.
_SESSION_LOGIN_KEY = "session_login"

#: Page-profile key: render the real register page's prepared ``INSERT`` tail
#: after the duplicate-username check. Same layering rationale as
#: :data:`_SESSION_LOGIN_KEY` (a flag on the existing ``single_statement``
#: complexity, never a new composition name).
_REGISTER_INSERT_KEY = "register_insert"

#: Page-profile keys that describe a **write** endpoint (a
#: ``stored_second_order`` cell's ``cell.route``, looked up by
#: ``cell.route.path``) rather than the render/sink endpoint every other
#: profile key above is looked up by. Named explicitly so
#: :meth:`LaravelEmitter._render_write_controller` can fail loud when a
#: ``stored_second_order`` cell names a write route this emitter has no write
#: profile for, instead of handing a half-populated context to Jinja2's
#: ``StrictUndefined`` and reporting the gap as an opaque template error.
_WRITE_PROFILE_KEYS = frozenset({"stored_model", "stored_field", "owner_param", "write_param_name"})

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
#:   :data:`_REAL_PAGE_KEY`/:data:`_CANONICAL_CELL_KEY`, as the URL the
#:   canonical cell's generated route serves -- because the ``PFF-``
#:   ground-truth cases those cells reproduce are labelled at those URLs and
#:   T-LAB0.9's gate forbids relocating them (§4.3.6.6a).
_PAGE_PROFILES: dict[str, dict[str, Any]] = {
    # The original L-P3.3a illustrative pair (unchanged, kept rendering).
    "/example/product": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
    # CC-LAB-0064: mass-assignment illustrative pair. `allowed_fields` is what
    # the `runtime_field_allowlist` transform allows -- the real fields this
    # endpoint legitimately lets a user edit about themselves; `role`/
    # `is_admin` are real columns on the same table the vulnerable twin's
    # unfiltered write can still reach, since they are simply absent from the
    # allowlist, not from the table itself. Mirrors
    # `fuzzlab.labgen.emitters.php_current`'s `/account_settings.php` profile.
    # CC-LAB-0210 (category 5, Booking.com pilot app): the "continue to
    # partner/payment provider" redirect a real Booking.com-style checkout
    # flow issues (docs/research/category5-travel-functionality-and-cwe-
    # research.md §1.1). No `table`/`column`: the source is an ordinary GET
    # query parameter, not a database lookup.
    "/booking/continue": {"var_name": "return_to", "param_name": "return_to"},
    # CC-LAB-0211 (category 5, Booking.com pilot app): the Extranet/
    # partner-admin booking-list export view (docs/research/category5-
    # travel-functionality-and-cwe-research.md §1.1/§2.1). No `table`/
    # `column`: the source is an ordinary GET query parameter, not a
    # database lookup.
    "/extranet/export": {"var_name": "label", "param_name": "label"},
    # CC-LAB-0212 (category 5, Booking.com pilot app): the checkout charge
    # endpoint (docs/research/category5-travel-functionality-and-cwe-
    # research.md §1.1/§2.1). `room_type_rates`/`default_room_type` are the
    # secure twin's own fixed, server-owned rate table -- the vulnerable
    # twin never reads them (its transform is empty).
    "/booking/checkout": {
        "var_name": "amount",
        "param_name": "amount",
        "room_type_rates": (
            ("standard", "89.00"),
            ("deluxe", "149.00"),
            ("suite", "249.00"),
        ),
        "default_room_type": "standard",
    },
    "/example/account_settings": {
        "var_name": "postFields",
        "table": "users",
        "id_column": "id",
        "allowed_fields": ("display_name", "bio", "avatar_url"),
    },
    # CC-LAB-0133: Huddle Hub's (category 3's Slack pick) webhook-signature-
    # verification cell -- a Slack-style Events-API-style callback receiver.
    # This key is used only for template-context lookup (`_profile_for`);
    # the cell is actually served at the illustrative `/cell/<slug>` URL
    # (`_served_route_for`), since Huddle Hub has no migrated real page to
    # anchor a pinned URL to. `secret` is a lab-only shared secret, never a
    # real credential.
    "/webhooks/events": {"var_name": "webhookRawBody", "secret": "lab-only-huddlehub-webhook-secret"},
    # CC-LAB-0134: Huddle Hub's SSRF-via-link-unfurling cell -- `get_param`
    # reads the pasted URL as `?url=`. Illustrative served URL, same
    # reasoning as `/webhooks/events` above.
    "/messages/unfurl": {"var_name": "unfurlUrl", "param_name": "url"},
    # CC-LAB-0135: Huddle Hub's header-injection cell -- `get_param` reads
    # the admin-configured trigger word as `?triggerWord=`. Illustrative
    # served URL, same reasoning as `/webhooks/events`/`/messages/unfurl`
    # above.
    "/integrations/outgoing-webhook": {"var_name": "triggerWord", "param_name": "triggerWord"},
    # CC-LAB-0216: CircleFeed's (category 2's Facebook pick) photo/tag-detail
    # page -- a Facebook-style single-photo view, reachable by anyone logged
    # in who knows/guesses the id (docs/research/category2-social-ugc-
    # functionality-and-cwe-research.md sec 3 item 4). Illustrative served
    # URL (`_served_route_for`'s no-`real_page` branch), same reasoning as
    # Huddle Hub's own pages: CircleFeed, like Huddle Hub, has no migrated
    # real puppy-fort-factory page to anchor a pinned URL to. No
    # `table`/`column`: `DbRowByIdLookupSink` names the `Photo` model and
    # its `id` column itself (an Eloquent fetch, not a raw `DB::select`).
    "/photos/view": {"var_name": "id", "param_name": "id"},
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
    # =======================================================================
    # Migrated REAL puppy-fort-factory/ pages (lane L-P3.3c). Every profile
    # below carries `real_page` and, per :data:`_CANONICAL_CELL_KEY`, names
    # (or explicitly declines to name) the one cell that owns the page's real
    # URL. `.php` suffixes are load-bearing (§4.3.6.6a), not cosmetic.
    # =======================================================================
    # --- L-P3.3c-G1: numeric-literal SQLi on two real tables ---------------
    "/product.php": {
        "var_name": "id",
        "param_name": "id",
        "table": "products",
        "column": "id",
        "real_page": True,
        "canonical_cell_id": "LABGEN-RPL-PRODUCT",
        "ground_truth_case": "PFF-0001",
    },
    # The real page's extra nuance -- it suppresses DB errors with `@`, making
    # it a blind-only target where product.php is also error-based -- is not
    # modeled here: error verbosity is a nuisance/observability axis, not a
    # `(transform, sink_context)` fact, so it cannot change this cell's
    # derived verdict and inventing an op for it would fork the shape
    # vocabulary the safety matrix is keyed on. Same deliberate omission
    # `php_current`'s own real-pages sample records.
    "/blog_post.php": {
        "var_name": "id",
        "param_name": "id",
        "table": "posts",
        "column": "id",
        "real_page": True,
        "canonical_cell_id": "LABGEN-RPL-BLOGPOST",
        "ground_truth_case": "PFF-0006",
    },
    # --- L-P3.3c-G2: catalog listing + its JSON feed -----------------------
    # Both are secure-only cells (PFF-1001 / PFF-1003 are true negatives),
    # both filter `products.category` at a quoted-string-literal SQL position
    # with a bound parameter, and differ only in presentation.
    "/products.php": {
        "var_name": "category",
        "param_name": "category",
        "table": "products",
        "column": "category",
        # The real page reads `$_GET['category']`, so the shape's default
        # `post_param` source is overridden (the same mechanism
        # `/example/profile` uses for a stored source).
        "source_override": "get_param",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-G2-0001",
        "ground_truth_case": "PFF-1001",
    },
    # The JSON feed the fetch-based JS pages (`deals.php` and friends)
    # consume. Same SQL position and same binding as `/products.php`; the
    # difference is the response, which is JSON with a declared field shape
    # and casts -- the `json_view` view category. `json_fields` mirrors the
    # real endpoint's own projection, in the real endpoint's own field order,
    # casts included.
    "/api/products.php": {
        "var_name": "category",
        "param_name": "category",
        "table": "products",
        "column": "category",
        "source_override": "get_param",
        "view_category": "json_view",
        "json_fields": (
            ("id", "int"),
            ("name", None),
            ("price", "float"),
            ("description", None),
            ("category", None),
        ),
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-G2-0002",
        "ground_truth_case": "PFF-1003",
    },
    # --- L-P3.3c-G3: the real auth pages ------------------------------------
    # login.php (PFF-0004 vulnerable `username` + PFF-1008 true-negative
    # `password`). `password_var`/`password_param` render the PFF-1008
    # position: an already-hashed secret folded into the same statement,
    # never a second injection point. `session_login` renders the real page's
    # session-establishment tail.
    "/login.php": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "password",
        "password_param": "password",
        "password_hash_fn": "md5",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLA-0001",
        "ground_truth_case": "PFF-0004",
        # PFF-1008 (POST `password`, "md5-hashed before use; not an injection
        # point") is the sink's second, non-tainted condition -- rendered
        # identically in both login cells via `password_var`/`password_param`
        # above, never a distinct cell of its own. See
        # `_SECONDARY_GROUND_TRUTH_CASES_KEY`.
        "secondary_ground_truth_cases": ("PFF-1008",),
        "session_login": {
            "id_column": "id",
            "name_column": "username",
            "redirect_to": "/profile.php",
            "error_message": "Invalid username or password.",
        },
    },
    # register.php (PFF-1004, secure-only). The modeled sink is the real
    # page's prepared duplicate-username check; `register_insert` renders the
    # prepared INSERT that follows it. No `password_var`: the real duplicate
    # check is `SELECT id FROM users WHERE username = ?` with no second
    # condition (the sink's password condition is optional for exactly this
    # reason).
    "/register.php": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLA-0003",
        "ground_truth_case": "PFF-1004",
        "register_insert": {
            "columns": ("username", "email", "password", "full_name", "bio"),
            "email_param": "email",
            "password_param": "password",
            "full_name_param": "full_name",
            "password_hash_fn": "md5",
            "taken_message": "That username is already taken.",
        },
    },
    # --- L-P3.3c-G4: the stored second-order pair --------------------------
    # profile.php is the READ/sink endpoint: the stored `bio` is rendered
    # into an HTML body. The taint origin is storage, so this profile
    # overrides the (xss, html_body) shape's default `get_param` source,
    # exactly as /example/profile does.
    "/profile.php": {
        "var_name": "bio",
        "stored_model": "\\App\\Models\\User",
        "owner_param": "user",
        "stored_expr": "$storedOwner->bio",
        "css_class": "bio",
        "source_override": "read_stored_field",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-0401",
        "ground_truth_case": "PFF-0005",
    },
    # edit_profile.php is the WRITE endpoint (`Cell.route`): the POSTed `bio`
    # is persisted verbatim through Eloquent. The write-only keys
    # (`_WRITE_PROFILE_KEYS`) are consumed by the `stored_field_write` write
    # module, not by the read path's composition -- this profile is looked up
    # by `cell.route.path`, while every other profile in this registry is
    # looked up by the render (sink) path.
    "/edit_profile.php": {
        "stored_model": "\\App\\Models\\User",
        "stored_field": "bio",
        "owner_param": "user",
        "write_param_name": "bio",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-0402",
        "ground_truth_case": "PFF-1007",
    },
    # --- L-P3.3c-G5: the two secure-only escaped-echo form pages -----------
    # `PFF-1005` (`contact.php`, POST `message`) and `PFF-1006`
    # (`newsletter.php`, POST `email`). Both real pages echo the submitted
    # value straight back through the app's `e()` helper and write nothing to
    # the database, so the shape is `xss`/`html_body` reached from a POST body
    # parameter -- hence the `post_param` source override (the shape's default
    # source, `read_stored_field`, is the stored-XSS origin, which neither
    # page has). The trivial case of the unified mechanism: a page with
    # exactly one cell has a canonical cell and no twins to derive a variant
    # URL for.
    "/contact.php": {
        "var_name": "message",
        "param_name": "message",
        # The real page wraps the reflected message in
        # `<blockquote class="bio">`; the sink fragment's element is a `div`,
        # which is not verdict-relevant (the sink *context family* -- an HTML
        # body position -- is what the safety matrix is keyed on).
        "css_class": "bio",
        "source_override": "post_param",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-1005",
        "ground_truth_case": "PFF-1005",
    },
    "/newsletter.php": {
        "var_name": "email",
        "param_name": "email",
        # Real page: `<p class="notice ok">Thanks! We'll send fort news to
        # <?= e($email) ?>.</p>`.
        "css_class": "notice ok",
        "source_override": "post_param",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-1006",
        "ground_truth_case": "PFF-1006",
    },
    # --- L-P3.3c-G6: search.php, RESOLVED by L-P3.3c-CUT (Path B) -----------
    # puppy-fort-factory/search.php, the largest single page of the
    # migration: ONE query parameter (`q`) reaching THREE sinks -- a
    # `LIKE '%q%'` SQL string literal (PFF-0002), an HTML body reflection
    # (PFF-0003), and a quoted `value="..."` attribute reflection (the page's
    # third documented sink, which labels.json folds into its XSS case rather
    # than numbering separately). One profile serves all six cells of the
    # page (three sink behaviors x vulnerable/secure).
    #
    # **Resolution (`CC-LAB-0058`/`FR-LAB-55`), Path B of that change's own
    # task brief.** `PFF-0002` and `PFF-0003` are both real, simultaneously
    # true at the real `/search.php` URL -- but the `Cell` IR has no
    # multi-sink page composition (a page profile is shared render-only
    # metadata across cells; a route/controller is rendered from exactly one
    # cell, per :func:`_served_route_for`'s own three-case docstring), and
    # building one would mean either (a) a controller template that composes
    # more than one cell's sink transform into one response -- forking the
    # "one cell, one verdict-relevant shape" invariant every module-set/
    # minimal-pair mechanism in this emitter is built on (see
    # :data:`_SOURCE_OVERRIDE_KEY`/:data:`_SINK_OVERRIDE_KEY`'s own repeated
    # "must never fork the verdict-relevant vocabulary" rule) -- or (b) a new
    # `Cell.sink_context` shape representing "more than one family," which
    # would ripple through the safety matrix, the minimal-pair checker, and
    # every whole-manifest regression test (`PA-0024`). Both are real
    # architecture changes, not a small, contained extension -- so this
    # resolution takes Path B: pick ONE cell canonical, exempt the other.
    #
    # **`LABGEN-PL-RP-0001` (the SQLi-vulnerable `LIKE` cell, `PFF-0002`) is
    # canonical.** Reasoning: (1) severity -- an unauthenticated catalogue
    # SQL injection is the more consequential of the two simultaneously-real
    # findings, next to a reflected-XSS that needs a victim to click a
    # crafted link; (2) precedent -- every other real-page group with a
    # SQLi/XSS choice to make on one URL (G1, G3) already canonicalizes the
    # SQLi cell; (3) it is what this task's own MariaDB-backed live-boot proof
    # (`CC-LAB-0058`) exercises for real at `GET /search.php?q=...` against
    # the real `products` table. `PFF-0003` (the two XSS reflections --
    # `html_body` and `html_attribute_quoted`, both already folded into that
    # one case by `labels.json`) is a genuine, documented downgrade from
    # "covered" to "exempted" -- see
    # `lab/ground-truth/migration-exemptions.yaml`'s `PFF-0003` entry for the
    # honest reason, never silently dropped.
    "/search.php": {
        "var_name": "q",
        "param_name": "q",
        "table": "products",
        "column": "name",
        "css_class": "search",
        "attr_name": "q",
        "source_override": "get_param",
        "sink_override_by_family": {"sql_string_literal": "sql_string_literal_like"},
        "real_page": True,
        "canonical_cell_id": "LABGEN-PL-RP-0001",
        # A single page-wide case now, exactly like every other one-case real
        # page (`login.php`, `product.php`, ...) -- attributed only to the
        # canonical cell, per `_GROUND_TRUTH_CASE_KEY`'s own gating rule.
        # `_GROUND_TRUTH_CASE_BY_FAMILY_KEY` is deliberately NOT set any more
        # (contrast the pre-`CC-LAB-0058` version of this profile): that
        # mechanism's per-family lookup is unconditional (never gated on
        # `canonical_cell_id`), so leaving `html_body`/`html_attribute_quoted`
        # mapped to `PFF-0003` there would still mark it "covered" even though
        # no cell of this page serves `/search.php` for those families any
        # more -- exactly the dishonest "covered while unservable at its real
        # URL" state this resolution exists to close. `PFF-0003` is named in
        # `lab/ground-truth/migration-exemptions.yaml` instead.
        "ground_truth_case": "PFF-0002",
    },
    # --- L-P3.3c-DOM: reviews.php/feedback.php's DOM-based XSS -------------
    # The real page: a `<script>` block reads `#author=` from `location.hash`
    # and writes it via `.innerHTML` with no escaping (VULNERABILITIES.md
    # finding #6, PFF-0007). The value never reaches the server -- `var_name`
    # is descriptive only, never a `$_GET`/`$request` key.
    "/reviews.php": {
        "var_name": "author",
        "dom_location": "hash",
        "dom_param_name": "author",
        "dom_target_id": "greeting",
        "dom_prefix": '<p class="notice ok">Thanks for your review, ',
        "dom_suffix": "!</p>",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-DOM-0001",
        "ground_truth_case": "PFF-0007",
    },
    # The real page: a `<script>` block reads `?ref=` from `location.search`
    # and writes it via `.innerHTML` with no escaping (VULNERABILITIES.md
    # finding #7, PFF-0008). The server never uses `ref` either.
    "/feedback.php": {
        "var_name": "ref",
        "dom_location": "query",
        "dom_param_name": "ref",
        "dom_target_id": "fb-status",
        "dom_prefix": '<p class="notice ok">Thanks for visiting from ',
        "dom_suffix": "!</p>",
        "real_page": True,
        "canonical_cell_id": "LABGEN-PLRP-DOM-0002",
        "ground_truth_case": "PFF-0008",
    },
}

#: The one controller method name every generated controller uses. Stable
#: across a minimal pair's twins on purpose (``minimal_pair
#: .check_identifier_stability``'s rule): per-cell identity is carried by the
#: per-cell controller *class* and route URL, both derived from the cell ID.
_METHOD_NAME = "show"

#: The write controller's action name (L-P3.3c-G4). Fixed across a minimal
#: pair's twins for the same reason :data:`_METHOD_NAME` is.
_WRITE_METHOD_NAME = "store"

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


def _resource_class_for(cell_id: str) -> str:
    """PascalCase Eloquent API Resource class name for a ``json_view`` cell,
    derived from ``cell_id`` like every other per-cell identifier on this
    stack (Addendum D's per-cell-identifier rule)."""
    return _controller_class_for(cell_id)[: -len("Controller")] + "Resource"


def _url_path_for(cell_id: str) -> str:
    """The **illustrative**, cell-ID-derived route URL -- ``/cell/<slug>``.

    The default for every cell that is not the canonical cell of a migrated
    real page: see :func:`_served_route_for` for the one function that
    decides where a cell is actually served, and
    ``fuzzlab.labgen.emitters.php_laravel.route_accumulator``'s module
    docstring for why a twin needs its own URL to coexist in one build.
    """
    return f"/cell/{_cell_slug(cell_id)}"


def _twin_url_for(real_url: str, cell_id: str) -> str:
    """The distinct, still-``.php``-suffixed URL a non-canonical cell of a
    real page is served at, e.g. ``/login.php`` + ``LABGEN-PLA-0002`` ->
    ``/login.labgen-pla-0002.php``.

    Never the plain cell-ID-derived ``/cell/<slug>``: keeping the ``.php``
    suffix on every route of a real page (canonical or not) is itself part of
    what makes this a *migration*, not a fresh illustrative page next to it --
    and it is the one design choice in the unified mechanism most likely to
    be revisited (see :data:`_CANONICAL_CELL_KEY`'s docstring)."""
    stem, dot, suffix = real_url.rpartition(".")
    if not dot:  # pragma: no cover - every real page path is `.php`-suffixed
        return f"{real_url}.{_cell_slug(cell_id)}"
    return f"{stem}.{_cell_slug(cell_id)}.{suffix}"


def _served_route_for(page_path: str, cell_id: str, method: str) -> tuple[str, str]:
    """The ``(url_path, http_method)`` this cell is actually served at, for
    the page profile named ``page_path``.

    **The one shared derivation of that fact** (PA-0003/PA-0021) -- the single
    mechanism that replaced the five sub-lanes' independent ones. Called with
    a cell's render/sink page for its main route, and (for a
    ``stored_second_order`` cell) again with its write page for the write
    route, since those can be two different real pages each with their own
    canonical claim (L-P3.3c-G4's ``/profile.php``/``/edit_profile.php``
    pair).

    Three cases:

    * **Illustrative page** (no :data:`_REAL_PAGE_KEY`): the cell-ID-derived
      ``/cell/<slug>`` URL, at the cell's own ``method`` (every pre-existing
      illustrative cell happens to be ``GET``, so this was long
      indistinguishable from hardcoding ``GET`` -- CC-LAB-0064's mass-
      assignment cells are the first illustrative ``POST`` cells, which
      surfaced that the hardcoding was itself the bug: a ``POST``-declared
      cell got registered as ``Route::get(...)`` and could never actually be
      exercised at its declared method).
    * **Real page, no canonical cell yet** (:data:`_CANONICAL_CELL_KEY` is
      ``None``): the deliberately-unpinned state -- no current profile uses
      it (L-P3.3c-G6's ``search.php`` was the one example, resolved by
      `CC-LAB-0058`/`FR-LAB-55`; see that page's own profile comment). Every
      cell of a page in this state falls back to the illustrative behavior
      above until a human resolves it.
    * **Real page with a canonical cell**: the canonical cell is served at
      the page's own path and ``method``; every other cell of that page gets
      :func:`_twin_url_for`'s variant URL, at its own ``method``.
    """
    profile = _PAGE_PROFILES.get(page_path, {})
    if not profile.get(_REAL_PAGE_KEY):
        return _url_path_for(cell_id), method.upper()
    if _CANONICAL_CELL_KEY not in profile:
        raise ValueError(
            f"php_laravel page profile for {page_path!r} declares {_REAL_PAGE_KEY!r} but names no "
            f"{_CANONICAL_CELL_KEY!r} -- a real page must either name the cell that owns its real "
            "URL, or explicitly set it to None to flag the decision as still open (fail loud "
            "rather than silently leave the page unserved or arbitrarily pick a cell)"
        )
    canonical = profile[_CANONICAL_CELL_KEY]
    if canonical is None:
        # Deliberately unpinned -- see the docstring above and
        # `_CANONICAL_CELL_KEY`'s own docstring for why this is a legal,
        # flagged-open state (L-P3.3c-CUT), not a bug.
        return _url_path_for(cell_id), method.upper()
    if cell_id == canonical:
        return page_path, method.upper()
    return _twin_url_for(page_path, cell_id), method.upper()


def _render_route_for(cell: Cell) -> Route:
    """The page the tainted value actually executes on -- ``sink_endpoint``
    when the cell has a distinct one, otherwise ``route``.

    Mirrors ``php_current.render()``'s own ``render_route`` choice. For a
    same-endpoint (``direct``) cell that is ``route``; for a
    ``stored_second_order`` cell it is ``sink_endpoint`` -- the read page
    where the stored payload executes, while ``route`` is the write page the
    payload was submitted to (rendered separately, see
    :meth:`LaravelEmitter._render_write_controller`). Factored out so
    :meth:`LaravelEmitter.render`, :meth:`LaravelEmitter.route_fragment_for`
    and :func:`served_url_for` cannot disagree about it (PA-0003/PA-0021: one
    shared derivation, not three)."""
    return cell.sink_endpoint if cell.sink_endpoint is not None else cell.route


def _profile_for(cell: Cell) -> dict[str, Any]:
    """This cell's page profile (its render/sink page), or a loud failure.
    Never a silent default -- guessing a page's table/column/parameter names
    is exactly the decision the profile exists to make explicit."""
    render_route = _render_route_for(cell)
    if render_route.path not in _PAGE_PROFILES:
        raise ValueError(
            f"{cell.cell_id}: php_laravel has no page profile for route {render_route.path!r} "
            f"-- known routes: {sorted(_PAGE_PROFILES)}"
        )
    return dict(_PAGE_PROFILES[render_route.path])


def served_url_for(cell: Cell) -> str:
    """The URL this build actually serves ``cell``'s render/sink page at.

    The one function :meth:`LaravelEmitter.route_fragment_for` (which
    registers the route) and
    :func:`fuzzlab.labgen.emitters.php_laravel.identifier_sqli.probe_cell_for`
    /:mod:`fuzzlab.labgen.emitters.php_laravel.auth_session` (which probe or
    post to it) all call -- a second, independent copy of this rule is
    precisely how an oracle ends up probing a URL no generated route serves.
    """
    render_route = _render_route_for(cell)
    url, _method = _served_route_for(render_route.path, cell.cell_id, render_route.method)
    return url


def ground_truth_cases_for(cell: Cell) -> tuple[str, ...]:
    """The ``PFF-`` ground-truth case ids ``cell`` reproduces, derived from
    the ground-truth metadata on its own page profile(s) -- never a
    hand-maintained per-cell literal (PA-0001/PA-0027; the
    ``fuzzlab.labgen.cutover_gate`` coverage gate calls this over every
    manifest's cells rather than restating a case-id map).

    Zero, one, or two case ids, from up to two profiles (``cell.route`` and,
    for a ``stored_second_order`` cell, the distinct render/sink page
    :func:`_render_route_for` names -- G4's ``edit_profile.php``/
    ``profile.php`` pair is exactly why both are checked):

    * :data:`_GROUND_TRUTH_CASE_KEY`, when set on that profile and ``cell`` is
      the :data:`_CANONICAL_CELL_KEY` it names (the case belongs to the one
      cell that owns the page's real URL, not to every twin of it).
    * :data:`_GROUND_TRUTH_CASE_BY_FAMILY_KEY`, keyed by ``cell.sink_context
      .family`` -- for a page like ``search.php`` whose one profile spans more
      than one ``PFF-`` case and therefore names no single page-wide case.
    * :data:`_SECONDARY_GROUND_TRUTH_CASES_KEY` -- attributed to *every* cell
      of that profile (not gated on being the canonical cell), since it names
      a structural, boilerplate position identical across a page's twins
      (e.g. login.php's already-hashed ``PFF-1008`` password condition).

    A non-``real_page`` profile (an illustrative page) or a missing profile
    contributes nothing. Order-preserving, de-duplicated.
    """
    render_route = _render_route_for(cell)
    case_ids: list[str] = []
    for path in dict.fromkeys((cell.route.path, render_route.path)):
        profile = _PAGE_PROFILES.get(path)
        if profile is None or not profile.get(_REAL_PAGE_KEY):
            continue
        primary = profile.get(_GROUND_TRUTH_CASE_KEY)
        canonical = profile.get(_CANONICAL_CELL_KEY)
        if primary is not None and canonical is not None and cell.cell_id == canonical:
            case_ids.append(primary)
        by_family = profile.get(_GROUND_TRUTH_CASE_BY_FAMILY_KEY) or {}
        family_case = by_family.get(cell.sink_context.family)
        if family_case is not None:
            case_ids.append(family_case)
        case_ids.extend(profile.get(_SECONDARY_GROUND_TRUTH_CASES_KEY, ()) or ())
    return tuple(dict.fromkeys(case_ids))


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
    HTML-sink cell, its own Blade view, and for a ``json_view`` cell, its own
    API Resource, and for a ``stored_second_order`` cell, its own write
    controller) by composing this stack's own module registries, and to a
    ``routes/web.php`` fragment for the accumulator.

    Like ``php_current``, :meth:`render` never falls back to a default
    shape/transform/page profile silently -- a shape, op, page or depth this
    emitter has no module or profile for raises, rather than guessing.
    """

    stack_env: StackEnv = PHP_LARAVEL_STACK_ENV

    def __init__(self) -> None:
        self._route_accumulator = RouteAccumulator()

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
        if cell.context_depth not in SUPPORTED_CONTEXT_DEPTHS:
            raise ValueError(
                f"{cell.cell_id}: php_laravel renders context_depth "
                f"{list(SUPPORTED_CONTEXT_DEPTHS)} only, got {cell.context_depth!r} -- the "
                "pass-through-helper depth fragments (same_file_helper, cross_file) are not "
                "ported to Laravel idiom yet, and rendering this cell as 'direct' would "
                "mislabel the depth its corpus record claims (fail loud rather than silently "
                "flatten the axis)"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]
        render_route = _render_route_for(cell)

        ctx: dict[str, Any] = _profile_for(cell)
        # Routing/provenance metadata, never template values -- popped so no
        # template can accidentally render a ground-truth case ID into a
        # served artifact (FR-LAB-2 keeps emitted IDs opaque) or see a routing
        # flag it has no business reading.
        ctx.pop(_REAL_PAGE_KEY, None)
        ctx.pop(_CANONICAL_CELL_KEY, None)
        ctx.pop(_GROUND_TRUTH_CASE_KEY, None)
        ctx.pop(_SECONDARY_GROUND_TRUTH_CASES_KEY, None)
        ctx.pop(_GROUND_TRUTH_CASE_BY_FAMILY_KEY, None)
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

        # Which *rendering* of this shape's sink this page uses (L-P3.3c-G6).
        # Popped before any template renders, so a profile key that is a
        # mapping never reaches a Jinja2 context.
        sink_overrides = dict(ctx.pop(_SINK_OVERRIDE_KEY, {}) or {})
        sink_name = sink_overrides.get(cell.sink_context.family, modules.sink)
        if sink_name not in SINKS:
            raise ValueError(
                f"{cell.cell_id}: php_laravel page profile for {render_route.path!r} names an "
                f"unknown sink module {sink_name!r} for family {cell.sink_context.family!r} "
                f"-- known sinks: {sorted(SINKS)}"
            )

        # The `view` category (L-P3.3c-G2): a page whose response has a
        # presentation layer the sink cannot carry, because the sink produced
        # data rather than markup -- a JSON endpoint. Selected by the page
        # profile, and fail-loud on an unknown name exactly like the source
        # override above.
        view_name = ctx.pop(_VIEW_CATEGORY_KEY, None)

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

        sink_result = SINKS[sink_name].render(ctx)
        renders_view = sink_name in VIEW_SINKS

        view_result = None
        if view_name is not None:
            if view_name not in VIEWS:
                raise ValueError(
                    f"{cell.cell_id}: php_laravel page profile for {render_route.path!r} names an "
                    f"unknown view module {view_name!r} -- known views: {sorted(VIEWS)}"
                )
            if renders_view:
                raise ValueError(
                    f"{cell.cell_id}: page profile for {render_route.path!r} names view category "
                    f"{view_name!r}, but sink {sink_name!r} already renders its own view body -- "
                    "a cell has exactly one presentation layer, and emitting two would put two "
                    "files at the one 'view' role with no defined precedence"
                )
            view_result = VIEWS[view_name].render({**ctx, "resource_class": _resource_class_for(cell.cell_id)})

        composition = " -> ".join((source_name, *applied_ops, sink_name, modules.complexity))
        # A `direct` cell's provenance block is byte-identical to what this
        # emitter produced before the depth axis was carried here -- the whole
        # pre-existing corpus regenerates unchanged (and is regression-tested
        # to), the same guarantee php_current's own `depth_comment` gives.
        depth_comment = (
            ""
            if cell.context_depth == "direct"
            else (
                f"// Context depth: {cell.context_depth}\n"
                f"// Sink endpoint (where the stored value executes): "
                f"{render_route.method} {render_route.path}\n"
            )
        )
        provenance = (
            f"// Generated by fuzzlab.labgen.emitters.php_laravel for cell {cell.cell_id}\n"
            f"// Manifest cell.route.path: {cell.route.path}\n"
            f"{depth_comment}"
            # A view-category module's name is recorded on its own line rather
            # than in the composition line (fuzzlab.labgen.minimal_pair
            # classifies every composition-line name through the shared,
            # cross-stack registries and raises for one it cannot find; the
            # `route` category sets the precedent). Identical between a
            # minimal pair's twins, so it lands in the checker's common
            # prefix.
            + (f"// View category: {view_name}\n" if view_name is not None else "")
            + f"// Module composition: {composition}\n"
        )

        # For a view-rendering cell the sink's code *is* the Blade view body,
        # so the controller body is source + transforms only and the
        # complexity module closes it by handing the value to that view.
        body_fragments = [source_result.code, *transform_code_blocks]
        if not renders_view:
            body_fragments.append(sink_result.code)
        if view_result is not None:
            # One controller statement, from the view module's own context --
            # the analogue of `render_only`'s `return view(...)` line. It
            # rebinds `$rows`, which is what lets the complexity module close
            # the method unchanged.
            body_fragments.append(view_result.context["view_bridge_code"])
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
        if view_result is not None:
            # A `view`-category artifact is an ordinary PHP class file, so its
            # provenance is a plain header (no `?>` needed, unlike a Blade
            # view, whose body is template text after the PHP block).
            resource_class = _resource_class_for(cell.cell_id)
            resource_source = "<?php\n" + provenance + "\n" + view_result.code
            resource_path = self.stack_env.file_roles[str(view_name)].format(
                cell_slug=resource_class[: -len("Resource")]
            )
            files.append(
                EmittedFile(path=resource_path, content=resource_source.encode("utf-8"), role="view")
            )
        if cell.context_depth == "stored_second_order":
            files.append(self._render_write_controller(cell, provenance))
        return tuple(files)

    def _render_write_controller(self, cell: Cell, provenance: str) -> EmittedFile:
        """The **write** half of a ``stored_second_order`` cell: the endpoint
        ``cell.route`` names, which persists the tainted parameter into the
        stored field the read/sink endpoint later renders.

        Emitted as its own controller file rather than a second method on the
        read controller, so each endpoint's route registration points at a
        controller whose whole job is that endpoint -- and so the write half
        carries the same ``// Module composition:`` provenance line the read
        half does, which is what lets :mod:`fuzzlab.labgen.minimal_pair`
        evaluate the pair invariant on this file too. Its body holds no
        transform, so it is identical between a vulnerable cell and its secure
        twin by construction.
        """
        profile = _PAGE_PROFILES.get(cell.route.path)
        if profile is None or not _WRITE_PROFILE_KEYS.issubset(profile):
            missing = sorted(_WRITE_PROFILE_KEYS - set(profile or {}))
            raise ValueError(
                f"{cell.cell_id}: php_laravel has no write page profile for the stored-write "
                f"route {cell.route.path!r} (missing {missing}) -- a 'stored_second_order' cell "
                "reproduces two real endpoints, so the write endpoint needs its own profile "
                "naming the model/field the payload is persisted into; there is no safe default"
            )
        write_ctx: dict[str, Any] = dict(profile)
        write_ctx.pop(_REAL_PAGE_KEY, None)
        write_ctx.pop(_CANONICAL_CELL_KEY, None)
        write_ctx.pop(_GROUND_TRUTH_CASE_KEY, None)
        write_ctx.pop(_SECONDARY_GROUND_TRUTH_CASES_KEY, None)
        write_ctx.pop(_GROUND_TRUTH_CASE_BY_FAMILY_KEY, None)
        write_ctx["write_method_name"] = _WRITE_METHOD_NAME
        # Redirect to wherever THIS cell's own read route lives -- canonical
        # or twin, decided the same way every other served URL is.
        write_ctx["sink_url_path"] = served_url_for(cell)
        method_code = WRITES["stored_field_write"].render(write_ctx).code

        base = _controller_class_for(cell.cell_id)[: -len("Controller")]
        controller_class = f"{base}WriteController"
        source = (
            "<?php\n"
            + provenance
            + f"// Write endpoint (where the payload is submitted): {cell.route.method} "
            f"{cell.route.path}\n"
            "\n"
            "namespace App\\Http\\Controllers;\n"
            "\n"
            "use Illuminate\\Http\\Request;\n"
            "\n"
            f"class {controller_class} extends Controller\n"
            "{\n"
            f"{method_code}"
            "}\n"
        )
        path = self.stack_env.file_roles["write_controller"].format(cell_slug=base)
        return EmittedFile(path=path, content=source.encode("utf-8"), role="write_controller")

    def route_fragment_for(self, cell: Cell) -> str:
        """This cell's ``routes/web.php`` fragment (accumulator category, one
        or two lines per cell -- see ``route_accumulator.py``'s module
        docstring for why this is not part of :meth:`render`'s own return
        value). A ``stored_second_order`` cell registers two routes (read +
        write); every other cell registers one."""
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(f"{cell.cell_id}: unsupported for php_laravel -- see render() for the same check")
        controller_class = _controller_class_for(cell.cell_id)
        render_route = _render_route_for(cell)
        read_url, read_method = _served_route_for(render_route.path, cell.cell_id, render_route.method)
        lines = [
            self._route_accumulator.fragment_for_cell(
                cell_id=cell.cell_id,
                controller_class=controller_class,
                url_path=read_url,
                method=read_method,
                action=_METHOD_NAME,
            )
        ]
        if cell.context_depth == "stored_second_order":
            write_controller_class = f"{controller_class[: -len('Controller')]}WriteController"
            write_url, write_method = _served_route_for(cell.route.path, cell.cell_id, cell.route.method)
            lines.append(
                self._route_accumulator.fragment_for_cell(
                    cell_id=cell.cell_id,
                    controller_class=write_controller_class,
                    url_path=write_url,
                    method=write_method,
                    action=_WRITE_METHOD_NAME,
                )
            )
        return "\n".join(lines)

    def render_scaffold(self) -> EmittedFiles:
        """The per-stack scaffold files (rendered once per build, never per
        cell) -- ``StackEnv.scaffold_files`` names the paths; this method is
        what actually renders their content."""
        return (
            EmittedFile(path=".env", content=self.stack_env.env_file_content(), role="scaffold"),
            EmittedFile(path="public/index.php", content=self.stack_env.index_php_content(), role="scaffold"),
        )
