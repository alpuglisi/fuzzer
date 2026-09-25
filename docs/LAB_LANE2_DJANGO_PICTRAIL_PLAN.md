# Browsable Labs Lane 2 — django: PicTrail

Status: **plan reviewed and converged, 3/3 agreement reached 2026-09-25**
(2 independent reviewer agents plus the proposing agent, after 1 revision
round — see §8 Review history). Reserved as `CC-LAB-0242` / `FR-LAB-160`
per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table. **Next step: draft the
condensed change-control entry and take it through its own 2-reviewer
gate**, mirroring `CC-LAB-0241`'s process exactly — this plan document's
own convergence does not yet authorize implementation.
**Update 2026-09-25:** the `CC-LAB-0242` entry cleared its own gate and the
plan was **implemented** the same day — see that entry's Deliverables and
Effectiveness (R1 took branch (a); the PA-0053 sweep found 5 bare-GET 500s,
fixed as `BUG-0052`/`PA-0054`).

## 0. What Lane 1 taught us, applied here from the start

Lane 1 (`php_laravel`) needed 5 sequential change-control entries because
several things were discovered late: a spider-based navigability test was
deferred to the very end (CC-LAB-0241) instead of built alongside the page
conversion; missing-request-parameter defaults were found only by that late
crawl (BUG-0051/PA-0053); and page-vs-api classification, URL-pinning, and
risk coverage were each drafted, then found incomplete on review, more than
once. This plan applies those lessons up front rather than repeating the
discovery order:

- The navigability acceptance test's **spec is written in §4 up front**,
  not invented as an afterthought — but round-1 review correctly caught
  that §5's sequencing still *runs* it last (step 5 of 6), after every page
  conversion, which is operationally the same order Lane 1 actually used.
  The honest claim is narrower than "not a follow-up step": designing the
  test's shape before any page conversion starts (so each page's PA-0053
  default decision, §2d, is made against a known target contract, not
  guessed) is the actual improvement over Lane 1, not the execution order.
- Every converted page's absent-input behavior is decided in §2 alongside
  its conversion, and **gated by that page's own live-boot assertion**
  (§5 step 2 names exactly what each assertion checks, not left as
  unspecified prose — see §5).
- §1 does the "is this real" research directly against the current code
  (django emitter, PicTrail's actual manifests, actual ground truth), not
  by analogy to what Lane 1 found for a different stack.

## 1. Scope — what already exists vs. what this step does

Confirmed via direct code reading:

- **PicTrail already exists as a real identity**, unlike Lane 1's
  CircleFeed/Huddle Hub/Booking pre-split: 6 real pages (`CC-LAB-0092`-
  `0097`, Phase C), each with its own manifest
  (`lab/manifests/phase_c_picktrail_{post_detail,comments,link_preview,
  settings,explore,inbox}.yaml`) and its own ground truth
  (`lab/ground-truth-picktrail-django/`). **No `--app`-split step is
  needed** — PicTrail is not merged into another app the way CircleFeed
  etc. were merged into PFF pre-Lane-1.
- **No homepage.** No route for `/` exists anywhere in the django emitter
  or its `urls.py` accumulator (`render_route_accumulator()`,
  `fuzzlab/labgen/emitters/django/__init__.py:388`).
- **Every page is JSON or a bare fragment**, never a real HTML page in a
  layout:
  - `single_statement.py.j2:5`: `return JsonResponse({"id": ..., "name":
    ...})` — the default tail for SQL-lookup sinks (`/post`, `/explore`).
  - `html_body_echo.py.j2:1`: `return HttpResponse('<div class="...">' +
    str(value) + "</div>")` — a bare fragment, the exact same class of gap
    Lane 1's CC-LAB-0241 fixed for `php_laravel`'s `html_body_echo`.
  - `django_template_render.py.j2:1` (`/post/comments`) is the only sink
    that calls `render()` with a real `.html` template, but that template
    (`_COMMENT_TEMPLATE_HTML`, `__init__.py:106`) is itself just
    `<div class="comment">{{ comment }}</div>` — still a bare fragment, no
    shared layout/nav.
  - `/upload/link-preview`, `/settings`, `/inbox` all return `JsonResponse`
    via their own sinks (`http_fetch_json_sink`, `profile_bulk_update_sink`,
    `inbox_deserialize_sink`).
- **Ground truth's `rendering` field carries the same wrong-inference risk**
  `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md` already found for `php_laravel`:
  5 of 6 points are `"rendering": "server-json"`, 1 (`/post/comments`) is
  `"rendering": "server"` — but `/post/comments` is confirmed (above) to be
  a bare fragment today, not a real HTML page, so `"server"` here means
  only "form-encoded request" (`fuzzlab/harness/auto.py:86-96`), exactly as
  Lane 1 found. This field will need updating once conversion lands, not
  read as already-true.
- **`_REAL_PAGE_CELL_IDS`** (`__init__.py:253-262`) already pins each real
  page's vulnerable cell to its own exact URL (`/post`, `/explore`, etc.)
  instead of the generic `generated/{slug}/` pattern every illustrative
  cell uses — the realistic-URL requirement is **already substantially
  met** for the vulnerable twin. **Important asymmetry (R1, below): the
  secure twin is deliberately NOT added to `_REAL_PAGE_CELL_IDS`** (the
  comment at `__init__.py:249-252` states this explicitly) — it keeps the
  generic URL. This is a real difference from `php_laravel`'s
  `canonical_cell_id`/`_twin_url_for` mechanism, where both twins get a
  URL in the same family.
- **No login flow, no session-gated cell.** `identity_session.py`'s
  `IdentitySessionStore` is a build-time oracle helper, not a runtime login
  route; no `LABGEN-MA-0003/0004`-style session gating was found in the
  django emitter. Confirmed nothing here needs the R8 sign-off's 401
  exception — flag this explicitly rather than silently assume it (§4).
- **Page vs. API classification** (per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s
  refinement) for the 6 real pages:
  - `/post` — page (post detail view).
  - `/post/comments` — page (comment thread, embedded in `/post`'s page or
    its own).
  - `/upload/link-preview` — **api**: a real oEmbed/unfurl-style JSON
    endpoint (`http_fetch_json_sink`, ported from a real corpus example,
    `docs/research/corpus-examples/ssrf/python/{vulnerable,idiomatic}-
    oembed-unfurl-4.py`) — gets a client page using `fetch()`, stays JSON.
  - `/settings` — page (account settings form).
  - `/explore` — page (search/sort listing).
  - `/inbox` — page (a DM/message view — the payload field models a
    message's own serialized data, not an M2M API contract); gets a form,
    not a client page.
  - No cell here is a webhook-receiver analog (unlike CircleFeed/Huddle
    Hub) — only `/upload/link-preview` is a genuine `api`.

## 2. Fix design

### 2a. Homepage + shared layout

New `layouts/site.html` (Django template), mirroring `php_laravel`'s
`layouts.site` contract exactly: header (app name "PicTrail" + nav), main,
footer, inline CSS, byte-identical across every page that extends it. New
`/` route rendering a homepage with nav links to `/post`, `/explore`,
`/settings`, `/inbox`, and a `/catalog`-equivalent (if PicTrail has
illustrative covering-array cells with no ground-truth case — confirm count
during implementation; if none exist, this list item is dropped, not
invented).

### 2b. JSON→HTML conversion for `page`-classified points

- `/post`: convert `single_statement.py.j2`'s `JsonResponse` tail to a
  `django_template_render`-style tail (or extend `single_statement` with an
  equivalent `html_list_view`/`html_row_view` tail flag, mirroring
  `php_laravel`'s CC-LAB-0239/0240 mechanism, adapted to Django's
  `render(request, template, context)` call rather than Blade's `view()`).
  Real post content in a shared, twin-consistent template (R1 below covers
  the twin-URL asymmetry).
- `/post/comments`: extend `_COMMENT_TEMPLATE_HTML` (or its generated
  `.html` file) to `{% extends "layouts/site.html" %}{% block content %}
  <div class="comment">{{ comment }}</div>{% endblock %}` — same fix shape
  as Lane 1's `html_body_echo.blade.php.j2`.
- `/settings`: convert to a real settings form page (GET renders the form,
  POST processes it — design contract §4). The whole-POST-body
  mass-assignment shape needs no single named field in the form beyond
  whatever `allowed_fields`-equivalent PicTrail's `/settings` models —
  confirm field names against `profile_bulk_update_sink`'s actual context
  during implementation, don't invent them.
- `/explore`: convert to a real search/listing page rendering results in
  the shared layout — same `sql_boolean`/length-differential concern as
  `php_laravel`'s `/search.php` (R1 in `CC-LAB-0240`'s own register) if
  `/explore`'s SQLi shape is boolean-based; confirm the actual shape
  (`explore_order_by_sink` suggests an ORDER BY / identifier-position
  shape, not boolean-based — verify before assuming R1-style risk applies
  or doesn't).
- `/inbox`: convert to a real message/DM view page with a form for
  composing (`payload`).

### 2c. `/upload/link-preview` client page (api, stays JSON)

A small page with an inline `fetch()` script calling `/upload/link-preview`
with a URL field, linked from the nav — the same "API client page" pattern
`docs/LAB_BROWSABLE_APPS_PLAN.md` §4 already specifies and Lane 1 already
used (CircleFeed's webhook client pages).

### 2d. Absent-input defaults (PA-0053, decided now, not deferred)

For every `param_name`-bearing route in `_ROUTE_PARAMS` (`/post`'s `id`,
`/upload/link-preview`'s `url`, `/explore`'s `sort`), decide and set an
explicit default **before** any sink runs, matching whichever pattern is
correct for that page (a real default value like `php_laravel`'s `?? '1'`,
or a handled 4xx if no sensible default exists — e.g. `/upload/link-preview`
probably has no safe default URL to fetch, so a bare GET should 4xx before
reaching `http_fetch_json_sink`, mirroring Huddle Hub's `/messages/unfurl`
follow-up from `CC-LAB-0241`, but decided here rather than left as a
same-shaped future bug). `/settings`/`/inbox` read the whole POST body, not
a named GET param, so they need no default — a bare GET should show the
form/page, not touch the sink at all (confirm the route only invokes the
sink on POST).

### 2e. Ground truth `rendering` correction

Update `lab/ground-truth-picktrail-django/injection-points.json`'s
`rendering` field only if it is currently misleading after conversion
(matching Lane 1's step 3 precedent of correcting `url`/`rendering` where
wrong, and leaving `auto.py`'s request-encoding meaning otherwise
untouched) — confirm the field's actual consumer (`auto.py:86-96`) still
gets a correct request-encoding signal after the URLs' response bodies
change to HTML.

## 3. Risk register

**R1 — secure-twin URL asymmetry.** Unlike `php_laravel`'s
`canonical_cell_id`/`_twin_url_for`, PicTrail's secure twins keep the
generic `generated/{slug}/` URL while only the vulnerable cell owns the
real path (`__init__.py:249-252`, explicit, deliberate). This means the
shared-layout/leakage-independence contract ("byte-identical for a
vulnerable twin and its secure twin") cannot be verified by visiting "the
same URL, different cell" the way Lane 1's twin-diff tests did — the two
twins are reached via genuinely different URLs today.

**Decision rule (not left open, per round-1 review):** default to branch
(a) — extend `_REAL_PAGE_CELL_IDS`-style pinning so each secure twin gets
its own twin-suffixed URL (e.g. `/post.twin` or a `?twin=1`-free path
variant, mirroring `php_laravel`'s `_twin_url_for` convention) — unless
implementation finds a concrete reason this breaks Django's own URL
resolver or route accumulator (e.g. a naming collision `render_route_
accumulator()` can't express), in which case fall back to branch (b): keep
the asymmetry, add a direct twin-content-equality test comparing the two
different URLs' rendered templates (not the same URL), and record which
branch was used and why as an explicit "R1 sign-off" note in this same
change's `requirements.md` entry (`FR-LAB-160`), mirroring exactly how
`CC-LAB-0241`'s R4 sign-off was recorded — not a bare implementation-time
prose note. (`MIN_GROUPS_FOR_GATE`/`MIN_CELLS_FOR_GATE` are almost
certainly not reached at PicTrail's scale either way, so the leakage gate
itself doesn't fire regardless of which branch is used — this only affects
which direct test proves the contract.)

**R1b — the risk register itself was mis-targeted on first draft (round-1
review finding, corrected here).** The original R3/R6 below speculated
about `/explore`'s SQL shape and a generic "oracle format-agnosticism"
concern without reading the actual sink templates or ground truth first.
Direct reading (done now, not deferred) shows:
- `/explore`'s sink (`explore_order_by_sink.py.j2`) is
  `cursor.execute("SELECT id, name FROM posts ORDER BY " + str(value))` —
  and PicTrail's own ground truth (`lab/ground-truth-picktrail-django/
  labels.json`, case `PT-0005`) states explicitly: "identifier/ORDER-BY-
  position injection, **not a syntax-break shape**." This is *not* a
  length/boolean-differential shape, so `/explore` does **not** carry the
  `CC-LAB-0240`-style length-delta risk R3 originally worried about.
- `/post`'s sink (`sql_numeric_lookup.py.j2`, via `_MODULE_SET_BY_SHAPE`'s
  `("sqli", "sql_numeric_literal")` mapping) is structurally **identical**
  to `php_laravel`'s `/product.php`/`/blog_post.php` — a single-row
  found/not-found lookup, exactly the shape `CC-LAB-0240`'s own R1 found
  needed a designed, literal ≥300-byte found/not-found HTML delta once
  wrapped in a shared layout, so `SqliBooleanStrategy`-style length-ratio
  detection keeps its signal. **This risk belongs on `/post`, not
  `/explore`** — the original draft put it on the wrong cell. See the
  corrected R3 below.
- A dedicated, django-adjacent oracle module exists for `/explore`'s actual
  shape: `fuzzlab/labgen/identifier_sqli_oracle.py` (a differential-response
  prober built specifically because value-context tools like sqlmap can't
  probe an identifier/ORDER-BY-position injection the way they probe an
  ordinary literal — see that module's own docstring). This is a *build-time
  validation* tool (confirming the cell is really vulnerable/secure), not a
  runtime detection strategy read from HTTP responses the way
  `fuzzlab/oracle/strategies.py`'s classes are — so it is unaffected by a
  response-body/layout change either way, but it should be named explicitly
  rather than omitted, since a reviewer checking "did you consider every
  oracle mechanism touching this cell" should find it named, not absent.

**R2 — `DjangoLiveBootHarness` is a separate class from `LiveBootHarness`,
not the same class with a different emitter arg.** Confirmed its API
surface matches what the navigability test needs (`_base_url()`, `get()`,
`post()`, `query_db()`), so the crawl design in §4 should port directly —
but verify this by actually running the crawl against it, not by API-shape
inspection alone (a different internal request-handling path could still
diverge in ways only a real run surfaces, e.g. redirect handling,
trailing-slash behavior in Django's own URL resolver).

**R3 (corrected, round-1 review) — `/post`'s single-row lookup needs the
same designed found/not-found byte-delta `CC-LAB-0240` used for
`php_laravel`'s structurally identical pages.** Confirmed (R1b above):
`/post` uses `sql_numeric_lookup.py.j2`, a single-row found/not-found
shape. Once wrapped in PicTrail's shared layout, `SqliBooleanStrategy`-style
length-ratio detection could lose its signal the same way `CC-LAB-0240`'s
R1 found for `/product.php`/`/blog_post.php`. Mitigated the identical way:
design a literal, independently-verified found/not-found HTML delta of at
least the same order of magnitude `CC-LAB-0240` used (re-measure against
*this* layout's actual byte size, don't reuse `php_laravel`'s 300-byte
number unexamined — PicTrail's layout may be a different size), with a
direct test asserting that delta, not just re-running the oracle strategy's
own test suite. `/explore` (ORDER-BY/identifier-position, confirmed
"not a syntax-break shape" per its own ground truth) does **not** carry
this risk — corrected from the original draft, which had this backwards.

**R4 — `/upload/link-preview`'s SSRF shape and its bare-GET default.** A
bare GET with no `url` param has no safe default to fetch (unlike
`/post`'s `?? '1'`) — decided in §2d as a 4xx-before-sink, but confirm the
real page this ports from (`docs/research/corpus-examples/ssrf/python/
vulnerable-oembed-unfurl-4.py`) doesn't itself define an intended
default worth reproducing, the same care Lane 1 took citing
`git show 876d2f9^` for its own real-page defaults.

**R5 — non-vacuous-pass guard for the navigability test.** Same guard
Lane 1's `CC-LAB-0241` built (assert both the ground-truth count and the
discovered-page count are non-trivial, hard-coded, before any per-URL
assertion) — built into §4 from the start here, not a later addition.

**R6 (corrected, round-1 review) — oracle-mechanism inventory, both kinds.**
Two distinct mechanisms touch these 6 cells, named explicitly rather than
lumped together:
1. `fuzzlab/oracle/strategies.py`'s runtime detection strategies
   (`fuzzlab.oracle.strategies`, shared cross-stack, confirmed
   stack-agnostic by reading their `confirm()` methods) read the live HTTP
   response — confirm none keys on the current JSON shape the way
   `php_laravel`'s `PriceIntegrityBypassStrategy` keyed on
   `"charged_amount":"<canary>"` before `CC-LAB-0239` changed its anchor.
   Re-run every such test touching these 6 cells after conversion, don't
   just read the strategy source.
2. `fuzzlab/labgen/identifier_sqli_oracle.py` (R1b above) is a **build-time**
   differential prober for `/explore`'s identifier/ORDER-BY-position shape,
   confirming the generated cell is really vulnerable/secure. It does read
   the raw TRUE/FALSE probe response bodies (`_classify_response_diff`),
   but its check is a plain body-equality/inequality comparison — format-
   agnostic, so it works identically whether the body is JSON or HTML — and
   is therefore unaffected by this change either way (round-2 accuracy
   review: "reads it but doesn't depend on its format" is the precise
   framing, corrected from an earlier "never reads" overstatement); named
   here so its irrelevance is a confirmed finding, not a silent omission.

**R7 — illustrative (non-real-page) django cells' bare-GET behavior.**
Apply PA-0053's rule proactively to every django route reachable from the
new homepage/nav, not only the 6 real pages — a repeat of Lane 1's
BUG-0051 pattern (illustrative cells 500ing on a bare GET) would be exactly
the kind of late discovery this plan's §0 is meant to avoid. Confirm during
implementation, before the navigability test is declared green, not after.

Accepted, not mitigated: none identified — every risk above has a concrete
verification-or-fix step.

## 4. Navigability acceptance test (built now, not deferred — PA-0053)

New live-boot pytest module (e.g. `tests/test_labgen_django_navigability_live_boot.py`),
directly mirroring `tests/test_labgen_navigability_live_boot.py`'s structure:

1. Boot PicTrail's full site with `DjangoLiveBootHarness`.
2. Crawl from `/` with `fuzzlab.tools.spider.LocalSpider` (`requests`
   engine), same-host scope; measure the real link depth empirically before
   setting the depth cap (R5/R7-equivalent of Lane 1's own R7).
3. **Non-vacuous-pass guard first** (R5 above): hard-coded, measured
   minimums for both the ground-truth count and the discovered-page count.
4. Assert every ground-truth URL is discovered and returns the anonymous
   visitor's correct status (200 for every PicTrail page — no session
   gating exists here, confirmed in §1, so no 401 exception is expected;
   if implementation finds one was missed, that is itself a finding to
   surface, not silently accommodate).
5. Assert `GET /` returns 200.
6. Apply PA-0053 directly: assert every discovered page also responds
   sanely (no 500) when requested without its query parameters, for every
   route the crawl reaches — not just the 6 real pages (R7).

## 5. Sequencing

1. Homepage + shared layout (§2a). Gate: a new offline test asserting the
   layout template exists and every real page's future template can
   extend it (structural, not yet content).
2. Convert `/post`, `/post/comments`, `/settings`, `/explore`, `/inbox`
   (§2b) — one page at a time. Each page's gate, named concretely (per
   round-1 review, not left as unspecified "an assertion"): (i) a bare `GET`
   with no query/body returns the page's decided absent-input status (§2d)
   — 200 with a default value, or a handled 4xx, never a 500; (ii) the
   response body renders inside the shared layout (`{% extends
   "layouts/site.html" %}` present, nav/header visible); (iii) for `/post`
   specifically, the found/not-found byte-delta (R3) is measured and
   asserted ≥ the value decided there. Gate after each page: that page's
   own live-boot test green before moving to the next, so a regression is
   attributable to one page's change.
3. `/upload/link-preview`'s client page (§2c) + its bare-GET 4xx (§2d/R4).
4. Ground-truth `rendering` correction (§2e), only where actually wrong.
5. Build and run the navigability test (§4) — apply PA-0053's bare-GET
   sweep to every reachable route, not only the 6 converted ones (R7).
   **Scope-creep rule, restated from `CC-LAB-0241` (not just cited, per
   round-1 review):** fold a crawl-surfaced defect into this same change
   only if it is the *same class* as this plan's own tracked work — a
   missing nav link, a missing absent-input default, a missing
   `{% extends %}` — and touches only the `LAB` component (specifically:
   only the django emitter's own templates/routes, not another
   component). Anything touching a different component, or needing new
   infrastructure beyond what §2/§4 already design, gets flagged as a
   named follow-up (its own recommended next `CC-LAB` number, not invented
   here) and does not block this step's own Effectiveness assessment for
   the 6 tracked pages plus the homepage/layout.
6. Full non-slow suite + all django live-boot suites (existing +
   `test_labgen_django_conformance.py`/`test_labgen_django_live_boot_phase_b.py`/
   `test_labgen_django_live_boot_single_shape.py`/`test_labgen_django_live_boot_picktrail*.py`
   + the new navigability test) green.

## 6. Deliverables checklist

- [ ] Homepage + shared layout template, structural gate green.
- [ ] `/post` + `/post/comments` converted, bare-GET default decided,
      found/not-found byte-delta designed and asserted (R3), twin asymmetry
      (R1) resolved via its decision rule and recorded as an explicit
      "R1 sign-off" in `requirements.md`'s `FR-LAB-160` entry (mirroring
      `CC-LAB-0241`'s R4 sign-off), live-boot green.
- [ ] `/settings` converted to a real form page, live-boot green.
- [ ] `/explore` converted, actual SQL shape confirmed (R1b), oracle-strategy
      tests re-run (R6), live-boot green.
- [ ] `/inbox` converted to a form page, live-boot green.
- [ ] `/upload/link-preview` client page + bare-GET 4xx (R4), live-boot
      green.
- [ ] Ground-truth `rendering` field corrected where wrong (§2e).
- [ ] Navigability test built and green, including the PA-0053 bare-GET
      sweep across every reachable route (not only the 6 real pages).
- [ ] Any same-class defect the navigability test surfaces fixed and
      folded in; any different-class finding flagged with its own
      recommended next `CC-LAB` number, not absorbed (mirroring
      `CC-LAB-0241`'s rule).
- [ ] Full non-slow suite + every django live-boot suite green.
- [ ] `docs/components/01-target-lab/requirements.md` — new `FR-LAB-160`
      entry.
- [ ] `CHANGELOG.md` — one dated line referencing `CC-LAB-0242`.
- [ ] `docs/LAB_BROWSABLE_APPS_PLAN.md`'s Lane 2 row updated to "done" (or
      to however many steps this actually took, mirroring Lane 1's own
      updates, bumping Lanes 3-7 by +1 again if this needed more than the
      1 pre-reserved `CC-LAB` number).
- [ ] **Bug protocol contingency (added per round-1 review, not in the
      original draft):** if PA-0053's bare-GET sweep (§4 step 6 / §5 step 5)
      finds a real crash the way Lane 1's own sweep found `BUG-0051`, follow
      the full bug protocol using Lane 2's pre-assigned numbers
      (`BUG-0052`/`PA-0054` per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane
      table) — `ERROR_LOG.md` entry, `docs/bugs/BUG-0052-*.md` full RCA
      including a recurrence review against `BUG-0037`/`PA-0039` and
      `BUG-0051`/`PA-0053`, and a preventive-action entry that strengthens
      rather than restates `PA-0053` if the same root cause recurs. If no
      such crash is found, state that explicitly in Effectiveness rather
      than leaving the item silently unaddressed.

## 7. Out of scope

- Lanes 3-7 (other stacks) — unaffected unless this step needs more than
  its pre-reserved single `CC-LAB-0242`, in which case their numbers shift
  by +1 following the exact same discipline Lane 1 used, applied
  immediately rather than deferred (the collision-avoidance lesson from
  `CC-LAB-0241`'s own review).
- Any further django polish beyond PicTrail's 6 real pages and what §4's
  crawl surfaces, subject to §5 step 5's scope-creep rule.

## 8. Review history

**Round 1 (accuracy + adequacy, 2 independent reviewer agents, 2026-09-25):**
ACCURATE / NOT YET ADEQUATE. Accuracy found no inaccuracies. Adequacy found
6 gaps, the most consequential being a genuine risk misattribution: the
original R3/R6 speculated about `/explore`'s shape without reading its sink
template or ground truth, and put the `CC-LAB-0240`-style length-delta risk
on `/explore` (which its own ground truth confirms is "not a syntax-break
shape") instead of `/post` (structurally identical to `php_laravel`'s
`/product.php`/`/blog_post.php`, the actual cells that risk applies to).
Fixed: R1b documents the correction with direct evidence; R3/R6 rewritten
to target the right cells and name `identifier_sqli_oracle.py` explicitly.
Also fixed: R1 given a concrete decision rule instead of two undecided
branches; the scope-creep rule restated in full rather than only cited;
§5 step 2's per-page gate named concretely; §0's "built from the start"
claim narrowed to what's actually true (the spec exists early; the crawl
still runs operationally last); a bug-protocol contingency deliverable
added to §6.

**Round 2 (accuracy + adequacy, same 2 reviewer agents, 2026-09-25):**
ACCURATE / ADEQUATE. Both reviewers independently re-verified the R1b/R3/R6
retargeting directly against the sink templates and ground truth, confirmed
the other 5 fixes, and found no new issues — 3/3 agreement (2 reviewers +
proposing agent) reached. One minor, non-blocking wording imprecision in
R6 ("never reads the response body" overstated `identifier_sqli_oracle.py`'s
format-agnostic body-diff check) was corrected in this same revision. The
plan is converged; implementation still requires its own change-control-
entry gate (see Status line above).

**Post-convergence correction (2026-09-25, during CC-LAB-0242's own entry
gate):** the CC-LAB-0242 entry's accuracy reviewer found this plan's own §6
still cited stale "R3" for `/explore`'s shape-confirmation deliverable, a
leftover from before round 1 redefined R3 to mean `/post`'s byte-delta risk
and introduced R1b for `/explore`'s shape-confirmation history. Fixed here
(§6 now cites R1b) and in the change-control entry to match verbatim — a
citation-label fix, not a change to any risk's actual content or
conclusion, so it does not reopen the plan's own 3/3 convergence above.
