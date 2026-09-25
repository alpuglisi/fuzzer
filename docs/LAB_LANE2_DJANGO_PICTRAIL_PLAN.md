# Browsable Labs Lane 2 — django: PicTrail

Status: **planning, pre-change review gate not yet run.** Reserved as
`CC-LAB-0242` / `FR-LAB-160` per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane
table.

## 0. What Lane 1 taught us, applied here from the start

Lane 1 (`php_laravel`) needed 5 sequential change-control entries because
several things were discovered late: a spider-based navigability test was
deferred to the very end (CC-LAB-0241) instead of built alongside the page
conversion; missing-request-parameter defaults were found only by that late
crawl (BUG-0051/PA-0053); and page-vs-api classification, URL-pinning, and
risk coverage were each drafted, then found incomplete on review, more than
once. This plan applies those lessons up front rather than repeating the
discovery order:

- The navigability acceptance test is **§4 of this same plan**, not a
  follow-up step — PA-0053 already requires it as part of what "converted"
  means for every Browsable Labs lane.
- Every converted page's absent-input behavior is decided in §2 alongside
  its conversion, not left to a crawl to find (PA-0053's own rule).
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
twins are reached via genuinely different URLs today. Mitigated: either (a)
extend `_REAL_PAGE_CELL_IDS`-style pinning to give the secure twin a
twin-suffixed URL too (the smaller, more consistent fix, matching
`php_laravel`'s mechanism), or (b) if that's out of this step's scope,
explicitly document why the asymmetry is acceptable at PicTrail's current
scale (`MIN_GROUPS_FOR_GATE`/`MIN_CELLS_FOR_GATE` almost certainly not
reached, so the leakage gate doesn't fire here either way) and add a direct
twin-content-equality test comparing the two different URLs' rendered
templates instead of the same URL. Decide and document explicitly during
implementation, not left open — same discipline `CC-LAB-0241`'s R4 used.

**R2 — `DjangoLiveBootHarness` is a separate class from `LiveBootHarness`,
not the same class with a different emitter arg.** Confirmed its API
surface matches what the navigability test needs (`_base_url()`, `get()`,
`post()`, `query_db()`), so the crawl design in §4 should port directly —
but verify this by actually running the crawl against it, not by API-shape
inspection alone (a different internal request-handling path could still
diverge in ways only a real run surfaces, e.g. redirect handling,
trailing-slash behavior in Django's own URL resolver).

**R3 — `/explore`'s actual SQL shape is unconfirmed.** The plan infers an
ORDER BY/identifier-position shape from the sink's name
(`explore_order_by_sink`) but has not read the sink template directly.
Confirm the actual shape and its oracle strategy before assuming or ruling
out an `R1`-style (`CC-LAB-0240`) length-differential risk from wrapping
the response in a shared layout.

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

**R6 — oracle-strategy format-agnosticism.** Confirm django's own oracle
strategies (or the shared cross-stack ones, if `fuzzlab/oracle/strategies.py`
is stack-agnostic — check) don't key on the current JSON shape the way
`php_laravel`'s `PriceIntegrityBypassStrategy` keyed on
`"charged_amount":"<canary>"` before `CC-LAB-0239` changed its anchor.
Re-run every oracle test touching these 6 cells after conversion, don't
just read the strategy source.

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
   (§2b) — one page at a time, each with its own bare-GET default decision
   (§2d) and its own live-boot assertion update. Gate after each: that
   page's own live-boot test green before moving to the next, so a
   regression is attributable to one page's change.
3. `/upload/link-preview`'s client page (§2c) + its bare-GET 4xx (§2d/R4).
4. Ground-truth `rendering` correction (§2e), only where actually wrong.
5. Build and run the navigability test (§4) — apply PA-0053's bare-GET
   sweep to every reachable route, not only the 6 converted ones (R7),
   fixing what it finds as the same class of change, flagging (not
   absorbing) anything genuinely different-class, mirroring `CC-LAB-0241`'s
   own scope-creep rule.
6. Full non-slow suite + all django live-boot suites (existing +
   `test_labgen_django_conformance.py`/`test_labgen_django_live_boot_phase_b.py`/
   `test_labgen_django_live_boot_single_shape.py`/`test_labgen_django_live_boot_picktrail*.py`
   + the new navigability test) green.

## 6. Deliverables checklist

- [ ] Homepage + shared layout template, structural gate green.
- [ ] `/post` + `/post/comments` converted, bare-GET default decided, twin
      asymmetry (R1) resolved or explicitly documented, live-boot green.
- [ ] `/settings` converted to a real form page, live-boot green.
- [ ] `/explore` converted, actual SQL shape confirmed (R3), oracle-strategy
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

## 7. Out of scope

- Lanes 3-7 (other stacks) — unaffected unless this step needs more than
  its pre-reserved single `CC-LAB-0242`, in which case their numbers shift
  by +1 following the exact same discipline Lane 1 used, applied
  immediately rather than deferred (the collision-avoidance lesson from
  `CC-LAB-0241`'s own review).
- Any further django polish beyond PicTrail's 6 real pages and what §4's
  crawl surfaces, subject to §5 step 5's scope-creep rule.
