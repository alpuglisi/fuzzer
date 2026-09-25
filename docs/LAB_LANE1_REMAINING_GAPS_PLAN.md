# Lane 1 step 5 — closing the remaining Browsable Labs gaps

Status: **planning, pre-change review gate not yet run.** Reserved as
`CC-LAB-0241` / `FR-LAB-159` ("Lane 1 step 5"). Lanes 2-7's `CC-LAB`/`FR-LAB`
ranges in `docs/LAB_BROWSABLE_APPS_PLAN.md` are bumped by +1 again once this
is gate-cleared, per that document's own "re-derive next free numbers"
instruction — no lane past Lane 1 has consumed a number yet, so this is a
pure table correction, not a rename of anything already used.

## 1. Scope — the three tracked, still-open Lane 1 gaps

Confirmed via direct code reading (this section, not the risk register,
carries the "is this real" verification; §4 covers "will the fix work"):

1. **The spider-based navigability acceptance test itself does not exist.**
   `docs/LAB_BROWSABLE_APPS_PLAN.md` point 6 requires: crawling from `/` with
   fuzzlab's own spider discovers 100% of an app's ground-truth
   injection-point URLs, each returning the response a real anonymous
   visitor would get (200 HTML for a public page; the R8-sign-off 401/redirect
   exception for a page gated behind a login the crawl doesn't have).
   `CC-LAB-0239`'s own Effectiveness assessment flagged this as the one
   deliverable never run. The crawler component itself
   (`fuzzlab.tools.spider.LocalSpider`) already exists and works (BFS from a
   start URL, same-host scope, records every visited URL + status code to a
   SQLite table) — no test anywhere uses it as a navigability/acceptance
   check. This is new test glue, not a new component.
2. **Bare-fragment layout gap** on `/contact.php`, `/newsletter.php`,
   `/edit_profile.php`'s POST/echo responses. Their sink template,
   `templates/sinks/html_body_echo.blade.php.j2`, is the entire response
   body — `<div class="{{ css_class }}">{!! $value !!}</div>` — with no
   `@extends('layouts.site')`, so these 3 pages' POST responses render
   outside the shared nav/header every other converted page now has. (Their
   GET-form pages, e.g. `site/contact.blade.php`, already extend the layout
   correctly — only the POST/echo response is bare.) The shared layout
   (`layouts/site.blade.php`) already defines `@yield('title', ...)` /
   `@yield('content')`, the same mechanism CC-LAB-0239/0240 pages already use.
3. **`/product.php`/`/blog_post.php` 500 with no `?id=`.** Pre-existing (not
   introduced by CC-LAB-0240), flagged there and left as a follow-up.
   `GetParamSource`'s template (`templates/sources/get_param.php.j2`) reads
   `$request->query('id')` with no default; the sink template
   (`templates/sinks/sql_numeric_lookup.php.j2`) string-concatenates that
   `null` straight into the SQL text, producing a syntactically invalid
   query and an uncaught `QueryException` → Laravel 500. The real historical
   page defaulted this: `git show 876d2f9^:puppy-fort-factory/blog_post.php`
   confirms `$id = $_GET['id'] ?? '1';`; the numeric manifest's own header
   comment says the same for `product.php`. Two live nav links currently
   point at these URLs with no `?id=` at all —
   `layouts/site.blade.php:29-30` and `site/home.blade.php:11-12` — so this
   is not theoretical: a real anonymous visitor clicking the nav bar hits it
   today, and it is exactly what gap 1's crawl would trip over.

## 2. Fix design

### 2a. Missing `?id=` default (smallest, do first — it unblocks gap 1's crawl)

Add a per-profile `default_value` key (or reuse an existing per-profile
mechanism if one already fits) consumed by `GetParamSource`'s render, so the
generated line becomes `$request->query('id', '1')` (Laravel's `query()`
takes a default as its 2nd arg) for `/product.php`'s and `/blog_post.php`'s
profiles only — not a blanket change to the shared `get_param.php.j2`
template, since other pages consuming `GetParamSource` may correctly want no
default (e.g. a page whose contract is "missing id is a 4xx", if any such
page exists — checked in §4 R2). Seed data must have a row with `id = 1` in
both the SQLite and MariaDB harnesses' `products` and `posts` tables (§4 R3).

### 2b. Bare-fragment layout fix

Change `html_body_echo.blade.php.j2` to:

```blade
@extends('layouts.site')
@section('title', '{{ page_title }}')
@section('content')
<div class="{{ css_class }}">{!! $value !!}</div>
@endsection
```

This needs a `page_title` context variable threaded into the sink's render
context for these 3 profiles specifically (a short label — "Contact",
"Newsletter", "Edit profile" — not modelled data, so no injection-context
concern). Since `html_body_echo` may be shared by other, non-Lane-1-tracked
cells elsewhere in the manifest set (checked in §4 R1), the title must be
profile-supplied with a sane fallback (e.g. the app name) for any caller
that doesn't set one, rather than becoming a required key that breaks an
unrelated cell's render.

### 2c. Spider-based navigability acceptance test

New pytest module (e.g. `tests/test_labgen_navigability_live_boot.py`),
live-boot only, one test per app (PFF; CircleFeed; Huddle Hub; Booking):

1. Boot the app's full site with the existing `LiveBootHarness` (already
   assembles every cell into one running app — this is not new
   infrastructure, it is the same harness `test_labgen_conformance_live_boot.py`
   already uses, pointed at the harness's own `_base_url()` instead of one
   path at a time).
2. Run `LocalSpider` (the `requests` engine is sufficient — every converted
   page is server-rendered HTML, no client-side JS routing) from `_base_url()
   + "/"`, same-host scope, no depth cap (or a depth cap generous enough to
   cover the site's real link depth, confirmed empirically, not guessed).
3. Load that app's `injection-points.json` (`lab/ground-truth/` for PFF;
   `lab/ground-truth-{circlefeed,huddlehub,booking-clone}/` for the split
   apps) and assert every listed `url` was discovered by the crawl.
4. For each discovered ground-truth URL, assert the status code matches what
   a real anonymous visitor should see: 200 for a public page; the R8
   sign-off's accepted 401 for a session-gated cell in a split app (the
   decision already recorded in `docs/LAB_BROWSABLE_APPS_PLAN.md` point 6);
   for PFF's own session-gated cells (`LABGEN-MA-0003`/`0004`, explicitly
   *not* covered by the R8 split-app exception since PFF has its own login
   flow from step 1) — see R4 below for how the crawl handles authentication.
5. Assert `GET /` returns 200 for every app.

## 3. Sequencing

1. Fix 2a (missing-id default) first — it removes a live 500 that would
   otherwise fail step 3's crawl for reasons unrelated to what step 3 is
   actually testing. Run the existing PFF live-boot suites green before
   proceeding (no cell/route touched besides these 2 profiles' source
   rendering — confirm no other test asserts the current 500 as expected
   behavior, R2).
2. Fix 2b (bare-fragment layout) next. Run the existing test suite green
   (in particular any oracle-strategy test touching these 3 cells, R1)
   before proceeding.
3. Build and run 2c (navigability test) last, once both live defects it
   would otherwise catch are already fixed. Iterate on real crawl results
   (depth cap, form-page reachability, R5/R6/R7 below) until every app's
   assertion passes for real — this step is allowed to reveal further small
   fixes elsewhere (e.g. a page not yet linked from anywhere); if it does,
   fix them here rather than deferring again, since deferring this exact
   check is the recurring pattern this step exists to end.
4. Full non-slow suite + all live-boot suites (SQLite + MariaDB + the new
   navigability tests) green.

## 4. Risk register

**R1 — `html_body_echo` may be shared by cells outside this plan's 3 pages.**
Verify (`_PAGE_PROFILES` + module-composition search) every cell that
resolves to the `html_body_echo` sink module before changing its shared
template. If any belong to a cell outside `/contact.php`/`/newsletter.php`/
`/edit_profile.php`, confirm the `page_title` fallback keeps their render
context valid (no `KeyError`/`UndefinedError` from Blade or Jinja) and that
wrapping their response in the shared layout does not change what their own
oracle-strategy tests (if any) assert against the body — re-run those tests,
don't just read them. If any such cell participates in
`SqliBooleanStrategy`'s length-ratio check (unlikely — these are `html_body`
XSS-context cells, not `sql_boolean` cells — confirm directly, don't assume),
apply the same designed-delta discipline `CC-LAB-0240`'s R1 used.

**R2 — the missing-id default could change behavior a test currently
depends on.** Grep the full test suite for any assertion that
`/product.php` or `/blog_post.php` with no `?id=` currently returns 500 (as
expected/intended behavior, not just as an unfixed known gap) before
changing it. If found, that assertion is itself the artifact of the bug
this step fixes — update it, don't work around it.

**R3 — seed-data availability.** Confirm both the SQLite live-boot harness's
seed data and the MariaDB harness's `lab/sql/schema.sql`-driven seed data
contain a row with `id = 1` in `products` and in `posts` (the schema
mismatch CC-LAB-0240's R6 already found between these two harnesses'
`posts` table makes this worth checking explicitly, not assuming parity).

**R4 — PFF's session-gated cells need real authentication for the crawl,
not the split-apps' R8 exception.** `LABGEN-MA-0003`/`0004` are built into
PFF's default merged build, which has its own login flow (step 1,
`CC-LAB-0237`). The navigability test must either (a) seed an authenticated
session before crawling PFF (the existing LAB-owned session helper /
`browserauth` module referenced by `LocalSpider`'s own `--identity` flag
looks like the fit — confirm it can mint a cookie jar this test can attach
to a `requests`-engine crawl before treating it as available) or (b) crawl
PFF anonymously and explicitly assert the 401/redirect anonymous-visitor
response for those two URLs specifically, documenting that as PFF's own
accepted anonymous-crawl outcome for exactly these 2 cells — distinct from,
and narrower than, the R8 split-app exception, which does not apply to PFF.
Decide and document explicitly during implementation; do not let this
silently default to whichever branch happens to compile first.

**R5 — link-only crawl vs. POST-only endpoints.** `LocalSpider` follows
`<a href>` (and, in the Playwright engine, `fetch()`/XHR targets) — it does
not parse `<form action>`. This is very likely fine, not a gap: per the
shared design contract (`docs/LAB_BROWSABLE_APPS_PLAN.md` §4), every POST
endpoint's URL is also its own GET-served form page, and every genuine API
endpoint has a linked client page using `fetch()` (which the Playwright
engine's XHR capture already records). Verify this holds for every
ground-truth URL before relying on it — for any URL where it doesn't
(a POST endpoint reachable only via a form on a page that itself isn't
linked from anywhere, or an API called by a page using something other than
`fetch()`), fix the missing link/page rather than extending the spider to
parse form actions it doesn't need to.

**R6 — the split apps' live-boot harness must serve the *whole* site, not
one cell.** Confirm `LiveBootHarness._assemble()` (or the split-app
equivalent used by CircleFeed/Huddle Hub/Booking's own tests) actually
builds every page of that app's manifest into one running instance the
spider can crawl end-to-end, not a single rendered cell in isolation — this
is the same harness existing live-boot tests already use, so this is a
confirmation, not new work, but confirm it for each of the 3 split apps
specifically before assuming parity with PFF's harness.

**R7 — crawl depth / start point.** `LocalSpider` takes a `--max-depth`;
confirm empirically (not guessed) the real link depth from `/` to every
ground-truth URL in each app, and set the test's depth cap with headroom
above that measured number, not an arbitrary default.

Accepted, not mitigated: none identified — every risk above has a concrete
verification-or-fix step, no risk is waved through.

## 5. Out of scope

- Lanes 2-7 (other stacks) — unaffected by this step; only their
  pre-reserved `CC-LAB`/`FR-LAB` numbers shift (§ header).
- Any further navigability polish beyond the 3 tracked gaps and what step 3
  (§3.3) surfaces along the way.
