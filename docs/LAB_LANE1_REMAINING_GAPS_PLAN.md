# Lane 1 step 5 — closing the remaining Browsable Labs gaps

Status: **plan reviewed and converged, 3/3 agreement reached 2026-09-25**
(2 independent reviewer agents plus the proposing agent, after 1 revision
round — see §7 Review history). Reserved as `CC-LAB-0241` / `FR-LAB-159`
("Lane 1 step 5"). This collided with Lane 2's then-current reservation
(also `CC-LAB-0241`/`FR-LAB-159-160`); fixed **already, not deferred** —
`docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table is bumped in this same
change (Lanes 2-7's `CC-LAB` numbers +1, their `FR-LAB` ranges +1 again),
so `CC-LAB-0241`/`FR-LAB-159` are genuinely free as of this commit. The
condensed change-control entry cleared its own 2-reviewer gate (3/3), and
the plan was **implemented 2026-09-25** — see `CC-LAB-0241`'s Deliverables
and Effectiveness for what was verified, the R4 decision (branch (b)), and
the two different-class follow-ups the crawl surfaced.

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
   `/edit_profile.php`, **and `/profile.php`** (4 pages, not 3 — round-1
   accuracy review found `/profile.php`'s page profile,
   `_PAGE_PROFILES["/profile.php"]`, `real_page: True`,
   `ground_truth_case: PFF-0005`, resolves through the
   `("xss","html_body")` module-set mapping to the same `html_body_echo`
   sink as the other 3, and there is no separate `profile.blade.php` view in
   the skeleton — only `edit_profile.blade.php` exists — so `/profile.php`'s
   real, GET-served, anonymous-visitor-facing response is bare today too,
   not merely a theoretical R1 risk). Their sink template,
   `templates/sinks/html_body_echo.blade.php.j2`, is the entire response
   body — `<div class="{{ css_class }}">{!! $value !!}</div>` — with no
   `@extends('layouts.site')`, so these 4 pages' responses render outside
   the shared nav/header every other converted page now has. (`/contact.php`,
   `/newsletter.php`, `/edit_profile.php`'s GET-form pages, e.g.
   `site/contact.blade.php`, already extend the layout correctly — only
   their POST/echo response is bare; `/profile.php` has no separate form
   page at all, since it's a pure read/display page.) The shared layout
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
context for these 4 profiles specifically (a short label — "Contact",
"Newsletter", "Edit profile", "Profile" — not modelled data, so no
injection-context concern). Since `html_body_echo` may be shared by other,
non-Lane-1-tracked cells elsewhere in the manifest set (checked in §4 R1),
the title must be profile-supplied with a sane fallback (e.g. the app name)
for any caller that doesn't set one, rather than becoming a required key
that breaks an unrelated cell's render.

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
   apps) and **first assert the ground-truth list itself is non-trivial**
   (`assert len(ground_truth) >= N` for a known, per-app expected minimum —
   read the file's actual count at implementation time and hard-code that
   number, don't compute it from the same file being asserted against) and
   that **the crawl itself found more than a trivial number of pages**
   (`assert len(discovered_pages) >= N`, same discipline) — a guard against
   an empty ground-truth load or a crawl that silently failed to start both
   satisfying a naive per-URL loop vacuously (the exact class of bug
   CC-LAB-0240's R2 already found once in this codebase, `mariadb.py:431`).
   Only then assert every listed ground-truth `url` was discovered by the
   crawl.
4. For each discovered ground-truth URL, assert the status code matches what
   a real anonymous visitor should see: 200 for a public page; the R8
   sign-off's accepted 401 for a session-gated cell in a split app (the
   decision already recorded in `docs/LAB_BROWSABLE_APPS_PLAN.md` point 6);
   for PFF's own session-gated cells (`LABGEN-MA-0003`/`0004`, explicitly
   *not* covered by the R8 split-app exception since PFF has its own login
   flow from step 1) — apply the R4 decision below.
5. Assert `GET /` returns 200 for every app.
6. Depth cap and per-URL reachability sub-items are filled in from §4 R5-R7's
   measurements once taken (not left as an open-ended "iterate until green"
   — see §3 step 3's scope-creep rule for what a crawl-surfaced defect does
   to this checklist).

## 3. Sequencing

1. Fix 2a (missing-id default) first — it removes a live 500 that would
   otherwise fail step 3's crawl for reasons unrelated to what step 3 is
   actually testing. **Gate:** `tests/test_labgen_conformance_live_boot.py`,
   `tests/test_labgen_conformance_live_boot_mariadb.py`, and
   `tests/test_labgen_php_laravel_pff_html_pages.py` (CC-LAB-0240's own
   `/product.php`/`/blog_post.php` twin-diff and byte-delta tests) all green
   before proceeding (no cell/route touched besides these 2 profiles' source
   rendering — confirm no other test asserts the current 500 as expected
   behavior, R2).
2. Fix 2b (bare-fragment layout) next. **Gate:**
   `tests/test_labgen_conformance_live_boot.py`,
   `tests/test_labgen_conformance_live_boot_mariadb.py`,
   `tests/test_oracle_browser.py`, `tests/test_labgen_conformance_tier1.py`,
   `tests/test_labgen_php_laravel_real_pages_forms.py`,
   `tests/test_labgen_php_laravel_real_pages_g4.py`,
   `tests/test_labgen_sink_endpoint.py`, `tests/test_labgen_context_depth.py`,
   and `tests/test_auto.py` (every file that references these 4 cells or
   `html_body_echo`, per a direct grep at plan time — re-grep at
   implementation time in case the set has grown) all green before
   proceeding.
3. Build and run 2c (navigability test) last, once both live defects it
   would otherwise catch are already fixed. Fill in the depth cap and
   per-URL reachability sub-items (§2c step 6) from R5-R7's measurements.
   **Scope-creep rule for anything the crawl newly surfaces:** fold a
   crawl-surfaced defect into this same `CC-LAB-0241` entry only if it is
   the *same class* as the 3 tracked gaps — a missing nav link, a missing
   default value, a missing `@extends` — and touches only the `LAB`
   component. Anything touching a different component, or requiring new
   infrastructure beyond what §2 already designs, gets flagged in this
   plan's own follow-up note (mirroring how CC-LAB-0240 flagged this very
   step) and split into its own, separately-numbered `CC-LAB` entry — it
   does not get silently absorbed here, and it does not block this step's
   own Effectiveness assessment for the 3 gaps this step was actually
   scoped to close.
4. Full non-slow suite + all live-boot suites (SQLite + MariaDB + the new
   navigability tests) green.

## 4. Risk register

**R1 — `html_body_echo` may be shared by cells outside this plan's 4 pages.**
Verify (`_PAGE_PROFILES` + module-composition search) every cell that
resolves to the `html_body_echo` sink module before changing its shared
template. If any belong to a cell outside `/contact.php`/`/newsletter.php`/
`/edit_profile.php`/`/profile.php`, confirm the `page_title` fallback keeps their render
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
`CC-LAB-0237`). Two branches:
  - (a) seed an authenticated session before crawling PFF (`browserauth`,
    the module `LocalSpider`'s own `--identity` flag already wires in for
    the Playwright engine, mints a cookie jar via the LAB-owned session
    helper), or
  - (b) crawl PFF anonymously and explicitly assert the anonymous-visitor
    401/redirect for those two URLs specifically.

**Decision rule (not left open):** try (a) first — spend one concrete spike
attempting to attach `browserauth`'s cookie jar to the navigability test's
crawl (the `requests` engine if it can carry cookies that way, or the
Playwright engine via `--identity` otherwise). If that spike succeeds within
this step's own implementation session, use (a) — it proves the *whole*
authenticated site is reachable, which is the stronger and more honest
check. If it does not attach cleanly (e.g. `browserauth` only supports the
Playwright engine and PFF's app has no reason to need JS rendering
otherwise, making the switch itself a scope question), fall back to (b)
without re-litigating it further. **Either way, the outcome is not left as
an implementation-time prose note**: record which branch was used, and why,
in `docs/components/01-target-lab/requirements.md`'s `FR-LAB-159` entry (a
short "R4 sign-off" callout, the same durable-record pattern
`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6 already used for the R8 sign-off)
so a future reader doesn't have to re-derive it from test source.

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
  pre-reserved `CC-LAB`/`FR-LAB` numbers shift (§ header; already applied to
  `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table in this same commit, not
  deferred to "once gate-cleared").
- Any further navigability polish beyond the 3 tracked gaps and what step 3
  (§3.3) surfaces, subject to §3 step 3's scope-creep rule — a
  different-component or new-infrastructure finding gets its own numbered
  entry, not folded in here.

## 6. Deliverables checklist (drafted here so the change-control entry can
copy it directly, per round-1 adequacy review)

- [x] `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table bumped for the
      `CC-LAB-0241`/`FR-LAB-159` collision — **done as part of this plan's
      own commit**, ahead of the change-control entry.
- [x] §3 step 1 gate: missing-`?id=` default added for `/product.php` and
      `/blog_post.php`; the 3 named gate test files green.
- [x] §3 step 2 gate: `html_body_echo.blade.php.j2` extends the shared
      layout with a `page_title` variable; all 4 cells' pages (`/contact.php`,
      `/newsletter.php`, `/edit_profile.php`, `/profile.php`) render inside
      the shared nav/header; the named gate test files green.
- [x] §2c navigability test built and green for all 4 apps (PFF; CircleFeed;
      Huddle Hub; Booking), including the non-vacuous ground-truth-count and
      discovered-page-count guards (§2c step 3).
- [x] R4 sign-off recorded in `requirements.md`'s `FR-LAB-159` entry (which
      branch, (a) or (b), and why).
- [x] Any crawl-surfaced same-class defect (§3 step 3's scope-creep rule)
      fixed and folded in; any different-class finding flagged with its own
      recommended next `CC-LAB` number, not silently absorbed.
- [x] Full non-slow suite + all live-boot suites (SQLite + MariaDB + the new
      navigability tests) green.
- [x] `docs/components/01-target-lab/requirements.md` — new `FR-LAB-159`
      entry.
- [x] `CHANGELOG.md` — one dated line referencing `CC-LAB-0241`.

(All checked off 2026-09-25 at implementation; `CC-LAB-0241`'s own
Deliverables list is the authoritative, annotated copy.)

## 7. Review history

**Round 1 (accuracy + adequacy, 2 independent reviewer agents, 2026-09-25):**
NOT YET ACCURATE / NOT YET ADEQUATE. Accuracy found: (a) `/profile.php` is a
real 4th page in the bare-fragment state, not a hypothetical R1 risk — fixed
throughout §1/§2b/§4 R1; (b) the `CC-LAB-0241`/`FR-LAB-159` reservation
collided with Lane 2's then-current, already-live reservation — fixed by
applying the lane-table bump immediately in this commit, not deferring it.
Adequacy found 6 gaps: R4's decision left undecided with no forcing
function (fixed — concrete decision rule + durable `requirements.md`
sign-off requirement added); no vacuous-pass guard on the navigability
test's ground-truth/discovered-page counts (fixed — §2c step 3); no
scope-creep boundary for crawl-surfaced defects (fixed — §3 step 3); vague,
unnamed sequencing gates (fixed — §3 steps 1-2 now name the exact test
files); §2c's "iterate until green" language not checklist-able (fixed —
split into §2c step 6 and this plan's own §6 checklist, drafted so the
change-control entry can copy it directly); the lane-table edit not listed
as its own deliverable (fixed — §6). All fixes applied in that revision.

**Round 2 (accuracy + adequacy, same 2 reviewer agents, 2026-09-25):**
ACCURATE / ADEQUATE. Both reviewers independently confirmed every round-1
fix, with no new issues raised — 3/3 agreement (2 reviewers + proposing
agent) reached. The plan is converged; implementation still requires its
own change-control-entry gate (see Status line above), per this project's
process.
