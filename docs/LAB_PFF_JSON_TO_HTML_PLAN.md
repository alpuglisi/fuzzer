# PFF's own real pages: JSON→HTML conversion — implementation + risk plan

Status: **implemented 2026-09-25** (`CC-LAB-0240`; see that entry's
Deliverables/Effectiveness for what was verified). Originally planning-only
(2026-09-25, revised 2026-09-25 after 2 independent reviewer agents checked
accuracy and adequacy per `docs/components/README.md`'s pre-change review
gate).
Reserved as `CC-LAB-0240`/`FR-LAB-158` — **Lane 1 step 4** of
`docs/LAB_BROWSABLE_APPS_PLAN.md`. This reservation required bumping Lanes
2-7's `CC-LAB`/`FR-LAB` numbers by +1 in that parent plan (the same
discipline it already used once, when Lane 1 grew from 1 to 3 steps),
since `CC-LAB-0240` was already pre-assigned there to Lane 2.

## Why this exists

`docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md` (Lane 1 step 3, CC-LAB-0239) asserted
"PFF's own real pages are already HTML... PFF needs no work in this step,"
based on `lab/ground-truth/injection-points.json` already saying
`"rendering": "server"` for these pages. That inference was wrong: `rendering`
in this ground truth format has exactly one functional consumer
(`fuzzlab/harness/auto.py:86-97`, deciding whether to send a JSON *request*
body) and says nothing about the actual *response* format the generated code
produces. A real build shows 5 of PFF's own migrated real pages still return
`response()->json($rows)`. This plan scopes fixing that gap, found and
confirmed by a dedicated research pass (not re-derived here; see citations
throughout).

## 1. Inventory

| Page | Cells | Manifest | Current response | Sink shape |
|---|---|---|---|---|
| `/product.php` | `LABGEN-RPL-PRODUCT` (vuln) / `LABGEN-RPL-PRODUCT-BOUND` (secure) | `phase3_php_laravel_real_pages_numeric.yaml` | `response()->json($rows)` | `DB::select(...)` → list |
| `/blog_post.php` | `LABGEN-RPL-BLOGPOST` / `LABGEN-RPL-BLOGPOST-BOUND` | same | same | `DB::select(...)` → list |
| `/products.php` | `LABGEN-PLRP-G2-0001` (secure-only) | `phase3_php_laravel_real_pages_g2.yaml` | same | `DB::table(...)->get()->all()` → list |
| `/search.php` | `LABGEN-PL-RP-0001` / `0002` (SQLi twins; 4 more XSS cells share this profile but use a different complexity, unaffected — see R-COMPAT) | `phase3_php_laravel_real_pages_search.yaml` | same | `DB::table(...)->whereRaw(...)->get()->all()` → list |
| `/register.php` | `LABGEN-PLA-0003` only (**no `LABGEN-PLA-0004`** — corrected; the manifest has exactly 3 cells, PLA-0003 is secure-only) | `phase3_php_laravel_real_pages_auth.yaml` | `register_insert` tail: JSON 409 on duplicate, JSON 200 on success | `DB::table('users')->where(...)->get()->all()` → list, then an `insert()` |

**Confirmed out of scope, with reasons (not oversights):**
- `/login.php` — success path already redirects (real page behavior); only
  its failure path is JSON (`401`). Small, same-shape issue as `register.php`'s
  duplicate-error path; **included in this plan** as a one-line tail change
  (see §3), not deferred, since it's the same mechanism already being touched.
- `/contact.php`, `/newsletter.php`, `/edit_profile.php` — already
  `return view(...)`. **Known, separate limitation, not silently ignored**:
  the rendered views are bare fragments (e.g. `<div class="notice ok">...</div>`)
  that don't `@extends('layouts.site')`, so they don't get the shared nav/
  header — confirmed this is a different mechanism entirely (the sink
  template itself, `html_body_echo.blade.php.j2`, not a tail flag), so it
  is a genuinely separate bug from this plan's JSON→HTML scope, correctly
  kept out rather than folded in. **Escalated per review**, since its
  user-visible impact is real: once this plan lands, the site will have 5
  more pages with full nav/header and 3 pages (on their POST/error paths)
  still bare-fragment — a visible inconsistency against
  `docs/LAB_BROWSABLE_APPS_PLAN.md`'s own "consistent, browsable site"
  goal. **Recommend this becomes the next CC-LAB-numbered step** after this
  one, not left as an unweighted aside.
- `/api/products.php` — genuine JSON API, correctly JSON.
- `/add_to_cart.php`, `/cart.php`, `/checkout.php` — appear only in
  `injection-points.json` (parameter discovery), never in `labels.json`
  (verdict cases) or any manifest — **no cell exists for these paths at all**.
  Not a rendering defect; there is nothing generated to convert. Confirmed
  by grep across every manifest and `labels.json`.
- `/track.php` — pre-existing, documented exemption (`PFF-1002`,
  `lab/ground-truth/migration-exemptions.yaml`): no sink at all, so no
  rendering format applies.

## 2. New mechanism: `$rows` here is a **list**, not the assoc-array shape `html_row_view` assumes

CC-LAB-0239's `html_row_view` tail does `return view($name, $rows)`, relying
on `$rows` being an associative array (`['id'=>1,'caption'=>'...']`) so
Laravel's `extract()` turns each key into a Blade variable. **Confirmed by
direct test** (research agent ran `extract([0 => (object)[...]], EXTR_SKIP)`
locally): a numeric-indexed list extracts **zero** variables. Every one of
these 5 pages' sinks (`DB::select(...)`, `->get()->all()`) always returns a
numeric list — even a primary-key lookup, since these use `DB::select`
rather than `->first()`/`->firstOrFail()`. Reusing `html_row_view` as-is
would silently render an empty page.

**New tail, `html_list_view`**: `return view($name, ['rows' => $rows]);` —
wraps the list under one `$rows` variable name; the Blade view iterates with
`@forelse ($rows as $row) ... @empty ... @endforelse`, matching the real,
pre-cutover Puppy Fort Factory pages' own empty-state text (recovered from
git history, commit `876d2f9^`, `puppy-fort-factory/{product,blog_post}.php`):
`"Sorry, we couldn't find that fort."` / `"Post not found."` — reused
verbatim rather than invented, so the fake app's copy matches what it
modeled.

**Mechanical hygiene, since I'm touching this file anyway (found by the
research pass, not previously flagged):** neither `html_row_view` nor the
new `html_list_view` has a named module-level constant (unlike
`_SESSION_LOGIN_KEY`/`_REGISTER_INSERT_KEY`), and `render()` never pops
either — they reach the Jinja context as bare literals, and the template's
`{% elif %}` chain means a profile that accidentally set two tail flags at
once would silently prefer whichever branch comes first, with no error.
This plan adds `_HTML_ROW_VIEW_KEY`/`_HTML_LIST_VIEW_KEY` constants,
pops both in `render()` (matching every other profile flag), and adds a
fail-loud check if a profile sets more than one tail flag
(`session_login`/`html_row_view`/`html_list_view`/`register_insert`)
at once — a real robustness gap now that 6 profiles use one of these
flags instead of 2.

## 3. `register.php`'s duplicate/success tail (and `login.php`'s failure tail)

**No precedent for "redisplay the form with an inline error" exists
anywhere in this stack** (confirmed: `SiteController::registerForm()` takes
no data, `site/register.blade.php` has no error slot or field prefill, and
no `withErrors`/`old()`/`@if` pattern exists in the skeleton). The real,
pre-cutover PFF page *did* have exactly this UX (recovered from git history,
`876d2f9^:puppy-fort-factory/register.php`): duplicate re-renders the same
page with `<p class="notice err">That username is already taken.</p>` and
the username field prefilled; success shows
`<p class="notice ok">Welcome to the pack, {{ $username }}! You can now <a href="login.php">log in</a>.</p>`.
This plan reuses that real copy rather than inventing new UX. **Verified,
not just copied (per review):** the historical page's fields
(`username`/`email`/`full_name`/`password`) were checked against the
*current* skeleton's `resources/views/site/register.blade.php` — it already
has exactly those same four fields, so there is no field-name mismatch to
introduce by reusing this copy.

**Status codes preserved** (200/409, matching what tests already pin — see
§4): the tail still returns 409 on duplicate and 200 on success; only the
body becomes HTML. The `"That username is already taken."` string stays a
literal in the generated PHP (passed as a view variable), so the existing
static assertion in `tests/test_labgen_php_laravel_real_pages_auth.py:132-134`
(checks the string appears *in the controller source*) needs no change.

`login.php`'s failure tail gets the same treatment: its `error_message`
(`"Invalid username or password."`) renders in a real HTML error page
instead of a JSON 401 body, reusing the same `site/login.blade.php` form
with an error slot added (mirroring register's own new error slot) —
status code (401) unchanged.

## 4. Risk register

### R1 — `SqliBooleanStrategy`'s length-ratio detection could silently break once wrapped in a shared layout (found by the research pass, genuinely novel)

**Found:** `SqliBooleanStrategy.confirm` (`fuzzlab/oracle/strategies.py:206-224`)
confirms only if the "true" probe's body length is close to the benign
body's (`_similar`, `abs(len(a)-len(b)) <= max(24, 0.05*max(len(a),len(b)))`)
**and** the "false" probe's body is *not* close to either. Today the bodies
are tiny JSON arrays (`[{...}]` vs `[]`) — a "found" vs "not found" delta is
the entire content. Once every response includes `layouts.site.blade.php`
(≈1,947 bytes), the delta becomes a small fraction of a much larger shared
page, and the 5%-of-max-length threshold scales up with it (≈100 bytes at
this layout's size). **If the "not found" state's content is much shorter
than the "found" state's** (e.g. a one-line "not found" message vs a full
product listing), the absolute byte delta could still clear the threshold —
but this must be a designed property of the templates, not an accidental
one, since a future page redesign could quietly shrink it back under
threshold with no test catching the regression until oracle detection goes
dark.

**Mitigation, made concrete per review** (an earlier revision said only
"comfortably over the threshold" — too qualitative to build or check
against, and risked a circular test that just re-derives the strategy's own
math): design each new Blade view to render enough real per-row content
(name, description, price, category — the actual columns these tables
have, not a truncated placeholder) that a found-vs-not-found delta is **at
least 300 bytes** — a fixed, independently-chosen number with real headroom
over the ~100-byte threshold at this layout's size, not derived from the
threshold formula itself. Add an explicit, direct test asserting the
rendered HTML's own found-vs-not-found byte-length delta is `>= 300`
(a literal length comparison on the actual template output, not a
recomputation of `_similar`'s formula — the two must stay independent, or a
future change to the strategy's own threshold could silently make the test
meaningless). This is the regression guard that survives future content
changes; re-running the oracle strategy's own test only proves today's
fixture data clears the bar, not that the templates will keep doing so. Run
`SqliBooleanStrategy`'s own test suite (`tests/test_oracle.py`) unchanged as
a negative control (it uses plain-text fixtures, format-agnostic, confirmed
by 2 independent reviewers reading `_similar`'s exact formula and the
layout's exact byte size, 1947 bytes) — expected to need no change, verify
it doesn't.

### R2 — 8 existing live-boot assertions count literal JSON syntax and will break

**Found (exhaustive, from the research pass):** `tests/test_labgen_conformance_live_boot.py`
(SQLite) and `tests/test_labgen_conformance_live_boot_mariadb.py` (MariaDB)
— both actually execute in this environment, not skipped — have 6 assertions
that `.count('"id"')` against response bodies for `/product.php` and
`/search.php`, and 2 `json.loads(reg_resp.body) == {"registered": True}`
equality checks for `/register.php`. One assertion
(`mariadb.py:431`, `secure_resp.body.count('"id"') == 0`) would **pass
vacuously** on any HTML page that never happens to contain the literal
string `"id"` — a silent false-pass, not a red test, the most dangerous
kind of breakage since nothing flags it. All 8 (plus the 2 status/body
pairs for register's success/duplicate paths) must be rewritten to check
HTML-appropriate content (row name/description present or absent, matching
the existing agnostic assertions already in the same tests), never left as
a vacuously-true check.

### R3 — `/search.php`'s shared profile: 4 XSS cells must stay unaffected

**Found:** `/search.php`'s one `_PAGE_PROFILES` entry is shared by 6 cells;
the 2 SQLi twins (`PL-RP-0001`/`0002`) use `single_statement` (reads the
whole profile as Jinja context), the other 4 XSS cells use `render_only`
(**correction, per review**: `RenderOnlyComplexity.render` passes 4 explicit
keys, not 3 — `body`, `method_name`, `view_name`, and `value_expr`,
confirmed by reading `modules.py:1457-1462`; none of the 4 is a tail-selection
flag, so a new `html_list_view` key on the shared profile still cannot reach
these cells — the correction doesn't change R3's conclusion, only its count).
**Mitigation:** none needed beyond confirming this stays true after the
change — add it as an explicit assertion (the 4 XSS cells' rendered
controllers must still contain no `html_list_view`-tail code), so a future
refactor of `RenderOnlyComplexity` can't silently regress this isolation
unnoticed.

### R4 — regression gate / ground truth: confirmed no risk (verified, not assumed)

**Found:** `regression_gate.py`'s `diff_ground_truth` compares only
`case_id`, `url`, and `expected_vulnerable` (`PageChange`/`VerdictChange`
dataclasses, `regression_gate.py:52-63,102-134`) — never body or `rendering`.
A body-format-only change with the same URL and verdict cannot trip this
gate. `lab/ground-truth/expectedresults.csv` has no rendering-or-body-
sensitive column either. **No ground-truth `url`/`rendering` field edits are
needed for this change** — `rendering: server` was already correct; only
the code needed to catch up.

### R5 — leakage/fingerprint-independence gate: structurally inapplicable here too, for a different reason than CC-LAB-0239's

**Found:** the leakage gate needs ≥40 cells and ≥6 groups
(`leakage_probe.py:688,695`); every PFF manifest touched here is far smaller.
Unlike CC-LAB-0239 (where the gate skipped due to per-manifest cell count),
here it's structurally out of scope for the whole `real_pages_*` family.
**Mitigation, same discipline as CC-LAB-0239's R5:** add a direct automated
twin-diff test (both twins render via the identical shared Blade view,
verified by reading the generated controller source, mirroring
`tests/test_labgen_price_integrity.py`'s and
`tests/test_labgen_access_control_circlefeed.py`'s existing pattern for
exactly this proof) for each of the 4 twin pairs (`register.php` and
`products.php` are secure-only single cells, no twin to diff).

### R6 — SQLite vs MariaDB seed-data/schema differences affect what the new views can safely assume

**Found:** the SQLite live-boot harness's `posts` table
(`conformance/live_boot.py:536-540`) has only `id, title, body` — no
`author`/`published_at`, which the real schema (`lab/sql/schema.sql:48-54`)
and MariaDB harness do have. Seed data also differs (SQLite: `Chew Toy`/
`Puppy Bed`, no apostrophes; MariaDB: 10 real products, `schema.sql:63-73`).
**Mitigation:** the new `blog_post.php` Blade view only references columns
present in *both* harnesses' schemas (`id`, `title`, `body`), or conditionally
renders `author`/`published_at` only `@if(isset($row->author))`, so the same
template works against both harnesses without erroring on a missing
property. **Checked, not assumed limited to `posts` (per review):** every
column the new views reference on `products` (`name`, `description`,
`price`, `category`, `stock`) and `users` (`username`, `email`, `full_name`)
was cross-checked against both harnesses' schema definitions directly —
`products` matches exactly (same columns, same types modulo SQLite `REAL`
vs. MariaDB `DECIMAL`), and `users` has no columns these views read that
differ between harnesses. `posts`' `author`/`published_at` is the *only*
mismatch found. Re-run both the SQLite and MariaDB live-boot test files — a
fix proven only against one harness is not proven.

### R7 — error-based SQLi detection unaffected (verified, not assumed)

**Found:** `stack_env.py:68-83` forces `APP_DEBUG=false`, so a `QueryException`
at the sink statement is caught by Laravel's own exception handler and
rendered as a generic 500 page *before* any tail (JSON or HTML) ever runs.
`SqliErrorStrategy`'s detection already doesn't depend on the tail today and
won't depend on it after this change either — confirmed, not assumed, by
reading `stack_env.py` and `SqliErrorStrategy.confirm`.

### R8 — `SqliTimingStrategy` and Tier1/Tier2 conformance: format-agnostic, verified

**Found:** `SqliTimingStrategy` uses only response `.elapsed` (timing), no
body inspection at all. `TestTier1RealLiveBoot`/Tier2 live tests
(`tests/test_labgen_conformance_tier1.py:204-258`,
`tests/test_labgen_conformance_tier2.py:206-266`) use a bare substring
`evidence_marker` (e.g. `"Puppy Bed"`) checked via `in response_body` —
format-agnostic, provided the new HTML view actually prints each row's
`name`/`title` field (which it must, to satisfy R1's own content
requirement anyway). No change needed to these strategies or tests; re-run
to confirm, not skipped.

## 5. Sequencing

1. Add `_HTML_ROW_VIEW_KEY`/`_HTML_LIST_VIEW_KEY` constants, pop both in
   `render()`, add the mutual-exclusivity fail-loud check (§2's hygiene
   fix) — no behavior change yet. **Gate, made explicit per review** (an
   earlier revision left this as a parenthetical aside rather than an
   enforced checkpoint): step 1 is not complete, and step 2 must not start,
   until `tests/test_labgen_php_laravel_access_control_live_boot.py` and
   `tests/test_labgen_phase_d_tier12_category5.py` — the two tests that
   actually exercise CC-LAB-0239's existing `html_row_view` users
   (`LABGEN-CF-0001`/`0002`, `LABGEN-BC-0005`/`0006`) — are re-run and
   confirmed green, the same explicit-gate discipline step 7's "full suite
   green" already gets.
2. Add the `html_list_view` tail to `single_statement.php.j2`.
3. `/product.php` + `/blog_post.php`: wire `html_list_view`, write one
   shared Blade view template used by both pages' twins (found/not-found
   states per R1's content requirement), update the 4 JSON-counting live-boot
   assertions (SQLite + MariaDB) for `/product.php`, add the R1 byte-length-
   delta test and the R5 twin-diff test for both pairs.
4. `/products.php`: wire `html_list_view` (secure-only, no twin-diff needed).
   Update its live-boot assertions if any are JSON-shaped (research found
   these already agnostic — verify, don't just trust the earlier finding).
5. `/search.php`: wire `html_list_view` on the shared profile; confirm R3
   (the 4 XSS cells stay unaffected); update the 2 JSON-counting MariaDB
   assertions, including fixing the vacuously-true one (R2); add the R1
   byte-length test and R5 twin-diff test for the SQLi pair.
6. `register.php` + `login.php`'s failure tail: bespoke HTML (§3), reusing
   the real historical PFF copy; update the 4 status/body assertions across
   SQLite + MariaDB; confirm the static controller-source assertion still
   holds unchanged.
7. Full non-slow suite + every test named in R1-R8 above, including both
   MariaDB and SQLite live-boot files, run for real and green.

## 6. Explicitly out of scope

- The bare-fragment (`contact.php`/`newsletter.php`/`edit_profile.php`)
  layout-inheritance cosmetic gap (§1) — separate, tracked, not conflated.
- Any change to `puppy-fort-factory/` itself (deleted, `CC-LAB-0061`) —
  only referenced here as historical UX precedent via git history.
- CircleFeed/Huddle Hub/Booking (already done, `CC-LAB-0239`).
