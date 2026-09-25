# Lane 1 step 3 — JSON→HTML conversion, detailed implementation + risk plan

Status: **planning only, not yet implemented** (2026-09-24, revised
2026-09-25 after a self-review research pass — see the dated CHANGELOG
entries for what changed). Scopes the third
and last step of Lane 1 (`docs/LAB_BROWSABLE_APPS_PLAN.md`), reserved as
`CC-LAB-0239`/`FR-LAB-156` (LAB side) plus `CC-FUZZ-0047`/`FR-FUZZ-31` (FUZZ
side, oracle-strategy and live-boot-test updates only — no new FUZZ feature).

This step touches ground truth and detection oracles, so before writing any
code it inventories every affected cell for real, decides its `page`/`api`
classification against the parent plan's own criteria, and — critically —
checks what currently anchors to each cell's response shape, so the risk
register below is built from things actually found in the repo, not
hypothetical concerns.

## 1. Inventory: what actually needs to change

Investigation (assemble each app for real, read the generated controller,
grep for who else depends on its response shape) turned up a **much smaller**
surface than "convert every JSON response to HTML" would suggest. Two things
already found in the repo materially shrink the scope:

1. **PFF's own real pages are already HTML.** `lab/ground-truth/injection-points.json`
   shows every PFF browser-facing point (`product.php`, `search.php`,
   `login.php`, `register.php`, `contact.php`, `newsletter.php`,
   `edit_profile.php`, …) already has `rendering: server`. Only
   `/api/products.php` is `server-json`, and it is already correctly modelled
   as a genuine API (`FR-LAB-…` products/api-products lane, `G2`). **PFF needs
   no work in this step.**
2. **Several CircleFeed/Huddle Hub/Booking cells already return realistic,
   non-JSON responses** — they just live at the wrong URL. Read directly out
   of a real `assemble_lab()` build:

   | cell_id | route (manifest, undelivered) | actual current response | needs a body-format change? |
   |---|---|---|---|
   | `LABGEN-CF-0001`/`0002` | `GET /photos/view` | `response()->json($rows)` | **yes** — real page |
   | `LABGEN-CF-0005`/`0006` | `GET /comments/share` | `header("Location: ...")` (real 302) | **no** — already a real redirect |
   | `LABGEN-CF-0007`/`0008` | `GET /settings/preferences` | JSON | no — genuine API (see §2) |
   | `LABGEN-HHB-0003`/`0004` | `GET /messages/unfurl` | JSON | no — genuine API (see §2) |
   | `LABGEN-HHB-0005`/`0006` | `GET /integrations/outgoing-webhook` | JSON | no — genuine API (see §2) |
   | `LABGEN-BC-0001`/`0002` | `GET /booking/continue` | `return redirect($return_to)` (real 302) | **no** — already a real redirect |
   | `LABGEN-BC-0003`/`0004` | `GET /extranet/export` | `text/csv` body | **no** — CSV is the realistic content type for an export feature |
   | `LABGEN-BC-0005`/`0006` | `POST /booking/checkout` | `response()->json($rows)` | **yes** — real page |
   | `LABGEN-MA-0003`/`0004` | `POST /example/account_settings` | JSON | no — genuine API (see §2) |

   So the **only** cells whose response body genuinely needs to become HTML
   are **`LABGEN-CF-0001`/`0002`** (photo detail view) and
   **`LABGEN-BC-0005`/`0006`** (checkout confirmation). Everything else in
   the table needs, at most, a URL move (off `/cell/labgen-*`) — not a
   rendering change. (§3a below finds that for `GET` cells this URL move
   needs *no separate nav-wiring step at all*; only the two `POST` cells,
   `LABGEN-BC-0005`/`0006` and the `api`-classified `LABGEN-MA-0003`/`0004`,
   need an actual new page built.)
   `LABGEN-HHB-0003`/`0004` and `LABGEN-HHB-0005`/`0006` were re-verified
   directly against a fresh `assemble_lab(app="huddlehub")` build (not just
   inferred from the manifest) — both still `response()->json(...)`,
   confirming the table above.

### 3a. Finding: the catalog page auto-discovers routes — most relocations need no nav code

Read `SiteController::catalog()` (the skeleton controller `app_site.py`'s
split apps also use, unchanged): it does not carry a hand-maintained link
list. It walks `Route::getRoutes()` at request time, keeps every registered
`GET` route (excluding `/`, `/up`, `/catalog` itself), sorts it, and renders
it. This means:

- **Every `GET` cell's URL relocation is automatically picked up by
  `/catalog`** the moment `routes/web.php` registers the new path — no
  `app_site.py` or nav-list change needed for
  `LABGEN-CF-0001/0002/0005/0006/0007/0008`, `LABGEN-HHB-0003/0004`, or
  `LABGEN-BC-0001/0002/0003/0004`. Their "nav link" work in §4/§5 below is
  purely the route-path change itself.
- **`POST`-only cells are invisible to `catalog()`** (it filters to `GET`
  only, matching the parent plan's own point 4: a POST endpoint needs a
  *page* — a GET-answerable form or client page — to be link-reachable at
  all). `LABGEN-BC-0005`/`0006` (checkout) and the `api`-classified
  `LABGEN-MA-0003`/`0004` (account settings) are the only two cells that
  genuinely need a new GET-reachable page built for this reason, independent
  of whether their response body also changes format.

## 2. `page` vs `api` classification, justified per the parent plan's own test

The parent plan's refinement section gives explicit examples of endpoints
that **stay JSON**: "webhook receivers, JWT APIs, JSON mass-assignment APIs,
deserialization endpoints". Applying that test cell by cell:

- **`LABGEN-CF-0007`/`0008` (insecure_deserialization, `/settings/preferences`)**
  → the parent plan names "deserialization endpoints" explicitly as staying
  JSON. Classification: **`api`**.
- **`LABGEN-HHB-0005`/`0006` (outbound_header_injection, `/integrations/outgoing-webhook`)**
  → the parent plan names "webhook receivers" explicitly. Classification:
  **`api`**.
- **`LABGEN-MA-0003`/`0004` (mass_assignment, `/example/account_settings`)**
  → the parent plan names "JSON mass-assignment APIs" explicitly.
  Classification: **`api`**.
- **`LABGEN-HHB-0003`/`0004` (ssrf, `/messages/unfurl`)** → link-unfurl
  ("paste a URL, get a preview card") is a link-preview *feature*, but real
  chat products (Slack/Discord-style) implement it as a JSON metadata
  endpoint that the frontend's own JS renders into a card — matching the
  parent plan's "out of scope: JS-rendered client pages… client pages use a
  minimal inline `fetch()` only where a real frontend would." Classification:
  **`api`**, with a client page containing the paste-a-link form and inline
  `fetch()` render, exactly as the plan's out-of-scope note describes.
- **`LABGEN-BC-0003`/`0004` (csv_formula_injection, `/extranet/export`)** →
  a CSV export is realistically a file download in the product being
  modelled (Booking.com-style extranet), not an HTML page; forcing it into
  HTML would make the lab *less* realistic, which the parent plan explicitly
  warns against. Classification: **`api`**-shaped (stays `text/csv`), with a
  real "Export as CSV" link/page (an `<a href="/extranet/export?...">`)
  instead of a bare fetch.
- **`LABGEN-CF-0001`/`0002` (access_control, `/photos/view`)** → viewing a
  single photo is a core product page, not machine-to-machine traffic.
  Classification: **`page`**.
- **`LABGEN-BC-0005`/`0006` (price_integrity, `/booking/checkout`)** → the
  checkout submission a real customer completes in the browser.
  Classification: **`page`**.
- **`LABGEN-CF-0005`/`0006`, `LABGEN-BC-0001`/`0002`** (both already return
  real redirects) → **`page`** by nature (redirects are core browser
  navigation), no body-format work needed.

## 3. Risk register (found, not hypothetical)

Each risk below was confirmed by reading the actual test/oracle code, not
inferred.

### R1 — `PriceIntegrityBypassStrategy` is anchored to the literal JSON shape

**Found:** `fuzzlab/oracle/strategies.py`'s `PriceIntegrityBypassStrategy.confirm`
does `if f'"charged_amount":"{canary}"' in text:` — an exact JSON-fragment
substring match, not a body-format-agnostic diff. Converting
`LABGEN-BC-0005`/`0006`'s response from `response()->json($rows)` to an HTML
confirmation page **will silently break this strategy** (false negative: a
real vulnerability the strategy used to catch would stop being detected) if
the HTML page doesn't carry an equivalent, deliberately-placed anchor.

**Mitigation:**
- Update `PriceIntegrityBypassStrategy` in the same change that changes the
  sink template, never as a follow-up. Its new anchor should match on the
  *rendered* checkout confirmation content (e.g. a `data-charged-amount="…"`
  attribute or a plain-text "Charged: $…" line), still exact-matched (not a
  loose substring) to keep the canary's own collision-avoidance property
  (three decimal places, rate-table exclusion) meaningful.
- Re-run `tests/test_oracle_strategies_price_integrity.py` and
  `tests/test_oracle_strategies_price_integrity_live_boot.py` — both must
  still pass against the *new* shape; if a test's own fixture sender still
  emits the old JSON shape, that fixture is updated too (the fixtures model
  what the real generated cell does; they follow the cell, not the other way
  round).
- This is the **highest-risk single change** in this step. Do it in its own
  isolated commit and CC-FUZZ entry, verified independently before touching
  anything else.

### R2 — `LABGEN-CF-0001`/`0002`'s existing live-boot test is JSON-anchored

**Found:** `tests/test_labgen_php_laravel_access_control_live_boot.py` asserts
literal JSON substrings: `'"id":{SEED_PHOTO_A_ID}'`, `'"owner_id":1'`,
`'"owner_id":2'`. This is a **regression test**, not the oracle strategy
itself (`AccessControlIdorStrategy` — see R3, not itself at risk) — but it
will fail the moment the controller stops returning JSON.

**Mitigation:**
- Update this test's assertions to check for the same facts (which photo's
  data is present/absent, per-owner isolation) against the new HTML body —
  e.g. assert the owner's caption text appears/doesn't appear, rather than a
  JSON key. Keep every existing assertion's *intent* (each `assert` line
  currently proves a specific fact about ownership isolation); do not delete
  or weaken any of them, only translate their shape.
- This test is the direct proof that `FR-LAB-155`'s `sink_context` invariant
  (§3 of the parent plan: "a value that was echoed into an HTML body stays
  in an HTML body") actually holds after conversion — so treat a green run
  of the *updated* test as the acceptance bar for this cell, not merely "no
  exception."

### R3 — `AccessControlIdorStrategy` itself is *not* at risk (verified, not assumed)

**Found:** unlike R1, `AccessControlIdorStrategy.confirm`
(`fuzzlab/oracle/strategies.py`, proven via
`tests/test_oracle_strategies_access_control.py`) is a generic body-diff +
denial-marker strategy. Its own test suite includes a fixture
(`_CannedPageSender`) that already returns raw HTML
(`"<html>static landing page</html>"`) and is correctly handled — the
strategy never parses JSON keys. **No change needed to this strategy.**
Called out explicitly so a future implementer doesn't spend time "fixing"
something that isn't broken, and doesn't skip verifying it either — confirm
this by re-running `test_oracle_strategies_access_control.py` unchanged
after the cell's conversion, as a negative control.

### R4 — shared module-template names across stacks

**Found:** `db_row_by_id_lookup`/`no_ownership_check` and several other sink/
transform names used by these cells exist as **separate template files per
stack** (`fuzzlab/labgen/emitters/php_laravel/templates/sinks/db_row_by_id_lookup.php.j2`,
plus independent `spring_boot`/`go_net_http` equivalents — confirmed via
grep, each stack owns its own template file, not a shared one). Editing the
`php_laravel` template cannot mechanically break another stack's generated
code — there is no shared Jinja include across stacks for these.

**Residual risk:** a *design* inconsistency, not a build breakage — after
this change, `php_laravel`'s `db_row_by_id_lookup` renders HTML while
`spring_boot`'s renders JSON (or whatever it currently does) for the
"same" sink family. That's an intentional, staged inconsistency (this is a
`php_laravel`-only lane), not a defect, but it needs to be written down so
Lane 4 (spring_boot) doesn't have to rediscover the question. **Mitigation:**
add a note to `docs/LAB_BROWSABLE_APPS_PLAN.md`'s Lane 4 row (or a shared
"cross-stack sink rendering" doc) that `db_row_by_id_lookup`-family sinks
render as pages in a lane whose parent app has a page for that sink, and to
follow the same `page`/`api` classification test done here, not
copy-render-format-verbatim from php_laravel.

### R5 — leakage / fingerprint-independence gate (chi-square)

**Found:** the parent plan's shared design contract requires the layout be
byte-identical between vulnerable/secure twins so the chi-square /
leakage-probe build gates (`T-LAB0.11`, `L-P1.3`) don't regress. The new
photo-detail and checkout-confirmation templates must reuse the **same**
Blade layout/partial for both twins of each cell (only the sink logic
differs, never the surrounding markup), exactly like every other converted
PFF page already does.

**Mitigation:** run the existing leakage-probe and chi-square build gates
(already wired as required checks per `L-P1.3`) against the two new pages
before merge — they are not optional/manual checks, they are the same
automated gate every other page went through, so treat a gate failure as a
build failure, not a warning.

### R6 — regression/additive-only gate (`T-LAB0.9`) — reassessed, verified inapplicable to these cells

**Originally flagged as a risk needing an exemption; re-checked against the
gate's actual implementation and found not to apply here.** Read
`fuzzlab/labgen/regression_gate.py` directly: it diffs two
`fuzzlab.labels.contract.GroundTruth` snapshots, and `GroundTruth` is loaded
*only* from `lab/ground-truth/labels.json` + `injection-points.json`
(`fuzzlab/labels/contract.py`'s `load()`). Checked those two files directly:
every `case_id` in `labels.json` has the `PFF-` prefix (verified by
extracting and de-duplicating every `case_id` in the file — `PFF` is the
only prefix present), and `injection-points.json`'s `target` is
`php_laravel` covering only PFF's own 24 real-page points. **None of
`LABGEN-CF-*`/`LABGEN-HHB-*`/`LABGEN-BC-*`/`LABGEN-MA-*` appear in either
file** — these cells were never hand-authored ground truth, so this gate has
no baseline entry to diff for them at all. Moving their route does not
touch any `case_id` this gate tracks.

`lab/ground-truth/migration-exemptions.yaml` (read directly) is a different
mechanism than what R6 originally guessed: it records which `PFF-NNNN`
cases the `php_laravel` *cutover* gate (`L-P3.3c-CUT`/`cutover_gate.py`,
comparing against `puppy-fort-factory/`) knows are deliberately unreproduced
— unrelated to relocating an already-`php_laravel`-native cell's route, and
not a mechanism this step needs to touch or add an entry to.

**Revised conclusion: no exemption, override, or migration-exemptions.yaml
entry is needed for any relocation in this step.** This *removes* work from
§4/§5 rather than adding it — kept as its own numbered item (rather than
deleted) so a future implementer sees that this was checked and ruled out,
not overlooked. If a future cell in this family ever gains a real
`labels.json`/`injection-points.json` entry (none currently do), re-run this
check before moving its URL.

### R7 — CSRF: verified as a single blanket app-wide setting, not per-cell

**Found (corrects an earlier, more cautious framing):** read
`bootstrap/app.php` in a real assembled build directly —
`$middleware->validateCsrfTokens(except: ['*'])`, with a comment recording
why: these cells model plain PHP forms with no CSRF framework of their own,
so Laravel's default session-CSRF middleware would add unmodeled protection.
CSRF is disabled **for every route in the app, uniformly** — there is no
per-cell or per-route CSRF posture to preserve, discover, or accidentally
change. **Mitigation, simplified accordingly:** confirm this one file
(`bootstrap/app.php`'s `validateCsrfTokens` line) is untouched by this
step's diff — that single line is the entire request-side CSRF contract,
for `LABGEN-BC-0005`/`0006` and every other cell alike. No per-cell grep is
needed.

### R8 — split apps have no login route: an authenticated page can never be reached by an anonymous crawl

**Found:** `LABGEN-CF-0001`/`0002`'s controller gates its real (non-401)
branch on `$request->session()->get('user_id')`. The standalone
`--app circlefeed` build's `routes/site.php` (`app_site.py`, step 2)
registers only `GET /` and `GET /catalog` — CircleFeed's own manifests carry
no login cell of any kind (login-capable cells are PFF's own
`LABGEN-PLA-*`, a different prefix, absent from the `LABGEN-CF-` filter).
**This means an anonymous crawl of the standalone CircleFeed app, or of
Huddle Hub/Booking similarly, can never establish a session, so
`GET /photos/view` will always hit the `401 unauthenticated` branch when
reached this way** — the ownership-differential content this step converts
to HTML is real and correctly detectable by a live-boot harness that sets
up a session directly (as `test_labgen_php_laravel_access_control_live_boot.py`
already does, independent of the `--app` split), but is not reachable by
*browsing* the standalone app end to end.

This is a genuine gap the parent plan's design contract point 6 ("crawling
from `/` … discovers 100% of that app's ground-truth injection-point URLs")
does not resolve on its own, and it predates this step (it was already true
the moment step 2 shipped the standalone split) — surfaced here because
converting `/photos/view` to a real page is the first place it actually
matters for this step's own acceptance criteria. Two options, not yet
decided — **needs sign-off before §4 step 2 starts**, not a call this plan
makes unilaterally:

- **(a) Give each split app a minimal login route/page**, reusing PFF's
  existing session-cookie mechanism and seeded demo users, so a real
  browser/crawler can authenticate and reach the gated branch. More
  realistic, more work, and it's new scope beyond "split the app" (step 2)
  or "convert this cell's response" (this step) — arguably its own small
  step.
- **(b) Document the 401 as the correct, expected anonymous-crawl result**
  for this and any other session-gated cell in a split app, and adjust the
  navigability acceptance test's wording to "every URL returns the response
  a real anonymous visitor would get" (200 for public pages, 401/redirect
  for gated ones) rather than "every URL returns 200" — matching how a real
  social app actually behaves for a logged-out crawler. No new login system
  needed.

This plan's authors' recommendation is **(b)**: it matches real product
behavior more closely than inventing a login flow these apps' own manifests
never asked for, and it keeps this step's scope to "convert response
format," not "add authentication." Recorded as a recommendation, not a
decision — flag for explicit user sign-off (or reviewer consensus) before
starting §4 step 2, and record whichever is chosen in the `CC-LAB-0239`
change-control entry.

## 4. Sequencing (safest-first, independently verifiable steps)

Do these as **separate commits**, each independently green, in this order:

0. **R8 sign-off**: get explicit agreement on option (a) or (b) before
   starting step 2 below — `LABGEN-CF-0001`/`0002`'s acceptance criteria
   differ depending on the answer (a reachable authenticated page vs. a
   documented 401-for-anonymous-crawl page).
1. **R3 negative control first**: re-run `test_oracle_strategies_access_control.py`
   unchanged, record that it's untouched by this step (paper trail for R3).
2. **`LABGEN-CF-0001`/`0002`** (access_control → HTML page): lowest oracle
   risk (R3 says the *strategy* is safe), needs the R2 live-boot test
   update and the R8 sign-off from step 0. R6 confirmed no
   migration-exemption entry is needed for the route move. Ship and verify
   this alone before touching price integrity.
3. **URL-only moves for the seven already-realistic/already-JSON-as-designed
   cells** (`LABGEN-CF-0005/0006`, `LABGEN-BC-0001/0002`, and the `api`-only
   relocations `LABGEN-CF-0007/0008`, `LABGEN-HHB-0003/0004`,
   `LABGEN-HHB-0005/0006`, `LABGEN-BC-0003/0004`): no body-format risk. Per
   §3a, every one of these is a `GET` route, so `/catalog` picks each new
   path up automatically — this step is the route-path edit alone, no
   separate nav code.
4. **`LABGEN-MA-0003`/`0004`** (mass_assignment `api`, `/example/account_settings`):
   the one remaining `POST`-only `api` cell. Per §3a it needs an actual new
   GET-reachable client page (a settings form whose inline `fetch()` POSTs
   JSON, per the parent plan's "minimal inline `fetch()`" client-page
   pattern) — batch with step 3 only if that page is ready; otherwise its
   own commit.
5. **`LABGEN-BC-0005`/`0006`** (price_integrity → HTML page) **last**,
   in its own commit, because it's R1 — the one genuine oracle-anchor
   change, and (per §3a) also needs a new GET-reachable page (the checkout
   form) since it's `POST`-only. Update `PriceIntegrityBypassStrategy` and
   its two test files in the same commit as the sink-template change; never
   split them across commits (a red build between them would mean an
   active, silent detection gap).
6. Only after all five land: re-run the full navigability acceptance test
   (crawl-from-`/` discovers every ground-truth/detection-bearing URL, per
   whichever R8 option was chosen in step 0) and the full non-slow suite +
   this lane's live-boot suite together, once, as the final integration
   check.

## 5. Verification checklist (maps 1:1 to the parent plan's own contract)

- [ ] `php -l` clean on every regenerated controller/route file.
- [ ] `tests/test_oracle_strategies_access_control.py` — unchanged, green
      (R3 negative control).
- [ ] `tests/test_labgen_php_laravel_access_control_live_boot.py` — updated
      assertions, green (R2).
- [ ] `tests/test_oracle_strategies_price_integrity.py` +
      `..._live_boot.py` — updated, green (R1).
- [ ] New/updated `tests/test_labgen_assemble_app_split.py`-style disk-content
      tests for each relocated URL (old `/cell/labgen-*` path gone, new
      realistic path serves the same cell).
- [ ] Leakage-probe / chi-square build gate — green on both new page
      templates (R5).
- [ ] Regression/additive-only gate — confirmed still green with no new
      exemption entry needed (R6; verified inapplicable, not skipped).
- [ ] `bootstrap/app.php`'s `validateCsrfTokens(except: ['*'])` line diffed
      against pre-change and confirmed unchanged (R7).
- [ ] R8 sign-off obtained and recorded in the `CC-LAB-0239` entry *before*
      `LABGEN-CF-0001`/`0002` is converted; its acceptance criteria below
      match whichever option was chosen.
- [ ] Full non-slow suite green; pass/skip counts stated in the CC entry.
- [ ] Live-boot: `GET /` and every `/catalog`-listed link on the
      CircleFeed/Huddle Hub/Booking apps fetched for real and returns 200
      (or the correct redirect/CSV content-type, or — if R8 option (b) was
      chosen — the correct 401 for a session-gated page fetched
      anonymously).
- [ ] Crawl-from-`/` navigability check discovers every one of these apps'
      ground-truth/detection-bearing URLs, scored per whichever R8 option
      was chosen (100% 200 under option (a); 100% "correct response for an
      anonymous visitor" under option (b)).

## 6. Rollback plan

Each of the five commits in §4 (steps 2–5) is independently revertable (no
commit depends on a later one). If R1's price-integrity commit fails
verification after merge, revert just that commit — `LABGEN-CF-0001`'s page
conversion and the URL-only moves stand on their own and are not affected.
If a build-gate failure (R5) surfaces after merge that CI didn't catch
locally, the same per-commit revert applies; there is no combined/squashed
commit to unwind.

## 7. Bookkeeping for this step

- `CC-LAB-0239`/`FR-LAB-156` (already reserved, `docs/LAB_BROWSABLE_APPS_PLAN.md`) —
  LAB-side: template/route changes for all cells in §1, and the R8 (a)/(b)
  decision once made (§3, R8).
- `CC-FUZZ-0047`/`FR-FUZZ-31` (already reserved for Lane 1's FUZZ-side work) —
  the `PriceIntegrityBypassStrategy` update (R1) and both of its test files.
- A `BUG-NNNN` entry is **not** warranted for R1/R2 themselves — these are
  anticipated, pre-identified coupling points being fixed proactively as
  part of this step, not defects discovered after the fact. If the
  implementation turns up a *third*, currently-undiscovered oracle/test
  anchored to one of these cells' old response shape once work starts, that
  discovery **does** get a `BUG-NNNN` (a latent defect in this plan's own
  inventory) plus the recurrence-review/PA workflow in `CLAUDE.md`, since it
  would mean this inventory pass missed something a full implementation
  pass caught.

## 8. Explicitly out of scope for this step

- Any `spring_boot`/`go_net_http`/`ruby_rails` template changes (R4) — noted
  for Lanes 3/4/5, not touched here.
- PFF's own pages — already done (§1).
- Compose services/ports/`labctl` profile wiring — that's Lane 7.
