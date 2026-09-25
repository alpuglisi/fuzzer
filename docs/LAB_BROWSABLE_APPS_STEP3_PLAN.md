# Lane 1 step 3 — JSON→HTML conversion, detailed implementation + risk plan

Status: **converged, planning only, not yet implemented** (2026-09-24,
revised 2026-09-25 after a self-review research pass, then revised three
more times 2026-09-25 after 3 separate rounds of 3 independent reviewer
agents each checked accuracy, thoroughness, and adequacy — see §9 and the
dated CHANGELOG entries for what changed each round; round 3's adequacy
reviewer confirmed no further full round is needed once its 2 concrete
fixes landed, which they have). Scopes the third
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
   | `LABGEN-CF-0003`/`0004` | `POST /groups/webhook` | JSON | no — genuine API (see §2) |
   | `LABGEN-CF-0005`/`0006` | `GET /comments/share` | `header("Location: ...")` (real 302) | **no** — already a real redirect |
   | `LABGEN-CF-0007`/`0008` | `GET /settings/preferences` | JSON | no — genuine API (see §2) |
   | `LABGEN-HHB-0001`/`0002` | `POST /webhooks/events` | JSON | no — genuine API (see §2) |
   | `LABGEN-HHB-0003`/`0004` | `GET /messages/unfurl` | JSON | no — genuine API (see §2) |
   | `LABGEN-HHB-0005`/`0006` | `GET /integrations/outgoing-webhook` | JSON | no — genuine API (see §2) |
   | `LABGEN-BC-0001`/`0002` | `GET /booking/continue` | `return redirect($return_to)` (real 302) | **no** — already a real redirect |
   | `LABGEN-BC-0003`/`0004` | `GET /extranet/export` | `text/csv` body | **no** — CSV is the realistic content type for an export feature |
   | `LABGEN-BC-0005`/`0006` | `POST /booking/checkout` | `response()->json($rows)` | **yes** — real page |
   | `LABGEN-MA-0003`/`0004` | `POST /example/account_settings` | JSON | no — genuine API (see §2) |

   **11 cell pairs / 22 instances total** (revised up from an earlier
   9-pair/18-instance count that missed two of them — see below). So the
   **only** cells whose response body genuinely needs to become HTML are
   **`LABGEN-CF-0001`/`0002`** (photo detail view) and
   **`LABGEN-BC-0005`/`0006`** (checkout confirmation). Everything else in
   the table needs, at most, a URL move (off `/cell/labgen-*`) — not a
   rendering change. (§3a below finds that for `GET` cells this URL move
   needs *no separate nav-wiring step at all*; the four `POST`-only `api`
   cells — `LABGEN-CF-0003/0004`, `LABGEN-HHB-0001/0002`,
   `LABGEN-MA-0003/0004` — plus `LABGEN-BC-0005/0006` need an actual new
   page built.)
   `LABGEN-HHB-0003`/`0004` and `LABGEN-HHB-0005`/`0006` were re-verified
   directly against a fresh `assemble_lab(app="huddlehub")` build (not just
   inferred from the manifest) — both still `response()->json(...)`,
   confirming the table above.

   **Correction (reviewer-found, 2026-09-25):** the first drafts of this
   plan missed `LABGEN-CF-0003`/`0004` (`lab/manifests/webhook_signature_circlefeed_sample.yaml`,
   `webhook_signature_bypass`, `POST /groups/webhook`) and
   `LABGEN-HHB-0001`/`0002` (`lab/manifests/webhook_signature_huddlehub_sample.yaml`,
   same class, `POST /webhooks/events`) entirely — re-deriving the full cell
   list from every `*circlefeed*.yaml`/`*huddlehub*.yaml`/`booking_*.yaml`/
   `mass_assignment_laravel_sample.yaml` manifest confirms these are the only
   two omissions; the table above and every section below now includes them.

   **`LABGEN-MA-0003`/`0004` scope note:** this pair lives only in the
   **default merged build** (`assemble_lab()` with no `--app`, i.e. still
   inside the PFF app carrying step 1's login/session routes) — it is
   *not* part of any of the three standalone `--app` split builds
   (`app_site.py`'s `APP_REGISTRY` filters by `LABGEN-CF-`/`LABGEN-HHB-`/
   `LABGEN-BC-` prefixes only, and `LABGEN-MA-` matches none of them). Its
   new client page (§4 step 4) is added to the default merged build, not to
   any split app. Because that build has PFF's own login flow, **R8's
   anonymous-crawl-can't-authenticate problem does not apply to this cell**
   and it is not part of the R8 sign-off's scope.

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
  `LABGEN-BC-0001/0002/0003/0004`. **Correction (R9, found in round 2 of
  review):** an earlier revision of this bullet called their remaining work
  "purely the route-path change itself" — that phrasing is now known to be
  inaccurate. No manifest `route.path` is edited at all (see R9): the fix is
  wiring `_PAGE_PROFILES`'s `real_page`/`canonical_cell_id` keys in the
  emitter, which is what makes the *manifest's own, already-correct* path
  become the actually-served one.
- **`POST`-only cells are invisible to `catalog()`** (it filters to `GET`
  only, matching the parent plan's own point 4: a POST endpoint needs a
  *page* — a GET-answerable form or client page — to be link-reachable at
  all). `LABGEN-BC-0005`/`0006` (checkout) and the `api`-classified
  `LABGEN-CF-0003`/`0004` (groups webhook), `LABGEN-HHB-0001`/`0002`
  (webhooks/events), and `LABGEN-MA-0003`/`0004` (account settings) are the
  four cell pairs that genuinely need a new GET-reachable page built for
  this reason, independent of whether their response body also changes
  format.

## 2. `page` vs `api` classification, justified per the parent plan's own test

The parent plan's refinement section gives explicit examples of endpoints
that **stay JSON**: "webhook receivers, JWT APIs, JSON mass-assignment APIs,
deserialization endpoints". Applying that test cell by cell:

- **`LABGEN-CF-0003`/`0004` (webhook_signature_bypass, `/groups/webhook`)**
  and **`LABGEN-HHB-0001`/`0002` (webhook_signature_bypass, `/webhooks/events`)**
  → the parent plan names "webhook receivers" explicitly as staying JSON
  (same wording R1's `LABGEN-HHB-0005`/`0006` classification already relies
  on). Classification: **`api`**, each with a client page (a "receive a
  webhook" explainer + the same minimal inline `fetch()` client-page
  pattern used for the other `api` cells).
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

**Correction (reviewer-found, 2026-09-25):** earlier drafts of this plan
named the wrong test files here — `tests/test_oracle_strategies_price_integrity.py`
and `tests/test_oracle_strategies_price_integrity_live_boot.py` exist, but
they test a **different strategy** (`PriceTrustDifferentialStrategy`)
against **spring_boot** Netflix plan-change cells (`LABGEN-JV-0009`/`0010`)
— completely unrelated to `PriceIntegrityBypassStrategy` or
`LABGEN-BC-0005`/`0006`. Confirmed directly: `PriceIntegrityBypassStrategy`'s
real unit tests are in `tests/test_oracle_vectors.py`
(`test_price_integrity_bypass_confirmed_when_client_amount_echoed_back` and
neighbors), and its real live-boot proof against `LABGEN-BC-0005`/`0006` is
`tests/test_labgen_price_integrity.py::test_live_boot_price_integrity_manifest_ignores_the_client_amount_on_the_secure_twin`
(the exact `"charged_amount":"..."` anchor). Following the original,
mistaken file references would have updated/re-run tests that never
exercise this strategy or these cells at all, producing a false "green"
while the actual regression test stayed JSON-anchored and silently broke.
This was the single most consequential error caught in review — fixed here.

**Mitigation:**
- Update `PriceIntegrityBypassStrategy` in the same change that changes the
  sink template, never as a follow-up. Its new anchor is a
  **`data-charged-amount="…"` attribute** on the confirmation page (chosen
  definitively, not left as an either/or with a plain-text line: an
  attribute is robust against incidental copy/wording changes to the
  surrounding confirmation text in a way a "Charged: $…" sentence is not),
  still exact-matched (not a loose substring) to keep the canary's own
  collision-avoidance property (three decimal places, rate-table exclusion)
  meaningful.
- Re-run `tests/test_oracle_vectors.py` (the strategy's unit tests) and
  `tests/test_labgen_price_integrity.py` (the live-boot proof against the
  real cells) — both must still pass against the *new* shape; if either
  test's own fixture/expectation still assumes the old JSON shape, it is
  updated to the new `data-charged-amount` anchor (the fixtures model what
  the real generated cell does; they follow the cell, not the other way
  round). **Also re-run `tests/test_labgen_phase_d_tier12_category5.py`**
  (found by review, previously unlisted here): it independently proves
  Tier1/Tier2 conformance for both `LABGEN-BC-0003`/`0004` and
  `LABGEN-BC-0005`/`0006` via its own `evaluate_tier1_response`/
  `build_tier1_case` marker mechanism, using the bare `"0.01"` amount as its
  `evidence_marker` rather than a JSON-fragment anchor — it will likely
  still pass against a `data-charged-amount="0.01"` HTML attribute, but this
  must be confirmed by actually running it, not assumed by similarity to
  R1's own anchor design.
- **Decimal/formatting precision**, added per review: confirm the
  `data-charged-amount` attribute's value is rendered with exactly the same
  string the JSON response used (e.g. Blade/PHP number formatting must not
  collapse `"123.450"` to `"123.45"` or otherwise reformat the canary) —
  both `PriceIntegrityBypassStrategy`'s exact-match and
  `test_labgen_phase_d_tier12_category5.py`'s marker match depend on the
  attribute carrying the literal string, not a numerically-equal
  reformatting of it.
- This is the **highest-risk single change** in this step. Do it in its own
  isolated commit and CC-FUZZ entry, verified independently before touching
  anything else. "Same commit" here is a **documented discipline this plan
  requires**, not something mechanically enforced by a hook or CI check —
  the implementer and reviewer are both responsible for verifying the
  sink-template change and the strategy update land together; call this out
  explicitly in the `CC-FUZZ-0047` entry's own text rather than assume it's
  guaranteed by the plan alone.

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

**Strengthened per review:** re-running the *existing* fixtures unchanged
only proves the strategy still handles the generic cases it was already
tested against — it doesn't prove the strategy behaves correctly against
the *actual new* photo-detail markup (a real Blade template has real
surrounding boilerplate: nav, footer, headings — any of which could
coincidentally contain a denial-marker word like "access" and cause a false
fail-closed). As part of this step's own commit for `LABGEN-CF-0001`/`0002`
(§4 step 2), add one new fixture sender to
`test_oracle_strategies_access_control.py` that returns a realistic mock of
the actual new photo-detail page's markup (copied from what the real Blade
template renders, not a generic `<html>` stub) and assert the strategy
still confirms on the vulnerable twin and fails closed on the secure twin.
Small, not over-engineering, given R3's whole "no change needed" conclusion
is load-bearing for this step's lowest-risk-first sequencing. **Sequencing
clause, added per review:** this fixture cannot be written before the real
Blade template exists — write the template first (as §4 step 2 already
does), then copy its actual rendered markup into the fixture, in that order
within the same commit. An earlier phrasing of this risk read as if the
fixture could be authored standalone; it cannot, since it must copy real
output that doesn't exist yet.

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
build failure, not a warning. **Concretely** (per review, this section
originally just said "run the existing gate" without saying how): the
command is `fuzzlab lab-generate --manifest <path> --out <dir> --emitter
php_laravel --check`, run against `access_control_circlefeed_sample.yaml`
and `booking_price_integrity_sample.yaml` respectively. **Before treating a
green run as meaningful**, confirm the gate actually executes rather than
silently short-circuits: `fuzzlab/labgen/leakage_probe.py` defines
`MIN_GROUPS_FOR_GATE = 6`, and each of these manifests has only 2 cells (a
vulnerable/secure twin pair) — if the gate's grouping falls under that floor
for either manifest, `leakage_probe.insufficiency_reason` reports the gate
as *skipped* (informative output, per `cli.py`'s own documented behavior,
never build-failing), not passed. A "green `--check` run" that's actually a
silent skip proves nothing about R5's own concern. State the actual group
count found for each manifest in the `CC-LAB-0239` entry. **Given
`MIN_GROUPS_FOR_GATE = 6` and each of these manifests having exactly 2
cells, the leakage gate is structurally guaranteed to skip for both — this
is the expected outcome, not merely a possibility to check for** —
`cli.py`'s `--manifest` flag takes exactly one manifest with no
multi-manifest/corpus mode, so no alternate invocation changes this. Since
R5's own concern is a *security* property (leakage/fingerprint-independence),
not a style nit, **a hand-diff "done by hand and recorded" is not adequate
on its own** (an earlier revision of this section proposed exactly that,
correctly flagged by review as underpowered for what it's guarding).
Required instead: **a new automated test**, written as part of this step's
own commit for each of the two body-format-converting cells, that renders
both twins, strips the known dynamic/sink region (identifiable directly from
the manifest's own `sink_context`), and asserts byte-equality of the
remainder — the same kind of automated byte-identical-output check this
codebase already uses elsewhere for determinism claims, just not yet
instantiated for a twin-vs-twin layout comparison. This turns "by hand" into
a committed, repeatable regression test rather than a one-time manual note.

### R6 — regression/additive-only gate: correctly ruled out for `lab/ground-truth/`, but WRONG about there being no ground truth at all — per-app ground-truth directories exist and DO carry these cells

**This section's prior conclusion ("no exemption needed, nothing to update")
was itself a factual error, caught by review and corrected here — the
single largest correction in this plan's revision history.**

The narrow claim about `regression_gate.py`/`T-LAB0.9` is still correct: it
diffs `fuzzlab.labels.contract.GroundTruth` snapshots loaded only from
`lab/ground-truth/labels.json` + `injection-points.json`, and neither file
contains any `LABGEN-CF-*`/`LABGEN-HHB-*`/`LABGEN-BC-*`/`LABGEN-MA-*`
`case_id` (confirmed: every `case_id` in that one directory's `labels.json`
is `PFF-`-prefixed). **But this repository has separate, per-app
ground-truth directories that the earlier check never looked at**:
`lab/ground-truth-circlefeed/`, `lab/ground-truth-huddlehub/`, and
`lab/ground-truth-booking-clone/` (each with its own `labels.json`,
`injection-points.json`, `expectedresults.csv`, loaded the same way via
`contract.load()`). Read directly, all three **do** carry hand-authored
cases for essentially every cell in this plan's scope, each with a
hardcoded `url` (still the old `/cell/labgen-*` path) and `rendering` field:

- `lab/ground-truth-circlefeed/labels.json`: `CF-0001`→`LABGEN-CF-0001`
  (`rendering: server-json`), `CF-0002`→`LABGEN-CF-0003`
  (`server-json`), `CF-0003`→`LABGEN-CF-0005` (`server-json`),
  `CF-0004`→`LABGEN-CF-0007` (`server-json`).
- `lab/ground-truth-huddlehub/labels.json`: `HHUB-0001`→`LABGEN-HHB-0001`,
  `HHUB-0002`→`LABGEN-HHB-0003`, `HHUB-0003`→`LABGEN-HHB-0005` (all
  `server-json`).
- `lab/ground-truth-booking-clone/labels.json`: `BKNG-0001`→`LABGEN-BC-0001`
  (`rendering: server`), `BKNG-0002`→`LABGEN-BC-0003` (`server`),
  `BKNG-0003`→`LABGEN-BC-0005` (`server-json`).

These are **live test dependencies, not dead files**:
- `tests/test_labgen_open_redirect.py:118` and
  `tests/test_labgen_csv_export_injection.py:112` both assert
  `case.url == served_url_for(vulnerable)` — a **literal string comparison**
  between the ground-truth `url` and the cell's actual served URL.
  Relocating `LABGEN-BC-0001`/`0003` off `/cell/labgen-*` **will fail these
  assertions** unless `labels.json`'s `url` field for `BKNG-0001`/`BKNG-0002`
  is updated in the same change.
- **Corrected split (review found the original list overclaimed this):**
  only `tests/test_labgen_php_laravel_booking_multitarget.py`,
  `tests/test_labgen_php_laravel_huddlehub_multitarget.py`, and
  `tests/test_multitarget_category3_combined.py` actually load a per-app
  `GT_DIR` and depend on `case.url`/`rendering` (confirmed: each imports
  `fuzzlab.labels.contract` and sets `GT_DIR = "lab/ground-truth-<app>"`).
  `tests/test_labgen_webhook_signature_circlefeed.py`,
  `tests/test_labgen_webhook_signature_circlefeed_magic_hash.py`,
  `tests/test_labgen_webhook_signature_live_boot.py`, and
  `tests/test_labgen_php_laravel_webhook_signature_circlefeed_live_boot.py`
  — an earlier revision of this section wrongly grouped these in as
  ground-truth-dependent too; **none of the four reference ground truth,
  `GT_DIR`, or `contract.load` at all** (confirmed by direct grep: zero
  hits in any of them). They still need to be re-run (their URLs are
  computed dynamically via `served_url_for(cell)`, so a route move doesn't
  break a hardcoded assertion, but the route *is* moving and R9's
  `DuplicateRouteError` risk applies to exactly these cells), just not for
  a ground-truth reason — re-run them because of the route/mechanism change
  (R9), not because they read `case.url`.
- The `rendering` field feeds `fuzzlab/harness/auto.py`'s live
  request-body-encoding decision (JSON body sent iff `rendering ==
  "server-json"`) for a real `fuzzlab auto` run against these apps. For
  `LABGEN-CF-0001` and `LABGEN-BC-0005`/`0006` — the two cells whose
  response body this step actually converts to HTML — this field must flip
  `server-json` → `server` in the same change, or a live `auto` run keeps
  sending JSON request bodies to an endpoint that no longer expects/returns
  JSON.
- **`LABGEN-MA-0003`/`0004` has no ground-truth entry anywhere** — not in
  any per-app directory, nor in the default `lab/ground-truth/` (confirmed:
  zero hits for `MA-0003`/`MA-0004`-shaped case ids in any `labels.json`).
  It is referenced only in `tests/test_labgen_mass_assignment.py` and
  `tests/test_labgen_mass_assignment_live_boot.py`. **Correction (round-3
  reviewer-found):** an earlier revision said both files "compute its URL
  dynamically via `served_url_for(cell)`" — only
  `test_labgen_mass_assignment_live_boot.py` does that;
  `test_labgen_mass_assignment.py` never references a URL at all (its one
  relevant test renders the cell and asserts on the PHP content directly,
  no routing involved). Either way this pair carries no `url`/
  `rendering`-field update risk, unlike the other 10 pairs in this section —
  one file doesn't hardcode a URL, the other doesn't have one to hardcode.
  Its own risk is R9's `_PAGE_PROFILES` wiring, not ground truth.

**Revised conclusion:** `regression_gate.py`/`T-LAB0.9` genuinely has no
baseline to diff for these cells (that narrow point stands, unchanged), but
`migration-exemptions.yaml` was correctly characterized as unrelated for a
different reason than "no ground truth exists" — it's specifically about
the `PFF-NNNN` *cutover* gate, and remains not needed here. What *is* needed,
reversing this section's earlier "removes work" framing: **every relocated
or converted cell's per-app `labels.json` + `injection-points.json` `url`
field (all relocations) and `rendering` field (`LABGEN-CF-0001`,
`LABGEN-BC-0005`/`0006`) must be updated in the same commit as that cell's
move/conversion**, and every test named above must be re-run and pass. This
restores real work to §4/§5 that the prior revision had incorrectly removed.

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

**Strengthened per review — choosing (b) is not a local wording tweak.** The
parent plan's shared design contract (`docs/LAB_BROWSABLE_APPS_PLAN.md`,
point 6) states the acceptance criterion in absolute terms: "**Every nav
link returns 200 HTML.**" Option (b) doesn't just reword *this step's own*
checklist (as an earlier draft implied) — it requires editing that
**parent-plan sentence itself**, since it's the shared contract every lane
(2 through 6) inherits. If sign-off picks (b) without that parent-plan edit,
Lanes 2–6 inherit an unresolved ambiguity: when one of their own apps has a
session-gated cell, its implementer won't know whether the parent doc's
"200 HTML" requirement was ever meant to admit an exception, because
nothing outside this one step-3 doc will say so. **Whichever option sign-off
picks, edit `docs/LAB_BROWSABLE_APPS_PLAN.md`'s point 6 in the same change**
— to state the (b) exception explicitly if (b) is chosen, or to leave it
unchanged (and build the login system) if (a) is chosen. Recall also that
per the inventory-table correction above, `LABGEN-MA-0003`/`0004` is *not*
in scope for this sign-off (its page lives in the default merged PFF build,
which already has a login flow).

### R9 — the actual URL-relocation mechanism is never invoked: every relocation in this plan will hit `DuplicateRouteError` as written

**The single most consequential gap found across both review rounds,
previously entirely missing from this plan.** Every one of the 11 cell
pairs in scope is, today, built and live-booted with **both twins present
in the same generated app at once** (confirmed: e.g.
`tests/test_labgen_php_laravel_access_control_live_boot.py` builds a
`LiveBootHarness(emitter, [login_cell, vulnerable, secure])`). This works
today only because neither twin's manifest `route.path` (e.g. `/photos/view`)
is actually honored as the served URL — `_served_route_for()`
(`fuzzlab/labgen/emitters/php_laravel/__init__.py`) treats every one of
these page profiles as **illustrative** (no `real_page` key set), so each
twin is served at its own distinct `/cell/<slug>` URL, avoiding collision.
This plan's own table header ("route (manifest, undelivered)") already
names this, but never connects it to what changes when the route becomes
*delivered*.

**Read directly:** `fuzzlab/labgen/emitters/php_laravel/route_accumulator.py`'s
`RouteAccumulator.render_file` raises `DuplicateRouteError` if two
fragments register the same URL. **Correction (round-3 reviewer-found):** an
earlier revision of this section said the collision key was `(method, url)`
— it is not. `_ROUTE_URL_RE` (`route_accumulator.py:76`) captures only the
URL; `by_url` (`route_accumulator.py:176-179`) is keyed purely by URL
string, with the method never compared. Two fragments at the same URL but
different HTTP methods would still collide under today's code. The
mechanism that avoids this for a page real enough to have one canonical URL
— already built, already used for every one of PFF's own real pages, and
exactly what the *parent* plan's point 5 means by "the existing URL-pinning
mechanisms (`_REAL_PAGE_CELL_IDS` and similar)" — is `_PAGE_PROFILES`' two
extra keys, `_REAL_PAGE_KEY` (`"real_page": True`) and `_CANONICAL_CELL_KEY`
(`"canonical_cell_id": "<one cell_id>"`). Setting both on a page profile
routes the **canonical** cell to the literal realistic path, and every
**other** cell sharing that profile to a distinct suffixed variant via
`_twin_url_for()` (e.g. PFF's own `/login.php`/`LABGEN-PLA-0002` →
`/login.labgen-pla-0002.php`, keeping the `.php` suffix; for these apps'
extension-less paths, `_twin_url_for`'s no-dot fallback applies, e.g.
`/photos/view` + `LABGEN-CF-0002` → `/photos/view.labgen-cf-0002`).

**Confirmed (round-3): no manifest edit is needed.** `_PAGE_PROFILES` is
keyed by the exact string in the manifest's `route.path` (`_served_route_for`/
`_profile_for` both do `_PAGE_PROFILES.get(cell.route.path, ...)`), and
every one of these 11 pairs' manifest paths (`/photos/view`,
`/booking/checkout`, `/groups/webhook`, `/webhooks/events`,
`/messages/unfurl`, `/integrations/outgoing-webhook`, `/comments/share`,
`/settings/preferences`, `/booking/continue`, `/extranet/export`,
`/example/account_settings`) already exists as a `_PAGE_PROFILES` dict key
today, each currently marked (in a comment) as illustrative. **The fix is
adding two fields to an existing emitter-code dict entry, not editing any
manifest or "changing a route path"** — an earlier revision of §3a/§4 step 3
described this as a "route-path edit," which is now known to be inaccurate
and is corrected there too.

**Second consumer, found in round 3 (thoroughness), low severity:**
`ground_truth_cases_for()` (same file, ~line 1142) also reads
`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` off a `_PAGE_PROFILES` entry, feeding
`fuzzlab/labgen/cutover_gate.py`'s PFF-only cutover-coverage computation
(exercised for real by `tests/test_labgen_cutover_gate.py`). As long as
none of these 11 new entries also sets `_GROUND_TRUTH_CASE_KEY`/
`_GROUND_TRUTH_CASE_BY_FAMILY_KEY`/`_SECONDARY_GROUND_TRUTH_CASES_KEY` (they
should not — none of these cells has a `PFF-*` ground-truth case, and
setting one of those keys would need a real `PFF-*` id to pass
`cutover_gate`'s own validation), this consumer stays a no-op for all 11
profiles. Add `tests/test_labgen_cutover_gate.py` to the re-run list below
as a cheap, direct guard that it does.

**What this plan must add, for every one of the 11 relocations in §4 steps
2–5, not only the 2 body-format conversions — and §4's own step text for
steps 2, 3, and 5 must say so explicitly, not defer this to §5's checklist
alone (round-3 adequacy finding: steps 2, 3, and 5 originally omitted any
mention of this, unlike step 4):**
1. Add `"real_page": True` and `"canonical_cell_id": "<chosen cell_id>"` to
   that cell pair's existing `_PAGE_PROFILES` entry in
   `fuzzlab/labgen/emitters/php_laravel/__init__.py` (no manifest change).
2. Decide which twin is canonical (the vulnerable one, by this codebase's
   own established convention — confirmed by reading the existing
   `LABGEN-PLA-0001`/`LABGEN-RPL-PRODUCT`-style entries, which all name the
   vulnerable cell canonical, and cross-checking each against its own
   manifest's `transform: []` twin).
3. Confirm the **non-canonical** twin's new `_twin_url_for`-derived URL is
   what every test that currently hardcodes or derives its URL now expects
   — this is exactly the same class of fix R6 and R2 already require for
   the *canonical* cell's URL, extended to the twin's suffixed variant too.
4. Re-run `tests/test_labgen_php_laravel_access_control_live_boot.py` (a
   genuine multi-twin-in-one-`LiveBootHarness` case, confirmed) and
   `tests/test_labgen_phase_d_tier12_category5.py` (also confirmed genuine —
   builds `LiveBootHarness(emitter, list(manifest.cells))` with both twins),
   plus `tests/test_labgen_cutover_gate.py` (above). **Correction
   (round-3 reviewer-found): the class-specific unit/live-boot files listed
   in an earlier revision here** (`test_labgen_access_control_circlefeed.py`,
   `test_labgen_header_injection_circlefeed.py`,
   `test_labgen_insecure_deserialization_circlefeed.py`,
   `test_labgen_ssrf.py`/`test_labgen_ssrf_live_boot.py`,
   `test_labgen_header_injection.py`/`test_labgen_header_injection_live_boot.py`,
   and the four webhook-signature files) **do not actually exercise the
   `DuplicateRouteError` collision path** — verified per-file: the
   `*_live_boot.py` variants each build one cell per `LiveBootHarness`
   (their own docstrings say so: "the twins share a route"), the magic-hash
   test never boots anything, and the plain unit-test file
   (`test_labgen_webhook_signature_circlefeed.py`) does render both twins in
   one process but via `tier3.render_whole_sample`, which merges by file
   path and never calls `RouteAccumulator`/`assemble_routes_file` at all.
   Still re-run every one of them (their served URLs change, and
   `served_url_for(cell)` is computed dynamically so they won't hard-fail,
   but confirm no other assumption broke) — just not *because* of
   `DuplicateRouteError` exposure, which only genuinely applies to the two
   tests named at the start of this step.

Without the `_PAGE_PROFILES` wiring, an implementer who does exactly what an
earlier revision of §3a/§4 literally described (treating this as a
"route-path edit," or naively re-registering both twins at the same new
literal path) hits a build-breaking `DuplicateRouteError` the first time
both twins of `LABGEN-CF-0001`/`0002` or `LABGEN-BC-0005`/`0006`
specifically are assembled together via `test_labgen_php_laravel_access_control_live_boot.py`/
`test_labgen_phase_d_tier12_category5.py` (the two tests confirmed to
actually exercise the collision path) — real, but narrower than an earlier
draft of this section claimed for "any of these 11 pairs." The
`_PAGE_PROFILES` wiring itself is still required for all 11 pairs (it's the
only mechanism that serves the *canonical* cell at its real, realistic
path at all — the collision risk is just one reason among several, not the
only one), and must be resolved (§4 revised below) before implementation
starts.

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
   update, the R3 new-fixture addition, the R8 sign-off from step 0,
   **the R9 `_PAGE_PROFILES` wiring** (`real_page`/`canonical_cell_id` on
   the `/photos/view` entry, canonical = `LABGEN-CF-0001`, confirm
   `LABGEN-CF-0002`'s `_twin_url_for` URL against
   `test_labgen_php_laravel_access_control_live_boot.py`'s own assumptions
   — this is the one test R9 confirms genuinely builds both twins together),
   **and (per R6, corrected) updating `lab/ground-truth-circlefeed/labels.json` +
   `injection-points.json`'s `CF-0001` entry: `rendering: server-json` →
   `server`, in this same commit.** Ship and verify this alone before
   touching price integrity.
3. **URL-only moves for the seven already-realistic/already-JSON-as-designed
   `GET` cells** (`LABGEN-CF-0005/0006`, `LABGEN-BC-0001/0002`, and the
   `api`-only relocations `LABGEN-CF-0007/0008`, `LABGEN-HHB-0003/0004`,
   `LABGEN-HHB-0005/0006`, `LABGEN-BC-0003/0004`): no body-format risk. Per
   §3a, every one of these is a `GET` route, so `/catalog` picks each new
   path up automatically once **the R9 `_PAGE_PROFILES` wiring**
   (`real_page`/`canonical_cell_id`, canonical = the vulnerable twin of
   each pair) is added for all six profiles — no manifest edit, per R9's
   correction — plus (per R6, corrected) each one's `url` field in its
   per-app `labels.json` +
   `injection-points.json` entry (`CF-0003`→`CF-0005` route,
   `CF-0004`→`CF-0007` route, `HHUB-0002`, `HHUB-0003`, `BKNG-0001`,
   `BKNG-0002` — see R6 for the case_id↔cell_id mapping), all in the same
   commit as the route move. `tests/test_labgen_open_redirect.py` and
   `tests/test_labgen_csv_export_injection.py` (`BC-0001`/`BC-0003`'s
   `case.url == served_url_for(...)` assertions) must still pass.
4. **The four `POST`-only `api` cell pairs needing a new GET-reachable client
   page**: `LABGEN-CF-0003`/`0004` (groups webhook), `LABGEN-HHB-0001`/`0002`
   (webhooks/events), and `LABGEN-MA-0003`/`0004` (account settings — built
   into the default merged PFF build, not a split app; see §1's scope
   note). Each needs a settings/webhook-explainer page whose inline
   `fetch()` POSTs JSON, per the parent plan's client-page pattern, plus
   `_PAGE_PROFILES` wiring (R9, canonical = the vulnerable twin) for
   `LABGEN-CF-0003/0004` and `LABGEN-HHB-0001/0002` (`LABGEN-MA-0003/0004`
   has no per-app ground-truth entry at all — R6 — so only the R9
   `_PAGE_PROFILES` wiring applies to it, not a `url` field update), plus
   re-running: for the ground-truth-dependent tests,
   `test_labgen_php_laravel_huddlehub_multitarget.py`,
   `test_labgen_php_laravel_booking_multitarget.py`, and
   `test_multitarget_category3_combined.py` (R6); for the URL change itself
   (not a `DuplicateRouteError` risk for these specific files — R9's
   round-3 correction confirmed none of the four actually exercise the
   collision path, since each either boots one twin at a time or bypasses
   `RouteAccumulator` entirely via `tier3.render_whole_sample`),
   `test_labgen_webhook_signature_circlefeed.py`, `..._magic_hash.py`,
   `..._live_boot.py`, and
   `test_labgen_php_laravel_webhook_signature_circlefeed_live_boot.py` —
   batch together only if all four pages are ready in the same commit;
   otherwise split by app.
5. **`LABGEN-BC-0005`/`0006`** (price_integrity → HTML page) **last**,
   in its own commit, because it's R1 — the one genuine oracle-anchor
   change, and (per §3a) also needs a new GET-reachable page (the checkout
   form) since it's `POST`-only. **Also needs the R9 `_PAGE_PROFILES`
   wiring** (`/booking/checkout`, canonical = `LABGEN-BC-0005`) and,
   per R9, re-running `tests/test_labgen_phase_d_tier12_category5.py` (the
   other test confirmed to genuinely build both twins together) and
   `tests/test_labgen_cutover_gate.py` (confirming the new
   `real_page`/`canonical_cell_id` entry doesn't perturb the unrelated PFF
   cutover-coverage computation). Update `PriceIntegrityBypassStrategy`
   (`tests/test_oracle_vectors.py`) and the live-boot proof
   (`tests/test_labgen_price_integrity.py`) — see R1's correction for the
   right file names — **and** `lab/ground-truth-booking-clone/labels.json`'s
   `BKNG-0003` `rendering: server-json` → `server`, all in the same commit
   as the sink-template change; never split them across commits (a red
   build between them would mean an active, silent detection gap).
6. Only after all five land: re-run the full navigability acceptance test
   (crawl-from-`/` discovers every ground-truth/detection-bearing URL, per
   whichever R8 option was chosen in step 0) and the full non-slow suite +
   this lane's live-boot suite together, once, as the final integration
   check.

## 5. Verification checklist (maps 1:1 to the parent plan's own contract)

- [ ] `php -l` clean on every regenerated controller/route file.
- [ ] `tests/test_oracle_strategies_access_control.py` — the existing suite
      unchanged AND green, plus the new realistic-photo-page fixture added
      per R3, also green.
- [ ] `tests/test_labgen_php_laravel_access_control_live_boot.py` — updated
      assertions, green (R2).
- [ ] `tests/test_oracle_vectors.py` (`PriceIntegrityBypassStrategy`'s own
      unit tests) + `tests/test_labgen_price_integrity.py` (its live-boot
      proof) — updated, green. **Not**
      `test_oracle_strategies_price_integrity.py`/`..._live_boot.py` — those
      test a different strategy entirely (R1's correction).
- [ ] New/updated `tests/test_labgen_assemble_app_split.py`-style disk-content
      tests for each relocated URL (old `/cell/labgen-*` path gone, new
      realistic path serves the same cell).
- [ ] The gate command is run and its group count recorded (expected: skip,
      since both manifests have 2 cells < `MIN_GROUPS_FOR_GATE`), **and** the
      new automated twin-diff byte-equality test (R5) is written and green
      for both `LABGEN-CF-0001`/`0002` and `LABGEN-BC-0005`/`0006` — a skip
      recorded without this new test does not satisfy R5.
- [ ] **`_PAGE_PROFILES` wired with `real_page`/`canonical_cell_id` for all
      11 relocated cell pairs** (R9), canonical twin chosen per this
      codebase's existing convention (vulnerable cell canonical), and every
      live-boot/class-specific test that builds both twins together
      re-run and confirmed free of `DuplicateRouteError` and stale-URL
      assertions (R9's own list, plus R2/R6's lists).
- [ ] Regression/additive-only gate (`T-LAB0.9`/`regression_gate.py`) —
      confirmed still green; no `lab/ground-truth/` (default dir) exemption
      entry needed (that narrow point of R6 stands).
- [ ] **Per-app ground truth updated** (R6, corrected): every relocated
      cell's `url` field, and `LABGEN-CF-0001`/`LABGEN-BC-0005`/`0006`'s
      `rendering` field (`server-json` → `server`), updated in
      `lab/ground-truth-circlefeed/`, `-huddlehub/`, `-booking-clone/`'s
      `labels.json` + `injection-points.json`, each in the same commit as
      its cell's move/conversion.
- [ ] Ground-truth-dependent (R6): `tests/test_labgen_open_redirect.py`,
      `tests/test_labgen_csv_export_injection.py`,
      `tests/test_labgen_php_laravel_booking_multitarget.py`,
      `tests/test_labgen_php_laravel_huddlehub_multitarget.py`,
      `tests/test_multitarget_category3_combined.py` — all green after the
      per-app `url`/`rendering` updates.
- [ ] Route/mechanism-dependent, not ground-truth (R9, corrected split from
      an earlier draft that miscategorized these as R6/ground-truth):
      `tests/test_labgen_webhook_signature_circlefeed.py`,
      `tests/test_labgen_webhook_signature_circlefeed_magic_hash.py`,
      `tests/test_labgen_webhook_signature_live_boot.py`,
      `tests/test_labgen_php_laravel_webhook_signature_circlefeed_live_boot.py`,
      `tests/test_labgen_access_control_circlefeed.py`,
      `tests/test_labgen_header_injection_circlefeed.py`,
      `tests/test_labgen_insecure_deserialization_circlefeed.py`,
      `tests/test_labgen_ssrf.py`, `tests/test_labgen_ssrf_live_boot.py`,
      `tests/test_labgen_header_injection.py`,
      `tests/test_labgen_header_injection_live_boot.py`,
      `tests/test_labgen_phase_d_tier12_category5.py` (also named under R1)
      — all green after `_PAGE_PROFILES` wiring, with no `DuplicateRouteError`.
- [ ] `LABGEN-MA-0003`/`0004`'s own tests
      (`tests/test_labgen_mass_assignment.py`,
      `tests/test_labgen_mass_assignment_live_boot.py`) — green; no
      ground-truth `url` update applies to this pair (R6).
- [ ] `bootstrap/app.php`'s `validateCsrfTokens(except: ['*'])` line diffed
      against pre-change and confirmed unchanged (R7).
- [ ] R8 sign-off obtained, **and `docs/LAB_BROWSABLE_APPS_PLAN.md` point 6
      edited to match** (state the anonymous-401 exception if (b), or leave
      unchanged if (a) — see R8), recorded in the `CC-LAB-0239` entry
      *before* `LABGEN-CF-0001`/`0002` is converted.
- [ ] `LABGEN-CF-0003`/`0004` and `LABGEN-HHB-0001`/`0002` (the two
      previously-missing webhook cell pairs) included in every step above,
      not just the newly-discovered cells added last.
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
- A `BUG-NNNN` entry is **not** warranted for R1/R2/R6 themselves — these
  were caught and corrected during this plan's own review cycle, before any
  implementation started, which is exactly what the review cycle is for.
  If implementation turns up a *further*, currently-undiscovered oracle/test
  anchored to one of these cells' old response shape, that discovery **does**
  get a `BUG-NNNN` (a latent defect in this plan's own inventory) plus the
  recurrence-review/PA workflow in `CLAUDE.md`, since it would mean this
  inventory pass missed something a full implementation pass caught.
- **Correction (reviewer-found, process-compliance gap):** an earlier
  revision of this section said the formal `CC-LAB-0239`/`CC-FUZZ-0047`
  entries could be "drafted once implementation actually starts." Read
  `docs/components/README.md`'s pre-change review gate directly: for a
  *substantive code/architecture change* (which this unambiguously is), the
  **fielded change-control entry itself** — not a discussion feeding it —
  must be drafted first, reviewed by 2 independent agents plus the
  proposing agent, and **agreed 3/3 before implementation begins**. This
  plan document's own 2 rounds of review satisfy that gate's *spirit* (real,
  independently-verified accuracy/thoroughness/adequacy checking) but not
  its *letter*, which requires the actual entry. **Corrected requirement:
  draft the real `CC-LAB-0239` and `CC-FUZZ-0047` entries (Change, Impact,
  Risk, Deliverables fields; Effectiveness left `pending`) from this plan's
  now-converged content, and take *them* through the same 2-reviewer-agent
  +3/3-agreement process this plan itself went through — as their own,
  separate, explicit gate — before §4 step 0 begins.** This plan document
  is the input those entries are grounded in; it does not substitute for
  them. **Made concrete per round-3 review:** the entries should be
  populated by condensing this document's §1–§9 directly (their Change/
  Impact/Risk fields are already, in substance, written here — this is
  compression into the change-control template, not a from-scratch
  redraft), drafted by whichever agent begins implementation, as the first
  action of §4 step 0, before anything else in that step.
- A one-line addition to `docs/LAB_BROWSABLE_APPS_PLAN.md`'s Lane 4 row
  (R4) is itself a small piece of bookkeeping this step owes going forward
  — do it in the same PR as this plan's implementation, not deferred
  further, since Lane 4 could plausibly start before this step's own
  retrospective would otherwise surface it.

## 8. Explicitly out of scope for this step

- Any `spring_boot`/`go_net_http`/`ruby_rails` template changes (R4) — noted
  for Lanes 3/4/5, not touched here.
- PFF's own pages — already done (§1).
- Compose services/ports/`labctl` profile wiring — that's Lane 7.

## 9. Review history (per-round convergence record)

This plan went through 3 rounds before being considered ready to implement
from, per `CLAUDE.md`'s multi-agent review convention (mirrors the
`L-P3.3c` "3x review→research→revise loop"):

1. **Initial draft** (2026-09-24): first inventory + risk register, written
   after real investigation (live builds, code reads) but a single author's
   pass.
2. **Self-review revision** (2026-09-25): the same author re-checked 3 of
   the draft's own claims by reading the cited code directly rather than
   trusting the earlier pass, correcting the `catalog()` auto-discovery
   finding (§3a), the original (mistaken) `T-LAB0.9` exemption guess, and
   the CSRF framing (R7), and added R8 (no login route) as a newly-found
   gap.
3. **3-independent-reviewer-agent revision** (2026-09-25): 3 agents,
   briefed separately with no shared context, reviewed for accuracy,
   thoroughness, and adequacy respectively, each doing its own independent
   code verification rather than trusting this document. All 3 confirmed
   the document's overall research discipline was sound, but found real,
   verified issues: the accuracy reviewer found the `LABGEN-MA-0003`/`0004`
   scope ambiguity (§1); the thoroughness reviewer found the two missing
   webhook cell pairs and — the most consequential single finding —
   reversed R6's conclusion by finding the per-app ground-truth directories
   the earlier rounds never checked; the adequacy reviewer found R1's wrong
   test-file references (the plan's highest-priority risk, pointing at the
   wrong strategy/stack/cells entirely) plus concreteness gaps in R5/R8/§7.
   Every one of these was independently re-verified against the actual repo
   (not just taken on the reviewing agent's word) before being folded into
   this document — see the "Correction (reviewer-found, 2026-09-25)" and
   "Strengthened per review" callouts throughout §1–§7 for exactly what
   changed and why.
4. **Second 3-independent-reviewer-agent round** (2026-09-25): with round 3's
   corrections in place, 3 fresh agents (no memory of round 3, briefed only
   on the document's then-current state) re-checked accuracy, thoroughness,
   and adequacy again. Most of round 3's fixes held up under independent
   re-verification, but this round found real, further issues: the accuracy
   reviewer found R6's own corrected dependent-test list had overclaimed —
   4 webhook-signature test files it listed as ground-truth-dependent
   reference no ground truth at all; the thoroughness reviewer found **R9**,
   the single most consequential finding across both rounds — every one of
   the 11 relocations in this plan will hit a build-breaking
   `DuplicateRouteError` unless `_PAGE_PROFILES`' `real_page`/
   `canonical_cell_id` mechanism is actually wired for each one (the plan
   had discussed *whether* a URL should move, never *how* the codebase's
   own existing routing mechanism makes that move safe), plus a missing
   `LABGEN-MA-0003`/`0004` ground-truth-absence note and an unlisted
   conformance test (`test_labgen_phase_d_tier12_category5.py`); the
   adequacy reviewer found a genuine process-compliance gap — this
   document's own §7 had deferred drafting the actual `CC-LAB-0239`/
   `CC-FUZZ-0047` change-control entries past what
   `docs/components/README.md`'s pre-change review gate actually requires
   (the fielded entry itself, 3/3-agreed, before implementation starts, not
   merely a plan discussion feeding it) — plus smaller strengthenings to
   R1 (decimal-formatting precision), R3 (explicit template-before-fixture
   sequencing), and R5 (replacing a "hand-diff" fallback with a required
   automated twin-diff test, since R5 guards a security property). Every
   finding was independently re-verified against the repo again before
   being folded in.
5. **Third 3-independent-reviewer-agent round** (2026-09-25), targeted
   specifically at whether R9 (round 2's biggest finding) was itself now
   adequate, accurate, and complete: the accuracy reviewer found R9's own
   description of `DuplicateRouteError`'s dedup key was wrong (URL alone,
   not `(method, url)` — `route_accumulator.py`'s regex never captures the
   method) and that the claim "all four webhook-signature test files build
   both twins together" was overstated (verified per-file: only
   `test_labgen_php_laravel_access_control_live_boot.py` and
   `test_labgen_phase_d_tier12_category5.py` actually exercise the
   collision path; the others boot one twin at a time or bypass
   `RouteAccumulator` entirely), plus a smaller inaccuracy in R6's
   `LABGEN-MA-0003`/`0004` note; the thoroughness reviewer, having
   exhaustively checked five other angles on the relocation mechanism with
   no further gap found, surfaced one precautionary addition — a second,
   currently-inert consumer of the same `_PAGE_PROFILES` keys
   (`ground_truth_cases_for()`/`cutover_gate.py`); the adequacy reviewer
   confirmed R9's core mitigation recipe was correct but found it was only
   explicitly wired into §4 step 4's own text, not steps 2/3/5 (which relied
   on §5's checklist alone), and caught a residual, unlooped-back
   inconsistency where §3a/§4 step 3 still described the fix as a
   "route-path edit" after R9 had already established no manifest edit is
   needed — explicitly calling this "exactly the kind of leftover
   contradiction incremental patching can accumulate," and explicitly
   recommending against a further full review round once these narrow,
   concrete fixes landed. All three findings were independently
   re-verified against the actual code (the `route_accumulator.py` regex,
   the four webhook test files' own harness calls, `test_labgen_mass_assignment.py`'s
   lack of any URL reference) before being folded in.

This document is considered converged (4/4 — the author plus all 3
reviewers, for whichever round is current) once a review pass finds no
further corrections needed beyond concurring with what's written here.
Three rounds of 3 reviewers each have now run; each round's findings have
been progressively narrower than the last (round 1: 2 pairs missing from
the inventory and a wrong-strategy test-file reference; round 2: an entire
missing mechanism, R9; round 3: precision corrections *within* R9 itself,
plus one small precautionary addition) — this narrowing, not a fixed round
count, is what "converged" means here, and round 3's own adequacy reviewer
explicitly recommended no further full round is warranted once its two
concrete fixes (folding R9 into steps 2/3/5's own text; correcting the
stale "route-path edit" language) land, which they now have. If a future
reviewer disagrees with anything in this section or elsewhere, treat that
as reopening the loop, not as this document being final regardless.
