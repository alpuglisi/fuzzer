# Browsable lab apps — plan

Status: **in progress** (2026-09-24). Owner component: LAB (01-target-lab), with
ground-truth relabels touching FUZZ (07) only where a detection strategy keys on
a response shape.

## Why

The generated labs were meant to be renderable and navigable in a browser. They
are not (survey, 2026-09-24):

- No app has a working HTML homepage. ForgeCart has a `/` route, but it
  returns plain text.
- Almost every endpoint returns JSON, plain text, or a bare `<div>` fragment.
  There is no shared layout and no links between pages.
- Many user-facing endpoints are POST-only, and no page contains the form that
  would submit to them. A browser visiting one gets 405.
- Only Puppy Fort Factory (PFF) is reachable at all (`lab/compose.yaml`, :8080).
  Every other stack runs only inside test-time live-boot harnesses, on a
  random port, torn down after the test.
- CircleFeed, Huddle Hub and the Booking clone are not separate apps. Their
  cells are merged into PFF under generic `/cell/labgen-*` URLs.

## Decisions (user, 2026-09-24)

1. **Convert endpoints to real HTML pages**, not just an additive shell.
2. **All app identities** get made browsable.
3. **CircleFeed, Huddle Hub and Booking become separate apps.**

### Refinement: browser pages vs. real APIs

`rendering: server-json` in ground truth carries two meanings. It describes the
response, and it also tells `fuzzlab auto` to send the request body as JSON
(`fuzzlab/harness/auto.py:86-96`). Some endpoints are genuine machine-to-machine
APIs in the real product the lab models: webhook receivers, JWT APIs, JSON
mass-assignment APIs, deserialization endpoints, and MeadowMart's backend-for-frontend
`/api/*`. Rendering those as HTML would make the lab *less* realistic and would
break request encoding. So:

- **Browser-facing endpoints** (product/post detail, search, explore, profile,
  comments, login/register/contact, settings forms, …) are **converted to
  server-rendered HTML** inside the app layout. Their ground-truth `rendering`
  becomes `server`, and detection is re-proven.
- **Genuine API endpoints stay JSON.** Each one gets a real HTML **client page**
  in the app (a form, or a small `fetch()` script, the way the real frontend
  would call it), linked from the nav. Every endpoint is then reachable by
  clicking through the site, while its wire contract stays unchanged.

Every lane must classify each of its endpoints as `page` or `api` in its
change-control entry and justify each `api` classification against the real
product being modelled. When unsure, choose `page`.

## Shared design contract (every stack)

1. **Homepage `/`**: returns 200 HTML with the app's name/branding, a short
   description, and nav links to every page in the app.
2. **One shared layout per app**: header (app name + nav), main, footer, and
   inline CSS (no external assets; the lab stays offline and loopback-only).
   The layout is **byte-identical for a vulnerable twin and its secure twin**,
   so it cannot leak which twin is which (leakage/fingerprint-independence
   gates, `CC-LAB` chi-square gate). Nav order is deterministic (sorted),
   following the generator's accumulator-determinism rule.
3. **Sink context preserved.** Converting to HTML must keep each cell's
   modelled `sink_context`. For example, a value that was echoed into an HTML
   body stays in an HTML body, and an attribute sink stays an attribute. SQL
   results render as an HTML table or detail view, so the boolean/error/timing
   differentials the oracles use still hold. Any cell whose vulnerability
   class or exploitability changes because of the conversion must be called
   out explicitly, never changed silently. The typical case is JSON-body
   reflected XSS, which becomes truly exploitable once rendered in HTML. Such
   a cell's ground truth and labels must be updated to match what is actually
   served.
4. **Forms for every POST endpoint.** A browser page endpoint answers GET with
   a form whose `action` is the endpoint itself, and POST is handled as
   today. An API endpoint gets its client page (see above). CSRF: keep each
   stack's existing per-cell CSRF posture (e.g. `@csrf_exempt` for Django
   non-GET cells, Laravel's documented middleware choice); a form page must
   not accidentally add or remove protection that the ground truth depends on.
5. **Realistic URLs.** App cells leave generic `/cell/…` and `/generated/…`
   paths in favour of paths that fit the app. Use the existing URL-pinning
   mechanisms (`_REAL_PAGE_CELL_IDS` and similar) and update ground truth to
   match. Generic covering-array cells with **no** ground-truth case (PFF's
   `LABGEN-PL-NNNN`) keep their paths, render inside the layout, and are
   linked from a `/catalog` page, so they stay reachable without pretending
   to be product pages.
6. **Navigability acceptance test** (per app, live-boot): crawling from `/`
   with fuzzlab's own spider discovers **100%** of that app's ground-truth
   injection-point URLs, each returning **the response a real anonymous
   visitor would get** — 200 HTML for a public page, or the correct
   401/redirect for a page gated behind a login the crawl doesn't have (see
   the decision below). `GET /` returns 200.

   **Decision (R8 sign-off, `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md`,
   2026-09-25):** the standalone `--app` split apps (CircleFeed, Huddle Hub,
   Booking) register no login route of their own (their manifests carry no
   login cell — that's PFF's own concern), so a session-gated cell like
   `LABGEN-CF-0001` cannot be reached authenticated by an anonymous crawl.
   Rather than build a login system these apps' manifests never asked for,
   this is accepted as correct, realistic behavior — a real anonymous
   visitor to a real social app also gets a login wall on a gated photo
   page — and this acceptance criterion is worded above to match. This
   applies to every session-gated cell in a split app; it does not apply to
   `LABGEN-MA-0003`/`0004` (built into the default merged PFF build, which
   has its own login flow from step 1).
7. **Detection must not regress.** After conversion, every ground-truth point
   that was detected before is still detected (live-boot differential tests +
   the existing oracle strategy tests), and `fp=0` on secure twins. A
   detection strategy that keyed on the old response shape is updated to
   match the new, still-honest shape. It is never weakened to pass.

## Apps and serving

Each app gets its own compose service, bound to loopback only, behind a compose
profile. `./labctl.sh up` keeps starting PFF by default, and `PFF_PROFILE=apps`
additionally brings up every other app.

| App | Stack | Port |
|---|---|---|
| Puppy Fort Factory | php_laravel | 8080 (unchanged) |
| CircleFeed | php_laravel | 8082 |
| Huddle Hub | php_laravel | 8083 |
| Booking clone | php_laravel | 8084 |
| PicTrail | django | 8085 |
| Twitch clone | go_net_http | 8086 |
| TrackerNest | spring_boot | 8087 |
| Netflix clone | spring_boot | 8088 |
| Expedia clone | spring_boot | 8089 |
| ForgeCart | ruby_rails | 8090 |
| MeadowMart | node_express | 8091 |

(8081 stays reserved for the existing h2→h1 downgrade front-end. The FastAPI
generic sample has no app identity and no ground truth. It gets a homepage and
layout, but no port unless it gains an identity later.)

## Lanes and pre-assigned bookkeeping (PA-0031)

Lane 1 runs first. It establishes the pattern that the other stack lanes copy
directly, so they don't design from scratch. Lanes 2 to 6 then run in parallel,
each in an isolated worktree. Lane 7 integrates.

| Lane | Scope | CC-LAB | FR-LAB | CC-FUZZ / FR-FUZZ (if needed) | BUG / PA (if a defect is found) |
|---|---|---|---|---|---|
| 1 | php_laravel pilot: PFF conversion + split CircleFeed, Huddle Hub, Booking into separate apps (5 steps, one CC-LAB each: 0237 presentation-only PFF homepage/nav/forms — done; 0238 `--app` split for CircleFeed/Huddle Hub/Booking — done; 0239 JSON→HTML conversion + realistic URLs for CircleFeed/Huddle Hub/Booking, detailed implementation + risk plan in `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md` — done, except the spider-based navigability acceptance test; 0240 JSON→HTML conversion for PFF's *own* real pages (`/product.php`/`/products.php`/`/search.php`/`/blog_post.php`/`/register.php`), detailed implementation + risk plan in `docs/LAB_PFF_JSON_TO_HTML_PLAN.md` — done (plus `/login.php`'s failure tail); 0241 closing the 3 remaining tracked gaps (spider-based navigability acceptance test; bare-fragment layout on `/contact.php`/`/newsletter.php`/`/edit_profile.php`/`/profile.php`; missing-`?id=` 500 on `/product.php`/`/blog_post.php`), detailed implementation + risk plan in `docs/LAB_LANE1_REMAINING_GAPS_PLAN.md` — done 2026-09-25; the crawl also surfaced 2 missing defaults, fixed in the same step, and 2 different-class gaps flagged as strict-xfail follow-ups: 4 PFF ground-truth URLs no cell serves (`/track.php`/`/add_to_cart.php`/`/cart.php`/`/checkout.php`) and Huddle Hub's `/messages/unfurl` bare-GET 500) | 0237–0241 | 155–159 | 0047 / 31 | 0051 / 0053 |
| 2 | django: PicTrail (1 step, one CC-LAB: 0242 homepage + shared layout + `/catalog`, JSON→HTML conversion of `/post`/`/post/comments`/`/settings`/`/explore`/`/inbox`, `/upload` client page for the `/upload/link-preview` api, twin-suffixed secure-twin URLs (R1 branch (a)), ground-truth `rendering` correction, spider-based navigability test, detailed plan in `docs/LAB_LANE2_DJANGO_PICTRAIL_PLAN.md` — done 2026-09-25; the PA-0053 bare-GET sweep found 5 crashing routes, fixed as BUG-0052/PA-0054; only 1 CC-LAB and 1 FR-LAB number used, so Lanes 3-7 are not bumped; no different-class follow-up flagged) | 0242 | 160 (161 unused) | — (unused) | 0052 / 0054 |
| 3 | go_net_http: Twitch clone | 0243 | 162–163 | 0049 / 33 | 0053 / 0055 |
| 4 | spring_boot: TrackerNest, Netflix, Expedia — Lane 1 step 3's `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md` (R4) found `spring_boot`'s sink/transform templates (e.g. `no_ownership_check`) are separate files from `php_laravel`'s own, so this lane starts from `php_laravel`'s response format with no inherited constraint — apply the same `page`/`api` classification test independently per sink family, don't copy-render-format-verbatim | 0244 | 164–165 | 0050 / 34 | 0054 / 0056 |
| 5 | ruby_rails: ForgeCart | 0245 | 166–167 | 0051 / 35 | 0055 / 0057 |
| 6 | node_express (MeadowMart) + python_fastapi sample. One step and one CC-LAB entry: 0246, done 2026-09-25, detailed plan in `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md`. **MeadowMart:** all of its BFF `/api/*` endpoints stay `api`, reached through `site.js`'s homepage, layout, `fetch()` client pages and `/catalog`; its preferences URLs answer GET with the resource read (R3 sign-off, branch (a)); a spider navigability test and a bare-request sweep of every route. **FastAPI sample:** homepage, layout, form pages and in-process checks, with twins served under `/twin/<cell-id>` (F3 sign-off, branch (a)). **Bug:** BUG-0056/PA-0058 (undeclared absent input in both emitters). **Numbers:** exactly 1 CC-LAB and 2 FR-LAB used, so Lane 7 is not bumped; CC-FUZZ-0052/FR-FUZZ-36 unused. **Adopts Lane 4's S15 cross-emitter test:** its `node_express`/`python_fastapi` xfail markers must be dropped at merge. **Flagged follow-ups** (the orchestrator assigns their CC-LAB numbers): F1 (`/api/profile` `currentUser` undefined) and F2 (async handlers exit the process on a rejected DB call), both pinned by strict xfails; F4 (the generated FastAPI `requirements.txt` lacks `python-multipart`); and the Lane 3/4 `absent_input` value-spelling unification, recommended for Lane 7's 0247 | 0246 | 168–169 | — (unused) | 0056 / 0058 |
| 7 | Integration: compose services + ports + `labctl` profile, runbook, cross-app navigability run, ARCHITECTURE/requirements | 0247 | 170–171 | — | 0057 / 0059 |

Lane 1 turned out to need 5 sequential CC-LAB entries instead of the 1
originally reserved (each of its narrowed steps is its own change, verified
and committed separately) -- Lanes 2-7's CC-LAB/FR-LAB numbers are bumped by
+1 again (on top of the earlier +2 bump when Lane 1 grew from 1 to 3 steps)
to keep every number unique, following the exact same discipline as that
earlier bump. Their CC-FUZZ/FR-FUZZ/BUG/PA numbers are unchanged (not yet
consumed by anything). Re-derive this table's "next free" numbers from the
component logs' actual current top before dispatching a lane if more of
Lane 1's own work lands first.

**Post-implementation FR-LAB correction (2026-09-25):** Lane 1's actually-used
FR-LAB range ended at **158** (`FR-LAB-158` for the now-implemented CC-LAB-0240),
which collided with Lane 2's previously-reserved starting number (also 158).
Lanes 2-7's FR-LAB ranges above are bumped by +1 once more to resolve this
(Lane 2 now 159-160, ... Lane 7 now 169-170); their CC-LAB numbers are
unaffected (no collision existed there — Lane 1's CC-LAB range ends exactly
at 0240 and Lane 2 starts at 0241). No lane past Lane 1 had consumed a
number yet, so this is a pure table correction, not a rename of anything
already used.

**Second post-implementation correction (2026-09-25, Lane 1 step 5 planning):**
Lane 1 needed a 5th step (`CC-LAB-0241`/`FR-LAB-159`, `docs/LAB_LANE1_REMAINING_GAPS_PLAN.md`)
to close 3 remaining tracked gaps, which again collided with Lane 2's
then-current reservation (`CC-LAB-0241`/`FR-LAB-159-160`). Fixed the same
way, and this time applied **before** the new step's own change-control
entry is drafted (not deferred to "once implemented"), specifically to
avoid a Lane 2 dispatch picking up the stale number in the meantime per
`docs/MULTI_AGENT_ORCHESTRATION.md`'s pre-assignment rule (PA-0031): Lanes
2-7's CC-LAB numbers are now bumped by +1 too (Lane 2 now 0242, ... Lane 7
now 0247), and their FR-LAB ranges by +1 again (Lane 2 now 160-161, ...
Lane 7 now 170-171). No lane past Lane 1 has consumed a number yet.

Use these numbers exactly. If one is already taken, stop and flag it; do not
pick a different number.

## Verification (orchestrator, per lane, before merge)

- Read the diff, and re-run the full non-slow suite and the lane's live-boot
  (slow) tests.
- Boot the app and fetch `/` and every nav link myself.
- Run the crawl-from-`/` navigability check and the ground-truth detection run.
- Confirm the bookkeeping IDs above exist exactly.

## Out of scope

- JS-rendered client pages as a *crawler-discoverability* exercise (D-open-1
  stays decided). The API client pages use a minimal inline `fetch()` only
  where a real frontend would.
- IDOR/BOLA/business-logic cells (no oracle; D20).
