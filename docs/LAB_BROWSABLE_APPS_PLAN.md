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
   injection-point URLs. Every nav link returns 200 HTML. `GET /` returns 200.
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
| 1 | php_laravel pilot: PFF conversion + split CircleFeed, Huddle Hub, Booking into separate apps (3 steps, one CC-LAB each: 0237 presentation-only PFF homepage/nav/forms — done; 0238 `--app` split for CircleFeed/Huddle Hub/Booking — done; 0239 reserved for the remaining JSON→HTML conversion step, detailed implementation + risk plan in `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md` — planned, not yet implemented) | 0237–0239 | 155–156 | 0047 / 31 | 0051 / 0053 |
| 2 | django: PicTrail | 0240 | 157–158 | 0048 / 32 | 0052 / 0054 |
| 3 | go_net_http: Twitch clone | 0241 | 159–160 | 0049 / 33 | 0053 / 0055 |
| 4 | spring_boot: TrackerNest, Netflix, Expedia | 0242 | 161–162 | 0050 / 34 | 0054 / 0056 |
| 5 | ruby_rails: ForgeCart | 0243 | 163–164 | 0051 / 35 | 0055 / 0057 |
| 6 | node_express (MeadowMart) + python_fastapi sample | 0244 | 165–166 | 0052 / 36 | 0056 / 0058 |
| 7 | Integration: compose services + ports + `labctl` profile, runbook, cross-app navigability run, ARCHITECTURE/requirements | 0245 | 167–168 | — | 0057 / 0059 |

Lane 1 turned out to need 3 sequential CC-LAB entries instead of the 1
originally reserved (each of its 3 narrowed steps is its own change,
verified and committed separately) -- Lanes 2-7's CC-LAB numbers are bumped
by +2 from the original reservation to keep every number unique. Their
FR-LAB/CC-FUZZ/FR-FUZZ/BUG/PA numbers are unchanged (not yet consumed by
anything). Re-derive this table's "next free" numbers from the component
logs' actual current top before dispatching a lane if more of Lane 1's own
work lands first.

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
