# Browsable Labs Lane 3 — go_net_http: Twitch clone

Status: **DRAFT, not yet reviewed (2026-09-25).** Reserved as `CC-LAB-0243` /
`FR-LAB-162-163` (and `CC-FUZZ-0049`/`FR-FUZZ-33`, `BUG-0053`/`PA-0055` if
needed) per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table. **Review gate
not yet run:** the proposing agent for this draft had no subagent-spawning
tool available, so the required 2-reviewer (accuracy + adequacy) rounds
have not happened. Per `docs/MULTI_AGENT_ORCHESTRATION.md` §4 this is
flagged, not substituted. This draft authorizes nothing; implementation
still requires this plan's own 3/3 gate and then the `CC-LAB-0243` entry's
own gate.

## 0. What Lanes 1-2 taught us, applied here from the start

- The navigability test's spec (§4) is written before any page work, and it
  applies **PA-0054** (not just PA-0053): an offline declaration check over
  every route the emitter's manifests produce, plus a live bare-request
  sweep over **every served route** (enumerated from the emitter, not the
  crawl).
- Every route's absent-input behavior is decided in §2d up front, one row
  per route, with no row left as "decide later".
- Scope and risks come from direct code reading of this emitter (§1), not
  from analogy to `php_laravel`/`django`. Several go-specific differences
  turned up (R1, R2, R5, R9 below).

## 1. Scope, confirmed by direct code reading

- **The Twitch clone already exists as a named identity with its own
  ground truth**, 14 manifests / 28 cells (`lab/manifests/*go_sample.yaml`
  plus `price_integrity_twitch_subscription_sample.yaml`, all
  `stack_profile: go_net_http`, `LABGEN-GO-0001..0028`), and
  `lab/ground-truth-twitch-clone/` with 15 cases (`TWCH-0001..0015`) over
  14 distinct points. Every vulnerable twin (odd cell ID) has a case. No
  illustrative cells without ground truth exist in this emitter, so there
  are no `--app`-split step and no PFF-style `/catalog` requirement.
- **No realistic URLs at all (unlike PicTrail).** `render_route_accumulator`
  (`fuzzlab/labgen/emitters/go_net_http/__init__.py:515-561`) registers
  every cell at `/generated/{cell_id.lower()}`
  (`__init__.py:542`), ignoring the manifest's own `route.path`.
  Ground truth uses those generic URLs (`labels.json`,
  `injection-points.json`, `expectedresults.csv`). There is no
  `_REAL_PAGE_CELL_IDS`/`served_url_for` equivalent. Grep count of
  `generated/labgen-go` outside docs: `tests/test_labgen_go_live_boot.py`
  87, `tests/test_labels_contract_category4.py` 16, and 10 other test
  files with 1-3 each, plus `fuzzlab/harness/auto.py:51` (comment) and
  `go_live_boot.py:209` (docstring).
- **No homepage, no layout, no HTML anywhere.** The skeleton `main.go`
  (`stack/skeleton/main.go:23-31`) only calls `registerRoutes(mux)`.
  Responses are JSON (analytics/subscribers, JWT settings, tokens,
  profile, purchase), plain text (webhook `ok`, chat commands), raw
  fetched/served bytes (thumbnail proxy, clip download, clip export,
  emote upload), or a bare 302 (both redirect cells).
- **Route/param table:** `_ROUTE_PARAMS` (`__init__.py:361-409`), keyed by
  route path, only carries `var_name`/`param_name` for query-reading
  sources. Nothing declares absent-input behavior.
- **Live-boot harness:** `fuzzlab/labgen/conformance/go_live_boot.py`,
  `GoLiveBootHarness`, a separate class (no `get()`, only `request()`/
  `post()`, `go_live_boot.py:318-344`). Gated on `go_boot_available()`
  (`:152-159`), which needs `go` on PATH plus a module-proxy round trip.
  **Confirmed available in this environment** (go1.24.7; probe returned
  True, 2026-09-25). No database. Whole-app boot already exists in
  practice: `tests/test_multitarget_category4.py:502` boots all 28 cells
  in one harness.
- **Session/login:** none. `read_channel_id_and_broadcaster_header`
  stands in for identity with an `X-Broadcaster-Id` header
  (`modules.py:254-280`). Two cells (analytics, subscribers) are
  owner-scoped in the real product, so a gated-page status applies to
  them. R8's split-app 401 wording does not literally cover this app,
  so it needs its own explicit sign-off (R6).
- **Existing coverage:** offline `test_labgen_go_net_http.py`,
  `_modules.py`, `_conformance.py` (whose `_MANIFESTS` omits
  `open_redirect_login_go_sample.yaml`, a pre-existing gap noted in R11);
  live `test_labgen_go_live_boot.py` (many slow tests) and the
  detection-regression boot `test_multitarget_category4.py`
  (`tp == 14`, `fp == 0`, `:671-672`), which also needs Maven/Java for
  its Netflix half.

### 1a. Page vs. api classification (per the contract's refinement)

| Route (method) | Cells | Class | Justification / treatment |
|---|---|---|---|
| `/webhooks/eventsub` (POST) | 0001/0002 | api | EventSub webhook receiver, machine-to-machine. GET at same URL serves a fetch() client page. |
| `/api/clips/thumbnail` (GET) | 0003/0004 | api | Image proxy fetched by the frontend, raw bytes. Client page links it. |
| `/channels/analytics` (GET) | 0005/0006 | **page** | Creator-dashboard analytics page. JSON to HTML inside the layout. |
| `/channels/settings` (GET) | 0007/0008 | api | Bearer-token JSON API (Helix-style). Client page with fetch(). |
| `/sessions/refresh` (POST) | 0009/0010 | api | Token refresh; `PredictableTokenSourceStrategy` parses JSON `session_token`. Client page. |
| `/channels/profile` (POST) | 0011/0012 | api | Channel-info JSON update API; `MassAssignmentPrivilegedFieldStrategy` parses the JSON echo. Client page. |
| `/channels/subscribers` (GET) | 0013/0014 | **page** | Dashboard subscribers page, same treatment as analytics. |
| `/clips/download` (GET) | 0015/0016 | api | Server-side download proxy, raw bytes. Client page with a GET form. |
| `/channels/emotes/upload` (POST) | 0017/0018 | **page** | Browser upload form. GET renders the multipart form; POST response unchanged (the served file is the sink context). |
| `/subscriptions/purchase` (POST) | 0019/0020 | api | JSON checkout API; `PriceTrustDifferentialStrategy` parses JSON. Client page. |
| `/clips/export` (GET) | 0021/0022 | api | File download (octet-stream), the Lane 1 `/extranet/export` precedent. Client page with export links. |
| `/channels/commands` (POST) | 0023/0024 | api | Chat-command JSON API; `GoTemplateSstiStrategy` sends a JSON body. Client page. |
| `/channels/redirect` (GET) | 0025/0026 | page (redirect) | Browser redirect endpoint. Stays a 302, per Lane 1's redirect precedent. |
| `/auth/login-redirect` (GET) | 0027/0028 | page (redirect) | Same as above. |

Only 3 routes change body format (analytics, subscribers, and the emote
upload's new GET form). Everything else keeps its wire contract and gains a
linked client page. Ground-truth `rendering` changes only for
`TWCH-0003`/`TWCH-0007` (to `server`). Body points `TWCH-0005/0006/0010/0012`
**must stay `server-json`** because `auto.py:92-96` derives the JSON content
type from it.

## 2. Fix design

### 2a. Realistic URLs (new mechanism for this emitter)

Add `served_url_for(cell)` as the one shared derivation (PA-0003/PA-0021),
mirroring django's (`django/__init__.py:383-398`): a vulnerable twin is
served at its manifest `route.path`; its secure twin at
`_twin_url_for(route.path, cell_id)` = `"{path}.{cell_id.lower()}"`
(e.g. `/webhooks/eventsub.labgen-go-0002`). Vulnerable/secure membership is
declared by two explicit frozensets (as in django), not inferred from odd
or even IDs. The accumulator uses `served_url_for`, and so do the tests.
Ground truth's `url`/`primary_endpoint` fields move to the new paths in the
same change. See R1 for the twin-URL decision rule.

### 2b. Site layer (skeleton, hand-written, identical in every build)

New `stack/skeleton/site.go`: one `renderPage(w, status, title, body)`
layout helper (header "Twitch clone" per the "Booking clone" naming
precedent, sorted nav, inline CSS, footer); `GET /{$}` homepage (exact
match; see R5); client/form page handlers keyed by `route.path`;
`registerSiteRoutes(mux)` called from `main.go`. For every POST cell, the
accumulator also emits a `GET <served_url>` registration pointing at that
route's page. Forms omit `action` and fetch() uses `location.pathname`, so
a page is byte-identical at the vulnerable and twin URLs (R1). The
per-cell handler files stay unchanged for every api route (the minimal
pair is untouched).

### 2c. HTML conversion for the 2 owner-scoped pages

`object_lookup_authorization_check.go.j2` (a shared sink, identical on both
twins) renders via `renderPage`: a 200 analytics/subscribers table that
**HTML-escapes** the echoed `channel_id` (R3), and a 403 page for the
denied branch. The layout text must contain none of
`AccessControlIdorStrategy._DENIAL_MARKERS` (R4).

### 2d. Absent-input declarations (PA-0053 + PA-0054), every route

A new required per-route key, `absent_input`, in `_ROUTE_PARAMS`, one of:
`default:<value>`, `required:400`, `form_on_get`, `auth_reject:401`,
`no_input`. Offline check: every route produced by every go manifest
declares exactly one, and `default`/`required` are actually rendered in
the source region (identical on both twins).

| Route | Declaration | Reason |
|---|---|---|
| `/api/clips/thumbnail`, `/clips/download` | `required:400` | No safe default URL. Today a bare GET is 502 on the vulnerable twin vs 403 on the secure twin (twin-distinguishing and >=500). |
| `/clips/export` | `required:400` | No meaningful default filename. Plus seed the export dir (R9). |
| `/channels/redirect` | `default:/` | `/` satisfies the secure twin's allowlist. Today the vulnerable twin sends an empty `Location`. |
| `/auth/login-redirect` | `default:<site path>` | `/` fails the secure regex (needs `/` + alphanumeric). Rule in R7. |
| `/channels/analytics`, `/channels/subscribers` | `default:caller` then `auth_reject:401` | Absent `channel_id` defaults to the caller's own `X-Broadcaster-Id`. If that is also absent, a handled 401 "sign in" page before the sink. A present `channel_id` behaves exactly as today (R6). |
| `/channels/settings` | `auth_reject:401` | Existing fail-closed token check already answers 401 on both twins. Asserted, not changed. |
| POST routes (6) | `form_on_get` | GET serves the page. A bare POST with empty body is also swept (§4). |
| `/sessions/refresh` | `no_input` | Source reads nothing (`no_op_token_request`). |

### 2e. Ground truth

Move the 15 cases' URLs (labels, points, CSV) and change `rendering` only
for `TWCH-0003`/`0007`. Re-run the contract loader's labels/CSV
cross-check.

## 3. Risk register

**R1 — twin URLs.** Default branch (a): twin-suffixed URLs via
`_twin_url_for`, matching Lane 2. Fall back to branch (b) (keep twins at
`/generated/...`, plus a direct twin-content-equality test across the two
URLs) only if Go 1.22 `ServeMux` rejects the suffixed pattern or reports a
pattern conflict at startup. Record which branch was used as an "R1
sign-off" in `FR-LAB-162`. Either way, a live test asserts every
converted/client page is byte-identical at both twin URLs. (The leakage
gate does not cover go, `leakage_probe.py:690-695`, so the direct test is
the proof.)

**R2 — test/ground-truth URL migration volume (~130 literal references).**
Rule: replace via a mapping derived from `served_url_for`, never by hand.
Before and after, `grep -c` each file (PA-0045). Done means zero
`/generated/labgen-go` in `tests/`, `lab/`, `fuzzlab/` code. Historical
docs/CHANGELOG are left as they are.

**R3 — HTML echo would add an unlabeled reflected XSS.** Converting the
analytics/subscribers echo from JSON to HTML without escaping changes the
cell's vulnerability class (contract §3). Rule: `html.EscapeString` on
both twins, with an offline template assertion and a live assertion that
a markup-bearing `channel_id` comes back escaped.

**R4 — oracle strategies that read response bodies/shapes.** Inventory
(`fuzzlab/oracle/strategies.py`): `AccessControlIdorStrategy` (`:884-941`:
needs 200, id echoed, no denial-marker words, distinct bodies);
`GoTemplateSstiStrategy` (`:448-593`: 3-digit token match; unaffected
unless the chat-command response gains a layout, which it doesn't, since
it's api); JSON-parsing strategies for tokens/mass-assignment/price
(unaffected, api); upload `Content-Type` strategy (POST response
unchanged); header-injection/open-redirect/path-traversal/SSRF (response
shapes unchanged). Rules: the layout and 200-page text must contain no
denial-marker word (offline assertion against the regex), and the layout
must contain no standalone 3-digit decimal token (offline assertion; this
guards any future page reuse of the layout by the SSTI cell). Re-run
`test_oracle*`, `test_labgen_go_live_boot.py`, and
`test_multitarget_category4.py` (`tp == 14`, `fp == 0` must hold).

**R5 — Go `ServeMux` pattern semantics.** `GET /` is a catch-all subtree,
so the homepage must use `GET /{$}` (otherwise every unknown path returns
200). Duplicate or conflicting patterns panic at startup. Mitigated by
an offline accumulator check for unique method+path pairs plus the live
boot.

**R6 — anonymous status for owner-scoped pages.** The R8 sign-off text
covers split `php_laravel` apps only. Decision: analytics/subscribers
answer a bare anonymous GET with the handled 401 page (§2d). Recorded as
an explicit "R6 sign-off" in `FR-LAB-162`. The crawl expects 401 for
`TWCH-0003`/`0007`.

**R7 — `/auth/login-redirect` default.** Rule: the default must (i) match
the secure template's own regex (extracted from the template file in an
offline test) and (ii) be a site-layer route that answers 200 live on
both twins' redirect target. Chosen value: `/dashboard`, a site-layer
page linking the creator tools. Any change must keep both assertions
green.

**R8 — crawl sees only `<a href>` and follows redirects.** `LocalSpider`
(`fuzzlab/tools/spider.py:217-228`, requests engine) parses links only,
follows redirects, and records the final status. So every GT URL must be
linked bare from a page, and redirect GT URLs are expected at their
followed final status (200). The raw status of each (302) is asserted
separately with the harness (no redirect following).

**R9 — clip-export directory missing in a fresh boot.** The secure sink's
`EvalSymlinks(absBase)` returns 500 when `static/clips_exports` is absent,
for any input. Rule: seed that directory in the skeleton with one sample
export (the path traversal test's own `mkdir(exist_ok=True)`,
`test_labgen_go_live_boot.py:1058-1059`, is compatible). If the sweep
confirms this 500 pre-change, it is a code defect and goes through the
bug protocol (§6).

**R10 — Go panic is not a 500.** `net/http` recovers a handler panic by
closing the connection with no response. The sweep must count any
exception or missing status as a failure, never skip it.

**R11 — offline conformance list is incomplete.**
`test_labgen_go_net_http_conformance.py`'s `_MANIFESTS` omits
`open_redirect_login_go_sample.yaml`. Same class as this work (route
enumeration), LAB-only, so fold it in: replace the list with the
emitter's `supports()`-driven glob (PA-0027).

**R12 — non-vacuous-pass guard** for the navigability test (Lane 1/2
pattern): hard-coded, measured minimums for GT points (14) and crawled
URLs, asserted before any per-URL check.

Accepted, not mitigated: none.

## 4. Navigability acceptance test

Offline, `tests/test_labgen_go_net_http_browsable.py`: `absent_input`
declared for every manifest route (PA-0054 part 1); unique ServeMux
patterns (R5); layout denial-word and 3-digit checks (R4); escaping (R3);
R7 regex; `served_url_for` round-trip; POST routes have GET page
registrations; handler files unchanged for api routes.

Live, `tests/test_labgen_go_net_http_navigability_live_boot.py` (slow,
skip-guarded on `go_boot_available()`), one whole-app boot of all 28
cells:
1. R12 guards first.
2. Crawl from `/` (`LocalSpider`, requests engine, `trust_env=False`). The
   depth cap is set from the measured depth plus headroom.
3. Every GT URL discovered, with the expected anonymous status table
   (hard-coded, one row per GT URL, compared for set equality).
4. `GET /` = 200.
5. PA-0054 part 2: for **every** served route (from `served_url_for` plus
   site routes), send a bare GET **and** a bare request with the route's
   own method (empty body, no headers). Every response must be < 500, and
   an exception counts as a failure (R10). Declared statuses are asserted
   per `absent_input`.
6. Twin byte-identity of every page (R1).

## 5. Sequencing (named gates)

1. `served_url_for` + ground-truth/test URL migration (R2). **Gate A:**
   full existing go offline + live suites green at the new URLs,
   `multitarget_category4` `tp == 14`, `fp == 0`.
2. Site layer + homepage + GET page registrations (R5). **Gate B:**
   offline accumulator/pattern checks, live `/` 200.
3. `absent_input` declarations + source rendering (§2d, R7, R9). **Gate C:**
   offline declaration check and per-route bare-request asserts.
4. Analytics/subscribers HTML (R3, R4, R6). **Gate D:** IDOR live tests
   and strategy re-run green.
5. Navigability test (§4), plus the scope-creep rule from `CC-LAB-0241`:
   fold in only same-class, LAB-only, go-emitter defects. Anything else is
   flagged with a recommended next CC-LAB number past Lane 7's reservation.
6. Full `pytest -m "not slow"` + every go live-boot suite, run explicitly.

## 6. Deliverables checklist

- [ ] `served_url_for`/`_twin_url_for` + accumulator; R1 branch recorded
      as the "R1 sign-off" in `FR-LAB-162`; Gate A green.
- [ ] Ground truth moved (labels/points/CSV); `rendering` changed only
      for `TWCH-0003`/`0007`.
- [ ] Test URL migration, grep-counted to zero (R2).
- [ ] Site layer (`site.go`), homepage `GET /{$}`, client/form pages,
      layout byte-identical across twins; Gate B green.
- [ ] `absent_input` on every route; offline PA-0054 check; Gate C green.
- [ ] Analytics/subscribers HTML with escaping and no denial markers;
      "R6 sign-off" in `FR-LAB-162`; Gate D green.
- [ ] Export-dir seed (R9); conformance manifest list derived (R11).
- [ ] Navigability test built and green, including the every-route
      two-method bare sweep.
- [ ] Same-class defects folded in; different-class findings flagged, not
      absorbed.
- [ ] Full non-slow suite + every go live-boot suite green, counts stated.
- [ ] `docs/components/01-target-lab/requirements.md`: new `FR-LAB-162`
      (and `FR-LAB-163` only if needed).
- [ ] `CHANGELOG.md`: one dated line referencing `CC-LAB-0243`.
- [ ] `docs/LAB_BROWSABLE_APPS_PLAN.md` Lane 3 row updated. Lanes 4-7
      bumped only if more than one CC-LAB number was used.
- [ ] Bug-protocol contingency: if the sweep finds a real crash/5xx (R9 is
      the likely candidate), do the full protocol with `BUG-0053`/`PA-0055`,
      including a recurrence review against `BUG-0051`/`PA-0053` and
      `BUG-0052`/`PA-0054`. The candidate strengthening is to sweep with
      each route's own method, not only GET. If none is found, say so
      explicitly.

## 7. Out of scope

- Other stacks (Lanes 4-7); compose/port 8086 wiring (Lane 7).
- New detection strategies. `webhook_signature` stays undetected, as
  before.
- Any change to a cell's vulnerable/secure logic beyond the §2d
  source-region defaults and the §2c escaping/rendering.

## 8. Review history

None yet. See the Status line: the reviewer mechanism was unavailable to
the proposing agent, and this is flagged to the orchestrator.
