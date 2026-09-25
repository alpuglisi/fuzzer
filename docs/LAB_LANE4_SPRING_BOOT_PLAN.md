# Browsable Labs Lane 4 — spring_boot: TrackerNest, Netflix clone, Expedia clone

Status: **revised after review round 1 (2026-09-25), awaiting round-2
confirmation.**

- Round 1 was run by the orchestrating session's own two reviewer agents
  (accuracy + adequacy), because this lane's sub-agent has no agent-spawning
  tool.
- The result was ACCURATE / ADEQUATE contingent on 2 fixes, plus 1
  recommended item. All three are applied in this revision (§8).
- **This plan does not authorize implementation.** It needs round-2 3/3
  agreement, and then the condensed `CC-LAB-0244` entry must clear its own
  gate, mirroring `CC-LAB-0242`'s process.

Reserved numbers, per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table, used
exactly: `CC-LAB-0244`; `FR-LAB-164` (browsable site) and `FR-LAB-165`
(declared absent-input contract, §2e); `CC-FUZZ-0050`/`FR-FUZZ-34` only if a
detection strategy must change (the plan expects not, §3 S7); `BUG-0054`/
`PA-0056` for the absent-input crashes Phase 1 already reproduced (§1.6, §6).
**One CC-LAB entry covers all three apps** (reasoning in §1.9). Lanes 5-7 are
**not** bumped.

## 0. What Lanes 1-2 taught us, applied here from the start

- **Reproduce the bug class live before planning, not at the end.** Lane 1
  found missing absent-input defaults only through its final crawl
  (BUG-0051). Lane 2 decided them up front but still confirmed crashes late
  (BUG-0052). This lane ran a **live pre-scan in Phase 1** (§1.6): every
  `spring_boot` cell booted for real, with a bare `GET`, a bare empty-body
  `POST` and a browser-`Accept` `GET` sent to every route. The plan's
  absent-input decisions (§2e) and its bug-protocol scope (§6) come from
  those observed results, not from guesses.
- **The navigability test's shape is designed before any conversion** (§4),
  as in Lane 2. As Lane 2's round-1 review pointed out, the crawl still
  *runs* late (§5 step 5). The real improvement is that every route's
  expected anonymous status is fixed in §4 before implementation starts.
- **PA-0054 applied as written, plus the gap Phase 1 exposed in it.**
  PA-0054's sweep is a bare `GET` of every served route. On this stack a
  bare `GET` to a `POST`-only route answers Spring's own `405` before the
  source runs (§1.6), so a `GET`-only sweep passes vacuously on exactly the
  routes that crash. The sweep designed in §4 therefore sends **each route's
  own method**, bare, as well as a `GET`.
- **R4's warning (Lane 1 step 3) verified directly, not assumed** (§1.2).
  The warning holds one level further than stated. Two routes that share
  **one sink family and the same two sink templates** classify differently:
  TrackerNest's `/wiki/pages/render` is a `page`, and Netflix's
  `/api/support/template-preview` is an `api`. The HTML conversion
  therefore has to be driven by the route profile, never by the sink
  template (§2b, S8).

## 1. Scope — what exists today (confirmed by direct code reading and a live pre-scan)

### 1.1 Emitter layout

- `fuzzlab/labgen/emitters/spring_boot/__init__.py` holds three things:
  - `_MODULE_SET_BY_SHAPE` (`:64-145`): `(vuln_class, family)` →
    source + complexity.
  - `_PAGE_PARAMS` (`:149-220`): the per-route render profile, keyed by
    `route.path`. This is the page-profile equivalent.
  - `SpringBootEmitter.render` (`:271-329`): one `@RestController` class
    per cell.
- `modules.py` holds the modules: 9 sources, 24 sinks, 2 complexities
  (`single_handler`, `single_handler_binary`). The op selects the sink
  directly; there is no transform stage (`modules.py:1-24`).
- **No route accumulator.** Spring's component scan discovers every
  generated controller (`__init__.py:21-28`).
- **Checked-in skeleton:** `stack/skeleton/`, Spring Boot 4.1.1, Java 21,
  Jackson 3, OGNL 3.4.13 (`pom.xml:10,26,31`).
  - Every generated class lives in `com.fuzzlab.trackernest.generated`
    (`__init__.py:324,328`), and the jar is always `target/trackernest.jar`
    (`live_boot_spring_boot.py:268`), **whichever app the cells belong to**.
- **No site layer exists**: no homepage, no layout, no catalog, no client
  pages. Live: `GET /` → `404 application/json` (Spring's default error
  body) for both builds (§1.6).

### 1.2 R4 verified: response formats differ per sink family

Read from every sink template and confirmed live (§1.6). Formats fall into
three families:

- **Explicit JSON** (`.header("Content-Type", "application/json")`):
  - `no_ownership_check`/`identity_match_before_fetch` (`:5-7`/`:5-8`)
  - `client_trusted_amount`/`server_recomputed_amount` (`:5-7`/`:16-18`)
  - `unfiltered_object_assign`/`typed_schema_allowlist` (`:23-26`/`:22-25`)
  - `predictable_token_source`/`csprng_token` (`:10-12`/`:13-15`)
  - the success branch of `jwt_*` (`:17-20`)
- **Plain `String`, no declared Content-Type:**
  - `user_supplied_template_compile`/`file_loaded_template_name`
    (`"Rendered macro result: …"`)
  - both SpEL sinks (`"Sort result: …"`)
  - both XXE sinks (`"Imported issue title: …"`)
  - both Java-native deserialization sinks
  - the Jackson deserialization sinks' `{"status":"ok"}` (JSON-shaped, but
    no declared type)
  - the JWT `401` body and every SSRF body (JSON-shaped text, no declared
    type)
- **Raw bytes:** `no_extension_check`/`extension_allowlist_mime_check`, via
  `single_handler_binary`. The response *is* the uploaded file, with a
  derived Content-Type.

So `spring_boot`'s default is **neither** `php_laravel`'s JSON **nor**
uniform. The per-route `page`/`api` test (§1.5) is applied route by route.

### 1.3 The three app identities exist, but as ground truth only, never as built apps

All 32 `spring_boot` cells form 16 same-route vulnerable/secure twin pairs:

| App | GT dir | GT points | Cells | Manifests |
|---|---|---|---|---|
| TrackerNest (cat. 3, Atlassian) | `lab/ground-truth-trackernest/` (TNEST-0001..0003) | 3 | `LABGEN-SSTI-0001/2`, `LABGEN-XXE-0001/2`, `LABGEN-DESER-0001/2` | `ssti_spring_boot_sample`, `xxe_spring_boot_sample`, `insecure_deserialization_spring_boot_sample` (first 2 cells) |
| Netflix clone (cat. 4) | `lab/ground-truth-netflix-clone/` (NFLX-0001..0011) | 11 | `LABGEN-JV-0001..0022` | `insecure_deserialization_spring_boot_sample` (JV-0001/2), 10 `*netflix*` manifests |
| Expedia clone (cat. 5) | `lab/ground-truth-expedia-clone/` (EXPD-0001..0002) | 2 | `LABGEN-EXP-0001..0004` | `expedia_spel_injection_sample`, `expedia_trip_restore_sample` |

Facts established from the code:

- **No app has ever been booted as a whole.** The harness takes exactly one
  cell by design (`live_boot_spring_boot.py:24-32,195-216`). The reason:
  both twins of every pair share one `route.path` (every manifest above),
  and Spring rejects an ambiguous mapping at startup.
  - The only multi-cell boots are hand-assembled, vulnerable-only
    multitarget fixtures, e.g.
    `tests/test_labgen_spring_boot_trackernest_multitarget.py:79`.
    Everything else is single-cell.
- **App membership cannot be derived from the manifest file.**
  `insecure_deserialization_spring_boot_sample.yaml` carries TrackerNest's
  `LABGEN-DESER-0001/2` **and** Netflix's `LABGEN-JV-0001/2`
  (`/api/playback/resume`).
  - It *is* derivable from the route, and from the cell-ID prefix: `JV-` is
    Netflix, `EXP-` is Expedia, and `SSTI-`/`XXE-`/`DESER-` are TrackerNest.
    Those prefixes are generic class names, not app names.
- Every `spring_boot` cell is a ground-truth-bearing real page or its
  secure twin. **There are no illustrative covering-array cells** (contrast
  PicTrail's 6).

### 1.4 No session/login mechanism; the R8 exception does not apply

Caller identity is modelled by fixed demo headers, per the
`read_account_id_and_caller_header` source docstring (`modules.py:295-309`)
and the JWT source (`modules.py:580-605`):

- `X-Account-Id`, which stands in for the caller's own account;
- `Authorization: Bearer <jwt>`.

No cookie, session or login route exists. The navigability test needs no R8
401 exception. `/api/account/preferences` answers an anonymous visitor with
`401`, but that is a **token-gated API's** correct response, not a
session-gated page (§4). It is stated explicitly rather than folded silently
into R8.

### 1.5 `page` vs `api` classification, per route

The test (`docs/LAB_BROWSABLE_APPS_PLAN.md` refinement), applied per route,
with "choose `page` when unsure":

| App | Route (method) | Class | Justification against the real product |
|---|---|---|---|
| TrackerNest | `/wiki/pages/render` (GET `macroExpr`) | **page** | Confluence's macro/page render is a server-rendered browser page (the real CVE-2021-26084 surface is a Velocity-rendered `.action` page). Not under an `/api/` namespace. |
| TrackerNest | `/issues/import` (POST raw XML) | api | A raw `application/xml` request body can't be produced by an HTML form. It is Jira's REST-style XML import. Client page: textarea + `fetch()`. |
| TrackerNest | `/integrations/webhook-payload` (POST Java-serialized binary) | api | A webhook receiver, named explicitly by the parent plan. Client page: file input + `fetch()` posting the bytes. |
| Netflix | `/api/playback/resume`, `/api/profiles/switch` (POST JSON) | api | Deserialization endpoints (named explicitly), called by the player/profile-gate SPA. |
| Netflix | `/api/content/import` (POST XML) | api | Partner (B2B) content-ingest feed, machine to machine. |
| Netflix | `/api/account/billing` (GET `account_id`) | api | JSON backend of the account SPA. The URL is literally `/api/`. `AccessControlIdorStrategy` reads its JSON. |
| Netflix | `/api/subscription/change-plan` (POST JSON) | api | JSON backend. `PriceTrustDifferentialStrategy` reads its JSON. |
| Netflix | `/api/profiles/avatar` (POST multipart) | api | Its response *is* the uploaded file's bytes. Wrapping it would destroy the modelled CWE-434 stored-XSS chain. Client page: a plain `enctype="multipart/form-data"` form (no `fetch()`: browsers submit multipart natively). |
| Netflix | `/api/account/settings` (POST JSON) | api | JSON mass-assignment API (named explicitly). |
| Netflix | `/api/account/preferences` (GET, `Authorization`) | api | JWT API (named explicitly). A link can't carry the header. Client page: token field + `fetch()`. |
| Netflix | `/api/content/thumbnail-import` (POST, `thumbnail_url` **in the query**) | api | Partner-portal backend call. The response is the fetched body. |
| Netflix | `/api/session/refresh` (POST, no input) | api | Token-refresh JSON API. |
| Netflix | `/api/support/template-preview` (GET `expr`) | api | Support-console backend, under `/api/` by design (`CC-LAB-0197`). Same sink family as TrackerNest's `page` above, but a different product surface (S8). |
| Expedia | `/api/hotels/search-sort` (GET `sortBy`) | api | Search-results sort call from the SPA, under `/api/`. |
| Expedia | `/api/trips/restore` (POST JSON) | api | Deserialization endpoint (named explicitly). |

Result: **1 `page`, 15 `api`.**

- Netflix's and Expedia's entire ground-truth surface is their SPA backend
  (`/api/*`). Their browsable form is a homepage, a layout and **one client
  page per api**.
- **No ground-truth URL moves.** Every GT URL already fits its app. Contract
  point 5 (realistic URLs) is already met for the vulnerable cells. Only
  secure twins get new URLs (S1).

### 1.6 Live pre-scan (Phase 1, 2026-09-25, research only, nothing committed)

Method: the 16 vulnerable cells (pairwise-distinct routes) were
hand-assembled and booted as one Spring app, then the 16 secure cells as a
second app, using the real skeleton and `mvn package` + `java -jar`. Each
route then received a bare `GET`, a bare empty-body `POST`, a browser-`Accept`
`GET`, and (for POST routes) a malformed-JSON `POST`. Findings:

1. **Absent-input crashes (the PA-0053 class):**
   - `/api/profiles/avatar`, **both twins**: a bare `POST` gets **500**.
     `request.getPart("file")` throws on a non-multipart request, before the
     source's own `part == null → 400` guard
     (`read_uploaded_avatar_file.java.j2:1-5`).
   - `/api/content/thumbnail-import`, **vulnerable twin**: a bare `POST`
     gets **502**. The absent `thumbnail_url` becomes `""`
     (`query_param.java.j2:1-4`) and reaches `unchecked_url_fetch`'s
     `URI.create("")`. The secure twin answers 403.
2. **Absent input that reaches the sink without crashing (undeclared, so
   still in PA-0054's scope):**
   - `/api/subscription/change-plan` vulnerable twin: 200 with **malformed
     output** `{"plan_tier":"","monthly_charge":}`.
   - `/api/account/billing` (both twins): 200 for `account_id=""`. On the
     secure twin, `""` equals a missing `X-Account-Id` (`""`), so billing
     data is disclosed.
   - `/wiki/pages/render` and `/api/support/template-preview`: vulnerable
     twin 400 (`Malformed OGNL expression: `), secure twin 200. This
     incidental twin split is visible on a bare URL.
   - `/api/hotels/search-sort` (both twins): incidental 400
     (`'expressionString' must not be null or blank`).
   - Whole-body routes with an empty body: incidental sink-side 400s
     (XML "Premature end of file", Jackson "No content to map",
     `ObjectInputStream` EOF). `/api/account/settings` gets 200 from the
     seeded record.
3. **Content-Type negotiation (a spring_boot-specific gotcha):** every
   plain-`String` response is served as `text/plain` to a default client
   but as **`text/html;charset=UTF-8` to a browser `Accept` header**.
   - Live: the OGNL vulnerable twins reflect `'<b>x</b>'` as
     `200 text/html` `Rendered macro result: <b>x</b>`.
   - That is a **latent, unlabelled reflected XSS** on both
     `/wiki/pages/render` and `/api/support/template-preview` today, and
     error messages that echo input share the exposure. It is independent
     of this lane (pre-existing). See S2.
4. **Malformed (present) JSON → 500 on both twins** of
   `/api/account/settings` and `/api/subscription/change-plan`. An uncaught
   `readTree` exception. This is a *different class* from absent input (S6).
5. **Bare `GET` of every POST route → Spring's 405**, before any source
   runs. A `GET`-only sweep can't see findings 1-2 on POST routes (§0, S5).
   A browser `GET` of a POST route shows Spring's "Whitelabel Error Page".

### 1.7 Existing test coverage

- **Offline:** `tests/test_labgen_spring_boot*.py` (non-live),
  `test_labgen_expedia_trip_restore.py`, `test_labgen_spel_injection.py`,
  `test_labels_contract_category4.py`, `test_auto.py`.
- **Live-boot** (all `slow`, all single-cell except the multitarget
  fixtures):
  - `test_labgen_spring_boot_live_boot.py` (SSTI)
  - `_xxe_live_boot`, `_deserialization_live_boot`,
    `_deserialization_jackson_live_boot`,
    `_deserialization_netflix_profiles_live_boot`, `_netflix_xxe_live_boot`
  - `_account_billing_live_boot`, `_subscription_price_integrity_live_boot`,
    `_netflix_avatar_upload_live_boot`,
    `_netflix_settings_mass_assignment_live_boot`,
    `_netflix_jwt_preferences_live_boot`, `_netflix_thumbnail_ssrf_live_boot`,
    `_netflix_session_refresh_live_boot`,
    `_netflix_support_template_preview_live_boot`
  - `test_labgen_expedia_trip_restore_live_boot.py`
  - `test_labgen_spring_boot_trackernest_multitarget.py`,
    `test_labgen_spring_boot_expedia_multitarget.py`,
    `test_multitarget_category4.py`,
    `test_multitarget_category5_combined.py`
- These tests request the **manifest route path on both twins**. Each twin
  is booted alone, e.g. `_ROUTE` in
  `test_labgen_spring_boot_account_billing_live_boot.py:30`.
- **No navigability test and no whole-app test exist** for any of the three
  apps.

### 1.8 Stack-specific gotchas (the analogue of Lane 2's PicTrail findings)

- **G1:** same-route twin collision. There is no whole-app build (§1.3, S1).
- **G2:** browser-`Accept` negotiation turns plain-text bodies into HTML
  (§1.6.3, S2).
- **G3:** `rendering` doubles as the *request* encoding for whole-body
  points (`fuzzlab/harness/auto.py:92-96`). 9 of the 16 GT points are
  `param=body` (TrackerNest 2, Netflix 6, Expedia 1), 6 of them
  `server-json`. Relabelling any of them would
  silently switch `fuzzlab auto` from JSON to raw encoding (S3).
- **G4:** one sink template pair serves both a `page` and an `api` route
  (S8).
- **G5:** a `GET`-only bare sweep can't see POST-route crashes (S5).
- **G6:** app membership is by route, not by manifest file (§1.3, S11).
- **G7:** all three apps share one Java package and jar name
  (`trackernest`). This is invisible to a visitor; it is not renamed
  (§7).

### 1.9 One CC-LAB entry or three?

**One: `CC-LAB-0244`.** The evidence:

- All three apps share one emitter, one skeleton, one harness, one twin-URL
  mechanism, one absent-input declaration scheme, one layout helper and one
  site-layer generator.
- The per-app differences are **data**: a route profile's `app` key, one
  registry entry per app (name/tagline/brand/nav), and the per-app client
  pages. They are not separate mechanisms.
- Only one app (TrackerNest) has a JSON/text→HTML page conversion, and it
  is a single route.
- Three entries would each restate the whole shared mechanism, or they
  would depend on one another in sequence. That is exactly the
  three-entries-for-one-change shape the per-step split in Lane 1 existed to
  avoid.
- Per-app risk is still kept separate in §3 (items T*, N*, E*), and the
  navigability test is per app (§4).

`FR-LAB-164` covers the browsable site and `FR-LAB-165` the absent-input
contract. Both numbers are inside the reservation. **No bump is needed for
Lanes 5-7.**

## 2. Fix design

### 2a. App registry and route-profile keys (shared)

A new `fuzzlab/labgen/emitters/spring_boot/app_site.py` defines
`APP_REGISTRY` with `trackernest`/`netflix`/`expedia`. Each entry carries
`name`, `tagline`, `brand` colour, and an ordered `nav` of
`(href, label)`. The nav is sorted deterministically, per contract point 2.

Every `_PAGE_PARAMS` route gains three render-only keys:

- `app`: the owning app key (S11);
- `classification`: `"page"` or `"api"`, per §1.5;
- `absent_input`: the declared absent-input behavior (§2e).

An offline test cross-checks two things:

- `{route.path of each app's vulnerable cells}` equals that app's GT
  `injection-points.json` URL set;
- the cell-ID prefixes of §1.3.

### 2b. Page conversion: route-profile-driven, at the complexity layer (TrackerNest `/wiki/pages/render` only)

A new complexity template `page_handler.java.j2` is selected when
`classification == "page"`. Its handler:

1. applies the route's absent-input behavior (`form_when_absent`, §2e):
   when `macroExpr` is absent or empty, it returns the page with the form
   and **no preview**, before the source/sink run;
2. otherwise calls a private `compute(request)` method whose body is the
   unchanged `source + sink` code;
3. returns `SiteLayout.page(app, title, formHtml, result)`.

`SiteLayout` is a new checked-in class,
`stack/skeleton/src/main/java/com/fuzzlab/trackernest/SiteLayout.java`, so
every build compiles, single-cell included. `SiteLayout.page`:

- **HTML-escapes** the sink's body (`org.springframework.web.util.HtmlUtils.htmlEscape`,
  already on the classpath via `spring-web`, so no new dependency) into
  `<pre class="result">`;
- **preserves the sink's status code**;
- sets `Content-Type: text/html;charset=UTF-8` explicitly, never relying on
  negotiation (S2).

The form's `macroExpr` input is always rendered **empty**. The page never
echoes the submitted value (S7).

**No sink template changes.** Netflix's `/api/support/template-preview`
renders through the same two sink templates with `single_handler`, so it is
unchanged (S8). An offline test asserts that no sink template references
`SiteLayout`.

**Exploitability change, called out per contract point 3:** escaping
removes `/wiki/pages/render`'s latent, unlabelled reflected XSS (§1.6.3).
The served behavior then matches its ground truth (`ssti` only). The
vulnerability class (OGNL evaluation) and the probe path are unchanged.

### 2c. Site layer, per app (home, catalog, client pages)

`SpringBootEmitter.render_site(cells, app_key)` emits one generated
`SiteController.java` for that app's build. It holds:

- `GET /`: the homepage (name, tagline, nav);
- `GET /catalog`: every cell's served URL, method and cell ID, twins
  included, sorted;
- a **client page** for every api route of that app:
  - For a **POST** api, the client page is served by `GET` on **the api's
    own served URL**, so a crawl reaches the GT URL itself with `200`. This
    is Lane 1's CircleFeed/Huddle Hub pattern (`CC-LAB-0239`), and it
    applies to both twins' URLs.
  - For a **GET** api, the client page lives at a separate, realistic,
    non-`/api` URL (`/account/billing`, `/account/preferences`,
    `/support/template-preview`, `/hotels/search`). It links to the raw api
    URL with an `<a href>` (so the crawl discovers the GT URL), and the
    catalog lists it too.

Client-page mechanics:

- `fetch()` sends the api's real wire format: `application/xml` for XML,
  `application/json` for JSON, `application/octet-stream` for the
  Java-serialized webhook, and an `Authorization` header built from a token
  field for JWT.
- `/api/content/thumbnail-import` puts `thumbnail_url` **in the query
  string** (GT `location: query`), never in the body.
- `/api/profiles/avatar` is a plain multipart `<form>`, with no `fetch()`.
- Results are shown with `textContent` only, never `innerHTML` (S12).

Every page uses `SiteLayout`: byte-identical per app, inline CSS, no
external assets, no request-derived interpolation in the layout, and **no
run of 3 or more digits in layout/page chrome** (S7).

### 2d. Whole-app build and twin URLs (shared)

`SpringBootEmitter(site_build: bool = False)` and
`served_url_for(cell, *, site_build)`:

- **Site builds:**
  - each vulnerable cell (the explicit frozenset
    `_REAL_PAGE_CELL_IDS`, 16 IDs) is served at its own `route.path`;
  - each secure twin (`_REAL_PAGE_TWIN_CELL_IDS`, 16 IDs) is served at
    `route.path + "." + cell_id.lower()`, e.g.
    `/wiki/pages/render.labgen-ssti-0002`. This is Lane 1's/Lane 2's
    `_twin_url_for` shape.
- **Single-cell builds** (`site_build=False`, the default) keep today's
  behavior exactly, with both twins at `route.path`. The decision rule is in
  S1.

`SpringBootLiveBootHarness` gains an additive **app mode**:
`SpringBootLiveBootHarness(emitter, cells, app="netflix")`. It assembles the
skeleton plus every cell of that app (site-mode URLs) plus `render_site`,
then builds and boots. Single-cell construction is unchanged, and all
existing callers keep working.

The assembly step becomes a public function,
`assemble_spring_boot_app(app_key, dest)`, so that Lane 7 can build each
app's jar for its compose service without re-implementing assembly. No CLI
or compose wiring is done here (§7).

### 2e. Absent-input contract (PA-0053/PA-0054, and PA-0056's strengthening), decided now

Every route profile declares exactly one `absent_input` value. It is
rendered in the **source region**, identically on both twins, **before any
sink**, and covers **every input channel** the route reads, not only named
query parameters:

| Route | Channel | Declared `absent_input` | Bare-request result (both twins) |
|---|---|---|---|
| `/wiki/pages/render` | query `macroExpr` | `form_when_absent` (page; accepted in review round 1, see below) | `GET` → 200 page, form only, sink not run |
| `/api/support/template-preview` | query `expr` | `required_param` | `GET` → 400 `missing required parameter: expr` |
| `/api/hotels/search-sort` | query `sortBy` | `default_value` = `'recommended'` (a SpEL string literal: "Sort result: recommended" on both twins) | `GET` → 200 |
| `/api/account/billing` | query `account_id` | `required_param` (also closes the secure twin's `""==""` disclosure, §1.6.2) | `GET` → 400 |
| `/api/content/thumbnail-import` | query `thumbnail_url` (on POST) | `required_param` (no safe default URL: any default would make the vulnerable twin fetch it; same reasoning as PicTrail's R4) | `POST` → 400; `GET` → 200 client page |
| `/api/account/preferences` | header `Authorization` | `required_header` → 401 + `WWW-Authenticate: Bearer` before the sink | `GET` → 401 |
| `/api/profiles/avatar` | multipart part `file` | `required_multipart`: non-multipart `Content-Type` or no `file` part → 400, checked **before** `getPart` | `POST` → 400 (was 500); `GET` → 200 client page |
| `/issues/import`, `/api/content/import`, `/api/account/settings` | whole body (`raw_body`) | `empty_body_400` | `POST` → 400; `GET` → 200 client page |
| `/api/playback/resume`, `/api/profiles/switch`, `/api/trips/restore` | whole body (`jackson_body`) | `empty_body_400` | `POST` → 400; `GET` → 200 client page |
| `/api/subscription/change-plan` | whole body (`read_plan_change_request`) | `empty_body_400` (also ends the vulnerable twin's malformed-JSON output) | `POST` → 400; `GET` → 200 client page |
| `/integrations/webhook-payload` | whole body (`request_stream`) | `empty_body_400` via `getContentLengthLong() == 0`. A chunked empty body still reaches the sink's own handled 400 (EOF), which is recorded, not hidden. | `POST` → 400; `GET` → 200 client page |
| `/api/session/refresh` | none | `no_input` (the modelled request has no input; a bare `POST` is the normal request) | `POST` → 200; `GET` → 200 client page |

**`form_when_absent`: decided in review round 1, adopted.** This is the one
value outside PA-0053's literal "default or 4xx".

- **Why the adequacy reviewer accepted it:** it satisfies PA-0053's safety
  property (no sink is reached with absent input), and it matches Lane 2's
  `/settings`/`/inbox` `get_form_template` precedent ("a bare GET should
  show the form, not touch the sink").
- **Rejected alternatives:**
  - `default_value = 'welcome'` (a quoted OGNL string literal), which was
    the draft's fallback;
  - a bare `welcome` default, because the vulnerable twin would answer 400.
- **Sign-off:** the `FR-LAB-165` entry records this as an explicit sign-off
  ("`form_when_absent` accepted, review round 1"). It is not an
  implementation-time choice.

### 2f. Ground truth: no edits

- `TNEST-0001` is already `rendering: "server"`, and after §2b that is
  literally true.
- Every other point stays an `api` with an unchanged wire format.
- Changing any `param=body` point's `rendering` would change `auto.py`'s
  request encoding (G3/S3).

An offline test pins that `points_from_ground_truth` yields the same
`body_content_type` for all 16 points as it does today.

## 3. Risk register

### Shared (all three apps)

**S1 — same-route twin collision; no whole-app build exists (G1).**

- **Decision rule:** secure-twin suffix URLs **in site builds only**
  (§2d). Single-cell builds keep `route.path` for both twins.
- **Rejected alternative:** suffixing everywhere. It would force rewriting
  the secure-twin half of about 15 proven single-cell differential tests
  (§1.7), all of which hard-code the manifest path, for no browsability
  gain. A single-cell build has no collision.
- **The one-derivation rule** (PA-0003/PA-0021) is kept:
  `served_url_for(cell, site_build=…)` is the only derivation, and both the
  emitter and the tests call it.
- **Offline tests:**
  - site-mode URLs are unique across `(method, url)` per app, site routes
    included;
  - `served_url_for(vulnerable, site_build=True) == route.path`, so GT is
    unaffected;
  - `site_build=False` is byte-identical to today's `render()` output for
    every non-page route.
- **Fallback:** if Spring's `PathPatternParser` mishandles a `.`-suffixed
  literal (not expected; suffix matching is off by default in Boot 3+), use
  `route.path + "/" + cell_id.lower()` instead, and record which one in
  `FR-LAB-164`.

**S2 — Content-Type negotiation turns plain-text bodies into HTML (G2,
confirmed live).**

- The page route sets `text/html` explicitly and escapes (§2b).
- The api routes are **not changed**. Adding `produces`/explicit types would
  change the wire contract of every plain-text api route (§1.2's second
  family: 10 of the 15 api routes), and the exposure is a different class:
  latent, unlabelled reflected XSS, not absent input.
- **Flagged as a follow-up.** It is pinned by one `xfail(strict=True)` live
  test in the navigability module, which asserts that
  `/api/support/template-preview`'s vulnerable twin does not serve an
  `Accept: text/html` reflection as `text/html`.
- **Recommended follow-up number:** the orchestrator's next unreserved
  `CC-LAB` (above `CC-LAB-0248`, which is already cited as Lane 1's
  follow-up).

**S3 — `rendering` is also the request encoding (G3).** Decision: no GT
edits (§2f). This is guarded by the offline `body_content_type` pin.

**S4 — the absent-input class (PA-0053/0054) is present (confirmed live,
§1.6.1-2).** Fixed by §2e's declarations.

- The two crashes (avatar 500 on both twins, thumbnail-import 502 on the
  vulnerable twin) are code defects. They go through the **full bug
  protocol as `BUG-0054`/`PA-0056`** (§6), with a recurrence review against
  `BUG-0051`/`PA-0053` and `BUG-0052`/`PA-0054`.
- **Why PA-0054 did not prevent them, as far as Phase 1 can tell:**
  1. its sweep is a bare `GET`, which a POST route answers with a
     framework 405 before any source runs (S5);
  2. its declaration rule names "each named request parameter", which
     doesn't cover whole-body, multipart-part or header channels;
  3. BUG-0052's own PA-0002 sweep deferred `spring_boot` "to its lane" in
     prose, against PA-0054(3)'s own "never a prose deferral".
- The candidate `PA-0056` must fix those three failure modes, not restate
  PA-0054.

**S5 — a `GET`-only sweep is blind on POST routes (G5).** §4's sweep sends
each route's own method bare, plus a `GET`, and asserts the **declared**
status from §2e, not just `< 500`.

**S6 — malformed present JSON → 500 (§1.6.4).**

- This is a **different class** (malformed present input, not absent
  input), so under the scope-creep rule in §5 step 5 it is **not fixed
  here**.
- It is flagged as a named follow-up and pinned by
  `xfail(strict=True)` live tests for `/api/account/settings` and
  `/api/subscription/change-plan`.
- If review judges it the same class, the fix is a `try/catch` → 400 in the
  shared sources `raw_body`/`read_plan_change_request`, identical on both
  twins.

**S7 — the SSTI oracle's echo and digit-collision constraints on the one
page.**

- `SstiStrategy.confirm` needs `product in text and expr not in text`
  (`strategies.py:308-315`). Products are 5-6 digits (operands in
  `[100,999]`).
- Two consequences:
  - an echoed `macroExpr` in the form would suppress every true positive;
  - a 5+ digit run in the chrome could false-positive the secure twin.
- **Mitigation:**
  - the page never echoes the value (§2b);
  - an offline test asserts that layout and page chrome contain no run of
    3 or more digits (which also covers SpEL's 3-digit canary if a SpEL
    route ever becomes a page);
  - `SstiStrategy` is re-run live against both twins through the existing
    `test_labgen_spring_boot_live_boot.py` and TrackerNest multitarget
    (recall stays 2/3).
- **`SpelInjectionStrategy` and every other strategy read only api
  responses**, whose wire format is unchanged. `CC-FUZZ-0050`/`FR-FUZZ-34`
  are expected **unused**. If a strategy does need changing, it uses those
  numbers, and it is never weakened (contract point 7).

**S8 — one sink family, two classifications (G4).** HTML conversion lives
only in `page_handler.java.j2`, selected by the route profile. An offline
test asserts that no `sinks/*.java.j2` references `SiteLayout` or
`text/html`, and that `/api/support/template-preview`'s rendered controller
is unchanged apart from its §2e guard.

**S9 — minimal-pair property (BUG-0027).** Every new line lives in the
source or complexity region and is identical on both twins: the guards, the
page wrapper, the form. This is asserted offline per route by normalizing
the handler name, in the same way as Lane 2's
`test_absent_input_lines_are_identical_on_both_twins`.

**S10 — backward compatibility of the harness and skeleton.**

- `SiteLayout.java` is checked into the skeleton, so single-cell builds
  still compile. `SiteController.java` is emitted only in app mode.
- **Gate:** every existing `spring_boot` live-boot suite (§1.7) is re-run
  green after §5 steps 1, 2 and 3.
- **Decision rule:** if an existing test asserts on a whole-body source's
  empty-body behavior, or on the SSTI route's raw text body, update the
  assertion only if the new behavior is the declared one from §2b/§2e.
  Never weaken a differential assertion.

**S11 — app membership (G6).** The route profile's `app` key is
cross-checked offline against the GT URL sets and the cell-ID prefixes
(§2a).

**S12 — client-page DOM XSS.** API responses are rendered via
`textContent` only. An offline test asserts that no generated client page
contains `innerHTML`, `outerHTML`, `document.write` or `insertAdjacentHTML`.

**S13 — non-vacuous pass and depth, per app.** Minimums for GT points and
crawled pages are hard-coded and measured per app (§4). The depth cap is
measured, and the deepest GT URL is asserted to be below the cap.

**S14 — oracle-mechanism inventory, both kinds (Lane 2's R6).**

- Runtime strategies touching these cells:
  - `SstiStrategy` (both OGNL routes)
  - `SpelInjectionStrategy`
  - `XxeInBandMarkerStrategy`
  - `InsecureDeserializationTypeConfusionStrategy`
  - `AccessControlIdorStrategy`
  - `PriceTrustDifferentialStrategy`
  - `JwtAlgNoneConfusionStrategy`
  - `SsrfInBandMarkerStrategy`/`SsrfOobStrategy`
  - `PredictableTokenSourceStrategy`
  - mass-assignment and file-upload strategies (to be enumerated by name
    from `strategies.py` at implementation time, not by memory)
- All of them, except SSTI on `/wiki/pages/render`, read api responses that
  are unchanged. Build-time validators, such as `static_precheck.py`'s SpEL
  check (`:175`), read generated source, and the SpEL source gains only a
  default line.
- **Verification is by re-running** every live-boot and multitarget suite
  in §1.7, not by reading code.

**S15 — the PA-0002 sweep across the other emitters, done by this lane
(review round 1, adequacy fix 1).**

The draft handed the other emitters to "the orchestrator reconciles". That
is the same prose deferral this plan diagnoses in BUG-0052 (S4 failure
mode 3), so this lane now pins them itself.

**What exists today** (verified directly, 2026-09-25, not assumed):

- `php_laravel`'s remaining known instances are already pinned by strict
  xfails (`tests/test_labgen_navigability_live_boot.py`, from BUG-0051).
- `django` is fixed and guarded by an offline declaration check
  (`tests/test_labgen_django_browsable.py::test_every_get_param_route_declares_its_absent_input_behavior`,
  BUG-0052).
- The other five emitters have **no pin of any kind and no declaration
  mechanism**. A search for `default_value`/`required_param` under
  `fuzzlab/labgen/emitters/{go_net_http,ruby_rails,node_express,python_fastapi,php_current}/`
  finds 0 files, and no test mentions PA-0053/PA-0054 for them:
  - `go_net_http` and `node_express` have `_ROUTE_PARAMS`
    (`go_net_http/__init__.py:361`, `node_express/__init__.py:171`);
  - `python_fastapi` and `php_current` have `_PAGE_PARAMS`
    (`python_fastapi/__init__.py:105`, `php_current/__init__.py:123`);
  - `ruby_rails` has no per-route profile at all, only the shape-keyed
    `_SHAPE_CTX` (`ruby_rails/__init__.py:118`) and
    `_REAL_PAGE_URL_BY_CELL_ID` (`:192`).

**What this lane adds** (a deliverable, not a hand-off): a new offline
module, `tests/test_absent_input_declarations_cross_emitter.py`.

- It is parametrized over **every** emitter package, and each case asserts
  PA-0054(1): every route the emitter's manifests produce carries a declared
  absent-input behavior.
  - `spring_boot` passes. It is fixed by this lane: `absent_input` on every
    `_PAGE_PARAMS` route.
  - `django` passes, re-asserting its existing check against its
    `default_value`/`required_param` keys.
  - `php_laravel` is **not assumed to pass**. `default_value` appears once
    in `php_laravel/__init__.py`, and its live pin covers only Huddle Hub's
    `/messages/unfurl`
    (`test_huddlehub_unfurl_bare_get_is_a_handled_error_not_a_crash`), so
    its full declaration coverage is unverified.
    - **Decision rule:** if every route declares, the case passes.
    - Otherwise the case is marked `xfail(strict=True)`. Its reason lists
      the undeclared routes and cites the existing live pin, and its owner
      is a Lane 1 follow-up with a recommended next CC-LAB number from the
      orchestrator.
    - Either way the result is recorded in `CC-LAB-0244`'s Effectiveness.
  - Each of `go_net_http`, `ruby_rails`, `node_express`, `python_fastapi`
    and `php_current` is marked `xfail(strict=True, reason="PA-0054(1)
    unmet: no absent-input declaration mechanism; owner: Browsable Labs
    Lane N (see docs/LAB_BROWSABLE_APPS_PLAN.md)")`. The owner is Lane 3,
    5, 6 or 6 respectively. `php_current` has no Browsable Labs lane, so it
    names "no lane assigned — follow-up" and gets a recommended next
    CC-LAB number from the orchestrator.
- This is an **offline failing check pinned by a strict xfail** (PA-0054(3)'s
  exact wording). When a lane adds declarations, its case XPASSes, the
  strict marker turns the suite red, and the marker must be removed in that
  same lane's change. That makes it mechanical, not remembered.
- The check reads each emitter's own route enumeration (its route-profile
  table plus its manifests via `supports()`), never a hand-kept list
  (PA-0027).

**Decision rule — interaction with concurrent Lanes 3/5/6:**

- This lane owns only the new test file. It edits none of those emitters.
- If a concurrent lane merges first and already declares absent-input
  behavior, the merge makes that emitter's case XPASS, and the fix is to
  delete that one `xfail` marker at merge time. This is expected and
  intended; it is a signal, not a conflict. The plan states it here, so the
  orchestrator's reconciliation is a known one-line edit, not a judgment
  call.
- **Scope of the pin, stated honestly:** it is an *offline declaration*
  check (PA-0054(1)). It does not prove that those emitters' routes crash
  live, because booting four more stacks is those lanes' own navigability
  work (PA-0054(2)). The xfail reason says exactly that.

### Per app

**T1 (TrackerNest) — the only JSON/text→HTML conversion.** Gated on:
200 HTML in the layout; bare `GET` → form only; SSTI still confirmed on the
vulnerable twin and not on the secure twin; existing assertions `"49"` /
`"Unknown macro"` / `"Welcome to the team wiki!"` still pass (none contains
an escapable character).

**T2 (TrackerNest) — the binary webhook client page.** A browser can't
author a Java-serialized stream, so the client page takes a file and POSTs
its bytes. The page says so plainly and does not pretend to be a real
webhook sender.

**N1 (Netflix) — 11 api client pages, 22 cells, the largest build.**
Three GET apis need separate client-page URLs plus `<a href>` links (§2c).
The measured crawl depth is expected to be at most 2.

**N2 (Netflix) — `/api/profiles/avatar`.** The multipart guard must run
before `getPart` (§2e). The client page is a plain multipart form. The
existing upload differential tests re-run green.

**N3 (Netflix) — `/api/content/thumbnail-import`'s query-carried param on a
POST.** The client page must use the query string. The `required_param`
guard fires only when the query **and** the form body lack it
(`getParameter` reads both).

**N4 (Netflix) — `/api/account/preferences`.** An anonymous visitor gets
401. This is a token API's correct response, not R8 (§1.4).

**E1 (Expedia) — `/api/hotels/search-sort` default.** `'recommended'` must
evaluate to 2xx on **both** SpEL contexts (restricted and unrestricted).
This is verified live at §5 step 2. If either twin errors, fall back to
`required_param` (400).

**E2 (Expedia) — smallest app** (2 api, 4 cells). The non-vacuous minimums
must still be meaningful: GT is at least 2, and pages are at least the
measured count.

Accepted, not mitigated: G7 (the shared `trackernest` package/jar name,
§7). Every other risk has a concrete fix or verification step.

## 4. Navigability acceptance test (designed now; one crawl per app)

A new module, `tests/test_labgen_spring_boot_navigability_live_boot.py`,
parametrized over `trackernest`/`netflix`/`expedia`. It uses a module-scoped
app-mode harness per app (separate builds and ports, one per future compose
service) and mirrors `tests/test_labgen_django_navigability_live_boot.py`.
For each app:

1. Boot the app (§2d) and crawl from `/` with `LocalSpider` (`requests`
   engine, same-host scope, `trust_env = False`). Set the depth cap after
   measuring the real depth.
2. **Non-vacuous guards first:** hard-coded minimum GT counts (3, 11, 2)
   and measured minimum crawled-page counts.
3. Every GT URL is discovered, and returns the anonymous status fixed here:

   | App | Anonymous status per GT URL |
   |---|---|
   | TrackerNest | `/wiki/pages/render` 200 (form); `/issues/import` 200 and `/integrations/webhook-payload` 200 (client pages) |
   | Netflix | the 8 POST apis 200 (client pages); `/api/account/billing` 400; `/api/account/preferences` 401; `/api/support/template-preview` 400 |
   | Expedia | `/api/hotels/search-sort` 200 (default); `/api/trips/restore` 200 (client page) |

4. `GET /` returns 200 `text/html`.
5. Every catalog entry that a `GET` can open is link-reachable.
6. **The PA-0054/PA-0056 route-enumerated sweep**, independent of the crawl.
   It covers every served route from `served_url_for(…, site_build=True)`
   plus the site routes. Each route gets:
   - a bare request with its **own method** (empty body, no query, no
     headers);
   - a bare `GET`.

   Each response must equal the §2e declared status on **both twins**. Every
   `≥500` fails, and so does every undeclared status. The count of routes
   swept must equal the number of cells plus the number of site routes.
7. Layout byte-identity: the layout region of the vulnerable and secure
   twin pages (and of every page in the app) is byte-identical.
8. Strict-xfail pins for the flagged different-class findings: S2 (1 test)
   and S6 (2 tests). Each names its follow-up.

## 5. Sequencing (named gates)

0. **Done in Phase 1:** the live pre-scan baseline (§1.6).
1. **Shared infrastructure, offline:**
   - `app_site.py` registry;
   - route-profile keys;
   - `served_url_for` and the `site_build` flag;
   - `SiteLayout.java` in the skeleton;
   - offline tests for S1, S7 (digit rule), S8, S9, S11 and S12's
     scaffolding, and the §2f `body_content_type` pin;
   - the S15 cross-emitter declaration module
     (`tests/test_absent_input_declarations_cross_emitter.py`), with
     `spring_boot`'s case expected to fail until step 2 lands. It is
     written first so that its failure is observed.

   **Gate:** the offline suite is green, and one existing single-cell
   live-boot suite (`test_labgen_spring_boot_live_boot.py`) is green, which
   shows the skeleton still compiles.
2. **§2e guards, one source module at a time.**

   **Gate per module:** a bare request with the route's own method returns
   the declared status on both twins (live), and that module's existing
   live-boot suites are green.

   This is also where **the bug protocol for the two crashes starts**: the
   ERROR_LOG line and the BUG-0054 draft, while the evidence is fresh.

   **Before/after evidence (review round 1, recommended item 3):**
   - The §4 step 6 own-method sweep, as a pytest function, is written
     **first**.
   - Its failing output is captured against the pre-fix emitter: avatar
     500 on both twins, thumbnail-import 502 on the vulnerable twin, and
     every other undeclared status.
   - It is then re-run passing post-fix.
   - Both runs (command, commit, per-route status table) are pasted into
     BUG-0054's "Where encountered" and "Corrective action" sections, so the
     check is demonstrated able to fail, not only seen passing (PA-0008).
3. **§2b page conversion of `/wiki/pages/render`.** **Gate:** T1's checks,
   plus the TrackerNest multitarget recall unchanged (2/3).
4. **§2c/§2d site layer and app-mode harness, one app at a time**
   (TrackerNest, then Expedia, then Netflix). **Gate per app:** boot,
   `GET /` 200, and every nav link 200.
5. **§4 navigability module, all three apps.**

   **Scope-creep rule** (restated from `CC-LAB-0241`/`CC-LAB-0242`): a
   crawl-surfaced defect is folded in only if it is the *same class* as this
   plan's tracked work and touches only the `spring_boot` emitter or
   skeleton or its harness. Same class here means:
   - a missing nav link;
   - a missing absent-input declaration or guard;
   - a page outside the layout.

   Anything else becomes a named follow-up with a strict-xfail pin, and
   the next `CC-LAB` number is allocated by the orchestrator.
6. **Full non-slow suite, plus every `spring_boot` live-boot suite (§1.7)
   and the new navigability module**, all green, with counts recorded.
7. **Bookkeeping:** the bug protocol completed (§6), `FR-LAB-164`/`165`,
   `CHANGELOG.md`, the `CC-LAB-0244` Deliverables/Effectiveness, and the
   lane-table row.

## 6. Deliverables checklist

- [ ] `app_site.py` registry and route-profile keys (`app`/`classification`/`absent_input`), with the offline cross-check (S11).
- [ ] `SiteLayout.java` (skeleton) and `page_handler.java.j2`. `/wiki/pages/render` converted (T1). Sink templates untouched (S8).
- [ ] `render_site` (home, catalog, 15 client pages across the 3 apps) and `site_build`/`served_url_for` twin URLs (S1). `assemble_spring_boot_app` made public for Lane 7.
- [ ] App mode in `SpringBootLiveBootHarness` (additive).
- [ ] §2e guards on every route, the offline declaration check (every route, every channel), and the twin-identity check (S9).
- [ ] The `form_when_absent` decision rule applied, with the branch recorded as a sign-off in `FR-LAB-165`.
- [ ] The §2f `body_content_type` pin (no GT edits).
- [ ] The navigability module, green for all 3 apps, including the own-method bare sweep and the strict-xfail pins (S2, S6).
- [ ] Every existing `spring_boot` live-boot and multitarget suite green. SSTI recall unchanged.
- [ ] Full non-slow suite green, with counts recorded.
- [ ] **Bug protocol, BUG-0054/PA-0056** (the crashes are already reproduced, so this is expected, not contingent):
  - `ERROR_LOG.md` line;
  - `docs/bugs/BUG-0054-*.md`: full RCA, Five Whys, and a recurrence review against `BUG-0051`/`PA-0053` and `BUG-0052`/`PA-0054` with a prior-PA failure analysis (S4's three failure modes);
  - `PA-0056`, strengthening PA-0054 on input channels, request method and pin-now;
  - the PA-0002 sweep: `spring_boot` fixed in full, plus **every other emitter pinned by this lane** via `tests/test_absent_input_declarations_cross_emitter.py` (S15). Strict-xfail cases for `go_net_http`/`ruby_rails`/`node_express`/`python_fastapi`/`php_current` name their owning lane; the `php_laravel` case follows S15's decision rule. There is no prose deferral;
  - before/after sweep evidence (failing pre-fix, passing post-fix) captured in BUG-0054 (§5 step 2).
- [ ] `docs/components/01-target-lab/requirements.md`: `FR-LAB-164` (browsable site) and `FR-LAB-165` (absent-input contract, including the `form_when_absent` sign-off).
- [ ] `CHANGELOG.md`: one dated line referencing `CC-LAB-0244` (and `BUG-0054`).
- [ ] **`docs/ARCHITECTURE.md` updated (unconditional; review round 1, adequacy fix 2).** The harness app mode, the public `assemble_spring_boot_app`, the `render_site` site-layer generator, `SiteLayout.java` and the `site_build` twin-URL derivation are structural additions by `CLAUDE.md`'s own test. Two edits:
  - amend the manifest-driven-generator status line's `spring_boot` clause (`ARCHITECTURE.md:162`) to say that all three `spring_boot` apps are browsable;
  - add a "TrackerNest, Netflix clone and Expedia clone are browsable (`CC-LAB-0244`, Browsable Labs Lane 4)" paragraph next to Lane 2's "PicTrail is browsable (`CC-LAB-0242`)" paragraph (`ARCHITECTURE.md:918`). It names the new harness API, the site layer, the twin-URL rule and the cross-emitter absent-input check.
- [ ] `docs/LAB_BROWSABLE_APPS_PLAN.md`: Lane 4 row updated.

## 7. Out of scope

- Compose services, ports 8087-8089, the `labctl` profile and the
  cross-app run: these are Lane 7. This lane only makes
  `assemble_spring_boot_app` public for it.
- Renaming the shared `com.fuzzlab.trackernest` package or the
  `trackernest.jar` name (G7). Invisible to a visitor, and it would touch
  every emitted file and test.
- Fixing S2 (api Content-Type negotiation) and S6 (malformed-JSON 500s).
  Both are flagged and pinned.
- A detector for Java-native `ObjectInputStream` deserialization
  (`TNEST-0003`'s existing, honest false negative).
- Lanes 3, 5, 6 and 7, and the other emitters.

## 8. Review history

**Round 1 (accuracy + adequacy, 2026-09-25): ACCURATE / ADEQUATE contingent
on 2 fixes, plus 1 recommended item.**

- **Who ran it:** the orchestrating session's own two reviewer agents,
  since this lane has no agent-spawning tool (see "Original blocker note"
  below).
- **Accuracy (ACCURATE, no inaccuracies).** The reviewer booted the harness
  live and independently reproduced:
  - the twin collision (`BeanCreationException: Ambiguous mapping` when
    `LABGEN-SSTI-0001`/`0002` are booted together);
  - both crashes (avatar bare-`POST` 500 on both twins; thumbnail-import
    502 on the vulnerable twin and 403 on the secure twin);
  - S2 (an unescaped `200 text/html` reflection under a browser `Accept`);
  - S6 (malformed JSON returns 500 on both twins).
- **Adequacy** raised 3 items; all are fixed in this revision:
  1. **The PA-0002 sweep across other emitters was a soft deferral** to the
     orchestrator: the exact BUG-0052 failure mode this plan diagnoses.
     - Fixed by new risk item **S15**. I verified directly that no pin
       exists today for `go_net_http`/`ruby_rails`/`node_express`/
       `python_fastapi`/`php_current`.
     - This lane now adds the offline cross-emitter declaration check
       itself, with strict xfails naming each owning lane, plus a
       decision rule for concurrent-lane merges and for `php_laravel`.
       `php_laravel` is not assumed to pass: its coverage was found
       unverified.
     - §6 is updated to match.
  2. **The `docs/ARCHITECTURE.md` update was left undecided.** It is now an
     unconditional §6 deliverable, with both concrete edit sites named
     (`:162`, and beside `:918`).
  3. *(Recommended, non-blocking)* **Before/after sweep evidence.** Added to
     §5 step 2 and §6: the own-method sweep is written first, shown failing
     pre-fix and passing post-fix, and both runs are captured in BUG-0054.
- **The adequacy reviewer also decided the draft's one open design
  question:** `form_when_absent` is **accepted** for `/wiki/pages/render`
  (§2e, now recorded as decided, with the FR-LAB-165 sign-off).
- **Round 2 is pending.** The same two reviewers are to confirm through the
  orchestrator. 3/3 agreement is not yet claimed.

**Original blocker note (draft, 2026-09-25), kept for the record:**

- The lane instructions require two independent reviewer sub-agents
  (accuracy and adequacy), spawned with the lane's own agent tool.
- This sub-agent's toolset contains **no agent-spawning tool**. Only
  `SendMessage`/`TaskStop` exist, and neither can create a reviewer.
- Remote-session creation is not a substitute either: a fresh cloud session
  can't see this unpushed worktree, and pushing is forbidden for this lane.
- Per `docs/MULTI_AGENT_ORCHESTRATION.md` §4 (stop and flag rather than
  silently substitute) and the instruction never to fabricate a reviewer's
  agreement, **no review has taken place, and no agreement is claimed**.
- The plan stops here pending the orchestrator's decision. The options are:
  - dispatch the two reviewers itself against this committed draft;
  - re-dispatch this lane with an agent-spawning tool available.
