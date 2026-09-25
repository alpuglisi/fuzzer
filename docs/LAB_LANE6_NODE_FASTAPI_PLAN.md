# Browsable Labs Lane 6 — node_express: MeadowMart + python_fastapi generic sample

Status: **DRAFT — plan written, review gate NOT yet run** (2026-09-25).
Reserved numbers per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table:
`CC-LAB-0246` / `FR-LAB-168-169` / `CC-FUZZ-0052` / `FR-FUZZ-36` /
`BUG-0056` / `PA-0058`. None has been used yet.

**Why the gate has not run.** The lane brief says to review this plan with
2 independent reviewer subagents (accuracy and adequacy) spawned through
the proposing agent's own Agent tool. That tool is not available in the
session that wrote this draft. `ToolSearch` found no `Agent`/`Task` tool.
`docs/MULTI_AGENT_ORCHESTRATION.md` §4 says to stop and flag when a
specified mechanism is missing, not to substitute another one silently.
So this draft has **not** been reviewed. §8 records no review rounds, and
this plan does not yet authorize a change-control entry or any
implementation. The orchestrator must run the 2-reviewer gate itself, or
explicitly approve a different reviewer mechanism.

## 0. Lessons from Lanes 1–2, applied from the start

- **The navigability test is specified before any conversion** (§4), with
  PA-0054's two checks built into it from the start: an offline check that
  every route declares its absent-input behavior, and a live bare-request
  sweep of every route the build serves. Lane 2's §0 said honestly that
  its crawl still *ran* last. This plan does the same, but the offline
  absent-input check (§5 step 1) is the *first* gate, before any site or
  page work. That is the part PA-0054 added after Lane 2 ran its crawl last.
- **Scope was confirmed by reading the code and probing live**, not by
  analogy with Lane 1 or 2. Every claim in §1 cites a file, a line, or a
  probe result. The probes were run on 2026-09-25 against a scratch
  assembly of this worktree's current emitters, not the repo's test
  fixtures (see §1d).
- **Two different targets are kept apart throughout.** MeadowMart is a real
  app identity with ground truth, so it gets the full treatment (§1a/§2A/§3A/§4A).
  The `python_fastapi` sample has **no** identity and **no** ground truth,
  so it gets only a homepage and layout (§1b/§2B/§3B/§4B). A third group,
  the `node_express` generic Tier-A sample cells (`LABGEN-NE-*`), is
  covered by the same emitter's offline check but is **not** part of
  MeadowMart (§1c). Each risk in §3 names the target it applies to.
- **Candidate defects were found during planning, not at the end.** The
  PA-0053 bug class (a bare request crashes a route) is already confirmed in
  `python_fastapi` and in the `node_express` Tier-A sample (§1d). §6 records
  the bug protocol as a planned deliverable, not an if-needed contingency.

## 1. Scope — what already exists (confirmed by reading the code and probing)

### 1a. MeadowMart (`node_express`)

- **MeadowMart already exists as a named identity** (`CC-LAB-0077`). It has
  its own ground truth (`lab/ground-truth-meadowmart/`: 4 points / 4 cases,
  `MMART-0001`–`0004`) and 2 manifests
  (`lab/manifests/prototype_pollution_node_sample.yaml`,
  `lab/manifests/redos_node_sample.yaml`: 4 cells, `LABGEN-PP-0001/0002`,
  `LABGEN-RD-0001/0002`). It is not merged into another app, so **no
  `--app` split is needed**.
- **MeadowMart's build is exactly those 2 manifests.** All 3 existing live
  fixtures build it from exactly these files:
  `tests/test_labgen_node_bff_app.py:175`,
  `tests/test_labgen_node_bff_multitarget.py:113`, and `tests/test_multitarget_category1_combined.py:109` (the MeadowMart half)
  of `tests/test_multitarget_category1_combined.py`. The generic Tier-A
  sample (`lab/manifests/phase3_node_express_sample.yaml`, `LABGEN-NE-0001`–`0008`)
  is **not** part of MeadowMart (see §1c).
- **Every MeadowMart ground-truth URL is a backend-for-frontend (BFF)
  `/api/*` URL.**
  `docs/LAB_BROWSABLE_APPS_PLAN.md`'s page-vs-api refinement names
  "MeadowMart's backend-for-frontend `/api/*`" as a genuine API family.
  The emitter's own module docstring (`node_express/__init__.py:34-65`)
  grounds the identity in real Walmart research: a Node/Express layer that
  aggregates legacy services for a frontend. Confirmed by reading:
  - `/api/preferences` (POST, whole JSON body): sink
    `object_property_bulk_set.js.j2` → `res.json({ preferences: ... })`.
  - `/api/search` (GET `q`): sink `regex_highlight_match.js.j2` →
    `res.send(content.replace(regex, '<mark>$&</mark>'))`. This is a string
    body, sent as `text/html` by Express's default, with the fixed product
    copy plus `<mark>` tags.
  - Twins are served at `/api/preferences-twin-labgen-pp-0002` and
    `/api/search-twin-labgen-rd-0002` (`_twin_url_for`, `__init__.py:227`).
    Both twins already coexist in one `app.js`. This differs from
    `python_fastapi` (§1b), whose twins share a path.
- **Three inert BFF routes are always included** (`_INERT_ROUTES_JS`,
  `__init__.py:257-286`): `GET /api/products`, `GET /api/orders/:orderId`,
  `GET /api/cart`. All three return static JSON, have no manifest cell and
  no ground-truth case, and read no input.
- **No homepage, no layout, no HTML page of any kind.** Probe: `GET /` →
  404 (Express's default "Cannot GET"). Every response is JSON or the bare
  `/api/search` string.
- **No login, no session, no session-gated cell** in the `node_express`
  emitter. It has no `IdentitySessionStore` use and no cookie handling, so
  the R8 401 exception in `docs/LAB_BROWSABLE_APPS_PLAN.md` point 6 does not
  apply.
- **Page vs. api classification** (the lane contract requires a
  justification for each `api`):
  - `/api/preferences` → **api**. It is the BFF's account/cart-preferences
    endpoint, and a real storefront frontend calls it with a JSON body.
    Its GT `rendering` is already `server-json`, which is what
    `fuzzlab/harness/auto.py:86-96` needs in order to send the
    `__proto__`-keyed body as JSON. Re-rendering it as HTML would break
    how the request is encoded. It gets a client page.
  - `/api/search` → **api**. It is the BFF's search/highlight endpoint,
    which the frontend fetches to render highlighted results. The
    contract's "when unsure, choose `page`" rule does not apply, because
    the contract itself names this `/api/*` family as the example of a
    genuine API. It gets a client page. Its wire contract (status, body
    bytes for a present `q`, content type) is unchanged. The only new
    behavior is the absent-input rule in §2A-d.
  - The 3 inert routes → **api** (same BFF family). Each gets a client
    page.
  - So **MeadowMart has no `page`-classified endpoint**. The conversion
    work is a site layer plus client pages, not JSON→HTML re-rendering.
    This is a real difference from Lanes 1–2, stated plainly so a reviewer
    can challenge the classification rather than find it buried.
- **Ground truth `rendering`**: `/api/preferences` is `server-json` and
  correct. `/api/search` is `server`, which to `auto.py` only means
  "not JSON-encoded". For a GET query parameter that is correct and
  unaffected. **No ground-truth change is needed** because no wire contract
  changes (§2A-f).
- **Detection mechanisms that touch these cells** (named, as Lane 2's R6
  did):
  1. `RegexDosStrategy` (`fuzzlab/oracle/strategies.py:692`)
     works on timing only. It uses the non-empty benign probe
     `"ordinary-search-term"` plus templates, and never reads the body format.
  2. Prototype pollution has **no** in-band runtime strategy. The
     `test_labgen_node_bff_multitarget.py` module docstring says
     `prototype_pollution`/`redos` are unmapped in `_VULN_TO_CATEGORY`, so
     recall is honestly 0. Its proof is the Node-subprocess test in
     `tests/test_labgen_prototype_pollution.py`, which is unaffected.
  3. There is no build-time body-diff oracle for these shapes, and nothing
     like `identifier_sqli_oracle.py`.
  → No CC-FUZZ change is expected. `CC-FUZZ-0052`/`FR-FUZZ-36` stay unused
  unless implementation disproves this (§3A R9).
- **Live boot is available in this environment.** It was confirmed on
  2026-09-25: `node` v22.22.2 and `npm` are at `/opt/node22/bin`, and the npm
  registry is reachable. `tests/test_labgen_node_bff_app.py`,
  `tests/test_labgen_node_bff_multitarget.py` and
  `tests/test_labgen_python_fastapi_sample.py` gave **43 passed, 0 skipped**.

### 1b. `python_fastapi` generic sample (no identity, no ground truth)

- **Cell inventory** (`lab/manifests/phase3_python_fastapi_sample.yaml`): 6
  cells, `LABGEN-PY-0001`–`0006`. They cover 3 synthetic routes: `/products`
  (GET `id`, numeric SQLi pair), `/login` (POST form `username`/`password`,
  string SQLi pair), and `/profile` (GET, stored-field XSS pair). There is
  **no ground truth directory** (`grep -ri fastapi lab/ground-truth*` finds
  nothing), and the emitter docstring (`python_fastapi/__init__.py:19-22`)
  calls these "illustrative synthetic routes", not a real app. That matches
  `docs/LAB_BROWSABLE_APPS_PLAN.md`: "no app identity and no ground
  truth … a homepage and layout, but no port". **So this lane does not
  give the sample an identity, realistic URLs, a ground truth, or a port.**
- **Current responses**: `/products` and `/login` return JSON
  (`complexities/single_statement.py.j2`: `return dict(row) if row else {}`).
  `/profile` returns a bare `<div class="bio">…</div>` fragment
  (`sinks/html_body_echo.py.j2`).
- **Serving model**: there is no route accumulator. `app/main.py`
  (`templates/scaffold/main.py.j2`) walks `app/routers/` sorted by module
  name and calls `include_router()` on each. `render_scaffold_files()` takes
  **no cell list**, so the scaffold cannot see which cells a build contains.
- **The "live" check is in-process only.**
  `tests/test_labgen_python_fastapi_sample.py:182` runs FastAPI's
  `TestClient` against the generated tree, and is not a socket boot.
  FastAPI 0.141.1, SQLAlchemy and httpx are installed here, so this test
  runs (it does not skip).
- **Probe (2026-09-25, TestClient, `raise_server_exceptions=False`)**:
  `GET /` → 404; **`GET /products` → 500**; `GET /products?id=` → 500;
  `GET /login` → 405; `POST /login` with an empty body → 200 `{}`;
  `GET /profile` → 200 bare fragment.
- **The twins share one path.** Both cells of a pair are decorated with
  `cell.route.path` (`__init__.py:198`), and the first-sorted module wins.
  So each secure twin (`PY-0002/0004/0006`) is **unreachable** in the
  whole-app build. This predates this lane and is not a browsability defect
  (see §7, F3).
- **There is no leakage/fingerprint gate over this sample's HTTP
  responses.** The chi-square fingerprint gate
  (`fuzzlab/labgen/fingerprint_gate.py`) runs over manifest corpus records
  via `fuzzlab lab-generate --check`, whose `EMITTER_REGISTRY`
  (`fuzzlab/labgen/cli.py:65`) holds only `php_current`/`php_laravel`. It
  never reads response bytes. The only byte-level twin contract that
  applies is the **minimal-pair checker** (`fuzzlab/labgen/minimal_pair.py`,
  run by `tests/test_labgen_python_fastapi_conformance.py::test_tier0_minimal_pair_diff_confirms_each_declared_pair`):
  vulnerable and secure twins may differ only in the transform/sink region.
  §3B's R-B1 is written against that contract.

### 1c. `node_express` generic Tier-A sample (`LABGEN-NE-*`) — not part of MeadowMart

- 8 cells on `/api/products` (SQLi), `/api/posts` (SQLi), `/api/login`
  (POST SQLi) and `/api/profile` (stored XSS). They are served at
  `/generated/labgen-ne-000N` (`_served_url_for`, `__init__.py:238`). Tests
  cover them only at Tiers 0 and 3
  (`tests/test_labgen_node_express{,_conformance}.py`). The conformance
  module docstring says Tiers 1 and 2 "need … a real database this
  environment does not have". **No live build serves them**, and no ground
  truth covers them.
- They still fall under **PA-0054 (1)**: "every emitter's route profile
  must declare each named request parameter's absent-input behavior …
  checked offline over every route the emitter's manifests produce". So the
  offline check (§2A-d) covers them, and their undeclared defaults are fixed
  in the same step (§2A-d).

### 1d. Candidate defects found during planning (evidence)

Probes ran on 2026-09-25 against a scratch assembly of all 12
`node_express` cells built with this worktree's emitter (`npm install`,
then `node app.js` on loopback), and against the `python_fastapi` sample
through `TestClient`:

| # | Where | Bare request | Result | Class |
|---|---|---|---|---|
| D1 | `python_fastapi` `/products` (`PY-0001`, vulnerable) | `GET /products` | **500** (`str(None)` → `WHERE id = None`, SQLite `OperationalError`) | **PA-0053 absent-input**, same as BUG-0051/0052 |
| D2 | `node_express` `/generated/labgen-ne-0001` (`/api/products`) | `GET` | **Node process exits, rc=1** (the SQL `… = undefined`, then an unhandled rejection in an `async` Express 4 handler; Node 22's default `--unhandled-rejections=throw` kills the process) | absent-input (**same class**) *combined with* F2 (different class, see §7) |
| D3 | `node_express` `/api/search` (MeadowMart, `RD-0001`) | `GET /api/search` | 200, `<mark></mark>` between **every character** (`new RegExp(undefined)` = the empty pattern); the secure twin returns 200 plain content (`escapeRegExp(undefined)` = `"undefined"`, so no match) | **undeclared** absent-input that differs between the twins (a PA-0054 (1) violation, not a crash) |
| D4 | `node_express` `/api/login` secure twin (`NE-0006`) | `POST` with no `username` | *suspected, not yet probed*: `mysql2` rejects an `undefined` bind value | same class. Verify at §5 step 1 before claiming it |
| F1 | `node_express` `/generated/labgen-ne-0007` (`/api/profile`) | `GET` | **500** on every request (`currentUser` is never defined, so `ReferenceError`) | **different class** (a render-context identifier with no definition) |

Other live results from the same probe, for reference: `GET /` → 404,
`GET /api/preferences` → 404 (POST-only), `POST /api/preferences` with an
empty body → 200 (the merge of `{}` does nothing), `GET /api/products`
(the inert route) → 200, `GET /api/search?q=(` → 500 (the vulnerable
twin's own regex syntax error. This is expected behavior for that twin,
not an absent-input case).

D1 alone is a live-reproducible code defect of exactly the PA-0053 class,
so **the bug protocol runs with `BUG-0056`/`PA-0058`** (§6). D2's
absent-input half and D3/D4 go in the same bug report as further instances
found by the PA-0002 sweep. F1 and F2 are different classes and are
flagged, not absorbed (§7).

## 2. Fix design

### 2A. MeadowMart

**2A-a. A shared layout and site layer in a new scaffold file,
`scaffold/site.js`.** This file is checked in, rendered once per stack, and
not generated per cell. It is picked up automatically as a scaffold file by
`stack_env._load_scaffold_files()`, which walks the directory. It exports
`register(app, catalog)`, which:
- defines `layout(title, bodyHtml)`: a header with the name "MeadowMart"
  and nav, then main, then a footer, all with inline CSS and no external
  assets. Nav links are sorted by path, per the design contract's
  determinism rule.
- registers the site routes (listed in **`_SITE_ROUTES`**, a Python tuple
  in `node_express/__init__.py` that is the single source of truth for the
  test, kept in step with `site.js` by an offline drift check, §4A):
  - `GET /`: homepage with a short description of the storefront and links
    to every site page.
  - `GET /products`, `GET /cart`, `GET /orders` (track an order),
    `GET /search`, `GET /account/preferences`: **client pages** for the BFF
    APIs (§2A-b).
  - `GET /catalog`: the "API endpoints" developer page. It lists, with
    `<a href>` links, every endpoint the build serves: each cell's served
    URL (canonical and twin, from `_served_url_for`) and each inert API
    route. This follows the design contract's point 5 (a `/catalog` page)
    and Lane 2's precedent (twins listed in `/catalog`).

`app.js` (the accumulator) adds exactly one line:
`require('./site').register(app, <catalog array>)`. The catalog array is
built in Python from the same `supported`/`by_id` list the route lines
already use, so it stays sorted and deterministic. **No cell controller
calls `layout()`**, because every MeadowMart cell is `api` (§1a). So the
responses of the vulnerable and secure twins are exactly as they are today,
and the contract's "layout byte-identical across twins" point holds
trivially: no twin response contains the layout at all.

**2A-b. Client pages** (the design contract's "API client page" pattern:
a small inline `fetch()`, the way a real frontend calls its BFF):
- `/search`: a form with a `q` field. `fetch('/api/search?q=' +
  encodeURIComponent(q))` fills a results `<div>`. Also shows "Popular
  searches" links that fill in the field.
- `/account/preferences`: shows the current preferences from `GET
  /api/preferences` (§2A-c), and a theme `<select>` plus a notifications
  checkbox that are sent with `fetch(..., {method: 'POST', headers:
  {'Content-Type': 'application/json'}, body: JSON.stringify(...)})` to
  `/api/preferences`, the canonical URL only. The real frontend calls the
  real URL; twins appear only in `/catalog`.
- `/products`, `/cart`, `/orders`: `fetch` the matching inert API and
  render it with `textContent`/`createElement` only. `/orders` has an
  order-ID input and fetches `/api/orders/<encodeURIComponent(id)>`.

**2A-c. `GET` on the preferences resource.** The ground-truth URLs
`/api/preferences` and its twin are POST-only today (a probe of `GET` gets
404). Point 6 of the contract requires each ground-truth URL to answer an
anonymous visitor with a real response. The `requests`-engine spider only
follows `<a href>` (`fuzzlab/tools/spider.py`, `_fetch_static`) and
`fetch()` targets are captured only by the Playwright engine, which the
contract rules out as a discoverability exercise (D-open-1). **Decision:**
every served URL of a route whose profile declares
`get_resource_literal` gets a **site-layer `GET` handler** that returns
the route's default resource, `res.json({ preferences: <target_literal> })`,
built from the same `target_literal` already in `_ROUTE_PARAMS`.
- The handler is registered in `app.js`, twin-identical, and reads no input.
- **Why:** a real BFF preferences resource supports both GET (read) and POST
  (update), so this is the realistic shape.
- **The POST contract is untouched**, because the GET handler is a separate
  method on the same path.

The fallback rule for this choice is under R3.

**2A-d. Absent-input declarations (PA-0053/PA-0054, decided here).**
These mirror Lane 2's key names exactly (`django/__init__.py:225-240`), so
every emitter uses one vocabulary. Each route profile in `_ROUTE_PARAMS`
declares its absent-input behavior according to the kind of source it
uses:

| Route (cells) | Source | Declaration | Rendered (identical on both twins) |
|---|---|---|---|
| `/api/search` (RD-0001/0002, MeadowMart) | `get_query_param` | `required_param` | `if (!searchTerm) { return res.status(400).json({ error: 'missing required parameter: q' }); }` placed before the transform |
| `/api/products`, `/api/posts` (NE-0001–0004) | `get_query_param` | `default_value: "1"` | `const id = req.query.id \|\| '1';` (the same `or`-semantics as Lane 2's `request.GET.get(...) or "1"`, and Lane 1's `?? '1'`) |
| `/api/login` (NE-0005/0006) | `post_body_param` | `required_param` | the same 400 guard before the transform (no safe default username exists; this also closes D4) |
| `/api/preferences` (PP-0001/0002, MeadowMart) | `post_body_json` (whole body) | *(no key; the source kind itself is the declaration)* | an absent or empty body parses to `{}` (body-parser), the merge does nothing, and the response is 200 with the defaults (probe-confirmed). The offline check asserts that neither key is present and that this source kind is on the whole-body allowlist |
| `/api/profile` (NE-0007/0008) | `read_stored_field` | *(no request input)* | not applicable. F1 (`currentUser` undefined) is a different class, see §7 |

- The guard or default lives in the **source** template region, identical
  on both twins apart from the handler identifier. So every minimal pair
  still differs only in its transform/sink region (BUG-0027; checked by
  §5 step 1's gate).
- For `/api/search`, a 400 before the sink is the right choice rather than
  a default. With `q=''`, both twins would mark every character position,
  and nothing on this page gives a meaningful default search term. This
  mirrors Lane 2's R4 decision for its single `api`
  (`/upload/link-preview`).
- `RegexDosStrategy` never sends an empty value (§1a), so detection is
  unaffected. §4A still re-runs it live.

**2A-e. Fixtures.** `app.js` will now `require('./site')`. The 3 existing
live fixtures copy only `package.json`/`db.js`
(`test_labgen_node_bff_app.py:171`, `test_labgen_node_bff_multitarget.py:109`,
`test_multitarget_category1_combined.py:105`), so they would fail to boot. They are changed to
copy every file in a new emitter constant, `RUNTIME_SCAFFOLD_FILES =
("db.js", "package.json", "site.js")`, so the next scaffold file added
cannot silently break them again. A shared helper, `tests/_meadowmart_app.py`
(mirroring Lane 2's `tests/_django_site.py`), assembles and boots the app
for the new navigability module. The 3 existing modules are changed only
at their copy loop, not rewritten.

**2A-f. Ground truth.** No change to URL, method, param, location,
`rendering` or `vuln_class`. Only the `notes` fields of `MMART-0001`–`0004`
get one sentence each naming the client page and `/catalog` that link the
endpoint, so the ground truth documents how each point is reached. If a
reviewer thinks editing `notes` is unnecessary churn, it is dropped. It
carries no semantics.

### 2B. `python_fastapi` sample (homepage and layout only)

**2B-a. A new scaffold file, `app/site.py`**, from a new template
`templates/scaffold/site.py.j2`, rendered by `render_scaffold_files()`. It
contains:
- `layout(title, body_html) -> str`: header ("fuzzlab FastAPI sample" plus
  nav), main, footer, inline CSS. It is byte-identical wherever it is used.
- `router`, with `GET /` (a homepage listing every sample route) and a
  **GET form page for each POST route** (only `/login` today: fields
  `username`/`password`, `action="/login" method="post"`, no CSRF token,
  because the sample has none. This follows contract point 4: forms neither
  add nor remove protection).
- The route table the homepage and forms are built from is **rendered
  statically from `_PAGE_PARAMS`**, with new render-only keys: `method`,
  `nav_label`, and `form_fields` for POST routes. It is not built by
  looking at `app.routes` at runtime (R-B3).

`main.py.j2` adds `from . import site` and
`application.include_router(site.router)` **after**
`_discover_and_include_routers(app)`. There is no overlap: the site router
adds only `GET /` and `GET /login`, and the cells register `GET /products`,
`POST /login` and `GET /profile`.

**2B-b. Cell responses are rendered inside the layout.** This follows
contract point 5's rule for generic cells: keep their paths, render inside
the layout, and link them from a listing page (here the homepage).
- `/profile` (`sinks/html_body_echo.py.j2`): `return HTMLResponse(content=
  layout("Profile", html_fragment))`. The `<div class="bio">{{ value }}</div>`
  fragment is unchanged, so the value stays in the HTML body and the sink
  context is kept (point 3).
- `/products` and `/login` (`complexities/single_statement.py.j2`): the
  JSON tail is replaced with an HTML detail view in the layout. A found row
  becomes an `html.escape`-d `<table>` of its columns. A missing row
  becomes a short "No matching record." paragraph. The difference between
  found and not-found is kept (R-B2).
- The header gains one line, `from ..site import layout`, identical in every
  cell file.

**2B-c. Absent-input declarations** (the same vocabulary as §2A-d):
- `/products`: `default_value: "1"` →
  `request.query_params.get("id") or "1"`. This fixes **D1**.
- `/login`: `required_param` → the 400 guard before the transform.
- `/profile`: no request input.

The offline check (§4B) covers all 3 routes.

**2B-d. Not done here** (this is what keeps FastAPI narrower): no app
identity or branding beyond a generic sample name, no realistic-URL work,
no ground truth, no port, no spider crawl (§4B explains why), and no fix
for the twin path collision (F3, §7).

## 3. Risk register

### 3A. MeadowMart (and the `node_express` emitter as a whole)

**R1 — The page-vs-api classification is the lane's main judgment call.**
Classifying all 5 MeadowMart endpoints as `api` means no endpoint is
converted to HTML, which a reviewer might read as dodging the conversion.
**Decision rule:** keep `api` for all of them, because the contract names
this family and the JSON-body encoding of `/api/preferences` depends on
`server-json` (§1a). Reclassify `/api/search` as `page` **only if** the
gate's reviewers conclude it models a server-rendered search page rather
than a BFF endpoint. In that case its conversion must keep the response
bytes for a present `q` inside the layout's `<main>` unchanged, and re-prove
`RegexDosStrategy` live (R9). That outcome would be a plan revision, not an
implementation-time choice.

**R2 — The site layer could become a prototype-pollution gadget.** After
the vulnerable `/api/preferences` POST pollutes `Object.prototype` in the
single running process, any site code that iterates with `for…in`, or reads
an optional property off a plain object (`opts.x`), would change its output.
That would add an in-band signal the lab never modelled, changing the
cell's detectability without being called out (contract point 3). **Rule:**
- `site.js` uses only arrays and literal markup: no `for…in`, no
  options-object property reads, no `Object.assign` of request data.
- It is enforced **offline** by a test that scans `site.js` for `for (… in`
  and `Object.assign(`.
- It is enforced **live** by a dedicated boot that captures the bytes of
  `/`, `/catalog` and every client page, then POSTs
  `{"__proto__": {"mmProbe": "x"}}` to the vulnerable URL, then re-fetches
  them. The bytes must be identical, and there must be no 5xx.
- This boot is separate, so the pollution cannot leak into other tests.

**R3 — The `GET /api/preferences` handler (§2A-c) changes how the endpoint
looks from outside.** **Decision rule:** use branch (a), the GET resource
read. Fall back to branch (b), Lane 1's pattern of serving the HTML client
page from a GET on the API URL itself, only if one of these holds:
- the gate reviewers judge that a GET resource read misrepresents the
  modelled BFF, or
- implementation finds that `auto.py`/`points_from_ground_truth` or the
  multitarget run sends a GET to a POST-only ground-truth URL and scores
  its response.

Whichever branch is used is recorded as an explicit **"R3 sign-off"** in
`FR-LAB-168`, the way `CC-LAB-0241`'s R4 sign-off was recorded.

**R4 — The new absent-input guard or default must not break the
minimal-pair contract or existing tests.** Several existing tests assert
exact template output:
- `tests/test_labgen_node_express_modules.py:34` asserts that
  `"req.query.id" in` the code. That is still true with `|| '1'`.
- `:52` asserts that the `read_stored_field` output is exactly
  `const bio = currentUser.bio;`. That is unchanged, because the source
  does not change.
- `:131` and `:159` cover the sink and route lines, which are unchanged.
- The `node --check` tests in `test_labgen_redos.py:255` and
  `test_labgen_node_express.py` are re-run.

**Rule:** after §5 step 1, run
`tests/test_labgen_node_express*.py`, `test_labgen_redos.py` and
`test_labgen_prototype_pollution.py`, plus a new offline test asserting
that the lines carrying the guard or default are identical on both twins
of every route. This is the same kind of test as Lane 2's
`test_absent_input_lines_are_identical_on_both_twins`. Any other
exact-string assertion that breaks gets updated only if its intent (what
the source reads) is unchanged, and each such update is listed in the
change-control entry.

**R5 — Name-leak scanner.** `site.js` and the generated `app.js` must not
contain any term on the vulnerability-class denylist
(`fuzzlab/labgen/denylist.py`: e.g. `vuln`, `exploit`, `payload`,
`prototype_pollution`). This has to be checked because the site copy will
be written by hand. **Rule:** a new offline test runs
`fuzzlab.labgen.gates.scan_generated_tree_for_name_leaks` over `site.js`
and the rendered `app.js`, and must find nothing.
- **Scope note:** existing controller comments (for example "CWE-1321" in
  the transform templates) are out of this lane's scope, and the scanner is
  not applied to controllers here. The emitter docstring already records
  that the scanner was not re-run for `node_express`.
- **Rule for that case:** if the scanner flags anything that already
  exists in `app.js` (the `_INERT_ROUTES_JS` comments), treat it as a
  finding. Fix it if it is a comment-only change inside this emitter;
  otherwise flag it.

**R6 — The client pages must not add a new, unlabelled sink.**
- `/search` writes the `/api/search` response into the page with
  `innerHTML`. That is safe only because that endpoint's output is made of
  fixed characters: the replacement string is the literal `'<mark>$&</mark>'`
  applied to the fixed `content_literal` (`regex_highlight_match.js.j2`),
  so `$&` can put back only matched, fixed product copy. No request byte
  can reach the output.
- **Rule:** that is the **only** `innerHTML` write in `site.js`. Every
  other write of API data or user input uses
  `textContent`/`createElement`.
- It is enforced offline by a test that counts `innerHTML` occurrences in
  `site.js` and requires exactly 1, and checks that its right-hand side is
  the `/api/search` response variable.
- If a reviewer prefers zero `innerHTML` writes, the fallback is
  `textContent`, at the cost of losing visible highlighting. That fallback
  is decided at the gate, not during implementation.

**R7 — Fixture drift across 3 existing modules plus the new one (§2A-e).**
**Rule:** all 4 copy exactly `RUNTIME_SCAFFOLD_FILES`. A new offline test
asserts that `RUNTIME_SCAFFOLD_FILES` equals the scaffold directory's file
set minus build-only files (`Dockerfile`, `package-lock.json`), so adding a
scaffold file without listing it fails loudly.

**R8 — The navigability test must not pass vacuously.** This is the same
guard as Lane 1/2's R5. Hard-coded, measured minimums for both the number
of ground-truth points (4) and the number of discovered pages (measured at
§5 step 4 and recorded, never derived from the file under test) are
asserted before any per-URL assertion.

**R9 — Detection must not regress (contract point 7).** Wire contracts
are unchanged except for the new 400 on a bare `/api/search` and the new
GET on the preferences URLs. **Rule:** re-run live, after the change:
- `test_labgen_node_bff_app.py`, which includes the real-HTTP ReDoS timing
  differential on both twins;
- `test_labgen_node_bff_multitarget.py`;
- `test_multitarget_category1_combined.py`;
- `test_labgen_redos.py` and `test_labgen_prototype_pollution.py`.

MeadowMart's recall stays honestly 0, and that expectation is unchanged
(its classes are unmapped, as documented in that module). If any of these
runs changes, the change is reported, and a CC-FUZZ entry is opened with
the reserved `CC-FUZZ-0052`/`FR-FUZZ-36`, not worked around.

**R10 — The inert `/api/orders/:orderId` has a path parameter.** A bare
request to `/api/orders/` returns 404 (no route), and
`/api/orders/<anything>` returns 200 with static JSON (the route reads no
input). **Rule:** the bare sweep enumerates it through a declared example
(`/api/orders/ORD-12345`, the value the existing test already uses) and
also requests `/api/orders/` bare, expecting < 500.

### 3B. `python_fastapi` sample

**R-B1 — Could the shared layout break the minimal-pair checker, the only
byte-level twin contract here (§1b)?**
- The new `from ..site import layout` header line and the complexity-tail
  change are identical on both twins.
- The `html_body_echo` change wraps the sink's existing `HTMLResponse` in
  `layout(...)`, in the sink region, and the twins already differ there
  only through `value_expr` (`html.escape(bio)` against `bio`).

**Rule:** run
`test_tier0_minimal_pair_diff_confirms_each_declared_pair` and
`test_tier0_minimal_pair_diff_rejects_byte_identical_output` after each
FastAPI step. If the checker rejects a pair because the layout call sits in
the sink region, move the `layout(...)` call into the complexity region,
which is shared and outside the checked region. Do **not** relax the
checker.

**R-B2 — The HTML tail must keep a found/not-found difference.** No oracle
or ground truth scores this sample (§1b). Even so, contract point 3's
"SQL results render as an HTML table or detail view, so the boolean
differentials the oracles use still hold" is kept deliberately:
- **Rule:** a direct offline or TestClient test asserts that the byte
  length of the found response differs from the not-found response by at
  least 200 bytes, with the actual difference measured and recorded.
- **Why 200 bytes:** this is a proportionate floor. The sample has no
  `SqliBooleanStrategy` target, so `CC-LAB-0240`'s 300-byte number is not
  carried over unexamined. The measured value is recorded.

**R-B3 — Don't build the homepage by looking at `app.routes` at runtime.**
On FastAPI 0.141.1, `app.routes` contains `_IncludedRouter` objects with
no `.path` attribute (seen while probing on 2026-09-25: an
`AttributeError`). Walking it is fragile across FastAPI versions. **Rule:**
build the homepage and form table statically from `_PAGE_PARAMS` (§2B-a).
A new offline test asserts that the set of `_PAGE_PARAMS` routes equals
the set of routes produced by the `python_fastapi` manifests, so a new cell
route without a site entry fails loudly.

**R-B4 — `POST /login` from the new form page needs `python-multipart`.**
The generated app's `requirements.txt.j2` does not declare it. It happens
to be installed here (0.0.32), so TestClient `POST /login` works in this
environment only. A real container would fail on `request.form()`. This is
a **different class** (a missing dependency declaration, where PA-0049's
lockfile discipline would apply), so it is flagged (F4, §7), not fixed.
**Rule:** the new TestClient assertions that POST to `/login` are
skip-guarded on `importlib.util.find_spec("multipart")`, following
PA-0005's pattern, so this environment's accidental availability never
disguises the gap as covered.

**R-B5 — `GET /login` (form) and `POST /login` (cell) on the same path.**
FastAPI matches on method as well as path, so there is no conflict. But
the site router is included **after** the cell routers. **Rule:** a
TestClient assertion checks that `GET /login` returns 200 with the form
and that `POST /login` still reaches the cell (a found row gives the table
view).

**R-B6 — The in-process check must also enforce PA-0054 (2).** See §4B.
The bare sweep enumerates every served route from the emitter's own
`_PAGE_PARAMS` plus the site table, not from whatever the homepage links.

Accepted, not mitigated: none. Every risk above has a concrete
verification or fix step, or a flagged follow-up (§7).

## 4. Tests

### 4A. MeadowMart navigability acceptance test (live, PA-0053/PA-0054)

New module `tests/test_labgen_node_meadowmart_navigability_live_boot.py`,
marked `slow` and skip-guarded like the existing MeadowMart modules
(`node`/`npm` on PATH, plus a real npm-registry probe, PA-0005/PA-0035).
It mirrors `tests/test_labgen_django_navigability_live_boot.py`:

1. Assemble MeadowMart from the same 2 manifests (§1a) with
   `tests/_meadowmart_app.py`, install it with `npm install`, and boot it
   with `node app.js` on 127.0.0.1.
2. Crawl from `/` with `fuzzlab.tools.spider.LocalSpider` using the
   `requests` engine, same-host scope, and `session.trust_env = False`
   (never go through the sandbox's HTTP proxy for a loopback target; the
   2026-09-25 probe needed `ProxyHandler({})` for the same reason). Measure
   the real link depth before fixing the depth cap, and assert that the
   deepest ground-truth URL is strictly below the cap.
3. **Non-vacuous guards first** (R8).
4. Every ground-truth URL is discovered, keyed by **path**. `/catalog`
   links GET APIs that require a parameter with an example query (for
   instance `/api/search?q=shoes`), so each ground-truth path is reached at
   the URL a visitor would actually click. The expected anonymous status is
   200 for all 4: the preferences URLs through their GET resource read
   (R3 branch (a)), and the search URLs through the example query. There
   is no session gating (§1a). Finding any would itself be a finding to
   surface, not something to quietly accommodate.
5. `GET /` returns 200 HTML containing "MeadowMart", and every nav link
   returns 200.
6. **PA-0053:** no crawled URL answers 5xx or status 0.
7. **PA-0054 (2):** independently of what links reach, a bare request is
   sent to **every route the build serves**. The list comes from
   `_served_url_for` over the build's cells, plus `_SITE_ROUTES`, plus the
   declared inert routes (with R10's example). It is not taken from the
   crawl. Bare `GET` must be < 500 everywhere, and the declared statuses
   are asserted exactly: `/api/search` and its twin → 400, both preferences
   URLs → 200. Bare `POST` (empty body) to both preferences URLs → 200.
8. **R2 live gadget check**, in its own boot fixture (§3A R2).

Offline companions (not slow), in new `tests/test_labgen_node_express_browsable.py`:
- **PA-0054 (1):** every route any `node_express` manifest produces
  (`lab/manifests/*.yaml`, filtered by `stack_profile == "node_express"`
  and `supports()`, per PA-0027) has a profile in `_ROUTE_PARAMS`. For
  each one, the offline check asserts:
  - a `get_query_param`/`post_body_param` source carries exactly one of
    `default_value`/`required_param`;
  - a `post_body_json` source carries neither key (it is whole-body);
  - a `read_stored_field` source carries neither key.

  The expected route set is **hard-coded** (`/api/login`, `/api/posts`,
  `/api/preferences`, `/api/products`, `/api/profile`, `/api/search`), so
  a new route cannot slip past with no declaration.
- The guard/default lines are identical on both twins (R4).
- `_SITE_ROUTES` matches the `app.get('…'` literals in `site.js` (drift
  check, §2A-a).
- `RUNTIME_SCAFFOLD_FILES` matches the scaffold directory (R7).
- The `site.js` gadget scan (R2), the name-leak scan (R5), and the
  `innerHTML` count (R6).
- `node --check site.js` and the rendered `app.js`, skip-guarded on
  `node`.
- The accumulator is byte-deterministic with the catalog array included
  (extending the existing determinism check).

### 4B. `python_fastapi`: an in-process link-and-bare-request check instead of a spider crawl (decided explicitly)

**Decision: there is no spider-based navigability test for
`python_fastapi`.** Contract point 6's acceptance criterion is "discovers
**100%** of that app's ground-truth injection-point URLs". This sample has
no ground truth (§1b), so the criterion would pass vacuously. Standing up a
socket boot (uvicorn) only to run `LocalSpider` against it would add a
harness without adding assurance. The PA-0053/PA-0054 obligations still
apply to every emitter, and they are met in-process instead, in the
existing `TestClient` test module
(`tests/test_labgen_python_fastapi_sample.py`, not slow):

1. `GET /` → 200 HTML with the layout, and nav links to every route.
2. **Link-reachability BFS** from `/` over `<a href>` (parsed with
   BeautifulSoup, the same parser as `LocalSpider._fetch_static`), keeping
   only same-app links: every served GET route is reachable within depth 2.
3. **PA-0054 (1), offline:** each `_PAGE_PARAMS` route declares its
   absent-input behavior under the same rules as §4A. The expected set is
   hard-coded: `/login`, `/products`, `/profile`.
4. **PA-0054 (2), bare sweep:** a bare `GET` of every served path
   (`_PAGE_PARAMS` plus the site table) returns < 500, with declared
   statuses: `/products` → 200 (default id 1), `/login` → 200 (form),
   `/profile` → 200, `/` → 200. A bare `POST /login` (empty body) → 400,
   skip-guarded per R-B4.
5. R-B2's found/not-found difference, R-B5's GET/POST coexistence, and the
   existing verdict smoke assertions, updated from `r.json()` to the HTML
   view with the same intent: a found row for `id=1`.

If a reviewer holds that PA-0053's wording ("the live-boot navigability
crawl … each Browsable Labs lane must extend that crawl to its own app")
requires a real socket crawl even here, the fallback is to boot uvicorn on
a free loopback port and run `LocalSpider` over it, reusing the 4B
assertions. That choice is settled at the gate.

## 5. Sequencing (each step has a named gate)

1. **Absent-input declarations, both emitters (§2A-d, §2B-c).** Probe D4
   first and record the result. Add `default_value`/`required_param` to the
   templates and route profiles.
   - **Gate:** the §4A and §4B PA-0054 (1) offline tests plus the
     twin-identical-lines test pass;
   - the existing `node_express`/`python_fastapi`/`redos`/
     `prototype_pollution` suites and both conformance modules
     (minimal-pair, Tier 3) are green (R4, R-B1);
   - D1 is fixed in `TestClient` (`GET /products` returns 200).
2. **Bug protocol for BUG-0056/PA-0058** (§6), written now that D1–D4 are
   fixed. It includes the PA-0002 sweep, whose scope is set in §6.
   - **Gate:** the `ERROR_LOG.md` ↔ `BUG-0056` ↔ `PA-0058` cross-references
     exist.
3. **MeadowMart site layer (§2A-a/b/c/e).**
   - **Gate:** the offline companions in §4A pass (drift, gadget scan,
     name-leak, `innerHTML` count, `node --check`, determinism);
   - the 3 existing live MeadowMart modules are green on the new fixtures
     (R7, R9).
4. **MeadowMart navigability test (§4A).** Measure the depth and the
   page-count minimums, then fix them in the module.
   - **Gate:** the module is green, including the bare sweep and the R2
     gadget boot.
   - **Scope-creep rule** (restated from `CC-LAB-0241`/`CC-LAB-0242`): fold
     a crawl-surfaced defect into this change only if it is the *same
     class* as this plan's tracked work (a missing nav link, a missing
     absent-input declaration, a missing layout on a site page) and it
     touches only the `node_express`/`python_fastapi` emitters' own
     templates, scaffold and routes. Anything else is flagged as a named
     follow-up with a recommended next number, and does not block this
     step's Effectiveness.
5. **`python_fastapi` homepage and layout (§2B-a/b) and the in-process
   check (§4B).**
   - **Gate:** `tests/test_labgen_python_fastapi_{sample,conformance,modules}.py`
     are green, including minimal-pair (R-B1).
6. **Full verification.** The full non-slow suite, plus explicitly: every
   `node_express` live module (`test_labgen_node_bff_app.py`,
   `test_labgen_node_bff_multitarget.py`,
   `test_multitarget_category1_combined.py`, the new navigability module)
   and the `python_fastapi` `TestClient` module. Report pass/fail/skip
   counts for each, confirming no skips from environment gaps.
7. **Bookkeeping (§6).**

## 6. Deliverables checklist

- [ ] §5 step 1: absent-input declarations for every `node_express` and
      `python_fastapi` route, with offline PA-0054 (1) checks green; D1 fixed;
      D4 probed and recorded.
- [ ] `BUG-0056` (`docs/bugs/BUG-0056-*.md`), with a full RCA (Five Whys)
      and a **recurrence review against BUG-0037/PA-0039, BUG-0051/PA-0053
      and BUG-0052/PA-0054**. It must include a prior-preventive-action
      failure analysis. The working hypothesis, to be confirmed in the doc
      and not assumed: PA-0054's rule was correct, but its offline check
      was built **per emitter, by the lane that reached that emitter**
      (`tests/test_labgen_django_browsable.py` covers only `django`).
      Emitters no lane had reached yet (`python_fastapi`, `node_express`,
      `php_current`) stayed unchecked. That is a "not enforced, wrong
      layer" failure. `PA-0058` must strengthen PA-0054 on that point.
      The candidate rule is a registry-driven cross-emitter check.
      - **Decision rule for PA-0058's own enforcement scope:** implement
        the check here only for the emitters this lane owns
        (`node_express`, `python_fastapi`), plus a strict-xfail offline pin
        for `php_current` if the sweep finds instances there.
      - Do **not** add a cross-emitter test that covers `go_net_http`,
        `spring_boot` or `ruby_rails`, because Lanes 3–5 are converting
        those concurrently and such a test would make their merges
        collide. Instead, flag to the orchestrator (Lane 7) that it should
        lift the check into one shared, registry-driven test once all
        lanes have merged.
- [ ] `ERROR_LOG.md` entry (newest on top), cross-referencing BUG-0056
      and PA-0058.
- [ ] `docs/PREVENTIVE_ACTIONS.md`: `PA-0058`, plus the PA-0002 sweep's
      results recorded in the bug doc.
- [ ] MeadowMart site layer: `scaffold/site.js`, the accumulator line, the
      preferences GET resource read (with the R3 sign-off recorded), and
      the fixtures refactored to `RUNTIME_SCAFFOLD_FILES`. The 3 existing
      live modules are green.
- [ ] MeadowMart navigability test green: crawl, the PA-0054 (2) sweep of
      every route, and the R2 gadget boot.
- [ ] `python_fastapi`: homepage, layout, `/login` form page, cell
      responses inside the layout, and the §4B in-process check green.
- [ ] Offline companions green (§4A list), including R5's name-leak scan
      and R6's `innerHTML` pin.
- [ ] Strict-xfail pins for the different-class findings, each naming its
      follow-up (§7: F1, F2, F3; F4 is skip-guarded and flagged).
- [ ] Full non-slow suite, every `node_express` live suite and the
      `python_fastapi` TestClient suite green, with counts reported.
- [ ] `docs/components/01-target-lab/change-control.md`: **one** entry,
      `CC-LAB-0246`, covering both targets in clearly separated
      subsections. **Why one entry and not two:**
      - both targets are one lane's single change, verified together;
      - they share one bug (BUG-0056 spans both emitters) and one
        preventive action;
      - the two reserved FR numbers already map one-to-one onto the two
        targets: `FR-LAB-168` is MeadowMart and `FR-LAB-169` is the
        `python_fastapi` sample;
      - a second CC-LAB entry would force a Lane 7 number bump that the
        orchestrator would have to reconcile against 3 parallel lanes, for
        no traceability gain.

      If the change-control gate's reviewers still conclude that two
      entries are needed, bump Lane 7 to `CC-LAB-0248` in
      `docs/LAB_BROWSABLE_APPS_PLAN.md` immediately, before drafting the
      second entry (the discipline from that doc's correction notes), and
      flag it.
- [ ] `docs/components/01-target-lab/requirements.md`: `FR-LAB-168`
      (MeadowMart browsable site, client pages, preferences GET resource
      read, navigability test, and the **R3 sign-off**) and `FR-LAB-169`
      (`python_fastapi` homepage and layout, in-process check).
- [ ] `CHANGELOG.md`: one dated line referencing `CC-LAB-0246`,
      `BUG-0056` and `PA-0058`.
- [ ] `docs/LAB_BROWSABLE_APPS_PLAN.md`: the Lane 6 row updated to done,
      naming what was used and what was not (`CC-FUZZ-0052`/`FR-FUZZ-36`
      are expected to stay unused, R9).
- [ ] `docs/ARCHITECTURE.md`: not expected to change. The new scaffold
      files sit inside existing emitter packages, and Lane 7 owns the
      compose/port and architecture integration. Check again at step 7
      and update if any structure or contract did change.

## 7. Out of scope, and flagged follow-ups

- **Port 8091, the compose service, the `labctl` profile**: Lane 7.
  `app.js` still honors `PORT` and binds 127.0.0.1 (`__init__.py:406-409`).
- **F1** (different class): `node_express` `/api/profile` (`NE-0007/0008`)
  references `currentUser`, which is never defined. Every request 500s
  (probe-confirmed). It is pinned with an offline strict xfail that
  asserts each `stored_expr` root identifier is defined in the controller
  or the scaffold. Recommended follow-up: the next free `CC-LAB` number
  after Lane 7.
- **F2** (different class): `node_express` `async` handlers
  (`single_statement.js.j2`) have no error handling. Under Express 4 and
  Node 22, **any** SQL error, including an error-based SQLi probe, exits
  the whole process (probe-confirmed through D2). This matters as soon as
  the Tier-A SQL cells are served live. It is pinned with an offline
  strict xfail (the rendered `async` handler catches and turns rejections
  into a response). Not fixed here: it changes the SQLi cells' error
  response shape, which is an oracle-facing decision
  (`SqliErrorStrategy`), and those cells have no live boot or ground
  truth to verify against.
- **F3** (different class): the `python_fastapi` twins share one path, so
  the secure twins are unreachable in the whole-app build (§1b). It is
  pinned with a strict xfail (a TestClient check that each twin is
  reachable at a distinct URL). Fixing it needs a twin-URL mechanism in a
  per-cell file, which the minimal-pair checker constrains, so it is its
  own design.
- **F4** (different class): the generated `python_fastapi`
  `requirements.txt` does not declare `python-multipart` (R-B4). It is
  flagged and skip-guarded, not fixed (PA-0049 lockfile scope).
- **Other emitters** (`go_net_http`, `spring_boot`, `ruby_rails`): Lanes
  3–5. `php_current` is handled only as far as §6's PA-0002 rule says.
- Any MeadowMart identity growth (new cells, new ground-truth points) is
  not part of this lane.

## 8. Review history

**No review round has run yet.** The 2-reviewer gate (accuracy and
adequacy) is **blocked**, because the proposing agent's session has no
Agent tool to spawn independent reviewers (see the Status line). No
agreement is claimed. The next step belongs to the orchestrator: run round
1 with 2 independent reviewers on this document at this commit, or
authorize a different review mechanism explicitly.
