# Browsable Labs Lane 5 — ruby_rails: ForgeCart

Status: **rounds 1–4 reviewed 2026-09-25. Round 4 found 1 adequacy gap: the
console script's error-path branch was not derived, and not confirmed live.
It is fixed in this revision. Awaiting round-5 confirmation. Not yet
converged, and implementation is not authorized.** The orchestrating
session ran the review rounds (§8). The original drafting-time status is
kept below for the record. Reserved as `CC-LAB-0245` / `FR-LAB-166` (`FR-LAB-167` reserved,
expected unused) / `CC-FUZZ-0051` / `FR-FUZZ-35` (expected unused, R11) /
`BUG-0055` / `PA-0057`, per `docs/LAB_BROWSABLE_APPS_PLAN.md`'s lane table.
The dispatch required two independent reviewer subagents (accuracy +
adequacy) before convergence. The drafting agent could not spawn them: it
has no Agent tool, and its one alternative (`create_session`, a separate
cloud session) was **denied by the permission classifier**. Per
`docs/MULTI_AGENT_ORCHESTRATION.md` §4, it did not work around that and did
not substitute a self-review. §8 records this. **Nothing in this plan is
converged, and implementation is not authorized.** Next step, for a session
that has the reviewer mechanism: run §8's round 1 against this document as
written.

## 0. Lessons from Lanes 1–2, applied from the start

- **Research first, from the code.** Every claim in §1 comes from reading the
  `ruby_rails` emitter, its skeleton and ForgeCart's ground truth directly, and
  from a **live boot of the current (pre-change) whole app** in this
  environment (Ruby 3.3.6, Bundler 4.0.9, Rails 8.1.3.1 on `PATH`;
  `rails_boot_available()` returned `True`). Nothing is carried over by
  analogy. Two of this lane's risks (R1, R2) exist only in Rails, and live
  probing found them, not by assuming the stack behaves like Laravel or Django.
- **The navigability test is specified before any page is converted (§4).**
  Lane 2's round-1 review noted that the crawl still *runs* last. That is
  still true here (§5 step 7). What changes is that each page's absent-input
  and anonymous-status contract is decided in §2d/§4 first and then checked
  by that page's own gate.
- **PA-0054 is built in, not bolted on.** It has three parts:
  1. an offline declaration check over every route the emitter's manifests
     produce, with its own adversarial self-test (PA-0034(2));
  2. a live bare-request sweep of every route the build serves, enumerated
     from the rendered `config/routes.rb` (the file Rails actually loads), not
     from the crawl;
  3. each sweep result compared with the **declared** status, not only with
     "< 500". R7 explains why "< 500" is too weak for this stack: a sink with
     a catch-all `rescue` hides a missing value that reaches it.
- **Risk items carry decision rules.** Any risk with an open design choice
  gets a concrete rule (R-numbered), not "decide during implementation".

## 1. Scope: what exists today (confirmed by reading code and a live boot)

### 1a. ForgeCart already exists as a named app identity (no `--app` split)

- Phase C (`CC-LAB-0077`/`FR-LAB-81`) created ForgeCart, a Shopify-style
  merchant storefront plus admin. It has its own manifest
  (`lab/manifests/shopify_forgecart_real_pages.yaml`, 5 real-page cells
  `LABGEN-RR-RP-0001`..`0005`) and its own ground truth
  (`lab/ground-truth-forgecart/`: 5 points, 5 cases `FCART-0001`..`0005`,
  and `expectedresults.csv`).
- Real URLs are pinned by `_REAL_PAGE_URL_BY_CELL_ID`
  (`fuzzlab/labgen/emitters/ruby_rails/__init__.py:192-215`) and resolved by
  `url_path_for` (`:218-228`). Every other cell stays at `/cell/<slug>`.
- **Realistic URLs are therefore already in place** for all 5 ground-truth
  points. No URL-pinning work is needed.
- **Twins in ForgeCart.** The only twin pair among the real pages is
  `RR-RP-0002` (naive `==`, `/webhooks/orders/create`) and `RR-RP-0003`
  (`secure_compare`, `/webhooks/customers/update`). They sit on two real,
  distinct Shopify topics by deliberate design (manifest header, lines
  13–20). The other three real pages have no secure twin in this build.
  Lane 2's R1 (a secure twin's URL left generic) therefore has no
  counterpart here.
- Inert surrounding pages are fixed routes in
  `route_accumulator._STATIC_APP_ROUTES` (`route_accumulator.py:52-58`):
  `/`, `/products`, `/cart`, `/admin`, `/admin/orders`. They are served by
  the checked-in skeleton controllers `StorefrontController` and
  `AdminController`.
- **Whole-app build = 12 cells**
  (`tests/test_labgen_ruby_rails_whole_app_live_boot.py:39-66`):
  - the illustrative `LABGEN-RR-0001`, which is built in the test itself and
    appears in no manifest;
  - the 6 Phase B sample cells `RR-0002`..`0007` from the three
    `*_rails_sample.yaml` manifests;
  - the 5 ForgeCart real pages.

  This lane's navigability test boots exactly this set.

### 1b. The only live runner: `RailsLiveBootHarness`, and it runs in development mode

- `fuzzlab/labgen/conformance/rails_live_boot.py:208-465` is a separate
  class from `LiveBootHarness`. It needs `ruby` and `bundle` on `PATH` and a
  real RubyGems round trip. Its probe is `rails_boot_available()`
  (`:143-155`), which is PA-0035-compliant.
- It assembles the build in `_assemble` (`:240-261`). There is no
  `assemble.py`-style CLI or compose service for `ruby_rails`; Lane 7 owns
  serving.
- It boots with `RAILS_ENV=development` (`_harness_env`, `:263-278`, set at
  `:276`). That choice drives R1 and R2.

### 1c. What a response looks like today (measured live, pre-change, whole-app build)

| Route | Today |
|---|---|
| `GET /` | 200 `text/plain`: `ForgeCart -- a Shopify-style merchant storefront (lab fixture).` (`storefront_controller.rb:19`) |
| `GET /products`, `/cart` | 200 JSON `{"products":[]}` / `{"items":[]}` (`:28`, `:35`) |
| `GET /admin` | 200 plain text (`admin_controller.rb:10`) |
| `GET /admin/orders` | 200 JSON `{"orders":[]}` (`:19`) |
| `GET /search?q=` | 200 **HTML** — see the note below this table |
| `POST /webhooks/*` | JSON `{"verified":…}` (`webhook_signature_verification.rb.j2:9-13`) |
| `POST /admin/customers/update` | JSON `user.as_json(only: [:id,:username,:bio,:role])` (`orm_entity_bulk_assign.rb.j2:7`) |
| `POST /admin/products/import` | JSON `{ok, parsed_class}` / `{ok:false, error}` (`object_deserialization.rb.j2:6-11`) |
| `GET` of any of the 4 POST-only real URLs | 404 (routes are verb-specific) |
| `/catalog` | 404 (does not exist) |

Note on `GET /search?q=`: `render_only.rb.j2:13` renders the cell's view by
explicit template path, and Rails wraps it in the skeleton's **default
layout** automatically. That layout is `app/views/layouts/application.html.erb`,
the stock `rails new` layout: title "Fuzzlab App" (`:4`), `csrf_meta_tags`
(`:9`), an external `stylesheet_link_tag :app` (`:20`), and `/icon.svg`
(`:17`). There is no nav, header or footer. The view itself is
`<div class="cell-output"><%= raw @value %></div>`
(`html_body_echo.erb.j2:7`). So **real HTML already exists**, but only as a
generic Rails shell around a bare fragment.

A POST-only real URL has no form page anywhere, which is the gap called out
in `docs/LAB_BROWSABLE_APPS_PLAN.md` "Why" (§ bullet 3).

### 1d. No homepage in the design contract's sense

`/` exists, but it is plain text. It has no nav and links to nothing.

### 1e. Page-vs-api classification (justified against the real Shopify product)

| Point | Class | Justification |
|---|---|---|
| `/search` (`FCART-0001`) | **page** | Storefront search results page, server-rendered HTML in every Shopify theme. |
| `/webhooks/orders/create` (`FCART-0002`) | **api** | A Shopify webhook receiver: a machine-to-machine POST of a raw JSON body plus an `X-Shopify-Hmac-SHA256` header, signed by Shopify's servers. The ground-truth parameter is a **header**, and no HTML form can set one. Stays JSON and gets a `fetch()` client page (§2c). |
| `/webhooks/customers/update` (`FCART-0003`) | **api** | Same reasoning as `orders/create`: the secure twin on a second real topic. |
| `/admin/customers/update` (`FCART-0004`) | **page** | Shopify admin's "edit customer" is a browser form in the merchant admin UI, not a public JSON API. The cell's own parameter shape (`user[role]` / `user[bio]`, Rails form-encoded nested params) is itself the browser-form encoding. |
| `/admin/products/import` (`FCART-0005`) | **page** | Shopify admin's product import is an upload/paste dialog in the admin UI. The design contract lists "deserialization endpoints" among typical APIs, but this cell reads one **named form field** (`yaml_payload`), not a whole-body wire contract, and nothing here is machine-to-machine. By the contract's "when unsure, choose page" rule it is a page. |

The inert pages `/products`, `/cart`, `/admin` and `/admin/orders` are all
**page**. So is the new `/catalog`, which contract §5 requires because the
build carries 7 illustrative cells with no ground-truth case.

### 1f. Session, login and gating

- There is no login route and no session-gated cell. The emitter has no auth
  module. `grep -rn "session\|login"` over the skeleton `app/` and
  `config/initializers/` finds only comments.
- The merchant-admin pages are served anonymously. That is the existing,
  modelled posture from `CC-LAB-0077`; the manifest models no auth.
- The R8 split-app 401 exception therefore does not apply, and every
  ground-truth URL is expected to return 200 to an anonymous GET (§4).
- A login wall in front of `/admin` would be more realistic. It is **not
  built here**, because no manifest cell asks for it (R14).

### 1g. Existing coverage

- **Offline:** `tests/test_labgen_ruby_rails_{webhook_signature,
  mass_assignment,insecure_deserialization}.py` — module/matrix/verdict
  tests, tier0 `ruby -c`, the naive minimal-pair check, and tier3
  regeneration. They assert, among other things:
  - each Phase B cell renders exactly one file, a controller (`..._mass_assignment.py:129-133`);
  - `"attrs = attrs.permit!"` is present;
  - `"YAML.unsafe_load(raw_yaml)"`, `"parsed.class.name"`, `"rescue => e"` and
    `"e.class.name"` are present (`..._insecure_deserialization.py:101-118`).
- **Live (slow):**
  - `test_labgen_ruby_rails_live_boot.py` (the illustrative cell);
  - the three per-shape `*_live_boot.py` files, each on its sample cells only;
  - `test_labgen_ruby_rails_whole_app_live_boot.py`, which asserts the
    current JSON and plain-text shapes at `:93`, `:97`, `:101`, `:105` and
    `:149`;
  - `test_multitarget_ruby_rails_forgecart.py` (`tp >= 1`);
  - `test_multitarget_category1_combined.py` (ForgeCart `tp >= 1`).
- **No navigability test and no absent-input declaration check exist** for
  this stack.

### 1h. Detection baseline (measured live, pre-change, 2026-09-25)

A `run_targets` run with `RequestsProbeSender` against the 5-cell ForgeCart
build, the same setup as `test_multitarget_ruby_rails_forgecart.py`,
produced:

- `tp=1` (`FCART-0001` matched), `fp=1`, `tn=1` (`FCART-0003`), `fn=3`
  (`FCART-0002`, `-0004`, `-0005`);
- `false_alarms = ['/admin/customers/update:user[role]:xss-reflected']`.

Two notes on the misses and the false alarm:

- **FN.** `FCART-0004` and `FCART-0005` fail closed by design.
  - `MassAssignmentPrivilegedFieldStrategy` returns `None` unless
    `candidate.content_type == "application/json"`
    (`fuzzlab/oracle/strategies.py:1321`). `auto.py:92-96` sets that only for
    a `param == "body"` point, and its docstring names `FCART-0004` as an
    intentional non-match (`:1300-1307`).
  - `InsecureDeserializationTypeConfusionStrategy` has the same JSON gate
    (`:993`) and is Jackson-specific.
- **FP.** `ReflectedXssStrategy` (`:236-256`) is handed a candidate with no
  `sink_context` (`fuzzlab/harness/pipeline.py:92-97` builds `Candidate`
  without one), so it types the reflection itself. It confirmed a break-out
  reflected in the mass-assignment endpoint's JSON response. Which break-out
  literally survived in the JSON body is **not yet confirmed**. A targeted
  live probe was attempted and was blocked in this session by the same
  permission denial as §8, so R5 treats it as a measurement still to take,
  not a known fact.

## 2. Fix design

### 2a. Skeleton hygiene: fix what the stock Rails shell leaks (R1, R2)

In `stack/skeleton/config/environments/development.rb`:

- `config.action_view.annotate_rendered_view_with_filenames = false` (today
  `true`, `:53`). This mode wraps every rendered view in
  `<!-- BEGIN app/views/cell_labgen_rr_rp_0001/show.html.erb -->` comments,
  seen live in `GET /search`. The comment names the cell's controller path,
  and so its **cell ID**, inside the page's layout output.
- `config.consider_all_requests_local = false` (today `true`, `:13`). With
  it on, every 4xx/5xx is Rails' debug exception page. **Confirmed live**: a
  bare `POST /admin/customers/update` returned a 121 KB 400 page whose
  "Extracted source" shows the generated controller around the raising line.
  That includes the transform comment
  `# permit_bang_unrestricted: every key in attrs is accepted…`. The secure
  sample twin `PATCH /cell/labgen_rr_0005` shows
  `# strong_params_explicit_allowlist: …` instead. In other words, **an
  anonymous request reveals whether a cell is the vulnerable or the secure
  twin.** The dev 404 page also lists the full route table. With the setting
  off, Rails serves the skeleton's own static `public/400.html`, `404.html`,
  `406-unsupported-browser.html`, `422.html` and `500.html`, all already
  checked in. Rails source confirms this setting alone controls the detailed
  page:
  - `railties-8.1.3.1/lib/rails/application.rb:325` maps it to
    `action_dispatch.show_detailed_exceptions`;
  - `actionpack-8.1.3.1/lib/action_controller/metal/rescue.rb:30-39`
    defaults `show_detailed_exceptions?` to `false` when it is off.

  This is a genuine defect (R2) and gets the full bug protocol as
  `BUG-0055`/`PA-0057`.
- Unchanged: `RAILS_ENV=development` itself (R2 decision rule),
  `config.server_timing` (R2 note) and `allow_browser` (R9).

### 2b. Homepage and shared layout (contract points 1 and 2)

Replace the skeleton's `app/views/layouts/application.html.erb` with
ForgeCart's layout. Rails applies it automatically to every
`ApplicationController` subclass that renders a template, so every cell view
and every skeleton page picks it up with no per-controller wiring. The
layout contains:

- **Header.** The brand "ForgeCart", a storefront **search box**
  (`<form action="/search" method="get"><input type="search" name="q">`),
  and the nav. The search box never pre-fills or echoes `q`, so the layout
  adds no reflection sink.
- **Nav.** Two fixed groups, each sorted by path so the order is
  deterministic:
  - Storefront: `/`, `/cart`, `/catalog`, `/products`, `/search`;
  - Merchant admin: `/admin`, `/admin/customers/update`, `/admin/orders`,
    `/admin/products/import`, `/webhooks/customers/update`,
    `/webhooks/orders/create`.
- **Main.** `<main><%= yield %></main>`.
- **Footer.** Inline `<style>` in `<head>`.
- **Title.** `<title><%= content_for(:title) || "ForgeCart" %></title>`.
- **Dropped from the stock layout:**
  - `csrf_meta_tags`: a random token on every request, which breaks
    byte-identical twin bodies, and inert under the global
    `skip_forgery_protection` (R3);
  - `csp_meta_tag`;
  - `stylesheet_link_tag :app`: an external asset (contract point 2);
  - the `/icon.svg` link.
- **Byte-identical across every page and twin.** The layout reads no request
  data except `content_for(:title)`, which each page sets from a literal.

`/` becomes `storefront/home.html.erb`: the brand, a one-paragraph
description, and links to every page.

`/products`, `/cart`, `/admin` and `/admin/orders` become HTML pages
(`storefront/products`, `storefront/cart`, `admin/dashboard`,
`admin/orders`) with honest empty states such as "No products yet". They
still read no input.

The skeleton controllers render by explicit `render template: "<dir>/<name>"`
(PA-0036 discipline), never by implicit inflection.

**`/catalog`** (new; `get '/catalog', to: 'storefront#catalog'` added to
`_STATIC_APP_ROUTES`) lists the illustrative `/cell/*` routes. It builds the
list at request time from Rails' own route table
(`Rails.application.routes.routes`), filtered to paths starting with
`/cell/` and sorted by path. The routes Rails serves are therefore the list,
by construction, with no second, independently maintained copy
(PA-0003/PA-0021). GET routes are rendered as links; non-GET routes as
unlinked "`POST /cell/…` (API endpoint)" text (R8).

### 2c. Pages, forms and the api client page

A single per-real-page profile, `_REAL_PAGE_PROFILES` in `__init__.py`, is
keyed by the real URL and read only for real-page cells. It carries:

- `kind` (`page`/`api`, the §1e classification in code, with a test pinning
  it to §1e's table);
- optional `get_page` (a skeleton `controller#action` that answers `GET` on
  the same URL);
- optional `result_template` (a skeleton view a POST page's sink renders into);
- optional `page_title`.

Both twins of a URL would share one profile, so any minimal pair still
differs only in its transform region (BUG-0027).

**GET form routes.** For a real-page cell whose profile has `get_page`,
`route_fragment_for` emits two lines:

- `get '<url>', to: '<get_page>'`, then
- the cell's existing verb line.

The duplicate-route check (`route_accumulator.py:127-149`) still keys on the
first line's URL per cell. An illustrative sample cell gets no GET page.

| URL | GET | POST / other verb |
|---|---|---|
| `/search` | the cell's view in the layout: `<% content_for :title, "Search" %>`, a heading, then the unchanged `<div class="cell-output"><%= raw @value %></div>` | — |
| `/admin/customers/update` | `admin#customer_form`: an "Edit customer shopper1" form, `method="post"`, action = the URL itself, **only** `user[bio]` (R4) | the sink renders `admin/customer_updated`: username, bio, role, all **escaped** with `<%= %>` (R5); status 200 as today |
| `/admin/products/import` | `admin#product_import_form`: a textarea `yaml_payload`, `method="post"`, action = the URL itself | the sink renders `admin/product_import_result`: "Parsed as `<class>`" or "Import failed: `<error class>`", escaped; status 200 as today |
| `/webhooks/orders/create`, `/webhooks/customers/update` | `webhooks#console` (api client page, below) | unchanged JSON wire contract |

**`/search` title for the illustrative cell.** `html_body_echo.erb.j2` gains
the optional `page_title`/heading lines, emitted only when the profile sets
them. The illustrative `LABGEN-RR-0001` view is therefore unchanged apart
from now rendering inside the layout.

**Sink rendering for the two POST pages.** `orm_entity_bulk_assign.rb.j2`
and `object_deserialization.rb.j2` gain an
`{% if result_template %}…{% else %}…{% endif %}` tail:

- `@user`/`@result` plus `render template: "<result_template>"` for the real
  pages;
- the byte-for-byte **unchanged** `render json:` for every illustrative cell.

The deserialization sink is restructured so the `begin/rescue` computes a
`result` hash and a single `render` follows it. That avoids a
double-render if template rendering raised inside `begin`, and keeps the
JSON body key-for-key identical to today. The existing offline string
assertions still hold (`YAML.unsafe_load(raw_yaml)`, `parsed.class.name`,
`rescue => e`, `e.class.name`), and each Phase B cell still emits exactly
one file, because the result views are skeleton files, not emitted ones.

**Keeping every template key defined.** The ctx always defines every new
key (`None` default). The module environment uses `StrictUndefined`
(`modules.py:75`), so an undefined key would fail the render.

**Webhook client page (`webhooks/console.html.erb`, api).**

- A form with a JSON payload textarea and an "X-Shopify-Hmac-SHA256" input.
- An inline script `fetch`es `window.location.pathname` with the raw textarea
  bytes as the body, `Content-Type: application/json`, and the header, then
  prints the JSON response.
- The page **never embeds the webhook secret** (R6).
- It does not interpolate its own URL server-side. The topic label is
  filled in from `location.pathname` by the script.
- As a result the two topics' client pages are **byte-identical**, so the
  vulnerable/secure twin pair cannot be told apart by their page (R6).
- No CSP is configured (`config/initializers/content_security_policy.rb` is
  entirely commented out), so the inline script and style run.

**Forms and CSRF.** All forms are plain HTML `<form>` elements, never
`form_with`, which would inject a per-request `authenticity_token` (R3).

### 2d. Absent-input behavior, declared up front (PA-0053/PA-0054)

A new table, `_ABSENT_INPUT_BY_SHAPE` in `__init__.py`, is per shape,
because the source region must be identical across twins. It declares, for
every **named** request input a shape reads:

- the absent-input **kind**: `default` or `required_4xx`;
- the bare-request status that kind produces.

| Shape (routes) | Input | Decision | Bare request (the route's own verb) | Before (measured live) |
|---|---|---|---|---|
| xss/html_body (`/search`, `/cell/labgen_rr_0001`) | query `q` | **default `""`**: `value = params.fetch(:q, "")` (a storefront search page with no query shows the empty results page) | GET → 200 | 200, but `nil` reached the view (`raw nil` → `""`) |
| mass_assignment (`/admin/customers/update`, `/cell/labgen_rr_0004`/`0005`) | body root `user` | **required_4xx**: `params.require(:user)`, unchanged. `ActionController::ParameterMissing` is Rails' own handled 400, raised before the transform or sink | POST/PATCH → 400 | 400 (dev debug page → R2) |
| insecure_deserialization (`/admin/products/import`, `/cell/labgen_rr_0006`/`0007`) | body `yaml_payload` | **required_4xx**: `raw_yaml = params.require(:yaml_payload)`. There is no meaningful default import payload. `require` also rejects blank, so an empty form submit gets the same handled 400 before the sink | POST → 400 | **200 `{"ok":false,"error":"TypeError"}`** on both twins: `nil` reached `YAML.*_load` and the sink's catch-all `rescue` hid it |
| webhook_signature (`/webhooks/*`, `/cell/labgen_rr_0002`/`0003`) | header `X-Shopify-Hmac-SHA256` | **default `""`**: `request.headers[...].to_s`, unchanged | POST → 401 `{"verified":false}` | 401, unchanged |
| webhook_signature (as above) | raw body | not a named parameter: `request.body.read` is never `nil` (empty is `""`), and the HMAC of `""` fails to verify. Declared as `default ""` for completeness | as above | as above |
| skeleton pages and `/catalog`, `/up` | none | no input | GET → 200 | — |

The `get_param`/`post_param` source templates render the declared construct
from the shape context. `all_params_nested` and `raw_request_body` already
do. The offline check (§4, check O1) ties each rendered controller back to
its declaration.

**Bug decision rule for §2d** (so a finding is not reframed after the fact):

- A pre-change behavior is a **defect requiring the bug protocol** if it is
  either:
  - (a) a served route answering ≥ 500 to an anonymous request; or
  - (b) an anonymous response that distinguishes a vulnerable twin from its
    secure twin, or reveals a cell's verdict.
- Otherwise the change is a **PA-0054 conformance change** decided in this
  plan and recorded in the change-control entry.

Applied to this lane's findings:

- The `yaml_payload` path is twin-identical and < 500 (measured), so it is a
  conformance change, not a bug. The same holds for `q`.
- The debug-page leak (§2a, R2) meets (b), so it is `BUG-0055`.
- If implementation measures anything different, the rule is re-applied to
  the measurement.

**How §2d's rule relates to R7 (round-1 adequacy finding).** The
`yaml_payload` catch-all `rescue` doesn't crash and doesn't tell the twins
apart, so under the rule above it isn't a bug. The obvious objection is
that it could quietly defeat detection, a different failure from "a weak
check". It is kept outside the bug trigger for three stated reasons:

1. **It only affects requests without `yaml_payload`.** No detection probe
   sends such a request, because every strategy sends a value in the
   parameter it tests. So it cannot change any detection verdict.
2. **`FCART-0005` was already a known false negative before this lane.**
   The §1h baseline (measured live, and confirmed by the round-1 accuracy
   reviewer) records it as a miss, caused by something unrelated to the
   `rescue`: `InsecureDeserializationTypeConfusionStrategy`'s JSON gate
   (`strategies.py:993`) and its Jackson-specific probes.
3. **The detection it does defeat is the absent-input sweep itself.** That
   is exactly what R7 addresses, by asserting the declared status instead
   of "< 500".

Guard on this reasoning: if the §5 step 8 post-change measurement shows
`FCART-0005`, or any other case, changing detection status in a way this
explanation doesn't predict, the rule is re-applied with "defeats
detection" treated as a verdict-affecting result, which counts as trigger
(b).

### 2e. Ground-truth `rendering` correction

In `lab/ground-truth-forgecart/`, both `injection-points.json` and
`labels.json`:

- `FCART-0004` and `FCART-0005`: `"server-json"` → `"server"`, because their
  responses become HTML pages.
- `FCART-0001` stays `server`.
- `FCART-0002`/`0003` stay `server-json` (api).
- `expectedresults.csv` has no `rendering` column and is unchanged.

**Consumer check.**

- `fuzzlab/harness/auto.py:92-96` reads `rendering` only to set a JSON body
  for a `param == "body"` point.
- `FCART-0004` (`user[role]`) and `FCART-0005` (`yaml_payload`) are not
  `param == "body"`, so they are sent form-encoded both before and after.
- **The change alters no request encoding.**

No case or point is added or removed, so the PA-0044 cardinality grep is run
anyway (R12) but should find nothing to change.

## 3. Risk register

**R1: Rails' dev-mode view annotations and the stock layout leak cell
identity and break byte-identical twin pages.**

Confirmed live:

- `GET /search` carries `<!-- BEGIN app/views/cell_labgen_rr_rp_0001/show.html.erb -->`;
- `csrf_meta_tags` differs on every request;
- the layout pulls an external stylesheet.

**Mitigation (§2a/§2b):** annotations off; a new layout with none of the
three. Checked in two places:

- offline: a structural test on the layout file (no `csrf_meta_tags`,
  `stylesheet_link_tag`, `javascript_include_tag`, `<link rel="stylesheet"`
  or `src="http`);
- live: no 200 HTML body in the sweep contains `BEGIN app/views`, and two
  GETs of the same page are byte-identical.

**R2: development-mode exception pages expose generated source and reveal
the twin's verdict (a genuine defect, `BUG-0055`).**

Confirmed live (§2a).

**Decision rule.** Fix by `consider_all_requests_local = false` in the
skeleton's `development.rb`. Do **not** switch the harness to
`RAILS_ENV=production` in this lane. Rails 8's `production.rb` brings
`force_ssl`/`assume_ssl`, eager loading, precompiled-asset expectations and
stricter secret handling, a separate surface this lane cannot verify inside
its own scope. That choice belongs to Lane 7's serving decision, which must
keep the PA-0057 check green. Fall back to production only if
implementation shows the development-mode setting does **not** suppress the
detailed page for some route (checked by the live sweep's
no-`Extracted source` assertion).

**Why this is folded in rather than flagged.**

1. Contract point 6 requires "the response a real anonymous visitor would
   get". This lane's own declared absent-input 4xx responses (§2d) are
   exactly those error pages, so shipping them as verdict-leaking debug
   dumps would make this lane's deliverable wrong.
2. It is LAB-only: a two-line skeleton config change with no new
   infrastructure.
3. It restores a documented cross-stack requirement the Rails port missed:
   `docs/LAB_IMPLEMENTATION_PLAN.md:775`'s "production-equivalent mode by
   default as a blanket rule". Each existing stack enforces it on its own:
   - `php_laravel`: `stack_env.py:83` `APP_DEBUG=false`;
   - `django`: `stack_env.py:151` `DEBUG = False`;
   - `node_express`: Dockerfile `NODE_ENV=production`;
   - `python_fastapi`: `main.py.j2:34` `docs_url=None`.

   `ruby_rails` has no equivalent.

A reviewer who judges this a different-class finding should say so. The
fallback is then to flag it with a recommended next `CC-LAB` number (after
Lanes 2–7's reservations, i.e. the one following `CC-LAB-0248` if that is
still the next free number at dispatch time) instead of folding it in.
Either way, the absent-input 4xx responses §2d declares would be served
through it.

**Blast radius of turning debug pages off (round-1 adequacy finding, its
own named step, §5 step 1a).** `consider_all_requests_local` governs every
4xx/5xx body Rails renders, not only the 400 above. It also replaces the
dev 404 page, which lists the full route table. So before the setting is
flipped, a dedicated check looks for anything that depends on debug-page
content. This is separate from R12's shape grep, which only looks for
JSON/plain-text body assertions.

- **Tests.** Grep `tests/` for debug-page-specific content: `Extracted
  source`, `Routing Error`, `Routes match in priority`, `Full Trace`,
  `Application Trace`, `Framework Trace`, `ActionController::RoutingError`,
  `ActionController::ParameterMissing`, `ActiveRecord::RecordNotFound`,
  `Rails.root`.
- **Detection code.** Grep `fuzzlab/` (outside the ruby_rails emitter and
  its harness) for the same strings, plus `ActiveRecord`/`ActionController`,
  since an oracle keyed on Rails error text would lose its signal.
- **Rails suites.** Re-run every Rails test that asserts a non-2xx status.
- **Result when this plan was revised (2026-09-25):**
  - **0 hits in `tests/`**;
  - **0 hits in `fuzzlab/`** outside the emitter and its harness (one
    unrelated docstring mention of "ActiveRecord" in
    `spring_boot/modules.py:555`);
  - the only Rails non-2xx assertion is
    `test_labgen_ruby_rails_webhook_signature_live_boot.py:104`
    (`tampered.status == 401`). That is the sink's own JSON 401, not a
    Rails error page, and it is unaffected.

**Standing check, not a one-time grep (added after round 2).** The same
string list and scope become the permanent offline test **O7** (§4). It
runs on every `pytest` invocation, so a *future* test or detection change
that starts depending on Rails debug-page content fails automatically,
instead of relying on someone remembering to repeat this grep. The
revision-time result above is O7's expected initial state. §5 step 1a gates
on O7 being green before the setting is flipped. Any hit O7 reports is
either updated to the static error page's contract or, if it is a detection
signal, treated under R11 as a possible regression. A hit is never simply
added to O7's allowlist.

**Side effect on the webhook api (round-2 note; before/after corrected in
round 3, checked against the installed Rails source).** Take a webhook POST
with `Content-Type: application/json` and a malformed JSON body. Rails'
parameter parser rejects it with a 400 before the controller runs, and the
receiver's own responses (`{"verified":…}`) are not involved.

- **Before this change** it was **not** a JSON error. `DebugExceptions`
  uses its API (JSON) renderer only when `api_request?` is true. That
  requires `@response_format == :api`
  (`actionpack-8.1.3.1/lib/action_dispatch/middleware/debug_exceptions.rb:206-208`),
  which is set only for a `config.api_only` app, and nothing in this
  skeleton sets `api_only`. So the response was the large interactive HTML
  debug page (`render_for_browser_request`, `:70-73`, `:80`).
- **After this change** the response comes from `PublicExceptions`
  (`public_exceptions.rb:25-46`):
  - for a request whose preferred format is HTML, the small static
    `public/400.html`;
  - if the client asked for another format it can serialise (for example
    `Accept: application/json`), a small `{"status":400,"error":"Bad
    Request"}` body in that format.

So the change is *large debug HTML → small static page*. It is not a
JSON-to-HTML format change.

**Which branch this lane's own console script hits (round 4; derived from
source, then confirmed live by §4 step 9d).** The §2c script's `fetch()`
sends `Content-Type: application/json` and the signature header, with **no
`Accept` override**, so the browser sends `Accept: */*`. In `PublicExceptions`
that resolves as follows (all in `actionpack-8.1.3.1/lib/action_dispatch/`):

1. `http/mime_negotiation.rb:72-92` (`formats`): `params_readable?` is
   `false` because the body does not parse (`:223-227`).
2. A lone `*/*` counts as a valid Accept header (`:229-232`), since
   `BROWSER_LIKE_ACCEPTS` requires a comma (`:221`). So `formats` is
   `[Mime::ALL]`, which survives the `ref == "*/*"` filter (`:86-88`).
3. `Mime::ALL` is `AllType` with symbol `nil` (`http/mime_type.rb:349-363`).
   So `PublicExceptions#render` builds the method name `"to_"`
   (`middleware/public_exceptions.rb:40`). The body hash does not respond to
   it, and control falls through to `render_html` (`:41-44`).

The console's own requests therefore **deterministically** get the static
HTML `public/400.html`. The JSON branch is reachable only by a client that
explicitly sends `Accept: application/json`, which this script never does.

The design rule for the §2c client page is unchanged. It reads
`response.text()`, attempts `JSON.parse` only inside a guard, and shows the
raw text when parsing fails. That guard is **defense in depth**, not a
response to live ambiguity: this script can reach only one branch. The guard
keeps the page correct if the script, the browser's default Accept, or Rails'
negotiation ever changes. O5 checks the guard offline, and §4 step 9d checks
the predicted branch live.

**One link cannot be settled from source.** The webhook action reads
`request.body.read` and never `params`, so whether Rails parses (and
rejects) the malformed body at all depends on something else touching the
params during the request. That is probably Action Controller's
instrumentation payload, which includes the filtered params. The predicted
outcome is `400`; §4 step 9d measures it.

**Decision rule:**
- If the live result matches (`400`, `text/html`, body equal to the
  skeleton's `public/400.html`), keep the assertion as written.
- If it differs (for example `401 {"verified":false}`, because nothing
  parsed the body), record the measured behavior here and in `CC-LAB-0245`,
  and assert that exact measured status/type instead.
- **Never** weaken the assertion to "HTML or JSON". In either case the
  guarded parse stays correct.

**Not changed:** `config.server_timing` (a `Server-Timing` response header
with per-request timings). It is response metadata, not a source or verdict
disclosure. It is recorded here and left to Lane 7's production-mode
decision.

**R3: CSRF posture must neither gain nor lose protection.**

`ApplicationController` calls `skip_forgery_protection` globally
(`application_controller.rb:23`); every cell's ground truth assumes
tokenless writes.

**Decision rule:**

- forms are plain `<form>`, never `form_with`/`form_tag`, which inject a
  per-request `authenticity_token` field that is random, breaks
  byte-identity, and implies protection that is not enforced;
- the layout renders no `csrf_meta_tags`;
- `skip_forgery_protection` is untouched.

An offline test asserts that no skeleton view calls `form_with`, `form_tag`
or `csrf_meta_tags`.

**R4: strong-parameters semantics and the fixed `shopper1` record.**

The mass-assignment sink updates `User.find_by!(username: "shopper1")`
(`orm_entity_bulk_assign.rb.j2:5`). A form that exposed `user[username]`
would let one ordinary submit rename `shopper1`. Every later request would
then raise `ActiveRecord::RecordNotFound` (404), breaking later probes and
tests in the same boot.

**Decision rule:** the customer form exposes **only** `user[bio]`, nested
under `user[...]` so `params.require(:user)`, `permit!` and
`permit(:username, :bio)` behave exactly as today. `user[role]` is what the
attacker adds. It is never a form field.

**R5: converting a JSON echo to HTML must not create a new vulnerability
class (contract point 3's "typical case").**

The mass-assignment response echoes attacker-controlled `role`/`bio`, and
the deserialization response echoes a class name. The measured pre-change
false alarm (§1h, `xss-reflected` on `/admin/customers/update`) shows the
XSS oracle already reacts to that JSON echo.

**Decision rule:**

- the result templates escape every echoed value with ERB `<%= %>`, never
  `raw`, so neither page becomes truly XSS-exploitable;
- ground truth gains **no** XSS case for these URLs;
- the mass-assignment verdict stays observable as the rendered `role` value.

After conversion, measure the multitarget report again (R11):

| Measured `fp` | Action |
|---|---|
| 0 | Pin it: assert `report.fp == 0` and `false_alarms == []` in `test_multitarget_ruby_rails_forgecart.py`, and record the mechanism that removed it. |
| still 1 | Pin `false_alarms` to exactly the one pre-existing key and flag the FUZZ-side cause as a different-class follow-up. |
| any new false alarm | Stop and investigate before proceeding. |

**R6: the webhook client page must not change the webhook vulnerability's
nature or distinguish the twins.**

Embedding the HMAC secret, or computing a valid signature in-page, would let
any visitor forge valid deliveries against the **secure** twin as well. That
changes the modelled class, since the vulnerability is a timing side channel
(D20 `partial`), not forgeability.

**Decision rule:**

- the page takes the signature as user input and never embeds or computes it;
- one shared view serves both topics, targets `location.pathname`, and
  interpolates nothing server-side;
- a live assertion: both GET bodies are byte-identical;
- an offline assertion: the view file does not contain the secret literal.

**R7: a live "< 500" sweep is too weak for this stack. The PA-0054
enforcement must compare against the declared status.**

The deserialization sink's catch-all `rescue => e`
(`object_deserialization.rb.j2:9`) turned `nil` reaching `YAML.*_load` into
a 200. A PA-0053/0054 sweep that asserts only "< 500" passes it, although
the absent value demonstrably reached the sink.

**Decision rule:**

- the live sweep asserts **equality with the declared bare-request status**
  (§2d, derived from `_ABSENT_INPUT_BY_SHAPE`, PA-0027), not a range;
- the offline check O1 is the authoritative declaration gate.

This is a strengthening of PA-0054's enforcement for this lane. Whether it
becomes a PA rule depends on §2d's bug decision rule: it is not a bug here,
so it is proposed through the plan and change-control entry, and folded into
`PA-0057`'s text only if `BUG-0055`'s root-cause analysis shows the same
failure mode.

**R8: catalog entries for POST/PATCH-only illustrative cells.**

A bare GET of `/cell/labgen_rr_0002` .. `0007` is a Rails 404 (no GET
route).

**Decision rule** (mirrors Lane 2's `_get_linkable` choice for Django's
`/api/login`):

- the catalog links only GET routes and lists the others unlinked with their
  verb;
- their bare GET 404 is the declared, accepted behavior. It is asserted as
  exactly 404 in the sweep, not merely < 500;
- a bare request with the route's own verb is also swept and must equal the
  declared status (§2d);
- no GET page is invented for illustrative sample cells: they have no ground
  truth and are not product pages.

**R9: `allow_browser versions: :modern` (`application_controller.rb:14`)
returns 406 to old-browser user agents.**

Confirmed live: a Chrome 49 UA got `406 Not Acceptable`. An unknown or
non-browser UA, such as `python-requests` or `Python-urllib`, gets 200.

**Decision rule:**

- keep it, as Rails 8's own default posture: not modelled data, and harmless
  to a real modern browser;
- the navigability crawl uses `LocalSpider`'s own `requests` session UA, so
  a green crawl proves fuzzlab's own client is not blocked;
- if any fuzzlab client (spider, `RequestsProbeSender`) is observed getting
  406, remove `allow_browser` in this lane instead.

**R10: static nav versus builds that lack the real-page cells.**

The layout's nav is fixed ForgeCart chrome, but a single-shape test build
(for example the webhook samples only) has no `/admin/customers/update`
route.

**Decision rule:**

- keep the nav static: ForgeCart is this emitter's one app identity, and
  single-shape builds are test fixtures that are never crawled;
- per-real-page GET routes are emitted only with their cell;
- an offline test asserts that every nav target is a route of the
  **whole-app** build (from the rendered `routes.rb`, §4 O3), so a nav link
  can never point at nothing in the build that is actually crawled.

**R11: detection must not regress (contract point 7).**

Baseline in §1h.

**Decision rule:**

- post-change, `FCART-0001` must still be in `matched`, `tp >= 1` and
  `tn == 1` (`FCART-0003`, the secure twin), and `fp` must not exceed 1 (see
  R5 for pinning);
- `FCART-0002`/`0004`/`0005` stay FN; their strategies fail closed on these
  shapes by design (§1h). No strategy is changed, so `CC-FUZZ-0051`/
  `FR-FUZZ-35` stay unused. They are used only if a strategy must change to
  keep an honest detection, which none of §1h's mechanisms requires.

Re-run `test_multitarget_ruby_rails_forgecart.py` and
`test_multitarget_category1_combined.py`, and quote the measured report.

**R12: existing tests assert the old shapes.**

- Known: `test_labgen_ruby_rails_whole_app_live_boot.py:93,97,101,105,149`
  assert JSON or plain text for `/products`, `/cart`, `/admin`,
  `/admin/orders` and `/admin/customers/update`. These are updated to the
  new HTML contract (asserting the same facts: empty state, rendered
  `role == admin`), not deleted.
- Before changing any template, re-grep the whole suite for every file
  that references `RailsEmitter`, `ruby_rails`, `forgecart` or `FCART-`,
  including `slow` files (PA-0044), and re-run each one explicitly.
- Expected untouched, because their shapes' JSON tails are byte-unchanged:
  the per-shape sample live-boot suites.
- PA-0045 applies: count the old-shape assertions per edited file and
  confirm that many were edited.
- This grep covers response shapes only. Dependencies on **debug-page**
  content (stack traces, the 404 route table, "Extracted source") have
  their own dedicated check in R2 ("Blast radius") and §5 step 1a.

**R13: vacuous pass and crawl depth.**

Same guards as `CC-LAB-0241`/`0242`:

- hard-coded, measured minimums for the ground-truth point count and the
  crawled-URL count, asserted before any per-URL check;
- depth measured, cap set with headroom, and the deepest ground-truth URL
  asserted strictly below the cap.

Expected depth is 1, since every ground-truth URL is in the layout nav; the
cap is 4.

**R14: anonymous access to merchant-admin pages.**

Confirmed that no auth exists (§1f).

**Decision rule:** assert 200 for every ground-truth URL, as the
anonymous-visitor status. If implementation finds any cell or route that
does gate on a session, stop and surface it; do not silently add a 401
expectation. Building a login wall is out of scope (§7).

**R15: `RailsLiveBootHarness` is its own class.**

- It exposes `_base_url()`, `request()`, `get()`, `post()` and `patch()`,
  never follows redirects, and returns non-2xx statuses rather than raising
  (`_NoRedirectHttpErrorProcessor`, `:158-172`).
- The crawl uses `LocalSpider`'s own `requests` session against
  `_base_url()`, with `trust_env = False` so the loopback target never goes
  through the ambient proxy (Lane 2 precedent).

**Mitigation:** actually run the crawl against it (§5 step 7); do not rely
on the API shape alone.

**R16: generated and skeleton code must stay syntactically valid Ruby and
minimal-pair clean.**

The template changes add Jinja branches to shared source and sink templates.

**Mitigation:** the existing tier0 `ruby -c` and naive minimal-pair tests
re-run green for all three sample manifests. The offline test also renders
every ruby_rails cell of every manifest plus `LABGEN-RR-0001` (PA-0024
whole-collection), and runs `ruby -c` on each controller that changed.

Accepted, not mitigated: none. Every risk above has a concrete verification
or fix step.

## 4. Navigability acceptance test and the PA-0054 checks (designed now)

### Offline: `tests/test_labgen_ruby_rails_browsable.py` (new, not `slow`)

- **O1 (PA-0054 part 1): declaration check over every route.** For every
  `ruby_rails`-supported cell of every `lab/manifests/*.yaml`, plus
  `LABGEN-RR-0001`, derived through `RailsEmitter().supports()` (PA-0027):
  - every named input the cell's source reads has an `_ABSENT_INPUT_BY_SHAPE`
    entry;
  - the rendered controller contains that declaration's construct
    (`params.fetch(:q, "")`, `params.require(:yaml_payload)`,
    `params.require(:user)`, `request.headers[...].to_s`);
  - it does **not** contain a bare `params[:<name>]` read of a declared
    input.
- **O1-neg (PA-0034(2) adversarial self-test).**
  - Run O1's checker function against a monkeypatched declaration table
    missing one entry, and against a source template rendered without its
    default. The checker must report the violation both times.
  - This proves the check can fail, and is not validated only against the
    currently-clean codebase.
- **O2.** The layout structure test (R1/R3): the nav groups are sorted, no
  forbidden helpers, inline `<style>`, and no external `src=`/`href=` to
  another host.
- **O3.** Every nav target is a route in the rendered whole-app `routes.rb`
  (R10). Every `_REAL_PAGE_PROFILES` URL is a ground-truth URL, and its
  `kind` matches §1e's table (`kind == "api"` exactly for `FCART-0002`/`0003`).
- **O4.** `route_fragment_for` emits the GET page line for exactly the
  profiles with `get_page`, and `render_file` still rejects a duplicate
  URL.
- **O5.** No skeleton view contains `form_with`, `form_tag` or
  `csrf_meta_tags` (R3). The webhook console view does not contain the
  webhook secret literal (R6). Its script sends no `Accept` override, which
  is what R2's branch derivation assumes. And it parses the response only
  inside a guard (`try`/`catch`, falling back to the raw text), as defense in
  depth: per R2, this script's own error path deterministically receives
  HTML, and §4 step 9d confirms that live.
- **O6 (PA-0057 offline half, final wording set by `BUG-0055`).** The
  skeleton's `development.rb` sets `consider_all_requests_local = false` and
  `annotate_rendered_view_with_filenames = false`. Also a cross-emitter debug
  check (see §6's bug item), which covers every emitter's known
  debug-disabling setting.
- **O7 (standing debug-page-dependency check, R2).** It scans every `*.py`
  file under `tests/` and `fuzzlab/` for the R2 string list:
  `Extracted source`, `Routing Error`, `Routes match in priority`,
  `Full Trace`, `Application Trace`, `Framework Trace`,
  `ActionController::RoutingError`, `ActionController::ParameterMissing`,
  `ActiveRecord::RecordNotFound`, `Rails.root`.

  It skips three kinds of file:
  - `fuzzlab/labgen/emitters/ruby_rails/` and
    `fuzzlab/labgen/conformance/rails_live_boot.py`, which generate or boot
    the app rather than consume its error pages;
  - `__pycache__`;
  - a **pinned, explicit allowlist of exactly 2 files** that name these
    strings only to assert their **absence**:
    - `tests/test_labgen_ruby_rails_browsable.py`, which is O7's own file,
      since every O-check lives there, and so is also where O7 lists the
      strings;
    - `tests/test_labgen_ruby_rails_navigability_live_boot.py` (§4 step 7).

  The allowlist is a literal set in the test. Adding to it needs a code
  change reviewed like any other, never a pattern match. O7 fails on any
  other hit and names the file and line.
- **O7-neg (PA-0034(2)): checks both directions.** O7's scanner takes the
  scan root as a parameter. Exclusions and the allowlist are matched on
  paths relative to that root, by exact equality or exact directory prefix,
  never by substring or glob. The scanner is called on a synthetic temporary
  tree holding six planted files, each containing one of the listed strings:
  - **Must be reported** (the positive path):
    - (p1) a non-allowlisted `tests/test_synthetic_scrape.py` containing
      `Extracted source`;
    - (p2) `fuzzlab/synthetic_oracle.py` containing
      `ActionController::RoutingError`.
  - **Must NOT be reported** (exclusions are honoured; round-3 addition):
    - (n1) `fuzzlab/labgen/emitters/ruby_rails/synthetic_module.py`, a hit
      inside the emitter exclusion;
    - (n2) `tests/test_labgen_ruby_rails_browsable.py`, a hit in a file with
      an allowlisted name.
  - **Must still be reported** (exclusions are exact, not broad; this guards
    against O7 being too loose):
    - (m1) `fuzzlab/labgen/emitters/ruby_rails_extra/synthetic.py`, a
      sibling that merely shares the excluded directory's name as a prefix;
    - (m2) `tests/test_labgen_ruby_rails_browsable_extra.py`, a name that
      merely extends an allowlisted one.

  The test asserts the reported set is **exactly** {p1, p2, m1, m2}. That
  proves the check can fail, and that neither the directory exclusion nor
  the allowlist quietly swallows a real hit next to it.

### Live: `tests/test_labgen_ruby_rails_navigability_live_boot.py` (new, `slow`)

Skip-guarded on `rails_boot_available()`.

1. **Build and crawl.** Boot the 12-cell whole-app build with
   `RailsLiveBootHarness` (module-scoped fixture). Crawl from `/` with
   `fuzzlab.tools.spider.LocalSpider` (`requests` engine, same host,
   `trust_env = False`, `max_depth = 4`).
2. **Non-vacuous guards first (R13).** ground-truth points
   `>= _MIN_GROUND_TRUTH_POINTS` (5); crawled URLs `>= _MIN_DISCOVERED_PAGES`
   (hard-coded from the measured count, with headroom).
3. `GET /` returns 200, both in the crawl and directly.
4. **Every ground-truth URL is discovered** and has the anonymous status:
   `_EXPECTED_STATUS = {"/search": 200, "/webhooks/orders/create": 200,
   "/webhooks/customers/update": 200, "/admin/customers/update": 200,
   "/admin/products/import": 200}`. The set equals the ground-truth URL set
   exactly, so nothing is silently skipped. The deepest ground-truth URL is
   below the cap.
5. **Link-reachability.** Every GET route of the build except `/up` (every
   skeleton page, `/catalog`, `/search`, the GET form and client pages, and
   `/cell/labgen_rr_0001` via `/catalog`) is among the crawled pages.
6. **PA-0053/PA-0054 sweep over every served route.** Routes come from the
   rendered `config/routes.rb`, parsed by a new `served_routes()` helper in
   `route_accumulator.py`, not from the crawl. For every `(verb, path)`:
   - a bare `GET` of the path gets 200 if a GET route exists for it, else
     404 (R8);
   - a bare request with the route's **own verb** (no query, no body)
     returns exactly the status declared in `_ABSENT_INPUT_BY_SHAPE`
     (webhooks 401, mass assignment 400, deserialization 400), per R7;
   - no crawled URL, with or without a query string, answers ≥ 500 or
     status 0.
7. **`BUG-0055` regression (R1/R2).**
   - Every non-2xx body from step 6 contains none of: `Extracted source`,
     `labgen`, `Module composition`, `permit`, `YAML.`.
   - Every 200 HTML body contains no `BEGIN app/views`.
   - `/catalog`'s body is exempt from the `labgen` check only, because it
     lists `/cell/labgen_…` routes by design.
8. **Twin page identity (R6).** The GET bodies of `/webhooks/orders/create`
   and `/webhooks/customers/update` are byte-identical. Two GETs of `/` are
   byte-identical (no per-request token, R1/R3).
9. **Per-page functional checks**, the §5 page gates.
   - `GET /search?q=<b>x</b>` reflects raw inside the layout.
   - The customer form POST with `user[role]=admin` renders `role` = `admin`,
     escaped.
   - The import form POST with an `OpenStruct` tag renders "OpenStruct".
   - The webhook POST contract is unchanged (valid signature → 200 JSON
     `{"verified":true}`).
   - **(9d) the console's error path, measured (round 4).** POST a malformed
     JSON body (`{"order_id": `) to both `/webhooks/orders/create` and
     `/webhooks/customers/update`, with exactly the headers the §2c script
     sends: `Content-Type: application/json`,
     `X-Shopify-Hmac-SHA256: <any>`, `Accept: */*`.
     - Assert the R2-predicted branch: status `400`, `Content-Type`
       starting `text/html`, and a body byte-equal to the skeleton's
       `public/400.html`.
     - Also assert it contains no `Extracted source`.
     - On a mismatch, apply R2's decision rule (record the measured result
       and assert it exactly), never a looser "HTML or JSON" assertion.
     - This closes the loop between R2's source-derived prediction and
       execution.

   Session note: the crawl is itself a multi-request, same-session run
   (PA-0037(2)).

## 5. Sequencing (each step's gate must be green before the next)

1. **Skeleton hygiene (§2a).**
   - **1a (must pass before the setting is flipped):** add the standing
     offline check **O7** (R2's blast-radius check over `tests/` and
     `fuzzlab/`, §4) together with its adversarial self-test O7-neg, and get
     both green. Every hit is resolved per R2 before step 1 continues. From
     then on O7 runs on every test invocation; it is not a manual step.
   - *Gate:* O6 green.
   - *Live:* whole-app boots, and a bare `POST /admin/customers/update`
     returns 400 with **no** `Extracted source` and no `permit`. Before the
     fix, it reproduces `BUG-0055` on the `HEAD` emitter (already done in
     this plan's research; repeat and record in the bug doc).
   - `test_labgen_ruby_rails_live_boot.py` green.
2. **Absent-input declarations and source templates (§2d).**
   - *Gate:* O1 + O1-neg green; the three offline sample suites (tier0
     `ruby -c`, minimal pair, tier3) green; the per-shape live suites for
     deserialization, mass assignment and webhooks green.
3. **Layout, homepage, inert pages and `/catalog` (§2b).**
   - *Gate:* O2, O3, O5 green.
   - *Live:* each skeleton page returns 200 inside the layout.
   - `test_labgen_ruby_rails_whole_app_live_boot.py` updated per R12 and
     green.
4. **`/search`, the customer form/result and the import form/result
   (§2c).** One page at a time. Each page's gate:
   - (i) its bare GET returns 200 inside the layout;
   - (ii) its bare own-verb request returns its declared status;
   - (iii) its §4 step-9 functional check passes live;
   - (iv) O4 green.
5. **Webhook client page (§2c, R6).**
   - *Gate:* both GETs return 200 and are byte-identical; the per-shape
     webhook live suite is green (wire contract unchanged).
6. **Ground-truth `rendering` correction (§2e).**
   - *Gate:* `contract.load("lab/ground-truth-forgecart")` succeeds; the
     PA-0044 grep list is re-run.
7. **Build and run the navigability test (§4 live).**
   - Fill in the measured minimums and depth.
   - **Scope-creep rule** (restated from `CC-LAB-0241`/`0242`): fold a
     crawl-surfaced defect into this entry only if it is the *same class* as
     this plan's tracked work and touches only the LAB component's
     `ruby_rails` emitter/skeleton. Same class means a missing nav link, a
     missing absent-input declaration, a page outside the layout, or a
     debug/annotation leak in a served response. Anything else gets flagged
     as a named follow-up with its own recommended next `CC-LAB` number (not
     invented here), and does not block this step's Effectiveness for the
     tracked pages.
8. **Detection non-regression (R11/R5).** Re-run both multitarget modules and
   the measurement; apply R5's pinning rule.
9. **Full verification.**
   - the full non-slow suite (`pytest -m "not slow"`);
   - **every** `ruby_rails` suite run explicitly (PA-0038): the 4 offline
     (3 existing + 1 new) and 8 live (6 existing + the 2 multitarget
     modules), plus the new navigability test.

   Quote each file's pass count.

## 6. Deliverables checklist

- [ ] Skeleton `development.rb`: `consider_all_requests_local = false`,
      `annotate_rendered_view_with_filenames = false` (§2a, R1/R2); O6
      green; live no-debug-page check green.
- [ ] Standing offline check **O7** (no test or detection code depends on
      Rails debug-page content; pinned absence-only allowlist) plus its
      adversarial self-test O7-neg, added and green **before** the setting
      above is flipped (§5 step 1a, R2). It is a permanent test, not a
      one-time grep.
- [ ] `_ABSENT_INPUT_BY_SHAPE` declarations and source-template constructs
      (§2d); O1 + O1-neg green; bare `POST /admin/products/import` → 400
      before the sink (was 200 with `nil` in the sink).
- [ ] ForgeCart layout, homepage, HTML inert pages and `/catalog` (§2b); O2,
      O3, O5 green; whole-app live test updated (R12) and green.
- [ ] `/search` in the layout; customer and import GET form pages and escaped
      HTML result pages (§2c, R4/R5); each page's §5 step-4 gate green.
- [ ] Webhook `fetch()` client page for both topics, no secret, byte-identical
      (§2c, R6); JSON wire contract unchanged (webhook live suite green);
      the console's malformed-JSON error branch is asserted live at R2's
      predicted (or, per R2's decision rule, measured) status/content type
      (§4 step 9d).
- [ ] Ground-truth `rendering` for `FCART-0004`/`0005` → `server`, in both
      points and cases (§2e).
- [ ] Navigability test (§4) built and green: non-vacuous guards, 100%
      ground-truth discovery with anonymous status, link-reachability,
      the PA-0054 sweep of every served route at the **declared** status
      (R7), and the `BUG-0055` regression checks.
- [ ] Any same-class defect the navigability test surfaces fixed and folded
      in; any different-class finding flagged with its own recommended next
      `CC-LAB` number, not absorbed (§5 step 7).
- [ ] Detection non-regression measured and pinned per R5/R11; both
      multitarget modules green.
- [ ] Full non-slow suite plus every `ruby_rails` suite green, per-file counts
      quoted (PA-0038).
- [ ] **Bug protocol for `BUG-0055`** (R2, the development-mode debug-page
      verdict leak, reproduced live pre-change):
  - an `ERROR_LOG.md` entry (added **Open** with this plan; flipped to
    Fixed at implementation);
  - `docs/bugs/BUG-0055-*.md` with a full RCA (Five Whys) and a recurrence
    review against `BUG-0051`/`PA-0053` and `BUG-0052`/`PA-0054` (the
    absent-input class this lane was also asked to check) and against the
    debug-page requirement's own history (`CC-LAB-0090`'s `DEBUG = False`,
    `php_laravel`'s `APP_DEBUG=false`,
    `docs/LAB_IMPLEMENTATION_PLAN.md:775`), including a
    prior-preventive-action failure analysis where a match is found;
  - `PA-0057` in `docs/PREVENTIVE_ACTIONS.md`, with mechanical, cross-emitter
    enforcement (not prose);
  - a PA-0002 sweep of every emitter's debug posture. Any instance found in
    an emitter this lane does not own is pinned by an offline failing or
    strict-xfail check, per PA-0054(3), and flagged to the orchestrator
    because Lanes 3, 4 and 6 are running concurrently.
- [ ] If the §2d bug decision rule, applied to implementation-time
      measurements, finds an additional defect: state it. `BUG-0055`/`PA-0057`
      are the only reserved numbers. Needing a second pair means bumping
      Lanes 6–7's BUG/PA reservations in `docs/LAB_BROWSABLE_APPS_PLAN.md`
      immediately and flagging it. If none is found, say so explicitly in
      Effectiveness.
- [ ] `docs/components/01-target-lab/requirements.md`: new `FR-LAB-166`
      entry (ForgeCart browsable, page/api classification, absent-input
      declarations, debug-page posture). `FR-LAB-81`/`FR-LAB-83` are
      cross-referenced in place where their JSON/plain-text descriptions are
      superseded.
- [ ] `docs/ARCHITECTURE.md`: the `ruby_rails`/ForgeCart build-status line
      updated (Lane 2 precedent).
- [ ] `CHANGELOG.md`: one dated line referencing `CC-LAB-0245`.
- [ ] `docs/LAB_BROWSABLE_APPS_PLAN.md`: Lane 5 row updated to done, with the
      numbers actually used. If more than one `CC-LAB` number was needed,
      bump Lanes 6–7 immediately.

## 7. Out of scope

- A login wall for `/admin` (R14): no manifest cell models auth.
- Switching the harness to `RAILS_ENV=production`, and compose/port-8090
  serving. Both are Lane 7, which must keep PA-0057's check green.
- New vulnerability cells or new detection strategies, including making
  `FCART-0002`/`0004`/`0005` detectable. `CC-FUZZ-0051`/`FR-FUZZ-35` stay
  unused unless R11's rule requires them.
- The `ReflectedXssStrategy`-on-JSON false alarm's FUZZ-side cause, beyond
  measuring whether the conversion removes it (R5).
- Other lanes' stacks, except the PA-0002 debug-posture sweep, which pins
  and flags but does not fix another lane's emitter.

## 8. Review history

**Drafting-time note (superseded by the actual round 1 below): the
drafting agent could not run round 1.** The dispatch specified two independent
reviewer subagents (accuracy + adequacy) spawned with the drafting agent's
own Agent tool, iterated to 3/3 agreement.

- **Mechanism status.** This agent has no Agent tool. It tried one
  alternative: creating a separate cloud session through the
  `create_session` tool, intended only as a disclosed stand-in reviewer. The
  **permission classifier denied it**, and a later live-boot probe script in
  the same session was denied under the same ruling.
- **No workaround and no substitute.** Per the denial's terms and
  `docs/MULTI_AGENT_ORCHESTRATION.md` §4, the agent pursued neither, and did
  **not** substitute a self-review for an independent one.
- **Nothing is claimed.** No reviewer agreement exists, and none is claimed.
- **What was done instead.** The drafting agent re-checked its own file:line
  citations against the working tree before committing. That check is not a
  review and counts for nothing toward the 3/3 gate.
- **Next step, for a session with the reviewer mechanism.** Run round 1
  (accuracy: every citation above; adequacy: risk completeness, decision
  rules, PA-0054 application, draftability of §6) against this document as
  written.
- **Implementation stays unauthorized** until this plan and the
  `CC-LAB-0245` draft each clear their own gate.

**Round 1, actually run (accuracy + adequacy, 2 independent reviewer
agents, 2026-09-25).** Since the drafting agent had no Agent tool, the
**orchestrating session** spawned the reviewers itself; this is a disclosed
change of who dispatched them, not a self-review. Result: **ACCURATE /
ADEQUATE with 2 minor gaps.**

- **Accuracy: no inaccuracies.** The reviewer reproduced the findings
  live:
  - the `BUG-0055` debug-page leak on **both** twins
    (`permit_bang_unrestricted` versus `strong_params_explicit_allowlist` in
    the "Extracted source" section of each twin's 400 page);
  - the §1h detection baseline, exactly (tp=1/fp=1/tn=1/fn=3);
  - all of the Rails gotchas, including the `allow_browser` 406 with an old
    Chrome UA.
- **Adequacy: 2 non-blocking gaps, both fixed in this revision per the
  project's fix-anyway discipline.**
  1. **No explicit blast-radius check for turning debug pages off.** R12's
     grep was scoped to JSON/plain-text shape assertions, but
     `consider_all_requests_local` also governs the 404 route-table page.
     Fixed: R2 gets its own "Blast radius" check, run over both `tests/`
     and `fuzzlab/` detection code at revision time (0 hits in either; the
     only Rails non-2xx assertion is the sink's own JSON 401). It becomes
     §5 step 1a, a gate that must pass before the setting is flipped, and
     R12 cross-references it.
  2. **The link between §2d's bug rule and R7 was left implicit.** Fixed:
     §2d now states directly why "defeats detection without crashing" stays
     outside the bug trigger. The missing-`yaml_payload` path is never sent
     by a detection probe. `FCART-0005` was already a known false negative
     in the measured baseline, for an unrelated reason (the strategy's JSON
     gate). The detection it does defeat is the absent-input sweep, which
     R7 addresses. A guard re-applies the rule if the post-change
     measurement contradicts this.

   **Clarification recorded rather than silently absorbed:** the round-1
   note said the `rescue` "bakes in a false negative for that ground-truth
   cell". The revised §2d explains why that attribution does not hold
   (reasons 1 and 2). The reviewer's requested fix, making the connection
   explicit, is applied in full.
- **Next:** round-2 confirmation by the same two reviewers.

**Round 2 (same 2 reviewers, dispatched by the orchestrating session,
2026-09-25): ACCURATE / NOT ADEQUATE, 1 gap.**

- **Confirmed adequate:** the §2d/R7 reconciliation. The reviewer
  independently verified, via `strategies.py:993`, the drafting agent's
  pushback on "bakes in a false negative by construction", and agrees with
  it. Side-effect coverage and R7's test design were also confirmed.
- **Gap:** the round-1 blast-radius grep was a **one-time** step ("re-run at
  implementation time"). A future test or detection change that depends on
  Rails debug-page content would not be caught automatically; the live
  step-7 regression check guards the app's responses, not the test and
  detection code.
  - **Fixed:** the grep becomes the permanent offline check **O7** (§4). It
    uses the same string list and scope, and runs on every test invocation.
  - Its allowlist of absence-only files is pinned and literal.
  - It has its own adversarial self-test, O7-neg (PA-0034(2)).
  - R2, §5 step 1a and §6 now reference O7 as a standing test, not a manual
    step.
- **Optional note, applied:** with debug pages off, a malformed-JSON webhook
  POST now gets the static HTML `public/400.html`, not JSON.
  - It is recorded under R2.
  - The §2c client page must parse the response only inside a guard,
    falling back to the raw text.
  - O5 checks this offline.
- **Next:** round-3 confirmation.

**Round 3 (adequacy reviewer, dispatched by the orchestrating session,
2026-09-25): NOT ADEQUATE, 1 narrow gap.** The accuracy reviewer's round 3
had not reported when this fix was made.

- **Gap:** O7-neg only proved the positive detection path. Nothing checked
  that the emitter/harness exclusion or the allowlist does *not* over-match.
  A broad skip could quietly swallow a real regression.
- **Fixed:** O7-neg's synthetic tree now also plants:
  - a hit under the emitter exclusion (n1) and a hit in an
    allowlisted-name file (n2), both of which must **not** be reported;
  - two near-miss files (m1, m2), one sharing the excluded directory's name
    as a prefix and one extending an allowlisted name. Both **must** still
    be reported.

  The test asserts the exact reported set, and O7's matching is specified as
  exact path or exact directory prefix, never substring. This makes O7-neg
  prove both that exclusions are honoured and that they are not broader than
  intended. The reviewer judged this a refinement of the existing design,
  not a new risk item.
- **Next:** round-4 confirmation.

**Round 3 (accuracy reviewer): NOT ACCURATE, 1 real inaccuracy plus 1
wording cleanup.** Both are fixed in this revision. The O7 spec, the
`CC-LAB-0245` draft update and the round-2 record were confirmed accurate.

1. **Inaccuracy.** R2's webhook side-effect note said a malformed-JSON POST
   went from "a JSON-shaped Rails error" to HTML. That premise was false:
   `DebugExceptions#api_request?` requires `@response_format == :api`
   (`debug_exceptions.rb:206-208`), which only a `config.api_only` app has,
   so the pre-change response was already HTML (the large debug page).
   - **Corrected** to *large debug HTML → small static `PublicExceptions`
     response*.
   - The drafting agent re-checked the source while fixing this and added
     one precision: `public_exceptions.rb:25-46` answers in the request's
     own format when it can serialise to it. The "after" body is therefore
     `public/400.html` for an HTML-preferring request, but a small JSON
     `{status, error}` body for `Accept: application/json`.
   - The guarded-parse design rule (O5) is unchanged. Its rationale is
     restated as "the error body may be HTML or JSON depending on `Accept`".
   - The `CC-LAB-0245` mirror is corrected the same way.
2. **Wording.** O7's allowlist was worded as three files, but "O7's own
   file" *is* `tests/test_labgen_ruby_rails_browsable.py`. It is reworded as
   exactly 2 files.
- **Next:** round-4 confirmation.

**Round 4 (dispatched by the orchestrating session, 2026-09-25): ACCURATE /
NOT ADEQUATE, 1 gap.** The accuracy reviewer re-checked every debug-page
claim against the installed gem source and found no errors.

- **Gap:** R2 presented the post-change error body as "HTML or JSON
  depending on Accept", as if both were live outcomes for this lane's
  console, without tracing which branch the console script actually hits.
- **Fixed:**
  - R2 now derives the branch from source: no `Accept` override means
    `*/*`, which means `Mime::ALL` with symbol `nil`, which means
    `render_html`. The drafting agent re-verified each step against
    `mime_negotiation.rb` and `mime_type.rb` before writing it. R2 states
    plainly that the script deterministically gets the static HTML 400, and
    that the guarded parse is defense in depth.
  - O5 also pins "no `Accept` override" in the script.
  - A live assertion, §4 step 9d, POSTs a malformed JSON body with the
    script's exact headers to both topics. It asserts `400` + `text/html` +
    a body byte-equal to `public/400.html`.
- **Drafting agent's addition:** one link in the chain cannot be settled from
  source. The action never reads `params`, so whether the body is parsed at
  all depends on instrumentation. R2 flags this explicitly and adds a
  decision rule: on a mismatch, record the measured behavior and assert it
  exactly, never a looser "either" assertion.
- **Next:** round-5 confirmation.
