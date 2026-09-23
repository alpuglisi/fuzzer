# Category 2 (Social / UGC platforms) — site-pair pick, functionality research, stack-specific CWE research

Produced per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.5-equivalent
ordering for category 2 (functionality research → CWE research → *then*
build), closing the gaps §0a items 2-3 identified: per-site feature research
and stack-specific CWE research, neither of which existed yet for this
category. This document is the category-2 pilot's research phase; §2 below
records the site-pair pick itself with the §9.1 methodology applied.

## 1. Site-pair selection (§9.1 methodology applied to category 2's 5 sites)

Category 2's 5 researched sites (`docs/research/site-architecture-survey.md`
§"Category 2"): YouTube, Facebook, Instagram, Reddit, Discord.

**Step 1 — filter out sites that aren't a sensible generator target:**
- **YouTube** — excluded. Google/YouTube's own engineering publications
  document Bigtable/Spanner-class internal infrastructure and a heavily
  custom transcoding/CDN pipeline, but no confirmed application-language
  claim at the level Instagram's Django or Facebook's PHP/Hack have (the
  survey's own write-up is infrastructure-only, not application-code-level).
  Same exclusion class as Amazon (category 1) and Disney+/Trip.com
  (categories 4/5).
- **Discord** — excluded. Its documented architecture (Elixir/Erlang-VM
  real-time chat and presence layer, persistent WebSocket-based messaging)
  is fundamentally a realtime/protocol system, not the request/response
  HTTP application this generator's `Cell`/`Route`/`Pipeline` IR models —
  the same exclusion reasoning §9.1 step 1 gives for Discord by name.

**Step 2 — group the remaining 3 by (language, architectural paradigm):**
- **Facebook** — PHP/Hack (via HHVM), synchronous web-tier serving a
  sharded-MySQL/TAO-backed social graph. Its own group.
- **Instagram** — Python/Django, a synchronous MVC monolith (one of the
  largest known production Django deployments) over PostgreSQL.
- **Reddit** — Python, originally a monolith ("r2"), now substantially
  service-decomposed, over PostgreSQL. Same language as Instagram and the
  same "synchronous monolith" paradigm — not architecturally distinct from
  Instagram for this purpose, per §9.1 step 2's own worked example (it gives
  exactly this kind of same-language/same-paradigm collapse as the reason
  Etsy and WooCommerce, both PHP, don't count as two distinct picks).

**Step 3 — pick the 2 groups most different from each other:**
PHP/Hack (Facebook) vs. Python/Django (Instagram) is the maximally distinct
pair among the 3 remaining candidates — different language, different
templating/ORM idiom, different framework-level guardrail posture. Reddit is
dropped as redundant with Instagram's group, not because it's a weaker site.

**Step 4 — reuse-vs-new check (distinctness still wins if it conflicts):**
- **Facebook → reuse.** PHP is already a built stack (`php_current`/
  `php_laravel`, §9.2 ledger). Facebook's real backend is specifically
  PHP/Hack on HHVM, not vanilla PHP — a literal HHVM/Hack runtime emitter
  would be new, disproportionate work for what it buys: the vulnerability
  *shapes* this project models (injection into a template/ORM/dynamic-eval
  sink, deserialization, SSRF, header injection, signature bypass) render
  idiomatically in PHP just as they would in Hack, since Hack is a gradually-
  typed superset of PHP rather than a different language family. Approximate
  Facebook's stack via `php_current`/`php_laravel`, and record the
  corpus-grounded content (real Facebook features, real Meta-documented
  storage/graph model) as what makes this pick distinct — not the runtime.
  This is the explicit judgment call §9.4's own prior note on this category
  flagged as needing to be made and recorded here.
- **Instagram → new stack.** No existing emitter models Django's paradigm.
  `python_fastapi` is Python but async-API-shaped (Pydantic-typed request/
  response, not template-rendering MVC) — a different paradigm per §9.2's
  own explicit note ("this is NOT the same stack as Django"). A `django`
  emitter is new, comparably-scoped work to category 1's Ruby-on-Rails pick
  (§9.4 row 1) — the biggest single piece of this category's build.

**Result:** Facebook (PHP/Hack, approximated via `php_current`/`php_laravel`)
+ Instagram (Python/Django, new emitter). No collision with category 1's
picks (Rails, Node/Express) or with any other stack already in the §9.2
ledger.

## 2. Instagram — functionality research (closing §0a item 2's gap)

Source: Instagram Engineering's own published blog posts (the primary
source the site-architecture survey already cites for the Django/PostgreSQL
architecture claim), cross-referenced against Instagram's own public-facing
product surface (which is directly observable, not merely reported).
Confidence: primary source (engineering blog) for the backend-stack framing
below, direct product observation for the feature list itself — the same
confidence bar the architecture survey already applied.

Real, cited feature set this app's page/route set should reflect:

1. **Home feed** — a chronological/ranked timeline of posts (photo/video +
   caption) from accounts the user follows.
2. **Stories** — ephemeral (24h) photo/video posts, viewed in a
   full-screen sequential viewer, with a "seen by" list visible to the
   poster.
3. **Post detail + comments** — a single post's photo/video, caption, like
   count, and a threaded (reply-to-comment) comment list; comments support
   `@mention` and `#hashtag` tokens rendered as links.
4. **Direct messages (inbox)** — a request/response-shaped inbox and
   thread view (kept request/response for this generator's IR; the
   real product's live-delivery layer is out of scope, matching how
   Discord's realtime layer was excluded above rather than approximated).
5. **Profile page** — bio text, a single external "website" link field,
   follower/following counts, and a grid of the account's own posts.
6. **Explore / search** — search across accounts and hashtags, and an
   algorithmically-selected explore grid.
7. **Upload flow** — photo/video upload with a caption field, hashtag/
   mention parsing, and (recorded here because it is the origin of a real
   Django-idiomatic vulnerability class below) an optional "add link"
   step that fetches a preview of an external URL the user pastes in
   (link-unfurl-style preview, a widely-implemented UGC-platform feature).
8. **Account settings** — privacy toggle (public/private account),
   profile-field edits (bio, name, external link), and notification
   preferences.

## 3. Facebook — functionality research (closing §0a item 2's gap)

Source: Meta's own Engineering blog (the primary source the architecture
survey already cites for PHP/Hack+HHVM and the MySQL/TAO graph-cache
model), cross-referenced against Facebook's own public product surface.

Real, cited feature set:

1. **News feed** — ranked posts from friends/pages, each with per-post
   audience/privacy setting (public/friends/only-me), like/reaction
   counts, and comments.
2. **Comments + reactions** on a post, including nested (reply-to-comment)
   threads.
3. **Friend requests / social graph** — send/accept/reject a friend
   request; a friends list; each relationship gates visibility of
   friends-only content (the real product's `TAO`-graph-backed
   permission model, approximated here as an ownership/membership check
   in the generated app, matching how `ownership_check_bypass` already
   models IDOR-shaped checks elsewhere in this lab).
4. **Photo albums + tagging** — an album of photos with a per-album
   privacy setting, and tagging another account in a photo (which the
   real product surfaces to the tagged account regardless of the
   album's own visibility setting — a realistic place for an
   authorization-check gap).
5. **Groups notifications / webhook-style integration** — Meta's own
   publicly documented Messenger Platform webhook contract (an
   `X-Hub-Signature`-verified POST callback) is a well-known, realistic
   integration surface for a Facebook-shaped app to model — kept here as
   a page/route (an inbound webhook receiver for a "connected app"
   notification), not the full realtime chat layer.
6. **Privacy settings** — per-post and per-album audience selector,
   plus an account-level default-audience setting.

## 4. Django-specific CWE research (tied to Instagram's real features, not just the abstract vuln class)

Researched against `https://cwe.mitre.org/top25/`, this project's existing
MITRE-index-lookup discipline, and well-documented, widely-cited Django
framework-specific footguns (not general Python knowledge) — checked
against `lab/safety_matrix.yaml`'s current op vocabulary so picks add
breadth (§0a item 4) rather than reintroduce a class already at full depth
on `php_laravel`.

| Real Instagram feature (§2) | Django-specific footgun | CWE | Breadth check |
|---|---|---|---|
| Upload flow's optional link-preview fetch | An unfurl/preview view that does `requests.get(user_supplied_url)` with no hostname allowlist or private-IP/metadata-endpoint block before fetching | CWE-918 (SSRF) | `ssrf/python` corpus dir already exists (framework-agnostic); this adds the Django-idiomatic view-level shape and a realistic feature-origin (link preview), not a duplicate. |
| Comments (mentions/hashtags rendered as links) | A dev disabling Django's default autoescaping for exactly this reason — rendering `@mention`/`#hashtag` spans as real `<a>` tags — via `mark_safe()`, the `\|safe` template filter, or `{% autoescape off %}`, without re-sanitizing the surrounding free-text comment body | CWE-79 (XSS) | `ugc-xss/python` corpus dir already has a Django-comments example; extends it with the specific realistic trigger (mention/hashtag auto-linking) rather than a generic "unescaped output" case. |
| Account settings (profile-field edits) / upload flow | A `ModelForm` (or DRF serializer) with `fields = "__all__"` (or a stale `exclude` list) on the account/profile model, letting a POST body set fields never exposed on the real settings form — e.g. `is_verified`/`is_staff`-shaped flags on a profile model, or another account's `user_id` foreign key on a comment/post-edit form | CWE-915 (mass assignment) | Already a matrix class (`mass_assignment` op); this is the Django-`ModelForm`-specific idiom (`fields = "__all__"`), distinct from the existing PHP/Node sinks, not a duplicate stack. |
| Search (hashtag/account search + sort) | Search/explore "sort by" built via `.extra()`, `RawSQL()`, or an f-string-interpolated `.raw()` call instead of the ORM's normal parameterized `.filter()`/`.order_by()` — the realistic Django escape hatch developers reach for when the ORM "can't express" a ranking query | CWE-89 (SQLi, identifier/ORDER-BY position) | Matrix already has `sql_order_by_injection`/`sql_identifier_substitution`; this is the Django-specific sink (`.extra()`/`RawSQL()`), a new idiom, still additive rather than a straight port. |
| Inbox / DM thread (request/response-shaped, per §2 item 4) | Session/cache data using `PickleSerializer` (Django ships JSON as the safe default but `django.contrib.sessions.serializers.PickleSerializer` is a real, documented opt-in some apps still use for non-JSON-safe session payloads) deserializing attacker-influenced cookie/cache data | CWE-502 (insecure deserialization) | `insecure-deserialization/python` corpus dir already exists; this adds the Django-session-serializer-specific realistic trigger. |
| Groups/webhook-style notification receiver (if folded into Instagram's own app rather than only Facebook's, TBD at manifest-design time) | `@csrf_exempt` on a JSON/webhook-receiving view (a real, common Django pattern for any inbound webhook, since Django's CSRF protection assumes a browser-submitted form) with no compensating signature/HMAC check on the exempted view | CWE-352 (CSRF) / CWE-345 (bypass) | New class for this stack; ties directly into `webhook-signature` corpus dir's existing coverage, extending it to Django's specific exemption mechanism. |

## 5. PHP/Hack-specific CWE research (tied to Facebook's real features)

Researched the same way — MITRE CWE Top 25, this project's existing
per-snippet CWE discipline, and well-documented PHP-framework-level
footguns — applied to Facebook's real feature set (§3), and checked for
breadth against what `php_current`/`php_laravel` already cover at depth
(SQLi value/identifier position, XSS body/attribute/DOM, IDOR/
`ownership_check_bypass`, JWT algorithm confusion, weak token entropy,
stale authorization state, price-integrity bypass, TOCTOU race conditions,
unrestricted file upload, path traversal, `ORDER BY` injection, SSTI, XXE,
mass assignment — per `lab/safety_matrix.yaml`'s existing op list).

| Real Facebook feature (§3) | PHP-specific footgun | CWE | Breadth check |
|---|---|---|---|
| Photo albums + tagging (privacy gap between album-level and tag-visibility) | A tagged-photo detail endpoint that checks "does the requester own this photo/album" but not "is this album's audience setting actually friends-only for this requester" — i.e., an ownership check that's present but checks the wrong scope | CWE-639 (IDOR / broken object-level authorization) | Existing `ownership_check_bypass` op — this is a *new page/feature origin* (tag visibility vs. album privacy mismatch) for an already-modeled class, which is legitimate depth-building, not padding, since the plan explicitly wants corpus-grounded *realistic placement*, not merely a new class per page. |
| Groups/webhook-style notification receiver | An inbound webhook endpoint verifying (or failing to verify) Meta's own documented `X-Hub-Signature`/`X-Hub-Signature-256` header using `==`/`strcmp()` instead of `hash_equals()`, or a receiver that never checks the signature at all | CWE-345 (bypass) / CWE-303 (improper auth) | `webhook-signature` corpus dir already exists; `constant_time_compare` op exists in the matrix but has been used for outbound/other contexts — this grounds it in a realistic *inbound receiver* specifically, matching a real, named Meta webhook contract. |
| News feed / comments "share to" or redirect-after-action flow | A `header("Location: " . $_GET['next'])`-shaped redirect built directly from an unvalidated `next`/`redirect_to` query parameter, without an open-redirect allowlist or a CRLF-stripping check, permitting a `\r\n`-carrying value to inject additional response headers | CWE-113 (HTTP response splitting / header injection) | `header-injection` corpus dir already exists; new realistic trigger (post/comment "share" redirect) -- built `CC-LAB-0218` (CircleFeed §6 row 3), this project's first real implementation of the matrix's `http_response_header_value` sink family. |
| Account/session preference storage (e.g., "remember my last-viewed album" or a signed preference cookie) | `unserialize()` called directly on an attacker-controlled cookie or cached value, with no `allowed_classes` restriction (PHP's own documented `unserialize()` footgun and the classic POP-gadget-chain CWE-502 pattern, distinct from `insecure-deserialization`'s existing Node/PHP/Python corpus entries if those don't already cover the bare-`unserialize()`-on-cookie shape specifically) | CWE-502 (insecure deserialization) | `insecure-deserialization/php` corpus dir already exists — verified at build time (`CC-LAB-0220`): neither `vulnerable-apcu-session-unserialize-5.php` (an APCu cache entry keyed by session ID) nor `vulnerable-laravel-raw-command-1.php` (a queued-job command's raw branch) is a cookie-read shape at all, so the bare-`unserialize()`-on-cookie shape is genuinely new, not a duplicate — **built** (`CC-LAB-0220`, §6 row 4). |

## 6. Page-set design (Phase C, §4 step 1) — PicTrail (Instagram/Django) and CircleFeed (Facebook/PHP)

Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 step 1: "a coherent
page/route set spanning the chosen vulnerability classes... not a loose bag
of unrelated illustrative cells." App identities (never reusing
`puppy-fort-factory`'s or `php_laravel`'s case-ID namespace, per §4's own
requirement): **PicTrail** (Instagram-style, built on `django`) and
**CircleFeed** (Facebook-style, built on `php_current`/`php_laravel`) —
original, clearly-fictional names, not the real platforms' own branding,
modeling their real functionality per §2/§3 above.

Each row below names the real feature it's grounded in (§2/§3), the CWE
research backing it (§4/§5), and its build status. Not every page needs a
brand-new emitter shape — reusing an already-proven generic shape (SQLi
numeric-literal) on a real, named, corpus-grounded route is itself a valid
way to stand up an app's identity/ground-truth machinery, per the
"reflect what would be observed in real life" bar (§0a item 5): a
photo-detail page with an unvalidated numeric ID is exactly the realistic
shape a real Instagram-style post-detail endpoint would have, whether or
not the specific *sink mechanism* is the newest researched one.

**PicTrail (Instagram/Django) page set:**

| # | Page (route) | Real feature (§2) | Vuln class / CWE | Shape | Status |
|---|---|---|---|---|---|
| 1 | Post detail (`/post?id=`) | §2 item 3, post detail + comments | `sqli` / CWE-89 | Reuses the existing, proven `sql_numeric_literal` shape (Phase A/B) | **Built this session** — see below. |
| 2 | Comments (`/post/comments`) | §2 item 3, `@mention`/`#hashtag` auto-linking | `xss` / CWE-79 | The researched, Django-specific footgun (§4 row 2): `mark_safe()` disabling template autoescaping — new template-rendering emitter infrastructure (a real `.html` template file, not a raw `HttpResponse` string). No request parameter (a stored-field read, like Phase B's `/api/profile` — the same `read_stored_field` source shape, matching that page's own no-`?id=` convention). A deliberately simplified, generic `mark_safe()`-on-raw-value shape, not the full `@mention`/`#hashtag` auto-linking shape (stays a later increment, row 2's own column above still names the fuller researched feature). | **Built this session** (`CC-LAB-0093`). |
| 3 | Link-preview unfurl (`/upload/link-preview`) | §2 item 7, upload flow's link preview | `ssrf` / CWE-918 | New sink category: `requests.get()` fetch with no scheme/resolved-IP check (§4 row 1), reusing `lab/safety_matrix.yaml`'s existing `server_side_http_fetch` family unchanged. Ports `docs/research/corpus-examples/ssrf/python/{vulnerable,idiomatic}-oembed-unfurl-4.py` almost verbatim. | **Built this session** (`CC-LAB-0094`). |
| 4 | Account settings (`/settings`) | §2 item 8 | `mass_assignment` / CWE-915 | Whole-POST-body dict source feeding a raw parameterized multi-column `UPDATE` sink (reusing this emitter's established "raw `connection.cursor()`, never the ORM" convention, `CC-LAB-0090`'s own reasoning, rather than a `ModelForm`) — `unfiltered_body_update` (SQL-column-name hygiene only) vs. `runtime_field_allowlist` (the real security boundary), reusing `lab/safety_matrix.yaml`'s existing `orm_entity_bulk_assign` sink family unchanged. | **Built this session** (`CC-LAB-0095`). |
| 5 | Explore/search (`/explore?sort=`) | §2 item 6 | `sqli` (identifier/`ORDER BY` position) | Raw `connection.cursor()` `ORDER BY " + str(sort)` concatenation instead of the ORM's parameterized `.order_by()` (§4 row 4) — `orm_order_by_unvalidated` vs. `identifier_allowlist`, reusing `lab/safety_matrix.yaml`'s existing `sql_order_by_clause` sink family (this project's first real implementation of it, on any stack). | **Built this session** (`CC-LAB-0096`). |
| 6 | DM inbox (`/inbox`) | §2 item 4 | `insecure_deserialization` / CWE-502 | `PickleSerializer`'s real footgun ported onto a base64-encoded inbox-message payload (this emitter has no session-middleware round trip to exercise a real cookie) — `unrestricted_pickle_loads` vs. `json_loads_type_check` (§4 row 5), reusing `lab/safety_matrix.yaml`'s existing `object_deserialization` sink family unchanged. This emitter's first sink whose deserialize *mechanism* differs between twins (a flag-only transform + Jinja2-time-interpolated sink, porting `ruby_rails`'s own `yaml_unsafe_load`/`yaml_safe_load` convention). | **Built this session** (`CC-LAB-0097`). |

**CircleFeed (Facebook/PHP) page set:**

| # | Page (route) | Real feature (§3) | Vuln class / CWE | Shape | Status |
|---|---|---|---|---|---|
| 1 | Photo/tag detail | §3 item 4, tagging vs. album privacy | `access_control` (IDOR) / CWE-639 | Reuses the existing `ownership_check_bypass` op, new page-origin — `no_ownership_check` (`Photo::where('id', $id)->firstOrFail()`, no owner check) vs. `identity_match_before_fetch` (a real `->where('owner_id', ...)` clause on the fetch itself), at the `db_row_by_id_lookup` sink family — this project's first real implementation of `access_control` on any stack | **Built this session** (`CC-LAB-0216`). |
| 2 | Groups webhook receiver | §3 item 5, Messenger-style webhook | `webhook_signature` / CWE-345 | New realistic inbound-receiver trigger (§5 row 2) | **Built this session** (`CC-LAB-0217`) — reuses the exact `webhook_signature_bypass`/`webhook_signature_verification` module composition Huddle Hub's own `/webhooks/events` cell already registers (`CC-LAB-0133`, `loose_equality_compare`/`constant_time_compare` at the same sink family), via a new `/groups/webhook` page profile (own lab-only secret) and manifest — pure wiring, no new transform/sink module. |
| 3 | Comment "share" redirect | §3 item 1/2 | `header_injection` / CWE-113 | New realistic trigger (§5 row 3) | **Built this session** (`CC-LAB-0218`) — this project's first real implementation of `lab/safety_matrix.yaml`'s `http_response_header_value` sink family (`raw_socket_response_write`/`allowlist_and_runtime_crlf_rejection`). PHP's own `header()` function has unconditionally rejected an embedded CR/LF since PHP 5.1.2 (empirically re-verified), so the genuine, real-executed response-splitting differential is proven at the raw-socket layer, not through the generated Laravel route directly — see `CC-LAB-0218`'s change-control entry. |
| 4 | Session/preference cookie | account settings | `insecure_deserialization` / CWE-502 | Bare `unserialize()` on a cookie value (§5 row 4) | **Built this session** (`CC-LAB-0220`) — this project's first real implementation of `lab/safety_matrix.yaml`'s `object_deserialization` sink family's PHP pair (`unrestricted_unserialize`/`json_decode_type_check`, both ops existed unimplemented since the family was added). Verified at build time (§5 row 4's own caveat) that the existing `insecure-deserialization/php` corpus does not already cover this bare-`unserialize()`-on-a-cookie shape. Ports `CC-LAB-0097`'s (PicTrail `/inbox`, Python pickle/JSON) and `CC-LAB-0074`'s (`ruby_rails`, YAML unsafe/safe load) "flag-only transform, sink branches at generation time" convention into PHP; a new, real, autoloadable skeleton class (`App\Support\MarkerWriteGadget`) provides the PHP `__wakeup()`-magic-method analogue of `CC-LAB-0097`'s pickle `__reduce__` RCE proof, verified by a real, executed live-boot test (a genuine marker file written on disk). **CircleFeed's own full four-page designed set is now complete.** |

**Sequencing note:** PicTrail's page 1 lands this session (proving the
app-identity/ground-truth pattern end to end for the first time on this
stack). Every other row is real, sized, next work — not attempted here.
Each new shape (rows needing "new template-rendering infrastructure" or a
wholly new sink module) should get its own change-control entry and
pre-change review, following the same discipline Phase A/B already used,
rather than batching several brand-new shapes into one entry.

**Route-notation correction (`CC-LAB-0092`'s own pre-change review,
reflected back here per the same discipline `CC-LAB-0131`'s TrackerNest
route simplification already established for this exact situation):**
rows 1-2 above were originally written as `/post/<id>` /
`/post/<id>/comments` (a path-parameter URL shape). This codebase's
`fuzzlab.labgen.schema.Route.path` is a plain string key, with no
path-parameter templating, and every emitter (`DjangoEmitter` included)
looks up a cell's route profile by exact-matching `cell.route.path` as a
literal dict key — so a `<id>`-templated path segment cannot actually be
emitted as designed. Corrected to the query-parameter shape (`/post?id=`)
every other real page in this project already uses (`php_current`'s own
`/product.php?id=`, Phase A/B's own `/api/products?id=`) — a real,
plausible URL shape for a page like this (query-string post lookups are
common in real apps, including older/legacy versions of real platforms),
not a step down from "corpus-grounded," just a notation correction to
match what this generator's `Route` IR can actually express today.

## 7. What this research does not yet do

- Does not compute the exact `(vuln_class, sink_family)` gap against
  `lab/safety_matrix.yaml` the way Phase B's own task 1 requires — that is
  explicitly a Phase B (module-inventory) task, done once the emitter/stack
  decisions below are final, not estimated here.
- Does not design the actual `labels.json`/`injection-points.json` ground
  truth or manifest cells (Phase C, per-app, once Phase A's Django skeleton
  exists) — this is the CWE-to-feature *mapping*, not the implementation.
- Does not build the Django emitter itself. Per `CLAUDE.md`'s pre-change
  review gate, a component-code change of this size (a brand-new emitter,
  comparable in scope to category 1's Rails pick) needs a change-control
  entry drafted first, reviewed by 2 independent reviewer agents, and 3/3
  agreement, before implementation begins — that gate has not run yet.
