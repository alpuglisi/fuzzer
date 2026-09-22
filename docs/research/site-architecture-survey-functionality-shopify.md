# Shopify — functionality research + Rails-specific CWE shortlist

Produced for `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.5 step 2-3
(category 1 pilot, E-commerce, Shopify/Ruby-on-Rails pick). Closes the
functionality-research gap `docs/research/site-architecture-survey.md`'s
Category-1 entry left open (architecture only, no per-site feature
breakdown) for Shopify specifically. Architecture facts (Rails core,
GraphQL-first API, Vitess-sharded MySQL, Liquid templating) are **not**
re-researched here — carried over unchanged from that document's own
confirmed entry.

**Sourcing caveat, upfront:** direct fetch of `shopify.dev` failed in this
sandbox (network egress proxy blocks the domain outright). All
`shopify.dev`-sourced claims below are relayed through WebSearch's own
snippet/summary of that page, not a direct page read — still Shopify's own
primary documentation content, just intermediated. Flagged per-claim below
where it matters. CVE numbers cited were relayed via WebSearch/NVD-listing
summaries, not independently re-verified against nvd.nist.gov directly —
recommend a direct NVD lookup before citing them in any future
`change-control.md`/`requirements.md` entry if precision matters.

## 1. Shopify functionality/pages

**Storefront**

- **Product catalog/browsing & PDP** — server-rendered via Shopify's
  Liquid templating engine over product/collection data. *(Primary source:
  Shopify engineering blog/public docs, already cited in the base
  architecture survey — confidence: primary source.)*
- **Cart** — a cart object built client/server-side before checkout
  hand-off.
- **Checkout** — a distinct, tightly-controlled, PCI-scoped subsystem
  ("Shopify pod"), separate from the theme-rendered monolith flow so card
  data never touches it. Supports **Shopify Functions**, a serverless
  customization layer letting merchant-installed logic (discount
  eligibility, custom shipping rules) run inline during checkout. *(Sources:
  Shopify's own blog on checkout integration/serverless architecture,
  shopify.com/blog/checkout-integration, shopify.com/blog/serverless-
  architecture, plus an InfoQ writeup of a Shopify flash-sale-architecture
  talk — two independent sources, confidence: two independent sources.)*
- **Discount codes at checkout** — applied via `discountCodeBasicCreate`-
  style Admin GraphQL mutations merchant-side, validated against a
  `DiscountCodeNode`/`DiscountCode` object at redemption (percentage,
  fixed-amount, free-shipping types). *(Primary source: shopify.dev Admin
  GraphQL/REST API reference — relayed via search snippet, see caveat
  above.)*
- **Customer accounts, search** — standard storefront surfaces exist in
  every theme; **not independently confirmed** beyond the generic
  theme/API surface (no Shopify-specific engineering deep-dive on search
  internals found) — treat as standard, not richly sourced.

**Admin/merchant side**

- **Product/inventory editing** — Admin REST or, increasingly, GraphQL
  Admin API (Shopify is pushing merchants/apps toward GraphQL; some newer
  resources are GraphQL-only). *(Primary source: shopify.dev, relayed.)*
- **Customer data view/export** — Admin API customer resources exist;
  **export mechanics not independently confirmed** — flagged as
  unconfirmed rather than guessed.
- **Webhook configuration** — merchants/apps subscribe to events (order
  created, product updated, etc.), delivered as signed HTTPS POSTs, or via
  Google Cloud Pub/Sub or Amazon EventBridge (those two channels do not
  carry/need the HMAC header). *(Primary source: shopify.dev/docs/apps/
  build/webhooks/verify-deliveries and .../subscribe/https, relayed.)*

**Shopify app/webhook ecosystem (the strongest concrete finding)**

- Every HTTPS webhook delivery carries a base64-encoded HMAC-SHA256
  signature in the `X-Shopify-Hmac-SHA256` header, computed over the
  **raw** request body using the app's client secret as key.
- Correct verification: (a) use the raw body (not re-serialized/parsed —
  order/whitespace-sensitive), (b) recompute HMAC-SHA256 with the shared
  secret, (c) compare to the header value — by general HMAC-verification
  best practice, with a constant-time compare, though this exact detail
  was not found as a literal Shopify quote in the fetched snippets
  (flagged as best-practice inference, not a direct quote).
- Secret rotation has a documented up-to-one-hour grace window where old
  and new secrets may both validate. *(Sourced via WebSearch snippets of
  the shopify.dev page plus two independent secondary write-ups — Hookdeck
  and dev.to's Shopify-webhook guides.)*
- **Directly relevant:** this maps onto this project's existing
  `docs/research/corpus-examples/webhook-signature/` class (currently
  Node-only). A Rails-side implementation — using Rails' own
  `ActiveSupport::SecurityUtils.secure_compare` idiom (secure) vs. a naive
  `==` comparison that skips the timing-safe helper (vulnerable) — is a
  realistic, idiomatic Rails-specific vulnerable/secure pair for this
  exact real mechanism.

## 2. Rails-specific CWE shortlist

| # | CWE | Why Rails-specific | Shopify page/flow | Corpus status |
|---|---|---|---|---|
| 1 | **CWE-915** (mass assignment) | Rails' Active Record + `ActionController::Parameters#permit!` (vs. `.permit(:a, :b)`) is the textbook Rails footgun. Canonical real incident: the 2012 Homakov/GitHub mass-assignment breach against a Rails app — the reason Rails 4+ made strong parameters default-on, though `permit!` still opts back out. | Admin product/inventory edit (a merchant-only field like `role`/`published`/`price` left in an unguarded `permit!` update action), or a customer-account update endpoint. | Already in corpus (`mass-assignment/`) but never as a **Ruby/Rails-idiomatic** instance (the `permit!` shape is unique to Rails). **Genuinely new as an idiom.** Two independent sources (Wikipedia mass-assignment entry + PentesterLab/Acunetix/CodeQL Rails-specific writeups). |
| 2 | **CWE-89**, identifier-position via `order`/`pluck`/`reorder` accepting raw SQL fragments/column names | Documented Rails/Active-Record-specific footgun distinct from value-position SQLi: `pluck`/`order`/`reorder` historically accepted arbitrary SQL strings (deprecated in Rails 6.0, disallowed for `pluck` in 6.1), with real CVEs (CVE-2012-2660/2661/2695, CVE-2013-0155, CVE-2016-6317; CVE-2017-17920 on `reorder` was disputed by Rails as "not intended for untrusted input" — a real, documented footgun regardless). | Admin product search/sort UI (sort-by-column on a product/order list), or a storefront collection-sort parameter. | Value-position CWE-89 already heavily covered. The **identifier-position `order`/`pluck` variant** is genuinely new as a Rails instance — this project's PHP corpus already values exactly this identifier-vs-value distinction. Two independent sources (Justin Collins/Brakeman's blog, vibeappscanner.com, NVD listings) — **CVE numbers not independently re-verified against NVD**, flag before formal citation. |
| 3 | **CWE-502** (insecure deserialization) via `YAML.load`/`Psych.load` (not `safe_load`) | Real, severe Rails-specific historical CVE: **CVE-2013-0156** — Rails' XML parameter parser accepted embedded YAML, deserialized via Psych, and Psych's `init_with` hook allows arbitrary object instantiation → unauthenticated RCE across essentially all contemporary Rails apps. A framework-parsing-layer defect, not a generic pattern. | A Shopify-app-side webhook payload handler accepting a non-JSON body format, or an admin bulk-import feature (e.g. "import products from YAML/CSV with embedded metadata"). | Already in corpus (`insecure-deserialization/`, Python-only) — genuinely new as a **Rails/`Psych.load`** instance (Ruby's mechanism, not Python's pickle-equivalent). Two-plus independent sources (Rapid7's original 2013 disclosure, GitHub PoC gists, Brakeman's own warning-class docs). |
| 4 | CWE-79 (XSS) via `raw()`/`html_safe`/`<%== %>` bypassing ERB auto-escaping | Real Rails/ERB-specific idiom, distinct code shape from PHP's unescaped-`echo` pattern already in corpus. | Storefront review/description rendering, admin-configured banner text via a theme partial. | CWE-79 is **already very heavily covered** across the corpus — **deprioritized** for CWE-ID-breadth purposes even though the Rails idiom itself would be new. Two independent sources (StackHawk, Semgrep Rails cheat sheet, OWASP Ruby-on-Rails cheat sheet). |
| 5 | CWE-601 (open redirect) / CWE-918 (SSRF) via `redirect_to` not validating host by default | Rails' `redirect_to` sets the `Location` header directly from a URL string with no default host allowlist — chains into SSRF when a webhook-callback/OAuth-style flow lets a merchant/app supply a callback URL the server then fetches. | Shopify-app OAuth install/callback flow, or a merchant-configurable webhook-target URL setting. | Both CWE IDs **already in corpus** (`header-injection/php` has CWE-601; `ssrf/php` has CWE-918) — not new IDs, though a Rails `redirect_to`/`Net::HTTP` instance would be a new idiomatic shape. **Weaker sourcing** (single aggregated WebSearch summary for the Rails-specific behavior claim) — verify against Rails' own `redirect_to` docs before implementation. |

**Recommendation for genuine CWE-ID breadth** (per §0a item 4's "expand,
don't duplicate" instruction): **CWE-915** (mass assignment, `permit!`
idiom) and **CWE-502** (Psych/YAML deserialization) are the two strongest
picks — both IDs exist elsewhere in the corpus but never as a Ruby/Rails
instance, both have primary-source-grade real historical incidents tightly
bound to Rails-the-framework. The `order`/`pluck` identifier-position SQLi
variant is a strong third pick for the same reason PHP's identifier-
position shapes were valued. CWE-79/601/918 are real and Rails-idiomatic
but don't expand ID breadth — deprioritize unless page design specifically
needs a checkout/webhook realism story that wants them anyway.

## 3. Confidence/sourcing summary

- Architecture-level Shopify facts carried over unchanged from
  `docs/research/site-architecture-survey.md`'s already-confirmed entry
  (primary source, per that doc's own rating) — not re-researched here.
- `shopify.dev`-sourced claims are relayed via WebSearch snippets, not a
  direct fetch (domain blocked by this sandbox's egress proxy) — still
  primary content, just intermediated.
- CVE numbers are search-relayed, not independently re-verified against
  nvd.nist.gov in this session.
- Storefront search internals and Admin customer-export mechanics could
  not be confirmed beyond "the API surface exists" — flagged unconfirmed,
  not guessed.
- Everything else (2012 GitHub breach, `html_safe`/`raw` XSS mechanics,
  Psych/YAML root cause, `pluck`/`order` deprecation history) had two or
  more independent sources agreeing, matching the base survey's own
  "two independent sources" confidence tier.
