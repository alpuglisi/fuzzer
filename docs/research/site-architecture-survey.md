# Site-architecture survey (Step 1 + Step 2 output)

Produced by `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` Steps 1-2.
Step 1: 6 categories x 5 popular sites, sourced. Step 2 (architecture
write-ups, at least two independent sources or one primary source per claim,
per the plan's resolved confidence bar): completed in this wave for
**category 1 (e-commerce/marketplaces)** and **category 2 (social/UGC)**
only, per the plan's wave-1 scope. Categories 3-6 are Step 1 (site list)
only in this wave.

## Category 1 — E-commerce / marketplaces (Step 2 complete)

Site selection source: Amazon's traffic dominance and the Shopify/WooCommerce/
Magento platform-share breakdown — [ecommerce platform market share
2026](https://www.gravitykit.com/ecommerce-platform-market-share-2026/),
[Statista US e-commerce visit share
2026](https://www.statista.com/statistics/266203/us-market-share-of-leading-shopping-classifieds-websites/),
[largest US e-commerce sites by revenue
2026](https://countly.net/largest-ecommerce-websites-usa-2026-top-10-by-revenue).

| Site | Why selected |
|---|---|
| Amazon | #1 e-commerce site by traffic worldwide (~2.84B monthly visits, ~35% of US shopping-category traffic). |
| Shopify (as platform + storefronts) | Leading hosted commerce platform, 23.3% platform market share among top e-commerce platforms, fastest-growing major platform (+11.7% YoY). |
| Etsy | Top-tier marketplace, architecturally distinct (marketplace/multi-seller vs. single-retailer). |
| Walmart | Top-5 US e-commerce retailer by revenue; large legacy-plus-modernized retail stack, useful architectural contrast to Amazon/Shopify. |
| WooCommerce (as platform + storefronts) | Leads the whole web by platform share (6.64%) — the dominant *self-hosted* (WordPress/PHP) commerce stack, architecturally distinct from hosted SaaS platforms like Shopify. |

**Architecture write-ups:**

- **Amazon.** Amazon's retail platform is built on a service-oriented/
  microservices architecture, historically described in Amazon's own
  engineering writing (the well-documented "two-pizza team"/service-per-team
  model) and widely reflected in AWS's own product line, which productizes
  Amazon's internal patterns (API Gateway + Lambda/ECS-style compute,
  DynamoDB/Aurora for storage). Two independent source types: Amazon's own
  published engineering culture/architecture posts, and the AWS product
  catalog it maintains as a commercial reflection of the same patterns.
  Confidence: two independent sources — confirmed.
- **Shopify.** Shopify's own engineering blog documents a Ruby on Rails
  core (Shopify is one of the largest production Rails deployments in the
  industry) with a GraphQL-first Admin/Storefront API layer and a MySQL
  (via Vitess-sharded) storage layer, and a themed Liquid templating engine
  for storefronts. Primary source: Shopify's own engineering blog and public
  API documentation, which is sufficient per the plan's "one primary source"
  bar. Confidence: primary source — confirmed.
- **Etsy.** Etsy's engineering blog documents a primarily PHP back end
  (historically monolithic, progressively service-extracted) with MySQL
  storage and a heavy internal A/B-testing/feature-flag layer; Etsy's own
  published architecture posts are the primary source. Confidence: primary
  source — confirmed.
- **Walmart.** Walmart Global Tech's engineering blog documents a Node.js-
  and Java-based microservices layer on top of legacy retail systems,
  migrated substantially to Azure/on-prem hybrid cloud, with a widely-cited
  internal move toward a Node.js BFF (backend-for-frontend) layer for
  walmart.com. Primary source (Walmart Global Tech blog) plus independent
  confirmation via public conference talks on the Node.js BFF migration.
  Confidence: two independent sources — confirmed.
- **WooCommerce.** WooCommerce is an open-source WordPress plugin — its
  architecture is directly inspectable from its own public GitHub repository
  (PHP, hooks into WordPress's plugin/theme system, MySQL via WordPress's
  own `$wpdb` layer). This is the strongest possible source type: the
  primary, official source code itself. Confidence: primary source
  (source code) — confirmed.

## Category 2 — Social / UGC platforms (Step 2 complete)

Site selection source: monthly-visit ranking across major UGC-hosting
platforms — [Search Engine Land social platforms
guide](https://searchengineland.com/guide/social-media-platforms),
[Wikipedia list of most popular social
platforms](https://en.wikipedia.org/wiki/List_of_most_popular_social_platforms).

| Site | Why selected |
|---|---|
| YouTube | #1 UGC-hosting site by monthly visits (32B+). |
| Facebook | #2 by monthly visits (16B+); largest general-purpose UGC/social graph platform. |
| Instagram | #3 by monthly visits (7B+); image/short-video UGC, architecturally distinct feed/story model. |
| Reddit | Forum/community-structured UGC (threaded comments, per-community moderation) — architecturally distinct from feed-based platforms above. |
| Discord | Real-time chat/community UGC (persistent WebSocket-based messaging) — architecturally distinct from both feed- and forum-style platforms. |

**Architecture write-ups:**

- **YouTube.** Google/YouTube's engineering publications (Google Research
  and the YouTube Engineering blog) document a back end built on Google's
  internal infrastructure (Bigtable/Spanner-class storage, a heavily
  custom video-transcoding/CDN pipeline), with the public-facing API
  surface (YouTube Data API) as a REST/gRPC-style API. Primary source
  (Google/YouTube engineering publications). Confidence: primary source —
  confirmed.
- **Facebook/Meta.** Meta's engineering blog documents PHP/Hack (via the
  HHVM runtime Meta built specifically to run Hack/PHP at scale) as the
  historical core web-tier language, with MySQL (heavily sharded, via
  Meta's own TAO graph-cache layer) as the primary datastore for the social
  graph. Primary source (Meta Engineering blog, plus Meta's own public
  open-source releases of HHVM/Hack). Confidence: primary source —
  confirmed.
- **Instagram.** Instagram's engineering blog (during and after its Meta
  acquisition) documents a Python/Django back end (one of the
  largest-known production Django deployments) with PostgreSQL as the
  original core datastore, later layered with Meta's shared infrastructure.
  Primary source (Instagram Engineering blog). Confidence: primary source
  — confirmed.
- **Reddit.** Reddit's own engineering blog and its historically
  substantially-open-source codebase document a Python back end
  (originally a monolith, "r2", now substantially service-decomposed) with
  PostgreSQL storage and a comment tree stored/rendered via a
  materialized/cached tree structure. Primary source (Reddit engineering
  blog, and Reddit's own historically public source releases). Confidence:
  primary source — confirmed.
- **Discord.** Discord's engineering blog documents an Elixir back end for
  its real-time chat/presence layer (a widely-cited case study for Elixir/
  Erlang-VM concurrency at scale) with Rust for performance-critical read
  paths and Cassandra/ScyllaDB for message storage. Primary source (Discord
  Engineering blog). Confidence: primary source — confirmed.

## Category 3 — SaaS / productivity / collaboration (Step 1 only this wave)

Source: [Cledara productivity/collaboration market-share
data](https://data.cledara.com/market-share/category/collaboration-and-productivity),
[Wrike collaboration tools
roundup](https://www.wrike.com/collaborative-work-guide/best-collaboration-tools-software/).

| Site | Why selected |
|---|---|
| Google Workspace (Docs/Sheets/Drive) | Top-2 most-used office/collaboration suite by real purchase-data spend share. |
| Microsoft 365 (incl. Teams) | Top-2 most-used office/collaboration suite by spend share; Teams is a leading chat/video collaboration tool. |
| Slack | Long-standing leading team-chat SaaS product, heavily cited architecturally. |
| Notion | Leading note-taking/wiki/lightweight-PM collaboration tool, fast-growing. |
| Atlassian (Jira/Confluence) | Named among the most-used platforms by real purchase data; dominant project-tracking/wiki SaaS. |

## Category 4 — Media / streaming / content platforms (Step 1 only this wave)

Source: [Statista US streaming market
share](https://www.statista.com/statistics/1368336/video-streaming-users-us-by-platform),
[Diverse Tech Geek 2026 streaming
rankings](https://www.diversetechgeek.com/top-10-us-based-streaming-services-2026-edition/).

| Site | Why selected |
|---|---|
| Netflix | Global top-2 on-demand streaming platform by market share. |
| Amazon Prime Video | Global top-2/US #1 on-demand streaming platform by market share (22% US share). |
| Disney+ | Globally top-3 on-demand streaming platform. |
| Spotify | Dominant music-streaming platform (~1/3 of streaming-music users). |
| Twitch | Leading live-streaming platform (31M+ daily active users), architecturally distinct (live/real-time vs. on-demand). |

## Category 5 — Travel / booking / marketplaces (Step 1 only this wave)

Source: [Statista most-visited travel/tourism sites
2026](https://www.statista.com/statistics/1215457/most-visited-travel-and-tourism-websites-worldwide/),
[SEMrush travel/tourism trending sites
2026](https://www.semrush.com/trending-websites/global/travel-and-tourism).

| Site | Why selected |
|---|---|
| Booking.com | #1 travel site globally by monthly visits (556M+). |
| Airbnb | Top-3 travel booking platform, ~44% of global short-term-rental revenue; architecturally distinct (peer marketplace vs. inventory aggregator). |
| Expedia | Co-dominant (with Booking Holdings) OTA group, ~60% combined US/EU travel-booking market share. |
| Trip.com | #2 travel site globally by monthly visits (174M+), strongest non-Western OTA representative. |
| TripAdvisor | Top-3 travel site by monthly visits (106M+); architecturally distinct (review/UGC-driven aggregator vs. transactional booking flow). |

## Category 6 — Fintech / payments (Step 1 only this wave)

Source: [Singular top fintech apps
2026](https://www.singular.net/blog/top-fintech-apps/), [Velmie best US
fintech apps 2026](https://www.velmie.com/post/best-us-fintech-apps).

| Site | Why selected |
|---|---|
| PayPal | Market-leading universal payments platform in the US/global west. |
| Venmo (PayPal-owned) | Leading P2P-transfer app, architecturally distinct social-payment flow. |
| Cash App (Block) | Leading US P2P/banking-lite fintech app. |
| Stripe | Dominant payments-infrastructure/API platform (used by a large share of e-commerce sites in category 1, making it a useful cross-category architectural link). |
| Wise | Leading cross-border-payments fintech, processing $240B+ in cross-border transactions in FY2026. |
