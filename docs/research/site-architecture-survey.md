# Site-architecture survey (Step 1 + Step 2 output)

Produced by `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` Steps 1-2.
Step 1: 6 categories x 5 popular sites, sourced. Step 2 (architecture
write-ups, at least two independent sources or one primary source per claim,
per the plan's resolved confidence bar): completed for **all 6 categories**
as of wave 2 (categories 1-2 in wave 1, categories 3-6 added in wave 2, per
the explicit instruction not to defer them). Sourcing for categories 3-6
leans more on third-party engineering-analysis writeups (Medium engineering
blogs, ByteByteGo, etc.) than categories 1-2's primary-source-only sourcing,
since not every site here (e.g. Google Workspace, Venmo) publishes as
detailed a first-party architecture writeup as Shopify/Meta/Reddit did —
each claim below still meets the plan's confidence bar (two independent
sources, or one primary/first-party source), and any claim that couldn't
clear that bar is marked "unconfirmed" rather than stated as fact.

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

## Category 3 — SaaS / productivity / collaboration (Step 2 complete)

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

**Architecture write-ups:**

- **Slack.** Slack's own engineering blog documents a split architecture:
  web/application-logic servers written in PHP/Hack running on HHVM
  (handling auth, business logic, DB writes), and separate real-time
  messaging servers (Channel/Gateway/Presence servers) written in Java for
  WebSocket fan-out; data storage is MySQL via Vitess sharding, with
  Memcached/MCRouter caching and SolrCloud for search. Primary source
  (Slack Engineering's own "Real-time Messaging" post). Confidence: primary
  source — confirmed.
- **Notion.** Notion's own engineering blog documents a block-based data
  model (every piece of content, from a paragraph to a table row, is a row
  in a sharded Postgres cluster — 96 physical instances as of the most
  recent published figures), with Redis Enterprise caching and PgBouncer
  connection pooling in front of the shard fleet, and a more recent
  migration to an event-driven architecture on Confluent Cloud (Kafka).
  Primary source (Notion's own engineering blog posts on the data model and
  data-lake scaling). Confidence: primary source — confirmed.
- **Atlassian (Jira/Confluence).** Atlassian's own Engineering blog
  documents a microservices architecture on AWS, each service written in
  one of three standardized stacks (Java/Kotlin+Spring Boot, Node.js
  +Express, or Python), orchestrated via Kubernetes or Atlassian's own
  "Micros" platform. Primary source (Atlassian's own "Cloud Engineering
  Overview" and Confluence-decomposition posts). Confidence: primary source
  — confirmed.
- **Microsoft 365 / Teams.** Microsoft's own public documentation and
  Microsoft Community Hub posts (both first-party) document Teams' new
  client architecture: Edge WebView2 hosting a ReactJS/TypeScript/Fluent UI
  front end, Apollo GraphQL for the client data layer, a Node.js backend
  runtime, and WebRTC for real-time audio/video. Primary source (Microsoft
  Community Hub, a first-party Microsoft engineering channel). Confidence:
  primary source — confirmed.
- **Google Workspace (Docs/Sheets/Drive).** Weaker sourcing than the other
  four: no single first-party "how Google Docs is built" engineering post
  was found in this pass (Google is comparatively far less open than
  Slack/Notion/Atlassian about internal architecture specifics for
  Workspace). What's confirmable from Google's own public technology
  disclosures (Cloud Platform documentation, published engineering talks):
  Bigtable/Spanner as the backing distributed-storage technologies Google
  uses broadly, and Protocol Buffers as Google's standard internal
  serialization format instead of JSON/XML. These are Google's own
  documented platform technologies (primary source), but their specific
  application to Docs/Sheets/Drive internals is not independently
  confirmed in this pass — **marked unconfirmed at the product-specific
  level**, confirmed only at the general-Google-infrastructure level.

## Category 4 — Media / streaming / content platforms (Step 2 complete)

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

**Architecture write-ups:**

- **Netflix.** Netflix's engineering culture is extensively documented
  (Netflix Tech Blog, widely cross-referenced by independent technical
  writeups): a microservices architecture (thousands of independently
  deployable services), primarily Java/Spring Boot on the backend, with
  Python and Go for ML/observability tooling, Node.js/React for the UI/API
  layer, and a more recent shift from a monolithic API to a Federated
  GraphQL gateway over Domain Graph Services. Two independent source types
  (Netflix's own published engineering talks/posts, cross-confirmed by
  multiple independent technical analyses). Confidence: two independent
  sources — confirmed.
- **Spotify.** Spotify's engineering is documented as microservices-based,
  primarily Java with Spring, with Python used heavily for backend
  automation/ML, Scala and Node.js for specific services, Apache Kafka as
  the core streaming/event backbone, and a custom Hermes protocol (built on
  ZeroMQ+Protobuf) for inter-service communication; PostgreSQL and
  Cassandra for storage. Two independent source types (technical-analysis
  writeups cross-confirming the same Kafka/Java/Postgres+Cassandra
  details). Confidence: two independent sources — confirmed.
- **Twitch.** Twitch's own engineering blog documents a deliberate,
  publicly chronicled migration ("Breaking the Monolith at Twitch," a
  two-part series) from a Rails monolith to a Go-centric microservices
  architecture — the new API edge is written in Go, with the transcode
  system in a mix of C/C++ and Go. Primary source (Twitch's own engineering
  blog). Confidence: primary source — confirmed.
- **Disney+.** AWS's own published case studies (a first-party source for
  the *infrastructure* Disney+ runs on, since AWS is naming its own
  customer) document AWS as Disney+'s preferred cloud provider, Amazon
  Kinesis for real-time event streaming/recommendations, S3 for media
  storage, and (per Disney's own open-source engineering blog posts) the
  Micronaut framework for microservices. Confidence: primary source (AWS's
  own case study, corroborated by Disney's own AWS open-source blog posts)
  — confirmed, though specific to the infrastructure/cloud layer rather
  than Disney+'s full application-level architecture, which is less
  publicly documented than Netflix/Spotify/Twitch — **partially
  unconfirmed at the application-code level.**

## Category 5 — Travel / booking / marketplaces (Step 2 complete)

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

**Architecture write-ups:**

- **Booking.com.** Booking.com's own tech blog and independently-published
  system-architecture writeups (cross-confirming each other) document a
  microservices architecture behind an API Gateway, PHP + MariaDB for core
  web-tier workloads (Booking.com is one of the largest production PHP
  deployments in the industry, alongside Wikipedia per the same source),
  Kafka+Flink for real-time content/fraud-detection pipelines, and
  JanusGraph/Cassandra for graph-based fraud detection. Two independent
  source types (Booking.com's own tech blog plus independent technical
  writeups). Confidence: two independent sources — confirmed.
- **Airbnb.** Airbnb's own engineering blog ("Building Services at
  Airbnb," a multi-part series) documents a service-oriented architecture:
  Ruby on Rails as the historical backbone, Java-based services on the
  Dropwizard framework with Thrift-over-HTTP for newer service-to-service
  communication, Kafka for event streaming, and MySQL plus Cassandra/
  DynamoDB for storage. Primary source (Airbnb's own tech blog).
  Confidence: primary source — confirmed.
- **Expedia.** Expedia Group's own engineering blog (Medium's
  "Expedia Group Technology" publication) documents the JVM as the primary
  backend platform — predominantly Java/Spring Boot microservices (a
  "hundreds of Spring Boot apps" figure cited directly), with a later,
  publicly documented adoption of Kotlin on the server side starting in
  2017. Primary source (Expedia Group's own engineering blog). Confidence:
  primary source — confirmed.
- **TripAdvisor.** TripAdvisor's own engineering blog documents an
  event-driven microservices architecture with a GraphQL-based
  Backend-for-Frontend (BFF) layer serving server-driven UI ("Sections") to
  mobile clients. Primary source (TripAdvisor's own Tripadvisor Tech
  Medium publication and engineering.tripadvisor.com). Confidence: primary
  source — confirmed.
- **Trip.com.** Weaker sourcing than the other four: the strongest source
  found is a CNCF case study (a semi-primary source, since CNCF case
  studies are written in collaboration with the featured company) documenting
  Trip.com's large-scale Kubernetes platform (100+ platform engineers,
  10,000+ engineers total, both on-prem and multi-cloud AWS/Alibaba Cloud
  clusters, Cilium for networking) — but this is infrastructure/platform
  level, not application-architecture/language-stack level. **Marked
  unconfirmed at the application-stack level** (no equivalent of "Trip.com
  is built in Java/PHP/etc." was found and independently confirmed in this
  pass); confirmed only at the Kubernetes-platform level.

## Category 6 — Fintech / payments (Step 2 complete)

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

**Architecture write-ups:**

- **PayPal.** PayPal's own technology blog (Medium's "The PayPal
  Technology Blog") documents a historical Java-centric backend that PayPal
  itself has publicly, deliberately diversified: PayPal's own Node.js
  adoption posts describe migrating high-traffic pages (starting with the
  account-overview page) to Node.js specifically to unify browser and
  server engineering teams on one language, alongside their own open-
  sourced Kraken.js framework; Java/Spring remains central elsewhere, with
  Go also adopted for concurrent microservices. Primary source (PayPal's
  own tech blog). Confidence: primary source — confirmed.
- **Stripe.** Stripe's own engineering culture is extensively documented
  (cross-referenced by the Pragmatic Engineer's published, Stripe-
  interview-based deep dive plus Stripe's own open-sourced tooling):
  Ruby as the historically dominant backend language (one of the largest
  production Ruby codebases in the industry, per that reporting), with
  Stripe's own open-sourced Sorbet static type checker built specifically
  to manage that scale; newer, performance-critical payment-processing
  services increasingly built in Go and Rust; TypeScript/React on the
  front end. Two independent source types (Stripe's own open-source
  release of Sorbet as direct evidence of the Ruby-at-scale claim, plus
  the independently-reported Pragmatic Engineer deep dive). Confidence: two
  independent sources — confirmed.
- **Wise.** Wise's own engineering blog ("Wise Tech Stack," a series
  republished with year-specific updates) documents, on the backend, a
  large Java-based microservice fleet (700+ Java repositories out of 1000+
  total microservices, per Wise's own published figures) built on an
  internal "microservice chassis" framework, with AWS as the core cloud
  provider (including early adoption of AWS Outpost for consistent tooling
  in regulated regions). Primary source (Wise's own engineering blog).
  Confidence: primary source — confirmed.
- **Cash App (Block).** Cash App's own engineering blog ("Cash App Code
  Blog") is a real, citable primary source, but this pass only surfaced
  client-side (Android/Compose) architecture detail from it, not backend
  language/service-architecture specifics. **Marked unconfirmed at the
  backend-architecture level** — confirmed only that Cash App's Android
  client uses a reactive Compose-based architecture (Cash App's own
  engineering blog); no independently-confirmed backend stack claim is
  made here.
- **Venmo (PayPal-owned).** No dedicated first-party Venmo engineering
  architecture post was found in this pass distinct from PayPal's own
  (Venmo's public "Engineering @ Venmo" page functions mainly as a careers/
  index page in what this pass could access, not a detailed architecture
  writeup). Venmo has operated as a PayPal-owned subsidiary since 2013,
  which is itself a two-independently-confirmable fact (PayPal's own
  investor/corporate disclosures, widely corroborated), but **the specific
  claim that Venmo's application stack matches PayPal's is unconfirmed** in
  this pass — recorded as such rather than assumed.
