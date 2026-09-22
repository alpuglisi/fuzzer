# Netflix — functionality research + Java/Spring-Boot-specific CWE shortlist

Produced for `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.5 step 2-3
(category 4 pilot, Media/streaming, Netflix pick). Architecture facts
(Java/Spring Boot microservices, Federated GraphQL gateway over Domain
Graph Services) are carried over unchanged from
`docs/research/site-architecture-survey.md`'s already-confirmed Category 4
entry — not re-researched here.

## 1. Netflix functionality/pages + GraphQL-federation implications

**Federation architecture, confirmed at the framework level (primary
source).** Netflix's own TechBlog ("How Netflix Scales its API with
GraphQL Federation," parts 1-2) and its own open-sourced **DGS Framework**
("Domain Graph Service Framework: GraphQL for Spring Boot," Netflix
TechBlog) document the concrete shape: a federated gateway sits in front
of Netflix's edge (historically Zuul), parses an incoming query, builds a
query plan, and fans out sub-queries to per-domain backend services. Each
backend team owns a **Domain Graph Service (DGS)** — a real, independently
deployable **Spring Boot** application that owns one slice of the overall
federated GraphQL schema and extends shared types via Apollo Federation's
`@extends`/`@key` directives. Netflix runs 2,000+ such Java 11+
microservices. *(Confidence: primary source — Netflix's own TechBlog and
its own open-sourced framework's own documentation — confirmed.)*

**Page/flow set this implies (member-facing surface, directly observable
from the product plus the DGS architecture's own stated purpose of serving
exactly this surface):**

- **Browse/homepage** — a "row of rows" personalized catalog view. In DGS
  terms this is exactly the federation gateway's headline use case: one
  query fans out to a title-metadata DGS, an artwork/images DGS, and a
  recommendations DGS, then stitches one response.
- **Title detail page** — synopsis, cast, related-titles ("More Like
  This"), maturity rating; another federated read composing metadata +
  recommendations services.
- **Playback** — "continue watching"/resume-position tracking (a
  per-profile, per-title playback-state object client apps read and write
  back), video manifest/license acquisition.
- **Search** — free-text query against the title catalog, another
  federated read.
- **Profile management** — multiple profiles per account (kids profiles,
  maturity settings, "my list", viewing-history/playback-state per
  profile) — a natural home for a **mutation** that writes a client-
  supplied structured object back into a domain service, which is exactly
  the shape the CWE pick below needs.
- **Account/billing** — plan/payment management; lower priority for this
  app's page set since the survey has no primary-sourced detail on this
  flow specifically (synthesis from the product, not sourced — flagged as
  such, not treated as researched fact).

**Vulnerability-placement implication (synthesis, not a sourced claim):** a
DGS resolver backing "resume playback" or "save profile preferences"
plausibly accepts a structured, client-round-tripped object (the shape
each backend already sent the client on a prior read — "give me back
exactly what I gave you, updated") and deserializes it directly via
Jackson rather than re-validating field-by-field through a typed GraphQL
input — a realistic Java/Jackson developer shortcut, not an invented one.

## 2. Java/Spring-Boot-specific CWE shortlist

Cross-checked against every `docs/research/corpus-examples/*/*/manifest.yaml`
CWE (~140 IDs across node/php/python) and `lab/safety_matrix.yaml` (stack-
capability matrix, not a CWE registry). No `java`/`spring` stack exists
anywhere in the corpus today — every pick below adds a genuinely new
*stack instance*, not just a new CWE ID.

| CWE | Why Java/Spring-specific | Realistic page/flow | Corpus status |
|---|---|---|---|
| **CWE-502** (Insecure Deserialization, Jackson polymorphic/default-typing) | Real, current, framework-specific: **Spring for GraphQL 2.0.0–2.0.4** shipped an unsafe-deserialization flaw processing paginated (`Connection`) GraphQL queries, rooted in Jackson deserializing untrusted data (Spring's own advisory, `spring.io/security/`). Independent of that specific CVE, Jackson's own polymorphic/"default typing" deserialization (`enableDefaultTyping`/`@JsonTypeInfo` accepting an attacker-chosen concrete class) is *the* canonical real-world Java CWE-502 vector (well-documented gadget-chain class going back to `ysoserial`) — a framework-idiomatic mistake distinct from PHP's `unserialize()`/Python's `pickle`/Node's `node-serialize` already in the corpus. | A "resume playback"/"save profile" DGS mutation resolver that Jackson-deserializes a client-supplied JSON blob into a polymorphic base type (e.g. a `PlaybackState` interface with per-device-type subclasses) using default typing, instead of a closed, explicitly-annotated subtype set. | **Genuinely new stack instance.** `CWE-502` already exists 3x (node/php/python, `cwe_shared` in every `insecure-deserialization` manifest) but zero Java instances — adds the framework-specific Jackson-default-typing variant of an existing class, mirroring how category 1's `ruby_rails` Phase A pick added a new-stack instance of an existing class (there: XSS) rather than requiring a brand-new CWE ID for the pilot's first cell. |
| **CWE-862** (Missing Authorization, GraphQL field/resolver-level) | GraphQL-federation-specific shape: a federated schema's field-level authorization is easy to apply inconsistently across independently-owned DGS services (one service's resolver checks the caller's profile-maturity/ownership, a federated `@extends` field pulled in from another service does not) — a real, named OWASP API3:2023/BOPLA-class risk for exactly this architecture (federation-gateway search results, this session). | A title-detail query federating in a "why recommended"/internal-scoring field, or a profile query federating in another profile's playback history via a shared `Profile` type, without the extending service re-checking the requesting profile owns that data. | **Genuinely new corpus surface**, not just a new stack: `access-control` exists in the corpus (node/php stacks, per `docs/research/corpus-examples/access-control/`) but has no GraphQL-federation-shaped entry anywhere — the *mechanism* (authorization checked at the wrong federation boundary) is architecturally distinct from a REST-route missing an `@login_required`-equivalent. Flagged as the stronger long-term Phase B pick, not built in this pilot's Phase A (see §3). |

**Pick for this pilot's Phase A build:** **CWE-502** (Jackson polymorphic
deserialization in a DGS mutation resolver) — the more self-contained
shape to prove end-to-end on a brand-new stack's first live-boot cell
(single request/response round trip, no federation-topology modeling
required), consistent with how `ruby_rails`'s own Phase A picked the
simplest illustrative shape and deferred its richer, stack-idiomatic CWEs
to Phase B. CWE-862 is recorded above as the Phase B follow-up, not
declined.

## 3. Sourcing and confidence notes

- Primary (Netflix's own TechBlog, cross-confirmed by its own open-sourced
  DGS Framework docs): "How Netflix Scales its API with GraphQL
  Federation" parts 1-2; "Open Sourcing the Netflix Domain Graph Service
  Framework: GraphQL for Spring Boot." Confirmed.
- Secondary/practitioner (moderate confidence, not independently verified
  against a primary Netflix source): Medium/InfoQ writeups on Netflix's
  70+-microservice GraphQL federation and its Java/ZGC backend — used only
  to corroborate scale figures already implied by the primary source, not
  as the sole basis for any claim above.
- CVE/CWE claims: `spring.io/security/` (Spring for GraphQL's own security
  advisory index) for the Spring-for-GraphQL CWE-502 CVE; MITRE's CWE
  definitions (`cwe.mitre.org/data/definitions/502.html`,
  `.../862.html`) checked directly for both picks; OWASP API Security
  Top 10 2023 (API3, BOPLA) for the GraphQL mass-assignment/field-
  authorization framing. All checked this session, not recalled from
  training data.
- Not confirmed: a Netflix-specific primary source naming exactly which
  DGS resolver accepts a client-round-tripped polymorphic object — the
  playback-state/profile-preferences shape above is synthesis from the
  product's known behavior (resume-position persists per profile) plus
  the DGS architecture's documented mutation pattern, flagged as
  inference, not sourced fact (same discipline `-functionality-walmart.md`
  used for its own BFF-aggregation inference).
