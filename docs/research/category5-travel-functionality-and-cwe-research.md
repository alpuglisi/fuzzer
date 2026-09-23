# Category 5 (Travel/booking/marketplaces) — functionality and stack-specific CWE research

Status: supports `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4's category-5
row. Site pair already decided there (do not re-derive): **Booking.com**
(PHP, microservices behind an API gateway — reuses `php_laravel`/
`php_current`) and **Expedia** (Java/Spring Boot microservices — new
stack, `CC-LAB-0210`-`0119` reserved). This document closes the
functionality-research and stack-specific-CWE-research gap identified in
§0a items 2-3 for this category, before any page/manifest design starts.

Per §0a's standing bar: every claim below is either (a) cited to a real
source, or (b) explicitly marked as inferred from well-documented public
product behavior rather than an engineering source, when no citable
architecture/engineering write-up was found for that specific feature. No
citation is invented.

---

## Part 1 — Functionality research

### 1.1 Booking.com

Booking.com does not publish a feature-level product spec, so most of
this is grounded in the site's own publicly documented user-facing help
pages, its Partner Hub/Extranet documentation (a first-party source for
the partner-facing side), and its Connectivity API docs (which describe
the shape of the same data flows browsers exercise). Where a flow is
described from general, well-known product behavior rather than a
specific citable page, that is flagged.

- **Search/filter (dates, location, guests).** The consumer search flow
  takes a destination, check-in/check-out dates, and number of
  adults/children/rooms, then returns a results list filterable by price
  range, star rating, review score, amenities ("Breakfast included",
  "Free cancellation"), property type, and distance from a point of
  interest; results can be sorted (price, review score, "Top picks").
  Deal/discount filters ("Deals only", "Top Reviewed & Discounted") and
  mobile-rate-only pricing are documented in third-party guides to the
  UI (not a Booking.com engineering source) — [Booking.com Genius
  program guide](https://iwandered.net/booking-genius/). The general
  shape (destination + dates + guests + filter/sort results) is the
  well-documented, observable behavior of the live site itself, cited
  here as product-behavior grounding rather than an engineering source.
- **Listing/results and detail pages.** Each result links to a property
  detail page showing room types, per-night and total price, cancellation
  terms, amenities, photos, and guest reviews. This is standard,
  directly observable product structure; no engineering blog was found
  describing this page specifically, so it is marked as inferred from
  product behavior, not cited to an architecture source.
- **Booking/checkout flow and payment.** Multi-step: select room/rate →
  guest details → payment method selection (the platform supports both
  "pay now" and "pay at property," and third-party payment methods) →
  confirmation. Booking.com's own architecture write-up (already in
  `docs/research/site-architecture-survey.md`, corroborated by
  [an independent architecture writeup](https://www.linkedin.com/pulse/high-level-system-architecture-bookingcom-momen-negm-9lgof))
  confirms the pipeline runs through an API Gateway into per-concern
  microservices (booking, payments, fraud detection via
  JanusGraph/Cassandra), which is the architectural shape this checkout
  flow is grounded in even though the step-by-step UI detail itself is
  inferred from product behavior.
- **User account / booking history / cancellation-modification.**
  Logged-in users can view upcoming and past bookings, modify dates
  (subject to the rate's flexibility), and cancel (subject to the rate's
  cancellation policy — "Free cancellation" vs. non-refundable). This is
  standard, observable account-area behavior; no specific engineering
  source found, so marked as inferred.
- **Reviews.** Guests can leave a review only after a completed stay
  (verified-stay review model); reviews contribute to the property's
  review score shown in search results and on the detail page. Standard,
  observable behavior; no specific engineering source found for the
  review-verification mechanism itself, so marked as inferred.
- **Loyalty program (Genius).** A tiered, account-based loyalty program:
  Level 1 (account signup) grants a base discount; Level 2 (5 bookings in
  2 years) and Level 3 (10 bookings in 2 years) unlock deeper discounts,
  free breakfast, and room upgrades at participating properties, and
  levels persist once unlocked. Cited to third-party guides describing
  the publicly documented tier structure —
  [Booking.com's own Genius landing page](https://www.booking.com/genius.html),
  [10xTravel's Genius guide](https://10xtravel.com/booking-com-genius-loyalty-program/).
  This is a genuinely useful feature for page design: a tier/discount
  value that the client should never be trusted to assert about itself.
- **Partner/host-side view.** Booking.com's Partner Hub/Extranet is a
  distinct, authenticated surface for property owners: managing listing
  content, room inventory and rates, viewing/replying to guest reviews,
  and (per Booking.com's own Connectivity API docs) programmatic access
  to the same booking/inventory data via API for larger partners/
  channel managers — [Booking.com Connectivity API
  docs](https://developers.booking.com/connectivity/docs),
  [AltexSoft's writeup of Booking.com's partner surfaces (Extranet, Pulse
  app, APIs)](https://www.altexsoft.com/blog/booking-com-partnerships-apis-extranet-pulse-app/).
  This two-sided (consumer + partner/host) surface is architecturally
  significant: it is a second authentication/authorization domain with
  its own admin-shaped functionality (content management, rate
  management, report/export views), which is exactly where access-control
  and export-related vulnerability classes become realistic (see Part 2).
- **Affiliate/partner-redirect behavior.** Booking.com runs a public
  affiliate program (embeddable widgets, deep links to specific
  properties/searches carrying an affiliate ID) documented on the
  partner-facing pages referenced above. A booking site that both accepts
  inbound affiliate-tagged links and constructs outbound redirect URLs
  (e.g., "continue to payment provider," "return to affiliate site after
  booking") is a realistic surface for redirect-target handling — see
  Part 2's CWE-601 candidate.
- **Price/rate-plan display.** Prices vary by rate plan (refundable vs.
  non-refundable, member-only/Genius rates, mobile-only rates) and can
  change based on account state (logged in vs. not, Genius level). This
  is standard, observable behavior and is the direct functional hook for
  the price/rate-integrity CWE candidates in Part 2 — the client
  necessarily receives multiple simultaneous price quotes for the same
  room (one per rate plan), which is exactly the shape where a
  server-side price-authority bug becomes realistic.

### 1.2 Expedia

Expedia Group publishes an active engineering blog (Medium's "Expedia
Group Technology" publication) that documents architecture and internal
tooling extensively, but — like Booking.com — does not publish a
consumer feature spec. The consumer-facing flow below is grounded in
Expedia's own public help-center pages and One Key program pages (first
party, describing real product behavior) plus the engineering blog for
architecture-adjacent claims.

- **Search/filter (dates, location, guests) and bundling.** Expedia's
  core differentiator versus Booking.com is bundling: search accepts a
  destination, dates, and traveler count, and returns not just hotel
  results but flight+hotel (and flight+hotel+car) package results, with
  a documented pricing incentive to bundle. This bundling behavior is
  described in Expedia's own [Packages help-center
  article](https://www.expedia.com/helpcenter/?product=Packages&productId=packages&articleId=16763).
- **Listing/results and detail pages.** Flight results show fare class,
  layovers, and baggage-inclusion; hotel results show room type,
  cancellation policy, and price. Standard, observable structure; no
  specific engineering source found for the page itself, so marked as
  inferred from product behavior.
- **Booking/checkout flow and payment.** Multi-step, with an explicit
  loyalty-currency payment option: One Key members can apply "OneKeyCash"
  (an accrued rewards balance) toward part or all of a flight/hotel cost
  at checkout, with documented restrictions (insufficient balance,
  added ancillaries like seat selection making the item ineligible) —
  per [Expedia's help-center coverage of applying OneKeyCash to
  flights](https://www.expedia.com/helpcenter/). A checkout flow that
  mixes a real payment amount with a stored, spendable account-balance
  currency is a directly relevant functional hook for price/balance-
  integrity vulnerability classes (see Part 2).
- **User account / booking history / cancellation-modification.**
  Expedia's help center documents distinct cancellation flows and
  policies for flights versus hotel/vacation-rental bookings, with
  different refund eligibility rules per product type —
  [Cancel your flight](https://www.expedia.com/helpcenter/?articleId=12324),
  [Cancel your hotel or vacation rental
  booking](https://www.expedia.com/helpcenter/?articleId=12326). Reward
  Night stays booked with points have their own return-to-account rule
  depending on what cancellation-refund tier would have applied had cash
  been used — per Expedia's [One Key Terms and
  Conditions](https://www.expedia.com/one-key-terms). This is a
  genuinely stateful, multi-branch business rule (refund-tier-dependent
  point return) that is realistic to get wrong server-side.
- **Reviews.** Hotel reviews are shown on hotel detail pages, generally
  sourced/aggregated similarly to other major OTAs; no Expedia-specific
  engineering or help-center source describing the review-submission
  mechanism itself was found in this pass, so this is marked as inferred
  from standard, observable product behavior rather than cited.
- **Loyalty program (One Key).** A unified rewards program (merging the
  formerly separate Expedia Rewards, Hotels.com Rewards, and Orbitz
  Rewards programs) that accrues "OneKeyCash" spendable across flights,
  hotels, cars, and activities, plus separate trip-protection benefits
  (cancellation/interruption coverage) — per
  [NerdWallet's guide to One Key](https://www.nerdwallet.com/travel/learn/expedia-guide)
  and [CNBC Select's coverage of the One Key
  launch](https://www.cnbc.com/select/expedia-one-key-rewards/), both
  independent (non-Expedia) sources describing Expedia's own publicly
  announced program; corroborated by Expedia's own terms page cited
  above. This is a strong functional hook: a stored, spendable
  account-balance currency, applied at checkout, is directly relevant to
  the price/balance-integrity CWE candidates in Part 2.
- **Partner/admin-side view.** Expedia's engineering blog documents
  significant internal microservice infrastructure (a "Detail Service,"
  legacy-microservice deprecation processes, Spring Cloud Gateway as an
  internal API gateway component) — [Introduction to Spring Cloud
  Gateway](https://medium.com/expedia-group-tech/introduction-to-spring-cloud-gateway-3948de177e1e),
  [The Perils of Deprecating a Legacy
  Microservice](https://medium.com/expedia-group-tech/the-perils-of-deprecating-a-legacy-microservice-febfa3e9f6cc) —
  but this documents internal engineering tooling, not a public-facing
  partner/host admin surface comparable to Booking.com's Extranet.
  Expedia Group does operate a partner-facing side (Expedia Partner
  Solutions / hotel-partner "Expedia Partner Central" for property
  management), which is standard, observable product surface but was not
  found described in an engineering source in this pass — marked as
  inferred, not cited to an architecture source. It remains a reasonable
  admin-shaped surface for page design (rate/inventory management, an
  export/report view) grounded in the same real-world pattern as
  Booking.com's Extranet, just without a specific citable engineering
  write-up for Expedia's version of it.
- **Affiliate/partner-redirect behavior.** Not specifically documented
  for Expedia in this pass (no citable source found); OTAs of this type
  commonly run affiliate/white-label programs, but this claim is not
  asserted as confirmed for Expedia specifically — flagged rather than
  invented.
- **Price/rate display.** Prices vary by fare class/rate plan and by
  whether OneKeyCash is applied; as with Booking.com, the client
  necessarily receives and displays a computed price that must be
  re-validated server-side at checkout — this is the direct functional
  hook for Part 2's price-integrity candidates.

---

## Part 2 — Stack-specific CWE research

Method, per §0a item 3/4 and the existing Step-6 discipline
(`docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`): for each
candidate, identify (a) CWE ID/name, (b) which site/stack/feature
combination grounds it and why, (c) whether it duplicates an existing
corpus category (`docs/research/corpus-examples/`: access-control,
auth-session, ecommerce-logic, file-handling, header-injection,
insecure-deserialization, mass-assignment, search-export, ssrf, ssti,
ugc-xss, webhook-signature) or an existing `lab/safety_matrix.yaml`
concern, and if so what's different about this stack's flavor, (d) a
one-line rationale. `https://cwe.mitre.org/top25/` and
`https://cwe.mitre.org/data/index.html` were consulted per candidate.

### 2.1 Booking.com — PHP / microservices-behind-API-gateway stack

The existing corpus already has deep PHP coverage across nearly every
category (`docs/research/corpus-examples/*/php/`), and
`lab/safety_matrix.yaml`'s concern vocabulary already models SQLi,
stored/reflected HTML injection, IDOR (`ownership_check_bypass`), JWT
algorithm confusion, weak token entropy, stale authorization state,
price-integrity bypass, TOCTOU race conditions, unrestricted file
upload, path traversal, `ORDER BY` injection, SSTI, XXE, mass
assignment, SSRF, insecure deserialization, mail/HTTP header injection,
and weak webhook-signature comparison. A Booking.com-shaped PHP app
should therefore lean on *booking-domain* features that are genuinely
new combinations, not a fifth generic PHP SQLi/XSS page.

- **CWE-601 — URL Redirection to Untrusted Site ('Open Redirect').**
  Grounded in: Booking.com's documented affiliate program and partner
  deep-link/redirect surface (Part 1.1) — a real booking flow that
  redirects to a payment provider and/or back to an affiliate's site
  after checkout, keyed by a `return_to`/`redirect_url`-shaped parameter.
  Coverage check: **not present in any existing corpus category or
  `safety_matrix.yaml` concern** — the concern vocabulary has no
  redirect-target-validation concept at all. This is a genuinely new
  vulnerability class for the project, not a re-flavored duplicate.
  Rationale: affiliate/partner redirect is a first-class, real feature
  of Booking.com specifically (unlike a generic e-commerce site), making
  this a realistic, not-bolted-on placement — per
  [CWE-601's own definition](https://cwe.mitre.org/data/definitions/601.html).
- **Price/rate-plan integrity (maps to existing `price_integrity_bypass`
  concern, CWE-840-family "business logic errors"/CWE-20 improper input
  validation of a client-supplied price).** Grounded in: Booking.com's
  multiple-simultaneous-rate-plan display (refundable/non-refundable/
  Genius-discounted/mobile-only — Part 1.1) feeding into checkout.
  Coverage check: `price_integrity_bypass` **already exists** in
  `lab/safety_matrix.yaml` (added `CC-LAB-0063`) and is presumably
  already represented in `ecommerce-logic`. Flavor difference: the
  existing concern is generic "trust the client's submitted price"; the
  Booking.com-specific flavor is a *rate-plan selection* bug — the
  server trusts a client-supplied rate-plan identifier (which of several
  simultaneously-quoted prices to charge) rather than the price value
  itself, which is a narrower, more realistic mechanism for a multi-rate
  display. Candidate for a page, but flagged as the same underlying
  class as existing coverage, not a new one.
- **Session/booking-reference predictability (CWE-330 — Use of
  Insufficiently Random Values, parent of the existing
  `weak_token_entropy` concern).** Grounded in: a booking confirmation
  flow needs a booking-reference/confirmation code, often used
  (alongside surname/email) as a lightweight "manage my booking" lookup
  credential without full login — a realistic pattern in the travel-OTA
  domain specifically. Coverage check: `weak_token_entropy` **already
  exists** in `safety_matrix.yaml` (`CC-LAB-0063`); this would be the
  same mechanism applied to a booking-reference code rather than a
  session/reset token. Not a new class — flagged as a duplicate flavor,
  lower priority than CWE-601.
- **CSV/report export injection (CWE-1236 — Improper Neutralization of
  Formula Elements in a CSV File).** Grounded in: the Extranet/
  partner-admin surface's plausible report/export view (booking lists,
  revenue reports) for property-owner users (Part 1.1) — a real,
  documented pattern in booking-adjacent admin panels, confirmed by
  real-world CVEs in comparable hotel/reservation booking systems (e.g.
  PHPJabbers Hotel Booking System) — per
  [CWE-1236's definition](https://cwe.mitre.org/data/definitions/1236.html)
  and the corroborating survey of CSV-injection-affected booking-system
  CVEs found in this pass. Coverage check: the existing corpus has a
  `search-export` category, but its current PHP/Node/Python entries (not
  individually re-read in this pass; category name only) are presumed to
  cover *search-parameter* export/injection shapes (e.g. search-to-SQL,
  not export-*output*-format injection). CSV formula injection is a
  distinct output-encoding mechanism (attacker-controlled cell content
  interpreted as a spreadsheet formula by the *downstream* application,
  not the web app itself) — genuinely different from anything named in
  `safety_matrix.yaml`'s concern vocabulary, which has no
  formula-injection/output-escaping concern at all. Reasonable
  candidate for genuine new breadth, contingent on confirming during
  page design that `search-export`'s existing PHP entries don't already
  cover this specific mechanism.
- **Mass assignment on partner/Extranet listing or rate updates (CWE-915
  — Improperly Controlled Modification of Dynamically-Determined Object
  Attributes).** Grounded in: the Extranet's rate/inventory-management
  forms (Part 1.1) — a plausible unguarded-model-binding bug on
  property-owner-submitted updates. Coverage check: `mass_assignment`
  **already exists** in `safety_matrix.yaml` (`CC-LAB-0063`) and the
  corpus's `mass-assignment` category currently only has a `node/`
  subfolder (no `php/` entry yet per the `ls` in this pass) — so a PHP
  mass-assignment entry specifically would add corpus breadth even
  though the *concern* itself is not new. Worth noting for corpus-entry
  purposes even though it's not a new CWE class for page design.

### 2.2 Expedia — Java/Spring Boot stack

This is the project's first Java-anything stack (`fuzzlab/labgen/
emitters/` currently has only `node_express`, `php_current`,
`php_laravel`, `python_fastapi`; no `java`/`spring` directory in
`docs/research/corpus-examples/` either), so essentially every
Java/Spring-specific mechanism here is new *tooling* breadth even where
the underlying CWE class already exists in another language's flavor.
The distinction the plan asks for (§0a item 4) is whether the *CWE
class* is new, separately from the *stack* being new — both are called
out below.

- **CWE-502 — Deserialization of Untrusted Data, Jackson polymorphic-
  typing gadget-chain flavor.** Grounded in: Expedia's documented "hundreds
  of Spring Boot apps" (survey doc, `site-architecture-survey.md` line
  ~277) — a JSON-heavy Spring Boot microservice fleet is the textbook
  setting for Jackson (`com.fasterxml.jackson.databind`) being used for
  request-body deserialization; real-world precedent found in this pass
  includes CVE-2026-41855 (Spring Framework JMS/Jackson deserialization,
  disclosed June 2026), CVE-2020-9547 and CVE-2019-12384 (Jackson
  polymorphic-typing gadget chains via ibatis-sqlmap/logback-core
  respectively) — see
  [SentinelOne's CVE-2026-41855 writeup](https://www.sentinelone.com/vulnerability-database/cve-2026-41855/)
  and [ZeroPath's analysis of the same
  CVE](https://zeropath.com/blog/cve-2026-41855-spring-framework-jms-deserialization).
  Coverage check: `insecure_deserialization`/`insecure-deserialization`
  **already exists** as both a corpus category and a `safety_matrix.yaml`
  concern, currently PHP-`unserialize()`-flavored (and presumably
  node/python entries per the `ls` in this pass). The Java/Jackson flavor
  is a **genuinely different mechanism** from PHP's `unserialize()`: PHP
  deserialization abuses `__wakeup`/`__destruct` magic methods on
  attacker-chosen classes from a single serialized blob; Jackson's
  polymorphic-typing gadget chain instead abuses `@JsonTypeInfo`/default
  typing to let a JSON payload's embedded type hint select an arbitrary
  class for Jackson to instantiate via setters/constructors, chaining
  through classpath "gadget" classes — a different trigger mechanism,
  different framework configuration flag (`enableDefaultTyping`/
  `@JsonTypeInfo` vs. PHP's `unserialize()` call site), and a different
  fix (type-hint allowlisting vs. `__wakeup` hardening or avoiding
  `unserialize()` on untrusted input entirely). This is exactly the
  "same class, genuinely different flavor" case the deliverable
  explicitly calls out as acceptable and worth flagging as such — this
  is a strong shortlist candidate specifically because it's a materially
  different exploitation mechanism from the corpus's existing PHP
  deserialization entries.
- **CWE-89 — SQL/JPQL Injection via Spring Data JPA/MongoDB `@Query` +
  SpEL parameter binding.** Grounded in: a Spring Boot service with a
  Spring Data repository whose `@Query`-annotated method interpolates a
  Spring Expression Language (SpEL) parameter reference unsafely — real
  precedent: CVE-2016-6652 (Spring Data JPA SQL injection via a `Sort`
  instance with a function call) and CVE-2022-22980/CVE-2026-41717
  (Spring Data MongoDB SpEL injection via `@Query`/`@Aggregation`
  parameter binding) — see
  [Spring's own CVE-2022-22980 advisory](https://spring.io/security/cve-2022-22980/)
  and [the CVE-2026-41717 advisory](https://spring.io/security/cve-2026-41717/).
  Coverage check: raw SQLi (`sql_syntax_break`) is heavily covered
  already in `safety_matrix.yaml`'s SQL-sink entries and presumably the
  PHP/Node/Python corpus entries. The Spring-specific flavor here is
  narrower and more interesting than generic SQLi: the vulnerable
  surface isn't string concatenation at all, it's a *framework
  convenience feature* (SpEL expression evaluation inside an ORM
  annotation) being reachable by attacker input — a mechanism unique to
  Spring Data's query-derivation machinery, with no PHP/Node/Python
  equivalent in the corpus. Flagged as the same broad SQLi/JPQL-injection
  *outcome* as existing coverage, but via a framework-specific trigger
  path (`ORDER BY`/sort-parameter → SpEL evaluation) genuinely distinct
  from `sql_identifier_substitution`/`sql_order_by_injection`'s existing
  string-concatenation model.
- **CWE-1321/CWE-915-adjacent — Mass assignment via unguarded
  `@RequestBody`-bound JPA entities.** Grounded in: any Spring MVC
  controller that binds a `@RequestBody` directly to a JPA `@Entity`
  (rather than a dedicated DTO) — a well-known Spring anti-pattern where
  extra JSON fields (e.g. a booking's `priceOverride`, a user's `role`)
  silently bind onto entity fields the endpoint never meant to accept.
  Coverage check: `mass_assignment` **already exists** as both concern
  and corpus category (currently node-only per the `ls` in this pass).
  Flavor difference: Node's mass-assignment flavor is typically an
  unguarded `Object.assign`/Mongoose-schema issue; Spring's is a
  binding-layer issue specific to `@RequestBody` + JPA entity reuse, with
  its own idiomatic fix (`@JsonIgnore`/DTO projection vs. Node's
  allowlist-object-assign fix) — a different flavor worth having, but a
  duplicate *class*, not a new one; lower novelty than CWE-502/CWE-601.
- **CWE-352 / CSRF and CWE-16 — Spring Security misconfiguration
  (CSRF protection disabled, or the Actuator endpoints exposed
  unauthenticated).** Grounded in: Spring Boot's Actuator module (health/
  metrics/env endpoints) being left exposed without authentication is a
  well-documented, common real-world Spring Boot misconfiguration
  pattern, and Spring Security's CSRF protection is easy to disable
  wholesale via a single config line, a well-known footgun in Spring
  tutorials/StackOverflow-copied config. Coverage check:
  `auth-session`/access-control-shaped concerns exist in the corpus, but
  none are specific to a *framework-default-security-feature disabled by
  misconfiguration* mechanism — this is closer to a config/exposure
  class (CWE-16: Configuration) than an access-control-logic bug, and
  isn't clearly represented. Flagged as a plausible but lower-priority
  candidate: harder to express as a single-page "sink" in this
  generator's Cell/Route/Pipeline IR (it's a global config toggle, not a
  per-request data flow), so it's noted as a candidate for future
  consideration rather than shortlisted here.
- **Spring MVC / Thymeleaf SSTI (CWE-1336 — Server-Side Template
  Injection).** Considered per the assignment's explicit prompt. No
  citable real-world Expedia- or Spring-Boot-specific incident was found
  in this pass to ground it further than "Thymeleaf SSTI is a known
  general class" — and `ssti`/`server_template_injection` **already
  exists** as both corpus category and `safety_matrix.yaml` concern
  (PHP/Node/Python). Without a stack-specific footgun distinct from the
  generic "unsanitized user input reaches template-source compilation"
  shape already modeled, this does not add a genuinely new flavor the
  way CWE-502's Jackson mechanism does — noted as considered and
  deprioritized rather than dropped silently.

---

## Recommended shortlist

Balancing "realistic for this real site/stack" against "expands the
project's existing coverage" per §0a item 4, and cross-checking each
against the existing corpus categories/`safety_matrix.yaml` concerns
listed above:

1. **CWE-601 — Open Redirect** (Booking.com, affiliate/partner-redirect
   flow). **Genuinely new class** — no redirect-target-validation concept
   exists anywhere in the current corpus or `safety_matrix.yaml`
   vocabulary. Strongest pick for breadth; also strongly grounded (real,
   documented Booking.com affiliate/partner-deep-link feature).
2. **CWE-502 — Jackson polymorphic-typing deserialization gadget chain**
   (Expedia, Spring Boot JSON request-body deserialization). **Same
   broad class as the corpus's existing `insecure-deserialization`
   coverage, but a materially different exploitation mechanism**
   (type-hint-driven class instantiation vs. PHP's `__wakeup`/
   `__destruct` magic-method abuse) — real-world CVE precedent found
   (CVE-2026-41855, CVE-2020-9547, CVE-2019-12384). Strong pick: adds a
   genuinely distinct *flavor* even though the label is shared, and is
   this project's first Java-stack vulnerability entry.
3. **Spring Data JPA/MongoDB SpEL injection via `@Query`** (Expedia).
   **Same outcome (SQL/JPQL injection) as existing SQLi coverage, but a
   framework-specific trigger path** (ORM convenience-annotation SpEL
   evaluation, not string concatenation) with real CVE precedent
   (CVE-2016-6652, CVE-2022-22980/CVE-2026-41717). Good pick for
   demonstrating a Spring-idiomatic footgun distinct from raw SQLi, at
   moderate novelty.
4. **CSV/report export formula injection, CWE-1236** (Booking.com
   Extranet/partner-admin export view). **Likely a genuinely new
   mechanism** (output-format/formula-injection, not input-validation) —
   contingent on confirming during page design that the corpus's
   existing `search-export` category entries don't already cover this
   specific shape; if confirmed distinct, this is a strong breadth pick
   with real-world precedent in comparable booking systems.
5. **Price/rate-plan-selection integrity** (Booking.com, multi-rate-plan
   checkout). **Same underlying class as the existing
   `price_integrity_bypass` concern**, narrower rate-plan-selection
   flavor. Include as a page because it's strongly grounded in
   Booking.com's actual product shape (genuinely realistic placement),
   but it is knowingly a duplicate class, not new breadth — lowest
   priority of the five kept.

**Considered and deprioritized, not shortlisted:** session/booking-
reference predictability (CWE-330, duplicate of existing
`weak_token_entropy`, no new flavor beyond "same mechanism, different
field"); mass assignment via `@RequestBody`+JPA entities (CWE-915/1321,
duplicate class, real Spring-idiomatic flavor but lower novelty than the
five above); Spring Security/Actuator misconfiguration (CWE-16/CWE-352,
plausible but awkward to express as a single-page Cell/Route/Pipeline
sink in this generator's IR — flagged for future consideration, not
built here); Thymeleaf SSTI (CWE-1336, duplicate of existing `ssti`
coverage with no stack-specific footgun found beyond the generic shape
already modeled).

**Unconfirmed / explicitly not asserted:** Expedia's affiliate/
partner-redirect program (no citable source found in this pass — not
used to ground any candidate above); Expedia's public-facing
partner/host admin surface's specific functionality (inferred from the
general OTA pattern and Expedia Partner Solutions' well-known existence,
not from a citable engineering or help-center source found in this
pass).
