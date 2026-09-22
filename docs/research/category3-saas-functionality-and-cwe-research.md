# Category 3 (SaaS/productivity/collaboration) — functionality and stack-specific CWE research

Closes the gap `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §0a items 2-3
identified for this category: per-site feature/functionality research (which
this project's own `docs/research/site-architecture-survey.md` confirmed it
does not yet have, being architecture-only), and CWE research tied to each
site's *actual stack + actual feature combination*, not just an abstract
vulnerability class. Site-pair selection and its reasoning are recorded in
the plan document's §9.4 tracker row and §9.2 ledger, not repeated here.

This document covers the two picks for category 3:

1. **Slack** — PHP/Hack web/app-logic tier (§9.2: reused as `php_laravel`'s
   paradigm group; the Java realtime-messaging tier is out of scope, per the
   plan's own exclusion of non-request/response paradigms).
2. **Atlassian (Jira/Confluence)** — Java/Kotlin + Spring Boot microservice
   (§9.2: new emitter).

## 1. Slack — functionality research

Slack's real product surface relevant to a request/response web app (its
Hack/HHVM tier handles auth, business logic, and DB writes per
`site-architecture-survey.md`'s own citation of Slack Engineering's
"Real-time Messaging" post):

- **Channels and messages.** The core primitive: users post messages into
  channels; messages support formatting, attachments, and links.
- **Incoming webhooks.** A workspace admin creates an incoming webhook,
  getting a unique URL; posting a JSON payload to that URL creates a message
  in a channel. ([Incoming webhooks for Slack](https://slack.com/intl/en-fi/help/articles/115005265063-Incoming-webhooks-for-Slack))
- **Outgoing webhooks and slash commands.** A workspace admin configures a
  URL Slack calls out to when a trigger word is used or a slash command is
  invoked; Slack POSTs event data (`command`, `text`, `user_name`, etc.) to
  that configured URL. ([Slash commands, O'Reilly "Building Slack Bots"](https://www.oreilly.com/library/view/building-slack-bots/9781786460806/ch06s02.html);
  outgoing-webhook mechanics per the same source family as incoming webhooks
  above)
- **Events API / request verification.** Slack signs every request it sends
  to a configured app endpoint (Events API callbacks, interactive
  components, slash-command deliveries) with an HMAC signature in the
  `X-Slack-Signature` header, computed over the raw request body and a
  signing secret; a receiving app is documented as required to verify this
  signature before trusting the payload.
- **Link unfurling.** When a message contains a URL, Slack (or an app
  subscribed to `link_shared` events) fetches that URL server-side to
  generate a preview (title, description, image) — a real, product-standard
  feature that requires the app's backend to make an outbound HTTP request
  to a user-supplied URL.

## 2. Slack — stack-specific CWE research (PHP/Hack web tier)

Cross-checked against `lab/safety_matrix.yaml`'s existing concern-ID
vocabulary and `docs/research/corpus-examples/` (which already has
`node`/`php`/`python` cells for these three classes) to confirm they satisfy
§0a item 4's breadth requirement: **none of `lab/manifests/*.yaml` currently
build a `webhook_signature_verification`, `ssrf`, or `header_injection`
cell** (verified: `grep -rl "ssrf\|header_injection\|webhook_signature"
lab/manifests/*.yaml` returns no hits) — these are exactly the classes
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 already named as
generalization-valuable because the current `php_laravel` lab doesn't model
them at all.

- **Webhook-signature-verification bypass (CWE-347 Improper Verification of
  Cryptographic Signature / CWE-345 Insufficient Verification of Data
  Authenticity).** Realistic vulnerable shape for a Slack-style app
  *receiving* Events API / interactive-component callbacks: skip the
  `X-Slack-Signature` HMAC check entirely, or compare it with PHP's `==`
  loose-equality operator (PHP's own well-documented "magic hash"
  type-juggling class — already the shape `docs/research/corpus-examples/webhook-signature/php/vulnerable-loose-equal-5.php`
  models) instead of `hash_equals()`. This is stack-specific: the loose-`==`
  footgun is a PHP-family behavior (type juggling of hex-looking strings in
  scientific-notation form), not a generic "forgot to check the signature"
  bug.
- **SSRF (CWE-918 Server-Side Request Forgery).** Realistic vulnerable shape
  for link unfurling: the backend fetches whatever URL a user pastes into a
  message with no allowlist/denylist of internal address ranges
  (`127.0.0.1`, `169.254.169.254` metadata endpoints, RFC1918 ranges) and
  follows redirects unchecked — the same shape as
  `docs/research/corpus-examples/ssrf/php/` cells (fetch-a-pasted-URL is a
  textbook SSRF entry point, and unfurling is the real Slack feature that
  produces it).
- **Header injection / CRLF (CWE-113 Improper Neutralization of CRLF
  Sequences in HTTP Headers, CWE-93 CRLF Injection).** Realistic vulnerable
  shape for outgoing-webhook delivery: constructing the outbound HTTP
  request to a user-configured webhook URL by concatenating a
  user-influenced value (e.g. the trigger word or channel name) directly
  into a header line, rather than using the HTTP client's own header-setting
  API — same shape as `docs/research/corpus-examples/header-injection/php/`.

## 3. Atlassian (Jira/Confluence) — functionality research

Real Jira/Confluence functionality relevant to a request/response app,
grounded in Atlassian's own developer documentation:

- **Issues (Jira) and pages (Confluence).** Core content objects; both
  support rich-text/markup bodies.
- **Macros / templated rendering (Confluence).** Confluence pages render
  "macros" — structured, templated content blocks (e.g. an "Include Page"
  or a Java-plugin-provided macro) evaluated server-side at render time.
  This is the real feature underlying CVE-2021-26084 and CVE-2022-26134
  (below) — both are OGNL-injection vulnerabilities in Confluence's
  server-side template/expression evaluation path
  (`ActionChainResult`/`translateVariables`/`findValue`, per
  [Rapid7's CVE-2022-26134 analysis](https://www.rapid7.com/blog/post/ra-cve-2022-26134-analysis/)),
  triggered via an OGNL payload placed directly in the request URI.
- **Attachments.** Both products support file attachments on
  issues/pages, addable via the REST API
  (`/rest/api/2/issue/{issue-key}/attachments` for Jira; the Confluence
  Cloud REST API's content-attachments group) — a realistic point for a
  file-upload or content-import path to parse untrusted structured data
  (XML in an import/export feature, or a serialized object in a legacy
  integration payload).
- **Webhooks.** Both products support outbound webhooks: Jira's Connect/
  OAuth 2.0 apps register webhooks via the REST API, and Confluence's own
  webhook feature (available since Confluence 7.7.0) signs each outbound
  request via HMAC when a secret is configured
  ([Confluence: Managing Webhooks](https://confluence.atlassian.com/doc/managing-webhooks-1021225606.html)).
- **Tech stack confirmation.** Atlassian's own "Cloud Engineering Overview"
  names the three standardized microservice stacks (Java/Kotlin+Spring
  Boot, Node.js+Express, Python); Atlassian additionally publishes a Spring
  Boot starter (`atlassian-connect-spring-boot`) specifically for building
  Connect add-ons for Jira and Confluence, confirming Spring Boot as a
  first-party, idiomatic stack for this product family, not merely one of
  three options picked arbitrarily.

## 4. Atlassian — stack-specific CWE research (Java/Kotlin + Spring Boot)

Cross-checked the same way as §2: `grep -rl "ssti\|server_template_injection\|xxe\|insecure.deserial" lab/manifests/*.yaml`
returns no hits, and `docs/research/corpus-examples/` has no `java` cell at
all yet for any class — so this pick is genuinely new corpus territory, not
a repeat.

- **Server-side template/expression injection (CWE-1336 Improper
  Neutralization of Special Elements Used in a Template Engine; maps to the
  existing `server_template_injection` concern-ID in
  `lab/safety_matrix.yaml`).** Directly grounded in CVE-2021-26084 and
  CVE-2022-26134: a page-macro/template value is compiled and evaluated as
  an **OGNL expression** rather than treated as inert data, letting an
  attacker-supplied macro parameter reach arbitrary object-graph navigation
  (and, in the real CVEs, remote code execution). This is a genuinely
  Java-specific footgun — OGNL is a Java expression language most other
  stacks in this project don't have an idiomatic equivalent of, unlike
  PHP/Python template engines' own auto-escaping bypass shapes already
  covered elsewhere in the corpus.
- **XML External Entity injection (CWE-611 Improper Restriction of XML
  External Entity Reference; matches the existing `xxe_entity_resolution`
  concern-ID).** Java's standard `javax.xml.parsers.DocumentBuilderFactory`
  historically defaults to resolving external entities and DOCTYPE
  declarations unless a caller explicitly disables them — a
  well-documented, Java-idiomatic footgun distinct from any scripting-stack
  XML-parsing default. Realistic feature: a Confluence-style content-import
  or Jira-style XML-backup/attachment-processing path that parses an
  uploaded XML document with a default-configured parser.
- **Insecure deserialization (CWE-502 Deserialization of Untrusted Data).**
  Java's native `ObjectInputStream`/Jackson polymorphic-typing
  deserialization of untrusted data is one of the most-cited Java-specific
  vulnerability classes industry-wide (the general class behind the
  "Java deserialization gadget chain" family of RCEs). Realistic feature: a
  legacy webhook/integration endpoint or an attachment-processing path that
  deserializes a client-supplied Java object graph (or a Jackson mapper with
  default/polymorphic typing enabled) instead of parsing a fixed, typed
  request DTO.

**Considered and not selected for this pick:** Spring MVC mass-assignment
via unguarded `@ModelAttribute` binding (CWE-915; real CVE precedent:
[CVE-2022-22968, Spring Framework's `disallowedFields` case-sensitivity
bypass](https://spring.io/blog/2022/04/13/spring-framework-data-binding-rules-vulnerability-cve-2022-22968/)) —
a genuinely Spring-specific footgun, but `mass_assignment` is already a
built concern-ID with existing `php_laravel` manifests
(`lab/manifests/mass_assignment_laravel_sample.yaml`,
`mass_assignment_sample.yaml`), so building a third mass-assignment variant
here would not add the breadth §0a item 4 asks for over the other three
candidates above, which are all currently unbuilt classes. Flagged here
(not silently dropped) since it remains a strong, real, stack-specific
candidate for a later page in this app if this pilot's page budget allows,
or for another category's Java/Spring pick.

## 5. Sources

- [Incoming webhooks for Slack](https://slack.com/intl/en-fi/help/articles/115005265063-Incoming-webhooks-for-Slack)
- [Slash commands — O'Reilly, "Building Slack Bots"](https://www.oreilly.com/library/view/building-slack-bots/9781786460806/ch06s02.html)
- [Rapid7 Analysis: CVE-2022-26134](https://www.rapid7.com/blog/post/ra-cve-2022-26134-analysis/)
- [Atlassian Confluence Exploit — CVE-2021-26084 (ExtraHop)](https://www.extrahop.com/resources/detections/cve-2021-26084-atlassian-confluence-exploit)
- [Confluence Server Webwork OGNL injection — CVE-2021-26084 (Atlassian Jira tracker)](https://jira.atlassian.com/browse/CONFSERVER-67940)
- [How to add an attachment to a JIRA issue using REST API](https://confluence.atlassian.com/jirakb/how-to-add-an-attachment-to-a-jira-issue-using-rest-api-699957734.html)
- [Confluence Cloud REST API — content attachments](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content---attachments/)
- [Confluence: Managing Webhooks](https://confluence.atlassian.com/doc/managing-webhooks-1021225606.html)
- [Atlassian's Cloud Engineering Overview](https://www.atlassian.com/blog/atlassian-engineering/cloud-overview)
- [atlassian-connect-spring-boot](https://bitbucket.org/atlassian/atlassian-connect-spring-boot)
- [Spring Framework Data Binding Rules Vulnerability (CVE-2022-22968)](https://spring.io/blog/2022/04/13/spring-framework-data-binding-rules-vulnerability-cve-2022-22968/)
- [CWE-915 — ClouDefense.ai](https://www.clouddefense.ai/cwe/definitions/915)
- `docs/research/site-architecture-survey.md` (existing, already-cited architecture research for Slack/Notion/Atlassian/MS365/Google Workspace)
- `lab/safety_matrix.yaml` and `docs/research/corpus-examples/` (existing project vocabulary, checked for breadth per §0a item 4)
- [MITRE CWE Top 25](https://cwe.mitre.org/top25/) (consulted as one input, per the plan's explicit instruction; CWE-918/CWE-611/CWE-502 all appear in the wider CWE Top 25 corpus MITRE maintains)

## 6. Phase C app design — identity, pages, and per-page vulnerability class

Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4's requirement that
each app have its own name, its own coherent page set, and its own
opaque case-ID scheme — never reusing `puppy-fort-factory`'s or
`php_laravel`'s case IDs.

### 6a. "Huddle Hub" — Slack-style app (reuses `php_laravel` emitter)

Case-ID prefix: `HHB-*`.

A small team-messaging workspace app, coherent around the real Slack
features researched in §1:

| Page/route | Real-feature grounding | Vulnerability class (§2) |
|---|---|---|
| `/webhooks/events` (inbound Events-API-style callback receiver) | Slack signs every inbound callback with `X-Slack-Signature`; app must verify before trusting the payload (§1) | Webhook-signature-verification bypass (CWE-347/345) — vulnerable twin uses PHP `==` loose comparison instead of `hash_equals()` |
| `/messages/unfurl` (link-preview fetch when a URL is pasted into a message) | Link unfurling fetches a user-supplied URL server-side for a preview (§1) | SSRF (CWE-918) — vulnerable twin has no allowlist/redirect check on the fetched URL |
| `/integrations/outgoing-webhook` (admin configures a URL + trigger word; app calls out on a match) | Outgoing webhooks / slash commands: Slack (here, the app itself) calls a configured URL and passes along message context (§1) | Header injection / CRLF (CWE-113/93) — vulnerable twin builds the outbound request's headers by string concatenation of the trigger word/channel name |

### 6b. "TrackerNest" — Atlassian-style app (new Java/Kotlin+Spring Boot emitter)

Case-ID prefix: `TRN-*`.

A small issue-tracker-plus-wiki app, coherent around the real Jira/
Confluence features researched in §3:

| Page/route | Real-feature grounding | Vulnerability class (§4) |
|---|---|---|
| `/wiki/pages/{id}/render` (renders a page body containing macro-style template blocks) | Confluence macro/template rendering — the real feature behind CVE-2021-26084/CVE-2022-26134 (§3) | Server-side template/expression injection (CWE-1336) — vulnerable twin evaluates a macro parameter as an OGNL-style expression instead of treating it as data |
| `/issues/{id}/import` (imports issue data from an uploaded XML document, mirroring Jira's XML-backup/import path) | Jira XML backup/import, Confluence content import (§3) | XXE (CWE-611) — vulnerable twin parses the uploaded XML with a default-configured `DocumentBuilderFactory` (external entities/DOCTYPE not disabled) |
| `/integrations/webhook-payload` (a legacy integration endpoint accepting a serialized payload) | Jira/Confluence webhook and Connect-app integration payloads (§3) | Insecure deserialization (CWE-502) — vulnerable twin deserializes the client-supplied object graph directly (native `ObjectInputStream` or a Jackson mapper with polymorphic typing enabled) instead of parsing into a fixed, typed DTO |

Each row above is a vulnerable/secure twin pair per this project's standard
manifest convention (one manifest per class, matching `php_laravel`'s own
`phase3_php_laravel_real_pages_*.yaml` pattern) — the actual manifest
authoring is Phase C's step 3, not done as part of this design pass.

**Not yet decided by this design:** exact request/response shapes, ORM/
query-builder choice for TrackerNest's persistence (Phase A's skeleton
decision determines this, same dependency `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
§2 task 3 flagged for the original `node_express` plan), and the full
`labels.json`/`injection-points.json` ground truth for either app (Phase C
step 2) — this section is the page/vulnerability-class design the rest of
Phase C builds from, not the finished ground truth itself.
