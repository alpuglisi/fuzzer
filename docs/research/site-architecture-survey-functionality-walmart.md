# Walmart — functionality research + Node/Express-specific CWE shortlist

Produced for `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.5 step 2-3
(category 1 pilot, E-commerce, Walmart/Node-Express pick). Architecture
facts (Node.js/Java microservices, Node.js BFF layer) are carried over
unchanged from `docs/research/site-architecture-survey.md`'s already-
confirmed entry — not re-researched here.

## 1. Walmart functionality/pages + BFF implications

**Storefront (catalog/search/PDP/cart/checkout)**

- Search: "Lessons from Building Low Latency Search at Walmart" (Jilson
  Joseph, Medium) — scaling from 10k to 10M queries/day; a real lesson: a
  single shared Elasticsearch cluster serving search + inventory +
  analytics + recommendations caused search-latency incidents, fixed by
  splitting into workload-dedicated clusters. *(Confidence: single
  detailed third-party/practitioner source, moderate.)*
- Order/cart/checkout/payment-authorization/inventory-reservation: "Design
  Patterns and System Architecture: Walmart.com Case Study" (Ram
  Kashigari, Medium) and **"Microservices with Orchestration and
  Choreography"** (Navdeep Singh, **Walmart Global Tech Blog** — primary
  source): order management is orchestrated by a BPM engine —
  payment authorization → inventory reservation → routing to store/
  warehouse → pick/pack → ship → deliver/return, each a separate
  bounded-context service. *(Confidence: primary source — confirmed.)*
- Order tracking/history/account management: directly observable from
  walmart.com's own support pages (sign in → "Your Orders" → per-item/
  per-shipment tracking, sometimes split into multiple shipments/tracking
  numbers with separate carrier-scan, pickup-readiness, return, and refund
  states). *(Confidence: primary source for the customer-facing flow
  shape, not internal service boundaries.)*

**Node.js migration / BFF specifics**

- **"Migrating Large Enterprise to NodeJS"** (Joel Chen, Walmart Global
  Tech Blog, 2018) — primary source, confirmed: Walmart moved off legacy
  Java to a Node.js server stack (originally `hapi` with custom "server
  partials"), using Node specifically as an **orchestration/aggregation
  layer in front of the legacy Java back end** — Node's job is to call
  multiple Java services and assemble one response for the client.
  Independently corroborated by the OpenJS Foundation's own Walmart
  Node.js case-study PDF — two independent sources, confirmed.
- General BFF responsibility split (pattern literature, not Walmart-
  specific primary sourcing beyond the above): aggregate several
  backend/microservice calls into one client-tailored response, a
  distinct BFF per frontend surface. **Not confirmed at Walmart-specific
  granularity** (no source found spelling out "this BFF endpoint
  aggregates services X, Y, Z") — the generic characterization is
  well-established (Netflix/SoundCloud BFF-pattern origin), consistent
  with but not verbatim-sourced to Walmart's own description.
- **Vulnerability-placement implication (synthesis, not a sourced claim):**
  a BFF aggregation endpoint (e.g. a product-detail-page endpoint calling
  pricing + inventory + reviews services and merging the three) plausibly
  mishandles one service's error/absence differently than the others —
  e.g. "inventory service timed out" treated as "in stock" (fail-open)
  while "pricing service errored" is correctly a hard failure. A
  design inference worth using in Phase C page design, but flagged
  explicitly as inference, not sourced fact.

## 2. Node/Express-specific CWE shortlist

Cross-checked against `lab/safety_matrix.yaml` (a stack-capability matrix,
not a CWE registry — not the right thing to check) and every
`docs/research/corpus-examples/*/*/manifest.yaml` (the full existing CWE
footprint, ~140 IDs).

| CWE | Why Node/Express-specific | Realistic page/flow | Corpus status |
|---|---|---|---|
| **CWE-1333** (ReDoS) | Real, current Express-ecosystem CVE: **CVE-2024-45296**, `path-to-regexp` (Express's own routing dependency) — a two-parameter route segment separated by a non-`.` character causes catastrophic backtracking (Express.js's own Sept-2024 security-release post, plus secondary write-ups). Also a real `body-parser` DoS (<1.20.3). | User-controlled search/filter reaching an unbounded regex (e.g. "highlight my search term" using the term as a regex), or a route-pattern shape stressing `path-to-regexp` itself. | **Genuinely new** — confirmed absent from the corpus (no `CWE-1333` anywhere), and `docs/architecture/oracle-confirmation.md` explicitly lists ReDoS under out-of-scope-for-now ("could use M1 timing later") — the project already identified this gap and deferred it. **Needs a timing-differential oracle (M1), not a single-request oracle** — a different confirmation shape than SQLi/XSS, worth flagging to whoever designs this module. |
| **CWE-1321** (Prototype Pollution) | JS/Node-specific weakness class (no prototype-chain equivalent in this project's PHP/Python stacks). Real npm CVEs: CVE-2019-10744 (lodash `merge`/`defaultsDeep`), CVE-2018-16487 (lodash `merge`/`mergeWith`/`defaultsDeep`), CVE-2020-8203 (lodash `zipObjectDeep`) — verified via Snyk's vulnerability DB. | A BFF "update account preferences" or "apply cart/checkout options" endpoint deep-merging a JSON body into a settings object via `Object.assign`, a hand-rolled deep-merge, or unguarded lodash `merge`/`_.set` — plausible for a BFF assembling/patching aggregated objects. | **Correction to the task brief's assumption — not fully absent.** CWE-1321 already appears once, incidentally (`insecure-deserialization/node/manifest.yaml`'s `idiomatic-job-spec-no-eval-2.js`, a `cwe_unique` side-effect of a bracket-lookup gadget, not an actual pollution demonstration), and is already named as its own first-class sourcing class (`proto_pollution`, target_count 3) in `lab/patterns/sourcing/crosswalk.yaml`. **What's actually missing: a dedicated vulnerable/secure pair demonstrating the real pollution mechanism** (deep-merge into a live object, escalating to a gadget) — that specific gap is real and worth filling, described accurately rather than as "not in the corpus at all." |
| CWE-77 (present) / **CWE-78** (Command Injection, `exec` vs `execFile`/`spawn`) | `child_process.exec()` invokes a shell (shell metacharacters live) vs. `execFile`/`spawn` with an argument array (never invokes a shell) — a genuine, well-documented Node-specific idiom split, analogous to but a different developer-mistake shape than PHP's `shell_exec`/`escapeshellarg`. | A BFF/admin "generate report export" or "resize uploaded product image" endpoint shelling out via `exec(\`convert ${file} ...\`)` instead of `execFile('convert', [file, ...])`. | **Minor refinement, not a new class.** CWE-77 (general command-injection) already exists in the corpus; CWE-78 specifically does not — but the underlying *shape* (unsanitized input into a shell command) is likely already covered by the existing CWE-77 cell. Check that cell before treating this as adding real breadth. |
| **CWE-943** (NoSQL/MongoDB query-object injection) | Real, well-known pattern (`{$ne: null}`/`{$gt: ''}` operator injection via unsanitized input spread into a Mongoose/native-driver filter). `docs/architecture/oracle-confirmation.md` already names a `nosql-injection` oracle strategy conceptually. | — | **Flagged, not recommended without an explicit scope decision.** `node_express`'s actual persistence layer is `mysql2` (relational — confirmed by reading `fuzzlab/labgen/emitters/node_express/modules.py`, parameterized `pool.query`), matching this plan's SQLite-for-conformance/MariaDB-for-production split. Adding MongoDB as this app's *primary* datastore to host one page would give it a second, different persistence stack than the rest of `node_express`'s module inventory — a bigger architectural decision than "add a CWE." The corpus does already use Mongoose in one illustrative snippet (`mass-assignment/node/*mongoose*`), but that's a standalone cell, not the app's DB choice. **Do not add silently — needs an explicit call.** |
| `express.static`/path-traversal misconfiguration | A hand-rolled file-serving route next to `express.static()` (which normalizes `..` by default and is comparatively hard to misuse directly) — e.g. `res.sendFile(path.join(uploadsDir, req.query.file))`. | Order-history "download receipt/invoice" or product-image-serving route — BFF/e-commerce-appropriate. | **Already covered.** CWE-22 and CWE-434 both present multiple times in `corpus-examples/file-handling/node/manifest.yaml`. Realistic *page*, not a new CWE. |

**Breadth ranking (most to least novel given the corpus's ~140-CWE
footprint):**

1. **CWE-1333 (ReDoS)** — genuinely absent, genuinely Express-specific
   (real `path-to-regexp`/`body-parser` CVEs), needs a new oracle shape
   the project has already flagged as deferred. Strongest pick.
2. **CWE-1321 (Prototype Pollution)** — the ID exists once incidentally
   and is named in the sourcing crosswalk, but no dedicated demonstration
   page exists. Still a strong pick — just describe accurately as "no
   dedicated cell yet," not "absent."
3. **CWE-78 vs. present CWE-77** — minor refinement, check the existing
   cell first.
4. **CWE-943 (NoSQL injection)** — flagged, not recommended without an
   explicit persistence-layer scope decision from the project owner.
5. **`express.static`/path traversal** — realistic page, not new breadth
   (CWE-22/434 already well-covered).

## 3. Sourcing and confidence notes

- Primary (Walmart's own blog), confirmed: "Migrating Large Enterprise to
  NodeJS" (Joel Chen, 2018); "Microservices with Orchestration and
  Choreography" (Navdeep Singh) — both Walmart Global Tech Blog/Medium.
  Independently corroborated by the OpenJS Foundation's own Walmart
  Node.js case-study PDF.
- Secondary/practitioner (moderate confidence, author's Walmart
  affiliation not independently verified): "Lessons from Building Low
  Latency Search at Walmart" (Jilson Joseph); "Design Patterns and System
  Architecture: Walmart.com Case Study" (Ram Kashigari).
- Primary (walmart.com itself): the order-tracking help-center flow —
  confirmed for customer-facing UX shape, not internal architecture.
- Not confirmed: a Walmart-specific primary source naming exactly which
  backend services one BFF endpoint aggregates — only generic BFF-pattern
  literature found.
- CWE definitions/parent-child relationships checked against MITRE
  directly; CVE claims checked against Snyk's vulnerability DB (lodash
  CVEs) and Express.js's own Sept-2024 security-release post
  (CVE-2024-45296). All CVE/CWE numbers verified via search this session,
  not recalled from training data.
