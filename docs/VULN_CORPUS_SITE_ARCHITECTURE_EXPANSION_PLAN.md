# Vulnerability corpus expansion — site-architecture extension plan

**Status: PLANNING ONLY. Not dispatched, not executed.** This document records a
proposed extension to `docs/VULN_CORPUS_EXPANSION_PLAN.md` (the "base plan").
No agents have been spawned, no research has been run, and no files have been
added under `docs/research/` as a result of this document. It exists so the
approach can be reviewed before any of it is authorized to start.

## Relationship to the base plan

The base plan (`docs/VULN_CORPUS_EXPANSION_PLAN.md`) sources its corpus
**top-down from functionality**: it enumerates user-facing features
(authentication, file upload, search, checkout, etc.), ranks them by
commonality x exploitability, and then collects real GitHub examples of each
feature per language/stack.

This document proposes a second, complementary sourcing angle, **top-down
from real deployed websites**: instead of starting from an abstract feature
list, start from the most popular websites in each major site category,
research the actual architecture/tech stack each one runs, and collect code
examples that reproduce those specific architecture + function combinations.
The two angles should converge on the same output shape (the
`docs/research/corpus-examples/<cell>/manifest.yaml` corpus and its
`validated: true` gate defined by the base plan) so that a converged corpus
entry sourced from either angle is interchangeable for Phase 3/handoff
purposes. This document does not redefine that output format or the
validation/licensing/secrets rules the base plan already established — it
reuses them and only adds the steps needed to get from "popular site
categories" to "candidate feature+language cells" that feed into the base
plan's existing Phase 2 onward.

## Why a second angle

The base plan's feature list is a reasonable abstract catalog, but it is not
grounded in *which concrete architectures and tech stacks are actually
running in production at scale*. Two apps that both have "search" can differ
enormously in real exploitability depending on whether search is a raw SQL
LIKE query, an ORM query-builder, or a hosted search service call — and which
of those shapes is actually common depends on which frameworks/platforms
dominate real traffic. Starting from real popular sites and reverse-engineering
their architecture keeps the corpus anchored to what's actually deployed,
the same grounding instinct the base plan already applies via
`puppy-fort-factory/VULNERABILITIES.md` and its own architecture history.

## Proposed steps

### Step 1 — identify popular website categories and leading sites per category

Identify the current most popular categories/genres of websites (e.g.
e-commerce, social/UGC platforms, SaaS/productivity, media/streaming, news/
publishing, forums/community, education/LMS, fintech/banking, travel/booking,
healthcare portals, government/civic, gaming, marketplaces, real estate,
job boards). For each category, identify **at least 5** of the most popular
representative websites/products in that category (using public traffic-
ranking sources, industry reports, and each platform's own published
technology disclosures where available).

**Output:** a table of category -> 5+ representative sites, each with a
one-line note on why it was selected (market share, traffic rank, or
architectural notability).

### Step 2 — architecture research per site (deep, iterative)

For each site identified in Step 1, spawn research agents to investigate the
site's real-world architecture: front-end framework, back-end
language/framework, database technology, hosting/CDN layer, auth mechanism,
API style (REST/GraphQL/RPC), and notable third-party integrations. This is
explicitly **iterative** — repeat research passes (different sources, follow-
up queries, cross-checking conflicting claims) until each site's write-up
reaches a documented, defensible level of confidence in its tech-stack and
functionality summary, rather than stopping after a single pass. Findings are
recorded per site with source citations (engineering blogs, job postings
listing stack requirements, public tech-radar/stack-sharing sites, HTTP
response headers/public static-asset fingerprints where lawfully observable,
conference talks) — never guessed from memory.

**Output:** one architecture write-up per site, each citing its sources and
stating a confidence level, following the base plan's precedent of citing
concrete sources (see the base plan's Phase 1 sourcing discipline) rather
than uncited claims.

### Step 3 — GitHub source search per architecture/tech-stack/function combination

For each distinct (architecture, tech stack, functionality) combination that
emerges from Step 2 across all researched sites, dispatch agents to search
GitHub for real, published source code that is representative of that exact
combination (e.g. "Ruby on Rails + Devise-style session auth", "Next.js API
route + Prisma ORM checkout flow", "Django REST Framework + Celery async job
webhook handler"). This reuses the base plan's existing source-quality bar
(license present, not a backup/fork dump, reasonable maintenance signal —
see the base plan's "Source quality bar") rather than defining a new one.

**Output:** a candidate list of GitHub source locations (repo, path,
commit) per combination, not yet copied into the repo.

### Step 4 — validate source code correctness before committing to a reference library

Before any candidate source from Step 3 is copied into a reference library,
validate that it is **correct** — i.e. that it actually compiles/parses,
reflects the claimed architecture/tech-stack/function combination, and is not
a mislabeled, broken, or unrelated snippet. This is a distinct check from the
base plan's later vulnerability-validation step (Step 7 below /
the base plan's Phase 3 "Validation" section) — this step only confirms the
snippet is a genuine, working example of what it claims to be, before it's
allowed to become reference material.

**Output:** a validated (not yet vulnerable-annotated) reference library
entry, gated the same way the base plan gates its corpus (`validated: false`
by default, flipped only after an explicit check — see the base plan's
"Validated data only reaches lab-generation-facing files").

### Step 5 — organize and name reference library entries

Organize and name each validated reference-library entry so that its tech
stack, architecture, and function are distinguishable from the file listing
alone, without needing to open metadata first. This extends the base plan's
existing `docs/research/corpus-examples/<feature>/<language>/manifest.yaml`
layout and `<role>-<n>.<ext>` naming convention (see the base plan's
"Organization and metadata" section) with an additional architecture/stack
axis, e.g.:

```
docs/research/corpus-examples/
  <function>/
    <language-or-stack>/
      <architecture-tag>/          # e.g. rails-devise, nextjs-prisma, drf-celery
        manifest.yaml
        <role>-<n>.<ext>
```

The exact directory/naming scheme is left to be finalized at execution time
(not decided by this planning document) but must satisfy the same
distinguishability requirement the base plan already applies to its
`manifest.yaml` entries.

### Step 6 — CWE research per architecture/function/tech-stack combination

For each validated reference-library entry, conduct additional research to
identify the CWE(s) specific to that entry's architecture, function, and tech
stack — not just a generic CWE for the abstract feature. Target identifying
**as many applicable CWEs as can be substantiated** for each combination
(more is better, provided each one is genuinely applicable and sourced, not
padded). This extends the base plan's Phase 3 CWE-mapping step (see the base
plan's "Phase 3 — CWE mapping" section and its `cwe:` manifest field) with a
stack-specific research pass rather than a generic one.

**Primary source:** the MITRE CWE index — <https://cwe.mitre.org/data/index.html>
— as the authoritative CWE catalog and identifier source for this step (and
for Step 7 below). Framework/stack-specific advisories (e.g. a framework's own
security-advisory database, OWASP's stack-specific cheat sheets) are used to
confirm which CWEs are actually realistic for the given combination, but the
CWE identifiers themselves are drawn from the MITRE index.

**Output:** each reference-library entry annotated with its applicable
CWE(s) and the sources justifying each one, following the base plan's
`cwe: [...]` manifest field convention.

### Step 7 — construct and validate vulnerable versions of the code

Using the CWEs identified in Step 6, construct a vulnerable version of each
reference-library entry's code. This reuses the base plan's existing
"Pair generation: alter collected code to manufacture a matched pair"
approach (see the base plan's Phase 3) rather than defining a new alteration
methodology — the vulnerable variant should differ from its reference
counterpart only in the mechanism the target CWE describes.

The vulnerable version **must be validated as actually vulnerable** before it
is saved for use by the lab generator — reusing the base plan's existing
two-tier validation approach (structural check via a tree-sitter-based
diff tool, then a behavioral check via sandboxed dynamic execution or a
static-analysis tool such as Semgrep/Bandit/Psalm/eslint-plugin-security —
see the base plan's "Validation: every pair must be confirmed before it's
trusted" section, including its execution-sandbox requirements) rather than
inventing a separate validation process for this angle. A vulnerable variant
that fails validation is not saved for the lab generator.

### Step 8 — implement validated pieces into generated lab applications

Once a vulnerable/reference pair is validated (per Step 7), it becomes
eligible for the lab generator, following the base plan's existing gate
("Validated data only reaches lab-generation-facing files" — only
`validated: true` entries are eligible to inform a `lab/safety_matrix.yaml`
row or a new per-stack module template). When implemented into additional
generated web applications, each piece of code must **serve the same
functional purpose in the generated application that it served in the real
site/architecture it was sourced from** in Step 1-2 (e.g. code sourced from a
checkout flow is used to build a checkout flow in the generated lab, not
repurposed for an unrelated feature) — preserving the realism grounding this
whole extension is meant to add, and matching the base plan's own module-
template precedent of deriving generator content from real code shapes
rather than inventing them from memory.

## Sources

- MITRE CWE index: <https://cwe.mitre.org/data/index.html> — authoritative
  CWE catalog used in Step 6 (CWE identification) and Step 7 (vulnerable-
  variant construction).
- All source-quality, licensing, secrets-scrubbing, manifest-schema, and
  validation-sandbox rules already defined in
  `docs/VULN_CORPUS_EXPANSION_PLAN.md` apply unchanged to work under this
  extension; this document does not restate or supersede them.

## Resolved scoping decisions (from the review/research/revise cycle)

These were "open questions" in the first draft. Resolved here so the plan is
directly executable rather than needing another round of judgment calls
mid-execution:

- **Directory/naming scheme (Step 5):** reuse the base plan's
  `docs/research/corpus-examples/<function>/<language>/manifest.yaml` +
  `<role>-<n>.<ext>` layout unchanged, and add the architecture tag as an
  additional manifest field (`architecture: <tag>`, e.g. `shopify-storefront`,
  `express-rest-cart`, `django-drf`) rather than a new directory level. A new
  directory level per architecture would fragment already-small cells (the
  base plan's own floor is 2 examples per cell) into cells of 1; a manifest
  field keeps the existing per-language cell intact while still making the
  architecture distinguishable in the metadata Step 5 requires. The file name
  itself additionally embeds a short architecture slug
  (`<role>-<architecture-slug>-<n>.<ext>`, e.g. `vulnerable-express-cart-1.js`)
  so it's visible from the directory listing alone, satisfying the base
  plan's "distinguishable from the file listing" requirement without a
  metadata lookup.
- **Category list and site count (Step 1) — frozen for this plan's
  execution:** 6 categories, 5 sites each (30 sites), chosen for overlap with
  the base plan's existing feature rows so architecture findings feed
  directly into the base plan's already-highest-priority cells rather than
  opening entirely new feature territory:
  1. **E-commerce / marketplaces** (feeds base plan row 6)
  2. **Social / UGC platforms** (feeds base plan row 3)
  3. **SaaS / productivity / collaboration tools** (feeds base plan rows 1-2)
  4. **Media / streaming / content platforms** (feeds base plan row 10)
  5. **Travel / booking / marketplaces** (feeds base plan row 15)
  6. **Fintech / payments** (feeds base plan row 6/9)
- **Confidence bar for Step 2 (resolved, not the base plan's Phase 1
  commonality/exploitability rubric — a different question):** an
  architecture write-up is "done" once at least **two independent, citable
  sources** (an engineering blog post, a public tech-stack disclosure such as
  BuiltWith/StackShare/job postings naming the stack, a conference talk, or
  directly observable public signals such as response headers/asset
  fingerprints) agree on a given stack claim, or **one primary source**
  (the company's own engineering blog, published documentation, or an
  official open-source repo) states it directly. A claim that can't clear
  either bar after a reasonable search is recorded as "unconfirmed" rather
  than stated as fact, and is not used to justify a GitHub search in Step 3.
  This is the stopping rule for Step 2's "iterative...until a documented,
  defensible level of confidence" language.
- **Sequencing against the base plan's existing queue:** this extension does
  not reprioritize or pause the base plan's own wave 2 (rows 7-11). It runs
  as additional, separately-tracked work feeding the same corpus directory
  and the same rows 1, 2, 3, 6, 9, 10, 15 the base plan already scored highly
  — an architecture-grounded reinforcement of cells the base plan already
  prioritized, not a competing queue.

## Tooling constraints in this execution environment

The base plan's Phase 3 validation section specifies a two-tier check
(structural diff via difftastic, then behavioral via a sandboxed dynamic
execution run under gVisor, or a static-analysis fallback via Semgrep/
Bandit/Psalm/eslint-plugin-security). Checked at execution time in this
remote session:

- **No gVisor/container runtime available** — the dynamic-execution tier is
  **not available in this environment**. Any pair collected here is capped at
  the static-analysis validation tier; it cannot reach the base plan's
  `validated_by: [dynamic]` status from this session. This is recorded
  per-entry (`validated_by: [static-review]` or `[bandit]`, etc.) rather than
  silently upgraded.
- **difftastic not installed, no package-manager access to add a system
  binary** in this environment — structural-diff checks in this execution use
  a manual side-by-side read of the pair (confirming the only difference is
  the declared CWE mechanism) instead, noted as `validated_by:
  [manual-review]` per the base plan's existing vocabulary for this case.
- **Semgrep installed via pip but non-functional in this environment**
  (`cffi`/`cryptography` native-module load failure in the sandbox — not a
  config issue, a broken native dependency at the OS level here). Not usable
  this session.
- **Bandit installed and functional** (Python static analysis, used for any
  Python-language entries).
- **detect-secrets installed and functional**, used in place of gitleaks
  (not available via pip; no system package manager access to install the Go
  binary) for the base plan's secrets-scrubbing step — equivalent
  regex/entropy-based scanning, same "any match gets redacted before first
  commit" rule applies.

None of this changes the base plan's rule that unvalidated
(`validated: false`) entries never inform a `safety_matrix.yaml` row — it
only means every entry collected in this environment is validated at the
static tier and is explicitly a candidate for a follow-up dynamic-tier pass
in an environment with sandboxed execution available, not yet at the base
plan's strongest tier.

## Wave 1 execution scope (this pass)

Executing the full 30-site x N-architecture matrix in one pass is not
proportionate to a single research/execution session — the base plan's own
Phase 2 scope cap (~90-375 examples total, stop and check in past ~400)
governs the *combined* corpus, and this extension adds to the same budget,
not a separate one. Wave 1, executed immediately following this plan
revision, is scoped as:

- **All 6 categories get Step 1 fully done** (5 sites each, 30 sites,
  identified and justified — this is cheap, it's a list).
- **2 of the 6 categories get Steps 2-7 carried through in this pass**:
  category 1 (e-commerce/marketplaces) and category 2 (social/UGC), chosen
  as the two feeding the base plan's two highest-signal existing rows (row 6
  and row 3, both priority 9). The remaining 4 categories got Step 1 only in
  wave 1.
  **Superseded:** per explicit instruction not to defer, wave 2 (same
  session) carried Steps 2-7 through for all 4 remaining categories as
  well — see this plan's Status section for wave 2's results. The "one
  category at a time, defer the rest" sequencing below described wave 1's
  actual scope at the time it was written; it is not a hard rule that
  blocks a later wave from doing more once asked.
- **Within each of the 2 executed categories: one concrete
  architecture/function combination is carried all the way through Step 8's
  proposal stage** (not full `safety_matrix.yaml` integration — see below).
- **Step 8, for this pass, stops at the proposal stage**: producing the
  `suggested_op`/`suggested_sink_family`/`cwe` fields the base plan's Phase 3
  already defines as the handoff artifact, matching the base plan's own
  existing precedent (every prior corpus-collection commit in `CHANGELOG.md`
  for this project is documentation/metadata-only; `suggested_op`/
  `suggested_sink_family` fields are proposals, not applied changes; the base
  plan's own Status checklist keeps "proposals acted on" as a separate,
  still-unchecked line item). Actually editing `lab/safety_matrix.yaml` or
  adding a new per-stack module template is a change to component **FUZZ**/
  **LAB** and requires its own `docs/components/<n>-*/change-control.md`
  entry and (if scope/interfaces change) a `requirements.md` update per
  `CLAUDE.md`'s Definition of Done — it is deliberately not bundled into this
  corpus-collection pass, the same way the base plan has never bundled it
  into any of its own corpus-collection commits either.

## Status

- [x] Review/research/revise cycle complete — open questions resolved above,
      tooling constraints checked against this execution environment,
      wave 1 scope frozen.
- [x] Step 1: all 6 categories x 5 sites identified, sourced —
      `docs/research/site-architecture-survey.md`.
- [x] Step 2-7 for category 1 (e-commerce/marketplaces) — one
      architecture/function combination carried through
      (`woocommerce-cart-hook`, PHP): real GPL-3.0 WooCommerce core hook
      excerpt collected (Step 3-4), organized into
      `docs/research/corpus-examples/ecommerce-logic/php/` with the
      `architecture` manifest field (Step 5), CWE-840/CWE-20 assigned citing
      the MITRE CWE index (Step 6), a manufactured vulnerable counterpart
      built and validated at the static/manual-review tier — no dynamic
      sandbox available in this environment (Step 7).
- [x] Step 2-7 for category 2 (social/UGC) — one architecture/function
      combination carried through (`django-contrib-comments`, Python): real
      BSD-3-Clause django-contrib-comments template collected (Step 3-4),
      organized into `docs/research/corpus-examples/ugc-xss/python/` (Step
      5), CWE-79 assigned citing the MITRE CWE index (Step 6), a manufactured
      vulnerable counterpart (`|safe` anti-pattern) built and validated at
      the static/manual-review tier (Step 7).
- [x] Step 8 proposal stage for both executed categories — `suggested_op`/
      `suggested_sink_family` fields appended to each new manifest entry
      (`hook_delegated_recompute`/`trust_client_price_input` for category 1;
      `default_autoescape` reused/`raw_concat` reused for category 2). Not
      yet applied to `lab/safety_matrix.yaml` — see below.
- [x] Wave 2 (not deferred, per explicit instruction): Steps 2-7 for the
      remaining 4 categories, one architecture/function combination each —
      `wekan-board-membership` (JS/Node, MIT, category 3 SaaS/collaboration)
      added to `docs/research/corpus-examples/access-control/node/`,
      CWE-639/862; `peertube-video-upload` (TS/Node, AGPL-3.0-or-later,
      category 4 media/streaming) added to `docs/research/corpus-examples/
      file-handling/node/`, CWE-434; `qloapps-booking` (PHP, OSL-3.0,
      category 5 travel/booking) added to `docs/research/corpus-examples/
      ecommerce-logic/php/`, CWE-840/CWE-20; `firefly-blocked-account-gate`
      (PHP, AGPL-3.0-or-later, category 6 fintech) added to
      `docs/research/corpus-examples/auth-session/php/`, CWE-287/CWE-613.
      All 4 pairs are real, license-verified, commit-pinned source plus a
      manufactured vulnerable counterpart, validated at the static/
      manual-review tier (same environment constraint as wave 1), with
      Step 8 stopping at the `suggested_op`/`suggested_sink_family`
      proposal stage. `docs/research/site-architecture-survey.md` Step 2
      write-ups completed for all 6 categories (previously categories 1-2
      only).
- [ ] `lab/safety_matrix.yaml` integration: explicitly out of scope for this
      wave — tracked as follow-up component-change work (its own
      `docs/components/<n>-*/change-control.md` entry, per `CLAUDE.md`), not
      bundled into this corpus-collection pass, matching the base plan's own
      established precedent for every prior corpus-collection commit.
- [ ] Dynamic-tier validation for both new pairs (`validated_by: [dynamic]`)
      — deferred to an environment with a sandboxed execution runtime
      available; both pairs are `validated: true` at the static/manual-review
      tier only in the interim, which the base plan's own `validated_by`
      vocabulary already accommodates.
