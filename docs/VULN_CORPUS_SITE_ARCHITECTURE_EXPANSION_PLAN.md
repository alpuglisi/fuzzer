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

## Open questions / not decided here

- Final directory/naming scheme for the added architecture-tag axis (Step 5).
- How Step 1's category list and Step 2's confidence-level bar will be scored
  (the base plan's Phase 1 commonality x exploitability rubric may or may not
  transfer directly to a site-popularity-driven list — not resolved here).
- Whether Step 2's iterative research passes need an explicit stopping rule
  (the base plan's Phase 1 does not currently define one for this angle).
- Sequencing against the base plan's own wave 2 (rows 7-11) work already in
  flight — not decided here; this document only proposes the extension, it
  does not reprioritize the base plan's existing queue.

## Status

- [ ] Not dispatched. This document is planning only, per the instruction
      that created it — no research, collection, or code changes have been
      performed as part of this plan.
