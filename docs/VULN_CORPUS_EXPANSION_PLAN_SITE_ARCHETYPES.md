# Vulnerability corpus expansion — site-archetype extension (research plan)

**Status: planning only. Nothing in this document is to be executed until a
human explicitly says to begin.** This file is the plan itself, not a log of
work done.

This is a proposed **extension** to `docs/VULN_CORPUS_EXPANSION_PLAN.md`
("the base plan"). The base plan organizes corpus collection by abstract
*feature* (auth, search, file handling, ...) sourced from generic
commonality/exploitability research. This extension instead organizes
collection by **real website category and the concrete architectures/tech
stacks those sites actually run**, so the corpus captures how a given
feature is actually built in a specific, popular kind of application (a
Shopify-style storefront's checkout vs. a forum's checkout-adjacent
donation flow are not the same code shape), not just the feature in the
abstract.

The two tracks are complementary, not competing: the base plan's
feature list stays the organizing taxonomy for *what* gets collected;
this extension adds *which real, popular systems* to mine for each
feature, and folds a new axis (architecture/tech stack) into the
corpus's metadata and directory layout. Phase 3 of the base plan (CWE
mapping → pair manufacturing → validation) is reused as-is here, not
redefined — see "Relationship to the base plan's Phase 3" below.

## Why this extension

The base plan already produces a feature-organized corpus with real
source, license triage, gitleaks scanning, and (as of this writing) CWE
mapping for wave 1. Two gaps it doesn't close on its own:

- **Architecture/tech-stack coverage is incidental, not deliberate.**
  Collection lanes picked whatever repos turned up per feature/language;
  there's no guarantee popular real-world architectures (e.g. a Rails
  monolith vs. a Next.js app vs. a WordPress plugin ecosystem) are
  represented in proportion to their actual popularity, or that a given
  feature's examples span the stacks it's actually built on in practice.
- **Functionality is sourced generically, not from what real popular sites
  in a category actually ship.** A generic "e-commerce" feature entry
  doesn't capture what, say, a marketplace platform's specific listing/
  bidding logic looks like as distinct from a single-vendor storefront's
  cart logic — both are "e-commerce" in the base plan's taxonomy but are
  different real systems worth mining separately.

This extension's payoff is a corpus organized so a generated lab page can
say "this vulnerable pattern is representative of how popular
category-X sites built on stack-Y actually implement function-Z" — and,
per step 8 below, actually reuse that pattern inside a generated
application serving the same real-world purpose it served in the source
site's category.

## Relationship to the base plan's Phase 3

This extension's steps 6-7 (CWE identification, vulnerable-version
creation) are **the same process as the base plan's Phase 3**, not a
parallel one — same validation bar, same `manifest.yaml` schema, same
"nothing reaches lab-generation-facing files until `validated: true`"
rule, same pair-floor-scaling rule, same validation-execution-sandbox
doctrine (gVisor, zero outbound network, ephemeral fixtures). Where this
document's steps 1-5 differ from the base plan's Phase 1-2 is *only* in
how candidate features/examples are sourced (real popular sites'
concrete architectures, rather than a generic feature catalog) and in
one added metadata axis (architecture/tech-stack). Do not re-derive a
separate validation or pair-manufacturing methodology for this track —
extend the shared one if a genuine gap is found, the same way any other
finding would update a living doc.

## Step 1 — identify popular website categories and their leading sites

Produce a table: **category → ≥5 concrete, currently popular real
sites/products in that category**, each with a one-line note on why it's
representative (market share, common architecture reference point, or
being a widely cloned/copied reference implementation).

Candidate categories to start from (not exhaustive — refine during
research, subject to the base plan's own "boundary rule": merge two
categories if they'd collect the same code shapes from the same sink
families):

- **Social / community** (e.g. forums, social networks, Q&A sites)
- **E-commerce / marketplace** (single-vendor storefronts vs. multi-vendor
  marketplaces vs. auction/bidding platforms — likely worth splitting,
  since their transaction/inventory logic differs architecturally)
- **Content / publishing / blogging** (CMS-driven sites, static-site-
  generator-driven sites, newsletter platforms)
- **SaaS / productivity / collaboration** (project management, docs/
  wikis, chat/collaboration tools)
- **Media streaming / sharing** (video, audio, image hosting)
- **Financial / fintech** (banking-adjacent, payments, budgeting)
- **Booking / marketplace-for-services** (travel, reservations, on-demand
  services)
- **Developer tools / code hosting** (package registries, CI/CD dashboards,
  git hosting)
- **Education / e-learning** (course platforms, LMS)
- **Government / public-sector-style portals** (forms-heavy, identity-
  verification-heavy — often a distinct architecture pattern worth
  capturing even though real government sites themselves aren't
  representative reference implementations to mine directly; use the
  open-source platforms that model this pattern, e.g. widely-deployed
  civic-tech stacks)

**Method:** for each category, identify ≥5 sites/products using a mix of
independent signals (not opinion alone) — e.g. traffic-ranking sources,
industry reports on platform/CMS market share (for stacks that are
themselves products, like WordPress/Shopify/Django-based platforms),
and "most forked/starred open-source clone or reference implementation
of X" where the real production site's code isn't available. Record
sources per category the same way the base plan's Phase 1 records
sources per feature (so scoring/selection is auditable, not vibes).

**Output:** a table in this document (or a linked
`docs/research/site-archetypes-catalog.md`) with columns: Category |
Representative sites (≥5) | Notes | Sources.

## Step 2 — deep architecture/tech-stack research per site (iterative)

For each site identified in Step 1, spawn research agents to determine,
to the extent publicly documented or reliably inferable:

- **Tech stack**: language(s), framework(s), datastore(s), notable
  infrastructure choices (queueing, search index, caching layer) —
  sourced from engineering blogs, published case studies, job postings
  listing their stack, public API/SDK docs revealing framework
  fingerprints, and (for open-source platforms) the actual repository.
- **Architecture pattern**: monolith vs. microservices vs. modular
  monolith; server-rendered vs. SPA-plus-API; multi-tenant vs.
  single-tenant, where discoverable.
- **Functionality inventory**: the concrete features the site
  implements that map onto the base plan's feature taxonomy (auth,
  search, file handling, checkout, etc.), noted with any
  site-specific variation worth preserving (e.g. "marketplace checkout
  splits payment across N sellers" vs. "storefront checkout is a single
  charge").

**This step repeats.** Per the user's instruction, keep iterating
research on a given site/category until there is a strong, well-sourced
understanding of its architecture, stack, and functionality — a single
research pass that turns up only marketing-page-level detail is not
sufficient; a second (or third) pass targeting engineering blogs,
conference talks, open-source components the company has released, and
(for stacks that are themselves open-source platforms) the actual
codebase is expected to be the norm, not an exception.

**Honesty requirement (mirrors the base plan's own discipline):** for
proprietary, closed-source sites, architecture/stack findings are
necessarily inferential (job postings, engineering blog posts, HTTP
fingerprinting of public-facing behavior, conference talks) — record
confidence and sourcing per finding, and never present an inferred stack
as verified fact. Where a site's architecture cannot be established with
reasonable confidence after repeated research passes, note that
honestly and prefer, for actual code collection in Step 3, the open-source
platforms/frameworks that are verifiably representative of that
category's common stacks (e.g. Discourse for forums, Saleor/Sylius for
e-commerce, Mastodon for federated social) alongside or instead of a
single closed-source site's guessed internals — the source code
collected in Step 3 must be real, inspectable, licensed code either way,
so a closed-source site's inferred architecture is only useful for
telling researchers *which kind* of open-source reference to go collect
from.

**Output:** one research note per site (or per category, if sites in a
category converge on materially the same stack/architecture — the base
plan's own "merge near-duplicates" instinct applies here too), stored
under `docs/research/site-archetypes/<category>/<site-slug>.md`,
recording stack, architecture pattern, functionality inventory, sources,
and confidence level per finding.

## Step 3 — collect representative source code per combination

For each **(architecture pattern, tech stack, functionality)**
combination surfaced in Step 2, spawn agents to search GitHub (and other
legitimate public source repositories) for source code examples
genuinely representative of that combination — reusing the base plan's
Phase 2 source-quality bar as the floor, not a lower one:

- Skip no-license repos (cite-only per the base plan's license triage),
  disk-dump repos, and forks with no meaningful changes.
- Prefer the actual open-source platform/framework code when the
  combination traces to one (e.g. real Discourse source for "forum,
  Ruby on Rails, threaded-comments") over a generic unaffiliated
  tutorial snippet claiming to implement the same thing — the whole
  point of this extension is fidelity to how popular real systems are
  actually built.
- Where a real production site's code isn't public, use the
  most-representative open-source reference implementation for that
  stack/architecture/functionality combination, and record that
  substitution explicitly in the collected example's metadata (see
  Step 5) rather than implying it came from the named production site.
- Collect multiple examples per combination where the combination is
  broad enough to have meaningful implementation variance (mirrors the
  base plan's "3-5 examples per cell, floor 2" — reuse that floor here
  per combination rather than inventing a new number).

**Output:** raw collected source files staged for validation (Step 4) —
not yet committed to the reference library. Same secrets/PII scrubbing
requirement as the base plan (gitleaks before anything is committed).

## Step 4 — validate source code before committing to the reference library

Before any collected example is committed to the reference library,
validate that it is **correct** — i.e., it actually is what it claims to
be:

- It genuinely implements the functionality attributed to it (not a
  stub, a dead code path, or a misleadingly-named example).
- It is genuinely representative of the claimed architecture/tech-stack
  combination (not, e.g., a Python file mislabeled as the Node.js
  example because it happened to live in a repo with an unrelated
  Node.js component).
- License and provenance are confirmed (repo URL, commit SHA — full
  40-char, never a branch/tag — and license, exactly as the base plan's
  Phase 2 `manifest.yaml` schema already requires).
- It parses/compiles or lints cleanly for its stated language where that
  is a meaningful correctness signal (a syntactically broken "example"
  is not representative of anything).

This is a **pre-commit gate**, distinct from and prior to the Phase-3-style
vulnerability validation in Step 7 below: Step 4 validates that the
*collected, presumed-safe/idiomatic* code is real and correct; Step 7
validates that the *deliberately altered* vulnerable twin is actually
vulnerable. Nothing skips Step 4 to go straight to Step 7.

**Output:** only examples that pass Step 4 are committed to the
reference library (Step 5's directory structure). Anything that fails is
discarded or sent back to Step 3 for a better replacement, not committed
with a caveat.

## Step 5 — organize and name the reference library

Extend (not replace) the base plan's `docs/research/corpus-examples/`
layout with the new architecture/tech-stack axis, so a file's path and
its `manifest.yaml` entry make the tech stack, architecture, and
function immediately distinguishable without opening the file:

```
docs/research/corpus-examples/<feature>/<language>/
    manifest.yaml   # extended with the fields below
    <role>-<n>.<ext>
```

Proposed `manifest.yaml` field additions (append to the base plan's
existing per-entry schema — `file`, `role`, `repo`, `commit_sha`,
`license`, `pattern`, `notes`, `validated`, `validated_by`, `redacted`,
plus Phase-3's `cwe`/`suggested_op`/`suggested_sink_family`):

- `site_category`: the Step 1 category (e.g. `ecommerce-marketplace`)
- `reference_site`: the specific site/product this example is
  representative of, or the substituted open-source reference platform
  per Step 3's substitution rule, with a `reference_is_substitute: true`
  flag when it's a substitute rather than the named site's own code
- `architecture_pattern`: e.g. `server-rendered-monolith`,
  `spa-plus-api`, `modular-monolith`
- `tech_stack`: structured, e.g. `{language: ruby, framework: rails,
  datastore: postgresql}`

Naming stays function-first (matching the base plan's existing
`<feature>/<language>/` convention) with the new fields carried as
structured metadata rather than crammed into the filename — mirrors the
project's own existing preference for `manifest.yaml`-as-canonical-
metadata over filename-encoding, since filenames can't cleanly express a
multi-field combination as it grows (a site-category *and*
architecture-pattern *and* tech-stack *and* role *and* index in one
filename becomes unreadable).

## Step 6 — identify CWEs per architecture/function/tech-stack combination

For each validated reference-library entry, research and record every
CWE genuinely applicable to that entry's specific
architecture/function/tech-stack combination — not just the one most
obvious CWE. The instruction is explicit: **the more CWEs that can be
legitimately identified and eventually implemented for a given
combination, the better** — this is a deliberate broadening goal, not
just mapping-for-mapping's-sake.

Reuse the base plan's CWE-mapping discipline exactly:

- Check `lab/safety_matrix.yaml`'s current `op`/`sink_family` vocabulary
  before proposing new names; reuse when the shape is genuinely the
  same, propose new vocabulary (with justification) when it isn't.
- A combination legitimately maps to multiple CWEs when the same code
  shape is vulnerable along independent dimensions (the base plan's own
  e-commerce examples already show this: a payment-amount trust issue is
  CWE-840/CWE-20, a same-code race condition is CWE-362/CWE-367 — both
  can apply to the same underlying checkout flow without forcing an
  artificial single-CWE label).
- Where a combination's CWE doesn't cleanly fit the existing
  `(op, sink_family, effect)` triple schema (as already flagged for
  TOCTOU/race-condition shapes in the base plan), record that
  architectural mismatch explicitly rather than forcing a bad fit, and
  route it to the same schema-design follow-up the base plan already
  identifies as open.

**Output:** each reference-library entry's `manifest.yaml` gains a `cwe`
list (already a list in the base plan's schema — this step is what
populates it richly rather than with a single token entry) plus, per
CWE, a `suggested_op`/`suggested_sink_family` pairing.

## Step 7 — create and validate vulnerable versions

For each CWE identified in Step 6, create a deliberately vulnerable
version of the corresponding reference-library code — this reuses the
base plan's Phase 3 "pair generation" step and its floor ("at least half
of the cell's available source examples, minimum 2" pairs per CWE) and
naming convention (`<role>-<n>-altered.<ext>` with a `derived_from`
field) exactly as already specified there. Do not redefine a new floor
or naming scheme for this track.

**The vulnerable version must itself be validated as being genuinely
vulnerable before being saved for use in the lab generator** — this is
the base plan's existing two-part validation (structural check via
difftastic confirming the alteration is confined to the intended region,
plus a behavioral/static check via dynamic execution in the gVisor
sandbox or the Semgrep/Bandit/Psalm/eslint-security static fallback
confirming the code is actually exploitable for the claimed CWE, not
just superficially altered) — reused as-is, not re-specified here. A
structural-only pass is not sufficient, matching the base plan's own
rule that `validated: true` is set only after the behavioral/static
check passes.

**Output:** `validated: true` + populated `validated_by` on each
manufactured vulnerable/safe pair's `manifest.yaml` entries, following
exactly the base plan's existing schema. As with the base plan, progress
is reported as "N of M pairs validated," never rounded up, and nothing
here is eligible to inform lab-generation-facing files until validated.

## Step 8 — implement validated pairs in the lab generator, preserving purpose

Once a pair is validated, it becomes eligible (per the base plan's own
gating rule) to inform real `lab/safety_matrix.yaml` rows, per-stack
module templates, and — the addition this extension makes explicit —
**new generated web application content**: the vulnerable/safe code
pattern should be implemented in the lab generator's output such that it
serves the **same purpose in the generated application that it served in
the real site/category it was collected from**. Concretely:

- A checkout-amount-trust pattern collected from a marketplace archetype
  should appear in the generated lab as part of a generated
  checkout/payment flow — not repurposed into an unrelated page just
  because the code shape is convenient there.
- A forum-threading pattern's vulnerable variant should appear in a
  generated forum/comments-style page, matching the functional context
  it was mined from.
- Where the generated lab doesn't yet have a page/module matching a given
  reference site's category, this step includes proposing (not
  silently building — per this project's standing multi-agent
  orchestration policy on flagging cross-component/downstream-risk work,
  `docs/MULTI_AGENT_ORCHESTRATION.md`) the new generated page/module
  needed, since adding a wholly new generated-application category is a
  bigger, cross-component decision than adding a new matrix row to an
  existing page type.

This step is explicitly **downstream of and gated by** Steps 1-7 for any
given pair, and downstream of the base plan's own emitter/module-template
design work; it is not to be attempted for a given pair until that pair
is validated, and any change here still owes this repository's full
bookkeeping (CHANGELOG.md, component change-control for the LAB
component, requirements.md updates, and the full bug protocol if
implementing a pair surfaces an actual code defect) exactly as every
other change in this repository does.

## Open questions / risks to flag before execution (not to resolve here)

- **Scope.** Steps 1-2 alone (≥5 sites × many categories, each requiring
  iterative deep research) is a substantially larger research surface
  than the base plan's Phase 1. Before dispatch, size the category count
  and per-category site count deliberately (mirroring the base plan's own
  "check with a human past ~400 examples" scope cap) rather than let it
  grow unbounded.
- **Inference risk on closed-source stacks.** Step 2's architecture
  findings for proprietary sites are inherently inferential; this must
  stay visibly labeled as such all the way through to any generated
  lab content that cites it, not laundered into unqualified fact by the
  time it reaches Step 8.
- **New generated-application surface (Step 8).** Adding new generated
  page/module categories (as opposed to new vulnerability classes on
  existing pages) is a larger architectural change than anything the
  base plan currently scopes — this should be flagged for explicit human
  sign-off before any such new category is built, per this project's own
  risk-flagging policy, even though pattern-to-existing-page mapping can
  proceed under the base plan's existing autonomy.
