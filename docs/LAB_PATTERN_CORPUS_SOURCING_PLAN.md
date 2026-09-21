# Pattern corpus sourcing plan — real-disclosure-fed provenance cards (T-LAB0.8)

**Revision 2 (2026-09-21) — draft for review, no data pulled, no cards
written, no code built.** Revision 1 asked a web-enabled agent to verify and
quantify the approach; its report (*"Validating and Quantifying the
Pattern-Corpus Sourcing Plan," 2026-09-21*) found five factual problems and
one wrong framing assumption in Revision 1. This revision adopts its
corrections. See §0 for exactly what changed and why — read that before
diffing against what you approved earlier, since the pull mechanism, the
review workload, and the refresh cadence are all materially different now.

## 0. What changed from Revision 1, and why

| # | Revision 1 said | The research found | This revision does |
|---|---|---|---|
| 1 | Query the OSV API, filtered by CWE | The OSV API (`/v1/query`, `/v1/querybatch`, `/v1/vulns/{id}`) takes a package/version/commit/PURL/ID — **there is no CWE filter and no ecosystem-wide listing.** It answers "what affects this package," not "what advisories match this weakness." | Pull is a `git clone` of `github/advisory-database`, not an API call (§2) |
| 2 | Query OSV and GHSA independently, join by alias | **GHSA is an upstream source *of* OSV**, not an independent second source — OSV aggregates GitHub's own advisory database. Joining them mostly rejoins a record to itself | GHSA (via its git mirror) is the **primary and effectively only** source; OSV bulk data is kept as an ecosystem-breadth fallback, not a second opinion (§2) |
| 3 | Unauthenticated GHSA GraphQL is "rate-limited but sufficient" | Measured: unauthenticated GraphQL limit is **0**; REST core is 60/hour. A systematic pull over an API is not viable without a token | Moot — the git-repo pull needs no auth at all |
| 4 | Sequential triage: read each candidate in order until enough survive | Measured selection ratio is **~1.5%** (≈1,900 usable candidates against a ~30-card target). That is not a filtering problem, it's a *sampling from abundance* problem — the scarce resource is distinct root-cause **shapes**, not advisories | Pipeline becomes **cluster-then-sample**: cluster candidates by shape within each class, triage cluster representatives, not raw advisories (§3) |
| 5 | Refresh quarterly, one card-authoring pass each quarter | Because shape-space saturates fast per class, a calendar-driven authoring pass will **usually produce zero new cards** and risks padding the corpus with near-duplicates just to fill a slot | Pull quarterly (cheap, automated); **author only when triggered** (a class falls under its target count, a new class is added, a generator cell needs a citation) (§3, step 7) |
| — | (framing gap, not a factual error) | The manifest's `id_ref: pattern://...` field, as sketched in the original report and carried into `CR-LAB-0001` §6, points *from* the functional manifest *to* the provenance corpus — the wrong direction per provenance-separation prior art (in-toto/SLSA: the artifact should be unchanged by whether provenance exists) | Provenance moves to a **separate `provenance.yaml`** keyed by `cell_id`, never referenced from inside a cell the verdict engine reads (§4). **This is an architecture correction to CR-LAB-0001 §6's manifest sketch — flagged as Addendum A there, not silently changed.** |

Licensing (CC-BY-4.0 for GHSA, confirmed by reading the actual `LICENSE.md`
in the source repo) and the overall no-verbatim-code posture were both
**confirmed correct** and are unchanged from Revision 1.

## 1. What this corpus is and isn't (unchanged)

Each "pattern card" is a short, hand-written, abstract description of a
root-cause shape drawn from a real, disclosed vulnerability — attached to a
generated cell as **provenance/justification only**. Cards are never read by
`verdict()` and never influence a label. They never contain verbatim
vulnerable source code, patch diffs, or working exploit code from a
third-party codebase — only a paraphrased, original description of the
mechanism.

## 2. Sources and access method

| Source | Role | Access | Why |
|---|---|---|---|
| **`github/advisory-database` (git repo)** | **Primary — this is the corpus.** 35,729 human-reviewed advisories in OSV format, prose-rich (median 1,230 chars, 41% with structured headings) | `git clone https://github.com/github/advisory-database` (~4 min, 3.3 GB, no auth, no rate limit); refresh via `git pull` | No API can do the pull Revision 1 wanted; the repo can, unauthenticated, with the whole history for free |
| **OSV.dev bulk (`all.zip` per ecosystem + `modified_id.csv`)** | Fallback breadth, for ecosystems GitHub reviews less densely | `https://storage.googleapis.com/osv-vulnerabilities/<ecosystem>/all.zip` | Reconcile against the ecosystem's directory index — the zips have a documented history of occasionally under-counting |
| **NVD / CVE (`cvelistV5`)** | CVSS context and a genuine second opinion (unlike GHSA, this is not an OSV upstream) | Public bulk JSON | CNA prose is inconsistent quality; used for cross-checking, not as a `root_cause` source |
| **CISA KEV** | Prioritization boolean ("is this actually exploited") | Public JSON feed | Unchanged from Revision 1 |
| **EPSS (FIRST)** | Prioritization score, continuous rather than KEV's binary list | Free daily CSV, no key | **New in this revision** — used only as a tiebreaker in ranking candidates within a class, never to decide inclusion (exploitation likelihood ≠ pedagogical value) |
| **PortSwigger Research / conference talks** | The only decent source for classes that rarely produce CVEs (race conditions, business logic) | Manual reading and citation only | Unchanged |

**Explicitly dropped from Revision 1:** the OSV REST API and the GHSA
GraphQL API as pull mechanisms (neither can do what was asked of it, per §0);
unreviewed OSV/GHSA advisories (measured: 90% of the database, ~0% usable —
median 321 characters, no structured prose, essentially none in our target
ecosystems); scraping HackerOne/Bugcrowd (still manual-cite-only, unchanged).

## 3. Pipeline, step by step (revised: cluster-then-sample)

1. **Pull.** `git clone`/`git pull` the advisory database. Record the
   checked-out commit SHA in a refresh log — this is what makes the whole
   pipeline exactly reproducible later.
2. **Index.** Parse every `github-reviewed` OSV JSON file into one local
   table (id, published/modified/reviewed dates, CWEs, ecosystems, severity,
   summary, details, whether it carries a fix-commit reference).
3. **Scope.** Filter to: the ~24-month currency window, our target
   ecosystems (npm, PyPI, Packagist, Maven — Go/RubyGems as needed later),
   and the CWE-to-class crosswalk (§5), including keyword-recovery rules
   where CWE mapping alone under-counts a class.
4. **Rank.** Score surviving candidates by prose quality (length, structured
   headings) and, as a tiebreaker only, EPSS/KEV signal.
5. **Cluster.** Within each class, cluster candidates by root-cause shape
   (embedding + clustering over the advisory prose only — never over linked
   code). Keep one representative plus two alternates per cluster. This is
   the step that replaces "read hundreds of candidates in sequence" with
   "look at 10–20 per class."
6. **Triage — human, on cluster representatives only.** For each
   representative, I read the advisory prose (never a linked patch diff —
   commit-link references are stripped before I read a candidate, so this is
   a tooling property, not just a discipline) and decide: is this a distinct
   shape, and can I describe it without reproducing the source's code or
   exploit steps. An optional, tightly-constrained LLM pre-screen may propose
   a cluster label and rationale as a `triage_hint` field, but **it may never
   exclude a candidate and never authors `root_cause`** — every cluster
   representative still reaches me, and the schema has no field a model can
   populate as the final card text (this constraint exists because a
   literature review of LLM-assisted screening found sensitivity ranging
   from 0.43 to 1.00 across models on the same task — far too unreliable to
   gate on).
7. **Author, store, validate.** Write the card (schema in §4), store it under
   `lab/patterns/cards/`, and validate it against a JSON Schema build gate
   (§4). Card authoring is **trigger-driven, not calendar-driven**: it
   happens when a class falls under its target count, a new class is added
   to the taxonomy, or a generator cell needs a citation that doesn't exist
   yet — not automatically every quarter.
8. **Refresh, quarterly, automated, cheap.** `git pull`, diff the newly
   added advisory files (which is exactly the set of new disclosures — no
   join, no dedup needed against a single source), re-run scoping/ranking/
   clustering, and emit a short dated report of what's new. Most quarters
   this report will say "no new distinct shapes" — that's a successful run,
   not a gap. Existing cards are never edited in place; a correction is a
   dated note appended to the card, or a `superseded_by` pointer to a new
   card — the original is never deleted or rewritten.

## 4. Card schema and storage (revised: separate provenance file)

```yaml
# lab/patterns/cards/pc-sqli-orm-identifier-0001.yaml
schema_version: 1                      # bump only on breaking changes
id: pc-sqli-orm-identifier-0001        # stable; never renumbered even if
                                        # reclassified later — class: carries
                                        # current truth instead
class: sqli_orm                        # must exist in lab/patterns/taxonomy/classes-v1.yaml
sink_family: sql_identifier
stack: python-fastapi                  # illustrative stack the disclosure occurred in;
                                        # not a constraint on which stack we build the cell in
root_cause: >
  Two to four sentences, written from scratch, describing the mechanism:
  what kind of input reached what kind of sink, and why the existing
  protection (if any) did not apply to that specific context.
source_url: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
published_date: 2025-11-05
confidence: observed                   # observed | plausible
triage_hint:                           # optional; only ever a label + rationale,
  label: sql_identifier_via_kwargs     # never the root_cause text itself
  model: <name>
  date: 2026-09-21
notes: >
  Optional scope note, and any losing CWE/class matches from the
  disambiguation rule in §5 (e.g. "also matched authz_bypass; sqli_orm
  takes precedence as the more specific class").
```

**Provenance is a separate, one-directional index — not a field inside a
manifest cell:**

```
lab/patterns/
  cards/pc-*.yaml               # the corpus
  provenance.yaml               # cell_id -> [card_id, ...]   ← the ONLY link
  taxonomy/classes-v1.yaml       # class vocabulary + CWE crosswalk, versioned
                                  # separately from the card schema
  refresh/YYYY-QN.md             # quarterly pull reports
  REFRESH_LOG.md                 # SHA range per refresh, append-only
```

The manifest the verdict engine reads carries no `id_ref` and no card ID
anywhere. `provenance.yaml` is generator-docs output only — emitted alongside
`labels.json` etc., never consumed by `verdict()`. This is the correction
flagged in §0 row 6 and in `CR-LAB-0001` Addendum A: the artifact (the
generated cell) must be unchanged by whether a provenance entry exists for
it, the same invariant SLSA/in-toto provenance formats enforce for build
artifacts.

**Validation gates, in order:** schema conformance → `id` uniqueness →
`class` exists in the versioned taxonomy → `source_url` shape valid offline
(reachability checked in a separate, non-blocking weekly job — the build
must never fail because a third party had a bad minute) →
`confidence: plausible` requires a `rationale` → every `cell_id` in
`provenance.yaml` resolves to a real manifest cell and vice versa → **a
negative check that no card ID and no `pattern://`-style reference appears
anywhere in the manifest or in the verdict module's source**, the same shape
as the existing name-leak scanner.

## 5. CWE-to-class crosswalk and first-wave scope (revised: 10 classes, ~31 cards)

Two corrections from the research, both adopted:

- **SSTI's crosswalk under-counted by ~27%** using only CWE-1336/917; adding
  CWE-94 filtered to template-engine keywords recovers the missing ~27%.
- **SSRF (CWE-918) is added as a tenth first-wave class.** It ranked as the
  4th most common relevant CWE in our target ecosystems in the measured
  data, and CR-LAB-0001 §4/§8 already plans a webhook/SSRF generator cell in
  Phase 4 that will need a citation.

Multi-CWE advisories (measured: ~24% of the corpus) are resolved by a fixed
**precedence order**, most-specific class first (e.g. `idor_bola` before the
catch-all `authz_bypass`); a losing match is recorded in the card's `notes`,
never silently dropped.

| Class | First-wave cards | Basis |
|---|---|---|
| `sqli_orm` | 4 | Identifier/alias/connector context, per CR-LAB-0001's realism lever |
| `deserialization` | 4 | Framework-protocol and signing-key-in-docs shapes |
| `proto_pollution` | 3 | Recursive-merge shape; effectively npm-only in practice, consistent with the existing structural-exclusion decision for non-JS stacks |
| `authz_bypass` | 4 | Internal-header-trust shape; broadest class, lowest confidence in shape count — largest allocation for that reason |
| `ssti` | 3 | Kept as two distinct `sink_family` values (template-source vs. sandbox-escape) per the original report's labeling note |
| `idor_bola` | 3 | Drawing on the OWASP API Security Testing Framework's cross-user methodology |
| `mass_assignment` | 2 | Saturates almost immediately — only ~2 distinct mechanisms exist (no allowlist at all; allowlist bypassed via nested/aliased fields) |
| `xss_context` | 3 | One per target stack's templating engine — escaping-context-mismatch shape |
| `race_condition` | 2 | Thin on CVEs; cards lean on PortSwigger citations, `confidence: observed` still applies since the research is public and cited |
| `ssrf` *(new)* | 3 | Added per above; feeds the Phase 4 webhook cell directly |

Total: **~31 cards**, matching the original ~25–30 target closely. This
intentionally leaves other `references/` categories (XXE, GraphQL
"injection," CSRF, path traversal) out of the first wave — path traversal
(CWE-22) was also flagged as a large, currently-unclassified class and is a
reasonable second-wave candidate, but is not proposed for the first wave
here.

## 6. What I need from you before I start pulling data

1. **Timing.** The research's own recommendation, which I'd endorse: run the
   pull now, in parallel with the rest of Phase 0's design-decision review —
   it has no code dependency on those decisions, the pull itself is a single
   `git clone`, and the corpus will actually inform the class-vocabulary and
   `sink_family` decisions those other items depend on. The one thing I'd
   hold until you've approved this revision is authoring any card marked
   `confidence: plausible`, since those encode judgment calls you should see
   before they're written, not after.
2. **First-wave scope.** Confirm §5's ten classes and the ~31-card target
   (up from nine/~25-30), or adjust.
3. **Storage path and provenance architecture.** Confirm
   `lab/patterns/cards/` plus the separate `provenance.yaml`/`taxonomy/`
   layout in §4 — this is a real change from Revision 1's `id_ref`-in-manifest
   sketch and needs your sign-off since it also amends `CR-LAB-0001` §6
   (flagged there as Addendum A, not silently applied).
4. **Review checkpoint.** As before: I'll show you drafted cards before any
   `provenance.yaml` entry references one, so you can spot-check paraphrasing
   and licensing judgment calls. New addition per the research: I'll also
   show you the cluster representatives I **rejected**, not just the ones I
   carded — the rejections carry more information about scoping judgment
   than the acceptances do.
