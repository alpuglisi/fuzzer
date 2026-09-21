You are a senior application-security data engineer and threat-intelligence
researcher. I need a rigorous, cited research report that validates, extends,
and quantifies a draft sourcing plan I'm attaching. Use web search extensively.
Prefer authoritative, recent sources (the last 12–24 months for anything you
call "current"), cite every non-obvious claim with a URL and its publication
date, and clearly separate established practice from experimental ideas. Where
you can pull actual numbers (API result counts, published statistics), do so
and label them as measured; where you must extrapolate, say so and give your
method and confidence.

## Context (read before researching)

**Attached: `LAB_PATTERN_CORPUS_SOURCING_PLAN.md`** — a draft plan for building
a small, versioned, hand-curated corpus of "pattern cards": short, original-text
descriptions of real, disclosed vulnerability root-cause shapes (never verbatim
code or patch diffs), each with provenance (source URL, date). This feeds a
manifest-driven generator for a deliberately vulnerable local security-testing
lab (same spirit as DVWA/Juice Shop/WebGoat — authorized, educational, on
infrastructure I own, loopback-only). The cards are **documentation and
justification only** — a generator manifest references a card by ID for
traceability, but the card content is never read by the verdict logic that
decides whether a generated lab endpoint is vulnerable or secure. Read the
attached plan fully before researching; don't restate it, build on it.

The plan's current draft, in brief: primary sources are **OSV.dev** (ecosystem-
scoped advisories, CWE-mapped, JSON API + bulk exports) and the **GitHub
Security Advisory (GHSA) database** (prose root-cause descriptions, GraphQL
API, believed CC-BY-4.0); NVD/CVE and CISA KEV as cross-checks; PortSwigger
Research and conference talks as manual-only sources for classes that rarely
produce CVEs (race conditions, business logic). The pipeline is: pull → filter
by CWE → manual human triage of each candidate's prose → author a short
original-language card → store one file per card → validate against a schema
→ refresh quarterly, append-only (existing cards are never rewritten, only
superseded with a dated note). The first-wave target is ~25–30 cards across
nine vulnerability classes: SQL injection at the ORM layer (identifier/alias/
connector context specifically, not raw string concatenation), insecure
deserialization, prototype pollution, broken access control / authorization
bypass (internal-header-trust pattern), server-side template injection,
IDOR/BOLA, mass assignment, XSS via escaping-context mismatch, and race
conditions (check-then-act limit overruns). Target ecosystems/stacks: Node.js/
TypeScript, Python, PHP (Laravel), with Java/Spring Boot as a possible fourth.

## Research areas

### 1. Data source verification and expansion

Verify the plan's factual claims about OSV.dev and GHSA (current API
endpoints, auth/rate-limit requirements, bulk-export formats, and — carefully —
their actual current licensing/terms-of-use for redistributing derived
summaries with attribution; don't assume the plan's characterization is still
accurate, confirm it). Then identify additional sources worth adding for
**automatable, well-documented, current** real-world vulnerability data across
our target classes and ecosystems: per-ecosystem advisory databases (npm
audit / GitHub's own npm advisories, PyPI Advisory Database, Packagist/
Composer security advisories, RustSec if relevant later, GitLab Advisory
Database), vendor/PSIRT feeds, EPSS (for prioritizing which disclosures matter
most), and anything else you find that's actually good for *root-cause prose*
rather than just CVE identifiers. Rate each source on: API/bulk availability,
licensing clarity for our paraphrase-only use case, and typical prose quality
(does it explain the mechanism, or just say "SQL injection was possible").

### 2. Capture methods and tooling

Research concrete, minimal tooling to pull from OSV.dev and GHSA reliably:
official or community client libraries, pagination and rate-limit handling for
GHSA's GraphQL API, bulk-vs-incremental pull strategies for OSV, and how to
join records from both sources by CVE/GHSA alias without duplicating cards.
Cover how to make quarterly re-pulls idempotent (detect "already have a card
for this advisory" vs. "new disclosure since last pull"). Separately, research
whether and how **LLM-assisted triage** is used responsibly in similar
pipelines — e.g., using a model to summarize/pre-screen candidate advisories
for a human to approve or reject, without letting it auto-author the final
card text unsupervised (our plan requires a human to read and paraphrase each
included advisory) — cite any published methodology for this kind of
human-in-the-loop literature triage, and flag if you find none.

### 3. Standardizing heterogeneous advisory data

OSV, GHSA, and NVD each use different schemas and CWE-mapping conventions for
the same underlying disclosure. Research how existing tools normalize
multi-source vulnerability data into one canonical record (e.g. Dependency-
Track, GUAC, OSV-Scanner, Grype, or any published data-model comparison) and
extract patterns applicable to us: a crosswalk approach for mapping CWE IDs to
our nine-class taxonomy (including advisories with multiple CWEs, or CWEs that
don't cleanly fit one class), a deduplication strategy when the same
disclosure appears in more than one source, and how to version the resulting
schema so a future addition (a tenth class, a new field) doesn't require
rewriting existing cards.

### 4. Integrating the corpus into the generator, without it becoming a verdict input

Research patterns for keeping provenance/traceability data structurally
separate from the functional artifact it documents, so a card can never
accidentally leak into the verdict logic — the closest prior art is probably
supply-chain provenance systems (in-toto, SLSA, SBOM formats) that deliberately
separate "how was this built and why" from "what does this do." Recommend a
concrete file format for the cards (plain YAML/JSON files vs. a small database)
and a validation approach (JSON Schema or equivalent) that's both easy for a
human to hand-edit and easy to gate a build on. Also research how to structure
the quarterly diff/refresh step as an auditable, append-only operation
consistent with keeping a permanent record of what was added when (this
project already keeps append-only logs elsewhere, if that framing helps you
find relevant prior art).

### 5. Quantifying expected yield

This is the part I most need real numbers for, not just qualitative advice.
For each of the nine first-wave classes, and for our target ecosystems
(npm/PyPI/Packagist, optionally Maven), try to actually **measure** (via the
OSV/GHSA APIs' own search/count capabilities, or published statistics from
these databases) roughly how many advisories exist that plausibly match the
class, filtered to the last ~24 months. Then estimate realistic post-triage
yield: what fraction typically survives the "does this actually have
usable root-cause prose, and is it a genuinely distinct shape" filter, based
on whatever evidence you can find (even rough analogues from the benchmark/
dataset literature on triage attrition rates count, cited as evidence, not
guesses). Give me: (a) a per-class table of raw candidate counts (measured,
with the query/date range used, so I can reproduce it) and (b) an estimated
realistic card yield for the first wave and for each subsequent quarterly
refresh, clearly flagging which numbers are measured vs. extrapolated and your
confidence in each.

## Output format

Produce a structured report: a short executive summary, then one clearly
headed section per research area above. In each, give the recommended
approach and alternatives with tradeoffs, concrete tools/APIs/citations,
pitfalls, and a maturity rating (established / experimental / not worth it at
this scale). Close with: (a) a concrete recommended pull → triage → store →
validate → refresh tooling stack; (b) a draft CWE-to-our-class crosswalk table
for the nine first-wave classes; (c) the quantitative yield table from area 5,
with method notes and confidence levels; and (d) open questions or gaps you
couldn't resolve. Cite sources inline with URLs and dates, add a final
reference list, and flag anything that is hype or not worth the effort for a
solo, local security-research lab.
