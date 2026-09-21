# Pattern corpus sourcing plan — OSV/GHSA-fed provenance cards (T-LAB0.8)

**Draft for review — no data has been pulled, no cards written, no code built.**
This document answers one question only: *how, concretely, will the
`patterns/` provenance corpus in CR-LAB-0001 / `LAB_PHASE_0_PLAN.md` (T-LAB0.8)
actually be obtained?* It does not start work; it's the methodology for you to
approve or amend first.

## 1. What this corpus is and isn't (recap of the constraint)

Each "pattern card" is a short, hand-written, abstract description of a
root-cause shape drawn from a real, disclosed vulnerability — used as
**provenance/justification** attached to a manifest cell via `id_ref`. Cards
are never read by `verdict()` and never influence a label (CR-LAB-0001 §3,
§5.1). They also must never contain verbatim vulnerable source code, patch
diffs, or working exploit code from a third-party codebase — only a
paraphrased, original description of the mechanism, per this project's
lab-only/defensive-research posture and the no-verbatim-code constraint
already stated in the research report.

## 2. Sources, access method, and licensing posture

| Source | What I pull | How I'd access it | Licensing (per the research report; to be re-confirmed against current terms at pull time) |
|---|---|---|---|
| **OSV.dev** | Ecosystem-scoped advisory records (npm, PyPI, Composer, Maven, Go, RubyGems) with CWE IDs, affected version ranges, and a prose summary/details field | OSV's public REST API (`api.osv.dev`) for targeted queries, or its published per-ecosystem bulk JSON archives for a broader pull | Described as open data in the report; I will read and quote OSV's own terms page during the actual pull rather than assume |
| **GitHub Security Advisory (GHSA) database** | The prose root-cause description — the part I'm actually allowed to paraphrase from | GitHub's public GraphQL API (`securityAdvisories`), unauthenticated calls are rate-limited but sufficient for a batch pull of dozens of advisories | Report states CC-BY-4.0; if confirmed, any card derived from GHSA prose will carry an attribution note back to the advisory URL |
| **NVD / CVE Program (cvelistV5)** | Breadth cross-check and CVSS context only — CWE mapping is noisy at our granularity, so this is never the primary source for a card's `root_cause` text | NVD's public JSON API or the `cvelistV5` bulk repo | US-government-origin, effectively free |
| **CISA KEV** | A prioritization filter only — "is this actually exploited," used to decide which candidate classes get more cards, not to source text | CISA's published KEV JSON feed | Public |
| **PortSwigger Research / conference talks (race conditions, business logic, smuggling-adjacent)** | The only decent source for classes that rarely produce CVEs | Manual reading and citation — no API, no bulk pull, no scraping | Cite the URL; paraphrase only, same rule as GHSA |

I will not scrape HackerOne/Bugcrowd program pages programmatically — per the
report, that corpus is manual-read-and-cite only, and I'd only use it where a
class (e.g. business-logic errors) has essentially no CVE-level source, and
even then the card is marked "plausible pattern, illustrative" rather than
"observed," per the report's honesty rule.

**This session already has web-fetch/web-search tooling available**, so the
actual OSV/GHSA pulls in T-LAB0.8 are something I can execute directly against
their public APIs when that task starts — I don't need to hand this off to a
separate research agent the way the earlier open-ended realism report needed
broad synthesis. This is closer to structured data retrieval against two
documented, stable-schema APIs, followed by a manual read of each candidate.

## 3. Pipeline, step by step

1. **Pull.** Query OSV for advisories in the target ecosystems, filtered to
   the CWE IDs that map to our first-wave class list (§5 below). Query GHSA
   similarly, and join records to the same underlying advisory by CVE/GHSA
   alias.
2. **Pre-filter, mechanically.** Drop anything without a CWE mapping in our
   target list, anything older than ~24 months (per the report's currency
   bar) unless it's a uniquely well-documented canonical example, and
   anything where the only available text is a CVSS vector with no prose.
3. **Triage, manually — this step is not automated.** For each surviving
   candidate, I read the advisory prose (and, where cited by the advisory
   itself, a vendor blog post or researcher write-up — never the raw patch
   diff) and decide: (a) does this actually illustrate a distinct root-cause
   *shape* we don't already have a card for, and (b) can I describe that shape
   in my own words without needing to reproduce any of the source's code or
   exploit steps. Candidates that fail either test are dropped, not forced
   into a card.
4. **Author the card.** Write the fixed schema below, with `root_cause` as
   2–4 original sentences describing the mechanism abstractly (the report's
   own Area 1 write-ups, e.g. the Django `_connector`-key SQLi shape or the
   Next.js internal-header-trust shape, are the model for how abstract "abstract"
   needs to be).
5. **Store.** One file per card under `lab/patterns/cards/` (pending the path
   decision already flagged in `LAB_PHASE_0_PLAN.md` — reusing that same
   proposed location), git-tracked, human-reviewable in a normal diff/PR.
6. **Validate.** A small schema check (required fields present, `id` unique,
   `source_url` resolves to a real advisory, `class` is one of our declared
   classes) — this becomes part of T-LAB0.8's own deliverable, run the same
   way the name-leak/secret scanners run as build gates in Phase 0.
7. **Refresh, quarterly.** Re-run the pull, diff against existing cards by
   source ID, and only **add** new cards for genuinely new disclosures —
   existing cards are never silently edited; a correction to an existing
   card is a new dated note appended to it, not a rewrite, consistent with
   this project's append-only change-control convention elsewhere.

## 4. Card schema

```yaml
id: pc-sqli-orm-identifier-0001        # stable, our own namespace
class: sqli                            # our manifest class vocabulary
sink_family: sql_identifier            # per CR-LAB-0001's structured sink contexts
stack: python-fastapi                  # illustrative stack the disclosure occurred in;
                                        # not a constraint on which stack we build the cell in
root_cause: >
  Two to four sentences, written from scratch, describing the mechanism:
  what kind of input reached what kind of sink, and why the existing
  protection (if any) did not apply to that specific context.
source_url: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
published_date: 2025-11-05
confidence: observed                   # observed | plausible (per §2's HackerOne caveat)
notes: >
  Optional: anything about scope, e.g. "this is a sandbox-escape variant,
  not a plain unescaped-template case — keep as a distinct sink_family
  from pc-ssti-template-source-*."
```

`confidence: plausible` is reserved for the handful of classes (business-logic
errors, some mass-assignment cases) where no CVE-grade source exists and the
card is honestly a constructed-but-realistic pattern rather than a cited
disclosure — per the report's explicit instruction not to stretch a citation.

## 5. First-wave scope (target ~25–30 cards)

Prioritized by where the report found rich, current, code-level write-ups,
intersected with the CWE Top 25 (2025) / OWASP Top 10 (2025) classes this
program is actually targeting (CR-LAB-0001 §9 already rules out chasing all
64 `references/` categories):

- **SQL injection at the ORM layer** (identifier/alias/connector context) — 3–4 cards
- **Insecure deserialization** (framework-protocol and signing-key-in-docs shapes) — 3–4 cards
- **Prototype pollution** (recursive-merge shape) — 2–3 cards
- **Broken access control / authorization bypass** (internal-header-trust shape) — 2–3 cards
- **SSTI** (developer-supplied template source vs. sandbox escape — kept as two
  distinct `sink_family` values per the report's labeling note) — 2–3 cards
- **IDOR / BOLA** — 2–3 cards (drawing on the OWASP API Security Testing
  Framework's cross-user methodology, cited, not a specific CVE)
- **Mass assignment** — 2 cards, `confidence: plausible` where no CVE exists,
  citing the named Laravel/Rails mechanisms whose *absence* is the vulnerability
- **XSS — escaping-context mismatch** — 2–3 cards, one per target stack's
  templating engine, since this pattern is stack-specific in its concrete form
  even though it's universal in shape
- **Race conditions — limit overrun** — 1–2 cards, citing PortSwigger research
  rather than a CVE (this class is thin on disclosures, per the report)

This intentionally leaves several `references/` categories (XXE, GraphQL
"injection," CSRF) out of the first wave, matching CR-LAB-0001 §9's "don't
build cells for all 64 categories" decision — the corpus only needs to be
ahead of, not broader than, what Phase 1/3 will actually consume.

## 6. What I need from you before I start pulling data

1. **Timing** — do you want T-LAB0.8 run now, in parallel with the rest of
   Phase 0's design-decision review, or held until the other four open Phase
   0 decisions in `LAB_PHASE_0_PLAN.md` are confirmed? It has no code
   dependency on them, but I'd rather not start pulling real advisory data
   into the repo before you've seen this plan approved.
2. **First-wave class list** — confirm §5's nine classes and rough card
   counts, or tell me to add/drop/reweight any.
3. **Storage path** — confirm `lab/patterns/cards/` (matches the path already
   proposed in `LAB_PHASE_0_PLAN.md` decision 2), or specify a different one.
4. **Review checkpoint** — I'd plan to show you the drafted cards (not just
   describe them) before any manifest cell references one by `id_ref`, so you
   can spot-check the paraphrasing and licensing judgment calls rather than
   discover them later embedded in generator output. Confirm that checkpoint
   works, or tell me how you'd rather review them.
