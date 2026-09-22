# Vulnerability corpus expansion — site-architecture extension plan

Rewritten from scratch 2026-09-22 following `docs/bugs/BUG-0029-*.md`: the
prior version of this plan stated Step 6 ("the more CWEs the better") as
unenforced prose, and that step was under-delivered twice in a row as a
result. This version fixes that by making every step's success criterion
concrete and, where the criterion is checkable, mechanically enforced —
not by writing the same intent in stronger words.

## Relationship to the base plan

`docs/VULN_CORPUS_EXPANSION_PLAN.md` (the "base plan") sources its corpus
top-down from **functionality**: enumerate common web-app features, rank
them, collect real GitHub examples per feature/language. This plan is a
second, complementary angle: top-down from **real deployed sites**. Instead
of starting from an abstract feature list, start from the most popular
sites in each major category, find out what architecture/tech stack each
one actually runs, and collect code that reproduces those specific
architecture + function combinations. Both angles feed the same output —
`docs/research/corpus-examples/<feature>/<language>/manifest.yaml`, gated by
the base plan's own `validated: true` rule — so this plan reuses the base
plan's manifest schema, licensing rules, secrets-scrubbing rules, and
validation tiers unchanged. It does not redefine them.

## The 8 steps

1. **Identify site categories and leading sites.** Pick the current most
   popular website categories/genres; for each, list at least 5 leading
   sites with a one-line reason each (traffic rank, market share, or
   architectural notability), cited.
2. **Research each site's real architecture.** Front-end framework,
   back-end language/framework, database, hosting/CDN, auth mechanism, API
   style, notable integrations — cited, iterated until confident, never
   guessed from memory.
3. **Search for representative real source code.** For each distinct
   (architecture, tech stack, function) combination found in step 2, find
   real, published, appropriately-licensed source code that demonstrates
   it.
4. **Validate the source is genuine.** Confirm it actually compiles/parses
   and matches the claimed combination before it enters the reference
   library — a distinct check from step 7's vulnerability validation.
5. **Organize the reference library.** Name and structure entries so tech
   stack, architecture, and function are distinguishable from the file
   listing alone.
6. **Research CWEs — to an enforced floor, not a vibe.** For each entry,
   research (against the MITRE CWE index, not recall) every CWE genuinely
   applicable to its architecture/function/tech-stack combination. See
   "Step 6 in detail" below — this is the step BUG-0029 was about, so it
   gets its own section instead of a one-line restatement.
7. **Build and validate a vulnerable counterpart.** Using step 6's CWEs,
   construct (or find) the vulnerable side of the pair; validate it is
   actually vulnerable before it's usable by the lab generator.
8. **Hand off to the lab generator.** Each validated pair becomes a
   proposal (`suggested_op`/`suggested_sink_family`) for a new
   `lab/safety_matrix.yaml` row or module template — a proposal, not an
   applied change; see "Step 8 handoff" below for why it stops there.

## Step 6 in detail (the fix for BUG-0029)

**Procedure, per entry:**

1. Identify the entry's actual weakness mechanism from its `pattern:` field
   (what specifically goes wrong, not just "XSS" or "IDOR" as a label).
2. Look up that mechanism's primary CWE in the MITRE CWE index
   (<https://cwe.mitre.org/data/index.html>).
3. Walk that CWE's own listed relationships — parent (`ChildOf`), children
   (`ParentOf`), and related weaknesses — and record every one that is
   **genuinely, specifically applicable** to this entry's actual code, not
   every relationship the index happens to list. A parent class applies
   only if the entry's mechanism truly instantiates it; a sibling/child
   applies only if the entry's code matches that child's more specific
   description.
4. Check whether the entry's code introduces a **second, independent**
   mechanism beyond the one that motivated collecting it (e.g. an unrelated
   path-traversal issue alongside the mimetype-check gap the entry was
   built to show). If so, that's a genuinely separate CWE, not padding.
5. Record the result as `cwe: [...]` plus a `cwe_count_rationale:` field:
   one line per CWE naming *why* it applies (the specific relationship or
   mechanism), not just the ID. A paired idiomatic/vulnerable entry that
   shares one mechanism can point its rationale at the other entry's
   write-up instead of repeating it.

**Floor: every entry needs at least 2 CWEs and a rationale, or an explicit,
honest statement of why fewer genuinely apply.** "Fewer CWEs, honestly
justified" is an acceptable outcome; "fewer CWEs, unexamined" is the bug
this plan exists to stop recurring.

**Enforcement.** `.claude/hooks/check-corpus-cwe-coverage.sh` runs as a
`Stop` hook and mechanically blocks the session from ending if any
`docs/research/corpus-examples/*/*/manifest.yaml` entry touched by the
turn has fewer than 2 CWEs and no `cwe_count_rationale:`. This is the
enforcement path PA-0032 requires for this instruction — the instruction is
not re-stated here as prose alone a third time.

## Step 8 handoff (unchanged from before, restated briefly)

A validated pair is eligible to inform `lab/safety_matrix.yaml` or a new
module template once `validated: true`. Actually editing
`lab/safety_matrix.yaml` is a change to component **FUZZ**/**LAB** and
needs its own `docs/components/<n>-*/change-control.md` entry per
`CLAUDE.md`'s Definition of Done — it is not bundled into a corpus-
collection pass, matching every prior corpus-collection commit in this
project's history. `suggested_op`/`suggested_sink_family` fields on each
entry are the proposal a later change accepts, renames, or merges.

## Scoping decisions (frozen, not re-litigated per wave)

- **Directory/naming:** reuse the base plan's
  `docs/research/corpus-examples/<feature>/<language>/manifest.yaml` +
  `<role>-<n>.<ext>` layout. Architecture is a manifest field
  (`architecture: <tag>`), not a new directory level (keeps small cells from
  fragmenting further), plus an architecture slug in the filename
  (`<role>-<architecture-slug>-<n>.<ext>`) so it's visible without opening
  metadata.
- **Categories (frozen):** 6 categories, 5 sites each — e-commerce/
  marketplaces, social/UGC, SaaS/productivity/collaboration, media/
  streaming/content, travel/booking/marketplaces, fintech/payments. Chosen
  for overlap with the base plan's highest-priority existing feature rows.
- **Step 2 confidence bar:** a claim is confirmed once **two independent
  sources** agree, or **one primary source** (the company's own engineering
  blog/docs/source) states it directly. A claim clearing neither is recorded
  as **unconfirmed**, not stated as fact, and is not used to justify step 3.
- **Tooling available in this execution environment** (checked, not
  assumed): no gVisor/container sandbox → step 7's dynamic-execution
  validation tier is unavailable here; every pair collected in this
  environment is validated at the static/manual-review tier and recorded as
  `validated_by: [manual-review]`, not silently upgraded. No difftastic →
  structural checks are a manual side-by-side read. Semgrep installs via pip
  but panics at import in this container (native `cryptography`/`cffi`
  binding failure — logged in `ERROR_LOG.md` 2026-09-22) → unusable here.
  Bandit and detect-secrets are installed and functional.
- **Scope per wave:** this plan does not mandate finishing all 6 categories
  x 5 sites x N architectures in one pass — but "not this pass" must be an
  explicit, stated deferral the user can see and override (as happened once
  already: wave 1 deferred categories 3-6, the user said not to, wave 2
  covered them). Default to covering everything asked for; defer only with
  a visible note, never silently.

## Status

- [x] Plan rewritten from scratch (this document), per `docs/bugs/BUG-0029-*.md`.
- [x] Step 1: all 6 categories x 5 sites identified, sourced —
      `docs/research/site-architecture-survey.md`.
- [x] Step 2: architecture write-ups complete for all 6 categories (20
      sites in wave 2, plus the first 10 in wave 1) — same file.
- [x] Steps 3-7: one real architecture/function combination carried through
      per category (6 total pairs) — see `docs/research/corpus-examples/
      {ecommerce-logic,ugc-xss,access-control,file-handling,auth-session}/
      {php,node,python}/manifest.yaml` for the `architecture:`-tagged
      entries added in waves 1-2.
- [x] Step 6 remediated to this plan's new floor for all 17 entries the
      BUG-0029 sweep touched (the 6 pairs added in waves 1-2 plus 5
      pre-existing entries sharing their manifest files) — `cwe_count_rationale:`
      present on each, `.claude/hooks/check-corpus-cwe-coverage.sh` passes
      clean on the current tree.
- [x] Step 8: `suggested_op`/`suggested_sink_family` proposals recorded for
      all 6 pairs. Not yet applied to `lab/safety_matrix.yaml` — deliberately
      out of scope for a corpus-collection pass (see "Step 8 handoff").
- [ ] Remaining architecture/function combinations within each of the 6
      categories (each category's 5 sites can surface more than one
      combination; only one per category has been carried through so far).
- [ ] Dynamic-tier validation for all 6 pairs (`validated_by: [dynamic]`) —
      deferred to an environment with a sandboxed execution runtime; every
      pair is `validated: true` at the static/manual-review tier in the
      interim.
- [ ] `lab/safety_matrix.yaml` integration — its own follow-up component
      change, not this plan.
