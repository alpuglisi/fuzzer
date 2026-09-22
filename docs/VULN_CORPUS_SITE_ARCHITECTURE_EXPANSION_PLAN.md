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

## Step 6 in detail (revised twice: BUG-0029, then tightened per direct
## follow-up instruction — shared CWEs don't count toward the floor)

**Schema: `cwe_shared:` / `cwe_unique:` / `cwe_rationale:`, not a flat
`cwe:` list.** A CWE genuinely relevant to more than one entry in this
corpus is real and worth recording — but it belongs in `cwe_shared:` and
does **not** count toward any entry's floor. Only CWEs that are unique to
one specific entry (not claimed by any other entry this corpus's
mechanical check covers) count toward the floor below.

**Procedure, per entry:**

1. Identify the entry's actual weakness mechanism from its `pattern:` field
   (what specifically goes wrong, not just "XSS" or "IDOR" as a label).
2. Look up that mechanism's primary CWE in the MITRE CWE index
   (<https://cwe.mitre.org/data/index.html>) and put the class-defining
   CWE(s) — the ones that would also apply to this entry's paired
   counterpart or to other entries with the same mechanism — in
   `cwe_shared:`.
3. Read the entry's **own actual code** (not the mechanism in the
   abstract) for details specific to *this* entry: a distinctive line, a
   parameter, a real bug the excerpt happens to contain, a consequence
   specific to what the code does (what kind of data, what kind of
   endpoint). Walk the MITRE index's relationships (parent/child/related)
   from those specifics, not from the shared class alone — a narrow,
   well-grounded child ID beats a broad parent every time two entries would
   otherwise end up wanting the same ID.
4. Check whether the entry's code introduces a second, independent
   mechanism beyond the one that motivated collecting it. If so, that's a
   genuinely separate CWE.
5. Record `cwe_shared: [...]`, `cwe_unique: [...]`, and `cwe_rationale:`
   (prose naming *why* each unique CWE applies, grounded in the entry's own
   code — not just the ID). A CWE that turns out to already be claimed
   unique by another entry moves to `cwe_shared` on both, and a fresh,
   narrower replacement is found — this is expected, not a failure; the
   mechanical check below is what catches it.

**Floor: every entry needs at least 2 `cwe_unique` entries, not shared with
any other entry this corpus's check covers.** No honesty-escape-hatch this
time — this floor is not negotiable per direct instruction; if step 3
doesn't turn up two genuinely distinct, well-grounded IDs on the first
pass, read the code again rather than padding with a generic parent CWE
(which almost always turns out to be shared with something else anyway).

**Enforcement.** `.claude/hooks/check-corpus-cwe-coverage.sh` runs as a
`Stop` hook and mechanically blocks the session from ending if any touched
`docs/research/corpus-examples/*/*/manifest.yaml` entry has fewer than 2
`cwe_unique` entries, or if any `cwe_unique` ID is also claimed unique by
another touched entry (a real cross-entry collision the first version of
this hook could not detect at all, since it only counted a flat list's
length). This is the enforcement path PA-0032 requires — verified against
the actual corpus, not just asserted: it caught 2 legacy entries still on
the old flat `cwe:` field and one real cross-entry ID collision
(CWE-367 claimed by two different entries) the first time it ran against
this pass's work.

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
      sites in wave 2, plus the first 10 in wave 1), then deepened further
      per direct instruction for the 4 weakest write-ups (Google Workspace,
      Cash App, Venmo, Trip.com) with additional independent sources — same
      file.
- [x] Steps 3-7: one real architecture/function combination carried through
      per category (6 total pairs) — see `docs/research/corpus-examples/
      {ecommerce-logic,ugc-xss,access-control,file-handling,auth-session}/
      {php,node,python}/manifest.yaml` for the `architecture:`-tagged
      entries added in waves 1-2.
- [x] Step 6 fully redone (not just remediated) to the tightened
      `cwe_shared`/`cwe_unique` standard for all 29 entries across the 5
      touched manifest files (the 12 entries added in waves 1-2, plus 17
      pre-existing entries sharing those manifest files) — every entry
      carries >= 2 `cwe_unique` CWEs not claimed by any other entry in the
      corpus, each grounded in that entry's own actual code (not the
      abstract mechanism), with `cwe_rationale:` prose per entry.
      `.claude/hooks/check-corpus-cwe-coverage.sh` (extended to check
      cross-entry uniqueness, not just count) passes clean on the current
      tree — it caught 2 entries still on the old flat `cwe:` field and one
      real cross-entry ID collision (CWE-367) the first time it ran against
      this pass's work, both fixed.
- [x] Step 8: `suggested_op`/`suggested_sink_family` proposals recorded for
      all pairs across all 12 cells. Applied to `lab/safety_matrix.yaml` per
      direct instruction (102 entries, was 25; 20 new sink families; see
      `CC-LAB-0059`/`FR-LAB-56`) — registry-only, no emitter/module yet
      generates code for the new sink families (separate future work).
- [x] Scope correction (per direct instruction): waves 1-2 had incorrectly
      confined collection to CWE classes already implemented in
      `lab/safety_matrix.yaml` (SQLi/XSS-adjacent only), defeating the
      point of this research (expanding the generator's vulnerability
      classes), and had collected only 1 pair per class instead of the
      required floor of >= 5. Corrected in wave 3: 6 brand-new
      vulnerability-class cells, one per site-architecture category, none
      previously in the corpus or `lab/safety_matrix.yaml` — mass-assignment
      (CWE-915, category 1/e-commerce), ssrf (CWE-918, category 2/social-
      UGC), insecure-deserialization (CWE-502, category 3/SaaS), ssti
      (CWE-1336, category 4/media), header-injection (CWE-93, category
      5/travel), webhook-signature (CWE-347/CWE-345, category 6/fintech) —
      see `docs/research/corpus-examples/{mass-assignment,ssrf,
      insecure-deserialization,ssti,header-injection,webhook-signature}/
      {node,php,python}/manifest.yaml`. Each class has >= 5 vulnerable/
      idiomatic pairs (60 entries total): one real, license-verified,
      commit-pinned upstream anchor per class plus 4 manufactured pairs
      (`synthetic: true`, `license: "N/A (synthetic)"`, no fabricated repo
      attribution) per Phase 3's "Pair generation" methodology, chosen
      because 5 independently-sourced real repos per brand-new class was
      impractical within this environment. All 60 entries meet the
      tightened `cwe_shared`/`cwe_unique` standard (>= 2 `cwe_unique` CWEs
      each, no cross-entry collisions across any touched manifest file);
      `.claude/hooks/check-corpus-cwe-coverage.sh` passes clean
      (`hook_exit=0`) across the full touched set. `suggested_op`/
      `suggested_sink_family` recorded per entry, applied to
      `lab/safety_matrix.yaml` together with the original 6 pairs' — see
      the Step 8 line above (`CC-LAB-0059`/`FR-LAB-56`).
- [ ] Remaining architecture/function combinations within each of the 6
      original categories (each category's 5 sites can surface more than
      one combination; only one per category has been carried through for
      the original 6 pairs so far) — separate from the 6 new classes above.
- [ ] Dynamic-tier validation for all 6 pairs (`validated_by: [dynamic]`) —
      deferred to an environment with a sandboxed execution runtime; every
      pair is `validated: true` at the static/manual-review tier in the
      interim.
- [x] `lab/safety_matrix.yaml` integration — done per direct instruction,
      `CC-LAB-0059`/`FR-LAB-56` (see Step 8 above). Registry-only: emitter/
      module code generation for the 20 new sink families remains a
      separate, unstarted follow-up.
- [x] Emitter/module code generation, first increment — `orm_entity_bulk_
      assign` (mass-assignment) implemented in `php_current` and
      `php_laravel` (`CC-LAB-0060`/`FR-LAB-57`, drafted and reviewed
      through this project's new pre-change review gate before
      implementation, per direct instruction). 2 of the family's 10 ops;
      the other 8 ops, the other 19 new sink families, and
      `python_fastapi`/`node_express` remain registry-only, explicitly
      deferred — not all 20 families x 4 emitters in one pass, matching
      this plan's own "scope per wave" convention.
