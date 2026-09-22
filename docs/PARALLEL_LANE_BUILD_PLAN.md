# Parallel Lane Build Plan — remaining safe-to-build-now backlog

Status: **PLAN ONLY — not yet dispatched.** This document organizes the current
offline-buildable backlog into build lanes for concurrent AI agents, per
`docs/MULTI_AGENT_ORCHESTRATION.md`. No lane in this plan has been executed;
creating/revising this document is itself the only change made.

Revision history:
- v1 (2026-09-22): initial draft.
- v2 (2026-09-22): revised after two independent review passes. Fixes: a real
  `CC-FUZZ-0019` numbering collision between Wave C1 and Wave B2; Wave B1's
  false premise that R1 (route-per-section split) is done (only R0 — shell +
  tokens — is done); an incorrect "duplicate CC-LAB-0056" claim; DOM-XSS
  incorrectly implied as already merged; an unspecified M8-wiring scope;
  an unaddressed same-wave, same-component `change-control.md`/`requirements.md`
  concurrent-edit conflict; a `--dry-run` scope that didn't distinguish the
  already-shipped web endpoint from the missing CLI flag; and a C2 gate that
  referenced a nonexistent "in-progress re-audit."

Scope: the three backlog groups called out as "safe to build now (offline, no
missing precondition)" — lab track / manifest generator, UI/diagnostics, and
oracle/mutation. Anything not offline-buildable (on-host live-target work,
anything needing `--authorized`) is explicitly out of scope, per D11.

## How to use this plan

1. Each lane below has a **pre-assigned bookkeeping-number block** (component
   change-control IDs), per PA-0031 — dispatch prompts must hand the lane its
   reserved numbers, not "claim the next free one." Numbers were computed from
   the current highest entry in each component's `docs/components/<n>-*/change-control.md`
   as of 2026-09-22; **re-verify the highest number immediately before dispatch**
   in case other lanes merged in the meantime, and flag rather than silently
   renumber on a collision (PA-0031).
2. Lanes in the same **wave** touch disjoint code/doc files and can run fully
   in parallel *except* for the shared per-component bookkeeping files
   addressed by the **merge protocol** below. A lane in a later wave either
   depends on an earlier wave's output or touches files an earlier-wave lane
   also touches (noted under "Overlap / sequencing risk").
3. **Merge protocol for shared per-component bookkeeping files.** When two or
   more lanes in the same wave share a component (e.g. Wave B1's five UI
   lanes all write to `docs/components/12-diagnostics-and-ui/`), they all
   touch that component's `change-control.md` (append-only) and
   `requirements.md` (living doc, edited in place). This is a real
   concurrent-edit conflict, not a trivial one:
   - `change-control.md` (append-only): each lane appends only its own
     pre-assigned `CC-<CODE>-NNNN` entry, at the top per the log's newest-first
     convention. An integrator merges each lane's branch **one at a time**,
     re-checking that no other lane's entry landed between the merges (if it
     did, re-verify the entry ordering rather than silently reordering).
   - `requirements.md` (living doc, edited in place): each lane proposes its
     requirements-spec delta as an isolated diff against the version it
     branched from. If two lanes' deltas touch the same section, the
     integrator resolves it by hand at merge time (do not let a lane auto-merge
     over another's edit); if they touch disjoint sections, merge is
     mechanical. Lanes should keep their `requirements.md` edits additive and
     section-scoped to minimize this.
   - Same rule applies to Lane group A (LAB) whenever more than one A1 lane
     lands in the same window, and to Lane group C if C1 and a future C-wave
     lane overlap.
4. Every lane still owes the full `CLAUDE.md` "Definition of done" checklist
   (tests, CHANGELOG line, change-control entry, requirements.md update,
   bug protocol if applicable) as part of its own commit — this plan only
   sequences the work, it doesn't waive bookkeeping.
5. Per `docs/MULTI_AGENT_ORCHESTRATION.md`: verify each lane's work
   independently before merging (re-run tests, read the diff, check the
   bookkeeping) — never merge on a lane's self-report alone.

---

## Lane group A — Lab track / manifest generator (component: LAB, primary)

### Wave A0 (serial prerequisite — must land before A1's sub-lanes are cut)

**A0 — Remaining-page inventory sweep**
- Reserved: `CC-LAB-0059`
- Scope: `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3/4.3.6.4 documents the
  G1–G6 wave (10 pages/pairs, now merged) but does **not** yet enumerate the
  next wave. This lane's only job is to produce that enumeration: list the
  remaining ~26 real pages, group them into pattern lanes the same way G1
  (numeric-literal), G2 (listing+JSON feed), G3 (auth pages), G4 (stored
  second-order pair), G5 (escaped-echo forms), and G6 (search.php + matrix
  row, serialized owner of `lab/safety_matrix.yaml`) were grouped, and size
  each (S/M/L) with its dependencies (e.g. a lane needing a new shared module,
  or touching the safety-matrix file, must be flagged as the sole owner of
  that shared file, same as G6 was).
- **DOM-XSS stays excluded.** Per `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.4
  decision D-open-2 (2026-09-22), `L-P3.3c-DOM` (reviews.php/feedback.php) was
  explicitly deferred out of the cutover scope — "dispatch only if separately
  prioritized." Its change-control entries are still `[ ]` pending, not
  merged. A0 must **not** fold DOM-class pages into G7…Gn; list them
  separately as a standing deferred item unless the user explicitly
  reprioritizes them.
- Output: an updated §4.3.6 in `docs/LAB_IMPLEMENTATION_PLAN.md` (or a new
  §4.3.7) naming lanes **G7…Gn**, each with a page list, a size, and an
  explicit "shared-file owner" flag where applicable.
- Note: an earlier draft of this plan flagged a "duplicate `CC-LAB-0056`
  entry" in the LAB change-control log. That was checked and is a **false
  positive** — there is exactly one `### CC-LAB-0056` heading; the second
  grep hit was an inline cross-reference inside the later `CC-LAB-0058`
  entry's prose. A0 does not need to chase this.
- Deliverable also reserves the **next LAB block**: `CC-LAB-0060`–`0075`
  (16 slots) for the G7…Gn lanes this sweep defines, so each downstream lane
  gets one committed number rather than re-deriving "next free."

### Wave A1 (parallel — dispatch once A0 lands; each lane owns disjoint page files)

**G7…Gn — Remaining ~26 page migrations into php_current/php_laravel emitters**
- Reserved block: `CC-LAB-0060`–`0075` (assigned per-lane by A0's output; a
  lane that needs more than one number, e.g. because it also touches a shared
  module, gets the next unused slot in the block — flag if the block is
  exhausted rather than reusing a number).
- Each lane = one pattern group from A0 (mirrors G1–G6 sizing precedent: S ≈
  1–2 pages/no shared module, M ≈ needs a small shared module or a stored
  pair, L ≈ touches a genuinely shared file like `safety_matrix.yaml` and
  must be the sole lane touching it that wave).
- Overlap / sequencing risk: any lane whose pages route through
  `lab/safety_matrix.yaml` (the G6 precedent) must be serialized against
  every other such lane — A0 must flag all matrix-touching lanes explicitly
  so at most one runs per wave.
- Each lane emits into both `php_current` and `php_laravel` emitters per
  page, plus its own fixtures/tests — no lane should need to touch another
  lane's page files. All lanes in this wave share `docs/components/01-target-lab/`
  bookkeeping files — follow the **merge protocol** above.

**T1 — Tier1 conformance-suite live wiring**
- Reserved: `CC-LAB-0076`
- Scope: `fuzzlab/labgen/conformance/tier1.py` + `tests/test_labgen_conformance_tier1.py`.
  Currently `"[design — not exercised against a live app/DB]"`; this lane
  wires it against a real in-process app+DB (following the `php_laravel`
  live-boot proof precedent already established at `CC-LAB-0054` — a
  synthetic, in-sandbox Laravel/SQLite boot, **not** the real lab target) for
  whichever stacks are ready. This stays inside the offline/lab-only scope
  and does not require `--authorized`: it never touches the real,
  loopback-only Ryder's Puppy Fort Factory target. Can start against the
  pages that exist today; extend incrementally as A1 lanes land rather than
  blocking on all of them.
- File ownership: `tier1.py` + its own tests only. Does not touch `tier2.py`
  or any shared conformance fixtures module without coordinating with T2
  (see below).

**T2 — Tier2 conformance-suite live wiring**
- Reserved: `CC-LAB-0077`
- Scope: same pattern as T1 but `fuzzlab/labgen/conformance/tier2.py` +
  `tests/test_labgen_conformance_tier2.py`. Same offline/in-sandbox scope and
  safety posture as T1.
- Overlap / sequencing risk: if T1 and T2 share a conformance test-harness
  fixture module (verify before dispatch — not confirmed by the research
  pass), one of them must own that shared file for the wave; otherwise they
  are file-disjoint and can run alongside T1 and the G7…Gn lanes.

### Wave A2 (capstone — gated on all of Wave A1 landing)

**A2 — Byte-identical full-manifest reproduction (Phase-0 exit criterion)**
- Reserved: `CC-LAB-0078`
- Scope: the actual Phase-0 lab-generator exit criterion — the manifest
  reproducing the full ~30-page app byte-identically. This is explicitly
  gated: it cannot be verified until every G7…Gn page-migration lane has
  merged, since it needs the full page set to diff against; T1/T2 landing
  first is preferred but not strictly required for this specific check.
  **Checkable gate condition**: every `CC-LAB-00NN` entry A0 assigned to a
  G7…Gn lane in `docs/components/01-target-lab/change-control.md` is present
  and marked done, and the page-manifest diff tool reports zero remaining
  unmigrated real pages. Do not dispatch until that condition is verified,
  not just assumed.
- This lane is also the natural place to close out Phase 0 in
  `docs/DECISIONS_AND_ROADMAP.md` and `docs/ARCHITECTURE.md`'s phase-status
  table once it passes.

---

## Lane group B — UI / diagnostics (component: UI, primary; some lanes also touch PROXY/ML)

**Correction from v1: R1 is NOT done.** Checked
`docs/components/12-diagnostics-and-ui/change-control.md` ("`[ ] R1 (routes +
Overview), R2 (Findings), R3 (Proxy rebuild) — pending.`") and
`docs/ARCHITECTURE.md` ("R1 still adds deep-linkable per-section routes + an
Overview dashboard, R2 a Findings workbench, R3 a Proxy rebuild"). Only **R0**
(shell + tokens, hash-based section switching preserved) and the Launch
master-detail view (a piece of R1 brought forward early) are done. There is
no per-section route scaffold yet for R2/R3/ML/diagnostics/store-exploration
lanes to plug into — without R1 first, all five "independent" lanes would be
editing the same still-monolithic shell/template concurrently, which is a
real collision, not a false one.

### Wave B0 (serial prerequisite — must land before B1's lanes are cut)

**R1 — Route-per-section split + Overview dashboard**
- Reserved: `CC-UI-0025`
- Scope: build the actual per-section route scaffold (deep-linkable routes)
  and the Overview dashboard on top of R0's shell, per
  `docs/UI_LAYOUT_REDESIGN.md`. This is the structural precedent Wave B1's
  lanes need: each B1 lane must be able to add **its own route file** rather
  than editing a shared monolithic template. R1's output should include a
  documented convention (e.g. "each section lives in its own route module
  under `<dir>/sections/<name>.*`, registered in a single small manifest
  file") so B1 lanes only touch their own new file plus one line in that
  registration manifest.
- This lane is the one place in Wave B0/B1 that legitimately owns the shared
  shell/template files; everything downstream depends on its route
  convention being in place first.

### Wave B1 (parallel — dispatch once B0/R1 lands; each lane owns its own route module)

**R2 — Findings workbench**
- Reserved: `CC-UI-0026`
- Scope: new findings-workbench section, built as its own route module per
  R1's convention. Owns its own route/view files, plus one line in R1's
  section-registration manifest.

**R3 — Proxy rebuild**
- Reserved: `CC-UI-0027` + `CC-PROXY-0017`
- Scope: UI-side proxy section rebuild (own route module) plus the
  PROXY-component changes it depends on. Dual bookkeeping — both component
  logs get an entry. Note the safety posture: proxy/desync tooling stays
  default-off and lab-only per CLAUDE.md; this lane must not flip that
  default.
- Overlap / sequencing risk: only lane touching `fuzzlab/proxy/`; no conflict
  expected with other B1 lanes beyond the shared registration-manifest line.

**ML tab**
- Reserved: `CC-UI-0028` + `CC-ML-0009`
- Scope: new ML section (own route module) plus whatever ML-component
  surface it needs to read from. Dual bookkeeping.
- Overlap / sequencing risk: check whether this lane and "Datasette-style
  store exploration" (below) share a common store-access/data-layer module;
  if so, one lane owns that module for the wave (flag before dispatch — not
  confirmed by the research pass).

**Diagnostics / metric_series tab**
- Reserved: `CC-UI-0029`
- Scope: new diagnostics section (own route module) exposing `metric_series`
  data.
- Overlap / sequencing risk: same store-access-layer check as the ML tab
  lane above — verify before dispatch.

**Datasette-style store exploration**
- Reserved: `CC-UI-0030`
- Scope: browsing UI over the store, Datasette-style (own route module).
- Overlap / sequencing risk: see ML tab and metric_series notes above — three
  lanes (ML tab, metric_series tab, store exploration) all read from "the
  store," so confirm whether a shared data-access module exists before
  treating them as fully disjoint. If it does, either (a) have one lane build
  the shared module first as a short blocking sub-step the other two lanes
  wait on, or (b) serialize the three.
- All five B1 lanes share `docs/components/12-diagnostics-and-ui/`
  bookkeeping files and R1's registration manifest — follow the **merge
  protocol** above; the registration-manifest line is a one-line append per
  lane, low collision risk, but still merge one lane at a time.

### Wave B2 (its own lane — sequenced against Lane group C)

**`--dry-run` CLI flag**
- Reserved: `CC-UI-0031` (if the flag is exposed/documented through the web
  UI) — see FUZZ number below.
- **Scope correction from v1**: the web UI already ships a dry-run preview
  (`POST /api/launch/dry-run` in `fuzzlab/web/app.py` + `web/runner.py`,
  shipped as `CC-UI-0013`/`CC-UI-0015`, both done) — "plans and reports the
  exact argv/display, sends nothing." **Do not rebuild that.** The actual
  remaining gap, per `docs/ARCHITECTURE.md`'s pending list, is a **CLI-level**
  `--dry-run` flag on the plain CLI entry points in `fuzzlab/cli.py` (listed
  alongside "a plain CLI entry point per tool for headless use," itself
  pending) — for headless use outside the web UI. Scope this lane narrowly to
  that CLI flag/entry-point work; reuse the web dry-run's plan/report logic
  rather than reimplementing it.
- Reserved: `CC-FUZZ-0021` (see numbering note below).
- Overlap / sequencing risk: this lane's CLI-entry-point work plausibly
  touches the same files as **M8-wiring** in Lane group C. Treat as
  sequenced after Wave C1, not a same-wave parallel lane.

---

## Lane group C — Oracle / mutation (components: FUZZ primary, MUT/CORE secondary)

M8 (`CC-MUT-0008`, the semantics-validator fail-open fix — note this is a
different "M8" than the oracle-confirmation OOB mechanism of the same
nickname, per `docs/architecture/oracle-confirmation.md`; don't conflate the
two when briefing a lane) is done and previously held the file lock on the
areas below.

### Wave C1

**M8-wiring — mutation-engine variants into the fuzzer's actual attempt path**
- Reserved: `CC-FUZZ-0019` + `CC-MUT-0009`
- **Scope, made concrete**: `docs/PHASE_8_PLAN.md` marks T8.1–T8.6 done,
  including T8.5's "emit accepted variants into the attempt path" — but that
  currently only reaches the standalone `fuzzlab mutate-run` CLI
  (`fuzzlab/mutation/cli.py`), not the main fuzzer's `greybox-run`/harness
  attempt loop. This lane's concrete deliverable: wire accepted mutation
  variants from the mutation engine into the **main harness's** attempt path
  (the code path `greybox-run` uses), not just the standalone `mutate-run`
  entry point. T8.7's on-host exit criterion stays out of scope here.
- This lane, not the UI group's `--dry-run` lane, should be treated as the
  primary owner of the fuzzer's attempt-path files for this wave — see
  Wave B2 note above. `CC-FUZZ-0019` belongs to this lane; Wave B2's dry-run
  lane was corrected to `CC-FUZZ-0021` to remove the collision an earlier
  draft of this plan introduced (both lanes had claimed `0019`).

### Wave C2 (conditional — do not dispatch until a human/orchestrator confirms scope)

**M10 offline slice — hook/interface layer against a stub coverage source**
- Reserved (on confirmation): `CC-CORE-0018` (current highest confirmed as
  `CC-CORE-0017`) + `CC-FUZZ-0020`.
- Scope: `fuzzlab/greybox/confirm.py` already holds the pure decision logic
  (`docs/PHASE_3_PLAN.md` T3.6/T3.7); both `docs/components/02-core-library/change-control.md`
  and `docs/components/07-fuzzing-harness-and-oracle/change-control.md` note
  folding M10 into `Oracle.confirm` with a per-candidate sink line as a
  pending follow-up. The offline-buildable slice would be the hook/interface
  layer wired against a **stub** coverage source (no live-host coverage
  collector).
- **Gate correction from v1**: there is no "in-progress re-audit" — a
  repo-wide search turns up nothing matching that description; this plan's
  own earlier draft was the only hit. The gate is therefore not a checkable
  "wait for the audit to finish" condition. Reword it plainly: **do not
  dispatch C2 until a human (or a dedicated scoping lane, run the same way as
  A0/B0) explicitly determines and documents that an offline-buildable M10
  slice exists** — i.e. this needs a scoping decision first, not a wait.
  If/when confirmed, this lane touches the same `Oracle.confirm` / oracle
  pipeline files as M8-wiring (Wave C1) — serialize C2 after C1, don't run
  them in the same wave even once C2 is unblocked.

---

## Wave summary (max parallelism per wave)

| Wave | Lanes that can run concurrently | Gate to enter this wave |
| --- | --- | --- |
| 1 | A0 (lab sweep) · B0 (R1 route split) · C1 (M8-wiring) | None — all offline-buildable now |
| 2 | A1's G7…Gn page lanes + T1 + T2 (once A0 lands) · B1's five UI lanes (R2, R3, ML tab, metric_series, store exploration — once B0/R1 lands, modulo the shared-store-layer check) · B2 `--dry-run` CLI flag (once C1 lands) | A0 merged (for A1/T1/T2); B0/R1 merged (for B1); C1 merged (for B2) |
| 3 | A2 byte-identical manifest capstone · C2 M10 offline slice (only if scoping lane/human confirms) | Wave A1 fully merged & verified (for A2); explicit scoping confirmation + C1 merged (for C2) |

**Correction from v1: Wave 1 has 3 concurrent lanes, not 7.** The original
draft counted B1's five UI lanes as Wave-1-parallel, but they depend on
R1 (Wave B0) landing first — R1 was wrongly assumed done. True Wave 1 is
A0 + B0 + C1 (3 lanes). Wave 2 is where the largest fan-out lands: up to
5 UI lanes (B1) + however many G7…Gn lanes A0 defines + T1 + T2 + B2, all
depending only on their respective Wave-1 prerequisite having merged and
verified.

## Known risks to flag before dispatch (per MULTI_AGENT_ORCHESTRATION.md — flag, don't silently resolve)

- Unconfirmed shared store-access module among ML tab / metric_series tab /
  Datasette-style store exploration (Wave B1) — verify before dispatch.
- Unconfirmed shared conformance-harness fixture file between T1 and T2 —
  verify before dispatch.
- M10's offline-buildability is an open scoping question, not yet confirmed
  by anyone — Wave C2 stays provisional until a scoping lane or a human
  explicitly resolves it (see Wave C2 gate).
- Same-wave, same-component concurrent edits to `change-control.md` /
  `requirements.md` (Wave A1's G7…Gn+T1+T2, Wave B1's five UI lanes) need the
  **merge protocol** above applied at integration time, not assumed away.
- R1's exact route-registration convention (module-per-section +
  single-manifest-line) is this plan's proposal for how B0 unblocks B1
  cleanly; if R1's actual implementation lands differently, re-check that
  B1's "own route module" framing still holds before dispatching B1.
