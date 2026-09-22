# Parallel Lane Build Plan — remaining safe-to-build-now backlog

Status: **PLAN ONLY — not yet dispatched.** This document organizes the current
offline-buildable backlog into build lanes for concurrent AI agents, per
`docs/MULTI_AGENT_ORCHESTRATION.md`. No lane in this plan has been executed;
creating this document is itself the only change made.

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
2. Lanes in the same **wave** touch disjoint files and can run fully in
   parallel. A lane in a later wave either depends on an earlier wave's output
   or touches files an earlier-wave lane also touches (noted under "Overlap /
   sequencing risk").
3. Every lane still owes the full `CLAUDE.md` "Definition of done" checklist
   (tests, CHANGELOG line, change-control entry, requirements.md update,
   bug protocol if applicable) as part of its own commit — this plan only
   sequences the work, it doesn't waive bookkeeping.
4. Per `docs/MULTI_AGENT_ORCHESTRATION.md`: verify each lane's work
   independently before merging (re-run tests, read the diff, check the
   bookkeeping) — never merge on a lane's self-report alone.

---

## Lane group A — Lab track / manifest generator (component: LAB, primary)

### Wave A0 (serial prerequisite — must land before A1's sub-lanes are cut)

**A0 — Remaining-page inventory sweep**
- Reserved: `CC-LAB-0059`
- Scope: `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3/4.3.6.4 documents the
  G1–G6 + DOM wave (10 pages/pairs, now merged) but does **not** yet enumerate
  the next wave. This lane's only job is to produce that enumeration: list
  the remaining ~26 real pages, group them into pattern lanes the same way
  G1 (numeric-literal), G2 (listing+JSON feed), G3 (auth pages), G4 (stored
  second-order pair), G5 (escaped-echo forms), and G6 (search.php + matrix
  row, serialized owner of `lab/safety_matrix.yaml`) were grouped, and size
  each (S/M/L) with its dependencies (e.g. a lane needing a new shared module,
  or touching the safety-matrix file, must be flagged as the sole owner of
  that shared file, same as G6 was).
- Output: an updated §4.3.6 in `docs/LAB_IMPLEMENTATION_PLAN.md` (or a new
  §4.3.7) naming lanes **G7…Gn** (and any further DOM-class or other
  new-capability lanes), each with a page list, a size, and an explicit
  "shared-file owner" flag where applicable.
- Note: before double-booking `CC-LAB-0056`, confirm/resolve the existing
  duplicate `CC-LAB-0056` entry in the LAB change-control log; this lane
  should flag it rather than silently overwrite.
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
  lane's page files.

**T1 — Tier1 conformance-suite live wiring**
- Reserved: `CC-LAB-0076`
- Scope: `fuzzlab/labgen/conformance/tier1.py` + `tests/test_labgen_conformance_tier1.py`.
  Currently `"[design — not exercised against a live app/DB]"`; this lane
  wires it against a real in-process app+DB (following the `php_laravel`
  live-boot proof precedent already established for CC-LAB-0056/live-boot
  tests) for whichever stacks are ready. Can start against the pages that
  exist today; extend incrementally as A1 lanes land rather than blocking on
  all of them.
- File ownership: `tier1.py` + its own tests only. Does not touch `tier2.py`
  or any shared conformance fixtures file without coordinating with T2 (see
  below).

**T2 — Tier2 conformance-suite live wiring**
- Reserved: `CC-LAB-0077`
- Scope: same pattern as T1 but `fuzzlab/labgen/conformance/tier2.py` +
  `tests/test_labgen_conformance_tier2.py`.
- Overlap / sequencing risk: if T1 and T2 share a conformance test-harness
  fixture module (verify before dispatch — not confirmed by the research
  pass), one of them must own that shared file for the wave; otherwise they
  are file-disjoint and can run alongside T1 and the G7…Gn lanes.

### Wave A2 (capstone — gated on all of Wave A1 landing)

**A2 — Byte-identical full-manifest reproduction (Phase-0 exit criterion)**
- Reserved: `CC-LAB-0078`
- Scope: the actual Phase-0 lab-generator exit criterion — the manifest
  reproducing the full ~30-page app byte-identically. This is explicitly
  gated: it cannot be verified until every G7…Gn page-migration lane (and
  ideally T1/T2) has merged, since it needs the full page set to diff
  against. Do not dispatch until Wave A1 is fully merged and independently
  verified.
- This lane is also the natural place to close out Phase 0 in
  `docs/DECISIONS_AND_ROADMAP.md` and `docs/ARCHITECTURE.md`'s phase-status
  table once it passes.

---

## Lane group B — UI / diagnostics (component: UI, primary; some lanes also touch PROXY/ML)

R1 (route-per-section split, `docs/UI_LAYOUT_REDESIGN.md`) is done and is the
structural precedent these lanes build into — each lane below adds one
route/section rather than restructuring shared layout.

### Wave B1 (parallel — five independent routes/sections)

**R2 — Findings workbench**
- Reserved: `CC-UI-0025`
- Scope: new findings-workbench route/section under the R1 layout. Owns its
  own route files and view components only.

**R3 — Proxy rebuild**
- Reserved: `CC-UI-0026` + `CC-PROXY-0017`
- Scope: UI-side proxy route rebuild plus the PROXY-component changes it
  depends on. Dual bookkeeping — both component logs get an entry. Note the
  safety posture: proxy/desync tooling stays default-off and lab-only per
  CLAUDE.md; this lane must not flip that default.
- Overlap / sequencing risk: only lane touching `fuzzlab/proxy/`; no conflict
  expected with other B-wave lanes.

**ML tab**
- Reserved: `CC-UI-0027` + `CC-ML-0009`
- Scope: new ML tab in the UI plus whatever ML-component surface it needs to
  read from. Dual bookkeeping.
- Overlap / sequencing risk: check whether this lane and "Datasette-style
  store exploration" (below) share a common store-access/data-layer module;
  if so, one lane owns that module for the wave (flag before dispatch — not
  confirmed by the research pass).

**Diagnostics / metric_series tab**
- Reserved: `CC-UI-0028`
- Scope: new diagnostics tab exposing `metric_series` data. Own route/view
  files only.
- Overlap / sequencing risk: same store-access-layer check as the ML tab
  lane above — verify before dispatch.

**Datasette-style store exploration**
- Reserved: `CC-UI-0029`
- Scope: browsing UI over the store, Datasette-style. Own route/view files.
- Overlap / sequencing risk: see ML tab and metric_series notes above — three
  lanes (ML tab, metric_series tab, store exploration) all read from "the
  store," so confirm whether a shared data-access module exists before
  treating them as fully disjoint. If it does, either (a) have one lane build
  the shared module first as a short blocking sub-step other two lanes wait
  on, or (b) serialize the three.

### Wave B2 (its own lane — cross-cutting, sequence against Lane group C)

**`--dry-run` mode**
- Reserved: `CC-UI-0030` (+ `CC-FUZZ-0019` if it needs a flag/hook in the
  fuzzer's own CLI entry point, which is likely since a dry-run flag has to
  intercept the actual attempt path, not just the UI)
- Scope: add a dry-run mode surfaced through the UI/CLI that runs the pipeline
  without sending live traffic.
- Overlap / sequencing risk: this is the one lane in the UI group that
  plausibly touches the same fuzzer execution/attempt-path files as **M8-wiring**
  in Lane group C below. Treat as sequenced against Lane group C, not a
  same-wave parallel lane — dispatch after M8-wiring lands, or coordinate
  explicitly if both must run at once (see Lane group C notes).

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
- Scope: Phase 8's offline half (`docs/PHASE_8_PLAN.md` T8.1–T8.7 — all
  offline tasks done per that plan; T8.7's on-host exit stays out of scope
  here). This lane was explicitly held back only to avoid file overlap with
  the now-merged M8 (`CC-MUT-0008`) lane and is clear to dispatch now.
- This lane, not the UI group's `--dry-run` lane, should be treated as the
  primary owner of the fuzzer's attempt-path files for this wave — see
  Wave B2 note above.

### Wave C2 (conditional — do not dispatch until the in-progress re-audit resolves)

**M10 offline slice — hook/interface layer against a stub coverage source**
- Reserved (on confirmation): `CC-CORE-00XX` (verify current highest
  `CC-CORE-NNNN` before dispatch — not established by this planning pass)
  + `CC-FUZZ-0020`
- Scope: `fuzzlab/greybox/confirm.py` already holds the pure decision logic
  (`docs/PHASE_3_PLAN.md` T3.6/T3.7); both `docs/components/02-core-library/change-control.md`
  and `docs/components/07-fuzzing-harness-and-oracle/change-control.md` note
  folding M10 into `Oracle.confirm` with a per-candidate sink line as a
  pending follow-up. The offline-buildable slice would be the hook/interface
  layer wired against a **stub** coverage source (no live-host coverage
  collector) — but this is explicitly **unconfirmed**: no in-progress audit
  document was found during this planning pass, so treat "offline-buildable"
  as an open question, not a given.
- **Gate: do not dispatch this lane until the re-audit referenced in the
  backlog explicitly confirms an offline-buildable slice exists.** If/when
  confirmed, this lane touches the same `Oracle.confirm` / oracle pipeline
  files as M8-wiring (Wave C1) — serialize C2 after C1, don't run them in the
  same wave even once C2 is unblocked.

---

## Wave summary (max parallelism per wave)

| Wave | Lanes that can run concurrently | Gate to enter this wave |
| --- | --- | --- |
| 1 | A0 (lab sweep) · B1's five UI lanes (R2, R3, ML tab, metric_series, store exploration — modulo the shared-store-layer check) · C1 (M8-wiring) | None — all offline-buildable now |
| 2 | A1's G7…Gn page lanes + T1 + T2 (once A0 lands) · B2 `--dry-run` (once C1 lands, or coordinated with it) | A0 merged (for A1/T1/T2); C1 merged (for B2) |
| 3 | A2 byte-identical manifest capstone · C2 M10 offline slice (only if re-audit confirms) | Wave A1 fully merged & verified (for A2); re-audit confirms + C1 merged (for C2) |

This gives up to **7 lanes running simultaneously in Wave 1** (A0, R2, R3, ML
tab, metric_series tab, store exploration, M8-wiring), with the largest
possible fan-out — A1's full G7…Gn split — unlocked in Wave 2 once A0 defines
how many lanes that is.

## Known risks to flag before dispatch (per MULTI_AGENT_ORCHESTRATION.md — flag, don't silently resolve)

- Duplicate `CC-LAB-0056` entry in the LAB change-control log — resolve before
  reserving `CC-LAB-0059`+.
- Unconfirmed shared store-access module among ML tab / metric_series tab /
  Datasette-style store exploration (Wave B1).
- Unconfirmed shared conformance-harness fixture file between T1 and T2.
- M10's offline-buildability is unconfirmed pending the referenced re-audit —
  Wave C2 is provisional until that resolves.
- `CC-CORE-NNNN`'s current highest was not established by this planning pass
  — verify before reserving a CORE number for Wave C2.
