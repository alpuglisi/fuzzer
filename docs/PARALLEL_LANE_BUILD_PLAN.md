# Parallel Lane Build Plan — remaining safe-to-build-now backlog

Status: **PLAN ONLY — not yet dispatched.** This document organizes the current
offline-buildable backlog into build lanes for concurrent AI agents, per
`docs/MULTI_AGENT_ORCHESTRATION.md`. No lane in this plan has been executed;
creating/revising this document is itself the only change made.

Revision history:
- v1 (2026-09-22): initial draft.
- v2 (2026-09-22): revised after review round 1. Fixed a `CC-FUZZ-0019`
  numbering collision, a false "R1 is done" premise, a false "duplicate
  CC-LAB-0056" claim, DOM-XSS wrongly implied merged, an under-specified
  M8-wiring scope, an unaddressed bookkeeping-file merge conflict, an
  imprecise `--dry-run` scope, and a nonexistent-audit gate for M10.
- v3 (2026-09-22): revised after review round 2 (two more findings, both
  confirmed by direct repo verification):
  1. **Lane group A's premise was wrong.** There is no ~26-page Layer-A
     migration backlog left — see the corrected Wave A0 below.
  2. **Lane group B duplicated an already-authoritative plan.** The repo
     already has `docs/UI_IMPLEMENTATION_PLAN.md` — a more detailed,
     decision-locked (D1–D5), already change-controlled (starting at
     `CC-UI-0023`) lane map for exactly this UI backlog (U0–U6, B0, X0). v3
     replaces the invented R2/R3/ML-tab/etc. lane structure with a pointer to
     that plan plus this document's own contribution: pre-assigned
     bookkeeping numbers.
- v4 (2026-09-22): revised after review round 3. Fixed: an arithmetic error
  in Wave A0's reconciliation (11 pages ≠ 16 cases; corrected to 13 cases +
  1 exempt + 2 deferred = 16); a real, previously-unflagged file overlap
  between B0's coverage-frontier emitter and C1/M8-wiring in
  `fuzzlab/greybox/run.py` (now split into Wave 1a/1b with an explicit
  sequencing note); A2's scope question resolved inline via D-open-1 (Layer
  A only) instead of left open, since A0 already quotes the answer; the
  `CC-SCHED-0004`→`0005` number resolved instead of left "TBD"; and D0 split
  into D0a (non-greybox CLI tools, Wave 1, no gate) + D0b (`greybox-run`
  only, Wave 2, gated on C1) to reclaim parallelism the single-lane version
  was leaving on the table.
- v5 (2026-09-22): revised after review round 4 (three reviewers; 1 approve
  with minor notes, 2 needs-revision). Fixed: **X0 ("register `lab-generate`
  in the launcher") is already done** — confirmed as `CC-UI-0024`, landed in
  `fuzzlab/web/commandspec.py` with tests; `docs/UI_IMPLEMENTATION_PLAN.md`
  was never updated to mark it done, which is what caused this plan to keep
  listing it as a Wave-0 lane through v4. Dropped X0 from dispatch and
  renumbered `CC-UI-0026`–`0032` accordingly. Also: this plan's own
  bookkeeping trail had a gap — v2/v3/v4 revised the document without adding
  corresponding `CHANGELOG.md` lines (fixed, consolidated entry added); and
  U3's dual-use safety-posture note is now promoted to the Known Risks list,
  not just stated inline in U3's own entry.
- v6 (2026-09-22): revised after review round 5 (three reviewers; 1 approve,
  1 needs-revision, 1 approve with minor notes). Fixed: **D0a was missing
  bookkeeping numbers for four of the five non-UI components it touches**
  (`CRAWL`, `AUD`, `FUZZ`, `MUT`, `PROXY` — it only reserved a UI number),
  a real PA-0031 gap. Added the missing numbers and, because D0a is Wave 1a
  but touches components B0's emitters (Wave 1b) and U3 (Wave 2) also touch,
  renumbered the full FUZZ (`C1=0019 → D0a=0020 → B0-coverage=0021 →
  D0b=0022 → C2=0023`), MUT (`C1=0009 → D0a=0010 → B0-MutationSearch=0011`),
  and PROXY (`D0a=0017 → U3=0018`) sequences to slot D0a in correctly. Also
  fixed a stale reference in Wave A1's exception-path text that would have
  had a future G7…Gn lane collide with T1/T2/A2's already-claimed
  `CC-LAB-0060`–`0062` (corrected to `CC-LAB-0063`+).

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
   more lanes in the same wave share a component (e.g. Lane group A's Wave A1,
   or UI's Wave 1 in `docs/UI_IMPLEMENTATION_PLAN.md`), they all touch that
   component's `change-control.md` (append-only) and `requirements.md`
   (living doc, edited in place):
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
4. Every lane still owes the full `CLAUDE.md` "Definition of done" checklist
   (tests, CHANGELOG line, change-control entry, requirements.md update,
   bug protocol if applicable) as part of its own commit — this plan only
   sequences the work, it doesn't waive bookkeeping.
5. Per `docs/MULTI_AGENT_ORCHESTRATION.md`: verify each lane's work
   independently before merging (re-run tests, read the diff, check the
   bookkeeping) — never merge on a lane's self-report alone.

---

## Lane group A — Lab track / manifest generator (component: LAB, primary)

### Wave A0 (fast reconciliation check — not a heavy sweep; must land before A1 is even considered)

**Correction from v2: the "~26 remaining pages" premise does not hold up
against the repo's own decisions.** Verified directly against
`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.1/§4.3.6.3/§4.3.6.7:

- The app splits into **Layer A** (16 labeled `PFF-` injection-cell cases —
  the only pages the `php_current`/`php_laravel` emitters model) and
  **Layer B** (≈17 unlabeled, JS-rendered/static realism pages — `about`,
  `faq`, `cart`, `checkout`, etc.).
- Layer A's page table (§4.3.6.3) is **already fully accounted for by case
  count, not just page count**: G1–G6 cover 11 pages (`product`, `blog_post`,
  `products`, `api/products`, `login`, `register`, `profile`+`edit_profile`,
  `contact`, `newsletter`, `search`) carrying **13 labeled `PFF-` cases**
  (`login` and `search` each carry 2; `profile`+`edit_profile` together carry
  2) — done. `track.php` is exempt (no sink, `PFF-1002`) — 1 case.
  `reviews.php`/`feedback.php` are the DOM-XSS pair (`PFF-0007`/`PFF-0008`),
  explicitly deferred (blocked — "no family exists"), not merged — 2 cases.
  13 + 1 + 2 = **16 `PFF-` cases**, all accounted for.
- **D-open-1 (decided 2026-09-22)**: "does retiring the fixture require
  reproducing Layer B? **No.**" Layer B is realism/crawler surface by design
  and was never meant to become generator cells.

So, as currently decided, **there is no Layer-A page-migration backlog left**
to split into G7…Gn lanes — G1–G6 already closed it out, and Layer B is
explicitly out of scope. The original "~26 remaining pages" figure this plan
was built from appears to be stale or to have conflated Layer B's page count
with Layer A's migration backlog; this plan does not silently resolve that
discrepancy either way.

**A0 — Layer-A reconciliation check** *(small, fast — hours not days)*
- Reserved: `CC-LAB-0059`
- Scope: mechanically confirm the reconciliation above against the live repo
  state at dispatch time (pages/cases may have changed since 2026-09-22):
  verify all 16 `PFF-` cases are accounted for (13 done via G1–G6, 2 deferred
  DOM, 1 exempt track.php) and that no new labeled cases were added. If the
  count still reconciles, **A0's output is a short note in
  `docs/LAB_IMPLEMENTATION_PLAN.md` confirming Layer A is closed** (pending
  only the deferred DOM pair, which stays its own explicitly-reprioritized
  item, not folded into this plan) — **no G7…Gn lanes get dispatched.**
- If A0 instead finds real, currently-undocumented remaining Layer-A scope
  (e.g. new pages added to the app since this plan was written), it should
  enumerate those specific pages/cases and size them the way G1–G6 were
  sized, reserving the next LAB numbers **after T1/T2/A2 below**
  (`CC-LAB-0063`+, not `0060` — T1, T2, and A2 already claim `0060`–`0062`)
  for that work — but this is the exception path, not the expected one.
- This lane also **does not** need to resolve a "duplicate `CC-LAB-0056`"
  claim from an earlier draft of this plan — that was checked and is a false
  positive (a cross-reference inside `CC-LAB-0058`'s prose, not a second
  `CC-LAB-0056` entry).

### Wave A1 (conditional — only exists if A0 finds real remaining scope; do not assume it will run)

If A0 confirms Layer A is closed (the expected outcome), **skip this wave
entirely** — there is nothing to dispatch here. If A0 finds real remaining
pages, they become G7…Gn lanes sized like G1–G6 (S ≈ 1–2 pages/no shared
module, M ≈ needs a small shared module or a stored pair, L ≈ touches a
genuinely shared file like `lab/safety_matrix.yaml` and must be the sole
lane touching it that wave), reserving `CC-LAB-0063` onward (**not** `0060`
— T1, T2, and A2 below already claim `0060`–`0062`; an earlier draft of this
plan had this wrong).

**T1 — Tier1 conformance-suite live wiring** *(does not depend on A0/A1 — dispatch independently)*
- Reserved: `CC-LAB-0060`
- Scope: `fuzzlab/labgen/conformance/tier1.py` + `tests/test_labgen_conformance_tier1.py`.
  Currently `"[design — not exercised against a live app/DB]"`; this lane
  wires it against a real in-process app+DB (following the `php_laravel`
  live-boot proof precedent already established at `CC-LAB-0054` — a
  synthetic, in-sandbox Laravel/SQLite boot, **not** the real lab target) for
  whichever stacks are ready. This stays inside the offline/lab-only scope
  and does not require `--authorized`: it never touches the real,
  loopback-only Ryder's Puppy Fort Factory target. Scoped to Layer A's 13
  already-decided pages — does not need to wait on A0/A1.
- File ownership: `tier1.py` + its own tests only. Does not touch `tier2.py`
  or any shared conformance fixtures module without coordinating with T2
  (see below).

**T2 — Tier2 conformance-suite live wiring** *(does not depend on A0/A1 — dispatch independently)*
- Reserved: `CC-LAB-0061`
- Scope: same pattern as T1 but `fuzzlab/labgen/conformance/tier2.py` +
  `tests/test_labgen_conformance_tier2.py`. Same offline/in-sandbox scope and
  safety posture as T1.
- Overlap / sequencing risk: if T1 and T2 share a conformance test-harness
  fixture module (verify before dispatch — not confirmed by the research
  pass), one of them must own that shared file for the wave; otherwise they
  are file-disjoint and can run alongside each other and alongside T1.

### Wave A2 (capstone — gated on Wave A1 if it exists, otherwise on A0 confirming closure)

**A2 — Byte-identical full-manifest reproduction (Phase-0 exit criterion)**
- Reserved: `CC-LAB-0062`
- **Scope, resolved via D-open-1 (v3 had left this an open question — round 3
  review correctly pointed out A0 already answers it two sections earlier)**:
  `docs/LAB_PHASE_0_PLAN.md`'s original "~30-page" exit-criterion wording
  predates the Layer A/B split and is superseded by D-open-1, which directly
  answers this exact question ("does retiring the fixture require
  reproducing Layer B? No"). A2's byte-identical scope is therefore **Layer A
  only** (the 16 `PFF-` cases / 13 non-exempt, non-deferred pages) — not the
  full ~30-page app. If a later decision reopens D-open-1, re-check this
  scope before dispatching.
- **Checkable gate condition**: every Layer-A `CC-LAB-00NN` entry (G1–G6,
  plus any A1 lanes if they exist) is present and marked done in
  `docs/components/01-target-lab/change-control.md`, and the manifest diff
  tool reports zero remaining unmigrated Layer-A pages.
- This lane is also the natural place to close out Phase 0 in
  `docs/DECISIONS_AND_ROADMAP.md` and `docs/ARCHITECTURE.md`'s phase-status
  table once it passes.

---

## Lane group B — UI / diagnostics

**Correction from v2: do not reinvent this lane map.** The repo already has
`docs/UI_IMPLEMENTATION_PLAN.md` — "fully task-broken-down with a parallel
lane map," locked build decisions D1–D5, already change-controlled starting
at `CC-UI-0023` (the plan document itself), and a wave map sized for exactly
this kind of concurrent dispatch. v2's Wave B0/B1 (an invented "R1 route-split" prerequisite plus
R2/R3/ML-tab/metric_series/store-exploration lanes) covered the same ground
less precisely and used a lane label (`B0`) that collides with that document's
own `B0` (a different, real lane — the `metric_series` migration). **Use
`docs/UI_IMPLEMENTATION_PLAN.md`'s own lane map and lane names directly**;
this plan's only added value here is the pre-assigned bookkeeping-number
layer, below.

### Wave 0 (per `UI_IMPLEMENTATION_PLAN.md` §4 — dispatch now, no gate)

**U0 — MPA routes + asset split** *(the serialization-breaker; one agent, not parallelized)*
- Reserved: `CC-UI-0025`
- Scope: exactly as specified in `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U0).
  This is the one lane every Wave-1 UI lane depends on — keep it a single
  agent to avoid self-conflict, per that document's own guidance.

**B0 — `metric_series` table + emitters** *(backend-only; no UI files; independent of U0)*
- Reserved: `CC-CORE-0018` (table/migration in `core/store.py`; current
  confirmed highest is `CC-CORE-0017`) — plus one number per emitter
  sub-lane, each in its own component:
  - GBT/logistic emitter → `CC-ML-0009`
  - Bandit-loop emitter → `CC-SCHED-0005` (current confirmed highest is
    `CC-SCHED-0004`, in `docs/components/08-payload-scheduler/change-control.md`)
  - Coverage-frontier emitter → `CC-FUZZ-0021` (after C1's `CC-FUZZ-0019` and
    D0a's `CC-FUZZ-0020` — see Lane group B's D0 entry for the full sequence;
    verify no other lane claimed it first) — **see the B0/C1 file-overlap
    risk below before dispatching this specific sub-lane**
  - `MutationSearch` reward/novelty emitter → `CC-MUT-0011` (after C1's
    `CC-MUT-0009` and D0a's `CC-MUT-0010`)
- **Sub-lane sequencing, made explicit**: per `docs/UI_IMPLEMENTATION_PLAN.md`
  §3 (B0, line 284), it's "table first, **then** one emitter per component in
  parallel" — the migration landing in `core/store.py` is a real serial
  sub-gate, not a fifth parallel piece. Treat B0 as **Wave 1a (table)** →
  **Wave 1b (4 emitters, parallel)** within Wave 1, not five simultaneous
  pieces from the start — see the wave-summary table's footnote.
- **File-overlap risk: B0's coverage-frontier emitter vs. C1's M8-wiring.**
  Both touch `fuzzlab/greybox/run.py`: C1 wires mutation variants into the
  same attempt/summary loop (`run.py`'s `_record_metric(...)` calls and the
  main run loop, roughly lines 165–259) that a coverage-growth
  `metric_series` emitter would naturally hook into. **Do not run these two
  sub-lanes as truly simultaneous edits to `run.py`** — either serialize
  B0's coverage-frontier emitter after C1 lands, or have the two lanes
  coordinate explicitly on disjoint functions within that file before
  dispatch. This was missed in v3 and is a real same-wave, same-file
  collision risk, not a hypothetical one.
- Scope: otherwise exactly as specified in `docs/UI_IMPLEMENTATION_PLAN.md`
  §3 (B0), including its resolved WAL/`open_store()` concurrency design —
  this plan's addition is giving each sub-lane its own reserved number and
  flagging the two risks above that the source document doesn't itself
  need to address (it wasn't written with C1 in mind).

**~~X0 — Register `lab-generate` in the launcher~~ — already done, drop from dispatch.**
Verified directly against `docs/components/12-diagnostics-and-ui/change-control.md`:
its actual top entry is `CC-UI-0024` — "Lane X0: register `lab-generate` in
the launcher (own group)," dated 2026-09-22, landed in
`fuzzlab/web/commandspec.py` (`_load_labgen` loader, `_REGISTRY` entry,
`group="Lab / authoring"`) with matching tests in
`tests/test_web_commandspec.py`. `docs/UI_IMPLEMENTATION_PLAN.md` itself was
never updated to mark X0 done, which is what caused this plan (through v4)
to still list it as a Wave-0 lane to dispatch. **Do not dispatch X0** —
correspondingly, `CC-UI-0024` (not `0023`) is the real current-highest UI
number, and `CC-UI-0025` (U0, below) is still correctly the next-free one.

**U6 — Control-plane hardening**
- Reserved: `CC-UI-0026`
- Scope: exactly as specified in `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U6).
  Shares `app.py` with U0 — land with or immediately after U0, per that
  document's own note, not fully parallel with it.

### Wave 1 (per `UI_IMPLEMENTATION_PLAN.md` §4 — gated on U0 landing)

**U1 — Overview dashboard**
- Reserved: `CC-UI-0027`

**U2 — Findings workbench** *(the R2 "Findings workbench" item from the original backlog)*
- Reserved: `CC-UI-0028`

**U3 — Proxy workbench rebuild** *(the R3 "Proxy rebuild" item from the original backlog)*
- Reserved: `CC-UI-0029` + `CC-PROXY-0018` (after D0a's `CC-PROXY-0017` —
  D0a is Wave 1a, dispatched before this Wave-2 lane)
- Note the safety posture: proxy/desync tooling stays default-off and
  lab-only per CLAUDE.md; this lane must not flip that default (also
  promoted to **Known risks** below — easy to miss on a skim of just the
  lane list).

**U4 — ML tab**
- Reserved: `CC-UI-0030` + `CC-ML-0010` (after B0's GBT/logistic emitter
  claims `CC-ML-0009` above — verify ordering at dispatch time)
- Also needs D2 (charting library, already resolved: uPlot 1.6.32) — no
  further research gate.

**U5 — Diagnostics + store explorer** *(covers both the "metric_series tab" and "Datasette-style store exploration" items from the original backlog — they're one lane per the authoritative plan, not two)*
- Reserved: `CC-UI-0031`
- Enriched by B0 landing but not blocked by it, per that document.

All five Wave-1 lanes share `docs/components/12-diagnostics-and-ui/`
bookkeeping files — follow the **merge protocol** above.

### D0 — `--dry-run` CLI flag *(not part of UI_IMPLEMENTATION_PLAN.md's lane map — a separate, smaller item; splits into two sub-lanes to reclaim parallelism)*
- **Scope, precisely**: the web UI already ships a dry-run preview
  (`POST /api/launch/dry-run` in `fuzzlab/web/app.py` + `web/runner.py`,
  shipped as `CC-UI-0013`/`CC-UI-0015`, both done) — "plans and reports the
  exact argv/display, sends nothing." **Do not rebuild that.** The actual
  remaining gap, per `docs/ARCHITECTURE.md`'s pending list, is a **CLI-level**
  `--dry-run` flag on the plain CLI entry points for headless use outside the
  web UI. `fuzzlab/cli.py` itself does no argparse — it's a thin string-
  dispatch shim that forwards args unchanged to each tool's own module
  (`greybox_cli.py`, `mutation/cli.py`, etc.), each with its own
  `build_parser()`/`main()`. So the flag has to be added **per tool module**,
  not in one shared place.
- **D0a — non-greybox tools** *(dispatch in Wave 1a, file-disjoint from C1;
  a single change touching six commands across five other components — each
  gets its own reserved number, per PA-0031, not just a UI one)*
  - Reserved: `CC-UI-0032` (if surfaced/documented through the web UI) +
    `CC-CRAWL-0007` (`crawl`, current highest `CC-CRAWL-0006`) +
    `CC-AUD-0015` (`audit`, current highest `CC-AUD-0014`) +
    `CC-FUZZ-0020` (`fuzz` + `auto` — both land in the FUZZ component; one
    entry covers both since it's one lane/commit) + `CC-MUT-0010`
    (`mutate-run`) + `CC-PROXY-0017` (`proxy`).
  - **Numbering note**: because D0a is Wave 1a (dispatched alongside C1) but
    touches FUZZ/MUT/PROXY, it slots in *ahead of* Wave 1b's B0 emitter
    sub-lanes and Wave 2's U3 in those components' sequences — this shifted
    several numbers from earlier drafts of this plan. The full FUZZ sequence
    is now C1=`0019` → D0a=`0020` → B0's coverage-frontier emitter
    (Wave 1b)=`0021` → D0b (Wave 2)=`0022` → C2 (Wave 3, conditional)=`0023`.
    The MUT sequence is C1=`0009` → D0a=`0010` → B0's `MutationSearch`
    emitter (Wave 1b)=`0011`. The PROXY sequence is D0a (Wave 1a)=`0017` →
    U3 (Wave 2)=`0018`. **Re-verify this ordering at dispatch time** — if
    lanes fire in a different order than this plan assumes, re-derive the
    next-free number per component rather than trusting these blindly (see
    Known Risks).
  - Scope: add `--dry-run` to every CLI entry point **except**
    `fuzzlab/greybox/greybox_cli.py` — `crawl`, `audit`, `fuzz`,
    `mutate-run`, `proxy`, `auto`. Reuse the web dry-run's plan/report logic
    rather than reimplementing it. None of these touch the files C1 (Wave
    C1, below) is editing, so this sub-lane needs no *file* gate — only the
    numbering ordering above.
- **D0b — `greybox-run --dry-run`** *(sequenced after Wave C1 — genuine file overlap)*
  - Reserved: `CC-FUZZ-0022` (see the renumbered FUZZ sequence above).
  - Scope: same flag, but on `fuzzlab/greybox/greybox_cli.py`'s parser/
    `main()` specifically — the one entry point that **does** overlap with
    **M8-wiring** (Wave C1), which also edits that module's run loop. Treat
    as sequenced after Wave C1 lands, not a same-wave parallel lane; this is
    the only piece of D0 that needs a *file* gate (as opposed to D0a's
    numbering-order-only dependency).

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
  attempt loop (confirmed: no mutation/variant references in
  `fuzzlab/greybox/run.py` or `fuzzlab/greybox/greybox_cli.py`). This lane's
  concrete deliverable: wire accepted mutation variants from the mutation
  engine into the **main harness's** attempt path (the code path
  `greybox-run` uses), not just the standalone `mutate-run` entry point.
  T8.7's on-host exit criterion stays out of scope here.
- This lane, not lane group B's `D0b` dry-run sub-lane, is the primary owner
  of the fuzzer's attempt-path files for this wave — see the D0 note above.
  `CC-FUZZ-0019` belongs to this lane only. The full FUZZ sequence, in
  dispatch order, is: this lane (`0019`) → D0a (`0020`, Wave 1a, no file
  overlap — just claims the next number) → B0's coverage-frontier emitter
  (`0021`, Wave 1b) → D0b (`0022`, Wave 2) → C2/M10 (`0023`, Wave 3,
  conditional). Verify no collision at dispatch time regardless.

### Wave C2 (conditional — do not dispatch until a human/orchestrator confirms scope)

**M10 offline slice — hook/interface layer against a stub coverage source**
- Reserved (on confirmation): `CC-CORE-0019` (after B0's table/migration
  claims `CC-CORE-0018` above) + `CC-FUZZ-0023` (last in the FUZZ sequence —
  see C1's entry above — verify ordering at dispatch time).
- Scope: `fuzzlab/greybox/confirm.py` already holds the pure decision logic
  (`docs/PHASE_3_PLAN.md` T3.6/T3.7); both `docs/components/02-core-library/change-control.md`
  and `docs/components/07-fuzzing-harness-and-oracle/change-control.md` note
  folding M10 into `Oracle.confirm` with a per-candidate sink line as a
  pending follow-up. The offline-buildable slice would be the hook/interface
  layer wired against a **stub** coverage source (no live-host coverage
  collector).
- **Gate**: there is no "in-progress re-audit" findable in this repo — a
  repo-wide search found nothing matching that description. The gate is
  therefore not a checkable "wait for the audit to finish" condition.
  **Do not dispatch C2 until a human (or a dedicated scoping lane, run the
  same way as A0) explicitly determines and documents that an
  offline-buildable M10 slice exists** — this needs a scoping decision
  first, not a wait. If/when confirmed, this lane touches the same
  `Oracle.confirm` / oracle pipeline files as M8-wiring (Wave C1) — serialize
  C2 after C1, don't run them in the same wave even once C2 is unblocked.

---

## Wave summary (max parallelism per wave)

| Wave | Lanes that can run concurrently | Gate to enter this wave |
| --- | --- | --- |
| 1a | A0 (Layer-A reconciliation, small/fast) · T1 · T2 · U0 · **B0-table** (the `metric_series` migration only) · U6 (lands with/right after U0) · C1 (M8-wiring) · **D0a** (`--dry-run` on every CLI entry point except `greybox_cli.py`) | None — all offline-buildable now (X0 dropped — already shipped as `CC-UI-0024`) |
| 1b | **B0's 4 emitter sub-lanes** (GBT/logistic, bandit-loop, `MutationSearch`, coverage-frontier) | B0-table merged (per `UI_IMPLEMENTATION_PLAN.md`'s "table first, then emitters"); **the coverage-frontier emitter specifically also waits on C1** (real `greybox/run.py` file overlap — see Lane group B) |
| 2 | UI Wave 1 (U1, U2, U3, U4, U5 — once U0 lands) · **D0b** (`greybox-run --dry-run`, once C1 lands) · A1 G7…Gn lanes (only if A0 found real remaining scope — expected not to exist) | U0 merged (for UI Wave 1); C1 merged (for D0b); A0 confirms scope exists (for A1, exception path) |
| 3 | A2 byte-identical manifest capstone (Layer-A scope, per D-open-1) · C2 M10 offline slice (only if scoping lane/human confirms) | A1 merged if it existed, else A0's closure confirmed (for A2); explicit scoping confirmation + C1 merged (for C2) |

Wave 1a has up to **7 concurrent lanes** (A0, T1, T2, U0, B0-table, C1, D0a —
U6 lands right behind U0 rather than fully parallel with it; X0 dropped, see
below). Wave 1b adds B0's 4 emitter sub-lanes once the table merges (3 of
them immediately; the coverage-frontier one waits on C1 too). The largest
single fan-out is Wave 2's five UI lanes (U1–U5), landing together once U0
merges.

## Known risks to flag before dispatch (per MULTI_AGENT_ORCHESTRATION.md — flag, don't silently resolve)

- **X0 ("register `lab-generate` in the launcher") is already done** —
  confirmed as `CC-UI-0024` in `docs/components/12-diagnostics-and-ui/change-control.md`,
  landed in `fuzzlab/web/commandspec.py` with matching tests.
  `docs/UI_IMPLEMENTATION_PLAN.md` still lists it as a lane because that
  source document was never updated to mark it done — do not dispatch X0,
  and don't trust that document's lane list as a completion signal without
  cross-checking the actual change-control log (this was missed through v4
  of this plan).
- **U3's dual-use safety posture**: proxy/desync tooling stays default-off
  and lab-only per CLAUDE.md; U3 (Proxy workbench rebuild) must not flip
  that default. Easy to miss if only skimming this risk list — also stated
  inline in U3's own entry.
- A0 may find nothing to do (expected outcome) — don't treat A1 as guaranteed
  work; confirm before allocating agents to it.
- Unconfirmed shared conformance-harness fixture file between T1 and T2 —
  verify before dispatch.
- **B0's coverage-frontier emitter and C1 (M8-wiring) both edit
  `fuzzlab/greybox/run.py`'s attempt/summary loop.** Don't dispatch these as
  truly simultaneous edits — serialize the emitter after C1, or have the two
  lanes agree on disjoint functions within the file before dispatch (see
  Lane group B's B0 entry).
- **D0a touches five components (CRAWL, AUD, FUZZ, MUT, PROXY) beyond
  UI — each now has its own reserved number** (`CC-CRAWL-0007`,
  `CC-AUD-0015`, `CC-FUZZ-0020`, `CC-MUT-0010`, `CC-PROXY-0017`); an earlier
  draft of this plan only reserved a UI number for D0a, which would have let
  it collide with B0's/U3's numbers in those same components. Fixed, but
  flagging since it's the kind of gap PA-0031 exists to prevent.
- The FUZZ-number sequencing depends on dispatch order matching this plan's
  assumed order: C1 (`CC-FUZZ-0019`) → D0a (`CC-FUZZ-0020`) → B0's
  coverage-frontier emitter (`CC-FUZZ-0021`) → D0b (`CC-FUZZ-0022`) → C2/M10
  (`CC-FUZZ-0023`, conditional). The MUT sequence is C1 (`CC-MUT-0009`) →
  D0a (`CC-MUT-0010`) → B0's `MutationSearch` emitter (`CC-MUT-0011`). The
  PROXY sequence is D0a (`CC-PROXY-0017`) → U3 (`CC-PROXY-0018`). If any of
  these lanes dispatch out of the order this plan assumes, re-verify the
  next-free number per component rather than trusting the numbers above
  blindly.
- An earlier draft of Wave A1's exception-path text incorrectly said its
  G7…Gn lanes (if they ever dispatch) should reserve `CC-LAB-0060` onward —
  that collides with T1/T2/A2, which already claim `0060`–`0062`. Fixed to
  `CC-LAB-0063` onward; re-verify at dispatch time regardless, per PA-0031.
- M10's offline-buildability is an open scoping question, not yet confirmed
  by anyone — Wave C2 stays provisional until a scoping lane or a human
  explicitly resolves it.
- Same-wave, same-component concurrent edits to `change-control.md` /
  `requirements.md` (UI's Wave 0/1 lanes, and any A1 lanes if they exist)
  need the **merge protocol** above applied at integration time, not assumed
  away.
