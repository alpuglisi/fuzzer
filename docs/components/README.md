# Component documentation

See `CLAUDE.md` for the full change process this fits into, and `docs/QUALITY_POLICY.md`
for the operating policy (risk route, defects vs CAPA, the control families).

Each primary component in `docs/ARCHITECTURE.md` has two documents in its folder
here:

- **`requirements.md`** — the component's requirement specification: purpose,
  scope, functional and non-functional requirements (with stable IDs),
  interfaces and data contracts, component dependencies, and acceptance criteria.
- **`change-control.md`** — the component's change-control log.

## How the component change-control log differs from the root CHANGELOG

The root `CHANGELOG.md` is a **high-level project history**: what changed and
why, across the whole project. The component change-control logs are
**lower-level and per-component**, and each entry is a controlled record with a
fixed set of assessments (below). A single project change may produce one root
CHANGELOG line and several component change-control entries.

## Update both logs on every change (required)

Every change updates **both** levels of log:

1. the root `CHANGELOG.md` — one high-level dated line (what changed and why); and
2. the change-control log of the **primary affected component** — one full controlled
   entry with the required fields below. Each other affected component gets a one-line
   entry that links to it (`see CC-<CODE>-NNNN`), so the impact is traceable without
   copying the narrative into every component.

If a change alters the project architecture, also update `docs/ARCHITECTURE.md` (its
maintenance rule).

## Review before and during the change (risk-based, adopted 2026-10-15, D70)

The review a change needs depends on its **risk class** (`docs/QUALITY_POLICY.md` §2).
The class is decided before the work starts and recorded in the entry and in the
commits' `Risk:` trailer.

| Class | Review |
| --- | --- |
| administrative / non-behavioural | owner self-check |
| low | the owner, or one reviewer |
| medium | one independent qualified reviewer (a domain specialist where needed) |
| high (safety, data integrity) | independent domain or security review before implementation, and again before release when the evidence changes |

This replaces the 2026-09-22 gate, which required two reviewer agents and 3/3 unanimous
agreement before any substantive change. That gate was not scaled by risk. Every
concern reset it, and stacked review rounds were a measured cause of delay (BUG-0141).
- **One combined design-and-code review per change** (owner, 2026-10-15). It returns one
  consolidated must-fix list, and a second round verifies those fixes. A third round
  means the scope or design needs clarifying, and the material concerns still open go to
  the owner.
- For uncertain capability work, give the reviewer the acceptance contract and the
  primary evidence, and ask for a counterexample (QUALITY_POLICY R2). Extra agents that
  share the author's assumptions are not independent evidence.
- For a substantive change, the entry is still drafted **before** the code, grounded in
  real file paths and functions. A divergence found during implementation is written
  back into the entry before the change is done.

**Change-control logs are append-only.** Add a new entry for every change; never
edit or delete an existing entry. All historical entries are kept as the record of
what was decided and when. When a change supersedes an earlier decision, say so in
the new entry (reference the superseded entry ID) rather than rewriting the old
one. The living requirement specifications (`requirements.md`) are updated in place
to reflect current truth; the change-control log is the immutable history behind
them.

## Required fields for every change-control entry

Every time a component changes, its primary component's entry has all of these (the
lean QC change record, `docs/QUALITY_POLICY.md` §7):

1. **ID and date** — `CC-<CODE>-NNNN`, newest first.
2. **Goal and acceptance** — the observable outcome, and the specific conditions that
   show it was met.
3. **Change** — outline what changed.
4. **Impact assessment** — effect on other components and on the project as a
   whole (name the components and consumers; note contract/interface changes).
5. **Risk** — the class (administrative/low/medium/high) with its consequence and
   exposure; for substantial risk, the mitigation or the accepted-risk justification.
6. **Hypothesis** — for uncertain work only: the prediction, the effort ceiling and the
   exit decision; and the evidence for each design-critical premise, or `unverified`
   (R2).
7. **Verification and review** — the `verify_change.py` evidence key / counts, and the
   reviewer with their disposition and the unresolved risk.
8. **Deliverables** — the tasks the change requires, each with a completion
   status (`todo` / `in-progress` / `done`).
9. **Rollback or recovery** — required for meaningful state changes.
10. **Effectiveness** — assessed after the change lands: did it achieve its intent,
    with evidence. Left as `pending` until it can be judged; control changes also state
    `control_status` (designed / implemented / qualified / operating-effective).

Entries written before 2026-10-15 use the earlier six fields; they are not rewritten.

## Entry template (copy for each change)

```
### CC-<CODE>-NNNN — <short title> (YYYY-MM-DD)
- Goal / acceptance:
- Change:
- Impact (other components / consumers / project):
- Risk (class; consequence and exposure; mitigation or accepted-risk justification):
- Hypothesis (uncertain work only; prediction, ceiling, exit; premise evidence):
- Verification / review (evidence key and counts; reviewer, disposition, residual risk):
- Deliverables:
  - [ ] <task> — <status>
- Rollback / recovery:
- Effectiveness (assessed <date> or pending; control_status where relevant):
```

A secondary component's one-line entry:

```
### CC-<CODE>-NNNN — <short title> (YYYY-MM-DD) — see CC-<PRIMARY>-NNNN
```

## Component index

| # | Component | Code | Folder |
| --- | --- | --- | --- |
| 1 | Target lab and ground truth | LAB | `01-target-lab/` |
| 2 | `core/` shared library | CORE | `02-core-library/` |
| 3 | Session manager | SESS | `03-session-manager/` |
| 4 | Crawler / spider | CRAWL | `04-crawler/` |
| 5 | Auditor / fetcher | AUD | `05-auditor/` |
| 6 | Indicator database and payload catalogs | IND | `06-indicator-db-and-catalogs/` |
| 7 | Fuzzing harness and oracle | FUZZ | `07-fuzzing-harness-and-oracle/` |
| 8 | Payload scheduler (bandit) | SCHED | `08-payload-scheduler/` |
| 9 | Mutation engine | MUT | `09-mutation-engine/` |
| 10 | ML components | ML | `10-ml-components/` |
| 11 | Intercepting proxy | PROXY | `11-intercepting-proxy/` |
| 12 | Diagnostics and UI | UI | `12-diagnostics-and-ui/` |
| 13 | Plugin system | PLUG | `13-plugin-system/` |
