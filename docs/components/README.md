# Component documentation

See `CLAUDE.md` for the full change process this fits into (bookkeeping, the living specs,
the bug protocol, and the mandatory preventive-action rules).

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
2. the change-control log of **each affected component** — a full controlled entry
   with all the required fields below.

Neither substitutes for the other. If a change touches more than one component,
add an entry to each affected component's `change-control.md`. If a change alters
the project architecture, also update `docs/ARCHITECTURE.md` (its maintenance
rule).

## Pre-change review gate (required, per direct instruction, 2026-09-22)

**The change-control entry is now written *before* the change, not alongside it,
and the change does not start until the entry is reviewed and agreed.** This
reverses this section's own prior wording ("do this as part of making the change,
not afterward") for a substantive code/architecture change — a documentation-only
correction, a typo fix, or routine corpus-collection bookkeeping does not need this
gate; a change to component code, schemas, or generator behavior does.

The process:

1. **Draft the change-control entry first** — `CC-<CODE>-NNNN`, every required
   field (Change, Impact, Risk, Deliverables, Effectiveness left `pending`),
   describing the change about to be made, grounded in the actual codebase (real
   file paths, real function/class names, a real LOC estimate where feasible) —
   not aspirational or vague.
2. **Spawn 2 independent reviewer agents** against the draft, each checking its
   **accuracy** (does it correctly describe the current code/architecture it
   claims to change?) and its **adequacy** (does it actually cover the
   change's real scope, risk, and impact — nothing hand-waved)?
3. **Revise until all 3 parties agree** (the two reviewer agents plus the
   agent proposing the change) — a 2/3 split is not enough; every raised
   concern gets addressed in a revision, then re-reviewed.
4. **Only once 3/3 agree does implementation begin.** The agreed entry is
   committed as the change's change-control record; the code change that
   follows should match what the entry described (a real divergence found
   during implementation gets reflected back into the entry before the
   change is considered done — this is a living draft until 3/3 agreement,
   append-only once landed like every other change-control entry).

This gate is scoped to substantive changes; it does not apply retroactively to
already-landed entries, and does not change the `requirements.md`/`CHANGELOG.md`/
`docs/ARCHITECTURE.md` update rules above — those still land together with the
code once the gate has cleared.

**Change-control logs are append-only.** Add a new entry for every change; never
edit or delete an existing entry. All historical entries are kept as the record of
what was decided and when. When a change supersedes an earlier decision, say so in
the new entry (reference the superseded entry ID) rather than rewriting the old
one. The living requirement specifications (`requirements.md`) are updated in place
to reflect current truth; the change-control log is the immutable history behind
them.

## Required fields for every change-control entry

Every time a component changes, add an entry with all of these:

1. **ID and date** — `CC-<CODE>-NNNN`, newest first.
2. **Change** — outline what changed.
3. **Impact assessment** — effect on other components and on the project as a
   whole (name the components; note contract/interface changes).
4. **Risk assessment** — the risk level; if the risk is substantial, how it is
   mitigated, or a justification for accepting it.
5. **Deliverables** — the tasks the change requires, each with a completion
   status (`todo` / `in-progress` / `done`).
6. **Effectiveness** — assessed after the change lands: did it achieve its
   intent, with evidence. Left as `pending` until it can be judged.

## Entry template (copy for each change)

```
### CC-<CODE>-NNNN — <short title> (YYYY-MM-DD)
- Change:
- Impact (other components / project):
- Risk (level; mitigation or accepted-risk justification):
- Deliverables:
  - [ ] <task> — <status>
- Effectiveness (assessed <date> or pending):
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
