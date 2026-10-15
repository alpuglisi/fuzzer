# CLAUDE.md — read first, every session

Guidance for any AI agent (and any contributor) working in this repository. It is
loaded automatically at the start of a session. **Do not skip the bookkeeping in this
file** — it is part of every change, not optional cleanup, and it has been overlooked
before (see `docs/bugs/` for what that costs).

## What this project is

`fuzzlab` — a modular, **lab-only** injection security-testing toolkit and research
platform, exercised against a self-hosted, deliberately vulnerable app (Ryder's Puppy
Fort Factory). See `README.md` and `docs/ARCHITECTURE.md`.

## Safety (non-negotiable)

- **Lab-only, authorized-only.** Run tools only against the local lab you own. The target
  is loopback-only and must never be exposed; anything that sends traffic requires an
  explicit `--authorized` flag; nothing runs against the target until asked (decision
  D11). Dual-use tooling (proxy, desync/smuggling, WAF) stays default-off and lab-only.
- Credentials live in the OS keyring / credential store (D12) — never commit secrets.

## Definition of done (MANDATORY)

The operating policy is **`docs/QUALITY_POLICY.md`** (owner-adopted 2026-10-15 as a
bounded pilot, D70). It replaces the earlier rule that every change reads the whole
preventive-action register and that every defect writes a new PA. Before you consider
**any** change complete, do each of these that applies, in the same commit — not "later".

1. **Define and classify.** State the observable outcome, the acceptance check and the
   scope. Classify the risk (QUALITY_POLICY §2: administrative, low, medium or high).
   Give every commit `Change-Type:` and `Risk:` trailers; the Stop hook
   `.claude/hooks/check_bookkeeping.py` checks them.
2. **Follow the affected controls.** Read the control families in QUALITY_POLICY §6
   that the change touches, and their rows in `docs/quality/CONTROL_INDEX.md`. A row's
   *current requirement* wins over a historical PA's wording.
   `docs/PREVENTIVE_ACTIONS.md` is the immutable history behind them; it is not
   per-change reading.
3. **Verify by risk class.**
   - A documentation-only change runs no pytest and is pushed directly (owner, F-058).
   - Otherwise, commit, then run `scripts/verify_change.py --base <ref>`. It checks the
     committed HEAD in a detached worktree. It runs the tests importing a changed
     `fuzzlab` module, the changed tests, and the guard tests of every whole-package
     guard, with `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`.
   - Before every merge, run `--full` on the candidate, and the coordinator reads the
     diff.
   - Never verify with a hand-picked list of tests.
   - Report the file count and the pass/fail/skip counts. `manifest.json` holds the
     per-file evidence.
   - A failing test is root-caused, never called "flaky".
4. **CHANGELOG.md:** one dated, high-level line on what changed and why.
5. **Component change-control.** Write one full controlled entry, in the primary affected
   component (`docs/components/<n>-*/change-control.md`, fields in
   `docs/components/README.md`). Every other affected component gets a one-line entry
   that links to it. The logs are append-only.
6. **Defects (QUALITY_POLICY §4).**
   - An **ordinary defect** needs an `ERROR_LOG.md` entry (reproduction, correction,
     regression check, scope) and its regression test.
   - **Formal CAPA** applies to a significant escape, a recurring or systemic defect, a
     security or data-integrity event, or a failed control. It also needs a
     `docs/bugs/BUG-NNNN-*.md` report with a recurrence review. Correct the existing
     control and update its row in `docs/quality/pa_control_map.tsv`.
   - Add a new PA only for a mechanism no control covers. It ends with its
     `- Enforced by:` line (`tests/test_pa_enforcement.py`), and it gets a map row
     (`tests/test_quality_controls.py`).
7. **Keep the specs current.** When a component's behaviour, scope, interfaces or data
   contracts change, update its living **`requirements.md`** in place (stable IDs; mark
   superseded requirements). When structure, components, dependencies, the
   store-as-contract or a phase's build status change, update **`docs/ARCHITECTURE.md`**.
8. **A fix to a shared primitive** (one listed in `docs/SHARED_PRIMITIVES.md`, or one that
   should be) is made in its owner. It **sweeps every caller** and every consumer that
   waits on or reads what changed, and it updates `docs/SHARED_PRIMITIVES.md` in the same
   change (`tests/test_shared_primitives.py`).
9. **Evidence before design (QUALITY_POLICY R2, R3).** A design that relies on how a real
   target, runtime or browser behaves links the decisive evidence, or labels the premise
   *unverified* and tests it. A claim to fix a general capability passes the diagnostic
   regression *and* independently authored variations. One lab is never "works in any
   lab".

If a step does not apply, it is because the change genuinely doesn't touch it — not because
it's inconvenient.

## The process artifacts (where each lives, when it's required)

| Artifact | File(s) | Required when | Policy |
| --- | --- | --- | --- |
| **Quality policy** | `docs/QUALITY_POLICY.md` | read the affected families on every change | living operating policy (12 families, R1–R3) |
| **Control index** | `docs/quality/CONTROL_INDEX.md` (generated) | read the affected rows | from `pa_control_map.tsv` via `scripts/quality_index.py` |
| **Changelog** | `CHANGELOG.md` | every change | one high-level dated line; newest on top |
| **Change control** | `docs/components/<n>-*/change-control.md` | every change to a component | one full controlled entry in the primary component, one-line links elsewhere; **append-only** |
| **Requirement spec** | `docs/components/<n>-*/requirements.md` | when a component's purpose/scope/FRs/NFRs/interfaces/contracts change | **living doc, edited in place** to current truth; new requirements get stable IDs |
| **Architecture** | `docs/ARCHITECTURE.md` | when structure, components, dependencies, contracts, or a phase's build status change | **living doc, kept current** |
| **Error log** | `ERROR_LOG.md` | every defect fixed (and deploy/env failures) | one dated entry: symptom / root cause / remediation / status |
| **Bug report** | `docs/bugs/BUG-NNNN-*.md` | formal CAPA only (QUALITY_POLICY §4) | full RCA + effectiveness plan; see `docs/bugs/README.md`; append-only |
| **Preventive actions** | `docs/PREVENTIVE_ACTIONS.md` + `docs/quality/pa_control_map.tsv` | a new PA only for an uncovered mechanism | immutable history; every PA mapped to a family |
| **Shared primitives** | `docs/SHARED_PRIMITIVES.md` | when a one-implementation mechanism is added, moved or changed | living table: owner + guard test per mechanism |

`change-control.md` is a component's **append-only history**; its `requirements.md` is the
**living specification** of what the component is now. A change that alters behaviour
updates both.

## CAPA workflow (formal investigations only)

1. **`ERROR_LOG.md`** — one dated entry, as for every defect.
2. **`docs/bugs/BUG-NNNN-<slug>.md`** — description, where encountered, impact, the defect,
   root-cause analysis ending in the verified cause, corrective action, the systemic
   action, owner, due date and an effectiveness plan with a predeclared criterion. See
   `docs/bugs/README.md`.
3. **Recurrence review.** Check `docs/bugs/` and `docs/quality/CONTROL_INDEX.md` for the
   same mechanism. If a prior control failed, write why (too narrow, wrong layer, not
   followed, not enforced, proxy measure). Then **correct that control**, rather than
   appending a near-duplicate PA.
4. **Sweep by mechanism** across the affected surface, bounded by risk (PA-0002 as
   rewritten). Record serious unrelated findings as separate items; do not widen the
   fix.
5. **Close against the effectiveness criterion**, not against a green regression test
   alone; until relevant opportunities have been observed, the status stays provisional.

## Numbering & conventions

- Change-control IDs: `CC-<CODE>-NNNN`, per-component, newest first. Component codes are in
  the index in `docs/components/README.md` (LAB, CORE, SESS, CRAWL, AUD, IND, FUZZ, SCHED,
  MUT, ML, PROXY, UI, PLUG). Find the next number from the top of that component's log.
- Bug IDs: `BUG-NNNN`, in discovery order, highest = newest. Next = highest existing + 1
  across the pushed branches. On a collision, keep both and record an alias; never
  renumber history.
- Preventive-action IDs: `PA-NNNN`, appended to `docs/PREVENTIVE_ACTIONS.md` with a row in
  `docs/quality/pa_control_map.tsv` (then `scripts/quality_index.py`).
- Requirement IDs (in each `requirements.md`): `FR-<CODE>-N` (functional) and
  `NFR-<CODE>-<name>` (non-functional), stable once assigned — add new ones rather than
  renumbering; mark a requirement superseded instead of deleting it.
- Logs that are **append-only**: component change-control logs, `docs/bugs/`. `CHANGELOG.md`
  and `ERROR_LOG.md` are newest-on-top running logs. **Living docs edited in place**:
  `QUALITY_POLICY.md`, `requirements.md` files and `docs/ARCHITECTURE.md`.
  `docs/PREVENTIVE_ACTIONS.md` keeps every entry (IDs immutable); an entry's current
  status lives in the map.
- **Governance/process docs** (this file, top-level `README.md`, `docs/` process docs,
  `docs/QUALITY_POLICY.md`) are project-level: record such changes in `CHANGELOG.md`.
  Component change-control is for the 13 architecture components only.

## Multi-agent / multi-lane orchestration (when working via concurrent AI agents)

If you are an orchestrating session dispatching concurrent build lanes/sub-agents against
this repo: read `docs/MULTI_AGENT_ORCHESTRATION.md` before dispatching anything. In brief —
run independent lanes in parallel and never let an eligible one sit idle (eligible = within the progress triggers below), but never two
lanes on the same file without a planned merge order; always independently verify a
lane's work yourself before merging (`scripts/verify_change.py` on the committed tree,
read the diff, check bookkeeping — never trust a self-report alone); restrict to offline-buildable work
and flag (never silently build or skip) anything carrying genuine cross-component/
downstream risk or that you cannot actually verify in the current environment;
**pre-assign each concurrent lane its own bookkeeping numbers** before dispatch rather than
"claim the next free one" (`PA-0031`) — this is the single biggest source of avoidable
merge friction across concurrent lanes; and when your own instructions to a sub-agent
specify *how* a task must be done (not just what it must produce), require that sub-agent
to confirm which mechanism it actually used, and to stop and flag rather than silently
substitute if the specified one is unavailable.

**Progress governance (mandatory, hook-enforced; `PA-0141`..`PA-0147`, §8 of that doc).**
- Before the first dispatch, open a goal ledger with
  `scripts/orchestration_guard.py goal open`, using the user's own success metric,
  measured. Register every work item, and tag every dispatch with `[item: <ID>]`.
- Checkpoint the metric every 3 h of unattended work, and push the `report` to the user.
- When the goal stalls (6 h without improvement), treat it as a defect. Stop feeding the
  stalled work, investigate why the metric is not moving, fix that cause (the process
  included), and report to the user unasked. Busy is not building.
- Contact is not a decision (BUG-0156). A hold is lifted only by `decide --hold
  stall|budget|review|scope`, quoting the user's own words from a message after the hold
  began. It lifts only that hold. An extension adds hours or rounds; it never resets the
  spend or the stall clock. Renames (`--continues`) and close/reopen keep the history.
- The holds:
  - a third review round (a round = the requests sent between two work dispatches);
  - work the session opened itself;
  - an item over its cumulative budget (4 h by default);
  - a fourth concurrent item, or two items on one file.
- Two cases need the delivery owner's **disposition** (`item disposition`; R1), not the
  user: a second bug spawned by one item's fixes, and an experiment (an item with a
  `--hypothesis`) that exhausted its budget. Every feature item states its hypothesis.
- Status answers lead with the `report`, which leads with the metric and its
  unchanged-since time. After a context compaction, compare progress with the goal
  before dispatching; a summary's task list is not authorisation.

## The agent failure record (MANDATORY for AI agents)

`docs/claude_juicelab_failures.md` records every failure, wrong action and oversight by
the AI agent working in this repository. It is append-only. When you find something the
agent got wrong, did badly or overlooked (a regression it caused, a wrong diagnosis, a
broken rule, a lab-fitted design, a status that overstated progress), append an `F-NNN`
entry **in the same turn**, with what / evidence / impact / status. Do not wait to be
asked and do not soften earlier entries; correct one with a new entry. It supports the
owner's investigation after the Juice Shop work.

## Canonical policy docs (the detail behind this summary)

- `docs/QUALITY_POLICY.md` — the operating policy: risk route, defects vs CAPA, R1–R3, the
  twelve control families. `docs/quality/CONTROL_INDEX.md` — the PAs under each family.
- `docs/components/README.md` — change-control policy + the CHANGELOG relationship + entry
  template + component index.
- `docs/bugs/README.md` — CAPA investigation policy and required contents.
- `docs/PREVENTIVE_ACTIONS.md` — the immutable history of preventive actions (read a PA
  through its control family).
- `docs/SHARED_PRIMITIVES.md` — the one-implementation mechanisms, their owners and guards.
- `scripts/verify_change.py` — the verification harness (`--help`).
- `CHANGELOG.md` / `ERROR_LOG.md` — their own headers restate their format.
- `docs/DECISIONS_AND_ROADMAP.md` — settled decisions (D-numbers) and the phased plan.
- `docs/ON_HOST_RUNBOOK.md` — how to run the on-host (lab) activities.
- `docs/MULTI_AGENT_ORCHESTRATION.md` — multi-lane/multi-agent orchestration policy:
  parallelism, independent verification, pre-assigned bookkeeping numbers, delegation
  mechanism fidelity, and when to flag risk instead of proceeding autonomously.

If this summary and a canonical doc ever disagree, the canonical doc wins — and fix this
file to match.
