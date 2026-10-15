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

## Definition of done — the bookkeeping checklist (MANDATORY)

Before you consider **any** change complete, do all of these that apply. This is the part
that gets forgotten; treat it as part of the change, done in the same commit — not "later".

1. **Follow the preventive-action rules.** Read `docs/PREVENTIVE_ACTIONS.md` *before and
   during* the change and comply with every rule (PA-0001…). This list is authoritative
   and must be followed — it is not advisory.
2. **Tests, verified through the harness.** Add/adjust tests for the change, commit, then
   verify with `scripts/verify_change.py --base <ref>` (`--full` for the whole suite) —
   never a hand-picked list of "relevant" tests. It checks the committed HEAD in a
   detached worktree (refusing a dirty tree), selects every test file that imports a
   changed `fuzzlab` module plus every whole-package guard and every changed test, and
   runs one pytest at a time with `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`, live-boot and
   timing files in a serial pass. Keep it green; state its file count and pass/fail/skip
   counts where you report the change. A failing test is root-caused, never called
   "flaky".
3. **CHANGELOG.md** — add one dated, high-level line: *what changed and why* (reference the
   commit/CC IDs where useful). Required for every change.
4. **Component change-control** — for each affected component, add a full
   `docs/components/<n>-*/change-control.md` entry (append-only; all required fields). See
   `docs/components/README.md`. A single change may yield one CHANGELOG line and several
   change-control entries.
5. **If you fixed a bug** (any code defect — failing test, wrong result, crash, regression,
   security flaw), do the full bug protocol below — not just a code fix. **A new PA names
   its enforcement** in its last line: `- Enforced by: tests/<file>.py::<test>[, …]` (a
   test that fails when the rule is broken; prefer an AST or whole-package guard proven
   on a synthetic offender) or `- Enforced by: none — <reason>`.
   `tests/test_pa_enforcement.py` checks every PA has exactly one such line and that each
   named test exists.
6. **Keep the specs current.** If a component's behavior, scope, interfaces, or data
   contracts changed, update that component's living **`requirements.md`** in place (add
   new requirements with stable IDs; mark superseded ones). If the project structure,
   components, dependencies, or the store-as-contract changed — or the build status of a
   phase advanced — update **`docs/ARCHITECTURE.md`**. These are living documents that must
   always reflect current truth, not just history.

7. **A fix to a shared primitive** (a mechanism listed in `docs/SHARED_PRIMITIVES.md`, or
   one that should be) is made in its owner, **sweeps every caller** of the owner and
   every consumer that waits on or reads what changed (not only the path the bug came
   from), and updates `docs/SHARED_PRIMITIVES.md` in the same change (new owner, guard or
   row). `tests/test_shared_primitives.py` checks the table.
8. **Measure before design.** A design or fix that relies on how a real target or the
   real browser behaves cites a measurement of it (see
   `docs/MULTI_AGENT_ORCHESTRATION.md` §7).

If a step does not apply, it is because the change genuinely doesn't touch it — not because
it's inconvenient. When in doubt, do it.

## The process artifacts (where each lives, when it's required)

| Artifact | File(s) | Required when | Policy |
| --- | --- | --- | --- |
| **Changelog** | `CHANGELOG.md` | every change | one high-level dated line; newest on top |
| **Change control** | `docs/components/<n>-*/change-control.md` | every change to a component | full controlled entry, **append-only**; see `docs/components/README.md` |
| **Requirement spec** | `docs/components/<n>-*/requirements.md` | when a component's purpose/scope/FRs/NFRs/interfaces/contracts change | **living doc, edited in place** to current truth; new requirements get stable IDs |
| **Architecture** | `docs/ARCHITECTURE.md` | when structure, components, dependencies, contracts, or a phase's build status change | **living doc, kept current** |
| **Error log** | `ERROR_LOG.md` | anything that broke and was fixed (bugs, deploy/env failures) | one dated entry: symptom / root cause / remediation / status |
| **Bug report** | `docs/bugs/BUG-NNNN-*.md` | every **code** defect | full RCA; see `docs/bugs/README.md` |
| **Preventive actions** | `docs/PREVENTIVE_ACTIONS.md` | one (or more) per bug report | distilled rule ending with its `- Enforced by:` line; **must be read and followed on every change** |
| **Shared primitives** | `docs/SHARED_PRIMITIVES.md` | when a one-implementation mechanism is added, moved or changed | living table: owner + guard test per mechanism |

Note the split: `change-control.md` is the **append-only history** of a component; its
`requirements.md` is the **living specification** of what the component is now. A change
that alters behavior updates both — a new change-control entry *and* the requirements
spec edited in place. Likewise `docs/ARCHITECTURE.md` is kept current, while the
`CHANGELOG.md` line records that it changed.

## Bug workflow (when you fix a code defect)

A single bug produces the three linked artifacts below (ERROR_LOG ↔ BUG-NNNN ↔ PA-NNNN),
with a recurrence review (step 3) gating the preventive action:

1. **`ERROR_LOG.md`** — one dated line (symptom / root cause / remediation / status).
2. **`docs/bugs/BUG-NNNN-<slug>.md`** — the rigorous RCA: description, where encountered,
   what it caused to fail, what the defect was, root-cause analysis (e.g. Five Whys ending
   in the root cause), corrective action (reference the commit / CC entry), then the
   recurrence review and preventive action below. See `docs/bugs/README.md` for the full
   required contents.
3. **Recurrence review (before deciding the preventive action).** Review the other
   `docs/bugs/` logs **and** `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of the
   same bug, or a different bug with the same root cause. If you find one, first write a
   **prior-preventive-action failure analysis** in the bug doc — why the earlier PA did
   not prevent this recurrence (too narrow / wrong layer / not followed / not enforced),
   naming the prior BUG-NNNN and PA-NNNN — and only then decide the new PA, which must fix
   that failure mode and **strengthen or supersede** the prior PA, not restate it.
4. **`docs/PREVENTIVE_ACTIONS.md`** — add the preventive rule(s) derived from the root
   cause (and, on a recurrence, from step 3), each ending with its `- Enforced by:` line,
   and then **sweep the codebase for other instances of that bug class and remediate
   them** (that sweep is itself a rule, PA-0002). For a shared primitive, sweep by
   primitive (every caller), not by symptom path.

The three cross-reference each other (ERROR_LOG ↔ BUG-NNNN ↔ PA-NNNN). Do not stop at the
ERROR_LOG line — that is the exact corner that has been cut before.

## Numbering & conventions

- Change-control IDs: `CC-<CODE>-NNNN`, per-component, newest first. Component codes are in
  the index in `docs/components/README.md` (LAB, CORE, SESS, CRAWL, AUD, IND, FUZZ, SCHED,
  MUT, ML, PROXY, UI, PLUG). Find the next number from the top of that component's log.
- Bug IDs: `BUG-NNNN`, in discovery order, highest = newest. Next = highest existing + 1.
- Preventive-action IDs: `PA-NNNN`, appended to `docs/PREVENTIVE_ACTIONS.md`.
- Requirement IDs (in each `requirements.md`): `FR-<CODE>-N` (functional) and
  `NFR-<CODE>-<name>` (non-functional), stable once assigned — add new ones rather than
  renumbering; mark a requirement superseded instead of deleting it.
- Logs that are **append-only**: component change-control logs, `docs/bugs/`. `CHANGELOG.md`
  and `ERROR_LOG.md` are newest-on-top running logs. **Living docs edited in place**:
  `requirements.md` files and `docs/ARCHITECTURE.md`. `docs/PREVENTIVE_ACTIONS.md` grows
  (rules are not deleted).
- **Governance/process docs** (this file, top-level `README.md`, `docs/` process READMEs)
  are project-level: record such changes in `CHANGELOG.md`. Component change-control is for
  the 13 architecture components only.

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
- When the goal stalls (6 h without improvement), stop dispatching, report and wait for
  the user. "Keep going" instructions do not cover a stall.
- The other triggers that stop an item until the user writes:
  - a third review round;
  - work the session opened itself;
  - a second bug spawned by one item's fixes;
  - an item over its 4 h budget;
  - a fourth concurrent item, or two items on one file.
- Status answers lead with the `report`. After a context compaction, compare progress
  with the goal before dispatching; a summary's task list is not authorisation.

## Canonical policy docs (the detail behind this summary)

- `docs/components/README.md` — change-control policy + the CHANGELOG relationship + entry
  template + component index.
- `docs/bugs/README.md` — bug-investigation policy and required contents.
- `docs/PREVENTIVE_ACTIONS.md` — the rule list to follow (read it every session).
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
