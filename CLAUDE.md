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
2. **Tests.** Add/adjust tests for the change and run the suite (`pytest`); keep it green.
   State the pass/skip counts where you report the change.
3. **CHANGELOG.md** — add one dated, high-level line: *what changed and why* (reference the
   commit/CC IDs where useful). Required for every change.
4. **Component change-control** — for each affected component, add a full
   `docs/components/<n>-*/change-control.md` entry (append-only; all required fields). See
   `docs/components/README.md`. A single change may yield one CHANGELOG line and several
   change-control entries.
5. **If you fixed a bug** (any code defect — failing test, wrong result, crash, regression,
   security flaw), do the full bug protocol below — not just a code fix.
6. **Keep the specs current.** If a component's behavior, scope, interfaces, or data
   contracts changed, update that component's living **`requirements.md`** in place (add
   new requirements with stable IDs; mark superseded ones). If the project structure,
   components, dependencies, or the store-as-contract changed — or the build status of a
   phase advanced — update **`docs/ARCHITECTURE.md`**. These are living documents that must
   always reflect current truth, not just history.

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
| **Preventive actions** | `docs/PREVENTIVE_ACTIONS.md` | one (or more) per bug report | distilled rule; **must be read and followed on every change** |

Note the split: `change-control.md` is the **append-only history** of a component; its
`requirements.md` is the **living specification** of what the component is now. A change
that alters behavior updates both — a new change-control entry *and* the requirements
spec edited in place. Likewise `docs/ARCHITECTURE.md` is kept current, while the
`CHANGELOG.md` line records that it changed.

## Change-control gate — adversarial review before implementation (MANDATORY)

The change-control document (the `docs/components/<n>-*/change-control.md` entry for
each affected component, per the entry template in `docs/components/README.md`) must be
**written and completed before the change is implemented** — not drafted afterward to
match what was already built. Implementation only starts once the gate below passes.

1. **Draft the change-control entry(ies) first**, with all required fields filled in
   (Change, Impact assessment, Risk assessment, Deliverables, Effectiveness left
   `pending`) — before writing or editing any implementation code.
2. **Spawn two AI agents to adversarially review the draft.** Each reviews the
   document's **adequacy** (does it cover the real impact/risk/deliverables? is
   anything missing or hand-waved?) and **accuracy** (are its claims about the change,
   its impact, and its risk actually correct?). The two agents review independently.
3. **The author (the agent/contributor writing the change-control entry) decides**
   whether to update the document in response to each reviewer's observations —
   updates are at the author's discretion, not automatic. The author is not obligated
   to accept an observation it judges wrong or out of scope, but should record why an
   observation was declined if it's substantive.
4. **Re-review on update.** If the document is changed to address observations, both
   agents re-review the updated document (steps 2–3 repeat) before proceeding.
5. **Implementation gate.** The change may be implemented **only once all three
   parties approve the change-control document**: the author and both spawned
   reviewing agents. If either agent withholds approval, iterate (update-or-justify,
   then re-review) until all three agree, or stand down on the change.

This gate applies to the change-control document itself, ahead of code — it does not
replace the append-only change-control log entry still required at completion under
the bookkeeping checklist below (deliverables get checked off, Effectiveness gets
assessed after the change lands). Governance-doc changes (this file, `README.md`,
`docs/` process READMEs) follow the same gate before being edited.

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
   cause (and, on a recurrence, from step 3), and then **sweep the codebase for other
   instances of that bug class and remediate them** (that sweep is itself a rule, PA-0002).

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
run independent lanes in parallel and never let an eligible one sit idle; always
independently verify a lane's work yourself before merging (re-run tests, read the diff,
check bookkeeping — never trust a self-report alone); restrict to offline-buildable work
and flag (never silently build or skip) anything carrying genuine cross-component/
downstream risk or that you cannot actually verify in the current environment;
**pre-assign each concurrent lane its own bookkeeping numbers** before dispatch rather than
"claim the next free one" (`PA-0031`) — this is the single biggest source of avoidable
merge friction across concurrent lanes; and when your own instructions to a sub-agent
specify *how* a task must be done (not just what it must produce), require that sub-agent
to confirm which mechanism it actually used, and to stop and flag rather than silently
substitute if the specified one is unavailable.

## Canonical policy docs (the detail behind this summary)

- `docs/components/README.md` — change-control policy + the CHANGELOG relationship + entry
  template + component index.
- `docs/bugs/README.md` — bug-investigation policy and required contents.
- `docs/PREVENTIVE_ACTIONS.md` — the rule list to follow (read it every session).
- `CHANGELOG.md` / `ERROR_LOG.md` — their own headers restate their format.
- `docs/DECISIONS_AND_ROADMAP.md` — settled decisions (D-numbers) and the phased plan.
- `docs/ON_HOST_RUNBOOK.md` — how to run the on-host (lab) activities.
- `docs/MULTI_AGENT_ORCHESTRATION.md` — multi-lane/multi-agent orchestration policy:
  parallelism, independent verification, pre-assigned bookkeeping numbers, delegation
  mechanism fidelity, and when to flag risk instead of proceeding autonomously.

Note: the two adversarial-review agents required by the change-control gate above are
review-only spawns for gating a specific change-control document and are distinct from
the parallel build lanes `docs/MULTI_AGENT_ORCHESTRATION.md` governs.

If this summary and a canonical doc ever disagree, the canonical doc wins — and fix this
file to match.
