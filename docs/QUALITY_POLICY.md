# Quality policy (lean operating policy)

**Status:** adopted by the owner on 2026-10-15 as a **bounded pilot** (D70). The source is
the lean quality-control review, `docs/quality/LEAN_QC_PROPOSAL_REV3.md` (Revision 3).
This file is the operating policy. `docs/PREVENTIVE_ACTIONS.md` keeps every historical
preventive action (PA) and its immutable ID. You do not read the register before each
change. `docs/quality/CONTROL_INDEX.md` (generated) lists the PAs under each family,
with their current requirement.

Being adopted does not mean the incident is resolved. The controls below stay
`implemented`, not `qualified`, until the evidence in §8 exists. Safety controls are
never relaxed to go faster (§9).

## 1. Operating instruction (every change)

1. **Define the outcome.** Write down the observable user outcome, the supported
   conditions, the acceptance check and the authorised scope. Qualify the baseline
   measurement before you compare any capability. Classify risk (§2) before you choose
   the review and the evidence.
2. **Consult only the affected controls.** Read the families in §5 that the change
   touches, and their rows in `CONTROL_INDEX.md`. The historical PAs are reference
   material, not 163 separate mandatory instructions.
3. **Validate impact by contract.** Work through each shared contract, state transition
   and consumer the change affects (L02). Sequence semantic edits that conflict. Bound
   the investigation to the mechanism. Report serious adjacent risks; do not silently
   widen the delivery scope.
4. **Bound uncertain work.** State a falsifiable prediction, an effort ceiling and an
   exit decision. Build the smallest change or experiment that tests it while keeping
   safety and data integrity. Reuse the qualified primitives (`docs/SHARED_PRIMITIVES.md`).
5. **Test on an identified tree.** Test the changed behaviour, the relevant boundaries and
   the affected consumers on a committed tree (`scripts/verify_change.py`). Fast feedback
   and final qualification serve different purposes (§3).
6. **Review in proportion to risk** (§2). The reviewer challenges the material causal and
   acceptance assumptions. Consolidate the must-fix issues and park unrelated
   improvements. Within the agreed budget, either change the hypothesis or escalate the
   unresolved obstacle.
7. **Record once** (§7): goal, risk, change, evidence and decision. Update a living
   `requirements.md` or `docs/ARCHITECTURE.md` only when its contract changes.
8. **Investigate significant or recurring defects as CAPA** (§4). Correct the existing
   control when you can; add a new one only for a mechanism no control covers.
9. **Report at the agreed cadence:** outcome or stage changes, unchanged-since time,
   cumulative spend, unresolved risk and the next experiment. A user message is not
   approval to widen scope or erase a budget. An informed decision applies only to the
   hold it names (L11).
10. **Preserve the safety controls on every route:** owned-process cleanup, scoped
    sending, private secrets, fail-closed safety state and honest evaluation. Release
    only with the required evidence and an explicit disposition of the residual risk.

## 2. Risk classes, review and verification

| Class | Examples | Review | Verification |
| --- | --- | --- | --- |
| Administrative / non-behavioural | link or wording fix; regenerated record; handoff or failure-record entry | owner self-check; independent review only if an active obligation changes | Markdown/record checks (`scripts/quality_index.py --check` when the map or register changes). Push directly; no pytest run (owner rule, F-058). Changing a safety requirement is never "just docs". |
| Low-risk local correction | display text; an isolated pure transformation behind a stable interface | owner, or one reviewer | `scripts/verify_change.py --base <ref>` (changed tests plus the cheap structural guards) |
| Medium-risk behaviour or shared contract | new CLI action; emitter shape; shared normalisation; a hook or harness change | one independent qualified reviewer; a domain specialist where needed | `--base` while iterating; `--full` on the merged candidate before merge |
| High-risk safety / data integrity | credential origins; destructive sends; imported schemas; holdout membership; durability | independent domain or security review before implementation, and again before release when the evidence changes | relevant adversarial, concurrency and real-browser tests; an explicit risk decision; `--full` on the final candidate tree |

- Record consequence, exposure and detectability separately. Never multiply them into
  one risk-priority number that lets a favourable average waive a catastrophic case.
- **One combined design-and-code review per change** (owner, 2026-10-15). It returns a
  single consolidated must-fix list. A second round verifies those fixes. A third round
  is a signal to clarify scope or design, not an invitation to generate more
  improvements. Material concerns still unresolved go to the owner; cosmetic
  preferences do not reset the gate.
- For uncertain capability or architectural work, give the reviewer the acceptance
  contract and the primary evidence, and ask for a falsifying case. Extra agents that
  share the coordinator's assumptions are not independent evidence.
- **Before every merge**, the full suite runs on the candidate and the coordinator reads
  the diff (owner, 2026-10-15).

## 3. Verification layers

1. **Structural:** lint, traceability and the guard *nodes* of mixed files. A `--base`
   run takes only the guard tests of an auto-detected guard file, not its behavioural
   tests (PA-0403 corrected).
2. **Affected contracts:** importers of a changed module, shared-primitive consumers and
   changed tests.
3. **Target runtime:** affected browser, emitter, process and live-tool suites, in
   qualified isolated environments.
4. **Merged-candidate backstop:** `--full` on the final integration tree. A relevant
   failure that `--full` finds and `--base` missed is a **selector miss**. It is a
   defect in the selector or the contract map, investigated as such.

Each run writes `manifest.json`. It holds the evidence key (commit tree, dependency-file
hashes, interpreter, installed distributions, flags, selected tests) and the per-file
results from that run's JUnit output, which a reader uses instead of a second pytest
run (PA-0038 corrected). `--reuse` accepts a previous passing manifest only when every
part of the key is identical. Never add automatic retries. A quarantined test has an
owner, a deadline, a risk statement and a compensating gate, and it never counts as
passed. A failing test is root-caused; "flaky" is not a cause.

## 4. Defects: ordinary correction or CAPA

- **Ordinary defect:** add one `ERROR_LOG.md` entry with the reproduction, the
  correction, the regression check and the affected scope. Add or adjust the regression
  test. No bug report or new PA is required.
- **Formal CAPA** applies to a significant escape, a recurring or systemic defect, a
  security or data-integrity event, or a failed control. Write a `docs/bugs/BUG-NNNN-*.md`
  report (see `docs/bugs/README.md`). It adds the verified cause, the systemic action,
  the owner, the due date and an effectiveness plan with a predeclared criterion.
  Correct the existing control and update its row in `pa_control_map.tsv`. Add a PA only
  for a mechanism no control covers, and name its enforcement (`- Enforced by:`).
- **Closure:** a CAPA closes against its effectiveness criterion, not against a green
  regression test alone. Until relevant opportunities have been observed, its status is
  provisional.
- **Identifiers are immutable.** When human labels collide, record an alias; never
  renumber history to tidy it.

## 5. Three explicit requirements (Revision 3)

**R1 — Systemic-diagnosis trigger (L01/L02/L11).** Two cases trigger it: the same
failure mechanism recurs across routes, consumers or applications; or a bounded
experiment exhausts its declared budget without its predicted stage improvement. Before
another equivalent local patch, the delivery owner dispositions the approach. Check
existing evidence first; if it is insufficient, run the smallest discriminating
experiment. Record one of four classes:
- isolated defect (with evidence);
- missing shared contract;
- broader capability gap;
- unresolved hypothesis.

The next action carries a fresh prediction and budget. A material safety exposure is
contained immediately regardless of the trigger. A first isolated defect does not
trigger it. `orchestration_guard.py item disposition` records it, and the guard holds
an item's bug chain until a disposition exists.

**R2 — Evidence for design-critical assumptions (L08/L10).** Before a capability change
relies on an assumption, link the decisive evidence: a source or call path, an
authoritative specification, or a controlled observation. State the material
uncertainty. Examples: which function calls a policy; whether the browser submits
credentials; which headers the runtime sends. If the evidence is missing, test the
premise within the experiment budget and label it *unverified*. A claim of validated
design or completion that rests on an unverified premise is blocked; an exploratory
spike to resolve it is not. The reviewer challenges the premise with a counterexample
or primary evidence. A schema can check that a link exists, not that it proves the
claim.

**R3 — Capability-transfer acceptance (L06/L07/L09).** A claim to fix a general
technology capability passes a predeclared behaviour contract on the diagnostic
regression *and* on independently authored variations of the mechanism. The variations
change misleading incidental details (route vocabulary, routing mode, login
presentation, body shape) and keep the supported semantics. Auth, configuration, target
state and budget stay equivalent.
- Production discovery never depends on lab identity, answer keys or undisclosed target
  hints. Supported protocol or framework adapters are legitimate when their contracts
  are explicit and tested independently.
- Previously working cases and safety controls stay in qualification.
- Cases exposed through tuning become regression data. An unbiased transfer estimate
  needs fresh, evaluator-controlled cases.
- Passing one lab never justifies "works in any lab".

## 6. Control families

Owners: the delivery owner holds L01 and L11; the verification owner holds L09, L10 and
L12; the affected component's technical owner holds L02 to L08. One person may hold
several roles where the risk permits.

### L01 — Change and CAPA triage
Every change records its scope, risk and evidence once (§7). Formal investigation is
reserved for the cases in §4. **Evidence:** the change record, the risk decision and
links. A routine correction does not create a new PA.

### L02 — Shared contracts
Shared decisions and state transitions have named owners and explicit semantics. Find
every consumer and every semantic duplicate, including differently named ones. Sequence
conflicting edits; run disjoint work in parallel. **Evidence:** the consumer impact list,
behavioural transition tests and early merged-tree checks. Name uniqueness alone is not
enough.

### L03 — Input and persistence boundaries
Untrusted values are bounded and typed. Unsafe storage is omitted, quarantined or
refused by explicit policy, and secrets pass one redaction boundary. A malformed value
returns a typed outcome; each consumer states whether it fails closed, quarantines or
reports unavailable. Unknown authorisation or holdout state is never treated as absent.
**Evidence:** malformed and limit cases, true negatives, non-vacuity controls.

### L04 — Network and secret containment
Authorisation is enforced at every sending and binding boundary, keyed to approved
origins and transport. The browser and driver layers are each tested for the traffic
they can observe. **Evidence:** receiving-server and attack tests, scope and transport
checks, qualified launch paths.

### L05 — Resource and storage lifecycle
Work owns its process tree, connections and artifacts. Each transition defines its
atomicity, cleanup and durability outcomes. For example, a failure before publication
rolls back, while one after a rename is "published, durability unknown". **Evidence:**
injected-failure, ownership, concurrency and recovery tests. An intermittent failure
stays unresolved and instrumented; it is never relabelled fixed because a rerun passed.

### L06 — Oracle and evaluation integrity
Acceptance and measurement are qualified before capability is compared. Preconditions,
auth and configuration are comparable, and stage losses and refusals are explicit. A
case used for tuning is no longer unseen. An inconclusive result never silently becomes
secure or negative. **Evidence:** per-case funnels, positive and negative controls,
independently adjudicated outcomes, fresh transfer cases (R3).

### L07 — Generated lab and environment compatibility
Supported shapes, absent inputs, twin behaviour and dependencies are qualified on the
target runtime. Weakness labels (CWE) are accurate mappings of the underlying weakness;
independent examples may share one. **Evidence:** a discovered contract matrix,
built-artifact checks, representative stateful checks.

### L08 — Provenance and identity
Runs, defects and goals have immutable identities. Facts, hypotheses, owner decisions
and deployed behaviour stay distinguishable. Current status is derived from dated
evidence without erasing history. Design premises carry their evidence (R2).
**Evidence:** cross-run and cross-target tests, the baseline manifest, the alias map,
writer/reader checks. Synthetic or stale evidence is never presented as observed.

### L09 — Verification and release
Verification runs on an identified, immutable tree in a qualified environment. Affected
suites are selected mechanically, and the broad integration run stays the backstop
(§3). **Evidence:** `manifest.json` (evidence key and per-file JUnit results).

### L10 — Test and guard quality
Expectations come from an independent contract or oracle, not from the code under test.
Guards have an offender control and a legitimate control, reachable non-vacuous inputs,
a qualified invocation and separately demonstrated operating effectiveness. Shell code
uses explicit branches with deliberate exit status; never `|| true` to mask a failure.
**Evidence:** counterexamples, positive and negative controls, targeted mutation, and
proof that a hook actually loads where one is relied on. Reviewer agreement or a test
name is not evidence.

### L11 — Delivery flow and escalation
Each item links to an outcome hypothesis, a necessary safety correction or a required
dependency. Uncertain work has a bounded hypothesis and an exit decision. Goal-level
clocks and spend survive contact, renames, close and reopen, and handoff. Authorisation
is specific to a decision: a quoted user decision clears only the hold it names.
**Evidence:** the `orchestration_guard.py report`, cumulative spend, the unchanged-since
time, a limited WIP and hypothesis dispositions.

### L12 — Performance and reuse
Shared setup is reused only while it is truly invariant, with a defined cache scope and
invalidation. Network and CPU work have explicit limits. Operation counts support
algorithmic claims, and controlled end-to-end benchmarks support performance claims;
real latency is profiled before anyone claims a speed-up. **Evidence:** phase timings,
cache-key and invalidation tests, benchmarks.

## 7. The change record

The change record lives in the commit trailers and in one controlled entry.
- **Commit trailers, required on every commit.** `Change-Type:` is one of `defect`,
  `feature`, `safety`, `process`, `docs`, `refactor` or `test`. `Risk:` is `low`,
  `medium` or `high`. Git reads trailers only from the message's final paragraph, so
  they go in the same block as `Co-Authored-By`. The Stop hook
  `.claude/hooks/check_bookkeeping.py` checks the trailers, and checks that a `defect`
  change or a bug report comes with its `ERROR_LOG.md` entry (PA-0020 corrected; there is
  no keyword scan).
- **One controlled entry.** For a component change, that is its `change-control.md`
  entry. Its template has the fields `goal`, `acceptance`, `hypothesis`, `verification`,
  `review` and `control_status`, plus `rollback`. A multi-component change writes the
  full entry once, in the primary component, and one-line entries that link to it
  elsewhere. A process or tooling change records itself in `CHANGELOG.md`.
- **`CHANGELOG.md`:** one dated line per change.

## 8. Effectiveness and the pilot

- **Control states:** `designed`, `implemented`, `qualified` and `operating-effective`
  are tracked separately in `pa_control_map.tsv`. A named test makes a control
  `implemented`. `qualified` needs challenge tests that hit the failure mode and accept
  legitimate cases. `operating-effective` needs observed use over comparable deliveries.
  Silence, meaning no relevant trigger occurred, keeps a control provisional.
- **Counterexamples the controls must expose** (paper replays qualify the logic only):
  - (a) a renamed login path defeats a lexical fix;
  - (b) a false runtime or header assumption has no supporting observation;
  - (c) commits and green unit tests pile up while the accepted capability stays
    unchanged;
  - (d) user contact or an item rename happens during an exhausted experiment.

  (d) is covered by guard tests (BUG-0156). (a) to (c) stay review obligations under
  R2, R3 and L11.
- **Measures, kept on a run chart:** change lead time (p50/p90), first-pass yield, escaped
  defects, rework and review demand, verification cost, selector misses, measurement
  validity and capability stage losses.
- **Pilot targets (not results):**
  - halve the median routine-change lead time;
  - fast structural lane under 2 min, routine affected suites under 10 min where
    feasible;
  - no duplicate manual record entry.

  An unacceptable quality loss stops the pilot even if it is faster.

## 9. Never relaxed

The following hold on every route, whatever the risk class, the deadline or the pilot:
- the lab-only, loopback-only, `--authorized` rules;
- credentials in the OS keyring;
- origin and transport containment;
- the redaction boundary;
- owned process cleanup;
- holdout sealing;
- inconclusive results that never become negatives.

A change that weakens one is high-risk by definition.

## 10. Migration status (2026-10-15)

| Stage | State |
| --- | --- |
| Recover a measurable slice | **Not done here.** It needs the held-out labs and their keys, which are not in this container, and it is capability work. It stays the first item of the work queue (`docs/HANDOFF-2026-10-15.md` §5). |
| Consolidate policy | Done. This file; the 163/163 map; `CONTROL_INDEX.md`; the register reframed as history. |
| Consolidate records | Partly done. The commit trailers and the extended template are in place; generated changelog/component views are not built. |
| Refactor verification | Partly done. Guard-node selection, evidence manifests and exact-key reuse are in place. A shared AST index and dependency metadata are not built. |
| Shadow pilot / adopt / sustain | Pending. Observe the next comparable changes, then review effectiveness (§8). |
