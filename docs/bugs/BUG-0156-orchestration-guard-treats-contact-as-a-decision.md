# BUG-0156 — The progress guard treated any user message as a decision, and counted review requests as rounds

- Date: 2026-10-15
- Status: fixed (CAPA status: provisional)
- Severity: high (a failed control: the guard reported holds that any status question
  silently lifted)
- Class: formal CAPA, failed control (`docs/QUALITY_POLICY.md` §4)

## Description
`scripts/orchestration_guard.py` (BUG-0141, PA-0141..PA-0147) was built to stop an
orchestrating session that keeps working while the goal metric does not move. Every one
of its holds, and the clocks behind them, was keyed to "the last user message":
- the stall clock;
- the item budget clock;
- the review-round count;
- the self-opened-scope hold;
- the bug-chain hold.

A user message of any content, "status?" included, restarted the stall and the budget,
zeroed the round count, approved self-opened scope and cleared the bug chain. The guard
also counted each review request as a round, so two reviewers in parallel used two of
the three rounds.

## Where encountered
The lean quality-control review (`docs/quality/LEAN_QC_PROPOSAL_REV3.md`, Revision 2,
"P0 — Specify escalation state"). Its synthetic reproduction showed a recent unrelated
user message clearing all five triggers.

BUG-0141 had itself recorded the gap as an accepted residual: "Any user message clears
an escalation, including an unrelated one."

## What it caused to fail
- A status question during an exhausted experiment erased the overrun.
- A rename (a new item for the same work) started a fresh budget and a fresh round count.
- Two parallel reviewers counted as two rounds.

The guard could therefore show "no holds" while the work ran past every limit, and
block a legitimate single round that used two reviewers. The F-051 false bug-chain
trigger (a re-registration) belongs to the same family: the guard had no notion of an
item continuing under a new ID.

## What the bug was identified to be
`evaluate()` and `gate_dispatch()` used `facts.last_user()` / `facts.user_after()` as
the clearing condition for every hold, and `_item_start()` took `max(start,
last_user)` as the budget start. A review dispatch appended one entry to
`item["rounds"]`. Nothing modelled a decision, a rename or cumulative spend.

## Root cause analysis
Five whys:
1. Why could a status question lift a budget hold? The hold cleared on any user message
   after it began.
2. Why was contact used as the clearing signal? The guard needed a signal the session
   cannot forge, and a real user message was the only one available in the transcript.
3. Why was forgery-resistance enough? The design conflated *authenticity* (the user
   wrote something) with *authority* (the user decided this hold).
4. Why was the conflation not caught? BUG-0141 recorded it as an accepted residual
   ("PA-0147 requires the report to come first"). It relied on a prose rule to cover a
   gap in the mechanical one, which is the pattern PA-0020 warns against.
5. Why did review rounds miscount? A "round" was never defined; the implementation used
   the dispatch event as its proxy.

**Root cause:** the guard measured contact, a proxy, instead of the property it
governs: a decision scoped to one hold. It had no state for decisions, renames or
cumulative spend.

## Corrective action
In `scripts/orchestration_guard.py`, this change (CHANGELOG 2026-10-15, "lean quality
policy"):
- **Decisions.** `decide --hold stall|budget|review|scope [--item] --quote "<user's
  words>" [--hours|--rounds]`. A decision counts only while a real user message after
  the hold began contains the quote (`TranscriptFacts.quoted_after`). It lifts only the
  hold it names.
- **Allowances add up.** Stall and budget decisions grant hours; review decisions grant
  rounds. Neither resets the spend or the stall clock.
- **Cumulative spend.** `spent_hours` survives `item done|drop|reopen`, `goal
  close|reopen` and `item add --continues <old>`. A rename keeps the item's opened time,
  origin, rounds, budget and holds (`lineage()`).
- **A round** is the set of review requests between two work dispatches for the item, at
  most `round_request_cap` (4) requests.
- **R1 dispositions** (`item disposition --class ... --evidence ... --next ...`) clear the
  bug chain and an exhausted experiment (a `--hypothesis` item past its base budget).
  This is the delivery owner's evidenced decision, not a user dependency.
- **Linked work.** A feature item must state `--hypothesis`.
- **History.** A new `goal open` archives the previous goal instead of discarding it.
- **Report.** It leads with the metric and its unchanged-since time, then the holds, and
  lists each decision with its verification state.

Tests (`tests/test_orchestration_guard.py`):
- `test_contact_and_renames_do_not_reset_an_exhausted_experiment` (counterexample (d) of
  the review);
- `test_a_decision_needs_the_users_words_and_names_its_hold`;
- `test_a_round_has_a_request_cap`;
- `test_a_closed_goal_keeps_its_history`;
- `test_a_feature_names_the_outcome_it_should_move`;
- the stall, review, scope and bug-chain tests, rewritten so that contact alone no
  longer clears a hold.

While building this, one defect surfaced: a reopened item ("open", not yet "active")
escaped the budget check. It was caught by the new test and fixed before commit.

## Recurrence review
- Searched `docs/bugs/` and `docs/quality/CONTROL_INDEX.md` (L11).
- BUG-0141 is the origin of the control; its residuals section names this exact gap.
- F-051 (`docs/claude_juicelab_failures.md`) is a related symptom: a re-registration
  tripped the bug chain.
- No other control uses user contact as authorisation.

## Prior-preventive-action failure analysis
PA-0141..PA-0147 (BUG-0141) were enforced mechanically, but their clearing condition was
a proxy. The failure mode was a *wrong measure*, not "not followed" or "not enforced":
the guard was green while the governed property (an informed decision within budget) was
absent. The prior record accepted the gap as a residual and covered it with prose
(PA-0147), which is the weakness PA-0020 describes.

## Systemic action
- **Corrected controls:** PA-0141, PA-0142, PA-0143, PA-0144, PA-0145 and PA-0147. Their
  map rows in `docs/quality/pa_control_map.tsv` carry the correction.
- **R1 implemented:** `docs/QUALITY_POLICY.md` L11 and R1 state the policy, and the guard
  implements R1's trigger.
- **No new PA:** the existing controls were corrected in place.

## Owner, due date and effectiveness
- Owner: delivery owner (the orchestrating session) for operation; verification owner
  for the guard's tests.
- Due: the next orchestrated delivery.
- Effectiveness criterion: over the next three orchestrated deliveries in which a hold
  fires, no hold is lifted without a verified decision in the `report`. A status
  question never resets spend or a stall. Two-reviewer rounds count as one. A hook-load
  check shows the hooks run in the session (`test_the_repository_hooks_call_the_guard`
  covers the wiring, not the loading).
- Status: provisional. The paper replays qualify the logic only (QUALITY_POLICY §8).

## Residuals
- The quote check proves that the user wrote the words, not that they meant the
  decision. A dishonest quote of an unrelated message is visible in the `report`, but it
  is not blocked.
- The ledger is container-local (git-ignored). Goal history does not survive a new
  container unless the `report` is exported into the handoff.
