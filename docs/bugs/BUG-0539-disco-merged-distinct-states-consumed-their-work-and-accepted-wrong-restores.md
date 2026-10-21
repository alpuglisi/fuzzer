# BUG-0539 — The disco explorer merged distinct states, let a step seen elsewhere or a failure consume a state's work, and accepted (then weakened) a wrong state on restore

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0055), with stated residuals
- Severity: high. The audit rated defects 1 and 2 BLOCKER and defect 3 CRITICAL. A
  multi-step workflow stopped at its first step, a dialog's confirmation was never sent,
  one transient driver error removed an action for the whole run, and a restore that
  showed the wrong state was explored and logged as the recorded one, its contract cut
  down for good. Nothing outside `fuzzlab/disco/explore.py` and
  `fuzzlab/disco/fingerprint.py` was affected.

## Description
Three decisions of the behavioural explorer (FR-CRAWL-19) were made on evidence too weak
for them (external adversarial audit, defects 1, 2 and 3):

1. **State identity (defect 1).** The visited-state check compared
   `fingerprint.state_fingerprint`: a hash of the folded route (digit runs folded, query
   names only) and the *set* of element signatures. `/wizard?step=1` and `?step=2` with
   the same Next button, `/users/17` and `/users/42`, one button and two identical
   buttons, and a select holding another option were one state. The next state of a
   wizard or a pager was "already known".
2. **Action work (defect 2).** A step was keyed `(route, signature, occurrence, kind)`
   (`_Shared.seen`), so the same Next in a dialog's second stage was "seen" in its first.
   A step taken on another route was skipped as presumed chrome from layout identity
   alone (`sig_routes` plus `done`). `seen` was written before the step ran, so a
   Playwright error consumed it for the run.
3. **Restore (defect 3).** A replay step whose element was missing was skipped. The
   reproduction check accepted a page on the same folded route whose signatures were a
   proper subset of the state's core, and replaced the core with that subset
   (`transient_dropped`). A replay re-sent every step of the path, a form's POST
   included.

## Where encountered
The external adversarial audit at 6552276 (defects 1-3, with their reproductions:
`/wizard?step=1` vs `?step=2`; one vs two identical buttons; a two-stage dialog with the
same Next; a transient Playwright error; a core `{pay, terms}` accepted with `{pay}` and
shrunk). Reproduced at 08e3eaa by `tests/test_disco_state_identity.py` and
`tests/test_disco_state_identity_browser.py`, written first.

## What it caused to fail
Measured at 08e3eaa on loopback pages the browser tests serve (one guarded Chromium, no
capture proxy, no harvest; no target contacted):
- **Wizard** (three steps, one layout, Next navigates by script): the finish request was
  made 0 times; step 2 hashed like step 1.
- **Two-stage dialog** (the same Next, the second stage adds Back): the confirmation POST
  was sent 0 times; the second stage's Next was "seen" on the route.
- **Transient error** (the first attempt of the only action raises a Playwright error):
  the action's request was made 0 times.
- **Consumed control** (a cart recorded with pay and terms, terms gone on the second
  load): the restore was accepted and the core shrank from `{start, pay, terms}` to
  `{start, pay}`.
- **POST transition** (Begin POSTs and reveals Confirm and Details): the server
  received the order 3 times (two replays).

These are the pre-fix runs of the new tests (CC-CRAWL-0055's effectiveness).

The fix met two more defects of the same class on the e2e fixture, both fixed here:
the explorer's first-visit reading made every step on the restored start page look
like a transition to a new state; and `_gather` marked a script or stylesheet body read
before reading it, so the second load of the start URL (the first-visit check) left the
first load's bodies unreadable and no script route was ever found.

## What the bug was identified to be
Each identity decision -- "this state was visited", "this step's work is done", "this
page is the state I recorded" -- was made on a similarity, not an identity: a folded
route and a set of layouts, a route-scoped step key, a subset of a core. A failure was
recorded as done, and a replay was assumed harmless.

## Root cause analysis (Five Whys)
1. Why did the wizard stop at its first step? The next step's state was "known".
2. Why was it known? The visited check compared a key built to *fold* similar pages
   (digits, query values, multiplicity), for the frontier's budget.
3. Why did one key do both? It was introduced as the state key (CC-CRAWL-0031) and the
   later fixes for budget and restorability (BUG-0501: core narrowing; BUG-0502:
   route-keyed steps and the chrome skip) widened what it, and the step key, merged,
   because merging was what made the counters improve (fewer header actions, no
   unrestorable start page).
4. Why did nothing catch the merges? Each fix was judged by the work it saved and the
   restores it made succeed, on the fixture and on Juice Shop. No test asked the
   opposite question: two states that must stay two, a step that must run in a second
   state, a restore that must be refused.
5. Why was no such test required? PA-0028 and PA-0029 (fail closed; test the branch a
   gate turns off) were written for semantics validators and checkers, and PA-0110
   (success only on a verified effect) was applied to report counters (PA-0502). A
   state key, a work key and a restore check were not seen as gates.

**Root cause:** a work-saving heuristic (folding states, skipping steps, accepting a
restore) was implemented as an identity or acceptance decision instead of as an order
or a reported bound, with no evidence of equivalence, and validated only by the work it
saved.

## Corrective action (CC-CRAWL-0055)
- **Two keys** (`disco/fingerprint.py`, FR-CRAWL-31, SP-62): `execution_key` -- exact
  route (query values, numeric segments; sensitive values replaced), element multiset,
  workflow markers (selection state, short non-token hidden inputs, a stepper's
  `aria-current`), session generation -- is the identity; `state_fingerprint` is kept
  for the frontier's order and bound and the harvest alias only (an AST guard). The
  per-route bound is reported (`coverage_excluded`, `states_over_budget`).
- **Work** (`explore.WorkLedger`, FR-CRAWL-32): the work key is (execution key,
  signature, occurrence, kind) with pending / running / succeeded / refused / retryable /
  failed; a failure is retried up to 3 attempts, then failed and reported; a step taken
  elsewhere is deprioritised, skipped only after equal observed effects (requests and
  transition) on two routes.
- **Restore** (`explore.contract_mismatch`, `Explorer.restore`, FR-CRAWL-33): the
  recorded contract (multiset and markers) is never rewritten; a proper subset is
  refused; optional features are declared with evidence (`first-visit` from a fresh
  second load of the start URL when it is recorded; `dismissed` when a control removed
  its own element); a missing replay step fails unless declared optional; a step that
  issued a non-idempotent request is recorded unsafe and never replayed -- its state is
  explored in place when reached; a failed restore marks the state unresolved with its
  reason.
- The e2e fixture's assertions that encoded the old contract were changed:
  `transient_dropped` (now `optional_declared`), "Theme acted on once" (now at most
  twice, never twice on one route), "no unrestorable state" (now none but the states a
  POST reached), "(route, element, step) never twice" (now per state).

### Review round 1 (on d9e269e): three more instances inside the fix
The implementation review found the root cause again in the fix itself, each
reproduced by a skeptic in a real browser or on the real loop:
- **B1:** `_dismissal` took one click as evidence. A modal closed by its own Close made
  Close and Pay optional run-wide, so a restore that did not reopen the modal was
  accepted as the modal state (`unresolved == {}`, Pay never taken, reported only as a
  failed action). Fixed: a dismissal is declared only from a safe click on an entry
  document as loaded, for what its recorded contract held, confirmed by a fresh load;
  a run-wide declaration never excuses what a state's own last step added.
- **B2:** the contract accepted a superset on purpose ("a page with more is
  accepted"), although the audit names supersets in defect 3. A server that moved to
  a later stage was taken for the earlier stage, and the earlier stage's Help was run
  and logged there. Fixed: an `extra` control or marker is refused unless declared; a
  step is taken only on a page that passed the contract.
- **B3:** a work item was marked succeeded before its result page was read; an
  unreadable result consumed it. Fixed: an item succeeds only once its result was
  read; a safe step is retried, an unsafe one reported `unreadable`.

Why the fix repeated its own root cause: B1 and B2 were designed to keep the e2e
fixture's restores passing (the notice, another worker's fresh context), and were
judged by those restores passing -- the work-saving side again -- with no test of what
they must refuse (PA-0539(5) was written in the same change and not applied to its own
declarations). B3 kept the pre-fix order (finish, then read). Each now has a test
proven on d9e269e (CC-CRAWL-0055's effectiveness).

## Recurrence review
Checked `docs/bugs/` (BUG-0501..0507 for disco; BUG-0026/0027, BUG-0072, BUG-0109) and
`docs/PREVENTIVE_ACTIONS.md` (PA-0028, PA-0029, PA-0048, PA-0073, PA-0110, PA-0501,
PA-0502, PA-0505):
- **BUG-0501 / PA-0501** (same component): its fix introduced the core narrowing
  (defect 3). PA-0501 asks for a run on a third-party app and checked counters; the
  narrowing was what made those counters pass.
- **BUG-0502 / PA-0502** (same component): its fix introduced the route-scoped step key
  and the chrome skip (defect 2). PA-0502(3) moved context *out of element identity*;
  the fix put it back, coarser, into the work key.
- **BUG-0026 / PA-0028, BUG-0027 / PA-0029**: the same root cause in another layer -- a
  check that accepts by default what it cannot prove, and a gate whose off branch was
  never tested.
- **BUG-0109 / PA-0110**: success reported without its effect verified; here a restore
  reported success on a subset, and "seen" was written before the step ran.
- **BUG-0046 / PA-0048**: a lookup collapsing one-to-many by a coarse key, in the
  auditor's point builder: the same collapse, at point-build time.

## Prior-preventive-action failure analysis
- **PA-0501 and PA-0502 targeted the wrong side of the trade.** Both ask that counters
  reflect effects and that a mechanism run on a third-party app. They say nothing about
  the cost side of a work-saving fold: what it merges that must not be merged. The
  merges were the fixes, so meeting the PA confirmed them.
- **PA-0028 and PA-0029 were scoped too narrowly.** Fail-closed acceptance and testing
  the gated-off branch were written for semantics validators and minimal-pair checkers;
  a state key, a work key and a restore verdict are the same kind of gate, and nothing
  named them.
- **PA-0110 was applied to counters only** (by PA-0502), not to the explorer's own
  verdicts (restored, done).
- None of the four was enforced on the explorer by a test that fails when a fold
  merges what it must not.

## Preventive action
PA-0539 (strengthens PA-0028, PA-0029, PA-0110 and PA-0502), text in the lane report:
an identity or acceptance decision rests on an exact key or recorded evidence; a
similarity key orders or bounds work and its bound is reported; work is consumed only
by success or an explicit refusal; an acceptance check never rewrites its contract and
optionality is declared with evidence when the contract is recorded; a replay requires
recorded evidence that the step is safe to repeat; a work-saving fold ships with a test
of what it must not merge.

**The PA-0002 sweep (by mechanism: a fold, skip or acceptance decided on a similarity):**
- `disco/explore.py`:
  - the harvest alias (`_alias_state`): a fold by the structural key, kept (BUG-0505's
    rule: the same document under two addresses), named in the AST guard;
  - `_document_first` (a body hash): exact content, kept;
  - the perturbation pass per (folded route, field set): kept as a bound on value
    variations, now reported (`perturbations_folded`);
  - `max_same_signature`: kept, now reported (`same_signature_capped`);
  - `denied` (a step denied run-wide after a lost session): audit defect 4's area, not
    in scope, not changed;
  - harvest queues by exact URL: kept;
  - `_gather`'s `bodies_read` marked a body read before reading it, so a failed read
    consumed it for the run: **fixed** (marked after the read).
- `disco/synth.py` endpoint keys (origin, method, template, content type): an inventory
  of observed requests, not a work decision; the audit's synthesizer findings (defect 9
  for the spider's capture) are their own items.
- The same class elsewhere, each its own audit item, not fixed here and flagged to the
  coordinator: defect 8 (injection and confirmation keys merge requests), 9 (captured
  API dedupe drops nested shapes), 10 (DOM template dedupe drops surfaces), 11 (the
  legacy frontier's scheduling key) and 12 (legacy transient failures finalized as
  visited).
- PA-0507(2): no other implementation of a UI state's identity exists; the spider keys
  documents by `core.urls.document_key` (SP-08) and has no state graph. PA-0505(2): the
  deprecated spider has no state graph to share this mechanism with.

## Residuals
- **R1 -- data held in a closure.** Two states that differ only in text or in a value
  their script holds (the fixture's two projects, whose "New task" posts to two ids)
  are one execution state; the second is not explored. Text stays out of the key by
  design (a counter or a new row is not a new state).
- **R2 -- background non-idempotent requests.** Safety is decided from the requests
  observed during a step. An app that POSTs telemetry while a step runs makes the step
  unsafe: its state is explored in place and later restores of it are unresolved, never
  replayed. Not measured on a third-party app here (PA-0501(1)): the lane had no lab.
- **R3 -- restores do not reset server state, cookies or storage** (stated in
  FR-CRAWL-33); a state that depends on them holds its contract or is unresolved.
- **R4 -- first-visit UI on a page other than the start URL** is not declared (one
  fresh second load is made, of the start URL); such a state is unresolved, reported.
- **R5 -- budget on a list that grows per submission.** The multiset makes each
  appended row a new state; the per-route bound (8) stops it and reports the rest.
- **R6 -- strict restores cost coverage on a changing server** (review round 1): a
  state whose page gains a control or loses one between visits (a list the server
  grows, a stage that moved on, a modal that no longer opens) is unresolved (`extra`,
  `core`), its remaining steps abandoned and counted, never explored as itself.
- **R7 -- a notice on a page reached by a step** (not an entry document) is never
  declared dismissed: a state that recorded it is unresolved once it is gone.
