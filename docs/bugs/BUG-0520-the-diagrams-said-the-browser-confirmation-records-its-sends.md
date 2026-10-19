# BUG-0520 — The diagrams said the browser confirmation records its HTTP sends; it recorded none

- Date: 2026-10-19
- Status: fixed (CC-FUZZ-0102, CC-CORE-0065, CC-UI-0064)
- Severity: medium. Every M6 (stored/DOM XSS) test and finding showed no target
  traffic, its interface's *executed* count left out every browser load, and the
  diagrams' status and `docs/DIAGRAMS.md` claimed the opposite. A recurrence of
  BUG-0513.

## Description
`report.diagram.status()` ("browser-only (M6) and out-of-band (M8) confirmations record
their HTTP sends only") and `docs/DIAGRAMS.md` ("Known limits") said M6 records its HTTP
sends. Measured, it records none:
- the store request (`context.request.fetch`) and every page request (the guard's
  `route.fetch`, and Chromium's own landing re-request) reach the target through the
  Playwright driver and Chromium, never a sender;
- so nothing passes `harness/tracing.TracingSender`, the one recorder of sends.

## Where encountered
The survey for DG-M6M8 (CC-FUZZ-0102 phase 1). A loopback `run_pipeline` with
`browser=` and a recorder:
- the target received 8 requests for two M6 tests;
- the trace held 0 events for them;
- the `/dom` finding cited none;
- the not-confirmed test's interface showed *executed* 1 while the target received 7
  requests for it.

## What it caused to fail
The diagrams' completeness claim (FR-CORE-505, FR-UI-511), an M6 finding's evidence
(FR-FUZZ-60), and coverage (*executed*). Recorded as F-081.

## What the bug was identified to be
"Every send" instrumented at the senders only, while a run also sends through the
browser it drives.

## Root cause analysis
**Method: Five Whys.**
1. Why did M6's sends never appear? No M6 send passes `TracingSender`.
2. Why was that not seen? The instrumentation was placed around the senders a run hands
   to strategies (FR-FUZZ-60), and "every send" was taken to mean "every sender".
3. Why did BUG-0513's fix not catch it? Its preventive action (PA-0513) required an
   independent count "on a run that exercises every configuration creating an X". Its
   sweep enumerated sender objects: the run's sender, the peer's and the
   unauthenticated one.
4. Why was the browser not on that list? `browser=` is a keyword of `run_auto`, not a
   sender. Nothing tied the count to the set of a run's sending keywords, and the count
   test ran without a browser.
5. Why was the claim written anyway? The author did not check it against the target's
   log, although a test comment of theirs said M6 "sends nothing through the sender"
   (F-081).

**Root cause:** a send was defined by the object that makes it, not by what reaches the
target, and the rule requiring an independent count was not mechanically tied to every
configuration that sends.

## Corrective action
- **CC-FUZZ-0102** (FR-FUZZ-62).
  - The M6 executor records each visit's steps where they happen: store, observe
    navigation, first refusal, `load`, sentinel, page counts and result.
  - Each out-of-band wait records its callback or its absence.
- **CC-CORE-0065.**
  - The steps are cited by the strategy run and the finding (`emit_step`,
    `collected_steps`).
  - The M6 browser's loads are its own overlay flow.
- **CC-UI-0064.**
  - The sequences draw the steps.
  - *executed* counts the M6 store and observe loads.
  - The status line names the limits that remain.
- **Tests.** `tests/test_confirm_trace.py::test_every_send_of_a_run_is_counted_by_the_server`
  drives `run_auto` with `sender`, `browser`, `oob` and `peer` against a loopback app.
  The app's 53 requests equal 39 exchanges + 2 API stores + 12 page requests. On the old
  code it fails: the app received 53 requests and the trace had 39.

## Recurrence review
- **BUG-0513 / PA-0513** (the same day): the same bug class. "Every send" was claimed
  while a configuration's sends were not traced: there the peer's senders, here the
  browser.
- **BUG-0510 / PA-0510(2)**: an evidence producer tested against an independent count.

## Prior-preventive-action failure analysis
PA-0513 failed in two ways.
- **Too narrow.** Its rule ("verified against an independent count on a run that
  exercises every configuration creating an X") left "configuration" to the author. Its
  sweep and its one enforcing test listed sender objects only.
- **Not enforced as a set.** Nothing checked that the count test covers each way a run
  can send. A new sending keyword, or one that is not a sender (`browser`, `oob`), passed
  unseen.

PA-0510(2) was likewise applied to the probe senders' tries only.

## Preventive action
PA-0520 strengthens PA-0513.
1. A send is anything that makes the target receive a request on the tool's behalf; an
   "every send" claim is swept and counted by what the target receives, not by which
   objects send.
2. The independent count runs every sending keyword of the run's entry point
   (`run_auto`), and a guard holds the count test to that signature. It classifies every
   parameter, checks the wrapping of each wrapped one, and fails on an unclassified new
   keyword.
3. A step seen in a callback is recorded from the producer's own context, with the
   callback's stamp.

Sweep: `run_auto`'s parameters were classified, and each sending one is wrapped or
self-tracing (P2). The in-band marker checks' callbacks are the one remaining untraced
target-side action, asserted as a gap in P1 and listed in FR-FUZZ-62.
