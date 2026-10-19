# BUG-0513 — The peer account's and the unauthenticated replays were never traced

- Date: 2026-10-19
- Status: fixed (CC-FUZZ-0101; the post-implementation review of the diagrams series, F-076)
- Severity: medium. A broken-access-control finding cited only account A sends; the replays that prove it were absent from the diagrams and the evidence, while FR-FUZZ-60 said every send is recorded.

## Description
`run_auto` wrapped only the run's own sender in `TracingSender` (CC-FUZZ-0099). The
cross-account check (`CrossAccountReplayStrategy`, FR-FUZZ-55) sends through
`PeerAccounts.sender` and `.anonymous`, built separately and never wrapped.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Both reviewers found it by reading the code.

## What it caused to fail
The trace and the finding's evidence for every cross-account finding.

## What the bug was identified to be
Instrumentation at one object while the claim covered every sender a run creates.

## Root cause analysis
**Method: change analysis.** The pipeline's sends pass one sender; a strategy given its
own senders bypasses it. Nothing enumerated the senders a run hands to strategies, and
the end-to-end trace test had no peer account.
**Root cause:** "every send" was implemented at the one sender the author knew of, and
verified only on runs without the second one.

## Corrective action
`run_auto` wraps the peer's sender (identity: its name) and the unauthenticated one
(`anonymous`) when a recorder is active.
`tests/test_cross_account.py::test_run_auto_traces_the_peer_and_unauthenticated_replays`
runs the real strategy through `run_auto`'s wrapping: every send is an exchange with its
identity, and the strategy run cites all of them. It fails without the wrapping.

## Recurrence review
- **BUG-0510 / PA-0510(2)**: an evidence producer is tested against an independent
  count of the actions. This is a case it should have caught.

## Prior-preventive-action failure analysis
PA-0510(2) was applied to the probe senders' tries only; its sweep did not ask which
other senders a run uses. The count it requires was taken on runs that never create
the peer senders.

## Preventive action
PA-0513 (strengthens PA-0510(2)): an instrumentation claim of "every X" is verified
against an independent count on a run that exercises every configuration creating an
X (here: a peer account and the unauthenticated control).
