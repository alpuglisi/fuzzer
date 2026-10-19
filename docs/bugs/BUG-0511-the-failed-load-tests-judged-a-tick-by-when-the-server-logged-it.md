# BUG-0511 — The failed-load tests judged a tick by when the server logged it, not when it was sent

- Date: 2026-10-19
- Status: fixed (test-only; the diagrams commit series, see the CHANGELOG line)
- Severity: low. A test defect with no product impact. It failed one verification run
  of the diagrams change and would have been set aside as "flaky" under the old habit.

## Description
Two tests check that a refused navigation ends the previous document:
- `tests/test_navigation_aborts.py::test_the_auditors_failed_load_ends_the_previous_document`
  (`ContentFetcher`, CC-AUD-0042);
- `tests/test_navigation_aborts.py::test_a_failed_load_ends_the_previous_document`
  (the spider, X1).

Page A runs a 50 ms POST ticker. After `/go` is refused, the code sends the page to
`about:blank`, then makes its static fallback request. The tests asserted
`("POST", "/tick") not in a.log[fallback:]`: the server logged no tick after the
fallback's own `GET /go`. The spider test also bounded the ticks logged or captured
between the mark and the fallback (`<= 2`).

## Where encountered
`scripts/verify_change.py --base 8f5efd0` on the diagrams commits (168 files, three
other harness runs in progress on the host): the auditor test failed. It passed 3 of 3
runs alone.

## What it caused to fail
The auditor test, under CPU load. The spider test asserts the same shape.

## What the bug was identified to be
A bounded experiment (`ContentFetcher` and the same site, each tick's body carrying the
browser's `Date.now()`, the browser clock read when the fallback starts):
- with no load: 0 ticks logged after the fallback's request in 3 runs;
- with 12 CPU-bound processes: one run of 3 logged 5 ticks after it. All 5 were sent
  **before** the page showed `about:blank`, by 2,243, 2,192, 2,143, 943 and 884 ms.
  None was sent after.

The document had ended as the code claims. Under load, requests the browser had sent
seconds earlier reached the server's handler after the fallback's own request. The
test read the server's log order as the order of sending.

## Root cause analysis
**Method: change analysis.** The only difference between the passing and failing
conditions is CPU load. Load changes the order in which two concurrent actors' requests
reach the server's handler: the ticker's fetches (queued in the browser's network
stack), and the fallback's request (sent by Python). The test's oracle depended on that
order.

**Root cause:** the oracle for "nothing was sent after the mark" was taken from the
observer's arrival order, not from a stamp the actor gave each event when it sent it.
Arrival order equals send order only when nothing delays delivery.

## Corrective action
- The ticker's body carries the browser clock at sending (`{k<n>: Date.now()}`; the key
  stays distinct, so the spider keeps every tick).
- The site records every POST body. The mark reads the browser clock once the page
  shows `about:blank`.
- Both tests assert that no tick the server received (and, for the spider, no tick it
  captured) was sent after that clock. The arrival-order slices and the `<= 2` bounds
  are gone.
- `test_the_send_time_oracle_sees_a_document_left_alive` proves the new oracle on the
  defect it guards: with the `about:blank` step removed, ticks carry send times after
  the mark.

Result: both tests and the proof passed 3 of 3 runs with 12 CPU-bound processes, the
load that produced the failure.

## Recurrence review
- **BUG-0144 / PA-0150** (2026-10-15): the same class. An exact count raced a second
  actor (the supervisor) under load. PA-0150 says to assert counts or orders only for
  actions the test alone performs, or to assert the outcome.
- **BUG-0135 / PA-0135:** wall-clock ratios under load. The same family: a
  scheduling-dependent oracle.
- **BUG-0143 / PA-0149(2):** a failure seen only under load must be reproduced before
  it is set aside. That is how this one was investigated instead of re-run.

## Prior-preventive-action failure analysis
**PA-0150 was not enforced and did not reach this test.** Its only enforcement is the
one test it fixed. It was written after these tests already existed (BUG-0137, commit
`3b29669`, 2026-10-14), and its PA-0002 sweep looked for exact counts of processes, not
for orders of requests from concurrent actors. Nothing checks a test's oracle shape, so
the rule depended on a reader recognising the class.

## Preventive action
PA-0511 (strengthens PA-0150): an absence claim about a concurrent actor ("nothing was
sent after the mark") is judged by a stamp the actor gave the event when it acted (its
clock, or a sequence it assigned), never by where an observer's log received it. An
AST guard (`tests/test_no_arrival_order_oracle.py`) fails on an assertion that tests
membership in, or counts, a log sliced from a mark. It is proven on this bug's own
lines.

The PA-0002 sweep (every test that slices a log after a mark): only the two tests above.
`tests/test_redirect_scope_sweep.py` compares a slice of a single-threaded fake's log
to an exact sequence. That fake has one actor, so it is not this class.
