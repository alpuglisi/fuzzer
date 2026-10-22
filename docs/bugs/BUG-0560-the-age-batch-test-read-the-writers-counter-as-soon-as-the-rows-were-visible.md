# BUG-0560 — The age-batch test read the history writer's counter as soon as the rows were visible

- Date: 2026-10-22
- Status: fixed (test-only; CC-PROXY-0032)
- Severity: low. A test defect with no product impact. It failed one targeted run of
  the REDACTURL lane. Under the old habit it would have been called "flaky" and re-run.

## Description
`tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age` (BUG-0550,
CC-PROXY-0030) submits two flows to a `HistoryWriter` whose batches are cut only by age
(`flush_seconds=0.2`). It polled until both flow rows were visible in the store, then
asserted at once:

```python
assert _until(lambda: len(_urls(store, run_id)) == 2)
assert sum(sizes) == 2 and h.stats["written"] == 2
```

The writer thread publishes one batch in three steps, in this order:

1. the flow rows: `HistoryWriter._write` inserts them and commits;
2. their trace events: `HistoryWriter._trace`, through `TraceRecorder.flush`, a second
   commit;
3. the counter: `_Pump._write` adds to `stats["written"]` under `cond`, after
   `_write_prepared` returns.

The live `run_metrics` (`history_*`) come fourth (`_Pump._metrics`). The test waited
for step 1 and read step 3. A read between the two sees the rows and a counter of 0.

## Where encountered
The REDACTURL lane's targeted run (round 2) on the gaps merge stack: the test failed
once. The lane root-caused it rather than re-running it (PA-0149(2)):
`/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/lanes/REDACTURL/r2/age_race.py`
and its log `.../lanes/REDACTURL/r2_age_race.log`. No redaction code runs in the
window, so the lane's change did not cause the failure.

## What it caused to fail
That test, intermittently. There was no product impact: once a batch is done, the
rows, the trace events and the counter all agree.

## What the bug was identified to be
Three measurements:

1. **The lane's injection.** A 0.3 s delay in `_trace` (after the commit, before the
   counter) failed the test 5 of 5 times. Without the delay it passed 5 of 5.
2. **This change's proof.** Plain Python, the test function called directly with a
   real `pytest.MonkeyPatch` per run:
   `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/age-race/age_race_proof.py`,
   log `.../age-race/age_race_proof.log`.
   - The pre-fix test (`bd20bb5`), with no delay, failed 1 of 5 times: the first run in
     the process. With a 0.3 s delay it failed 5 of 5.
   - The fixed test passed 5 of 5 times with no delay and 5 of 5 with 0.3 s.
3. **The natural window.** `_trace` was timed on each writer's first batch
   (`.../age-race/trace_window.py`, `.../age-race/trace_window.log`, 3 fresh
   processes, 5 writers each).
   - The first writer in a process took 6.9-9.3 ms. Its `_trace` imports
     `fuzzlab.core.trace` lazily and builds the writer's `TraceRecorder`.
   - Later writers took 1.2-5.6 ms.
   - `_until` polls every 10 ms, so a poll often lands inside that window. The test
     is most exposed when it is the first to trace in its process, which a parallel
     targeted run can arrange. That fits the unforced failure on the first run in
     measurement 2.

## Root cause analysis
**Method: Five Whys.**

1. *Why did the assertion fail?* `h.stats["written"]` was 0 when both rows were
   visible.
2. *Why was the counter 0 while the rows were visible?* The writer thread moves the
   counter after the rows' commit and after `_trace`, which commits again. Between the
   two, the rows are visible and the counter has not moved.
3. *Why did the test read the counter in that window?* It waited for one publication,
   the rows, and then read a later one, the counter, as if both had happened by the
   time the wait ended.
4. *Why did the test treat them as one event?* It took "the writer wrote the batch" to
   be one moment. In fact the writer publishes a batch in several ordered steps, and a
   presence wait proves only the value it polled. The module's `_until` helper cites
   PA-0511 ("poll a presence claim, never an absence one"). PA-0511 is about how to
   judge an absence claim; it says nothing about which values a presence wait covers.
   Nothing stated the writer's publication order for its consumers.
5. *Why did nothing catch it?* PA-0511 and PA-0150 are each enforced on other shapes:
   a log sliced from a mark, and the exact count of a supervisor's kills. No guard
   checks that a read after a wait is of what the wait observed. The window is
   milliseconds wide, so the test passed in almost every run.

**Root cause:** the test synchronised on one publication of a concurrent writer (its
committed rows) and then read a later publication (its counter), with nothing ordering
the read after the counter. A presence wait proves only the value it polled, and what
the writer published before that value.

## Corrective action
In `tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age`:
- The test now polls `h.stats["written"] == 2`, the last of the three publications, as
  a presence claim (PA-0511).
- After that it asserts the rows. The assertion is now the exact URLs in order, not a
  count.
- Then it asserts the batch sizes. The spy appends a size before its batch's commit,
  so the sizes are complete by then.

No product code changed (CC-PROXY-0032). The proof is measurement 2 above: the delay
injection fails the pre-fix test every time and passes the fixed test every time.

### Sweep (PA-0002)
The sweep went by publication, not by symptom. It covered every read of the writer's
counters, trace events or `run_metrics` that follows a wait, in every test module that
drives `HistoryWriter` or `ProxyController`. That is 21 modules:
`test_loopback_listeners`, `test_proxy_history`, `test_proxy_history_writer_thread`,
`test_proxy_intercept`, `test_proxy_intercept_live`, `test_proxy_redaction`,
`test_proxy_repeater`, `test_proxy_rules_and_scope`, `test_proxy_server`,
`test_proxy_trace`, `test_proxy_upstream_and_flush`, `test_proxy_ws`,
`test_storage_redaction`, `test_web_frontend`, `test_web_intercept`,
`test_web_launcher_browser`, `test_web_proxy_history`, `test_web_proxy_serve`,
`test_web_repeater`, `test_web_scope` and `test_web_store_locks`.

- `test_proxy_history_writer_thread.py`:
  - **`test_a_batch_is_cut_by_age`:** the only instance. Fixed above.
  - **`test_a_batch_is_cut_by_count` and `test_a_batch_is_cut_by_bytes`:** these poll
    the counter itself, and read the sizes after `close`. Safe.
  - **`test_a_full_queue_drops_are_counted_reported_and_written_live`:**
    - Its `stats` read comes before any wait. It reads only `accepted`, `dropped` and
      `dropped_bytes`, which `submit` sets on the test's own thread.
    - It polls `run_metrics`, then reads `reports`. The warning is logged before the
      metrics commit (`_metrics` calls `_log_counts` first).
    - Safe.
  - **`test_a_failing_write_is_retried_then_counted_and_later_flows_still_write`:**
    - It reads `stats` after `flush()`. `flush()` waits on `finished`, which moves in
      the same critical section as the counters.
    - It polls `run_metrics`, then reads `reports`. The error is reported before the
      counter moves.
    - Safe.
  - **Every other test:** reads after `close`, after `ProxyController.stop`, or after
    the process exits. Safe.
- `test_proxy_trace.py`: the `proxied` fixture polls the trace-event count and reads
  that same count. This is the same publication. Safe.
- The other 19 modules write synchronously (`record`, then `flush`), wait for
  something that is not one of the writer's publications (the interceptor's pending
  queue, a server's start, a peer's close), or read after a drain or a close. Safe.

The new guard (below) confirms this sweep. After the fix it finds 0 offenders in the
21 modules. On the pre-fix file it reports exactly one line:
`pre-fix:237:test_a_batch_is_cut_by_age: reads stats after waiting for rows`.

## Recurrence review
Checked: `docs/bugs/` for test races and scheduling-dependent oracles (a search for
race, counter, stats, presence and `_until`), and `docs/PREVENTIVE_ACTIONS.md` for
rules on waits, polls and concurrent actors.

- **BUG-0511 / PA-0511 (2026-10-19).** The same root-cause family: a test oracle that
  depends on the timing between two concurrent actors. PA-0511 covers absence claims
  judged by arrival order. This module's `_until` helper was written to PA-0511, and
  its docstring cites it.
- **BUG-0144 / PA-0150 (2026-10-15).** The same family. An exact count raced a second
  actor. PA-0150 says to assert counts only for actions the test alone performs, or to
  assert the outcome. Here the counter is moved by another actor, the writer thread.
- **BUG-0135 / PA-0135 and BUG-0526 / PA-0526.** The same family, in a different shape:
  wall-clock oracles under load.
- **BUG-0550 / PA-0550.** The change that introduced the writer thread and this test.
  Its rules govern the product's writer (bounded, draining, counted). They do not cover
  how a test synchronises with it.
- **PA-0149(2).** Followed: the failure was reproduced deterministically before it was
  fixed. It was not set aside.

Result: this is a recurrence of the root-cause family of BUG-0511 and BUG-0144: an
oracle that reads a concurrent actor's state without synchronising on the value it
reads. It is not a recurrence of either bug's exact shape.

## Prior-preventive-action failure analysis
- **PA-0511 (BUG-0511) was too narrow, and it was followed in letter only.**
  - It says how to judge an absence claim (by the actor's stamp). It says nothing about
    what a presence claim proves.
  - The author of this test followed it: the wait is a presence claim, and the helper's
    docstring cites PA-0511. But the wait was on the wrong value, so the rule gave false
    assurance.
  - Its guard (`tests/test_no_arrival_order_oracle.py`) finds membership tests and
    counts over a log sliced from a mark. That shape is not this one, so the guard
    could not see this test.
- **PA-0150 (BUG-0144) was not enforced in this shape.**
  - Its only enforcement is the test it fixed. BUG-0511 already found that, and
    strengthened PA-0150 toward stamps for absence claims, not toward reads after a
    wait.
  - The counter here is moved by another actor. The test asserted an exact value of it
    without synchronising on it. Nothing checks a test's synchronisation against what
    it reads.
- **PA-0550 (BUG-0550) did not state the publication order to consumers.** It
  introduced a writer that publishes one batch in several ordered steps (rows, trace
  events, counter, metrics). Neither the rule nor the test module named that order, so
  nobody writing a test against the writer could know which value to wait on.

## Preventive action
**PA-0560**, which strengthens PA-0511 and PA-0150:
1. **A wait on a concurrent actor proves only the value it polled, and what the actor
   published before that value.**
   - A test that reads several of an actor's results waits on the one the actor
     publishes last, or on the actor's own drain or close. Only then does it read the
     others.
   - A read of a value the wait did not cover is a race, however short its window.
2. **When an actor publishes one unit of work in several steps, the steps are listed in
   order next to the guard that checks its tests.** The guard flags a read of a later
   step after a wait on an earlier one. It is proven on the bug's own lines and on
   synthetic offenders (PA-0034(2)).
   - For the proxy history writer, the order is rows, trace events, `stats`,
     `run_metrics` (`_PUBLISHED` in `tests/test_proxy_history_writer_thread.py`). The
     guard covers every test module that drives `HistoryWriter` or `ProxyController`.
3. **The sweep goes by the actor's publications, not by the failing assertion.** It
   reads every value of the actor that a test reads after a wait.

The guard's limits:
- It knows only the history writer's publications.
- It treats any `close`, `aclose`, `flush`, `drain` or `join` as a wait for everything,
  whatever the receiver. That makes it lenient, never strict.
- It recognises a poll as a call named `*until*`, or as a loop that sleeps.
- It follows a module's own helpers by name.

- Enforced by: tests/test_proxy_history_writer_thread.py::test_no_history_test_reads_a_later_publication_than_it_waited_for, tests/test_proxy_history_writer_thread.py::test_the_read_after_visible_guard_on_synthetic_code, tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age
