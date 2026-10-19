# BUG-0510 — The trace took a PRG follow-up's observation for its send, and a run counter for an exchange's re-sends

- Date: 2026-10-19
- Status: fixed (CC-FUZZ-0100)
- Severity: medium. The diagrams' evidence model left out requests the tool really sent,
  and over-counted another exchange's re-sends. No verdict, count or send was wrong,
  but the trace, whose whole claim is "every send, as it happened" (FR-FUZZ-60,
  `docs/DIAGRAMS.md`), was not complete.

## Description
`harness.tracing.TracingSender` (CC-FUZZ-0099) records each send as an `exchange`
event, and a PRG follow-up as its own `exchange` (role `follow-up`, `parent` = the
probe). It decided whether a follow-up had been sent from `Probe.followed`. That field
is the follow-up's **observation** (FR-FUZZ-49): it is `None` when the follow-up was sent
but was answered by another redirect, timed out, or got no response (`prg =
"unobserved"`). Those follow-ups went out and were never recorded.

Reproduced on ede72b9, with a loopback app that answers the POST with a 303 to `/next`
and `/next` with a 302:

```
prg: unobserved   requests the server saw: ['/f', '/next']
exchange events: ['probe']
```

The PA-0002 sweep found a second instance of the same class in the same file. The
exchange's `resent` copied `Probe.resent`, which is a **run counter**:
`RequestsProbeSender._follow` adds the follow-up's re-sends into it (BUG-0147). A probe
answered on its first try, whose follow-up was re-sent once, was recorded with
`resent: 1`.

## Where encountered
While building FR-FUZZ-61 (each HTTP try as its own evidence). The lane had to
attach a follow-up's tries to the follow-up's exchange, and found that the exchange
did not exist when the follow-up was not an observation.

## What it caused to fail
- `fuzzlab diagram`, the web Diagrams page and the JSON export: a PRG follow-up
  answered by a second redirect, timed out (anonymous sender) or unobserved was
  missing from the test's and the exchange's sequence and from the testing overlay. The
  lost arrow `docs/DIAGRAMS.md` promises for "a response that never came" was never
  drawn for it.
- Coverage: the follow-up target's interface did not count that send.
- The exchange's `resent` overstated the probe's own re-sends whenever its follow-up was
  re-sent.

## What the bug was identified to be
The trace derived two facts about sends from fields that summarise them for another
consumer:
- "a follow-up was sent" from `followed`, the verdict's observation;
- "this exchange was re-sent N times" from `resent`, the run's request counter.

Neither field was written to say what the trace needed, and each also encodes
something else.

## Root cause analysis (Five Whys)
1. Why was the follow-up missing? `TracingSender` emitted it only when
   `probe.followed` was set.
2. Why was that the test? `followed` was the only record of the follow-up that the
   senders exposed. A sent follow-up that was no observation left only `prg =
   "unobserved"` and a counter.
3. Why did the senders expose only the observation? `Probe` was designed for the
   oracle (FR-FUZZ-49). The trace was added later around the sender. It read what was
   already there instead of having the sender record the send where it happens.
4. Why was the gap not caught? The trace's end-to-end test (`tests/test_diagram_e2e.py`)
   had one redirect, whose follow-up was observed. No test compared the events with
   what the server received.
5. Why no such comparison? The design treated "reads the sender's result" as
   equivalent to "records the send". The same assumption sat behind the stated limit
   for re-sends: they were counted from `resent` because the senders did not expose
   each try.
   **Root cause:** evidence of an action was reconstructed from fields that summarise
   the action's result for other consumers (an observation, a run counter), not
   recorded where the action happens. And the evidence producer was never checked
   against a count the target itself made.

## Corrective action (CC-FUZZ-0100)
- `oracle.probe.Probe.prg_sent`: the follow-up the sender sent, observed or not (`url`,
  `outcome`, `status`, `elapsed_ms`, `error`, `attempts`). Both senders set it in
  `_follow`, where the follow-up is sent:
  - `RequestsProbeSender`: response, timeout or unobserved;
  - `SeamProbeSender`: response, or unobserved when its try reached the transport.
  `followed` and `prg` are unchanged.
- `TracingSender` emits the follow-up from `prg_sent`, and falls back to `followed` for
  a sender that keeps no record.
- The exchange's `resent` is `attempts - 1`, from the tries the sender recorded
  (FR-FUZZ-61). `Probe.resent` (the run counter) is still used, unchanged, for the run's
  `requests` and for a sender that records no tries.
- Tests (`tests/test_trace_attempts.py`):
  - `test_a_follow_up_that_was_no_observation_is_still_recorded`: a second redirect, and
    a follow-up never answered;
  - `test_a_follow_ups_retry_is_parented_to_the_follow_up`: own `resent` per exchange;
  - `test_the_seams_follow_up_with_no_response_is_recorded_as_sent`;
  - `test_run_auto_records_every_try_and_changes_no_count_or_verdict`: through
    `run_auto`, the server's request count equals the recorded tries and the run's
    `requests`. The run's counts and verdicts are the same with the trace on and off.

## Recurrence review
- `docs/bugs/`: no earlier bug in the trace. It landed the same day (CC-CORE-0063,
  CC-FUZZ-0099). BUG-0147 introduced `Probe.resent` as a counter for the run's
  requests, and correctly used it as one. This bug is a second reader that took it for
  something else.
- `docs/PREVENTIVE_ACTIONS.md`:
  - **PA-0078** (BUG-0077): "Never reconstruct a count from parameters that also encode
    something else." This is the same root cause: the exchange's `resent` was
    reconstructed from a counter that also encodes the follow-up's re-sends, and "a
    follow-up was sent" from an observation that also encodes whether it observed
    anything.
  - PA-0071 / PA-0089 (a reader depends only on what production writes): related, not
    the same. Production did write these fields, but for another meaning.
  - PA-0083(1) (a safety gate sits at the action it guards): the same principle,
    applied to gates only.

## Prior-preventive-action failure analysis
PA-0078 (from BUG-0077) did not prevent this, for two reasons:
- **Too narrow.** It was written for a displayed count, the bandit panel's pulls. Its
  enforcement is that one panel's test. An evidence producer (an event, not a display)
  and a presence fact ("was it sent?", not a count) fell outside its wording, so nobody
  writing the trace would have read it as applying.
- **Not enforced as a class.** No guard compares a recorder of actions with an
  independent count of those actions. The trace's own test checked shapes (a reset is
  drawn lost, a redirect has a target), not completeness.

## Preventive action
PA-0510 (strengthens PA-0078 from displayed counts to every evidence record; related:
PA-0083(1)):
1. **Evidence of an action is recorded where the action happens, by the code that
   performs it.** It is never reconstructed from a field that summarises the action's
   result for another consumer (an observation, a verdict input, a run counter). When
   the actor exposes no such record, add one to the actor. Do not infer it.
2. **An evidence producer is tested against an independent count of the actions**: the
   number of requests a loopback server received equals the number of recorded tries,
   end to end through the real pipeline, with at least one case for each way an action
   can fail to produce its usual result (a re-send, a redirect that is no observation,
   no response).

PA-0002 sweep (by mechanism: every trace producer's reads):
- `harness.tracing.TracingSender`, the follow-up: fixed (`prg_sent`).
- `harness.tracing.TracingSender`, `resent`: fixed (`attempts - 1` when tries are
  recorded).
- `TracingSender`'s outcome from `probe.status == 0`: the anonymous sender's documented
  timeout record, made at its try loop. Not this class.
- `oracle.oracle` `test.strategy` and `finding` events: verdicts recorded by the code
  that decides them, citing `trace.collected()` keys recorded at each send. Not this
  class.
- `tools.store_adapter` discovery events: written from each imported row as it is read.
  Not this class.
- Residual, not a trace field: `Probe.prg_sends` counts a seam follow-up whose copy
  re-login got no response as sent, although nothing went out. It is a cost counter
  (the run's `requests`), and this change leaves counts alone. Recorded for the owner.
