# BUG-0650 — The M6 quiet-settle early end missed sinks that fire late by events no tracker saw

- Date: 2026-11-20
- Status: fixed (the change withdrawn)
- Severity: high (lost XSS detections; on lane PERF's branch only, never merged into the
  integration branch)

## Description
CC-FUZZ-0650 (lane PERF, commit 48609d1) made the M6 browser executor end its sentinel
wait before `SETTLE_MS` once a page "had gone quiet": no request SP-40 counts in flight,
and no pending timer, interval, animation frame, idle callback or running animation in
any frame, for 500 ms (SP-105, `tools/pagequiet.py`). A payload that fires after that
point was observed as "not executed", a negative.

## Where encountered
The orchestrator's independent verification of lane PERF (a verifier session, real
Chromium 1243 through the real `PlaywrightBrowserExecutor.run()`), 2026-11-20. Every
case below was missed on every repeat; the 4 s window (2be7a50) caught each.

## What it caused to fail
Missed sinks (early end about 0.6 s, sink about 1.0 s unless stated): an SVG `<set
onend>`, `<animate onend>` and `<animate begin=1s onbegin>`; `scheduler.postTask(fn,
{delay: 1000})`; a MessageChannel task chain (React's scheduler); a `window.postMessage`
loop; a `<meta http-equiv=refresh content=1>` to the payload page; a video's
`timeupdate`; a fetch answered after 2.8-3.2 s (SP-40 stops counting a request open
past `LONG_LIVED_MS`); a page that replaces `performance.now` or
`Map.prototype[Symbol.iterator]` after setting its timer (the tracker read them at
check time). Also: the quiet read's `frame.evaluate` had no timeout, so a page whose
main thread is blocked hung the probe (the 4 s wait ended at 4.1 s); popups were not
read though the sentinel is context-wide; a shortened wait was not marked in the result
or the trace, so a miss would have become a confirmed negative for the ML dataset
(PA-0551(3), PA-0137(4)).

The lane's own evidence had not seen any of it: tp/fp/fn/tn were identical on ten lab
configurations (CC-LAB-0371) and the shadow run saw no hit after the would-be end, but
only 2 of its 311 observations were hits. The labs exercise none of these mechanisms.

## What the bug was identified to be
A predicate "nothing left can run this page's script" that is false: a document's
script is run again by many event sources (SMIL animation events, the Prioritized Task
Scheduling API, message ports, `postMessage`, navigation by a meta refresh, media
events, a long-held request) and the tracker watched five of them.

## Root cause analysis (Five Whys)
1. Why were late sinks missed? The wait ended at about 0.6 s on pages whose sink ran at
   1-3 s.
2. Why did it end? `PageQuiet` read the page as quiet: its tracker saw no pending timer,
   request or animation frame.
3. Why did it see none? The sinks were scheduled through mechanisms it did not wrap or
   could not see (SMIL, `postTask`, message ports, refresh, media, a request SP-40
   deliberately stops counting), or it read state the page itself had replaced.
4. Why was a partial tracker trusted? Its tests and the measurement covered only the
   mechanisms it watched (a timer, a fetch, an interval, `requestAnimationFrame`) and the
   labs, whose late sinks are timer- and request-driven; the shadow run had 2 positive
   observations, too few to see a miss of an absent mechanism.
5. Why was that accepted as evidence? **Root cause:** I treated "every hit I measured
   came before the predicted end" as proof that the end loses nothing, for a mechanism
   whose correctness depends on enumerating everything the platform can do -- an
   open-ended set -- and validated it against fixtures drawn from the tracker's own list
   instead of the platform's.

## Corrective action
CC-FUZZ-0651 (this change): the early end is removed. `fuzzlab/tools/browserexec.py` is
restored to its 2be7a50 text (the whole `SETTLE_MS` window, as FR-FUZZ-48 says);
`fuzzlab/tools/pagequiet.py` and `tests/test_pagequiet.py` are deleted; SP-105 is
withdrawn (not reused); FR-FUZZ-650/651 are superseded by FR-FUZZ-653;
`scripts/measure_scan_perf.py` loses its `--shadow-quiet` mode. The verifier's cases are
real-browser regression tests that the full window detects
(`tests/test_m6_slow_sinks.py`), and a deterministic test pins that the wait lasts its
whole window without a hit (`tests/test_m6_window_guard.py`).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for an observation window cut short
and for a classifier validated only on the shapes its author measured:
- **BUG-0126 / PA-0126(2)** -- same root cause: the M6 executor read the sentinel 300 ms
  after `load` and missed Juice Shop's asynchronously rendered sink. PA-0126(2) requires
  "a real-browser check against a page whose sink fires after `load`" and a polled wait
  "up to a stated window". **A recurrence.**
- **PA-0551(2)** -- "a discovery mechanism's fixture covers each way the platform
  presents UI, not only the shapes a measured lab had": the same failure mode, scoped to
  discovery.
- **PA-0507(1)** -- "a rule that classifies names the evidence that separates its
  confusable alternative, measured where that alternative occurs": the quiet predicate
  classified "will run again" vs "will not" and was measured where the alternative
  (late sinks by untracked events) never occurs.
- BUG-0137 / PA-0137(4), PA-0551(3): an unobserved or shortened observation must never
  read as a negative -- the unmarked shortened wait broke that too.

## Prior-preventive-action failure analysis
- **PA-0126(2) was too narrow and its enforcement too specific.** It names one fixture,
  "a page whose sink fires after `load`" (`test_the_m6_executor_sees_a_sink_that_fires_
  after_load`: a 1.2 s `setTimeout`). A design that tracks timers passes it while
  missing every other late mechanism. It forbids a *fixed* short read but says nothing
  about a *computed* early end, so the rule was followed to the letter.
- **PA-0551(2) was scoped to discovery mechanisms** (crawlers); I did not apply it to a
  confirmation mechanism, though the failure mode -- a fixture built from what the
  author's mechanism handles -- is the same.
- **PA-0507(1) was followed in form, not in substance:** the predicate was measured on
  labs, but none holds the confusable alternative, and the shadow measurement had too
  few positives to see one.
- MULTI_AGENT_ORCHESTRATION §7 was followed (I measured), but the measurement's power
  was not stated or checked.

## Preventive action
PA-0650 (strengthens PA-0126(2), extends PA-0551(2) to confirmation mechanisms,
strengthens PA-0507(1)):
1. A confirmation mechanism's observation window ends only on its evidence, its
   deadline or an error, never on a prediction that nothing more can happen.
2. A change that shortens or skips any part of an observation is tested against a
   fixture built from the platform's ways of running work later (for a browser: timers,
   requests incl. long-held ones, animation frames, SMIL and CSS animation events,
   task-scheduling and message-port APIs, `postMessage`, refresh navigation, media
   events, workers, popups), not from the change's own list.
3. A "no detection lost" claim states how many positive observations its evidence
   holds; a shadow or BEFORE/AFTER run with too few positives to see a miss is not
   evidence that nothing is missed.

PA-0002 sweep: the other confirmation windows were checked -- the OOB wait
(`OobListener.wait_for`, `_await_callback`) ends only on a hit or its deadline; the
timing and differential strategies have no observation window; the network-quiet
settles (SP-40) serve discovery and login, not confirmation. No other instance.
