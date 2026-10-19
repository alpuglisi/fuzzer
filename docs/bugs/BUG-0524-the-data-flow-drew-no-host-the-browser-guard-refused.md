# BUG-0524 — The data flow drew no external host the browser guard refused

- Date: 2026-10-19
- Status: fixed (CC-AUD-0054)
- Severity: medium. The diagrams' "external hosts the browser asked for" (DIAGRAMS.md)
  were empty for a capture whose out-of-scope requests were all refused in the browser,
  which is every capture measured.

## Description
`tools/observe.py::observe_disco` recorded refused hosts only from the capture proxy's
stats (`capture.jsonl.stats.json` `blocked`). The guarded browser (navguard, the first
layer of three) refuses an out-of-scope request before it reaches the proxy, and counts
it in the explorer's report (`explore.py::_count_out_of_scope` → `explore.json`
`explore.out_of_scope`). Nothing read that count into the trace.

## Where encountered
DG-LIVEDISCO phase 1, measuring the capture before designing the live trace (CLAUDE.md
#8). In 7 loopback captures of the `tests/test_disco_e2e.py` fixture, the proxy's
`blocked` was `{}` every time, while the browser guard refused the fixture's other
origin 22–41 times (`{"127.0.0.1": 22}` with 1 worker, `{"127.0.0.1": 38..41}` with 4).
Found as §Q2 of DRAFT-LIVEDISCO and put in scope by the coordinator.

## What it caused to fail
The data flow (FR-UI-510) and its exports showed no external reference for a capture
whose page referenced another origin. The `observe.external` vocabulary and the
reducer's refused, never-sent flow existed, but this layer never fed them. The CLI's
summary line ("refused out of scope") already merged both layers, so the CLI and the
diagram disagreed.

## What the bug was identified to be
An evidence consumer read one of two layers that record the same kind of action (a
request refused by scope): the proxy's summary, but not the guard's.

## Root cause analysis
Five whys:
1. Why were no hosts drawn? `observe_disco` read only `capture.jsonl.stats.json`.
2. Why only that file? CC-AUD-0050 took "hosts the scope refused" from the capture
   proxy, the component named in the capture's own docstring as the scope firewall. The
   browser guard and the launch arguments are the other two layers (`recorder.py`,
   PA-0123(1)), and they were not considered as evidence sources.
3. Why did no test show it? CC-AUD-0050's test wrote the stats file by hand, with
   `{"blocked": {"evil.example.com": 3}}`. The real-capture test
   (`test_the_real_capture_builds_the_diagram_model`) asserted on interfaces and
   workflows, never on external hosts. No real run's refusals were counted against the
   trace.
4. Why was no independent count used? PA-0513 ("an every-X claim is verified against an
   independent count on a run exercising every configuration creating an X") was
   written for sends, and was not applied to observations.
5. Why does it matter which layer? The layers refuse in order: the first refusal wins,
   and the later layers never see the request. A consumer of only a later layer sees
   only what the earlier ones let through.

**Root cause:** an observation was taken from one of several layers that produce it,
chosen by the component's name ("the scope firewall") instead of by where the action
happens. It was never checked against an independent count from a real run.

## Corrective action
CC-AUD-0054:
- `observe_disco` emits one `observe.external` per host in `explore.json`
  `explore.out_of_scope`, with key `<tag>:guard:<host>` and body
  `{"src": "browser-guard", "host", "count"}`. This is its own key: sharing the proxy's
  `…:external:<host>` would make `INSERT OR IGNORE` drop one of the two.
- Both layers count by hostname, and the reducer keeps a host's two counts as a set
  (documented in FR-AUD-28; `explore.py` was not changed, because nothing disco captures
  may change).
- Tests:
  - `tests/test_disco_livetrace.py::test_both_refusal_layers_are_traced_under_their_own_keys`.
    On the old code it fails with "KeyError: 'disco:8053220071:guard:cdn.example'".
  - The guard-count assertion in
    `::test_a_real_capture_is_in_the_store_while_it_runs_and_unchanged`: a real
    Chromium through mitmdump, each `…:guard:<host>` count equal to `explore.json`'s.

## Recurrence review
I checked `docs/bugs/` (BUG-0510, BUG-0512, BUG-0513 and BUG-0515, the diagrams series)
and `docs/PREVENTIVE_ACTIONS.md` (PA-0510, PA-0512, PA-0513, PA-0515, PA-0123).

- **BUG-0513 / PA-0513 is the same root cause one class over.** "Every send" was
  instrumented at one sender, and the peer and unauthenticated senders were never
  traced.
- **BUG-0510 / PA-0510(1)** ("evidence of an action is recorded where the action
  happens") is related.

## Prior-preventive-action failure analysis
- **PA-0513 was too narrow.** It names an "every X instrumentation claim" and was read
  as being about sends: its enforcement is a cross-account send test. CC-AUD-0050's
  claim, "each host the capture proxy refused", was phrased to match its one source, so
  it never read as an "every X" claim at all. The diagrams' own claim ("external hosts
  the browser asked for", DIAGRAMS.md) was the every-X claim, and nothing tied it to the
  producer.
- **PA-0510(1) was followed for the proxy's layer.** It does not say what to do when the
  same action has more than one place it can happen.

## Preventive action
**PA-0524** strengthens PA-0513 from sends to every kind of evidence:
1. An observation claim ("every refused host", "every request the browser made") names
   each layer that can produce the observation, and its consumer reads all of them.
2. It is tested against an independent count from each layer, on a real run where an
   earlier layer acts first.

Enforced by:
- `tests/test_disco_livetrace.py::test_a_real_capture_is_in_the_store_while_it_runs_and_unchanged`
- `tests/test_disco_livetrace.py::test_both_refusal_layers_are_traced_under_their_own_keys`

PA-0002 sweep, by mechanism ("a refusal counted at more than one layer"): the legacy
spider's `skipped_out_of_scope` (`tools/spider.py`) is not read by `observe_spider`. It
is its own follow-up item, by the coordinator's decision.
