# BUG-0523 — An unplaceable stored-XSS store was recorded as a negative

- Date: 2026-10-19
- Status: fixed (CC-FUZZ-0103, CC-AUD-0055, CC-UI-0066)
- Severity: medium. A stored-XSS case whose store could not be placed was recorded as a
  plain negative (`checked`). So was any browser-only candidate whose browser could not
  start. Each became a scored negative and an ML training negative for a case the only
  deciding mechanism never ran. This contradicts FR-FUZZ-47 ("the executor gives no
  verdict before starting a browser"; "never a negative").

## Description
Two defects combined.
1. `PlaywrightBrowserExecutor.run` refuses a placement before any browser starts, and
   returned the refusal as an observation, `ExecObservation(False, detail="unplaceable
   …")`. The refused cases are a store in a header, cookie, path or fragment; POST, PUT
   or PATCH to `query`; GET or DELETE to `body`/`json`; and a JSON store with no leaf.
   Its only reader, `_BrowserXssStrategy.confirm`, takes that as "observed, not
   executed". It tried all six payloads (six refusals) and returned `None`, which is
   `not_confirmed`.
2. Even with the refusal raised, `Oracle._confirm_outcome` counted any mechanism's
   placement as a check. On a stored case's page the reflected-XSS probe was placed and
   did not confirm, so the candidate was `checked`. The same happened for a ground-truth
   DOM point whose browser could not start (BUG-0126's state).

## Where encountered
DG-M6M8's survey (Q1). It was reproduced on `685259e` through
`Oracle(browser=PlaywrightBrowserExecutor()).confirm_outcome(...)` and through `run_auto`
with a ground-truth store point in a header and in a path:
- the candidate was `checked`, with `oracle_rejected` 1;
- the trace disagreed with itself: `test.strategy` said `not_confirmed`, while six
  visits ended `unplaceable`.

## What it caused to fail
FR-FUZZ-47 and FR-FUZZ-45 (never a silent negative); PA-0115(1); PA-0126(3); the scoring
and ML negatives of such cases.

## What the bug was identified to be
A refusal returned as an observation. And a candidate built for one mechanism, judged by
a mechanism that does not address it.

## Root cause analysis
**Method: Five Whys.**
1. **Why was an unplaceable store a negative?** The strategy read the executor's
   refusal as "not executed".
2. **Why did the executor return it?** BUG-0115's corrective action ("the browser
   executor refuses an unplaceable observe or store location before starting a
   browser") was built as a returned `ExecObservation(False)`. PA-0115(1) said "raises
   `UnplaceableLocation` or gives no verdict", and a returned not-executed looked like no
   verdict from the producer's side.
3. **Why was that not caught?** PA-0115's enforcement (`test_sender_conformance`)
   covers senders, not executors. Three tests asserted `not obs.executed` for a refusal
   at the producer, which pinned the defect, and none checked the candidate's final
   status.
4. **Why did the candidate stay a negative once the refusal was raised?** "Placed" in
   `_confirm_outcome` meant placed by any mechanism. FR-FUZZ-47 defined "unplaceable"
   only for a candidate no mechanism could place.
5. **Why does that matter?** A stored case or a DOM-only point is decided by its
   browser mechanism alone. Another mechanism's not_confirmed on its page answers a
   different question.

**Root cause:** no-verdict was judged where it was produced, not where it was consumed,
and a candidate's deciding mechanism was not recorded anywhere the oracle could read.

## Corrective action
CC-FUZZ-0103, CC-AUD-0055 and CC-UI-0066:
- the executor raises `UnplaceableLocation` for each refusal;
- the point builder names the deciding mechanism (`decided_by`, scoped to its category
  by the auditor, FR-AUD-30), and the pipeline keeps it only when every row of a key
  agrees;
- one oracle predicate (`_decides`) counts only the decider's placement (a strategy with
  no arm decides no candidate that names one), reports a missing decider, and prefers
  the decider's reason;
- `test.strategy` records `decides`, and the diagram notes a non-deciding run and does
  not count it as evaluated.

Tests: `tests/test_unplaceable_confirmation.py` (new). Each fails on `bf1356a` or with
its own part reverted (CC-FUZZ-0103's effectiveness). The five pinning tests now expect
the raise.

## Recurrence review
- **BUG-0115 / PA-0115** (refuse, never relocate). The executor's refusal from that fix
  is this bug's first half.
- **BUG-0126 / PA-0126(3)** (a browser that cannot start is no verdict) and
  **BUG-0137 / PA-0137(1)** (a mechanism's external failures are no verdict). They
  mapped the browser's failures to `UnplaceableLocation`, but not its refusals, and
  neither checked the candidate's final status: here, a stored case with no browser
  was still `checked`.
- **BUG-0147 / PA-0153** (a probe without a response is no verdict). It is the same
  "never a negative" class, applied at the oracle; it is not affected.

## Prior-preventive-action failure analysis
- **PA-0115(1)** offered "raises `UnplaceableLocation` or gives no verdict". The second
  branch was satisfied at the producer by a returned `executed=False`, which the
  consumer reads as an observation. Its enforcement (`test_sender_conformance`) covers
  senders only. So the rule was too loose (it gave a choice of form) and enforced on the
  wrong layer (the producer, not the consumer).
- **PA-0126(3) and PA-0137(1)** were stated per mechanism ("a browser that cannot start
  is no verdict"). They were enforced by the mechanism raising, never by the
  candidate's final status, which another mechanism could still turn into a negative.

## Preventive action
PA-0523 strengthens PA-0115(1) and PA-0137(1):
1. a refusal is raised, never returned as an observation, and "no verdict" is checked
   at the consumer (the candidate's final status);
2. a candidate built for one mechanism is decided only by it, within its category
   (FR-AUD-30); another mechanism's placement may confirm it but never makes it a
   negative.

It is enforced by an AST guard over every executor (an exact allowlist of
"observed, no hit" returns) and by `run_auto` tests over every category.

**Sweep (PA-0002), by primitive:**
- every `BrowserExecutor` implementation in `fuzzlab/`: `PlaywrightBrowserExecutor`
  (fixed) and `FakeBrowserExecutor` (refuses nothing);
- every reader of `ExecObservation` / `NotObserved` (`_BrowserXssStrategy` only);
- every point a browser mechanism alone decides (stored cases, ground-truth DOM points):
  fixed.

**Stated gap:** a stored case whose observe point is also an ordinary point, so the rows
of the key disagree, keeps today's behaviour.
