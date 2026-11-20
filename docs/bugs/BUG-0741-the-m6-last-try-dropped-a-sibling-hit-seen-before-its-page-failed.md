# BUG-0741 — The M6 last try dropped a sibling hit seen before its page failed

- Date: 2026-11-20
- Status: fixed (CC-FUZZ-0721)
- Severity: low (detection; a narrow case). After two unobserved payloads, the last-try
  payload's page could fail after one of the candidate's other tokens had fired on it;
  that hit was dropped and the candidate left inconclusive instead of confirmed. Never a
  false positive. Found before the lane merged.
- Records: ERROR_LOG 2026-11-20, PA-0741, CC-FUZZ-0721, F-741.

## Description
CC-FUZZ-0720 gave each M6 payload its own token and made a `NotObserved` carry the
tokens that fired before the page failed (`exc.hits`), so a stored sibling's echo is
credited to its own payload. The strategy's main loop read `exc.hits`; `_last_try`,
the other reader of a `NotObserved` outcome, caught it through its base class
(`except UnplaceableLocation`) and set the observation to None.

## Where encountered
The lane's adversarial-test subagent:
`tests/test_m6_concurrency.py::test_the_last_try_credits_a_sibling_seen_before_its_page_failed[1]`
and `[3]` failed on dc4692d (payloads 0 and 1 `NotObserved`; payload 2's
`NotObserved` carries payload 0's token: expected confirmed, credited to payload 0;
got inconclusive). The control through the main loop passed.

## What it caused to fail
On dc4692d only (never merged): the case above was inconclusive.

## What the bug was identified to be
A new fact on an exception (`hits`) read by one of its two consumers.

## Root cause analysis (Five Whys)
1. Why was the hit dropped? `_last_try` never read `exc.hits`.
2. Why? Its handler was written for the old meaning, "not observed: nothing seen", and
   catches `NotObserved` through `UnplaceableLocation`, so a search for
   `except NotObserved` did not find it.
3. Why was the change not followed there? The agent added the field and its reader in
   the loop it was editing, and did not enumerate every handler that receives the
   exception.
4. Why did no test catch it? No test drove a failed page with a sibling hit through the
   last try; the existing guards check outcomes of the main loop.
- **Root cause:** a change to what an outcome carries was applied to one consumer;
  the consumers were not enumerated (a handler reached through a base class among them).

## Corrective action (CC-FUZZ-0721)
- `_BrowserXssStrategy._failed_hit(exc, payload, payloads, tokens)`: the one reader of a
  `NotObserved`'s hits; the main loop and `_last_try` (a `NotObserved` handler before its
  `UnplaceableLocation` one) both call it.
- Tests: the failing test above; the AST guard below.

## Recurrence review
Same class as BUG-0138 (a fix applied on one consumer path only; PA-0138(3) "follows
the change to every consumer that waits on or reads what it changed") and PA-0002 (sweep
for the class).

## Prior-preventive-action failure analysis
PA-0138(3) did not prevent it: **not followed, and not enforced at this layer.** Its
guard covers navigation and load-state helpers across the package; nothing enumerates
the readers of an exception's fields inside a strategy, and the reader that was missed
caught the exception by a base class, which a name search does not show.

## Preventive action
PA-0741 (strengthens PA-0138(3)): every handler that is the first in its `try` to
receive a `NotObserved` -- by its own name or by a base class (`UnplaceableLocation`,
`Exception`, a bare `except`) -- in the M6 strategy hands it to `_failed_hit`; enforced by
an AST guard proven on BUG-0741's own shape (a base-class handler) and on dc4692d's
code. The sweep: the M6 strategy's handlers (`confirm`, `_last_try`; `_outcomes` stores
outcomes for those two and reads none); outside them no module of `fuzzlab/` names
`NotObserved` but the executor that raises it (grep), and the oracle receives only the
strategy's verdict or an `UnplaceableLocation` the strategy re-raised.
