# BUG-0137 — A page the M6 executor could not load ended confirmation for every remaining candidate

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0083)
- Severity: high for coverage (one bad page silently ended the oracle's work for the
  rest of the run); no safety impact (nothing was sent that should not have been).

## Description
`PlaywrightBrowserExecutor.run` (`tools/browserexec.py`) let any Playwright error from
its context set-up, its stored-XSS plant or its observe `goto` escape: a timeout, a
refused own redirect (`net::ERR_ABORTED`, before BUG-0136 `net::ERR_FAILED`), a crashed
page. Nothing above it contained the exception:
- `DomXssStrategy` / `StoredXssStrategy` call `executor.run` directly;
- `Oracle._confirm_outcome` contains only `UnplaceableLocation`;
- `harness/pipeline.run_pipeline._confirm` contains only `HeaderPointsStopped`.

So the exception ended the confirmation loop. Every candidate not yet reached kept
`pending` (unlabelled, BUG-0071's crash safety), and the run reported only what it had
done so far.

BUG-0136 added a new trigger. A page whose script navigates to a refused URL before
`load` has its navigation aborted with ERR_ABORTED, the page stays, and its `load`
never fires. The observe `goto(wait_until="load")` then waited out its 8 s timeout and
raised.

## Where encountered
BUG-0136's review (X2) measured the M6 semantics on a real browser; the pre-`load` row
timed out and raised. The lane flagged it with the containment gap, and the coordinator
confirmed both as one defect.

## What it caused to fail
- **Coverage:** one candidate whose page could not be loaded ended confirmation for
  every later one. On a real app this is common: a page that redirects to `/logout`
  when the session is missing, an observe URL whose redirect leaves scope, a slow page.
- **Cost:** a page whose load was superseded cost the full `timeout_ms` per payload
  before the raise.
- **Labels:** none wrong (the rows stayed `pending`, never a negative), but nothing
  after the failure was confirmed.

## What the bug was identified to be
The executor had no rule for "the page could not be observed". A launch failure had one
(BUG-0126: no verdict); a page-level failure had none, so it surfaced as a raw exception
to callers that do not contain it.

## Root cause analysis
Five Whys:
1. *Why did the run stop?* An exception from `executor.run` propagated out of the
   strategy, the oracle and `pipeline._confirm`.
2. *Why did the executor raise?* Its observe `goto` (or plant, or context set-up)
   failed or timed out, and nothing in `run` handled a Playwright error after launch.
3. *Why only launch failures?* BUG-0126 fixed the failure it saw ("the browser cannot
   start") and wrote PA-0126(3) for that case. Each probe's own browser work was not
   in its scope.
4. *Why did nothing above catch it?* By design the oracle contains only the no-verdict
   signal (`UnplaceableLocation`), and the pipeline contains only the header breaker.
   Containment is each mechanism's job, so the executor was the only place that could
   map its failures, and it did not.
5. *Why was it not caught by tests?* The executor's real-browser tests covered pages
   that load, and the fake-Playwright tests modelled a launch failure, never a failed
   navigation after launch.

**Root cause:** a confirmation mechanism mapped only one of its external failure modes
(the browser cannot start) to "no verdict"; its per-probe failures (the page cannot be
loaded or observed) had no mapping, and no layer above contains a mechanism's raw
errors.

## Corrective action
CC-FUZZ-0083, in `tools/browserexec.py` only:
- **(a) No superseded load is waited out.** The observe `goto` waits for the commit,
  then `wait_for_load_state("load")` for at most `LOAD_WAIT_MS` (3 s, suppressed), then
  the sentinel wait as before.
- **(b) A failure with no hit is no verdict.**
  - A Playwright error or timeout of the context set-up, the plant or the observe
    navigation raises `UnplaceableLocation` with a reason. The reason is the error's
    class and its text up to the URL; it never includes the URL, which carries the
    payload.
  - So does a page that never reached `load` by the end of the sentinel wait.
  - A hit recorded at any point is executed=True.
  - Only `playwright.sync_api.Error` is caught (PA-0106).
  - `browser.close()` on a dead browser is suppressed, so it cannot replace the
    no-verdict with a raw error.
- **(c)** A launch failure keeps BUG-0126's path.

Reading of the brief, stated: (a) says the bounded load wait is suppressed, and the
brief's test says the before-`load` navigation "gives no verdict". Both hold because a
page that never reached `load` and showed no hit counts under (b) as a timeout of the
observe navigation. A page that loads late (during the sentinel wait) and shows no hit
is still a negative.

Tests:
- `tests/test_m6_navigation_failures.py`:
  - a before-`load` script navigation to a refused URL is no verdict in about 4.7 s
    (it was 8 s and a raise);
  - a hit after such a navigation still counts;
  - a two-candidate `run_pipeline`: the first candidate's own redirect is refused, the
    second is a real DOM sink, and the second is still confirmed;
  - only Playwright errors are no verdict, a `KeyError` propagates, and the reason
    names no URL or payload.
- `tests/test_navigation_aborts.py`: X2's pin (c) is now
  `test_m6_a_target_whose_own_redirect_is_refused_is_no_verdict`.
- Test fakes of `playwright.sync_api` gain `Error` and `wait_for_load_state`
  (`test_browser_scope.py`, `test_destructive_urls.py`, `test_json_points.py`).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0126 / PA-0126(3)** ("a browser that cannot start is no verdict, remembered for
  the run: never a crash, never a negative"). **A recurrence:** the same failure mode
  (a browser failure ends the run) one step later, per probe instead of at launch.
- **FR-FUZZ-45 / FR-FUZZ-47 and PA-0108 / PA-0115** ("never a silent negative"; a
  point a mechanism cannot place is no verdict via `UnplaceableLocation`). These are
  the same contract this fix applies, not a recurrence of their defects; their path is
  the one used here.
- **BUG-0071** (crash safety: rows not reached keep `pending`). It limited the damage
  (no false labels) but is not a containment. Different defect.
- **BUG-0128** (teardown hangs while a page navigates). Same executor, different
  failure (teardown, not observation); its `release` is unchanged.

## Prior-preventive-action failure analysis
**BUG-0126 / PA-0126(3).** It did not prevent this because:
1. **Too narrow.** It named one failure ("cannot start"). The rule was about the
   browser's availability, not about every failure of the external effect the
   mechanism depends on, so a page-level failure fell outside it.
2. **Not enforced past launch.** Its tests faked a driver or launch failure; none
   failed a navigation after launch, so nothing showed the gap.

PA-0137 widens the rule from "the browser cannot start" to "the mechanism could not
observe", requires a test per failure point of the mechanism's external work, and adds
the two-candidate run as the enforcement.

## Preventive action
**PA-0137** (strengthens PA-0126(3); generalises FR-FUZZ-45/47's "never a silent
negative" to a mechanism's external failures), in `docs/PREVENTIVE_ACTIONS.md`.

### PA-0002 sweep (every executor or browser call reachable from `oracle.confirm`)
`Oracle.confirm` → `DomXssStrategy` / `StoredXssStrategy` → `executor.run` is the only
browser path: no other strategy or seam of the oracle drives a browser. The OOB
listener (M8) and the greybox seams are not browsers.

| Call in `PlaywrightBrowserExecutor.run` | Failure | Before | Now |
| --- | --- | --- | --- |
| `sync_playwright().__enter__()` | driver cannot start | no verdict (BUG-0126) | unchanged |
| `chromium.launch` | browser cannot start | no verdict (BUG-0126) | unchanged |
| `new_context` / `expose_binding` / `new_page` / `guard_page` / `page.on` | Playwright error | **escaped** | no verdict |
| plant: `checked_api_request` | `OutOfScope` | cannot fail: the scope is built from the store URL | unchanged |
| plant: `context.request.post` | Playwright error (refused, timeout) | **escaped** | no verdict |
| plant: `page.goto(..., wait_until="load")` | Playwright error, timeout | **escaped** | no verdict; residual: still waits for `load` (below) |
| observe: `page.goto` | refused own redirect, timeout, crash | **escaped** (a superseded load: 8 s, then a raise) | commit-level wait; error → no verdict |
| observe: `wait_for_load_state("load")` | never loads | (not called) | bounded, suppressed; never loaded + no hit → no verdict |
| `_wait_for_token` (`page.wait_for_timeout`) | page or context gone | ends the wait (pre-existing broad `except Exception`) | unchanged; noted below |
| `release(context)` | any | best effort inside (`navguard.release`) | unchanged |
| `browser.close()` | dead browser | **could escape and mask** | suppressed (Playwright errors only) |
| `manager.__exit__` | driver stop fails | could escape | unchanged; residual |

## Residuals
- The stored-XSS **plant** navigation still waits for `load` (only the observe
  navigation was in scope). A plant page whose load is superseded now costs
  `timeout_ms` and then gives no verdict, never the end of the run.
- `_wait_for_token`'s `except Exception` predates PA-0106 and is wider than a named
  list. It only ends the wait (no verdict is invented from it), so it is noted, not
  changed here.
- `manager.__exit__` (the driver's stop) is not contained. A failure there after a
  verdict would still escape; it has not been seen.
- A page that never fires `load` costs `LOAD_WAIT_MS` + `SETTLE_MS` per payload (about
  7 s by default) before its no verdict.

## Review of the fix (added in review)
Reviewers A and B both agreed with changes (D54, Z1–Z6). Both found the same main gap:
the corrective action contained a failure **per candidate** but not **per probe**. One
unobserved payload raised `UnplaceableLocation` out of the strategy's payload loop, so
a later payload that would have fired was never tried. And because that path is "no
verdict from this mechanism", a query point whose other mechanisms ran ended CHECKED,
a negative in the ML data.

- **Z1, per payload:** the executor raises `NotObserved` (a subclass of
  `UnplaceableLocation`) for a probe it could not observe. The strategy tries its next
  payload and stops after 2 unobserved in a row, a stated cost bound. A launch failure
  or an unavailable browser stays the plain `UnplaceableLocation` and stops at once.
- **Z4, inconclusive (decision D54):** no hit with at least one payload not observed
  gives an inconclusive Verdict (`evidence["not_observed"]`), so the FR-FUZZ-45 path
  records the candidate INCONCLUSIVE: unlabelled, never a negative, never in the ML
  negatives. This **supersedes** the corrective action's "other mechanisms still
  decide" for a page that could not be observed. Placement refusals (BUG-0115) and
  "browser unavailable" (BUG-0126) are unchanged.
- **Z2:** the driver's stop is contained (the first residual above is closed). A
  failed stop is logged and never replaces the result; repeated failed stops make the
  browser unavailable for the run.
- **Z3:** the post-`load` settle is a full `SETTLE_MS` from when `load` fires
  (`page.once("load")`), capped at `timeout_ms` + `SETTLE_MS`. Before, a page whose
  load took over 3 s got less than `SETTLE_MS` after it.
- **Z5:** the browser login's password clear (BUG-0136 X3) no longer waits for the
  field (CC-SESS-0023).
- **Z6:**
  - `_wait_for_token` catches only the Playwright error (closes the second residual);
  - pending sentinel calls are pumped before the failure branch reads the hits;
  - hits are read again after the load check;
  - the plant navigation uses the commit and a bounded load too (closes the plant
    residual).

Updated sweep rows (the PA-0002 table above):

| Call | Now |
| --- | --- |
| plant `goto` | commit + bounded `load`; error → not observed |
| observe `goto` / load wait / never loaded | not observed **per payload**; the candidate is inconclusive if nothing hit |
| `_wait_for_token` | only the Playwright error ends the wait |
| `manager.__exit__` | contained by `_stop_driver`; logged; 2 in a row → unavailable |

Remaining residual: an unobservable page still costs up to 2 × (`LOAD_WAIT_MS` +
`SETTLE_MS`) per candidate (about 14 s by default). This is the stated bound
(FR-FUZZ-48).
