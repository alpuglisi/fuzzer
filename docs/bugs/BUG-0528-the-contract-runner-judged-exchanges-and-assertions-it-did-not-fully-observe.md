# BUG-0528 — The contract runner judged exchanges and assertions it did not fully observe

- Date: 2026-10-20
- Status: fixed (CC-FUZZ-0105; SP-56 CC-CORE-0069; SP-16 facts CC-SESS-0028)
- Severity: high. A cut, stalled or late 200 passed the case and became the endpoint's
  baseline, hiding later real matches (`body_matches` and the leak patterns are skipped
  when the baseline shows them). A state check that could not be evaluated, or that read
  a 401/404/429/5xx body as the state, never stopped a pass. A setup step's cut or
  login-redirected answer counted as a setup. Every one of these is a false `pass` -- a
  claim that the endpoint behaved -- in the results ledger. Audit defects 15 and 16 (the
  owner's adversarial audit of 6552276, confirmed in F-096).

## Description
`fuzzlab/disco/runner.py` (FR-FUZZ-52) treated "a status line arrived" as "the answer
arrived":
1. `Runner.send` (lines 288-328 at 8100959) recorded a body failure while keeping the
   status; a stalled or cut body after a 200's headers kept `status == 200`. The
   in-read deadline set `timed_out` but kept the status. `resp.close()` (line 317) was
   skipped on a raise.
2. `judge` (lines 420-462) treated only `status is None` as "no response". An
   incomplete 200 was matched as if whole, passed, and became the endpoint's baseline
   (lines 459-461). A timeout before the headers matched any `latency_ms_gt` rule, even
   one above `timeout_ms`, and a connect timeout (nothing sent) counted as latency.
3. A setup step (lines 379-383) accepted any status below 400: a cut body, or a failed
   form login redirected back to its login page.
4. `_state_check` (lines 473-482) returned None when it could not evaluate (not JSON,
   path missing, not prepared, refused at the send) -- and `judge` acted only on False
   (lines 456-458) -- and evaluated a 401/403/404/429/5xx body as if it were the state.
5. Evidence wrote an incomplete body; the redactor keeps a cut JSON body it can only
   sniff (served `text/plain`, measured), secret included.

## Where encountered
The owner's adversarial systems audit of 6552276 (defects 15 and 16), confirmed against
the source (F-096), then measured at 8100959 on the real transport (requests 2.34.2,
urllib3 2.8.0, Python 3.13.16, a loopback socket;
`scratchpad/au_outcome/measure_transport.py`): a 200 cut after its headers
(Content-Length short or chunked cut) raises `ChunkedEncodingError` while iterating; a
stall raises `ConnectionError(ReadTimeoutError)`; a drip under the read timeout took
3.01 s against a 1 s deadline. In every case `Runner` returned `pass` and admitted the
answer as the baseline. 42 of the 54 Phase-1 tests in
`tests/test_disco_runner_outcomes.py` failed at 8100959 for their stated reason.

## What it caused to fail
- False passes for incomplete exchanges and unevaluated state assertions.
- Baseline poisoning: a later complete answer's leak or `body_matches` match was
  suppressed because the cut answer was the baseline (measured:
  `test_an_incomplete_exchange_never_suppresses_a_later_cases_match`).
- False latency findings from timeouts that prove nothing (a connect timeout; a bound
  above `timeout_ms`).
- A leaked connection on every cut body.
- A possible secret in evidence (a cut JSON body under `text/plain`).

## What the bug was identified to be
The runner had no notion of a *complete* exchange or of a *three-valued* assertion:
"observed" was read off one field (`status is None`), and "not falsified" was read as
"satisfied".

## Root cause analysis
Five Whys:
1. Why did a cut 200 pass? `judge` judged any exchange with a status.
2. Why only the status? The runner's error contract came from SP-34 (`_unobserved`),
   which classifies *exceptions*; FR-FUZZ-52 said "a send with no complete response is an
   `error`", but the code mapped that to "no status", and the exception raised while the
   body was read left the status in place.
3. Why did no test catch it? The runner's tests used `FakeResponse`, whose body always
   arrives whole; no fixture failed the way the real stack fails (status known, body
   cut). PA-0153's guard covered the *probe senders*, not this judge.
4. Why was None from a state check ignored? `assertion_holds` was written three-valued
   (True/False/None) but its caller used it two-valued (`if held is False`), so "could
   not tell" fell through to "pass".
5. Why was there no rule? The project's "never a silent negative" rules (PA-0137,
   PA-0153, FR-FUZZ-45/47/50) are stated for the *oracle's* negatives. A judge that
   produces *positives* (a pass, a baseline, a setup success) had no rule saying a
   positive outcome rests only on complete, evaluated observations.

**Root cause:** a verdict producer outside the oracle (the contract runner) inferred
success from the absence of a failure signal -- a status present, no False -- with no
completeness or evaluation requirement on the observations behind a pass, and no fixture
that reproduced the real transport's partial-failure shape.

## Corrective action
CC-FUZZ-0105 (FR-FUZZ-52 edited in place), on SP-56 (CC-CORE-0069) and SP-16's
`login_facts` (CC-SESS-0028):
- `Exchange.incomplete` / `timeout_kind`; the response closed in a `finally`;
- `judge` classifies first: an incomplete exchange is an `error` unless a read or
  deadline timeout proves a `latency_ms_gt` bound at most `timeout_ms`;
- baselines only from complete application answers below 400 that passed;
- setup steps complete, application, below 400, not a login redirect (an account
  creation's redirect excepted);
- state checks three-valued with a reason; a pass needs every one satisfied;
- evidence of an incomplete exchange writes "omitted (incomplete)" and its byte count.
Tests: `tests/test_disco_runner_outcomes.py` (58), including three on a loopback socket.
Each rule's revert fails its named tests (the lane's per-revert record).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of "success
inferred from the absence of a failure signal" and "a partial response judged as whole":
- **BUG-0023 / PA-0025:** a tool-oracle wrapper inferred `confirmed_secure` from no
  positive match plus a clean exit. Same root cause (a positive outcome inferred from
  the absence of a signal), a different judge.
- **BUG-0048 / PA-0050:** a liveness probe equated "up" with an incidental status. Same
  family: a status read as more than it proves.
- **BUG-0311 / PA-0311(2):** a live assertion on a channel that could not carry the
  violation. The state check that evaluated a 401/429 body is that: the read cannot
  carry the state.
- **BUG-0147 / PA-0153:** no complete response is no verdict -- enforced at the probe
  senders (SP-34) and the oracle, not at the contract runner, which was added later
  (CC-FUZZ-0089) with its own judge.
- **BUG-0101 / PA-0102(1):** a network read has a byte cap and an overall deadline --
  applied to the proxy only; the runner's in-read deadline fires only between chunks.
- **BUG-0137 / PA-0137(4):** with anything unobserved and no evidence, inconclusive --
  stated for confirmation mechanisms, not for a judge's pass.

## Prior-preventive-action failure analysis
- **PA-0025 and PA-0311(2) -- wrong layer, not enforced over a new judge.** Both state
  the right doctrine (verify the observation could carry the outcome), but each is
  enforced only on the judges it was written for (the labgen oracles; ground-truth
  labels). `Runner.judge` (CC-FUZZ-0089, 2026-10-17) was a new verdict producer and
  nothing discovered it.
- **PA-0153 -- enforced at producers, not consumers.** SP-34 classifies the exception;
  the consumer still had to decide what a kept status means. The runner kept the status
  of a cut exchange, and PA-0153's guard (every sender maps a transport failure) does not
  look at a consumer that streams its own body.
- **PA-0102(1) -- not swept.** The overall-deadline rule was applied to the proxy and
  never to the runner's read loop (the drip measured at 3 s for a 1 s deadline).
- **PA-0137(4) -- too narrow.** "Unobserved is never a negative" was written for the
  oracle's negatives; the mirror (unobserved is never a *positive*: a pass, a satisfied
  assertion, a baseline) was never stated.

## Preventive action
**PA-0528** (strengthens PA-0025, PA-0311(2) and PA-0153; text for
`docs/PREVENTIVE_ACTIONS.md`, written by the coordinator at merge):
An outcome that claims something held (a pass, a satisfied assertion, a baseline, a setup
success) rests only on observations that were complete and evaluated.
1. An exchange is complete only when its status, its headers and its whole body arrived
   within its limits. An incomplete one is judged only by what its incompleteness proves
   (a **read** timeout proves latency of at least the limit; a connect timeout proves
   nothing). It is never written to evidence, and the response is closed on every exit.
2. Every assertion is three-valued, with its reason. A pass needs every mandatory one
   satisfied. Each unobserved branch has a fixture whose body would *satisfy* the
   assertion.
3. A new judge or oracle is built against (1) and (2), with fixtures for a cut, stalled,
   late and connect-timed-out answer and an unobservable assertion. Not enforced by a
   test: a judge that does not exist yet has no stable shape to discover (verdict
   vocabularies differ: `pass`, `confirmed_secure`, `CHECKED`); it is applied in review.
   The line below enforces (1) and (2).
- Enforced by: tests/test_disco_runner_outcomes.py::test_an_incomplete_200_is_never_a_pass_nor_the_endpoints_baseline, tests/test_disco_runner_outcomes.py::test_an_unobserved_state_check_is_never_a_pass, tests/test_disco_runner_outcomes.py::test_every_state_check_must_be_evaluated_for_a_pass, tests/test_disco_runner_outcomes.py::test_the_response_is_closed_on_every_exit, tests/test_disco_runner_outcomes.py::test_an_incomplete_body_is_never_written_to_evidence, tests/test_disco_runner_outcomes.py::test_a_connect_timeout_never_proves_latency, tests/test_disco_runner_outcomes.py::test_a_real_200_cut_or_stalled_after_its_headers_is_an_error

**The PA-0002 sweep** (other judges of an exchange's outcome, `grep` over `fuzzlab/`):
- the oracle's strategies and the blind-SQLi builder: BUG-0529 (incomplete and
  non-comparable answers);
- `labgen/identifier_sqli_oracle.py`: already healthy-only (a 2xx, fail closed);
- `greybox/run.py::_screening`, `harness/pipeline.py::_baseline`: no verdict rests on
  them (residual R12, BUG-0529);
- `disco/ede.py`, `tools/spider.py`: discovery baselines, not verdicts;
- `session/detect.py::detect_logout`: defect 6's later item.

**Residuals (stated):** R5 a body over `max_body_bytes` is an `error` (`MATCH_BYTES` is
smaller than the cap); R6 a drip still holds the runner until the server stops (the
verdict is now an `error`; liveness needs a socket shutdown, measured 0.5 s, and belongs
to defect 21's read-deadline owner); R7 a state read answered 404 is unobserved, not a
finding; R8 `assertion_holds` reads a type mismatch as violated; R15 strict
incompleteness drops observed evidence (a cut 5xx's status, a match in the received
bytes) -- in tension with PA-0137(1), decided.
