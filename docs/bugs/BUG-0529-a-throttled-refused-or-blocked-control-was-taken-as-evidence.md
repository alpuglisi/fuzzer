# BUG-0529 — A throttled, refused or blocked control was taken as evidence

- Date: 2026-10-20
- Status: fixed (CC-FUZZ-0105, CC-CORE-0069, CC-SESS-0028, CC-MUT-0403, CC-SCHED-0007)
- Severity: high. False confirmations: a SQL-error, path-traversal or CRLF finding
  confirmed because its benign control was answered by a throttle, a gateway, a timeout
  stand-in, a refused credential, a login redirect or a block (none shows the marker);
  the differential and NoSQL engines and the ReDoS baseline likewise. False negatives
  (training negatives): an unobserved PRG follow-up, a throttled peer replay, a throttled
  correlated probe, a timed-out timing baseline or a throttled probe ended the mechanism
  as "not confirmed". The live WAF filter recorded a 429 or an unanswered request as a
  bypass. The blind-SQLi builder averaged and labelled non-application samples. In the
  contract runner a 429/503 was judged by its status class and a credentialed 401 or
  login redirect passed a 4xx/3xx expectation. Audit defect 17 (the owner's audit of
  6552276, confirmed in F-096).

## Description
A control, a baseline sample, a compared slot or a replay is evidence only through what
the application did with the value sent. No consumer checked that the answer *was* the
application's:
1. **Oracle, controls and baselines** (`oracle/strategies.py` at 8100959): SqliError
   (the `fz…` controls, line 520), PathTraversal and PathTraversalFsPathRead (the
   `passwd` control, :1221, :1300), HttpHeaderInjectionCrlf (:2823), CrossAccountReplay
   (the owner's request and the other-value control, :1780-1782), the differential
   engine's B0/V/B/D (`_differential`), NoSqlOperator's B/V/D, `_confirm_timing`'s and
   RegexDos's baseline samples read any answer as a comparable one.
2. **Oracle, every response:** a throttled or unavailable answer, or a sender's status-0
   stand-in, was read like any other: a throttled XSS probe or a throttled greybox
   correlated probe was a negative; a connect timeout's status-0 stand-in of the full
   timeout was read as latency by ReDoS (measured through the real
   `RequestsProbeSender`).
3. **PRG follow-ups:** a control's follow-up with no observation (`PRG_UNOBSERVED`) was a
   negative (reviewers A and B, measured).
4. **Replays:** a throttled or credential-refused peer replay was "denied" (a negative).
5. **The live WAF filter** (`mutation/livefilter.py:64, :68`): every non-403 was "allow".
6. **The blind-SQLi builder** (`tools/blind_sqli_fuzzer.py:107-207`): the baseline
   skipped only 504; payload rows were written for any answer.
7. **The contract runner** (`disco/runner.py::judge`): see the severity line.

## Where encountered
Audit defect 17, reproduced at 8100959 (Phase 1): a quote's SQL error, then `429 rate
limited` for the benign control, confirmed. `tests/test_oracle_comparable_controls.py`
had 83 of 100 Phase-1 tests failing at 8100959 for their stated reason (63 false
confirmations, 10 negatives where inconclusive was wanted, 4 filter/baseline "did not
raise", 1 scheduler update, 5 blind-SQLi rows); the runner file's throttle and refusal
rows failed the same way. Reviewer A measured the true-positive loss a status-only rule
would cause (`/j_security_check` and `/register` answer a failed login with a login
redirect); review round 3 measured the over-match of reusing the login window's account
test (`/api/users/42`, `/api/account/billing`, `/rest/user/whoami`,
`/api/orders/42/change-status`).

## What it caused to fail
False findings on throttled, gateway-fronted, logged-out or WAF-protected targets; false
negatives (and ML training negatives) wherever a mechanism met such an answer; false
"bypasses" recorded by `mutate-run`; skewed blind-SQLi datasets; wrong runner verdicts.

## What the bug was identified to be
The negative-evidence mechanisms (a marker *absent* from a control, a slot *alike* or
*unlike* its base, a latency *above* a baseline, a replay *denied*) took the control's
answer as the application's evaluation of the value, with no classification of whether
it was the application's answer at all, and no per-request fact about whether a refusal
was the endpoint's own (an anonymous request, a credential submission) or a lost
session.

## Root cause analysis
Five Whys:
1. Why did a 429 control confirm the SQL error? The strategy checked only that the
   control lacked the signature.
2. Why only that? PA-0117(1) requires the signature be absent from *a* benign control,
   not from a *comparable* one: it was written against payload-independent noise (a page
   that always shows the signature), so a control that could not show it never
   occurred to it.
3. Why was there no classification to apply? "Is this the application's answer?" was
   decided nowhere. SP-34 classifies exceptions; `detect_logout` decides a session
   loss inside the session manager with its own status list; the labgen oracle has its
   own 2xx check. Each consumer would have had to invent its own -- and the strategies
   invented none.
4. Why did a refused credential look like an answer? The facts that separate a lost
   session from an endpoint's own refusal (was a credential sent? is this a login or a
   registration?) were not carried to the consumers: the harness's sender wrappers
   forward only `prg_capable`, so a sender-level fact never reached the oracle.
5. Why did the sweeps not find it? PA-0153's discovery runs every mechanism against a
   sender that *never answers* -- not one that answers with a non-application status;
   PA-0137(4)'s rule was swept to the browser and the probe senders, not to timing
   baselines, replays or follow-ups.

**Root cause:** no shared primitive classified an HTTP answer as the application's own
(or not), and the per-exchange facts that classification needs (credential carried,
credential submission, redirect to a login page) were not available where controls are
read; so every negative-evidence mechanism, and every other consumer that judges by a
response, read a non-application answer as evidence.

## Corrective action
- **SP-56** `core.comparability.response_class` (CC-CORE-0069, FR-CORE-507): application
  / throttle-or-unavailable / gateway / auth-failure / policy-block / incomplete, with
  the facts as required inputs.
- **SP-16's facts** `session.detect.login_facts` (CC-SESS-0028, FR-SESS-22).
- **The oracle** (CC-FUZZ-0105, FR-FUZZ-63): per-probe `credentialed` and `timeout`;
  layer 1 (`_ObservedOnly`/`require_observed`) on every response a mechanism reads,
  `send_correlated` included; layer 2 (`_compared`/`require_comparable`) with each
  strategy's declared admits; B2's "observed alike" raise; `not-comparable`
  inconclusive; the scheduler charged without a reward (CC-SCHED-0007).
- **The blind-SQLi builder** and **`auto_cli`** (CC-FUZZ-0105); **the live WAF filter**
  (CC-MUT-0403, FR-MUT-401); **the runner's** classification (CC-FUZZ-0105, FR-FUZZ-52).
- **`tools/probesender.py`**: the five approved lines (connect versus read timeout; the
  per-probe credential).
Tests: `tests/test_oracle_comparable_controls.py` (117, with the M9 discovery table and
send guard), `tests/test_core_comparability.py` (33), the login-facts tests in
`tests/test_session_detect.py`, the runner file's throttle and refusal rows. Each piece's
revert fails its named tests (the lane's per-revert record).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for "a control or baseline that is
not comparable taken as evidence" and "a non-answer read as an answer":
- **BUG-0117 / PA-0117(1)/(3):** a signature also on the benign page; a single-sample
  differential. Same mechanism family (negative evidence from a control), a different
  failure of the control (present noise, not absent comparability).
- **BUG-0137, BUG-0147 / PA-0137(4), PA-0153:** a mechanism's external failure and a
  probe with no response are no verdict. Same root-cause family (an unobserved answer
  must never be a negative), applied to exceptions, not to answered-but-not-the-app.
- **BUG-0023 / PA-0025, BUG-0048 / PA-0050:** a status read as more than it proves. Same
  family, other judges.
- **BUG-0122 / PA-0122:** the session manager read any redirect containing "login" as a
  logout -- the login-redirect decision, now reused through SP-16 rather than re-made.
- **BUG-0507 / PA-0507(2):** search for an existing implementation before registering a
  new primitive. Revision 2 of this item's design did not, at first (below).

## Prior-preventive-action failure analysis
- **PA-0117(1)/(3) -- too narrow.** It requires *a* control and proves the guard on
  payload-independent noise only. A control that could not have shown the marker (a
  429) passes its rule and its discovery guard. It is strengthened here: the control
  must be *comparable*, by one classification, enforced by discovery over every
  control-reading strategy.
- **PA-0153 -- enforced at producers.** It classifies the exception and runs every
  mechanism against a sender that never answers. A sender that answers with a throttle
  or a gateway was never in its guard.
- **PA-0137(4) -- not swept.** "Anything unobserved and no evidence is inconclusive" did
  not reach HTTP timing baselines, replays or PRG follow-ups.
- **PA-0025 / PA-0050 / PA-0311(2) -- wrong layer.** Their doctrine lives in the judges
  they were written for.
- **PA-0507(2) -- not followed at first.** Revision 2 drafted a new credential test
  while `core.redaction.is_credential_name` and SP-16's login decisions existed; reviewer
  A's measurement found the true-positive loss it caused. The final design reuses
  `is_credential_name`, `looks_like_login_url`, `_same_login_url` and
  `redirect_is_logout`, and states why `browserlogin.account_endpoint_reason` is *not*
  reused (B1: it names user and account collections, measured).

## Preventive action
**PA-0529** (strengthens PA-0117(1)/(3) and PA-0137(4), applies PA-0507(2); text for
`docs/PREVENTIVE_ACTIONS.md`, written by the coordinator at merge):
A control, a baseline sample, a compared slot or a replay is evidence only when it is
the application's own answer. That is decided by one classification (SP-56) from the
answer and SP-16's credential and login facts.
1. Each strategy declares the classes each role admits, with its reason. Any other answer
   gives no verdict: inconclusive, never a confirmation and never a negative.
2. Every response a mechanism reads is an observation or ends it: a throttle or
   unavailable answer, an incomplete non-timing send, or a non-read timing timeout. A
   payload whose follow-up got no observation keeps its own response; a run that then
   decides nothing is inconclusive. A control's unobserved follow-up ends the mechanism
   only where the strategy needs it observed alike.
3. A request that submits a credential is never read as a session loss. The credential
   a probe carried is a per-probe fact; an unknown one counts as carried.
4. This is enforced by discovery. Every default strategy is classified. Every send of a
   control reader is compared, or is a declared literal mutation (AST, proven on a
   revert of `_compared`, an untagged control and a non-literal role). No status
   classification exists outside the owner but a reviewed allowance list.
- Enforced by: tests/test_oracle_comparable_controls.py::test_a_signature_absent_from_a_control_that_is_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_differential_whose_baseline_and_variant_are_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_credential_submissions_own_refusal_is_its_answer_and_still_confirms, tests/test_oracle_comparable_controls.py::test_every_default_strategy_says_how_it_reads_controls, tests/test_oracle_comparable_controls.py::test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner, tests/test_disco_runner_outcomes.py::test_a_throttled_answer_is_never_judged_by_its_status_class

**The PA-0002 sweep** (every consumer that judges by a response; every caller of the
changed mechanisms): every default strategy (33) is classified in the discovery table
and the control readers' sends are guarded; the oracle's `ProbeUnobserved` catchers see
`NotComparable` unchanged; `_SessionNotes`' correlated send is wrapped by
`_ObservedOnly`; the live filter, the blind-SQLi builder and the runner are fixed here;
`labgen/identifier_sqli_oracle.py` is already healthy-only; `core/features.py::extract`
has no production baseline caller; `disco/ede.py` and `tools/spider.py` hold discovery
baselines (another class); `session/detect.py::detect_logout` and the session manager's
status checks are defect 6's later item (on the status guard's allowance list).

**Residuals (stated; each accepted or owned elsewhere):**
- R1 classification uses status, headers and the facts: a block page answered 200 is not
  detected; no vendor fingerprinting.
- R2 a credential check none of the rules names (`/rest/2fa/verify` with `code`) reads its
  401 as a refused credential (fail closed: inconclusive).
- R3 a session lost to an in-place login page (a 200) is not classified (defect 6).
- R4 a signature, traversal or CRLF control the application itself answers 403 is
  inconclusive (decided: fail closed).
- R9 a non-deciding mechanism's no-verdict keeps a decided candidate inconclusive
  (decided: keep, PA-0523).
- R10 a *payload* (not a control) refused by a policy block or a credentialed auth
  failure still reads as not confirmed for a positive-evidence strategy; session-loss
  negatives from credentialed payloads are defect 6's later item.
- R11 a delaying throttle (a tarpit) answers 200 late; ReDoS has no rising-delay check.
- R12 greybox screening and the pipeline's fingerprint baselines may be non-application
  answers; no verdict rests on them.
- R13 greybox's sender maps every `RequestException` to status 0; layer 1 makes that
  inconclusive, but PA-0153 wants a refused connection to fail loudly (sender unchanged).
- R14 503 is throttle-or-unavailable **by policy** (RFC 9110 §15.6.4; nginx's documented
  `limit_req_status` default), not measured here; an application's own 503 is never
  judged by its class and its positive evidence in a payload's 503 is dropped.
- R16 the mutation run's coverage sends are not classified (no bypass rests on them).
- R17 in the runner, a 403 under a 4xx expectation passes for any case type (decided).
- R18 Retry-After pacing is a later item under defect 17.
- R19 `is_credential_name("pass_count")` is True (the `pass` token): a field so named
  makes its request a credential submission, so its 401 reads as the endpoint's answer --
  a narrow fail-open (ADOPT 2).
- R20 the web run page's inconclusive sentence (`fuzzlab/web`, UI) still names three
  reasons; a `not-comparable` row is listed by its mechanism (UI is another component).
- R21 a *payload* answered 502 or 504 by a positive-evidence strategy stays as today (not
  confirmed): layer 1 does not end a mechanism on a gateway; only compared responses
  exclude it (ADOPT 4).
- R22 a compared send is recognised by its trace role (`control`, `baseline`): a plugin
  strategy that tags a payload send `control` would hide that payload's unobserved
  follow-up from the final-None rule. The default strategies are guarded by the send
  guard.
- R23 a seam sender with an identity but no session manager (a test double) reads as
  credentialed (fail closed).
