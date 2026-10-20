# BUG-0533 — A forbidden answer logged the session in again

- Date: 2026-10-20
- Status: fixed (CC-SESS-0029, CC-CORE-0070, CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404)
- Severity: high. Every 403, scope 401, privilege-gated login redirect or credential
  submission's own 401 invalidated the session: N such probes cost N logins (6 requests
  each, uncapped), every probe ran on a new session, and the run's peer re-logged in on
  each denied replay. Audit defect 6 ("Every forbidden response can trigger another
  login").

## Description
`session.detect.detect_logout` read every 401 and 403 as a session loss
(`status in (401, 403)`), and `SessionManager.observe` acted on it at once: it set
`valid = False`, persisted the row and told the listeners, so the next `prepare` logged
in again. Nothing asked whether the answer was evidence about **this** session:

1. a 403 is a policy answer (SP-56 says so), and was read as a loss;
2. a credential submission's own refusal, a 401 for scope and a privilege-gated login
   redirect were read as losses;
3. an answer from an earlier session generation was applied to the current one;
4. nothing confirmed a suspicion on a resource whose answer depends on the session;
5. nothing limited successful re-logins.

## Where encountered
The owner's audit, defect 6; measured on loopback fixtures at 15a8a27
(`tests/test_session_forbidden_answers.py`, DRAFT-AU-SESS403 §1.2): admin 403, WAF 403
and CSRF 403 each gave 10 logins / 10 invalidations / 10 sessions in 10 probes; a scope
401, a privilege-gated login redirect, a password check's 401 the same; 30 probes of a
JSON app's scope-401 route gave 30 logins; four rounds of six concurrent 403s gave four
logins; a late answer from an earlier session cost one extra login.

## What it caused to fail
- N forbidden probes made N logins, uncapped, with an account-lockout exposure per
  login (R15).
- Every probe ran on a new session: a comparison could straddle sessions (R6).
- The cross-account peer re-logged in on each denied replay, the lab's own secure twins
  included.
- A late answer from an earlier session logged the current one out.
- `verify_live` (the crawler's session check, `_verify_main`) read a 403 as "logged
  out" and tripped the single-session breaker falsely.

## What the bug was identified to be
`detect_logout`'s `status in (401, 403)`, acted on by `observe` with no confirmation,
no generation and no submission fact. Nothing limited successful re-logins.

## Root cause analysis
Five Whys:
1. Why a login per 403? `observe` invalidated on `detect_logout`.
2. Why "loss"? FR-SESS-5 listed 403 among the logout signals.
3. Why was a status taken as proof? The state change had no evidence standard: one
   answer's surface feature decided it, unconfirmed on a session-dependent resource and
   untied to the session the request carried.
4. Why did SP-56 and PA-0529(3) not prevent it? They were enforced at the oracle, and
   the session manager was deferred (CC-SESS-0028; SP-56's allowance list carried
   `detect_logout`, `verify_live` and `_verify_authenticated`).
5. Why persistent? PA-0007's positive differential was required for login only.

**Root cause:** a session-state change decided from one answer's surface feature,
without positive evidence about that session or a binding to it.

## Corrective action
CC-SESS-0029, CC-CORE-0070, CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404 (FR-SESS-23,
FR-FUZZ-65, FR-MUT-401; design
`docs/components/03-session-manager/DRAFT-AU-SESS403.md`, revision 3 and the owner's
decisions D and D′):
- one loss predicate through SP-56; classification first; a stable protected resource
  checked before any change; generations; single flight with the cover at the send;
  compare-and-set on the current state for every verdict and every write, the
  invalidation's row and every install's row in one critical section;
- a pause and a sticky unknown for an inconclusive check; a refilling re-login budget;
  with no resource and no token, decision D (carry on at once), each request so sent
  marked lost, and every consumer -- the oracle (any sender), the live WAF filter and
  the blind-SQLi builder -- reading its answer as not comparable (D′);
- a policy block covered by any live verdict of its generation within the TTL, so a WAF
  that blocks every path or header payload costs one health check per window;
- `verify_live` on its own bounded wait; `_verify_authenticated` through the verdict.

Measured after the fix (§1.3 of the draft; the same fixtures): every forbidden scenario
1 login / 0 invalidations / 1 session; a real expiry 2 logins / 1 invalidation; 30
scope-401 probes on a JSON app 6 logins, 0 s asleep, every answer in D's window not
comparable at the oracle.

## Recurrence review
Checked `docs/bugs/` (the session, logout, login and scope records: BUG-0008, BUG-0113,
BUG-0122, BUG-0134, BUG-0529) and `docs/PREVENTIVE_ACTIONS.md` (PA-0007, PA-0113,
PA-0122, PA-0134, PA-0529):
- **BUG-0008 / PA-0007:** login inferred from an ambient cookie. The same root cause,
  login side (one surface feature taken as proof of a session state).
- **BUG-0113 / PA-0113:** the coarse "any password field" logout rule read
  `password_change.php` as a logout. Its fix narrowed the rule to this session's login
  form (`shows_login_form`). **PA-0113 itself covers base URLs, cookie scope and sub-path
  tests, not logout evidence**: the logout rule had no preventive action of its own.
- **BUG-0122 / PA-0122:** a substring login redirect read as a logout.
- **BUG-0134 / PA-0134:** `observe` looked the state up by host, so another app's login
  page on another port of the host logged this session out
  (`BUG-0134-session-sent-to-another-port-of-the-host.md`, §"What it caused to fail" and
  the sweep row `manager.observe`). The same root cause, its **"not bound to this
  session"** half: an answer that was not evidence about this session changed it.
- **BUG-0529 / PA-0529(3):** a submission's refusal read as a loss, fixed at the oracle
  only.
- **Result:** a recurrence, the fifth on logout detection.

## Prior-preventive-action failure analysis
- **PA-0122 (BUG-0122):** too narrow, the wrong layer: it constrained one signal's
  grammar (how a `Location` is compared), not whether a signal may change the state.
- **PA-0113 (BUG-0113):** not applicable by its own text: it governs where a base URL
  and a cookie reach, and BUG-0113's logout narrowing (one signal's content) was never
  made a rule. A logout rule that existed only as a fix, not a PA, could not stop a
  sibling signal (a status) from doing the same.
- **PA-0529(3) (BUG-0529):** not applied at the actor. Its own guard (SP-56's allowance
  list) allow-listed `detect_logout`, `verify_live` and `_verify_authenticated` "until
  defect 6's item routes it".
- **PA-0007 (BUG-0008):** too narrow: a positive differential for login only, never for
  loss.
- **PA-0134 (BUG-0134).** It did not prevent this recurrence, for three reasons:
  1. **Too narrow: it bound the send, not the evidence.** PA-0134(1) governs where a
     secret-bearing artefact may go. Its sweep fixed `observe` as one of eight send
     carriers, by changing its lookup key from the host to the origin. Being on one of
     the session's origins is necessary for an answer to be about the session, but not
     enough: the answer must also be to a request that carried *this* session, of *this*
     generation, and the loss must be confirmed on a session-dependent resource. None of
     that was asked, so a late answer from an earlier generation on the same origin, and
     a 403 to the same session, still changed the state.
  2. **The wrong layer for its guard.** PA-0134(3)'s AST guard finds hostname
     comparisons that decide a send. It cannot see a state change decided from the wrong
     evidence.
  3. **The actor was not changed.** After BUG-0134, `observe` still wrote
     `valid = False` itself, on its own reading of one answer. No single owner decided
     the state change: the gap PA-0529(3) left from the oracle's side.
- **The common failure:** each rule constrained a signal, a reader or a send path, never
  the state change; and PA-0134 bound a session's evidence to its origin only.

## Preventive action
**PA-0533**, strengthening PA-0007, PA-0113, PA-0122, PA-0134 and PA-0529(3): an
identity's state changes only on evidence about that session, classified by SP-56
first and decided by the resource's answer; evidence is bound to the session's origins,
generation, current state object and the time it was taken, with every write a
compare-and-set atomic with installs; re-logins draw on a refilling budget; an answer to
a request sent on a session known lost is never evidence; and the decision has one
owner, guarded over the whole package. Text and enforcement in
`docs/PREVENTIVE_ACTIONS.md` (the matrix that proves each rule's enforcement is in
DRAFT-AU-SESS403 §13).

## The sweep (PA-0002, PA-0138(3), SHARED_PRIMITIVES rule 2)
By primitive, from the code (PA-0152); dispositions:

| Site | Before | Disposition |
|---|---|---|
| `detect.detect_logout` callers: `observe`, (new) `health_verdict`; tests `test_session_detect.py`, `test_logout_redirect.py` | `status in (401, 403)` | **fixed**: through SP-56; T19 allows only these two callers (whole package, AST) |
| `observe` (`core/http.py` calls it for every `HttpClient` with a manager: `tools/authhttp`, `make_probe_sender` -- run and peer --, `tools/fetcher.py`, `mutation/cli.py`, `tools/blind_sqli_fuzzer.py`, every isolated copy) | invalidated on one answer | **fixed** for every caller (one owner) |
| writers of `.valid` | `observe`, `verify_live` wrote `False` | **fixed**: `_mark_lost` only; `adopt`, `ensure` (anonymous), `_established`, `_browser_login_state`, `_basic_login`, `proxy/session_capture.py` write `True` (T19) |
| writers of the session row (`_persist`) | outside any lock | **fixed**: `_mark_lost` and `_install` only, under one lock |
| `verify_live` (`tools/spider.py` `_live_session_intact`; `probesender._verify_main`) | 401/403 or the login form | **fixed**: the health check; `_verify_main`'s behaviour unchanged |
| `_verify_authenticated` | `status in (401, 403)` | **fixed**: through `health_verdict`, acceptance kept (R8) |
| `_spa_probe` (browser login) and the HTTP logins' resource | browser logins only, any agreeing non-5xx status | **fixed**: one owner for both, the admission (B1) |
| SP-56's allowance list | 8 rows | 5 rows |
| listeners (`_on_logout`, `_on_main_logout`) | told on every 401/403 | told once per transition seen on a send |
| `SessionHealthUnknown` catch-alls: `tools/fetcher.py:881` (per page), `oracle.py` PRG restore, `blind_sqli_fuzzer` top level, `mutation/run.py`, `SeamProbeSender._on_copy` | -- | stated in DRAFT §5.4: loud, sticky, no traffic; a copy's counts toward the failed-logins breaker |
| answers sent in D's window, read by the **oracle** through the run's sender | -- | **fixed** (D′, FR-FUZZ-65): layer 1 in `_ObservedOnly`, not comparable |
| ... read by the oracle through **another sender** (the cross-account replay's peer and anonymous senders, `CrossAccountReplayStrategy` via `_FormBoundSender` and `_compared`) | -- | **fixed** in review round 5 (CC-FUZZ-0107): `_compared` applies layer 1 whichever sender made the send. Found by reviewer A at f1d31dd: a guest view gave a negative, an open object a confirmation |
| ... read by the **live WAF filter** (MUT, `mutation/livefilter.HttpFilter`) | -- | **fixed** (CC-MUT-0404): `FilterUnobserved`; the round-4 pin is a passing test |
| ... read by the **blind-SQLi builder** (FUZZ, `SeamSender` / `answer_class`) | -- | **fixed** (CC-FUZZ-0110): never a baseline sample or a row, its 504 included; the round-4 pin is a passing test |
| ... read by the auditor's and crawler's fetches | -- | discovery, not evidence: stated (a degraded audit or crawl in the window), no pin |
| contract runner, disco, greybox's static header | no `SessionManager` / a captured state | not consumers (R9); disco's defect 4 may build on the public `health_verdict` |
