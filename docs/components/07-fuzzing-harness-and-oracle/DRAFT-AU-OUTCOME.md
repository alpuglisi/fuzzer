# DRAFT AU-OUTCOME: an incomplete answer, an unobserved assertion or a non-comparable control is never a pass or a confirmation

- Item: `AU-OUTCOME` (audit defects 15, 16 and 17; owner's audit at 6552276, confirmed in F-096).
- Base: `8100959`. Status: **implemented** (revision 4). Revision 3 passed the third
  review round with two blocking defects, B1 and B2, which the owner decided to apply
  exactly as specified, with reviewer B's ADOPT list 1-8; this revision folds them in
  and records the implementation. The committed change-control entries
  (CC-CORE-0069, CC-SESS-0028, CC-FUZZ-0105, CC-MUT-0403, CC-SCHED-0007) and the bug
  records (BUG-0528, BUG-0529) are the records of what landed; this draft is the design
  history.

**Numbers:**

| Number | Covers |
|---|---|
| CC-CORE-0069 / FR-CORE-507 | the classifier `fuzzlab/core/comparability.py` |
| CC-SESS-0028 / FR-SESS-22 | the SP-16 login-facts helper in `session/detect.py` (A1) |
| CC-FUZZ-0105 | the runner, the oracle, the blind-SQLi builder, `harness/auto_cli.py`, the `harness/pipeline.py` comment, and the five `tools/probesender.py` lines |
| FR-FUZZ-52 (edited in place) | the runner |
| FR-FUZZ-63 (new) | the oracle |
| CC-MUT-0403 / FR-MUT-401 | the live WAF filter (M11) |
| CC-SCHED-0007 (FR-SCHED-8 amended in place) | `ThompsonBandit.charge`, `UniformScheduler.charge` (A7) |
| SP-56 | the shared primitive |
| BUG-0528, BUG-0529, PA-0528, PA-0529 | the bug and preventive-action records |

**Decided (were open requests):**
- (§10, Q1) A7 is CC-SCHED-0007 (`charge()` in bandit and uniform).
- (§10, Q2) The three M2 probesender lines (3.6 changes 3-5) are approved, minimal and
  exactly as listed (AU-REQID14 edits the same file and merges after this item).
- (§10, Q3) The `harness/pipeline.py:369-371` comment is this item's (released for that
  comment only).

The revision-2 draft under `04-crawler/` is removed.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### 1.1 The real transport (requests 2.34.2, urllib3 2.8.0, Python 3.13.16; loopback socket)

Probe: `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au_outcome/measure_transport.py`.
Output: `.../au_outcome/measure_transport.out`.

| Server behaviour after the 200's headers | `requests` raises while iterating | `Runner` at 8100959 | Baseline admitted | Time / deadline |
|---|---|---|---|---|
| (a) closes, 985 of 1000 `Content-Length` bytes missing | `ChunkedEncodingError` <- `ProtocolError` | **pass** | **yes** | 0.0 s / 2 s |
| (b) chunked body cut mid-chunk | `ChunkedEncodingError` <- `ProtocolError` | **pass** | **yes** | 0.0 s / 2 s |
| (c) stalls past the 1 s read timeout | `ConnectionError` <- `ReadTimeoutError` | **pass** | **yes** | 1.0 s / 1 s |
| (d) drips, then closes incomplete | `ChunkedEncodingError` after 3 s | **pass** | **yes** | **3.01 s / 1 s** |
| (d2) drips a complete body over 2.75 s | none | **pass** | **yes** | **2.75 s / 1 s** |
| (e) `resp.close()` from another thread at 0.5 s | not interrupted (3.0 s) | | | |
| (f) `socket.shutdown()` from another thread at 0.5 s | interrupted at 0.5 s | | | |

### 1.2 Facts the design relies on

| Fact | Source | Result |
|---|---|---|
| Juice Shop's login answers a failed login with **401** and a quote with **500 SQLITE_ERROR** | `tests/test_json_points.py::JsonLoginApp`, `tests/_spa_login_fixture.py:262`, `tests/test_external_labs_static.py:1029` | a credential submission's own 401 must stay an application answer |
| Credential submissions that are **not** SP-16 login URLs answer a failed login with a login redirect or a 401 | reviewer A, `scratchpad/review_a/tp_loss.py`, run at 8100959: `/j_security_check` (302 -> `/login?error`) and `/register` (302 -> `/login`) **confirm today**; `looks_like_login_url` is False for both; `redirect_is_logout` is True | revision 2's rule would have made both inconclusive. M2 adds the credential-submission fact. |
| SP-16 on real URL shapes | `looks_like_login_url`, run here | True for `/app/rest/user/login`, `/rest/user/login`, `/login.php`, `/bWAPP/login.php`. False for `/api/items`, `/rest/2fa/verify`, `/rest/user/reset-password`, `/api/authenticate` (not in `_LOGIN_SEGMENTS`) |
| A name that carries a credential is decided once | `core.redaction.is_credential_name` (`CREDENTIAL_TOKENS` = password, passwd, pwd, pass, secret), shared by the importer and the point builder | reused for "the point carries a password field" (PA-0507(2); not `is_sensitive_name`, which also matches a CSRF `token`) |
| `RequestsProbeSender` is anonymous | `probesender.py:873-877`, `:935-938` (it clears its jar before every send) | its 401 is the handler's own answer |
| A **connect** timeout counts as a timeout | reviewer B, `scratchpad/reviewB/probe_gaps.py`: `_is_timeout(requests.ConnectTimeout())` is True. `RequestsProbeSender` then returns `Probe(status=0, elapsed=timeout)` (`:996-1000`). | measured through the real sender (§1.3): ReDoS confirms on connect timeouts today |
| An unobserved PRG follow-up of a control is a **negative** today | reviewer A, `prg_unobserved.py`; reviewer B (a): both measured `(False, False)` | M4 |
| A throttled peer replay is a **negative** today | reviewer B (b): `(False, False)` | M5 |
| The redactor keeps a cut JSON body that it can only sniff | run here: `redact_body(cut_json, "text/plain" or "" or "text/html")` keeps `SECRETPW`; under `application/json` it is omitted | M3 (the redactor side is AU-REDACT's) |
| The path-traversal twin answers the `passwd` control with 404 | `go_net_http/templates/sinks/unconfined_path.go.j2` | its live true positive keeps a comparable control |
| Dependency directions | `grep` | `session/detect.py` imports core. Core imports neither session nor oracle. `disco/explore.py` already imports `session.detect`. `harness/auto.py::_CountingSender` forwards only `prg_capable`, so a *sender-level* attribute never reaches the oracle, and a *per-probe* field does (M2). |

**A policy, not a measurement: every 503 is "throttle or unavailable".**
- The reason is RFC 9110 §15.6.4 plus nginx's documented `limit_req_status` default
  (503). That default was not measured on this host: there is no nginx and no network
  beyond loopback.
- A 503 is never a control's or a baseline's evidence, and is never judged by its status
  class (residual R14).

### 1.3 Failing tests against the real code (written first; run at 8100959)

Run one pytest at a time, each after the wait loop showed no other pytest or
`verify_change`. Every new fixture fails for its stated reason; every pin passes.

**`tests/test_disco_runner_outcomes.py`: 42 failed, 12 passed.**
- Failures: 39 of them are `pass` or `finding` where `error` is wanted. The other three
  are `resp.closed == 0`, `SECRETPW` kept in the evidence (M3), and no `unobserved` key
  on the result.
- The 12 pins:
  - closed on the complete and over-cap exits;
  - the clean baseline (M10);
  - the violated and satisfied state checks;
  - `status_in` names a 429;
  - `status_in` names a credentialed 401;
  - a credentialed 403 under 4xx;
  - an anonymous 401 (M1);
  - an anonymous login redirect under 3xx (A2);
  - a credential submission's 401: a login URL, and a password field (A1/M2);
  - a 502 under the 5xx rule (M6).

**`tests/test_oracle_comparable_controls.py`: 83 failed, 17 passed.** The failures:
- **63** false confirmations, `(True, False)` where `(False, True)` is wanted:

  | Fixture | Count |
  |---|---|
  | four signature strategies x 10 non-application control answers | 40 |
  | PRG follow-up 429 / 401 / login redirect | 3 |
  | cross-account control x 9 | 9 |
  | engine B0/V/B 429 / status 0 / 401 / login redirect | 4 |
  | D 401 | 1 |
  | NoSQL D 403 | 1 |
  | ReDoS baseline 429 / 401 / login redirect / 403 | 4 |
  | ReDoS on **connect timeouts through the real `RequestsProbeSender`** | 1 |

- **10** negatives, `(False, False)`, where inconclusive is wanted:

  | Fixture | Count |
  |---|---|
  | M4 controls, for 3 strategies | 3 |
  | M4 payload | 1 |
  | M5 peer 429, peer 401, anonymous timeout | 3 |
  | timed-out timing baseline | 1 |
  | throttled XSS probe | 1 |
  | throttled greybox correlated probe (A5) | 1 |

- **4** "did not raise": the live filter on 429 and on status 0, a throttled mutation
  variant, and the all-throttled blind baseline.
- **1** scheduler update recorded (A7).
- **5** blind-SQLi rows: baselines averaging 429, a login redirect and 502; rows written
  for 429 and 403.

The 17 pins are:
- 8 "still confirms";
- the login URL's 401;
- 3 credential submissions (`/j_security_check`, `/register`, `/api/authenticate`);
- cross-account with the app's own 403;
- an unauthenticated 401 replay as a real negative;
- D 403;
- a read timeout as latency;
- a payload's 504 kept as a blind-SQLi timing row.

Previous revisions measured 32/6 and 43/11. The added rows are the reviewers' cases.

## 2. The defects, as measured

**BUG-0528: the runner judges an outcome it did not fully observe (defects 15 and 16).**
- `Runner.send` (`disco/runner.py:288-328`) records a body failure while keeping
  `status`.
- `judge` (`:420-462`) treats only `status is None` as no response. So an incomplete 200
  is matched, passes, and becomes the endpoint's baseline (`:459-461`).
- `resp.close()` (`:317`) is skipped on a raise.
- A setup step (`:379-383`) accepts an incomplete or login-redirected answer below 400.
- `_state_check` (`:473-482`) returns None when it could not evaluate, and evaluates a
  401/429/404/5xx body as if it were the state. `judge` acts only on False (`:456-458`).
- A timeout before the headers matches any `latency_ms_gt` rule, even one above
  `timeout_ms`, and a connect timeout counts as one.
- Evidence writes an incomplete body, which the redactor can keep (1.2).

**BUG-0529: a non-comparable control, baseline or replay is taken as evidence (defect
17).**
- The control-reading strategies (§5.3) never check that the control got the
  application's answer. So a throttle, an unavailable server, a gateway, a timeout
  stand-in, a refused credential, a login redirect or a block confirms.
- An unobserved PRG follow-up, a throttled peer replay, a throttled correlated probe,
  a timed-out timing baseline or a throttled probe gives a **negative**.
- In the runner, a 429 or 503 is judged by its status class, and a credentialed 401 or
  login redirect passes under a 4xx or 3xx expectation.
- The live WAF filter reads a 429 or status 0 as "allow" (a bypass).
- The blind-SQLi builder averages non-application samples and labels them.

## 3. Design

### 3.1 SP-56: the classifier (CC-CORE-0069, FR-CORE-507)

`fuzzlab/core/comparability.py` is pure and total. It imports nothing from
`fuzzlab.session` or `fuzzlab.oracle`, so defect 6's item can route `session/detect.py`
through it later.

```python
APPLICATION, THROTTLE_OR_UNAVAILABLE, GATEWAY, AUTH_FAILURE, POLICY_BLOCK, INCOMPLETE = (
    "application", "throttle-or-unavailable", "gateway", "auth-failure", "policy-block",
    "incomplete")

def response_class(status, headers=None, *, complete: bool, credentialed: bool,
                   credential_submission: bool, redirect_to_login: bool
                   ) -> tuple[str, str]:
    """(class, reason). The reason names a class and a status, never a URL, header
    value or body. A malformed input is INCOMPLETE, never an exception (PA-0500(1))."""
```

The four facts are **required keyword inputs** (no defaults), so no caller can omit one.

Rules (first match wins):

| # | Answer | Class |
|---|---|---|
| 1 | no status, a status of 0 or below or not an integer, or `complete=False` | INCOMPLETE |
| 2 | 429, or 503 with or without `Retry-After` (503 by policy) | THROTTLE_OR_UNAVAILABLE |
| 3 | 502, 504 (M6) | GATEWAY |
| 4 | 407 (an intermediary's demand, whoever sent the request) | AUTH_FAILURE |
| 5 | 401, when `credentialed` and not `credential_submission` (M2) | AUTH_FAILURE |
| 6 | 3xx with `redirect_to_login`, when `credentialed` and not `credential_submission` | AUTH_FAILURE |
| 7 | 403, 451 | POLICY_BLOCK |
| 8 | anything else, including a 401 or login redirect that is uncredentialed or a credential submission | APPLICATION |

**PA-0507(2) search, unchanged from revision 2.**
- `detect_logout` is defect 6's item. It will decide its status part through SP-56.
- SP-34 classifies exceptions, not answers.
- The labgen `_is_healthy` is stricter (2xx) and already fail-closed.
- The blind fuzzer's 504 skip is replaced (3.4).
- For "carries a password field", `core.redaction.is_credential_name` already exists and
  is reused.

### 3.2 SP-16's login facts, one helper (CC-SESS-0028, FR-SESS-22; A1, M2)

```python
@dataclass(frozen=True)
class LoginFacts:
    credential_submission: bool
    redirect_to_login: bool

def login_facts(url: str, headers=None, *, response_url: str | None = None,
                login_url: str | None = None, entry_names=()) -> LoginFacts:
```

- **`credential_submission`** (M2) is any of:
  - `url` is an SP-16 login URL (`looks_like_login_url`; or the session's own
    `login_url` when known, `_same_login_url`);
  - **(B1, revision 4)** the path names account creation or a password reset:
    `CREDENTIAL_PATH_TOKENS` = register, registration, signup, password, passwd, reset,
    plus the pair "sign up". `browserlogin.account_endpoint_reason` is **not** reused:
    it names any user/users/account/accounts path and a bare `change`
    (browserlogin.py:91-97, 216-218), measured to match `/api/users/42`,
    `/api/account/billing`, `/rest/user/whoami` and `/api/orders/42/change-status`,
    which would hide a lost session;
  - any of `entry_names` is a credential name (`core.redaction.is_credential_name`;
    strings only -- a JSON leaf by its `jsonbody.display_name`, ADOPT 1:
    `is_credential_name` on a path tuple raised TypeError, measured).
- **`account_submission`** (ADOPT 5, revision 4): the credential path rule holds and the
  URL is not a login URL. A setup step that is one and is redirected to the login page
  succeeded ("now log in").
- **`redirect_to_login`**:
  - `Location` is looked up case-insensitively (`_lower_headers`);
  - it is resolved against `response_url or url` (a PRG follow-up passes `followed.url`);
  - it is judged by `redirect_is_logout(location, base, login_url)`, which uses the known
    `login_url` when one exists.
- **The runner and the oracle each call this one helper** (PA-0003). Neither knows a
  session `login_url` today, so both pass None. The session manager (defect 6's item)
  will pass its own.

### 3.3 The runner (CC-FUZZ-0105; FR-FUZZ-52 edited in place)

`disco/runner.py` imports `core.comparability` and `session.detect` (disco already imports
it). It imports nothing from `fuzzlab.oracle`. The timeout classifier
`_is_connect_timeout` comes from SP-34, as `_is_timeout` already does.

1. **Completeness.**
   - `Exchange.incomplete -> str | None` ("no response", "timed out before the headers",
     "timed out after the headers (200)", "body cut off (200)", "body over max_body_bytes
     (200)").
   - `Exchange.timeout_kind` is "connect", "read" or "deadline" (M7). "deadline" is the
     runner's own wall-clock check, which fires after the headers.
   - `send` closes the response in a `finally`. The status is kept.
2. **Credential facts.**
   - `Prepared.credentialed` is true when the profile's auth headers were added: a kind
     other than `none`, on the base origin.
   - `entry_names` are the query names, plus the JSON body's keys at every depth (a
     `raw_body` gives none).
   - The facts come from `login_facts(req.url, ex.headers, entry_names=...)`.
3. **`judge` classifies first (strict, as before):**
   - **INCOMPLETE** is an `error` "incomplete response: <why>". There is one exception:
     a timeout of kind **read or deadline** under a `latency_ms_gt` rule whose bound is
     at most `timeout_ms` is a finding `["latency_ms_gt"]` (M7: a connect timeout never
     proves latency).
   - **THROTTLE_OR_UNAVAILABLE** is judged only when `status_in` names the code.
     Otherwise it is an `error`.
   - **AUTH_FAILURE** (credentialed; M1, A2) is an `error` "credentials not accepted
     (<reason>)", unless `status_in` names the code. An uncredentialed 407 keeps the 4xx
     rule.
   - **POLICY_BLOCK** is judged where `expect_status_class` holds 4xx or `status_in` names
     the code (any case type). Otherwise it is an `error`.
   - **GATEWAY** is judged like an application answer: the built-in 5xx rule applies (M6).
   - **APPLICATION**, which includes an anonymous 401 or login redirect and a credential
     submission's own refusal, is judged as today.
4. **Baselines** come only from a complete APPLICATION answer below 400 with no match.
   The reachable case is pinned (M10).
5. **Setup steps** fail unless the answer is a complete APPLICATION answer below 400 that
   is **not** a redirect to a login page. A failed form login is a setup failure (A8),
   whatever `credential_submission` says.
6. **State checks** are satisfied, violated or unobserved. The branches are:
   - not prepared;
   - refused at the send;
   - incomplete;
   - not a 2xx (every non-application class is non-2xx, so a single "complete 2xx"
     check covers them);
   - not JSON;
   - not evaluable.

   M8's fixtures give each non-2xx and incomplete row a body that **satisfies** the
   assertion, so each branch fails on its own revert. A pass needs every state check
   satisfied. Unobserved checks are listed in `result["unobserved"]`.
7. **Evidence (M3).** An incomplete exchange, the main one or a state read, writes
   `"body": "omitted (incomplete)"` and `"body_bytes": N`, never its bytes. A complete
   body is redacted as today.
8. **Results** gain `unobserved` and `response_class`, both additive. `VERDICTS` is
   unchanged.

### 3.4 The oracle (CC-FUZZ-0105; FR-FUZZ-63)

**Probe fields** (`oracle/probe.py`):
- **`credentialed: bool | None = None`**: whether this request carried the run's
  credential. None (a sender that does not say, a test double, greybox) is read as
  **True**, to fail closed.
- **`timeout: str | None = None`**: "read" or "connect", on a sender's status-0 timeout.

A per-probe field reaches the oracle through every wrapper, `harness/auto.py`'s included.
A sender-level attribute would not (1.2).

**The oracle's side of SP-56** (`oracle/probe.py`):
- `NotComparable(ProbeUnobserved)`, with `resent` carried so cost counts stay exact;
- `require_observed(probe, *, url, candidate, timing)`;
- `require_comparable(probe, *, url, candidate, role, admits)`.

Facts:
- `credentialed = probe.credentialed is not False`.
- `login_facts(url, probe.headers, response_url=<followed.url for a follow-up>,
  entry_names=<the candidate's param and entry names, when url_key(url) is the
  candidate's>)`.

**Layer 1 (every response a strategy reads; `_ObservedOnly` in `oracle.py`).** It raises
`NotComparable` for:
- THROTTLE_OR_UNAVAILABLE (the probe or its PRG `followed`);
- INCOMPLETE on a non-timing send;
- on a timing send, status 0 unless `timeout == "read"` (M7: only a read timeout after
  the request was sent is latency).

**M4 as narrowed by B2 (revision 4).** Layer 1 does **not** raise on `PRG_UNOBSERVED`: it
also covers a follow-up the app answered with a second redirect, and FR-FUZZ-50 keeps the
probe's own response.
- A **payload's** own `PRG_UNOBSERVED` (a non-timing send outside the `control` and
  `baseline` trace roles) is counted; the strategy reads the payload's own response and
  runs its other payloads (SSTI tries its others). Only a final None (or a plain negative
  verdict) is turned into `NotComparable` by the oracle.
- A **control's** `PRG_UNOBSERVED` matters only where the follow-up is needed: in the
  "observed alike" branches of SqliError, PathTraversal and PathTraversalFsPathRead
  (`strategies.py:490-491, :1187-1188, :1266-1267` at 8100959), when the payload was seen
  through PRG and a needed control's follow-up is `PRG_UNOBSERVED`, the strategy raises
  `NotComparable`. A direct signature never needs it (pinned for all three: a true
  positive today).

`_ObservedOnly.__getattr__` wraps **`send_correlated`** the same way (A5: a few lines,
mirroring `_SessionNotes`).

**Layer 2 (controls, baseline samples, compared slots):**
`ConfirmationStrategy._compared(sender, candidate, value, *, role, admits=APPLICATION_ONLY,
timing=False)`.

| Strategy | Response compared | Admits | Reason |
|---|---|---|---|
| SqliError | `fz…`, `1fz…` controls | APPLICATION | fail closed on 403 (coordinator answer 4) |
| PathTraversal, PathTraversalFsPathRead | `passwd` control | APPLICATION | the twin answers 404 (1.2) |
| HttpHeaderInjectionCrlf | no-CRLF control | APPLICATION | |
| CrossAccountReplay | the owner's other-value control | APPLICATION, POLICY_BLOCK | an API's own 403 for a foreign id |
| same, **peer replays** (M5) | each replay, `_compared` with `credentialed=True` | APPLICATION, POLICY_BLOCK | a refused peer credential is not "denied". A 403 stays the denial. A 502/504 is not comparable (ADOPT 4). |
| same, **unauthenticated replays** (M5) | each replay, `_compared` with `credentialed=False` | APPLICATION, POLICY_BLOCK | a 401 is the endpoint's own denial |
| `_differential` (SqliBoolean) | B0, V, B | APPLICATION | |
| same | D | APPLICATION, POLICY_BLOCK | V and D share their characters. A 401 to D is refused, measured in a fixture. |
| NoSqlOperator | B, V, D | APPLICATION | `$ne` versus `$in` can be singled out |
| `_confirm_timing`, RegexDos | baseline samples | APPLICATION | |
| JwtAlgNone | rejection control | unchanged (`status in (401, 403)`) | the rejection is its evidence |

GATEWAY is never admitted by any row (M6).

**Mapping onto the existing paths (unchanged from revision 2):**
- the FR-FUZZ-50 branch: no verdict from the mechanism;
- `placed` via `_decides`, so the candidate is never a negative (PA-0523);
- `NOT_COMPARABLE = "not-comparable"` as the inconclusive mechanism, with the reason under
  `evidence["unobserved"]`;
- the trace detail is the reason.

**Changes in this revision:**
- **A7:** a `NotComparable` arm is **charged its cost without a success update**. The
  oracle calls `scheduler.charge(ctx, arm, cost)` when the scheduler has it, and
  otherwise neither `charge` nor `update`. `ThompsonBandit.charge` adds to `_cost` only;
  `UniformScheduler.charge` is a no-op. That is a SCHED change (§10, Q1).
- **A9:** the log line says "control or baseline not comparable" with its class, not
  "probe got no response". `harness/auto_cli.py` gets its own summary branch and header
  wording. The equivalent comment in `harness/pipeline.py:369-371` is this item's
  (decided, revision 4): "…stopped by a cost cap (FR-FUZZ-45), got no response
  (FR-FUZZ-50) or met a response that was not the application's own answer
  (FR-FUZZ-63)".
- **A8 decided candidates:** kept as today (PA-0523).

**Blind-SQLi builder (`tools/blind_sqli_fuzzer.py`; A4):**
- `get()` returns a **3-tuple carrying `.headers`** (a `tuple` subclass). It unpacks
  exactly as before, so `tests/test_fuzzer_seam.py` is unchanged.
- The credential is known by construction: `RequestsSender` is uncredentialed;
  `SeamSender` is credentialed unless its identity is anonymous.
- **Baseline:** a sample is used only when it is a complete APPLICATION answer and is
  not a redirect to a login page. A 502, a 504, a 429 and a login redirect are skipped.
- **When every sample is excluded,** `establish_baseline` raises `BaselineNotComparable`
  ("no baseline sample was the application's answer: N throttled or unavailable, …").
  `main()` says so; "could not reach" stays for request errors only.
- **Payloads:** a 504 **stays a timing observation** (a gateway that timed out waiting
  for a sleeping query saw its latency). Any other non-APPLICATION answer gets no row:
  `import_fuzz_csv` never receives a reward-0 attempt for one.

### 3.5 The live WAF filter (CC-MUT-0403, FR-MUT-401; M11)

- `HttpFilter` classifies each answer with SP-56. Its sender is a lab probe sender, so
  `credentialed` comes from the probe; the login facts use the filter's URL.
  - `block_status` (403 by default) is a block, as today.
  - THROTTLE_OR_UNAVAILABLE, GATEWAY and INCOMPLETE raise **`FilterUnobserved(reason)`**.
    Like `DestructiveRefused`, it is never counted as a block or an allow.
  - Anything else is an allow, as today. A 401 means the request passed the WAF.
- `mutation/run.py::run_mutation` contains `FilterUnobserved` per base:
  - `summary["unobserved"] += 1`;
  - the base's result names the reason;
  - no bypass is recorded;
  - the base's search ends.
- `MutationSearch` and `FilterLearner` are unchanged: the exception passes through
  `search`, and `FilterLearner` never runs on the live filter (`HttpFilter(` is
  constructed only in `run.py:60`).

### 3.6 `tools/probesender.py`: the exact lines (SP-34; AU-REQID14 merges after this)

**M7 (permitted):**
1. Insert after line 206 (between `_is_timeout`, which ends at 205, and `_unobserved` at
   208) a new function of about 11 lines:
   ```python
   def _is_connect_timeout(exc: BaseException) -> bool:
       """A timeout before the request was sent (connect), which proves nothing about
       the server's latency (M7). urllib3's NewConnectionError is not one."""
       import requests
       from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
       chain = _chain(exc)
       if any(isinstance(e, NewConnectionError) for e in chain):
           return False
       return any(isinstance(e, (requests.ConnectTimeout, ConnectTimeoutError))
                  for e in chain)
   ```
2. Line 1000, inside `RequestsProbeSender._request`'s timeout branch
   (`resent=attempt - 1, attempts=tries)`), gains one keyword:
   `timeout="connect" if _is_connect_timeout(exc) else "read"`.

**M2 (approved, revision 4; applied exactly as listed):**
3. Line 993, the response probe in `RequestsProbeSender._request`, gains
   `credentialed=False`.
4. Line 1000 gains `credentialed=False` as well, on the same line as change 2.
5. Lines 857-861, the response probe in `SeamProbeSender._dispatch`, gain
   `credentialed=identity != "anonymous" and self._session_note(req) is None`.

**Fallback if 3-5 are not approved:**
- Every probe's `credentialed` stays None and is read as True (fail closed).
- The cost: a 401 or login redirect answering a control at a URL that is **not** a
  credential submission becomes inconclusive even from the anonymous plain sender.
- The M2 pins (`/j_security_check`, `/register`, `/api/authenticate`) still confirm,
  because they rest on the credential-submission fact.

## 4. What is unchanged on purpose

- The positive-evidence strategies, the OOB strategies, M6 and greybox's verdict logic.
- SP-34's classification of exceptions; the senders except the lines in 3.6.
- The contract schema and `VERDICTS`.
- `test_fuzzer_seam.py`'s `get()` unpacking.

## 5. The sweep (PA-0002; PA-0138(3); SHARED_PRIMITIVES rule 2)

### 5.1 Callers of the changed mechanisms

| Mechanism | Callers (`grep`) | Disposition |
|---|---|---|
| `core.comparability.response_class` (new) | `disco/runner.py`; `oracle/probe.py` (`require_*`); `tools/blind_sqli_fuzzer.py`; `mutation/livefilter.py`. Later: `session/detect.py` (defect 6). | one owner, status guard |
| `session.detect.login_facts` (new, SP-16) | the same four | one helper (A1) |
| `Runner.send` | `run_case` (main, setup), `_state_check`; tests | 3.3 |
| `Runner.judge`, `_baselines`, `_state_check`, `_drift`, `_evidence` | `run_case` / `judge` only | 3.3 |
| `Oracle._confirm_outcome` and its wrappers | `confirm_outcome`, `confirm`; `harness/pipeline.py:276`, `blind_sqli_fuzzer.py:314` | `_ObservedOnly`; `NOT_COMPARABLE`; `charge` |
| `ProbeUnobserved` catchers | `_send_blind`, `_CostCounter`, `_confirm_outcome`, `harness/tracing.py` (sender level, below the oracle) | unchanged; they see `NotComparable` |
| `_SessionNotes.__getattr__` (`send_correlated`) | greybox | `_ObservedOnly` classifies it too (A5) |
| `HttpFilter.caught` / `evaluate` | `mutation/run.py`, `search.py`, `learn.py` (no live use) | `FilterUnobserved`, contained in `run.py` |
| `_is_timeout` | runner, `_failed_try`, seam, `RequestsProbeSender` | unchanged; `_is_connect_timeout` added beside it |

### 5.2 Consumers of runner results and baselines

- `disco/cli.py::_run` writes each result and prints `summary` counts; the keys added are
  additive.
- No other reader of the results ledger exists.
- Baselines are read only by `judge`.

### 5.3 Every default strategy (33)

| Strategy | How it reads controls | Exposed (measured) | Disposition |
|---|---|---|---|
| SqliError | negative control (PRG) | **yes, 10 answers, PRG and M4** | `_compared`, APPLICATION |
| SqliBoolean | B, V and D engine | **yes** | 3.4 table |
| SqliEvaluationMarker | two positive probes | throttled second probe was a negative | layer 1 |
| SqliTiming, CommandInjection | timing baseline | **timed-out baseline is a negative** | samples APPLICATION; M7 |
| NoSqlOperator | B, V and D | **yes** | APPLICATION |
| ReflectedXss | positive | throttled probe was a negative | layer 1 |
| DomXss, StoredXss | browser | no | unchanged |
| OpenRedirect, CsvFormula, PriceIntegrityBypass, PriceTrustDifferential, PredictableToken, AccessControlIdor, MassAssignment, UnrestrictedFileUpload, InsecureDeserialization | positive requirements | no | layer 1 |
| Ssti, Spel, GoTemplateSsti | positive; an absence is a disqualifier | no | layer 1 |
| PathTraversal, PathTraversalFsPathRead | negative control (PRG) | **yes, 10 answers and M4** | `_compared`, APPLICATION |
| RegexDos | timing baseline | **yes, including connect timeouts** | samples APPLICATION; M7 |
| CommandInjectionOob, SsrfOob, XxeOob | callback | no | layer 1 (`_send_blind` waits) |
| SsrfInBandMarker, XxeInBandMarker | HMAC proof | no | layer 1 |
| CrossAccountReplay | control and replays | **yes, control x 9; replays (M5)** | 3.4 |
| JwtAlgNone | rejection control | no false confirmation | unchanged; status guard allowance |
| HttpHeaderInjectionCrlf | negative control | **yes, 10 answers** | `_compared`, APPLICATION |
| Greybox | coverage via `send_correlated` | **a throttled probe was a negative** | layer 1 via `__getattr__` (A5, fixed) |

### 5.4 Other consumers in `fuzzlab/`

- `mutation/livefilter.py:64, :68`: **exposed** (M11). Fixed under CC-MUT-0403.
- `mutation/run.py`'s coverage function (`RequestsCorrelatingSender`): a throttled
  coverage send gives no coverage novelty. That is a score, not a decision. Residual R16.
- `tools/blind_sqli_fuzzer.py`: **exposed**. Fixed (3.4).
- `greybox/run.py::_screening`, `harness/pipeline.py::_baseline` (AU-REQID's): no verdict
  rests on them. Residual R12.
- `core/features.py::extract(..., baseline)`: no production caller passes a baseline.
- `labgen/identifier_sqli_oracle.py`: already healthy-only.
- `disco/ede.py`, `tools/spider.py`: discovery baselines, another class.
- `session/detect.py::detect_logout`: defect 6's item.

### 5.5 Existing tests whose expectation changes (M12; static review, confirmed by the Phase-2 harness run)

| Test | Today | After |
|---|---|---|
| `tests/test_oracle_sqli_string.py:568-587` `test_false_positive_classes_are_not_confirmed[429]` (`_RateLimited`, `SqliBooleanStrategy().confirm` called directly) | `None` | **raises `NotComparable`** (layer 2: a slot answered 429). ADOPT 8, measured: every seed 0-4 reaches the 429 at request 8 (unthrottled, the site confirms after 24). The row moved to its own test, `test_a_site_that_throttles_mid_differential_is_not_comparable_never_a_negative`: a seed that reaches the 429 raises at request 8; a seed that ended earlier would keep `None` (handled explicitly); all five reached it. |
| `tests/test_prg_observation.py::test_a_second_redirect_is_no_observation` | SSTI tries every payload | unchanged under B2: the payload's own response is read and every payload still runs; a final None becomes `NotComparable`. The assertion `prg_unobserved == prg_follow_ups > 0` holds. |
| `tests/test_oracle_sqli_string.py` (auto_cli summary), `tests/test_json_points.py` (auto_cli summary) | the inconclusive header names three reasons | it names four, with FR-FUZZ-63 (A9) |
| `tests/test_disco_runner_outcomes.py:306-311` (this item's pin) | credentialed 401 under 4xx passes | flipped (M1); the anonymous-401 pin added |

Checked and unchanged:
- `test_disco_contract` (reasons still contain "no response"; ReadTimeout with rule 100
  is at most 2000);
- `test_json_points` and `test_login_form_isolation` (credential submissions);
- `test_cross_account` and `test_path_params` (403 replays are POLICY; anonymous 302s
  have no Location);
- `test_oracle_strategies_xxe:39` and `test_oracle_oob:184` (a 502 on positive or OOB
  strategies: layer 1 has no GATEWAY);
- `test_mutation_live`, `test_mutation_search`, `test_destructive_send_gate` (403 and 200
  only);
- `test_probe_unobserved` and `test_trace_attempts` (sender level, or `ProbeUnobserved`
  only);
- `test_fuzzer_seam` (`get()` still unpacks to 3).

**The status guard's allowance list** (every status-literal comparison in `fuzzlab/`
outside the owner, each with its reason):

| Site | What it decides |
|---|---|
| `session/manager.py:639` | the liveness probe after a login |
| `session/manager.py:805` | a Basic challenge |
| `session/manager.py:818` | a failed login response |
| `session/manager.py:1085` | a 401 at the base URL means Basic |
| `session/manager.py:1264-1266` | session verification |
| `session/detect.py:243` | Basic `WWW-Authenticate` detection |
| `session/detect.py:342` | `detect_logout`, until defect 6's item |
| `oracle/strategies.py:1994` | JWT's rejection control |

`tools/blind_sqli_fuzzer.py:118` (`status == 504`) is **removed** by this change.

## 6. Tests (PA-0034(2): each must fail on its named revert)

Every row's measured state at 8100959 is in 1.3.

**Runner (`tests/test_disco_runner_outcomes.py`).**

| Test | Fails on the revert of |
|---|---|
| `…incomplete_200_is_never_a_pass_nor_the_endpoints_baseline` (3) | `judge`'s INCOMPLETE gate |
| `…body_that_arrives_after_the_deadline…` | `timed_out` after the headers counted as incomplete |
| `…incomplete_exchange_never_suppresses_a_later_cases_match` | the INCOMPLETE gate (no baseline) |
| `…clean_complete_answer_is_the_endpoints_baseline` (pin, M10) | an over-narrowed admission |
| `…response_is_closed_on_every_exit` (3) | `finally: close()` |
| `…incomplete_body_is_never_written_to_evidence` (M3) | the omitted marker |
| `…timeout_matches_a_latency_rule_only_when_it_proves_the_bound` | `timeout_ms >= rule`; the after-headers timeout in the exception |
| `…connect_timeout_never_proves_latency` (M7) | `timeout_kind != "connect"` |
| `…incomplete_setup_step…` | the setup check's completeness |
| `…setup_login_redirected_back_to_the_login_page_fails_the_setup` (A8) | the setup check's `redirect_to_login` |
| `…unobserved_state_check_is_never_a_pass` (11 rows, satisfying bodies, M8) | the not-JSON, not-evaluable, not-2xx and incomplete branches, each on its own rows |
| `…state_check_that_cannot_be_sent…` (2) | the prepare and send branches |
| `…violated…satisfied…` (pin) | over-reach |
| `…every_state_check_must_be_evaluated…`; `…observed_finding_stands…` | the mandatory rule; `result["unobserved"]` |
| `…throttled_answer_is_never_judged_by_its_status_class` (5) | the THROTTLE_OR_UNAVAILABLE gate; rule 2's 503 |
| `…refusal_the_case_does_not_expect…` (6, incl. lowercase `location`) | AUTH_FAILURE "credentials not accepted"; POLICY admission; A1's case-insensitive lookup |
| `…credentialed_401_is_credentials_not_accepted_even_where_4xx…` (flipped, M1) | M1 |
| `…credentialed_401_is_judged_where_status_in_names_it` (pin) | `status_in` admission |
| `…policy_refusal_is_judged_where_4xx_is_expected` (pin) | POLICY admission (answer 6) |
| `…anonymous_401_is_the_handlers_answer` (pin, M1) | `credentialed` |
| `…credentialed_login_redirect_is_an_error_even_where_3xx…` (A2) | A2 |
| `…anonymous_login_redirect_is_judged_where_3xx…` (pin, A2) | `credentialed` |
| `…credential_submissions_own_401_is_its_answer` (2 pins: login URL; password field) | each credential-submission rule alone |
| `…gateway_answer_is_judged_by_the_5xx_rule` (pin, M6) | GATEWAY judged like an application answer |
| `…real_200_cut_or_stalled_after_its_headers_is_an_error` (3, loopback) | the INCOMPLETE gate on the real stack (§7 pin) |

**Oracle (`tests/test_oracle_comparable_controls.py`).**

| Test | Fails on the revert of |
|---|---|
| `…signature_absent_from_a_control_that_is_not_the_applications…` (4 x 10) | that strategy's `_compared`. The 401, login-redirect (both cases), 403 and 502/504 rows reach **only** layer 2; the 429/503/status-0 rows reach layer 1 too. |
| `…application_answer_to_the_control_still_confirms` (8 pins); `…login_endpoints_own_401…` (pin) | over-reach; the login-URL fact |
| `…credential_submissions_own_refusal…still_confirms` (3 pins, M2) | the password-field and account-endpoint facts, each alone |
| `…controls_prg_follow_up_that_is_not_the_applications…` (429, 401, login redirect; M10) | classifying `_observed(probe)` in `_compared`; the 401 and login rows reach only layer 2 |
| `…control_whose_follow_up_got_no_observation…` (3, M4); `…payload_whose_follow_up…` (M4) | layer 1's `PRG_UNOBSERVED` rule |
| `…cross_account_control_that_is_not_the_applications…` (9); `…app_itself_denies…` (pin) | the cross-account `_compared` and its admits |
| `…replay_that_is_not_the_applications_is_inconclusive…` (3, M5); `…unauthenticated_replay_refused_with_401_is_a_real_negative` (pin) | replay `require_observed` with role credentials |
| `…differential_whose_baseline_and_variant…` (429, status 0, 401, login redirect; M10) | `_compared` on B0, V and B. The 401 and login rows reach only layer 2. |
| `…differential_whose_d_is_a_refused_credential…` (M10); `…d_the_app_denies…` (pin) | D's admits |
| `…nosql…operator_probe_is_blocked…` | NoSQL's admits (layer 2 only) |
| `…redos_baseline_that_is_not_the_applications…` (429, 401, login redirect, 403; M10) | ReDoS samples. The last three reach only layer 2. |
| `…timing_baseline_that_timed_out…` | `_confirm_timing`'s samples |
| `…only_a_read_timeout_is_latency_evidence` (connect; read pin; real `RequestsProbeSender`) | M7's `timeout == "read"` rule and the probesender line |
| `…throttled_probe_is_no_observation…` | layer 1 |
| `…throttled_correlated_probe…` (A5) | the `send_correlated` wrap |
| `…non_comparable_run_charges_its_cost…` (A7) | `charge` versus `update` |
| `…live_filter_never_reads_a_non_observation_as_allowed` (2); `…throttled_variant_is_never_an_evasion` (M11) | `FilterUnobserved` |
| blind SQLi: `…baseline_never_averages_a_non_application_sample` (3), `…baseline_of_throttled_samples_is_not_comparable`, `…payload_not_answered_by_the_application_is_never_a_row` (2), `…payload_answered_504_stays…` (pin) | A4 |

**Phase 2 guards, each proven on synthetic offenders (PA-0034(2)):**

| Guard | What it checks |
|---|---|
| `tests/test_core_comparability.py::test_every_rule_row_classifies_as_stated` | the full credentialed x credential-submission x redirect matrix |
| `…::test_response_class_is_total` | non-integer, negative or bool status; `None` or odd headers |
| `…::test_the_classifier_imports_neither_session_nor_oracle` | AST; proven on a synthetic import |
| `…::test_no_module_classifies_a_throttle_or_refusal_but_the_owner` + `…::test_the_status_guard_catches_a_synthetic_offender` | the allowance list in 5.5 is exact, and a stale entry fails |
| `tests/test_session_detect.py::test_login_facts_reads_location_in_any_case_against_the_follow_ups_url`, `…::test_login_facts_names_every_credential_submission`, `…::test_login_facts_uses_the_sessions_known_login_url` | A1 |
| `tests/test_oracle_comparable_controls.py::test_every_default_strategy_says_how_it_reads_controls` | **the discovery table** (M9): every `default_strategies()` class has one row (kind and reason). It fails on an unclassified or stale row. Proven on a synthetic strategy appended through `monkeypatch`. |
| `…::test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation` + `…::test_the_send_guard_catches_its_synthetic_offenders` | M9, below |
| existing: `tests/test_sender_conformance.py` (`_ObservedOnly`); `tests/test_shared_primitives.py::test_every_owner_is_defined_once` (SP-56) | |

The M9 send guard is keyed on the discovery table. For every class whose row is a
control reader (negative-control, differential, timing-baseline, replay):
- every send in its methods, and in the shared engines that row names (`_differential`,
  `_confirm_timing`), must be one of:
  - `_compared(...)`;
  - a `require_observed` / `require_comparable` call on its result;
  - a send lexically inside `with trace.role("mutation")`, with a **literal** role.
- A non-literal role counts as a control.

The synthetic offenders:
- SqliError's source with the control's `_compared` reverted to `_send`;
- a strategy with an untagged control send;
- a `trace.role(variable)` send.

Verification: `scripts/verify_change.py --base 8100959`, with its counts quoted.

## 7. Change-control entries (drafts)

```
### CC-CORE-0069 — One classification of an HTTP answer (SP-56, FR-CORE-507, BUG-0528, BUG-0529) (2026-10-19)
- Change: new `fuzzlab/core/comparability.py`.
  - `response_class(status, headers, *, complete, credentialed, credential_submission,
    redirect_to_login) -> (class, reason)`.
  - The classes: application / throttle-or-unavailable / gateway / auth-failure /
    policy-block / incomplete.
  - It is pure and total, with no session or oracle import.
  - A 503 is classified by policy.
  - About +70 LOC, plus `tests/test_core_comparability.py`.
- Impact: read by FUZZ (the runner, the oracle, blind SQLi) and MUT (the live filter).
  SESS's `detect_logout` will read it (defect 6). New row SP-56; ARCHITECTURE note.
- Risk (low): a new pure function. Its consumers carry the risk.
- Deliverables:
  - [ ] the module — todo
  - [ ] its tests and guards (rows, totality, import, status) — todo
  - [ ] FR-CORE-507, SP-56, ARCHITECTURE — todo
- Effectiveness (assessed <date> or pending): pending
```

```
### CC-SESS-0028 — SP-16 login facts for one exchange: credential submission and redirect to a login page (FR-SESS-22, BUG-0529) (2026-10-19)
- Change: `fuzzlab/session/detect.py::login_facts` (with `LoginFacts`).
  - `credential_submission`: an SP-16 login URL or the known `login_url`, an account
    endpoint (`browserlogin.account_endpoint_reason`, imported lazily), or a credential
    name among the entries (`core.redaction.is_credential_name`).
  - `redirect_to_login`: `Location` read case-insensitively, resolved against the
    response's own URL (a PRG follow-up's), and judged by `redirect_is_logout` with the
    known `login_url`.
  - About +35 LOC, plus 3 tests in `tests/test_session_detect.py`.
- Impact: FUZZ (runner, oracle, blind SQLi), MUT (live filter). No existing session
  behaviour changes.
- Risk (low): read-only reuse of SP-16, SP-17 and `account_endpoint_reason`. The risk is
  under-approximation: a credential submission not named by any of the three rules reads
  as a session loss. That direction fails closed (inconclusive).
- Deliverables:
  - [ ] `login_facts` — todo
  - [ ] its tests — todo
  - [ ] FR-SESS-22 — todo
- Effectiveness (assessed <date> or pending): pending
```

```
### CC-FUZZ-0105 — Complete, evaluated, application answers only: the contract runner and the oracle (FR-FUZZ-52, FR-FUZZ-63, BUG-0528, BUG-0529) (2026-10-19)
- Change:
  - **Runner** (3.3):
    - `Exchange.incomplete` and `timeout_kind`; `finally` close;
    - `Prepared.credentialed`;
    - `judge` through SP-56 and SP-16's facts: strict incompleteness, the read-or-deadline
      latency exception, the throttle and auth rules, the policy admission, gateway
      judged under 5xx;
    - baselines;
    - setup steps (with A8);
    - three-valued state checks;
    - omitted evidence for an incomplete body;
    - the additive keys.
  - **Oracle** (3.4):
    - `Probe.credentialed` and `Probe.timeout`;
    - `NotComparable`, `require_observed` and `require_comparable`;
    - `_ObservedOnly` (with `send_correlated`);
    - `NOT_COMPARABLE`; the `charge` call (A7); the log line (A9);
    - `_compared` and its admits in SqliError, both path-traversal strategies, CRLF,
      cross-account (control and replays), the B, V and D engine, NoSQL, `_confirm_timing`
      and ReDoS.
  - **`tools/blind_sqli_fuzzer.py`** (A4).
  - **`harness/auto_cli.py`** (A9).
  - **`tools/probesender.py`**: the lines in 3.6 only.
  - About +330 / -45 LOC, plus 154 tests (54 + 100) and the oracle guards.
- Impact:
  - CORE (SP-56), SESS (SP-16 helper), SCHED (`charge`; needs its number), MUT (none from
    here).
  - `harness/pipeline.py` (AU-REQID) is unchanged: the reason travels under
    `evidence["unobserved"]`. A comment edit is proposed there (A9).
  - ML gets fewer negatives (unobserved results are inconclusive and unlabelled).
  - Existing-test expectation changes are in 5.5.
  - FR-FUZZ-52 is edited in place; FR-FUZZ-45 and FR-FUZZ-50 are noted.
- Risk (medium): over-reach on a real application answer. It is mitigated by:
  - the credential and credential-submission facts (M1, M2);
  - declared admits;
  - 29 pins (12 runner, 17 oracle);
  - the harness's selected suites.

  Accepted residuals are in §8.
- Deliverables:
  - [x] measurement and failing tests — done (Phase 1)
  - [ ] the runner (3.3) — todo
  - [ ] the oracle (3.4) — todo
  - [ ] blind SQLi; `auto_cli` — todo
  - [ ] probesender lines (3.6; M2's three need approval) — todo
  - [ ] the oracle guards (§6) — todo
  - [ ] FR-FUZZ-52 in place, FR-FUZZ-63, FR-FUZZ-45/50 notes; BUG-0528, BUG-0529; PA-0528, PA-0529 — todo
  - [ ] update the test in 5.5 (`test_oracle_sqli_string.py` `[429]`) — todo
  - [ ] `scripts/verify_change.py --base 8100959` green, counts quoted — todo
- Effectiveness (assessed <date> or pending): pending
```

```
### CC-MUT-0403 — The live WAF filter never reads a throttled, gateway or unanswered request as "allowed" (FR-MUT-401, BUG-0529) (2026-10-19)
- Change:
  - `fuzzlab/mutation/livefilter.py`: `HttpFilter` classifies each answer through SP-56;
    `FilterUnobserved` is raised for throttle-or-unavailable, gateway or incomplete; a
    block and an allow are unchanged.
  - `fuzzlab/mutation/run.py`: `run_mutation` contains it per base (an `unobserved`
    count; no bypass recorded).
  - About +25 LOC, plus 3 tests in `tests/test_oracle_comparable_controls.py`.
- Impact: the mutation runs' bypass records. Consumers of `caught` and `evaluate` are
  listed in 5.1. No other component.
- Risk (low): a run against a throttling WAF now reports unobserved bases instead of
  bypasses. That is the intent.
- Deliverables:
  - [x] failing tests — done (Phase 1)
  - [ ] `FilterUnobserved` and its containment — todo
  - [ ] FR-MUT-401 — todo
- Effectiveness (assessed <date> or pending): pending
```

(A7's SCHED entry is **CC-SCHED-0007** (decided, revision 4): `ThompsonBandit.charge`
and `UniformScheduler.charge`, +15 LOC, pinned by
`…::test_a_non_comparable_run_charges_its_cost_and_leaves_the_arms_estimate`; FR-SCHED-8
amended in place. The drafts above are superseded by the committed entries.)

## 8. Requirement text

**FR-CORE-507 (SP-56).**
- `core.comparability.response_class(status, headers, *, complete, credentialed,
  credential_submission, redirect_to_login)` names an HTTP answer as one of:
  - **incomplete**: no status, a status of 0 or below, or not complete;
  - **throttle or unavailable**: 429, or 503 by policy;
  - **gateway**: 502, 504;
  - **auth failure**: 407; or a 401 or login redirect, when credentialed and not a
    credential submission;
  - **policy block**: 403, 451;
  - **application**: anything else.
- It is total; its reason names no URL, header value or body.
- It imports nothing from session or oracle.
- No other module classifies an answer by these statuses, except the listed allowances.

**FR-SESS-22 (SP-16 login facts).** `session.detect.login_facts(url, headers, *,
response_url, login_url, entry_names)` states:
- whether the request submits a credential: an SP-16 login URL or the known `login_url`;
  an account endpoint; or a credential name among its entries;
- whether the answer redirects to a login page: `Location` in any case, resolved against
  the response's own URL, judged by `redirect_is_logout` with the known `login_url`.

The runner, the oracle, the blind-SQLi builder and the live filter take these facts from
it alone.

**FR-FUZZ-52, edited in place** (the contract runner). It replaces "a send with no
complete response is an `error` …" and amends the oracle bullet:
- **Completeness.**
  - An exchange is complete when its status line, its headers and its whole body arrived
    within `timeout_ms` and `max_body_bytes`.
  - An incomplete one is never a pass, a baseline, a finding or a setup success, a cut
    5xx included.
  - Its only finding is a **read** (or deadline) timeout under a `latency_ms_gt` rule
    whose bound is at most `timeout_ms`; a connect timeout never proves latency.
  - Otherwise it is an `error` naming why.
  - The response is closed on every exit.
  - An incomplete body is never written to evidence ("omitted (incomplete)" and its byte
    count).
- **Every answer is classified once** (FR-CORE-507), with FR-SESS-22's facts:
  - **Throttle or unavailable** is judged only when `status_in` names its code.
  - **Auth failure**, for a profile that sends a credential, is an `error` "credentials
    not accepted" unless `status_in` names its code. This covers a 401, a 407 and a
    redirect to a login page. With no credential sent, a 401 or a login redirect is the
    endpoint's own answer.
  - **Policy block** is judged where `expect_status_class` holds 4xx or `status_in` names
    its code.
  - **Gateway** falls under the 5xx rule.
  - Otherwise each is an `error`. None is matched merely by being outside the expected
    class.
- **Baselines** come only from complete application answers below 400 that matched no
  rule.
- **Setup steps** must be complete application answers below 400 and not a redirect to a
  login page (a failed login).
- **State checks** are satisfied, violated or unobserved, each unobserved one with its
  reason:
  - not prepared, or refused at the send;
  - the read was not a complete 2xx, or not JSON;
  - not evaluable.

  A pass needs every state check satisfied. An unobserved one is an `error` "state check
  N (<call>) unobserved: <why>", or is listed in the result's `unobserved` beside a
  finding, with its redacted evidence.
- **Results** add `unobserved` and `response_class`. The verdicts are unchanged.

**FR-FUZZ-63 (a control counts only when it is the application's answer).**
- **Every response a mechanism reads is checked by the oracle**, the correlated probe
  included. Any of the following ends the mechanism with no verdict (`NotComparable`):
  - a throttle or unavailable answer;
  - a non-timing send's incomplete answer, or its PRG follow-up with no observation;
  - a timing send's status 0 that is not a read timeout.
- **A control, a baseline sample, a compared slot or a replay** counts only when its
  class is one the strategy declares for that role (default: application only; a gateway
  never). A probe's credential is the sender's per-probe fact; an unknown one counts as
  credentialed. A credentialed peer's refused credential is not a denial.
- The candidate is **inconclusive** (`not-comparable`, with its reason) unless another
  mechanism confirms. It is never confirmed on such a control and never a negative.
- The scheduler is charged the mechanism's cost without updating its success estimate.
- The blind-SQLi builder neither averages a non-application sample nor writes a row for
  one; a payload's 504 stays a timing observation; a baseline with no application sample
  is "not comparable".

FR-FUZZ-45 and FR-FUZZ-50 notes are as in revision 2, adding the read-timeout rule to
FR-FUZZ-50.

**FR-MUT-401 (the live WAF filter).** `HttpFilter` decides "caught" and "allowed" only on
an answer that observed the WAF:
- the block status is caught;
- a throttle-or-unavailable, gateway or incomplete answer raises `FilterUnobserved`. It
  is never counted as a block or a bypass.
- `run_mutation` counts it per base and records no bypass for that base.

## 9. Residual limits

1. **R1.** Classification uses status, headers and the credential and login facts. A
   block page answered with 200 is not detected. No vendor fingerprinting.
2. **R2.** A credential check that matches none of the three credential-submission rules
   (for example `/rest/2fa/verify` with a `code` field) reads a 401 as credentials refused.
   It fails closed (inconclusive).
3. **R3.** A session lost to an in-place login page (a 200) is not classified (defect 6).
4. **R4.** A signature, traversal or CRLF control the application itself answers with 403
   is inconclusive (decided: fail closed).
5. **R5.** In the runner, a body over `max_body_bytes` is an `error`. `MATCH_BYTES` (256
   KiB) is smaller than the cap (existing).
6. **R6.** The in-read deadline. A drip still holds the runner until the server stops
   (measured 3 s for a 1 s deadline); the verdict is now an `error`. Liveness needs a
   socket shutdown (measured 0.5 s; `close()` does not interrupt). That belongs to defect
   21's read-deadline owner.
7. **R7.** A state read answered 404 is unobserved, not a finding.
8. **R8.** `assertion_holds` reads a type mismatch as violated.
9. **R9.** A non-deciding mechanism's no-verdict keeps a decided candidate inconclusive
   (decided: keep).
10. **R10.** A payload (not a control) refused by a policy block or a credentialed auth
    failure still reads as not confirmed for a positive-evidence strategy. **Session-loss
    negatives from credentialed payloads are linked to defect 6's later item.**
11. **R11.** A delaying throttle (a tarpit) answers 200 late. Timing strategies cannot
    see it; ReDoS has no rising-delay check.
12. **R12.** Greybox screening and the pipeline's fingerprint baselines may be
    non-application answers. No verdict rests on them.
13. **R13.** Greybox's sender maps every `RequestException` to status 0. Layer 1 now
    makes that inconclusive, but PA-0153 wants a refused connection to fail loudly; the
    sender is unchanged.
14. **R14.** **503 by policy**, not measurement: RFC 9110 and nginx's documented default,
    not measured here. An application's own 503 is never judged by its class, and its
    **positive evidence in a payload's 503 is dropped** (layer 1).
15. **R15.** **Strict incompleteness drops observed evidence:** an observed 5xx status and
    a match in the received bytes of an incomplete exchange are not judged. This is in
    tension with PA-0137(1), and is decided.
16. **R16.** The mutation run's coverage sends (`RequestsCorrelatingSender`) are not
    classified. A throttled send scores no coverage novelty; no bypass decision rests on
    it.
17. **R17.** **A 403 under a 4xx expectation passes for any case type.** A WAF or CSRF
    block then passes a type, boundary, structural or syntax case. This is a black-box
    judgment, decided.
18. **R18.** Retry-After pacing is registered by the coordinator as a later item under
    defect 17. What it needs is unchanged from revision 2 (§3.5 there): per-origin pacing
    in the senders and `_pace`, a `retry_after()` in SP-56's owner, a whole-mechanism
    re-run from a fresh baseline, a runner re-queue, and a run metric.

## 10. Questions for the coordinator

**All decided (revision 4):** Q1 is CC-SCHED-0007; Q2's three probesender lines are
approved as listed; Q3, the pipeline comment, is this item's; Q4 (PA-0528(3) not
mechanically enforced, with its reason) is kept as stated. The original questions:

1. **A7 needs a SCHED number.** `scheduler/bandit.py` and `scheduler/uniform.py` (component
   SCHED) gain `charge()`. No CC-SCHED number was assigned. Assign one, or approve the
   fallback: the oracle calls neither `update` nor `charge` for a `NotComparable`, so no
   cost is charged. The fixture then still passes on "no update".
2. **M2's three probesender keywords** (3.6 changes 3-5) go beyond M7's permission. Approve
   them, or choose the fallback (3.6).
3. The `harness/pipeline.py:369-371` comment (A9) is AU-REQID's file. The proposed text
   is in 3.4. Forward it, or drop it.
4. A6: PA-0528(3) is stated as **not mechanically enforced**, with its reason (below).
   Accept that, or ask for a guard keyed on verdict producers (5 today: `Runner.judge`
   and four labgen oracles).

## 11. The coordinator's list, item by item

| Item | Where it is answered | Fixture or guard |
|---|---|---|
| M1 | 3.3(3), FR-FUZZ-52 | the flipped pin and the anonymous-401 pin |
| M2 | 3.1, 3.2, 3.4 (`credentialed`), 3.6 | the 3 oracle pins and 2 runner pins |
| M3 | 3.3(7) | `…never_written_to_evidence` |
| M4 | 3.4, layer 1 | 4 fixtures |
| M5 | 3.4 table | 3 fixtures and a pin |
| M6 | 3.1 rule 3, 3.3, 3.4 | a 502 and a 504 in the control grid; the 5xx pin |
| M7 | 3.3(1, 3), 3.4, 3.6 | the runner's connect timeout; the real-sender ReDoS pair |
| M8 | 3.3(6) | satisfying bodies, 11 rows |
| M9 | §6 | discovery table and send guard (Phase 2) |
| M10 | §6 | the 401 and login rows (B0/V/B, D, ReDoS, PRG), the clean baseline pin |
| M11 | 3.5, CC-MUT-0403 | 3 fixtures |
| M12 | 5.5 | |
| A1 | 3.2, CC-SESS-0028 | the runner login-URL pin; lowercase `location` (runner and oracle) |
| A2 | 3.3(3) | 2 runner tests |
| A3 | this file's path; test docstrings | |
| A4 | 3.4 | 7 tests |
| A5 | fixed, 3.4 | 1 fixture |
| A6 | §12 PA-0528 | |
| A7 | 3.4, §10 Q1 | 1 fixture |
| A8 | 3.3(5) | 1 fixture |
| A9 | 3.4 | (auto_cli display; Phase 2) |
| Residuals | §9: R10, R14, R15, R17, R18 | |

## 12. Bookkeeping text (for the orchestrator)

**Recurrence review**, as in revision 2:
- PA-0025, PA-0050 and PA-0311(2) were the wrong layer and not enforced over a new judge.
- PA-0117(1)/(3) was too narrow: a control, not a comparable one, and payload-independent
  noise only.
- PA-0153 and SP-34 were enforced at producers, not consumers. The status-0 stand-in, and
  now the connect timeout, still reached strategies.
- PA-0137(4) was not swept to HTTP timing baselines, replays or follow-ups.
- PA-0102(1) was enforced for the proxy only.
- **Added: PA-0507(2) was not followed in revision 2.** The `is_credential_name`
  predicate and `account_endpoint_reason` existed but were not used, and reviewer A's
  measurement found the true-positive loss.

**PA-0528 (from BUG-0528), proposed.** An outcome that claims something held (a pass, a
satisfied assertion, a baseline, a setup success) rests only on observations that were
complete and evaluated.
1. An exchange is complete only when its status, its headers and its whole body arrived
   within its limits. An incomplete one is judged only by what its incompleteness proves
   (a **read** timeout proves latency of at least the limit; a connect timeout proves
   nothing). It is never written to evidence, and the response is closed on every exit.
2. Every assertion is three-valued, with its reason. A pass needs every mandatory one
   satisfied. Each unobserved branch has a fixture whose body would *satisfy* the
   assertion.
3. A new judge or oracle is built against (1) and (2), with fixtures for a cut, stalled,
   late and connect-timed-out answer and an unobservable assertion. **Not enforced by a
   test:** a judge that does not exist yet has no stable shape to discover (verdict
   vocabularies differ: `pass`, `confirmed_secure`, `CHECKED`). It is applied in review.
   The line below enforces (1) and (2).

This strengthens PA-0025, PA-0311(2) and PA-0153.
- Enforced by: tests/test_disco_runner_outcomes.py::test_an_incomplete_200_is_never_a_pass_nor_the_endpoints_baseline, tests/test_disco_runner_outcomes.py::test_an_unobserved_state_check_is_never_a_pass, tests/test_disco_runner_outcomes.py::test_every_state_check_must_be_evaluated_for_a_pass, tests/test_disco_runner_outcomes.py::test_the_response_is_closed_on_every_exit, tests/test_disco_runner_outcomes.py::test_an_incomplete_body_is_never_written_to_evidence, tests/test_disco_runner_outcomes.py::test_a_connect_timeout_never_proves_latency, tests/test_disco_runner_outcomes.py::test_a_real_200_cut_or_stalled_after_its_headers_is_an_error

**PA-0529 (from BUG-0529), proposed.** A control, a baseline sample, a compared slot or a
replay is evidence only when it is the application's own answer. That is decided by one
classification (SP-56) from the answer and SP-16's credential and login facts.
1. Each strategy declares the classes each role admits, with its reason. Any other answer
   gives no verdict: inconclusive, never a confirmation and never a negative.
2. Every response a mechanism reads is an observation or ends it: a throttle or
   unavailable answer, an incomplete non-timing send, or a non-read timing timeout. A
   payload whose follow-up got no observation keeps its own response; a run that then
   decides nothing is inconclusive. A control's unobserved follow-up ends the mechanism
   only where the strategy needs it observed alike. *(B2, revision 4.)*
3. A request that submits a credential is never read as a session loss. The credential
   a probe carried is a per-probe fact; an unknown one counts as carried.
4. This is enforced by discovery. Every default strategy is classified. Every send of a
   control reader is compared, or is a declared literal mutation (AST, proven on a
   revert of `_compared`, an untagged control and a non-literal role). No status
   classification exists outside the owner but a reviewed allowance list.

This strengthens PA-0117(1)/(3) and PA-0137(4), and applies PA-0507(2).
- Enforced by: tests/test_oracle_comparable_controls.py::test_a_signature_absent_from_a_control_that_is_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_differential_whose_baseline_and_variant_are_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_credential_submissions_own_refusal_is_its_answer_and_still_confirms, tests/test_oracle_comparable_controls.py::test_every_default_strategy_says_how_it_reads_controls, tests/test_oracle_comparable_controls.py::test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner, tests/test_disco_runner_outcomes.py::test_a_throttled_answer_is_never_judged_by_its_status_class

**SP-56 row, proposed.**

| ID | Mechanism | Owner | Guard test(s) | From |
|---|---|---|---|---|
| SP-56 | Whether an HTTP answer is the application's own (comparable), or a throttle-or-unavailable, gateway, auth-failure, policy-block or incomplete answer, from the answer and the exchange's facts (credentialed: per probe; credential submission and login redirect: SP-16's `login_facts`). Read by the contract runner, the oracle's `require_observed` and `require_comparable`, the blind-SQLi builder and the live WAF filter. | `fuzzlab/core/comparability.py::response_class` (facts: `fuzzlab/session/detect.py::login_facts`; the oracle's `NotComparable`, `require_observed` and `require_comparable` in `oracle/probe.py`) | `tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner`, `tests/test_core_comparability.py::test_the_status_guard_catches_a_synthetic_offender`, `tests/test_core_comparability.py::test_the_classifier_imports_neither_session_nor_oracle`, `tests/test_oracle_comparable_controls.py::test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0528, PA-0529 (CC-CORE-0069, CC-SESS-0028, CC-FUZZ-0105, CC-MUT-0403) |

**ARCHITECTURE note, proposed.**
- `core/comparability.py` (SP-56) depends on nothing above core.
- `session/detect.py::login_facts` supplies its facts.
- The runner, `oracle/probe.py`, blind SQLi and `mutation/livefilter.py` read both.
- The runner gains no `fuzzlab.oracle` import.
- `Probe` carries `credentialed` and `timeout`.

## 13. Revision 4: the third review's B1, B2 and ADOPT 1-8, as implemented

| Item | Implemented as | Pinned by (each fails on its named revert) |
|---|---|---|
| B1 | `session.detect.CREDENTIAL_PATH_TOKENS` (register, registration, signup, "sign up", password, passwd, reset) replaces the login window's account test | runner `test_a_credentialed_401_at_a_user_resource_is_credentials_not_accepted`; oracle `test_a_peer_replay_refused_at_an_account_resource_is_inconclusive`; the `/register` pin still confirms; `test_login_facts_names_every_credential_submission` (the four measured URLs) |
| B2 | layer 1 no longer raises on `PRG_UNOBSERVED`; payload follow-ups counted (not the `control`/`baseline` roles), a final None becomes `NotComparable`; the three "observed alike" branches raise | `test_a_direct_signature_with_a_control_whose_follow_up_got_none_still_confirms` (3); `test_a_control_showing_the_signature_is_a_negative_whatever_its_follow_up`; the M4 control (3) and payload tests |
| ADOPT 1 | `oracle.probe.candidate_entry_names`: a JSON leaf by `jsonbody.display_name` | `test_a_json_points_password_leaf_makes_its_refusal_the_endpoints_answer` |
| ADOPT 2 | residual R19 (`pass_count`) in BUG-0529 and FR-SESS-22 | -- |
| ADOPT 3 | `Prepared.credentialed` from the final headers | `test_a_case_that_replaces_the_credential_is_judged_under_its_expectation` (forged, empty) |
| ADOPT 4 | a replay admits application or policy, never a gateway; payloads unchanged (residual R21) | the 502/504 replay rows |
| ADOPT 5 | `LoginFacts.account_submission`; the setup check excepts it | `test_a_setup_registration_redirected_to_the_login_page_is_its_success` |
| ADOPT 6 | the unreachable "redirect to the login page" follow-up fixture replaced by a 403 and a 502 follow-up | `test_a_controls_prg_follow_up_that_is_not_the_applications_never_confirms` |
| ADOPT 7 | this draft's numbers table, §3.4, §3.6, §7, §10 | -- |
| ADOPT 8 | every seed measured to reach the 429 at request 8; explicit early-end branch | `test_a_site_that_throttles_mid_differential_is_not_comparable_never_a_negative` |

Added after implementation, each with its revert proof: the anonymous plain sender's
401 (change 3), the seam sender's credential by identity (change 5), a follow-up
inheriting its request's credential fact, a read-timed-out timing baseline (layer 2
only). Residuals added: R19-R23 (BUG-0529).
