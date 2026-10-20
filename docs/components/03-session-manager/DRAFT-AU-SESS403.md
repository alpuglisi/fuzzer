# DRAFT AU-SESS403: a forbidden answer is never, by itself, a lost session

- **Item:** `AU-SESS403`, audit defect 6 ("Every forbidden response can trigger
  another login"). The owner's audit is at 6552276. The coordinator confirmed it at
  6552276.
- **Base:** `15a8a27`, the tip of `ccr-602fc4d9-vyovmz`.
- **Status:** Phase 1. The defect is measured and the design is drafted; nothing is
  implemented. This draft goes to the pre-change review gate
  (`docs/components/README.md`) for two reviewers. Implementation starts only after
  3/3 agreement.

**Numbers (pre-assigned; only these are used):**

| Number | Covers |
|---|---|
| CC-SESS-0029 | `session/detect.py`, `session/manager.py`, `session/state.py` |
| FR-SESS-23 | the new requirement (§7). FR-SESS-5, -15, -16, -17 and -18 are amended in place. |
| BUG-0533 / PA-0533 | the bug record and its preventive action (§10) |
| CC-CORE-0070 | `core/http.py::Request.session_generation` (one field), and SP-56's guard allowance list in `tests/test_core_comparability.py` (three rows removed) |
| *(not assigned; needs the coordinator)* | the optional oracle part (§3.13). It is a FUZZ change: **asked, not drafted as approved.** |

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### 1.1 The probe

**`tests/test_session_forbidden_answers.py`** is committed with this draft. It holds:
- a real loopback app (`_App`, `ThreadingHTTPServer` on `127.0.0.1:0` through
  `require_loopback`);
- the real `SessionManager` with its **default requests fetcher**
  (`browser_login=False`: no browser);
- the real `core.http.HttpClient` seam with its default requests transport;
- the real `SeamProbeSender`, which is how the oracle and the cross-account peer send.

Credentials are in memory: `CredentialStore(backend=tests.test_credentials.FakeBackend())`
(D12). No secret is real and nothing leaves loopback.

How each count is taken:
- **Logins:** the server counts each successful `POST /login.php`.
- **Invalidations:** an FR-SESS-16 logout listener counts each valid -> invalid
  transition.
- **Sessions used:** the server records the `SID` each request carried when it arrived,
  read from its whole log (PA-0511).

The app is shaped like the PHP labs:
- `GET /login.php` sets an anonymous `SID` first, as PHP's `session_start()` does
  (PA-0007).
- The login form's `user_token` is new on every load, as DVWA's is.
- A successful login regenerates the `SID` and redirects to `/home.php`.
- Every protected page redirects an anonymous visitor to `/login.php`.

Each route models one answer:

| Route | Answer to the low-privilege identity |
|---|---|
| `/admin.php` | 403: an authorization denial |
| `/search.php?q=` | 403 when `q` holds a quote: a WAF rule |
| `POST /comment.php` | 403 without the session's CSRF token |
| `/products.php` | 429 with `Retry-After` |
| `/api/reports` | 401 "insufficient scope" |
| `/manager.php` | 302 to `/login.php?next=…`: a privilege-gated login redirect, FR-SESS-18's residual |
| `POST /account/password.php` | 401 for a wrong current password: a credential submission's own refusal |

`python3 -m tests.test_session_forbidden_answers` prints the table below. It was run
twice at 15a8a27 with identical counts, while another session's full verify run was
loading the host.

### 1.2 Today's behaviour (15a8a27), per scenario

Each scenario sends 10 probes by the low-privilege identity through `SeamProbeSender`.

| Scenario | Probes | Logins | Invalidations | Sessions the probes carried | Statuses |
|---|---|---|---|---|---|
| admin route, 403 (authorization denial) | 10 | **10** | **10** | **10** | 403 |
| WAF 403 on a quote | 10 | **10** | **10** | **10** | 403 |
| CSRF-failure 403 | 10 | **10** | **10** | **10** | 403 |
| 429 | 10 | 1 | 0 | 1 | 429 |
| 401 "insufficient scope" on a live session | 10 | **10** | **10** | **10** | 401 |
| privilege-gated login redirect | 10 | **10** | **10** | **10** | 302 |
| credential submission's own 401 | 10 | **10** | **10** | **10** | 401 |
| admin 403, n = 1 / 5 / 20 | 1 / 5 / 20 | **1 / 5 / 20** | **1 / 5 / 20** | **1 / 5 / 20** | 403 |

**N forbidden probes cost N logins** (one first login plus N-1 re-logins), with no cap:
- 20 probes made 20 logins.
- `max_reauth` counts only *consecutive failed* logins. `_failures` is reset to 0 on
  every success (`manager.py:483`), so it never limits successful re-logins.
- Every probe ran on a new server-side session: the "session changing mid-test" of the
  audit, measured.

**Cost per login on this app: 6 requests.**
- The requests are: `GET /` twice (discovery, then verification), `GET /login.php`,
  `POST /login.php`, and `GET /home.php` twice.
- 10 forbidden probes cost 60 extra requests and 10 password submissions.
- Probe: `scratchpad/au-sess403/cost.py`. Output: `admin-403 total requests: 70 probes:
  10 login-handshake requests: 60 logins: 10 per login: 6.0`. The 429 run took 16
  requests, one login.

### 1.3 Concurrency and late answers

| Run | Logins | Invalidations | Reading |
|---|---|---|---|
| one round of 6 concurrent first sends (the server holds the round until all 6 have arrived) | **1** | 1 | **The single-flight lock stops simultaneous duplicates.** The audit's claim is measured true. |
| 4 rounds of 6 concurrent 403s | **4** (1 per round) | 4 | The lock does not stop **sequential** churn: one login per round. |
| a late answer from an earlier session | **3** (2 needed) | **2** (1 needed) | **Not in the audit.** See below. |

The late-answer run, step by step:
1. `/slow.php` is sent on session 1, and the server holds it.
2. The server expires session 1.
3. The next send sees the loss, and session 2 logs in.
4. Session 1's late redirect to the login page then arrives. It invalidates session 2,
   and a third login follows.

Single-flight cannot prevent this. Nothing ties a loss signal to the session the
request carried.

### 1.4 The stable protected resource on an HTTP login today

`run_protected_resource` logs in on the app, then calls the one existing differential,
`SessionManager._spa_probe` (FR-SESS-19), on `/home.php` and on `/`:

| Login page | `state.protected_probe` after the login | `_spa_probe` finds |
|---|---|---|
| token new on every load | **None** | **nothing** (the refused arms' bodies differ on every fetch) |
| a static token | **None** | `/home.php`, with a refusal digest |

- An HTTP form login records **no** protected resource today. Only a browser login does
  (`manager.py:984`).
- The existing differential needs byte-identical refusal bodies. A per-load CSRF token
  breaks that, even though both refused arms are this session's login form.

### 1.5 Facts the design relies on

| Fact | Source | Result |
|---|---|---|
| `detect_logout` decides a loss by status | `session/detect.py:421` | `if status in (401, 403): return True`. Measured: `detect_logout(401)` and `detect_logout(403)` are True; 451, 429, 502, 503, 504 and 407 are False. |
| `observe` acts on it at once | `session/manager.py:399-410` | `state.valid = False`, persisted, and the listeners are told; the next `prepare` re-logs in (`:350-353`) |
| SP-56 already classifies these answers | `core/comparability.py:69-90` | 403 and 451: `policy-block`. A credentialed 401 or a credentialed login redirect that is not a credential submission: `auth-failure`. 407: `auth-failure` whoever sent it. 429 and 503: `throttle-or-unavailable`. The module imports neither session nor oracle, by design for this item (its docstring names defect 6). |
| SP-16 already computes the facts SP-56 needs | `detect.login_facts` (FR-SESS-22) | a credential submission (a login URL, credential path tokens, a credential field name) and a redirect to a login page |
| SP-56's status guard lists this item's sites | `tests/test_core_comparability.py:136-151` | `detect_logout` ("until defect 6's item routes it"), `verify_live` and `_verify_authenticated` ("defect 6's item routes it"), plus `_login`, `_discover_login_form` and `detect_session_credential` (login and Basic, not session loss) |
| A framework's own answer to a missing credential | `scratchpad/au-sess403/fastapi_missing_auth.py`, offline (Starlette `TestClient`, no network). FastAPI 0.143.3: `HTTPBearer`, `OAuth2PasswordBearer`, `APIKeyCookie`, `APIKeyHeader`, `HTTPBasic` | **all answer 401** with `WWW-Authenticate`; none answers 403 |
| What this repo's own labs answer 403 for | `labgen/emitters/spring_boot/templates/sinks/identity_match_before_fetch.java.j2:10`, `labgen/emitters/go_net_http/templates/sinks/object_lookup_authorization_check.go.j2:12` | a 403 to a **valid** identity on someone else's object. These are the secure twins of the access-control cells, and the cross-account peer replay (FR-FUZZ-55) hits them. A grep of `fuzzlab/labgen` found no lab that answers 403 for a missing session. |
| Django REST framework's `SessionAuthentication` answers 403 for a missing session | its documentation | **Not measured:** DRF is not installed and there is no network. The design does not rely on it (§8, R1). |
| How a `SessionAuthError` from `prepare` reaches the oracle | `tools/probesender.py:219-242`, `oracle/oracle.py:470-510` | `_unobserved` maps only transport errors, so a `SessionAuthError` is re-raised; the oracle catches only `UnplaceableLocation` and `ProbeUnobserved`. The run then ends and is marked aborted (`auto_cli.py:240`), as today's `max_reauth` cap does. |
| The contract runner does not use the session manager | `disco/runner.py:243-330` | static auth profiles (`keyring:`, `env:`, storage state). SP-56 already makes a credentialed 401 or login redirect an `error` there. |
| The disco explorer's session check | `disco/explore.py:1251-1336` | `looks_like_login_url(page.url)` only; no status. This is audit defect 4's item; see §5.7. |
| The header breaker and the single-session breaker are told inside the observing send | `tools/probesender.py:315-326`, `:452-461`, `:601-621`; FR-SESS-16 | They need the listener to fire in the send that saw the loss, so a check that confirms a loss must run inside `observe`. |
| Loopback traffic bypasses the agent proxy | `NO_PROXY` holds `127.0.0.1` | the loopback measurement is direct |

### 1.6 The failing tests (written first; run at 15a8a27)

`tests/test_session_forbidden_answers.py` has 15 tests.
- **10 fail on 15a8a27, each for the measured reason.** They are marked
  `xfail(strict=True)` with BUG-0533 as the reason, so this lane branch stays green;
  CC-SESS-0029 removes the markers. If a marker is left behind, the test fails as an
  XPASS.
- **5 are pins that pass today** and must keep passing: the 429; the real expiry; the
  single-flight lock; `detect_logout`'s loss signals and its throttle and gateway
  negatives; and the 451.

The pytest run, one pytest at a time, after the wait loop showed no other pytest or
`verify_change`: see §12.

## 2. The defect, as measured

`observe` acts on one answer's status. It never asks whether that answer is evidence
about *this session*:
1. A 403 is a policy answer: a denial, a WAF, a CSRF check. SP-56 says so, but
   `detect_logout` does not consult it.
2. Some answers never had a loss to suspect: a 401 to a credential submission, which
   PA-0529(3) states is never a session loss; a 401 for scope; a privilege-gated login
   redirect.
3. An answer from an earlier session generation is applied to the current one.
4. Nothing confirms a suspicion on a resource whose answer is known to depend on the
   session.
5. Nothing caps successful re-logins.

The result is one login, 6 requests and a new session per forbidden probe. The session
also changes in the middle of the oracle's differentials.

## 3. Design

### 3.1 Classification first: `detect_logout` routes through SP-56 (`session/detect.py`)

New signature (callers today: `observe` only):

`detect_logout(status, headers, body, login_url=None, page_url=None, content_check=True,
login_fields=None, *, credentialed=True, credential_submission=False) -> bool`

It returns True for a **suspected loss**, and only in these cases:
- **An auth failure that is this session's.** `core.comparability.response_class`, with
  `redirect_to_login` from `redirect_is_logout` (FR-SESS-18, unchanged), gives
  `AUTH_FAILURE` for the request as sent, *and not* for the same answer with
  `credentialed=False`.
  - The second test removes the 407, which SP-56 names an auth failure whoever sent it:
    it is an intermediary's demand, never this session's loss.
  - It needs no status literal, so the module leaves SP-56's guard allowance list.
  - What remains: a credentialed 401, or a credentialed redirect to a login page, to a
    request that is not a credential submission.
- **This session's login form, shown again at 200.** `content_check` is true, the
  request was credentialed and is not a credential submission, and the FR-SESS-15 /
  BUG-0113 form rules match (`shows_login_form`, or `is_login_page` without a known
  login URL). **The form rules are unchanged.** Only the credential-submission
  exclusion is added: PA-0529(3) applies to every signal.

Every other class never changes the session: `policy-block` (403, 451),
`throttle-or-unavailable`, `gateway`, `incomplete`, and the rest of `application`.

The defaults (`credentialed=True`, `credential_submission=False`) keep the old callers'
meaning for everything except the 403. This is the SP-56 convention: a fact nobody
states is read as carried.

A new helper in the same module (SP-16):
`request_entry_names(url, body, content_type) -> tuple[str, ...]`.
- It returns the query's names, a urlencoded body's names, and a JSON body's leaves by
  `jsonbody.display_name`.
- It reads at most 64 KiB of body, and is total: odd input reads as `()`.
- Multipart bodies are not read (§8, R11).
- `observe` passes it to `login_facts(..., entry_names=...)` for `credential_submission`.

### 3.2 Generations (`session/state.py`, `session/manager.py`, `core/http.py`)

- **`SessionState.generation: int`.** Each successful login, and each `adopt`, takes the
  next value of a per-`(host, identity)` counter in the manager. It is in memory only,
  not secret, and shown by `redacted()`.
- **`core.http.Request.session_generation: int | None = None`.** This is CC-CORE-0070,
  one field beside `session_decision`. `prepare` sets it when it applies the session.
- **In `observe`, a suspected loss is judged only against the generation the request
  carried.**
  - A request prepared on another generation is **stale**: ignored and counted.
  - A request that does not say (None: a test double, a direct `observe` call) is read
    as the current generation, which fails closed.
- This fixes the late-answer run (§1.3).

### 3.3 The health check: one owner, `SessionManager.check_health(host, identity, base_url) -> Health`

`Health` is a frozen dataclass: `state` is `LIVE`, `LOST` or `INCONCLUSIVE`; `reason` is
a fixed text naming a class and a status, never a URL, header value or body; and
`retry_after_s` is a float or None.

**The request.**
- One `GET` of the session's stable protected resource (§3.4) with a fresh fetcher.
- It carries `state.apply({})`: the session's cookies and headers, never a probe's.
- `_navigate` walks the redirects by hand, inside `session_origins=state.origins` and
  the transport floor (FR-SESS-13 and FR-SESS-20, unchanged).
- A new `_navigate(..., stop_at=…)` stops at the first hop whose `Location`
  `redirect_is_logout` judges a login redirect. A login redirect to another origin (an
  IdP) is therefore judged at that hop and never fetched.

**The verdict** is `health_verdict(...)` in the manager, a pure function of the answer,
the hop that stopped, and the state:

| Answer of the protected resource | Verdict |
|---|---|
| SP-56 `auth-failure` that is this session's (a 401; the login redirect it stopped at) | **LOST** |
| 2xx that shows this session's login form (`shows_login_form`), or whose body hashes to the recorded refusal (`probe_refusal_digest`) | **LOST** |
| any other 2xx | **LIVE** |
| `policy-block`, `throttle-or-unavailable` (its `Retry-After` kept), `gateway`, 407, any other status, no response (a `requests` exception) | **INCONCLUSIVE** |
| an unapproved hop (`_navigate` raises `SessionAuthError`) | propagates from `check_health`, so `verify_live` keeps its pinned contract (`tests/test_session_origin_scope.py:435`, `:451`: it raises, "cannot verify"). `observe` and `prepare` catch it as **INCONCLUSIVE**. |

**Locking and caching.**
- Single-flight per `(host, identity)` under a health lock. The lock is held across the
  health GET and never together with the login lock or `_observe_guard`.
- A live verdict is cached as `(generation, at)` for `health_ttl_s` (default 30 s), and
  only for that generation.
- A lost verdict needs no cache: the state goes invalid and the next login is a new
  generation.

### 3.4 The stable protected resource (`SessionState.protected_probe`): where it comes from

It is recorded at login, by the first rule that holds:

1. **Browser login (FR-SESS-19).** `_spa_probe`'s differential over the app's
   post-click GETs. Unchanged except for (3)'s extension.
2. **HTTP form or JSON login, by the base URL's own redirect: no extra request.** It
   holds when both observations hold:
   - Discovery reached this login form by following **the base URL's own** redirect
     (`_discover_login_form`'s first candidate, landing on another page). That is the
     anonymous arm: the discovery fetcher's first GET carries no session cookie (the
     measured app sets its anonymous `SID` only on the login page).
   - The post-login check of the base URL (`_verify_authenticated`) was LIVE. That is
     the credentialed arm.

   This is FR-SESS-5's own definition: a protected probe stops redirecting to login. On
   the measured app it records `/`.
3. **Otherwise, an HTTP login's post-login landing URL.** This is the target of the
   credential POST's redirect, when it was followed, inside the origins, not an auth
   endpoint and not destructive. It is recorded when `_spa_probe`'s differential holds
   on it, with one extension:
   - The two refused arms (anonymous and corrupted) also **agree when both show this
     session's login form**. With both refused arms shown to be the login form, the
     second fetch of each is skipped.
   - A per-load token then no longer breaks the agreement (§1.4).
   - It costs 3 GETs (6 with the byte rule).
4. **HTTP Basic.** The base URL that challenged anonymously (the 401 that
   `_discover_login_form` read) and answered 2xx with the header.
5. **None of these.** An adopted captured session (FR-SESS-11), a public base with no
   protected landing, or an SPA login whose differential found none (which already fails
   that login).

`_spa_probe` becomes the one owner of the decision "this URL tells a live session from a
lost one" for every login kind (PA-0507(2)). Rule (2) supplies arms the login already
observed, judged through the same `health_verdict`. Its docstring and FR-SESS-19 say so.

**With no protected resource**, a suspected loss is a loss, **unconfirmed**.
- These are FR-SESS-5's signals minus the 403: a credentialed 401, a login redirect, or
  this session's login form.
- Each one is counted (`unconfirmed_losses`) and is bounded by the re-login cap (§3.6).
- Without a resource whose answer depends on the session, no request can tell an expiry
  from a denial. The residual is stated (§8, R2).

### 3.5 What `observe` does

```
signal = detect_logout(..., credentialed=<prepared by this manager>,
                       credential_submission=login_facts(url, response.headers,
                           login_url=state.login_url,
                           entry_names=request_entry_names(...)).credential_submission)
no signal                                  -> counted by SP-56 class; nothing changes
generation(request) != state.generation    -> stale (counted); nothing changes
state invalid or paused                    -> nothing (the re-login / re-check decides)
cached LIVE for this generation, in TTL    -> cached (counted); nothing changes
no protected resource                      -> LOST (unconfirmed)
else check_health:
   LIVE         -> cache; nothing changes
   LOST         -> _mark_lost: the atomic valid -> invalid, persist, listeners told once
   INCONCLUSIVE -> pause (§3.7); nothing else changes, no listener
```

- `_mark_lost` is the one place that writes `valid = False`. `verify_live` reaches it
  through `check_health`. An AST guard holds this (§6, T19).
- The request's facts (`login_facts`, `request_entry_names`) are computed only when the
  answer could be a signal: SP-56 names it an auth failure on the worst-case facts
  (credentialed, not a submission), or it is a 200 the content rule reads. That
  pre-check goes through `response_class` too, so no classified status appears as a
  literal in session code (the SP-56 guard). Today's 200 HTML parse is unchanged.

### 3.6 The re-login cap

- At most `max_relogins` loss-driven re-logins (default 5) per `relogin_window_s`
  (default 600 s) per `(host, identity)`, on the manager's clock.
- The next one makes `ensure` raise `SessionAuthError`. It names the count, the window
  and the last loss's class, and the run ends loudly (FR-SESS-5's "cap attempts then
  hard-fail"; FR-SESS-6).
- The first login and a JWT `exp` refresh (`is_time_expired`) do not count.
- `max_reauth` (consecutive failed logins) and an isolated copy's `max_logins` are
  unchanged.
- A cap reached is no longer a forbidden-probe storm: 403s no longer log in. It is a run
  whose session really keeps getting lost (a logout endpoint probed, a session bound to a
  probed header), and that run is not testing one identity.

### 3.7 The pause: an inconclusive check changes nothing

**On an INCONCLUSIVE verdict:**
- No invalidation, no login, no listener.
- The identity is **paused** until `now + backoff`. The backoff is 5 s, doubling to
  60 s; a `Retry-After` on the check's answer is honoured up to 60 s.

**`prepare` for a paused identity** (a credentialed send):
- It waits the pause out on the manager's injectable `sleep` and `clock`, holding no lock.
- Then it checks again, single-flight:
  - **LIVE:** resume, and the send goes out on the same generation.
  - **LOST:** `_mark_lost`, then a re-login under the cap, and the send goes out on a
    new generation.
  - **INCONCLUSIVE:** paused again with the backoff doubled.
- After `max_pause_s` (default 300 s) unresolved, `prepare` raises
  `SessionHealthUnknown(SessionAuthError)` with a fixed reason. An isolated copy raises
  `IsolatedLoginFailed(reason="isolated session health unknown")` instead (FR-SESS-17's
  one class), so its sender releases the copy and sends that path anonymously.
- **No request ever goes out on an identity whose state is unknown, and no identity
  changes silently.**

**How the pause reaches the oracle.** No oracle change is needed.
1. The pause is a delay inside the send of the mechanism's next probe.
   - That probe goes out only once the identity is known: still live on the same
     generation, or explicitly re-logged in.
   - The probe's request records the generation it carried.
2. Past `max_pause_s`, `SessionHealthUnknown` propagates as today's `max_reauth` cap
   does (§1.5): `_unobserved` returns None for it, the oracle does not catch it, and the
   run ends marked aborted with its results so far.
3. A comparison whose probes straddle a re-login is **not** detected by the oracle
   without the optional part §3.13. That is residual R6.

**How it reaches the runner: it does not.**
- The contract runner never uses `SessionManager` (§1.5). It has no observe and no
  re-login, so it has nothing to pause.
- Its SP-56 judgement already makes a credentialed 401 or login redirect an `error`, and
  a 403 or 451 an `error` unless the case expects it.
- A lost runner session therefore shows as errors, never as passes (R9).

### 3.8 Listeners and the breakers (FR-SESS-16)

The listeners are told only by `_mark_lost`: a confirmed loss, or an unconfirmed one when
no resource is known. They are never told for:
- a policy block or another non-signal;
- a stale answer;
- a cached-live suspicion;
- an inconclusive check.

They are still told inside the observing send, atomically, once per valid -> invalid
transition.

- **Header breaker (FR-FUZZ-43).** A session bound to a probed header is killed
  server-side. The health check carries only the session's own headers, so it reads LOST
  and the breaker trips in that same send.
  - With no resource, the existing fixtures behave as today (unconfirmed loss).
  - A bound session that shows its loss only as a 403 no longer trips the breaker (R1).
- **Single-session breaker (FR-FUZZ-44).** `_on_main_logout` and `_verify_main` are
  unchanged.
  - `_verify_main` calls `verify_live`, whose INCONCLUSIVE is `False` without
    invalidating (§3.9). It trips the breaker, as an unapproved hop does today: fail
    closed.

### 3.9 `verify_live` and `_verify_authenticated`

- **`verify_live(host, identity, base_url)`** is `check_health(...)`:
  - **LIVE:** True.
  - **LOST:** False, and the state is invalid and persisted (as today; listeners not
    told, as today).
  - **INCONCLUSIVE:** False, and **nothing is changed**.
  - **An unapproved hop:** raises `SessionAuthError`, exactly as today (pinned by
    `tests/test_session_origin_scope.py::test_verify_live_never_follows_a_redirect_to_another_port`
    and `…::test_verify_live_keeps_the_session_inside_its_origins_even_where_a_login_may_go`).
  - The changes from today: a 403 on the base URL no longer invalidates, and a 429, 503
    or 5xx is no longer read as live.
  - With no resource it judges `base_url` with `health_verdict`, as today's base-URL
    check does but through SP-56.
  - Callers: the crawler's `_live_session_intact` (fail closed, unchanged; R10) and
    `SeamProbeSender._verify_main` (§3.8).
- **`_verify_authenticated`** (the post-login check) is routed through `health_verdict`,
  with today's acceptance kept and stated:
  - **LOST:** False.
  - **`policy-block`:** False. Today's 403 rejection, now named by class.
  - **Anything else:** True. Today's acceptance of a 429 or 5xx.
  - It also supplies rule (2)'s credentialed arm (§3.4).

### 3.10 What is reported

`SessionManager.health_report()` returns counts per `(host, identity)`:
- policy blocks seen, by class;
- suspected, stale, cached, checks, live, lost, unconfirmed and inconclusive;
- paused seconds;
- re-logins, and the cap if reached.

It holds no URL, header value or body. Surfacing it in `auto`'s run metrics is a FUZZ
change: question Q2.

### 3.11 Locks (the order is fixed and never nested the other way)

- **`_observe_guard`:** the valid -> invalid check-and-set only (unchanged).
- **Health lock, per `(host, identity)`:**
  - It is held across one health GET.
  - Taken in `observe` (a signal) and in `prepare` (a pause re-check).
  - It is released before `_mark_lost` calls the listeners, and before any login.
- **Login lock, per `(host, identity)`:** `ensure`, unchanged.
- **The pause wait** holds no lock.
- **The health GET** goes through the manager's own fetcher, never the seam, so it never
  re-enters `observe`.

### 3.12 Files and size (estimates)

| File | Change | LOC |
|---|---|---|
| `fuzzlab/session/detect.py` | `detect_logout` through SP-56 (keyword facts); `request_entry_names` | +45 / -5 |
| `fuzzlab/session/manager.py` | `Health`, `health_verdict`, `check_health`, `_mark_lost`, the pause, the cap, generations, `_navigate(stop_at=)`, rules (2)-(4), `_spa_probe`'s login-form agreement, `health_report`; new kwargs `health_ttl_s`, `max_relogins`, `relogin_window_s`, `max_pause_s`, `clock`, `sleep` (copied to isolated copies) | +260 / -30 |
| `fuzzlab/session/state.py` | `generation`; the live cache and pause fields (in memory, `compare=False`) | +12 |
| `fuzzlab/core/http.py` | `Request.session_generation` (CC-CORE-0070) | +4 |
| `tests/test_core_comparability.py` | three `ALLOWED` rows removed (CC-CORE-0070) | -6 |
| `tests/test_session_forbidden_answers.py` | markers removed; Phase-2 tests (§6) | +450 |

### 3.13 Optional: the oracle part (a FUZZ change; **asked first, not assumed**)

Two of BUG-0529's residuals were handed to this item, and neither closes without the
oracle:
- **R3:** a session lost to an in-place 200 login page is not classified.
- **R10:** session-loss negatives from credentialed payloads.

Defect 6's "changing session context during differential tests" also needs the oracle,
for the straddle case.

The proposal:
- **F1.** `SeamProbeSender._dispatch` copies the request's `session_generation`, and
  `observe`'s outcome for it (lost, confirmed or unconfirmed), onto the `Probe`. This
  needs `Probe.session_generation` and `Probe.session_lost`, and `observe` would record
  the outcome on `Request` (CC-CORE-0070 would grow by one field).
- **F2.** `require_observed`, layer 1, raises `NotComparable` (`auth-failure`, "the
  session was lost") for a probe whose session was found lost.
- **F3.** `_ObservedOnly` raises `NotComparable` ("the session changed during the
  comparison") when a mechanism's credentialed probes carry different generations.

Files: `tools/probesender.py`, `oracle/probe.py`, `oracle/oracle.py`. It needs a
CC-FUZZ number and the coordinator's approval. Without it, R6 and R7 stand as stated.

## 4. What is unchanged on purpose

- **The form rules of `detect_logout`'s content check** (BUG-0113: this session's form;
  `is_login_page` without a known login URL), and **FR-SESS-18's redirect rules**
  (`redirect_is_logout`, `_same_login_url`).
- **`_login`'s rejection of a credential POST answered 401 or 403**, and the Basic
  challenge reads (`_login`, `_discover_login_form`, `detect_session_credential`).
  These decide login success, not session loss, and their allowance rows stay.
- **The single-flight login lock, `max_reauth`, and an isolated copy's `max_logins` and
  distinctness.**
- **The JWT `exp` proactive refresh.**
- **`_spa_probe`'s existing byte-equality rule.** The login-form agreement only adds
  acceptances.
- **The FR-SESS-20 origin rules for every request the health check makes.**

## 5. The sweep (PA-0002; PA-0138(3); SHARED_PRIMITIVES rule 2; CLAUDE.md item 7)

SP-16 is the shared primitive. The sweep is by mechanism.

**5.1 Callers of `detect_logout`.** `grep -rn detect_logout fuzzlab tests`:
- `session/manager.py:399` (`observe`) is the only production caller. It is fixed here.
- `tests/test_session_detect.py:86-89` and `tests/test_logout_redirect.py:38` call it
  with the old signature. They keep passing: the defaults keep 401, login redirect and
  login form as signals.
- `tests/test_core_comparability.py:142`: its row is removed (CC-CORE-0070).

**5.2 Consumers of `observe` and of `SessionState.valid`.**
`grep -rn "\.observe(\|\.valid\b" fuzzlab`:
- `core/http.py:214` (`HttpClient.send`) calls `observe`. It is unchanged, apart from
  `Request.session_generation`, which `prepare` sets.
- Every `HttpClient` with a manager gets the fix:
  - `tools/authhttp.py` (`make_auth*`, `make_authenticated_client`);
  - `tools/probesender.py::make_probe_sender`, which is the run's sender and the
    cross-account **peer** sender (`harness/auto_cli.py:387-389`);
  - `tools/fetcher.py:957` (the auditor's seam);
  - every isolated copy's client.
- Writers of `.valid`: `adopt :312`, `observe :405`, `verify_live :644`, `_established
  :920`, `_browser_login_state :985`, `_basic_login :1237`. After the change:
  - the two `False` writers become `_mark_lost`;
  - the four `True` writers are the login ends and `adopt`, each of which takes a new
    generation.
- Readers of `.valid`: `prepare :350`, `ensure :452`, `verify_live :622`, `redacted`,
  `non_secret_state`. A paused state is still `valid`; `prepare` reads the pause.
- `core/store.py:182` persists `valid` (non-secret, unchanged).

**5.3 The logout listeners (FR-SESS-16).** There is one registrant, `SeamProbeSender`:
`_on_logout` (the header breaker, `:365`) and `_on_main_logout` (the single-session
breaker, `:437`). See §3.8. They are told in the same send, at the same atomic
transition, now only on `_mark_lost`.

**5.4 Callers of `verify_live`.**
- `tools/spider.py:2524` (`_live_session_intact`): its API and its fail-closed action
  are unchanged. Its message for an inconclusive check reads as a loss (R10).
  `spider.py`'s text is AU-REDACT's and a hot file: **not edited**.
- `tools/probesender.py:580` (`_verify_main`): see §3.8.

**5.5 Every status decision about a session left in `session/`** (the SP-56 guard's
rows):
- `detect_logout`, `verify_live` and `_verify_authenticated` are **routed through SP-56
  and leave the list**: 8 rows become 5.
- `_login`, `_discover_login_form` and `detect_session_credential` stay. They decide
  login success and the Basic challenge.

**5.6 Browser login (FR-SESS-19).**
- `session/browserlogin.py` makes no status-based loss decision (grep:
  no 401, 403, `detect_logout` or `.valid`).
- `_spa_probe` gains the login-form agreement (§3.4).
- A browser-login session's health check is its existing protected probe, with the
  existing refusal digest.
- `tools/browserauth.py` adopts the session through `ensure` and `session_headers`, with
  no loss decision.

**5.7 The disco explorer's session check (audit defect 4: not taken on).**
- `disco/explore.py:1327` marks the session lost when the page URL is a login URL, and
  rebuilds the context from the storage state.
- It does not use `SessionManager`, `detect_logout` or SP-56. Nothing here changes it.
- **Overlap.** Defect 4 asks for "an identity-scoped auth-health state machine using a
  known protected probe, response classification, and session generations". That is
  `check_health`, `health_verdict`, the generations and the protected resource built
  here.
- Per PA-0507(2) and PA-0505(2), the defect-4 item should decide through this owner (an
  adapter over its storage-state context), not build a second one. That is recorded as
  the proposed SP row's consumer note (§10.5).

**5.8 Others.**
- `disco/runner.py`: not a consumer (§3.7).
- `greybox/greybox_cli.py:43` and `greybox/run.py`: `session_header` once; no observe.
  A lost greybox session is not detected today and still is not (R9).
- `session/cli.py:72` (`session print`): `ensure` only.
- `proxy` capture to `adopt`: the adopted session takes a generation; it has no
  protected resource, so its losses are unconfirmed (R2).
- `harness/auto.py` and `harness/pipeline.py`: no session-loss decision. The header
  breaker's report is unchanged.

**5.9 Existing tests that exercise the changed paths.** They are expected to stay green;
the Phase-2 harness run confirms it, and any expectation that changes is listed there
with before and after (PA-0073(3)):
- `tests/test_session_manager.py`: `observe` of a 200 login page; single-flight. The
  fixture has no protected resource, so its losses are unconfirmed and behave as today.
- `tests/test_logout_listener.py`: 200 login pages; same.
- `tests/test_forms_phase2.py` (the header breaker), on the UA-bound fixture: no
  resource, so as today.
- `tests/test_login_form_isolation.py`:
  - Its `FakeApp` base redirects an anonymous visitor to its static login page, so rule
    (2) records `/app/` and its losses (302 -> login) are **confirmed**: one more
    fetcher GET per loss.
  - Its `fetcher_gets` and `fetcher_hosts` assertions (`:1017`) are checked against
    that.
  - Its `observe(..., Response(401, …))` calls (`:536`, `:641`) now trigger a check.
- `tests/test_session_origin_scope.py:1184`: a Basic 401; rule (4) applies.
- `tests/test_session_persistence.py`, `tests/test_session_browser_login.py`,
  `tests/test_browserauth.py`, `tests/test_json_login.py`: unchanged paths, rerun by the
  harness (they import the changed modules).

## 6. Tests (PA-0034(2): each must fail on its named revert)

**Committed now** (strict xfail where marked; Phase 2 removes the markers):

| # | Test (`tests/test_session_forbidden_answers.py::…`) | Fails on 15a8a27 | Must fail against (revert) |
|---|---|---|---|
| T1 | `test_a_forbidden_answer_never_logs_the_session_in_again[admin-403, waf-403, csrf-403]` | yes: 10 logins | restoring `if status in (401, 403): return True` in `detect_logout` |
| T2 | `test_a_throttled_answer_never_logs_the_session_in_again` | no (pin) | adding the throttle class to the signals |
| T3 | `test_a_suspected_loss_on_a_live_session_is_confirmed_before_any_login[scope-401, privilege-login-redirect]` | yes: 10 logins | `observe` calling `_mark_lost` on a signal without `check_health`; or dropping rule (2) (no resource, so unconfirmed) |
| T4 | `test_a_credential_submissions_own_refusal_is_never_a_session_loss` | yes: 10 logins | `observe` passing `credential_submission=False` (no `login_facts`) |
| T5 | `test_a_real_expiry_is_still_seen_and_recovered_with_one_login` | no (pin) | a `detect_logout` that drops the login-redirect signal; or a `health_verdict` that reads the login page, or the redirect to it, as LIVE |
| T6 | `test_a_late_answer_from_an_earlier_session_never_logs_in_again` | yes: 3 logins | removing the generation comparison in `observe` |
| T7 | `test_the_single_flight_lock_stops_simultaneous_duplicate_logins` | no (pin) | removing `ensure`'s login lock |
| T8 | `test_concurrent_forbidden_rounds_cost_no_login_after_the_first` | yes: 4 logins | T1's revert |
| T9 | `test_an_http_form_login_records_a_stable_protected_resource` (asserts rule (2)'s base URL) | yes: None | removing rule (2) (rule (3) would record `/home.php` instead) |
| T10 | `test_detect_logout_reads_a_policy_block_never_as_a_loss[403]` (and `[451]`, a pin) | 403: yes | T1's revert |
| T11 | `test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle` | no (pin) | a `detect_logout` that drops the 401, the login redirect or the 200 form |

**Phase 2 (new API, written with the implementation):**

| # | Test | Must fail against (revert) |
|---|---|---|
| T5b | `test_an_expiry_that_redirects_to_another_origins_login_is_lost_and_never_fetched` (the login redirect on another origin is judged at its hop) | `_navigate` without `stop_at` (the hop is refused, so INCONCLUSIVE, never LOST) |
| T9b | `test_a_landing_page_behind_a_per_load_token_login_is_a_protected_resource` (public base, so rule (2) does not apply) | removing `_spa_probe`'s login-form agreement |
| T12 | `test_an_inconclusive_check_pauses_and_never_changes_the_identity`. The resource answers 503 at the signal: no invalidation, no login, no listener. The next send waits (the fake `sleep` records it), checks again, and goes out on the **same** SID. | INCONCLUSIVE treated as LOST (a login), or as LIVE (no wait recorded) |
| T13 | `test_a_pause_past_its_bound_fails_loudly_and_sends_nothing`. The resource always answers 503: after `max_pause_s` of fake time `prepare` raises `SessionHealthUnknown`, and the server's whole log has no probe after the first signal. | raising nothing (a send on an unknown identity), or re-logging in |
| T13b | `test_a_copys_unknown_health_falls_back_to_anonymous` | raising `SessionHealthUnknown` from a copy (the run would end) |
| T14 | `test_a_live_verdict_is_cached_for_its_window_and_its_generation`. Fake clock: N signals within the TTL make 1 resource GET (server count); after the TTL, 2; after a re-login the cache is not reused. | no cache (N GETs), or a cache keyed without the generation |
| T15 | `test_relogins_are_capped_per_window`. An app that ends the session on every probe: after K confirmed losses in W, `ensure` raises naming the cap; a JWT `exp` refresh does not count. | removing the cap (K+1 logins) |
| T16 | `test_without_a_protected_resource_a_suspected_loss_is_still_a_loss_and_a_403_never_is` | treating "no resource" as INCONCLUSIVE (a pause) or as LIVE (no recovery) |
| T17 | `test_listeners_hear_only_a_lost_session`: never on a 403, a stale answer, a cached-live suspicion or an inconclusive check; once on LOST | telling listeners on a signal before the check |
| T18 | `test_a_header_bound_session_with_a_protected_resource_still_trips_the_breaker`, the UA-bound fixture plus a protected landing | `check_health` carrying the probe's headers, or not calling `_mark_lost` |
| T19 | `test_only_the_owner_decides_a_session_loss` (AST): `detect_logout` is called only in `SessionManager.observe`; `.valid = False` is written only in `SessionManager._mark_lost`. Proven on synthetic offenders: a module that calls `detect_logout` and invalidates, and a manager method that writes `valid = False`. | each synthetic offender (PA-0034(2)) |
| T20 | `tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner`, with three rows removed | restoring a status literal in `detect_logout`, `verify_live` or `_verify_authenticated` |
| T21 | `test_verify_live_reads_a_policy_block_as_unknown_never_as_a_loss`: False, the state stays valid, and no login on the next send | `verify_live` invalidating on INCONCLUSIVE |
| T22 | `test_prepare_records_the_generation_it_applied` | `prepare` not setting it (T6 would then pass vacuously on None) |
| T23 | `test_request_entry_names_reads_query_form_and_json_leaves_and_is_total` | returning `()` (a credential field name missed) |
| T24 | `test_the_pause_and_the_health_lock_never_nest_with_the_login_lock`: concurrent signals and a re-login under a fake transport with events, with a 10 s join bound | taking the login lock inside the health lock |

If §3.13 is approved, two more tests come with it:
- `test_a_probe_whose_session_was_lost_is_not_comparable`
- `test_a_comparison_that_straddles_a_relogin_is_not_comparable`

Both live in `tests/test_oracle_comparable_controls.py`.

## 7. Requirement text

**New: FR-SESS-23 (a forbidden answer is never, by itself, a lost session; CC-SESS-0029,
BUG-0533).**

- **Classification first (SP-56).** `observe` classifies each answer to a request this
  manager prepared with `core.comparability.response_class`. It uses SP-16's facts
  (`detect.login_facts`, with the request's own entry names from
  `detect.request_entry_names`) and whether the request carried the session.
  - A policy block (403, 451), a throttle or unavailable server (429, 503), a gateway
    (502, 504), an intermediary's 407 and an incomplete answer never change the session.
    Each is counted.
- **Suspected loss.** `detect.detect_logout` names one in two cases:
  - an auth failure that SP-56 gives only because the request carried the session (a
    401; a redirect to this session's login page or an anchored login URL, FR-SESS-18);
  - this session's login form shown at 200 (FR-SESS-15's form rules).

  In both cases the request must not submit a credential (PA-0529(3)).
- **Generations.** Each login, and an adopted session, gets a new
  `SessionState.generation`. `prepare` records it on the request
  (`core.http.Request.session_generation`).
  - A suspected loss from a request prepared on another generation is ignored and
    counted as stale.
  - A request that does not say is read as the current generation.
- **Confirmation.** A suspected loss is confirmed on the session's stable protected
  resource before anything changes (`SessionManager.check_health`).
  - The check is one GET carrying the session. Its redirects are walked by hand inside
    the session's origins, and it stops at a login redirect.
  - **Lost:** a 401, a login redirect, this session's login form, or the recorded
    refusal body.
  - **Live:** any other 2xx.
  - **Inconclusive:** anything else, including no response and an unapproved hop.
  - The check is single-flight per (host, identity). A live verdict is cached for
    `health_ttl_s` (default 30 s), for the generation it judged only.
- **The stable protected resource** (`SessionState.protected_probe`) is recorded at
  login, by the first rule that holds:
  1. a browser login's differential (FR-SESS-19);
  2. an HTTP login's base URL, when discovery reached this login form by following the
     base URL's own redirect and the post-login check of the base URL was live (no
     extra request);
  3. the post-login landing URL, when `_spa_probe`'s differential holds there. Two
     refused arms that both show this session's login form agree, so a per-load token
     does not break it.
  4. a Basic session's base URL (401 without the header, 2xx with it).

  With none, a suspected loss is taken as a loss, unconfirmed, and counted.
- **Lost.** The state is marked invalid in one place (`_mark_lost`: the atomic
  check-and-set) and persisted, and the logout listeners are told (FR-SESS-16). The next
  `prepare` logs in again, on a new generation.
- **Re-login cap.** At most `max_relogins` (default 5) loss-driven re-logins per
  `relogin_window_s` (default 600 s) per (host, identity). The next one raises
  `SessionAuthError`, naming the count, the window and the last loss's class.
  - The first login and a JWT `exp` refresh do not count.
  - An isolated copy keeps `max_logins`.
- **Pause.** An inconclusive check changes nothing: no invalidation, no login, no
  listener.
  - The identity is paused for a backoff of 5 s, doubling to 60 s. A `Retry-After` up to
    60 s is honoured.
  - `prepare` for it waits the pause out, then checks again: live sends, lost re-logs in
    under the cap, and inconclusive pauses again.
  - After `max_pause_s` (default 300 s), `prepare` raises `SessionHealthUnknown` (an
    isolated copy raises `IsolatedLoginFailed`). No request goes out on an identity
    whose state is unknown.
- **`verify_live`** is `check_health`: True when live. When lost it returns False and
  marks the state invalid. When inconclusive it returns False and changes nothing.
- **Reported.** `SessionManager.health_report()` gives counts per class and outcome. It
  holds no URL, header value or body.
- **Residuals.** R1-R13 of DRAFT-AU-SESS403 §8, carried into this requirement when it
  lands.
- **Enforced by:** T1, T3, T4, T6, T12, T13, T15, T16, T17, T19, T20 (names in §6).

**Amended in place:**
- **FR-SESS-5.** "Detect logout/expiry from multiple signals (401/403, …)" becomes:
  "Detect a suspected logout or expiry from multiple signals (a credentialed 401, a
  redirect to the detected login page, the login form reappearing, JWT `exp`), confirm
  it on the session's stable protected resource (FR-SESS-23), and re-authenticate under
  a single-flight lock. Cap re-logins per window, then hard-fail. A 403 is a policy
  answer, never a logout signal."
- **FR-SESS-15 (Basic).** "A Basic session has `login_url=None`, so its logout signal is
  401/403" becomes "…its logout signal is a credentialed 401, confirmed on its base URL
  (FR-SESS-23)".
- **FR-SESS-16.** `observe` calls the listener once per valid -> invalid transition, in
  `_mark_lost`. That means a confirmed loss, or an unconfirmed one when no protected
  resource is known. It is never called for a policy block, a stale answer, a
  cached-live suspicion or an inconclusive check.
- **FR-SESS-17 (`verify_live`).** "fails on 401/403 or on this session's login form"
  becomes "is `check_health` (FR-SESS-23): lost marks it invalid; inconclusive changes
  nothing".
- **FR-SESS-18 (residuals).** "privilege-gated redirects to the real login page still
  read as a logout" becomes: "…are suspected losses; with a stable protected resource
  they are confirmed live and change nothing; without one they are unconfirmed losses
  (FR-SESS-23)".
- **NFR-SESS-single-flight.** "Concurrent expiry triggers exactly one re-auth" gains:
  "and one health check per (host, identity). A late answer from an earlier session
  generation triggers neither."

## 8. Residual limits (stated)

- **R1. A session that ends with a 403.** An app that answers 403 for a lost session is
  not recovered from that answer. DRF's `SessionAuthentication` is documented to do
  this; it is **not measured** here.
  - What was measured: FastAPI 0.143.3 answers 401, and this repo's labs answer 403 only
    for authorization denials.
  - Such an app's probes classify as `policy-block`. The oracle reads them as not
    comparable, so they are inconclusive, never negative.
  - The loss is still seen by any 401, login redirect or login page, and by a JWT `exp`.
  - A 403 that triggers the cached health check is question Q3, pending a measured
    fixture.
- **R2. No stable protected resource.** This covers a public base with no protected
  landing, an adopted captured session, and a resource that rule (3)'s differential
  cannot prove.
  - A credentialed 401, a login redirect or a login page is then still a loss,
    unconfirmed. FR-SESS-18's privilege-gated-redirect residual remains for such apps,
    bounded by the re-login cap and failing loudly after it.
  - A 403 never is a loss.
- **R3. A live verdict is trusted for `health_ttl_s`.** A session that dies inside the
  window is found only after it. Its probes in between are credentialed auth failures,
  which the oracle reads as not comparable (SP-56), never negative.
- **R4. The resource can move or break.** A 404 or 5xx there is inconclusive. That
  pauses, and fails loudly after `max_pause_s`.
- **R5. The health GET is a request of the run** that is neither budgeted nor traced.
  The login handshake's requests are not either, today (PA-0520's every-send count runs
  without a session manager). It is counted in `health_report()`.
- **R6. A comparison that straddles a re-login is not detected by the oracle** without
  §3.13 (F3).
- **R7. A probe whose own answer was a confirmed loss at 200 still reads as `application`
  to the oracle** without §3.13 (F1, F2). This is BUG-0529's R3 and R10.
- **R8. `_verify_authenticated` keeps today's acceptance.** A policy block on the
  post-login check fails the login; a throttle or 5xx there accepts it.
- **R9. Consumers outside this mechanism.**
  - The contract runner's static auth profiles have no recovery: a lost session shows as
    `error`.
  - The disco explorer's own check is defect 4's.
  - Greybox's header is never re-checked.
- **R10. The crawler's message.** An inconclusive `verify_live` reads as "the server no
  longer accepts the session" (same fail-closed action). The `spider.py` text is
  AU-REDACT's.
- **R11. Multipart bodies' field names are not read** by `request_entry_names`. A
  multipart credential change's 401 is then a suspected loss: confirmed live when a
  resource is known, unconfirmed otherwise.
- **R12. The pause waits in the sending thread.** Parallel senders of one identity each
  wait, to the same deadline.
- **R13. An isolated copy's health check costs its own GETs,** bounded by `max_logins`
  (3) times rule (3)'s 3-6 GETs at login.

## 9. Change-control drafts

### CC-SESS-0029 — A forbidden answer is never, by itself, a lost session (FR-SESS-23, BUG-0533) (2026-10-20)
- **Change:**
  - `session/detect.py`:
    - `detect_logout` decides through SP-56, `response_class`, with keyword facts
      `credentialed` and `credential_submission`. A 403 or 451 is never a signal, nor
      is a 407. The content rules are unchanged.
    - New `request_entry_names`.
  - `session/manager.py`:
    - `check_health` and `health_verdict`, the one owner of "is this identity's
      session live".
    - `SessionState.generation`, recorded by `prepare` on the request.
    - `observe` ignores stale signals, uses a generation-bound live cache, confirms on
      the stable protected resource, and invalidates only in `_mark_lost`.
    - Protected-resource rules (2)-(4), and `_spa_probe`'s login-form agreement.
    - The re-login cap per window; the pause with backoff, `Retry-After` and
      `max_pause_s`; `SessionHealthUnknown`.
    - `verify_live` and `_verify_authenticated` route through `health_verdict`.
    - `health_report`; the `_navigate(stop_at=)` hop rule.
    - New kwargs, copied to isolated copies.
  - `session/state.py`: `generation`, and the live-cache and pause fields.
  - About +320/-35 LOC; tests about +450.
- **Impact (other components / project):**
  - **CORE:** `Request.session_generation` (CC-CORE-0070), and SP-56's guard list shrinks
    by three rows.
  - **FUZZ:** every `SeamProbeSender`, the run's and the peer's, stops re-logging in on
    forbidden answers. Breakers are told only on a lost session.
    `SessionHealthUnknown` ends a run as the `max_reauth` cap does. No FUZZ code changes
    (§3.13 is asked separately).
  - **AUD:** `tools/fetcher.py`'s seam gets the same behaviour.
  - **CRAWL:** `verify_live` keeps its API. An inconclusive check is `False` without
    invalidating, and a 429, 503 or 5xx is no longer "live".
  - **SP-16:** gains `request_entry_names`; `detect_logout` becomes an SP-56 consumer.
  - **A proposed new shared-primitive row** (§10.5).
  - The consumers were found by grep (§5; PA-0152).
- **Risk (medium):**
  - A missed real loss: mitigated by the T5 pin and by unconfirmed losses when no
    resource is known.
  - A run that now fails loudly at the re-login cap or after a pause: stated, and
    bounded by its defaults.
  - Lock-order mistakes: mitigated by the fixed order (§3.11) and T24.
  - Extra GETs at login (0 with rule (2); 3-6 with rule (3)): accepted against 6
    requests per avoided re-login (§1.2).
- **Deliverables:**
  - [ ] detect.py changes — todo
  - [ ] manager.py changes — todo
  - [ ] state.py — todo
  - [ ] T1-T24 (markers removed) — todo
  - [ ] FR-SESS-23 and the in-place amendments — todo
  - [ ] the PA-0002 sweep recorded in BUG-0533 — todo
- **Effectiveness:** pending.

### CC-CORE-0070 — The request records the session generation it was prepared with; SP-56's guard list loses three session rows (FR-SESS-23, BUG-0533) (2026-10-20)
- **Change:**
  - `core/http.py::Request` gains `session_generation: int | None = None`, set by the
    session addon's `prepare` (+4 LOC).
  - `tests/test_core_comparability.py::ALLOWED` drops the rows for
    `SessionManager.verify_live`, `SessionManager._verify_authenticated` and
    `detect.detect_logout`. Those sites now decide through SP-56.
- **Impact:** SESS (the only writer and reader). `HttpClient.send` is unchanged. The
  sender reads it only if §3.13 is approved.
- **Risk (low):** an optional field with a None default; existing `Request(...)` calls
  are unaffected.
- **Deliverables:**
  - [ ] field — todo
  - [ ] the three rows removed and T20 green — todo
- **Effectiveness:** pending.

## 10. Bookkeeping text (for the coordinator; this lane edits none of those files)

### 10.1 BUG-0533 (the record lands with the fix: `docs/bugs/BUG-0533-a-forbidden-answer-logged-the-session-in-again.md`)

- **Description:** a 403 (or any 401, a privilege-gated login redirect, or a credential
  submission's own 401) made the session manager invalidate the session. The next
  request logged in again.
- **Where encountered:** the owner's audit, defect 6 (6552276). It is measured at
  15a8a27 by `tests/test_session_forbidden_answers.py` (§1).
- **What it caused to fail:**
  - N forbidden probes made N logins, at 6 requests each, with no cap.
  - Every probe ran on a new server-side session.
  - The cross-account peer re-logged in on each denied replay. That includes the lab's
    own secure access-control twins (§1.5).
  - A late answer from an earlier session caused one more login (§1.3).
- **What the bug was:**
  - `detect_logout` returned True for every 401 and 403.
  - `observe` invalidated on it with no confirmation, no generation and no
    credential-submission fact.
  - Nothing capped successful re-logins.
- **Root cause (Five Whys):**
  1. Why a login per 403? `observe` invalidated on `detect_logout`.
  2. Why did `detect_logout` say "loss"? It listed 403 as a logout status (FR-SESS-5
     said so).
  3. Why was a status taken as proof? The decision had no evidence standard. One answer's
     surface feature (a status, earlier a substring or any password field) decided the
     session's state. It was never confirmed on a resource whose answer depends on the
     session, nor tied to the session the request carried.
  4. Why did SP-56 and PA-0529(3) not prevent it? Both were applied at the oracle. The
     session manager is the one actor that changes identity state, and it was deferred
     to this item (CC-SESS-0028: "`detect_logout` … untouched"; SP-56's guard
     allow-listed it).
  5. Why did it persist? FR-SESS-5 set the bar for login (a positive differential,
     PA-0007) and never for logout.

  **Root cause:** a session-state change was decided from one answer's surface feature,
  without positive evidence about that session and without binding the evidence to the
  session it was about.
- **Corrective action:** CC-SESS-0029, CC-CORE-0070.
- **Recurrence review:**
  - **BUG-0008 / PA-0007:** login success from an ambient cookie. The same root cause
    on the login side; PA-0007 demands a positive differential for login only.
  - **BUG-0113 (its FR-SESS-15 rule):** any password field read as a logout.
  - **BUG-0122 / PA-0122:** any "login" substring redirect read as a logout.
  - **BUG-0529 / PA-0529(3):** a credential submission's refusal read as a lost session.
    Fixed at the oracle; the session manager was deferred to this item (R3, R10).
  - **Result:** a recurrence of the same root cause (the fourth on logout detection).
- **Prior-preventive-action failure analysis:**
  - **PA-0122 is too narrow / the wrong layer.** It fixed one signal's grammar (URL
    anchoring), not the decision's evidence standard.
  - **The BUG-0113 rule is too narrow.** It narrowed the content signal only.
  - **PA-0529(3) was not applied at the actor.** It stated the rule for every reader,
    but enforced it only in SP-56's consumers. Its own guard (PA-0529(4)) carried
    `detect_logout` on the allowance list, so the place that acts on a "session loss"
    was knowingly outside it.
  - **PA-0007 is too narrow.** Positive evidence for login, never for logout.
  - **The common failure:** each rule constrained a signal or a reader, never the state
    change itself.
- **Preventive action:** PA-0533 (§10.2), which strengthens PA-0007, PA-0122 and
  PA-0529(3).
- **The PA-0002 sweep:** §5 of this draft, recorded per site with its disposition.

### 10.2 PA-0533 (text for `docs/PREVENTIVE_ACTIONS.md`)

**PA-0533** strengthens `PA-0007`, `PA-0122` and `PA-0529(3)`, after BUG-0533: a 403
logged the session in again. Each earlier rule constrained one signal or one reader;
none constrained the state change.

1. **An identity's state changes only on evidence about that session.**
   - The answer is classified by SP-56 first. A policy block, throttle, gateway, 407 or
     incomplete answer never changes it.
   - A suspected loss is confirmed on the session's stable protected resource before the
     session is invalidated. "Suspected" means a credentialed 401, a login redirect, or
     this session's login form, to a request that is not a credential submission.
   - Without such a resource, the loss is unconfirmed: counted, and capped.
2. **Evidence is bound to the session it is about.** A signal from a request prepared on
   another session generation is ignored. A live verdict is cached only for its
   generation.
3. **Re-logins are capped per window. An inconclusive check pauses the identity; it
   never logs in or out.**
4. **Enforced at the actor.** One function writes the invalidation (`_mark_lost`), and
   only `observe` calls `detect_logout`: an AST guard, proven on synthetic offenders.
   The loss decisions leave SP-56's status allowance list.

- Enforced by: tests/test_session_forbidden_answers.py::test_a_forbidden_answer_never_logs_the_session_in_again, tests/test_session_forbidden_answers.py::test_a_suspected_loss_on_a_live_session_is_confirmed_before_any_login, tests/test_session_forbidden_answers.py::test_a_credential_submissions_own_refusal_is_never_a_session_loss, tests/test_session_forbidden_answers.py::test_a_late_answer_from_an_earlier_session_never_logs_in_again, tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner

### 10.3 ERROR_LOG line

`2026-10-20 — BUG-0533`:
- **Symptom:** every 403 (and a scope 401, a privilege login redirect, a password
  check's 401) logged the session in again: N probes, N logins.
- **Root cause:** `detect_logout` read 401/403 as a loss, and `observe` invalidated it
  without confirmation or a session generation.
- **Remediation:** CC-SESS-0029 and CC-CORE-0070 (SP-56 first, a health check on a
  stable protected resource, generations, a re-login cap, a pause).
- **Status:** fixed.

### 10.4 CHANGELOG line

`2026-10-20`: forbidden answers no longer log the session in again. A suspected loss is
confirmed on the session's stable protected resource, bound to its session generation,
with re-logins capped and an inconclusive check pausing (AU-SESS403, audit defect 6;
CC-SESS-0029, CC-CORE-0070, BUG-0533).

### 10.5 SHARED_PRIMITIVES

- **SP-16's row:** add `detect_logout`, a suspected loss decided through SP-56, and
  `request_entry_names`.
- **SP-56's row:** add the session manager to its readers.
- **New row (number for the coordinator):** "Is an identity's session live now: the
  health check on its stable protected resource, its verdict, the session generation,
  the live cache and the pause".
  - Owner: `fuzzlab/session/manager.py::SessionManager.check_health`, with
    `health_verdict`, `_mark_lost` and `_spa_probe`.
  - Guards: T19 and `tests/test_shared_primitives.py::test_every_owner_is_defined_once`.
  - Consumer note: audit defect 4's disco item decides through it.

### 10.6 ARCHITECTURE

The session manager's paragraph gains one sentence: a loss is confirmed on a stable
protected resource and bound to a session generation; 403 is policy. There is no new
component and no new dependency.

## 11. Open questions

- **Q1. The oracle part (§3.13).** Is a FUZZ change for F1-F3 approved? If so, under which
  CC-FUZZ number? Without it, R6 and R7 stand.
- **Q2. Run metrics.** Should `health_report()` appear in `auto`'s run metrics? That
  would be a small FUZZ change in `harness/auto.py`. Without it, the counts are reachable
  only from the manager.
- **Q3. A 403 to a credentialed request.** Should it trigger the cached health check
  when a resource is known (R1)?
  - It would recover apps whose session loss shows as 403, at no more than one GET per
    TTL.
  - The orchestrator's brief says a 403 is "never a session loss on its own". The check
    would not make it one: only the resource's answer would.
  - It relies on behaviour not measured here. It needs a measured fixture first: DRF is
    not installed, and the one measured framework, FastAPI 0.143.3, answers 401.
- **Q4. The defaults:** `health_ttl_s` 30, `max_relogins` 5 per 600 s, and
  `max_pause_s` 300 with a 5-60 s backoff.
  - Should the re-login cap **fail loudly** (as drafted, like `max_reauth`) or
    **pause**?
  - Failing loudly can end a run that today finishes while churning. That is mostly
    R2's apps.
- **Q5. Rule (2)'s scope.** It trusts discovery's anonymous redirect to the login page
  as the refused arm, with no corrupted arm. For a bearer session, should rule (2)
  require the corrupted arm too (one extra GET)?

## 12. Phase-1 verification

Each run started only after no other pytest or `verify_change` was live on the host.
- My waiter (`scratchpad/au-sess403/wait_then_test.sh`) has no timeout of its own.
- `verify_change.py` takes the host lock and refuses rather than falling through.

**The new file alone** (2026-10-20 06:49Z, the `FUZZLAB_REQUIRE_*` flags set):
- `tests/test_session_forbidden_answers.py`: **5 passed, 10 xfailed** in 7.9 s.
- Each of the 10 was then called directly, without pytest
  (`scratchpad/au-sess403/why_xfail.py`). Each fails on an `AssertionError` that carries
  the measured counts, never another exception:
  - the three 403 scenarios, the scope 401, the privilege redirect and the password 401:
    `logins 10, invalidations 10, sessions 10`;
  - the late answer: `logins 3, invalidations 2`;
  - the concurrent rounds: `logins 4`;
  - the protected resource: `recorded None`;
  - `detect_logout(403)`: True.

**The harness:** `scripts/verify_change.py --base 15a8a27` on the committed tree
`f92d8ed`, in a detached worktree.
- It selected **66 files** (every package guard plus the changed test file), all in the
  parallel pass.
- **2811 passed, 0 failed, 0 errors, 1 skipped, 28 xfailed** in 383 s.
- The skip is `tests/test_packaging.py:179`: bdist_wheel is unavailable here (a Debian
  setuptools bug, pre-existing).
- This file's share of the run, from the junit XML: 5 passed, 10 xfailed.
- Summary: `scratchpad/au-sess403/vc/summary.json`.

Nothing is implemented, so this run proves only one thing: the committed tests and draft
break no guard. Every listener, wall-clock, arrival-order, lint and PA guard passes over
the new test module.
