# DRAFT AU-SESS403: a forbidden answer is never, by itself, a lost session

- **Item:** `AU-SESS403`, audit defect 6 ("Every forbidden response can trigger
  another login").
- **Base:** `15a8a27`, with the branch tip `7ebf48a` (the host pytest lock, BUG-0532)
  merged in.
- **Status:** revision 2, Phase 1: measured and drafted, **not implemented**.
  - Revision 1 went to the review gate. Both reviewers disagreed with it and endorsed
    the direction: SP-56 first, then a health check on a protected resource, then
    generation binding.
  - This revision answers their merged list (M1-M10) and the adopted items.
  - At most two review rounds remain.

**Numbers (pre-assigned, unchanged):**

| Number | Covers |
|---|---|
| CC-SESS-0029 | `session/detect.py`, `session/manager.py`, `session/state.py` |
| FR-SESS-23 | the new requirement (§7). FR-SESS-5, -15, -16, -17 and -18 and NFR-SESS-single-flight are amended in place. |
| BUG-0533 / PA-0533 | the bug record and the preventive action (§10) |
| CC-CORE-0070 | `core/http.Request.session_generation` (one field), and three rows removed from SP-56's guard allowance list (`tests/test_core_comparability.py`) |

## 0. What changed in revision 2

| Review item | Change | Where |
|---|---|---|
| **M1** tests pin each layer | Each test asserts the layer it guards: the server's count of health GETs, logins and invalidations. The tests run on eight app shapes (§1.1). | §6 |
| M1 (continued) | T4 and T6 also run on an app with no resource. T3's contradicting second revert is gone. T24 has a revert that really cycles. | §6 |
| M1 (continued) | Four true-positive pins: a 401 on `/api`, a 200 in-place login form, Basic, and 403-on-expiry. Plus two more for M4: a presence page and a static redirect base. | §6 |
| M1 (continued) | Every test is proven against its named revert on a run-time prototype of this design (§1.9). PA-0533 names T13 and T15. | §6, §10.2 |
| **M2** a 403 with a resource | A credentialed policy block triggers the cached health check when a resource is known; with none, it triggers nothing. T1 asserts at most one check per window and no login. | §3.2, T1, TP4 |
| **M3** credential submissions | A submission's loss shape is checked when a resource is known. It never counts as an unconfirmed loss. The DVWA `password_new` point still recovers a real expiry. | §3.2, T4, T4b |
| **M4(a)** the credentialed arm | Judged by `health_verdict` on the walk that stops at a login redirect, never by `_verify_authenticated`'s acceptance. | §3.5, T9, TP6 |
| **M4(b)** one rule for every kind | Rule 2 is `_spa_probe` on the base for every session kind, with the corrupted arm. The static-redirect base and a page that answers any cookie are tested, and the JSON/bearer case is measured. | §3.5, §1.6 |
| **M5** refusal status | Recorded with the resource. A matching answer reads as LOST. | §3.4, T9, TP4 |
| **M6** the cache and the breakers | `verify_live` never reads the cache. The cache key is (generation, the signal's URL key). A foreign header bypasses the cache. A pause re-check notifies no listener. T18 starts warm. | §3.6, §3.7, T14, T17, T18, T21b |
| **M7** generation at the write | `check_health` judges a given generation and returns it. `_mark_lost` and the pause compare-and-set on it. The verdict is recorded under the lock, so N concurrent signals make one GET. `_mark_lost` has a stated `notify` flag. | §3.4, §3.7, M7 tests |
| **M8** sticky unknown | Sticky, with a per-run pause budget. The sweep covers `audit_page`'s catch-all and the PRG restore boundary. T13 asserts that the second send raises with the clock unchanged. | §3.8, §5.4, T13, T13b |
| **M9** `verify_live` | On an inconclusive check it waits out the bounded pause and checks again. If that is still inconclusive it keeps today's answer (live) and logs once. Never False on an inconclusive check, and no FUZZ change. | §3.10, T21 |
| **M10** re-login budget | A token bucket: a burst of 5, refilled at 1 per 120 s. An empty bucket waits inside the pause bound, then goes sticky. Credential POSTs are counted per account, the JSON control included. The lab-resource measurement is in §1.7. | §3.9, §1.7, T15 |
| ADOPT: one loss predicate | `detect_logout` is the one predicate; `health_verdict` calls it, and T19 holds that. | §3.1, T19 |
| ADOPT: T19 whole-package | Proven on `state.valid = ok`, `setattr`, `dataclasses.replace(valid=…)` and `.valid = False` offenders. | T19 |
| ADOPT: fail fast | An unapproved hop fails fast and never pauses; FR-SESS-23 and §3.4 agree. | §3.4, test THOP |
| ADOPT: Basic exception | Kept in `health_verdict` and in the signal. | §3.1, TP3 |
| ADOPT: `Set-Cookie` and headers | The health GET adopts a rotated id on a live answer, measured. It is sent with the seam's headers, and a pause start is logged once. | §3.4, §1.5, TROT |
| ADOPT: sweep additions | `mutation/cli.py:75`, `tools/blind_sqli_fuzzer.py:341,374`, and a copy's "health unknown" (it counts toward the failed-logins breaker: kept, stated). | §5 |
| ADOPT: PA-0113 | Named in the recurrence review. | §10.1 |
| ADOPT: F3 (straddle) | A stated residual, pinned by a strict xfail. It needs a CC-FUZZ number, which this item does not have. | §3.13, R6 |
| ADOPT: disco | Recorded as a known gap. `health_verdict` is public, and `adopt` takes a resource. | §5.7 |

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### 1.1 The probes

**`tests/test_session_forbidden_answers.py`** (58 tests)
- Real loopback apps, each a `ThreadingHTTPServer` on `127.0.0.1:0` through
  `require_loopback`, in eight shapes (`_App(mode=…)`):
  - `redirect`: PHP-like. An anonymous cookie before the login, a per-load login token,
    `/` → `/home.php` or `/login.php`.
  - `none`: no protected resource can be proved.
  - `static`: `/` → `/login` always; a logged-in `/login` → `/dashboard`.
  - `presence`: `/` answers any SID with 200.
  - `forbid`: a lost session gets 403 everywhere.
  - `basic`: HTTP Basic.
  - `json`: a JSON/bearer login from the page's script (FR-SESS-21).
  - `rotate` / `rotate_all`: a rotating session id.
- Sends go through the real `SessionManager` with its default requests fetcher
  (`browser_login=False`), the real `HttpClient` and `SeamProbeSender`.
- Credentials are in memory: `FakeBackend` (D12).
- The manager's time is a fake clock (`clock`, `sleep`), passed only when the
  `SessionManager` accepts it, so the same tests run on the base.

**Counts are taken by the server or by a listener:**
- **Logins:** successful logins, counted by the app.
- **Invalidations:** the FR-SESS-16 listener.
- **Checks:** the app counts GETs of its resource that carry the session and lack the
  login fetcher's browser headers. That is the health GET's wire signature: it is sent
  with the seam's headers, while the login fetcher sends browser headers.
- **Sessions:** the SID each probe carried, from the server's whole log (PA-0511).

**The prototype** (`docs/components/03-session-manager/au-sess403-prototype/`)
- `proto.py` patches this design onto `SessionManager` and `session.detect` at run time.
  It is never collected and is not part of `fuzzlab/`; Phase 2 deletes it.
- `REVERT=<name>` undoes one decision (43 names).
  - 39 undo a decision of the design.
  - 4 (`guard_*`) weaken T19's own guard.
  - Every collected test is named by at least one revert, except T19's whole-package
    assertion and F3's pin (§6).
- `run_reverts.sh` runs every revert against its named tests, then the design.
- This is reviewer B's masking technique, applied to every test.

**Other probes**
- `python3 -m tests.test_session_forbidden_answers` prints the tables below for
  whatever code is loaded. `scratchpad/au-sess403/smoke_proto.py` runs it with the
  prototype.
- `scratchpad/au-sess403/fastapi_missing_auth.py`: an offline FastAPI check.

### 1.2 The base, per scenario (10 probes by the low-privilege identity)

`measure_r2_base.out`:

| Scenario | `redirect`: logins / invalidations / sessions / checks | `none`: logins / invalidations / sessions / checks |
|---|---|---|
| admin 403, WAF 403, CSRF 403 (each) | **10 / 10 / 10** / 0 | **10 / 10 / 10** / 0 |
| 429 | 1 / 0 / 1 / 0 | 1 / 0 / 1 / 0 |
| scope 401; privilege-gated login redirect | **10 / 10 / 10** / 0 | **10 / 10 / 10** / 0 |
| password 401; a 401 to a body naming `current_password` | **10 / 10 / 10** / 0 | **10 / 10 / 10** / 0 |
| admin 403 at n = 1 / 5 / 20 | **1 / 5 / 20** logins | |

- **Concurrency.** Six concurrent first sends make 1 login: the single-flight lock
  works. Four rounds of six concurrent 403s make **4** logins: sequential churn.
- **A late answer from an earlier session** makes **3** logins (2 needed) and **2**
  invalidations.
- **Real expiries** (on `/home.php`, `/api/me` 401, `/profile.php` 200 in-place form,
  forbid 403, presence, static) are each recovered with 2 logins and 1 invalidation.
- **Cost:** 6 requests per login on this app (revision 1's
  `scratchpad/au-sess403/cost.py`).

### 1.3 With the prototype (this design)

| Scenario | `redirect`: logins / invalidations / sessions / checks | `none`: logins / invalidations / sessions / checks |
|---|---|---|
| admin 403, WAF 403, CSRF 403 | 1 / 0 / 1 / **1** | 1 / 0 / 1 / **0** |
| 429 | 1 / 0 / 1 / 0 | 1 / 0 / 1 / 0 |
| scope 401; privilege login redirect | 1 / 0 / 1 / **1** | **10 / 10 / 10** / 0 (unconfirmed: no resource, R2) |
| password 401; name-only 401 | 1 / 0 / 1 / **1** | 1 / 0 / 1 / 0 |
| admin 403, n = 1 / 5 / 20 | 1 login, 1 check each | |

- **Concurrency.** Four rounds of six concurrent 403s make 1 login (and 1 check with a
  resource).
- **A late answer** makes 2 logins and 1 invalidation (and 1 check with a resource:
  the real loss).
- **Every real expiry** is recovered with 2 logins and 1 invalidation.

### 1.4 The resource each login records

| Mode | Base | Design (prototype) | Why |
|---|---|---|---|
| `redirect` | None | `/` | anonymous and corrupted both stop at the redirect to `/login.php` |
| `static` | None | `/dashboard` | `/`'s credentialed walk stops at `/login` (M4(a)) |
| `presence` | None | `/home.php` | `/` answers the corrupted SID with 200 (M4(b)) |
| `forbid` | None | `/`, refusal status **403** | anonymous and corrupted both 403 (M5) |
| `basic` | None | `/` | anonymous and corrupted both 401 |
| `none` | None | None | `/` is public; the login has no landing |
| `json` | None | **None** | `/` is the login page (an auth endpoint) and a JSON login has no landing |

### 1.5 A rotating session id (ADOPT; measured)

- **`rotate_all`** (every authenticated request rotates the SID): 10 probes make **10
  logins** on the base and with the prototype (`statuses` all 302).
  - The seam adopts no response cookie (`probesender.py:85-89`, a recorded
    divergence).
  - The login's own verification (`_verify_authenticated`) already rotates the id
    away from the state's copy.
  - So such an app churns whatever the health check does. That is pre-existing, R14.
- **`rotate`** (only a live health GET rotates):
  - With adoption: the next send uses the new id, with 1 login and 1 check.
  - Without (`REVERT=noadopt`): the health check kills its own session and a second
    login follows.

### 1.6 JSON/bearer (M4(b))

- A JSON login (FR-SESS-21) records no resource. Its base is the page holding the login
  form, which `_json_login` records as an auth endpoint (`manager.py:908`), and the
  JSON login has no redirect landing.
- So on JSON/bearer apps, a credentialed 401 is an **unconfirmed** loss: a re-login,
  limited by the token bucket. A 403 does nothing.
- Juice Shop's browser login is the exception: rule 1's probe (FR-SESS-19).

### 1.7 Which labs' logins get a resource (M10; repo sources only, nothing booted)

| Lab | Identity in the repo | What the sources say | Expected rule |
|---|---|---|---|
| bWAPP | `bwapp-bee`, base = the origin (`docs/ON_HOST_RUNBOOK.md:140,161`; BUG-0300) | `/` → 302 `/bWAPP/portal.php` (`lab/external/bwapp/apache-root.conf:6`); `portal.php` → 302 `login.php` anonymously, 200 logged in (`apache-root.conf:1-4`, `lab_fixtures/external.py:1106-1119`, `01-target-lab/requirements.md:6338`); login → 302 `portal.php` (`external.py:1119`) | **rule 2 on `/`**: anonymous and corrupted `PHPSESSID` both stop at the redirect to `login.php` |
| Juice Shop | `juice-user` (`ON_HOST_RUNBOOK.md:151,166`) | SPA; browser login (FR-SESS-19) | **rule 1** (the existing post-click differential; an offline fixture, `tests/_spa_login_fixture.py`; Juice Shop itself never exercised, FR-SESS-19's residual) |
| secdevlabs-gossip-world | `sdl-gossip-user`, `sdl-gossip-peer` (`01-target-lab/requirements.md:6410,6426`) | login → 302 `/gossip`; `/gossip` → 302 `/login` without a session (`tests/test_external_labs_static.py:1343-1371`, modelled on the live bring-up, CC-LAB-0305) | **rule 3** (landing `/gossip`) |
| secdevlabs-ecommerce-api | `sdl-ecommerce-user`, `-peer` (`requirements.md:6382-6383`) | JSON login from the page's script, cookie `sessionIDa5` (CC-SESS-0026) | **none** (like `json`): 401s are unconfirmed losses, 403s nothing |
| PFF (the php_laravel lab, `lab/ground-truth`) | — | login → `redirect('/profile.php')` (`php_laravel/templates/complexities/single_statement.php.j2:41`, `__init__.py:975`). `/` is a public home (`stack/skeleton/routes/site.php:11`). `/profile.php` renders by `?user=`, not by session (`__init__.py:1016-1029`). The layout never changes with login state (`layouts/site.blade.php`). Only the id-lookup sink answers 401 without a session (`sinks/db_row_by_id_lookup.php.j2:8-11`). | **none expected**: no candidate tells a session apart |
| Generated stacks (spring_boot, go_net_http, ruby_rails, node_express, django, python_fastapi) | caller header or bearer | a handled 401 for a missing credential (`spring_boot/__init__.py:159`, `templates/sources/read_authorization_bearer_token.java.j2:11-14`, `go_net_http/__init__.py:381-473`, `ruby_rails/__init__.py:324`); no login form | **not consumers** (no login to detect). Their 403s are authorization denials (`identity_match_before_fetch.java.j2:10`, `object_lookup_authorization_check.go.j2:12`). |
| copy-n-paste, Security Crawl Maze | "no identity" (`requirements.md:6419`, `:6476-6480`) | — | not consumers |

None of these were measured live: booting was out of scope. The table is what the
sources predict.

### 1.8 Facts the design relies on

| Fact | Source | Result |
|---|---|---|
| `detect_logout` decides by status | `session/detect.py:421` | `status in (401, 403)` |
| `observe` acts at once | `manager.py:399-410` | invalidate, persist, tell |
| SP-56's classes | `core/comparability.py:69-90` | 403/451 policy-block; a credentialed 401 or login redirect that is not a submission is an auth-failure; 407 is an auth-failure whoever sent it; 429/503 throttle |
| A framework's missing-credential answer | `fastapi_missing_auth.py`, FastAPI 0.143.3 offline | all five built-in security dependencies answer **401**, never 403 |
| DRF answers a missing session with 403 | its docs | **not measured** (not installed); the design does not rely on it (M2 covers it when a resource is known; R1) |
| The seam adopts no response cookie | `tools/probesender.py:85-89` | a recorded divergence (BUG-0112) |
| `verify_live` raises on an unapproved hop | `tests/test_session_origin_scope.py:435,451` | that contract is kept |
| A `SessionAuthError` from `prepare` ends a run | `probesender.py:219-242`, `oracle.py:470-510`, `auto_cli.py:240` | not mapped to "unobserved"; the run is marked aborted |
| The listeners fire inside the observing send | FR-SESS-16; `probesender.py:452-461,601-621` | the breakers attribute a culprit from the current send |
| The contract runner has no `SessionManager` | `disco/runner.py:243-330` | static auth profiles |
| The disco explorer checks only the page URL | `disco/explore.py:1251-1336` | defect 4 |

### 1.9 The test results

**On the base** (lock-serialised runs, `scratchpad/au-sess403/r2_final.log`):
- 58 tests: **17 passed, 41 xfailed**.
- With `--runxfail`, 41 fail:
  - **37 on the measured counts or behaviour.** The 10/10/10 counts, 3 logins for a
    late answer, 4 for concurrent rounds, `recorded None`, no health GET, DID NOT
    RAISE where a pause or bucket should, and listeners told on a 403.
  - **4 on an absent API:** `health_report`, `Request.session_generation`,
    `request_entry_names`, and `Probe.session_generation` (F3).
- The 17 that pass are pins:
  - T2 ×2, T4b, T5, T7;
  - T9[none], TP1, TP2, TP3, TP4, TP5;
  - TOFF, T18, T21b;
  - T10[451], T11, and T19's synthetic-offender proof.

**With the prototype:** **56 passed, 2 failed.**
- T19's whole-package assertion reads `fuzzlab/`'s source, which a run-time patch
  cannot change; it passes on the implementation.
- F3's strict-xfail pin is the stated residual R6.

**Every revert** fails every test named for it (§6, the revert column). There are 43,
and every collected test is named by at least one, except T19's whole-package assertion
and F3's pin. `run_reverts.sh` reports each revert on one line as
`selected N failed N`. The runs on the committed files are in §12.

## 2. The defect, as measured

`observe` acts on one answer's status. It never asks whether that answer is evidence
about this session:
1. A 403 is policy (SP-56 says so), and `detect_logout` ignores that.
2. A credential submission's own refusal, a 401 for scope and a privilege-gated login
   redirect are read as losses.
3. An answer from an earlier session generation is applied to the current one.
4. Nothing confirms a suspicion on a resource whose answer depends on the session.
5. Nothing limits successful re-logins.

The result is a login, 6 requests and a new session per forbidden probe.

## 3. Design

### 3.1 One loss predicate (SP-16; ADOPT)

`detect.detect_logout(status, headers, body, login_url=None, page_url=None,
content_check=True, login_fields=None, *, credentialed=True, credential_submission=False)`
is **the** predicate "this answer is a loss". It returns True in two cases:
- **An auth failure that is this session's.** `core.comparability.response_class`
  (with `redirect_to_login` from `redirect_is_logout`, FR-SESS-18) gives `AUTH_FAILURE`
  for the request as sent, *and not* for the same answer uncredentialed.
  - The second test drops SP-56's 407, which is an intermediary's demand.
  - No classified status is written as a literal, so the site leaves SP-56's allowance
    list.
- **This session's login form, shown again at 200.** It counts when the request was
  credentialed and is not a submission, under FR-SESS-15 / BUG-0113's unchanged form
  rules.
  - `content_check=False` for a Basic session: Basic keeps BUG-0113's exception, in the
    signal and in `health_verdict`.

**`health_verdict` calls it** with `credentialed=True, credential_submission=False`, so
"loss" is decided once (SP rule 2). T19 enforces that only `observe` and
`health_verdict` call it.

**`detect.request_entry_names(url, body, content_type)`**
- Returns the query's names, a urlencoded body's names, and a JSON body's leaves by
  `display_name`.
- Reads at most 64 KiB of body and is total. Multipart is not read (R11).

### 3.2 `observe`'s decision (M2, M3)

| The answer to a request this manager prepared | Resource known | No resource |
|---|---|---|
| loss shape (§3.1), not a credential submission | **suspected**: `check_health` | **unconfirmed loss**: `_mark_lost` (counted) |
| loss shape, credential submission (`login_facts` with `request_entry_names`) | `check_health` (M3) | nothing (never an unconfirmed loss) |
| credentialed policy block (403, 451) | `check_health` (cached; M2) | nothing |
| anything else (throttle, gateway, 407, incomplete, application) | nothing (counted by class) | nothing |

Before any check, the request's generation (§3.3) must be the state's. A stale signal is
ignored and counted. A signal on an invalid or paused generation is ignored.

### 3.3 Generations

- **`SessionState.generation`:** the next per-(host, identity) value at each login and
  each `adopt`.
- **`core.http.Request.session_generation`** (CC-CORE-0070): `prepare` sets it when it
  applies the session.
- A request that does not say is read as the current generation (fail closed: it can
  only cause a check).

### 3.4 The health check: `check_health(host, identity, base_url=None, *, generation=None, signal_url=None, seen_seq=None, foreign=False, use_cache=True)`

It returns `(Health(state, reason, generation, retry_after_s), transitioned)`.

**The request.**
- One GET of the stable protected resource.
- It carries `state.apply({})` (the session's own cookies and headers) and is sent with
  **the seam's headers** (ADOPT): `requests.request` per hop, no browser header set, as
  `core.http` sends.
- Redirects are walked by hand inside the session's origins and the transport floor
  (`_navigate`).
- **`stop_at`:** the walk stops at the first hop whose `Location` `redirect_is_logout`
  judges a login redirect. A login on another origin (an IdP) is therefore judged at its
  hop and never fetched (TOFF).
- **An unapproved or off-origin hop that is not a login redirect raises
  `SessionAuthError`: fail fast**, never a pause. `verify_live` keeps that pinned
  contract (THOP).
- **`Set-Cookie`.** A live answer that set a new value for one of the session's own
  cookies (a rotating id) is adopted, so a check never kills its own session. A lost
  answer's cookies (the login page's anonymous SID) are never adopted (TROT, §1.5).

**`health_verdict(state, status, headers, body, page_url, *, stopped_at_login)`** is
public:

| Answer | Verdict |
|---|---|
| stopped at a login redirect; `detect_logout` true (credentialed, not a submission; Basic: no content) | **LOST** |
| the resource's recorded refusal status (M5), or a 2xx whose body hashes to the recorded refusal body | **LOST** |
| any other 2xx | **LIVE** |
| a policy block, throttle (its `Retry-After` kept), gateway, 407, another status, no response | **INCONCLUSIVE** |

**Single flight and compare-and-set (M7).**
- The check runs under a per-(host, identity) health lock. It judges the generation
  it was given: if the state has moved on, it returns `STALE` and changes nothing.
- The verdict is recorded **before the lock is released**. A waiter re-checks under the
  lock: a live verdict recorded after its signal was seen covers it, so N concurrent
  signals make one GET (T M7).
- A LOST verdict calls `_mark_lost(state, generation)`, which compare-and-sets on
  (the state object, its generation).
- An INCONCLUSIVE verdict sets the pause, keyed by its generation. A pause found for an
  older generation never pauses the new one (T M7b).

### 3.5 The stable protected resource (M4, M5)

One owner decides "this URL tells a live session from a lost one": `_spa_probe`, extended
(PA-0507(2)).

**The test it applies to a candidate:**
- **The credentialed arm** must be LIVE by `health_verdict` on the `stop_at` walk
  (M4(a)), not by `_verify_authenticated`'s acceptance.
- **The anonymous arm** (ambient cookies only) **and the corrupted arm** (M4(b);
  `_corrupted`: a flipped token, a random credential cookie) must agree as a refusal,
  in one of three ways:
  - both LOST by `health_verdict` (a login redirect, a 401, this login form);
  - or both the same non-2xx, non-5xx status, which is recorded as
    `probe_refusal_status` (M5);
  - or both the same stable 2xx body that differs from the credentialed one, which is
    recorded as `probe_refusal_digest` (today's byte rule).

**The candidates, by the first rule that holds:**
1. A browser login's post-click GETs (FR-SESS-19), as today.
2. **The operator's base URL**, for every session kind (form, JSON, Basic).
3. The post-login landing: the credential POST's redirect target, inside the origins,
   not an auth endpoint and not destructive.
4. For Basic, rule 2 is the base URL that challenged.

**`adopt(state, *, protected_probe=None, refusal_status=None)`** takes a resource
(ADOPT, for a captured session and for disco's future use).

**With no resource**, the table in §3.2 applies: unconfirmed losses for loss shapes, and
nothing for 403s or submissions.

### 3.6 The live cache (M6)

A live verdict covers a later signal in two cases:
- **(a)** The verdict was recorded after the signal was seen. This is the single-flight
  rule; a sequence counter orders signals and verdicts, never a clock.
- **(b)** For `health_ttl_s` (default 30 s), a signal of the **same generation and the
  same URL key** (`url_key`, origin and path), unless the request carries a **foreign
  header**.
  - Foreign means a header the session does not own: anything but `Cookie`,
    `Authorization`, the state's own header names, and the body's `Content-Type` and
    `Content-Length`.
  - The framing headers are exempt on purpose: otherwise every POST probe would bypass
    the cache. A header probe (`User-Agent`, `Referer`) is foreign.

**`verify_live` never reads the cache.**

### 3.7 Invalidation and listeners (FR-SESS-16, M6, M7)

**`_mark_lost(state, generation) -> bool`** is the only writer of `valid = False`
(T19). Its caller states `notify`:

| Path | `notify` | Why |
|---|---|---|
| `observe` (a confirmed or an unconfirmed loss on this send) | True | the culprit is the observing send; the breakers attribute it as today |
| a pause re-check inside a later `prepare` | **False** | no send caused it; a listener would attribute it to the wrong probe ("carry no culprit") |
| `verify_live` | False | as today ("listeners are not told") |

Listeners are called after the health lock is released, once per transition.

### 3.8 Pause, sticky unknown, budget (M8)

**On an INCONCLUSIVE verdict:**
- Nothing else changes: no invalidation, no login, no listener.
- The identity is paused: 5 s, doubling to 60 s, with a `Retry-After` honoured up to
  60 s.
- One log line marks the pause's start (ADOPT).

**`prepare` for a paused generation:**
- It waits the pause out on the injectable `sleep`, holding no lock. Each wait is
  clipped to the pause bound and to the run's remaining budget.
- Then it re-checks, single-flight:
  - **live:** send;
  - **lost:** `_mark_lost(notify=False)`, then a re-login under the bucket;
  - **inconclusive:** pause again.
- **The bounds:** `max_pause_s` (default 300 s) for one pause, and `pause_budget_s`
  (default 600 s) for the whole run.
  - Past either, `prepare` raises `SessionHealthUnknown` (a `SessionAuthError`). An
    isolated copy raises `IsolatedHealthUnknown` (an `IsolatedLoginFailed`).
  - It is **sticky**: every later `prepare` for that (host, identity) raises at once,
    with no clock and no network, until a check succeeds (`verify_live`).

**How it reaches the oracle.**
- During a pause, as a delay inside the next probe's send. The probe goes out only on a
  known-live or freshly logged-in generation.
- Past the bound, `SessionHealthUnknown` propagates the way today's `max_reauth` cap
  does: `_unobserved` returns None, and the oracle does not catch a `SessionAuthError`.
  The run ends marked aborted. No oracle change.
- A comparison that straddles a re-login is R6 / F3 (§3.13).

**How it reaches the runner: it does not.** The contract runner has no
`SessionManager`. SP-56 already makes a credentialed 401 or login redirect an `error`.

**Catch-alls on the way (PA-0138(3)):**
- `audit_page`'s per-page `except Exception` (`tools/fetcher.py:881`) swallows it, page
  by page. Because it is sticky, each later page raises at once, with no pause and no
  network. Each page prints "Fetch failed". Loud, cheap, and the audit finishes (§5.4).
- The PRG restore boundary (`oracle.py:405`) counts it as `prg_restore_failed`. The next
  send outside the boundary raises and ends the run.

### 3.9 The re-login budget (M10)

- **A token bucket per (host, identity):** a burst of `relogin_burst` (5), refilled at
  1 per `relogin_refill_s` (120 s).
- It is drawn only by **loss-driven** re-logins (after `_mark_lost`). The first login
  and a JWT `exp` refresh do not draw.
- **An empty bucket waits** for the next token if that is within the pause bound and
  the run's budget. Otherwise the identity goes **sticky unknown** (§3.8).
- `max_reauth` (consecutive failed logins) and a copy's `max_logins` are unchanged.
- **Credential POSTs are counted per account** in `health_report()["credential_posts"]`:
  - `submitted`: each login's POST;
  - `control`: a JSON login's wrong-password control (`WRONG_SUFFIX`), which is a
    failed credential submission by design.

  An account-lockout policy is not modelled: no lab has one, so it is unmeasured (R15).

### 3.10 `verify_live` (M9)

| Check result | `verify_live` |
|---|---|
| LIVE | True, and clears any sticky unknown |
| LOST | False; `_mark_lost(notify=False)` (as today) |
| an unapproved hop | raises `SessionAuthError` (as today; pinned) |
| INCONCLUSIVE | waits out the bounded pause and checks again. Still inconclusive: **True** (today's "not lost"), logged once, nothing changed, never sticky. Never False on an inconclusive check. |

**`_verify_main`'s behaviour is unchanged:**
- No FUZZ change.
- It still trips on False and on a raise.
- It no longer trips on a throttle or 5xx that the bounded re-check could not resolve;
  today a 403 there tripped it with a false "the isolated login logged the run's
  session out".

### 3.11 `_verify_authenticated`

It is routed through `health_verdict`, with today's acceptance kept and stated:
- LOST: False.
- `policy-block`: False.
- Anything else: True.

Its SP-56 allowance row goes. This decides login success, not session loss (R8).

### 3.12 Locks

The order is login lock → health lock → `_observe_guard`, and never the reverse:
- A login takes the health lock only to end the old generation's pause.
- **No path re-logs in while holding the health lock.** T24's revert,
  `relogin_under_health_lock`, makes `observe` do exactly that, which closes the cycle
  health → login → health. The test's observing send then never returns.
- The pause and bucket waits hold no lock.

### 3.13 F3: a comparison that straddles a re-login (residual R6)

The coordinator approved F3 "if small". It is small (about 15 LOC in three FUZZ files):
- `Probe.session_generation`, set by `SeamProbeSender._dispatch` from the request;
- `_ObservedOnly` raises `NotComparable` when a mechanism's credentialed probes carry
  two generations.

But it needs a CC-FUZZ number, and this item's numbers are fixed. So it is a **stated
residual**, pinned by the strict xfail
`test_a_seam_probe_carries_the_session_generation_it_was_sent_on` (PA-0054(3)). Asked as
Q1.

### 3.14 Files and size (estimates)

| File | Change | LOC |
|---|---|---|
| `session/detect.py` | `detect_logout` through SP-56 (keyword facts); `request_entry_names` | +50 / -5 |
| `session/manager.py` | `Health`, `health_verdict`, `check_health`, `_mark_lost`, `_navigate(stop_at=)`, the health fetcher, `_spa_probe`'s extension and candidates, the pause, sticky unknown, budget, bucket, generations, `health_report`, `adopt(protected_probe=)`; new keywords (`health_ttl_s`, `relogin_burst`, `relogin_refill_s`, `max_pause_s`, `pause_budget_s`, `clock`, `sleep`, `health_fetch_factory`) copied to copies | +380 / -40 |
| `session/state.py` | `generation`, `probe_refusal_status` | +10 |
| `core/http.py` | `Request.session_generation` | +4 |
| `tests/test_core_comparability.py` | three rows removed | -6 |
| tests | markers removed; the prototype directory deleted | -700 (prototype) |

## 4. Unchanged on purpose

- The form rules (BUG-0113) and the redirect rules (FR-SESS-18).
- `_login`'s rejection of a credential POST answered 401 or 403, and the Basic challenge
  reads.
- The single-flight login lock, `max_reauth`, and a copy's `max_logins` and
  distinctness.
- The JWT refresh.
- FR-SESS-20's origin rules on every health request.
- The seam's non-adoption of response cookies (R14).

## 5. The sweep (PA-0002; PA-0138(3); SHARED_PRIMITIVES rule 2; CLAUDE.md item 7)

**5.1 `detect_logout`'s callers.**
- `observe` (`manager.py:399`) and, new, `health_verdict`.
- Tests: `test_session_detect.py:86-89` and `test_logout_redirect.py:38` use the old
  signature, and the defaults keep their meaning.
- SP-56's row goes (CC-CORE-0070).

**5.2 Consumers of `observe` and of `.valid`.**
- `core/http.py:214` calls `observe`. Every `HttpClient` with a manager gets the fix:
  - `tools/authhttp.py`;
  - `make_probe_sender`, which builds the run's sender and the peer's
    (`harness/auto_cli.py:387-389`);
  - `tools/fetcher.py:957`;
  - `mutation/cli.py:75`;
  - `tools/blind_sqli_fuzzer.py:341` (`make_auth`) and `:374`;
  - every isolated copy.
- Writers of `.valid` (T19, whole package):
  - `_mark_lost` (False);
  - `adopt`, `ensure` (the anonymous state), `_established`, `_browser_login_state`,
    `_basic_login` (True);
  - `proxy/session_capture.py:93` (`SessionCapture.state`, True).
- Readers of `.valid`: `prepare`, `ensure`, `verify_live`, `redacted`,
  `non_secret_state`, and `core/store.py:182`. A paused state stays valid; `prepare`
  reads the pause.

**5.3 Listeners.** `SeamProbeSender._on_logout` (the header breaker) and
`_on_main_logout` (the single-session breaker): see §3.7. They are told in the observing
send only.

**5.4 `SessionHealthUnknown` and the catch-alls (M8).**

| Site | What it does with `SessionHealthUnknown` | Disposition |
|---|---|---|
| `tools/fetcher.py:881` (`audit_page`, `except Exception` per page) | swallows it, prints "Fetch failed" per page | Sticky makes each later page raise at once: no pause, no network. Loud per page, and the audit ends without traffic. A follow-up (AUD) could re-raise `SessionAuthError`; recorded. |
| `oracle/oracle.py:405` (the PRG restore boundary, PA-0086) | counts `prg_restore_failed`, logs the class | The next send outside the boundary raises at once and the run ends. |
| `tools/blind_sqli_fuzzer.py:388` (the top-level guard) | logs it, and the run ends | fine |
| `mutation/run.py` (only `FilterUnobserved` caught) | propagates, and the run ends | fine |
| `SeamProbeSender._on_copy` / `_create_copy` | a copy's `IsolatedHealthUnknown` is an `IsolatedLoginFailed`: the copy is released and its path goes anonymous; it **counts toward the failed-logins breaker** | Kept. A copy whose health cannot be known is a failed copy, and after `MAX_FAILED_ISOLATED_LOGINS` the run stops making copies (fail closed). Stated, no FUZZ change. |

**5.5 `verify_live`'s callers.**
- `tools/spider.py:2524` (`_live_session_intact`): its fail-closed action is unchanged,
  and an inconclusive check now reads live (§3.10). The message is AU-REDACT's text and
  is not edited.
- `probesender.py:580` (`_verify_main`): §3.10.

**5.6 Browser login.** It makes no status-based loss decision. `_spa_probe` is extended
(§3.5), and a browser session's check uses its existing probe and digest.

**5.7 Disco (audit defect 4): a known gap, not decided here.**
- The explorer (`disco/explore.py:1327`) holds a `storage_state`, not a `SessionManager`.
- It has no credentials to log in again with, and its browser never calls `prepare`.
- This item exposes `health_verdict` publicly and lets `adopt` take a resource. Defect
  4's item may build on those; nothing here claims disco decides through this owner.

**5.8 Others.**
- The contract runner: not a consumer.
- greybox (`session_header` once; R9).
- `session print`.
- `harness/auto.py` / `pipeline.py`: no loss decision.

**5.9 Existing tests on these paths** (rerun by the harness in Phase 2; an expectation
change is listed with before and after, PA-0073(3)):
- `test_session_manager.py`, `test_logout_listener.py`, `test_forms_phase2.py`: their
  fixtures have no resource, so they behave as today.
- `test_login_form_isolation.py`: its `FakeApp` base redirects to its login, so rule 2
  records `/app/` and its losses are confirmed, with extra fetcher GETs.
- `test_session_origin_scope.py:435,451`: kept (fail fast).
- `test_session_persistence.py`, `test_session_browser_login.py`,
  `test_browserauth.py`, `test_json_login.py`.

## 6. Tests (`tests/test_session_forbidden_answers.py`; PA-0034(2))

How to read the columns:
- **"Base"** is how the test fails on the base: by the measured counts or behaviour, or
  by an absent API, or "pin" (it passes).
- **"Revert"** names the `REVERT` each test fails against on the prototype.
- Every revert below was run (`run_reverts.sh`; §12).

| Test | Layer | Base | Revert(s) |
|---|---|---|---|
| T1 `…forbidden_answer_never_logs_in_and_checks_at_most_once[{admin,waf,csrf}-403 × {redirect,none}]` | M2; SP-56 first | counts (10/10/10) | `403` (none: 10 logins), `nocache` (redirect: 10 checks), `policy_nocheck` (redirect: 0 checks) |
| T2 `…throttled_answer_never_triggers_anything[redirect,none]` | throttle is no signal | pin | `throttle` |
| T3 `…suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in[scope-401, privilege-login-redirect]` | confirmation | counts | `noconfirm`, `nocache` |
| T4 `…credential_submissions_answer_is_checked_never_an_unconfirmed_loss[{password,name-only}-401 × {redirect,none}]` | M3; PA-0529(3) | counts | `nosubmission`, `noentrynames` (none), `submission_ignored` (redirect) |
| T4b `…password_change_point_still_recovers_a_real_expiry` | M3 (DVWA) | pin | `submission_ignored` |
| T5 `…real_expiry_is_recovered_with_one_login_and_one_check` | a true positive | pin | `redirect_live` |
| T6 `…late_answer_from_an_earlier_session_is_ignored[redirect,none]` | generations | counts (3 logins) | `nogen`, `nogenrecord` |
| T7 `…single_flight_lock_stops_simultaneous_duplicate_logins` | the audit's claim | pin | `nologinlock` |
| T8 `…concurrent_forbidden_rounds_never_log_in_again[redirect,none]` | sequential churn | counts (4 logins) | `403` (none), `nocache` (redirect) |
| T9 `…each_login_records_the_resource_its_answers_prove[redirect,static,presence,forbid,basic,none]` | M4, M5 | `recorded None` (none: pin) | `norule2` (redirect, basic), `rule2_cookie_only` (basic), `rule2verify` (static), `nocorrupt` (presence), `norefusal` (forbid), `publicbase` (none) |
| TP1 `…401_expiry_on_an_api_route…` | a true positive | pin | `redirect_live` |
| TP2 `…in_place_login_form_expiry…` (BUG-0113) | a true positive | pin | `content_rule_off` |
| TP3 `…basic_expiry_is_recovered_and_a_password_page_is_never_a_signal` | Basic's exception | pin | `basic_content` |
| TP4 `…app_that_ends_sessions_with_403…` | M2 + M5 | pin | `norefusal`, `policy_nocheck` |
| TP5 `…page_that_answers_any_cookie_never_hides_a_real_expiry` | M4(b) | pin | `nocorrupt` |
| TP6 `…static_redirect_base_neither_churns_nor_misses_an_expiry` | M4(a) | counts | `rule2verify` |
| T12 `…inconclusive_check_pauses_and_never_changes_the_identity` | the pause | listener told | `inconclusive_lost`, `inconclusive_live` |
| T14 `…live_verdict_is_cached_for_its_window_its_generation_and_its_url` | M6 | no checks | `nocache`, `cache_nourl`, `cache_nogen` |
| TOFF `…expiry_that_redirects_to_another_origins_login_is_lost_at_its_hop` | `stop_at` | pin | `nostop` |
| T M7 `…n_concurrent_signals_make_one_health_get` | M7 | no GET | `noflight` |
| T M7b `…pause_found_for_an_older_generation_never_pauses_the_new_one` | M7 CAS | no GET | `nocas` |
| T18 `…header_probe_bypasses_a_warm_cache_and_trips_the_breaker_on_its_own_send` | M6 | pin | `foreign` |
| T17 `…listeners_hear_only_a_lost_session_and_a_pause_recheck_has_no_culprit` | FR-SESS-16 | told 5 times | `notify_pause` |
| T24 `…health_and_login_locks_never_deadlock` | locks | no GET | `relogin_under_health_lock` (a real cycle) |
| T13 `…unknown_session_is_sticky_and_costs_nothing_after` | M8 | DID NOT RAISE | `nosticky` |
| T13b `…runs_pause_budget_ends_a_second_pause_early` | M8 | no sleeps | `nobudget` (55 s slept) |
| T15 `…relogins_draw_on_a_refilling_budget[100-raises, 300-200]` | M10 | DID NOT RAISE / no wait | `nobucket` |
| TCP `…credential_posts_are_counted_and_the_json_control_too` | M10 | API absent | `nocount` |
| T21 `…verify_live_waits_out_an_unknown_and_then_reads_live` | M9 | no GET | `verifylive_false` |
| T21b `…verify_live_never_reads_the_cache` | M6 | pin | `verifylive_cache` |
| THOP `…unapproved_redirect_from_the_resource_fails_fast_and_never_pauses` | ADOPT | DID NOT RAISE | `hop_pauses` |
| TROT `…health_check_never_kills_a_rotating_session` | ADOPT | counts | `noadopt` |
| T22 `…prepare_records_the_generation_it_applied` | generations | API absent | `nogenrecord` |
| T23 `…request_entry_names…is_total` | SP-16 | API absent | `noentrynames` |
| T10 `…policy_block_never_as_a_loss[403, 451]` | the predicate | 403: counts; 451: pin | `403`, `policy_loss` |
| T11 `…keeps_its_loss_signals_and_never_reads_a_throttle` | the predicate | pin | `throttle`, `content_rule_off` |
| T19 `…only_the_owner_decides_a_session_loss` + `…guard_catches_synthetic_offenders` | PA-0533(4) | 2 offenders (`observe`, `verify_live`) | whole package: fails on the base and on the prototype, since a run-time patch cannot change `fuzzlab/`'s source, so Phase 2 proves it. Synthetic: `guard_noassign`, `guard_nosetattr`, `guard_nokeyword`, `guard_nocall`; each re-executes the guard with one branch off. |
| F3 `…seam_probe_carries_the_session_generation_it_was_sent_on` | R6 (strict xfail) | API absent | — (a residual's pin; fails on the prototype too) |
| T20 `tests/test_core_comparability.py::…but_the_owner` (three rows removed) | CC-CORE-0070 | Phase 2 | restoring a status literal in any of the three sites (its existing synthetic offenders) |

## 7. Requirement text

**New: FR-SESS-23 (a forbidden answer is never, by itself, a lost session; CC-SESS-0029,
BUG-0533).**

- **One loss predicate.** `detect.detect_logout` names a loss shape in two cases:
  - an auth failure SP-56 gives only because the request carried the session (a 401;
    a redirect to this session's login page or an anchored login URL);
  - this session's login form at 200 (FR-SESS-15's rules; never for Basic).

  `health_verdict` decides through the same predicate.
- **Classification first.** A throttle, gateway, 407, incomplete answer or other
  application answer never changes the session.
  - With a stable protected resource, three answers trigger the health check:
    - a loss shape;
    - a credentialed policy block (403, 451);
    - a credential submission's loss shape (`login_facts`, with `request_entry_names`).
  - Without one, only a loss shape that is not a submission counts, as an
    **unconfirmed loss**. Nothing else does.
- **Generations.** Each login and `adopt` makes a new `SessionState.generation`.
  `prepare` records it on the request (`core.http.Request.session_generation`).
  - A signal from another generation is ignored.
  - An unstated one is read as the current generation.
- **The health check** (`check_health`) is one GET of the resource, carrying the
  session and sent with the seam's headers.
  - **The walk.** Redirects are walked by hand inside the session's origins and the
    transport floor, stopping at a login redirect. An unapproved hop that is not one
    raises at once (fail fast).
  - **The verdict** (`health_verdict`): **lost** for a loss shape or the resource's
    recorded refusal (status or body); **live** for any other 2xx; **inconclusive**
    otherwise.
  - **Cookies.** A live answer's rotated value of one of the session's own cookies is
    adopted.
  - **Single flight.** Single-flight per (host, identity). The verdict is recorded
    before the lock is released, and covers every signal seen before it. Each write
    compare-and-sets on the generation judged.
- **The cache.** For `health_ttl_s` (30 s), a live verdict also covers later signals of
  the same generation and URL key, except from a request that carries a header the
  session does not own (`Content-Type` and `Content-Length` excepted). `verify_live`
  never reads it.
- **The stable protected resource** is recorded at login: a URL whose credentialed
  answer is live on that walk, and whose anonymous and corrupted answers agree as a
  refusal (lost, the same non-2xx non-5xx status, recorded, or the same stable body,
  recorded).
  - Candidates: a browser login's post-click GETs; the operator's base URL (every
    session kind); the post-login landing.
  - `adopt` may take one.
- **Lost.** `_mark_lost` is the only writer of `valid = False`. It persists the state,
  and tells the listeners only when the loss was seen on a send (not from a pause
  re-check, not from `verify_live`).
- **Pause.** An inconclusive check changes nothing.
  - **The wait.** The identity is paused (5 s doubling to 60 s; `Retry-After` up to
    60 s; one log line when it starts). `prepare` waits it out, then checks again.
  - **The bounds.** Past `max_pause_s` (300 s), or the run's `pause_budget_s` (600 s),
    `prepare` raises `SessionHealthUnknown` (a copy: `IsolatedHealthUnknown`). That is
    sticky: every later `prepare` raises at once until a check succeeds.
- **Re-login budget.** Loss-driven re-logins draw on a token bucket: a burst of 5,
  refilled at 1 per 120 s.
  - An empty bucket waits within the pause bound and budget; otherwise the identity
    goes sticky unknown.
  - Credential POSTs are counted per account (`submitted`, `control`).
- **`verify_live`** is a fresh check:
  - live: True;
  - lost: False and invalid;
  - an unapproved hop: raises;
  - inconclusive: it waits out the bounded pause and checks again; still inconclusive,
    it returns True, logged once, never sticky.
- **Reported.** `health_report()` gives counts per class and outcome, paused seconds,
  re-logins and credential POSTs. It holds no URL, header value or body.
- **Residuals:** R1-R15 (§8).
- **Enforced by:** T1, T3, T4, T6, T9, T12, T13, T13b, T14, T15, T17, T18, T19, T21, the
  M7 tests (names in §6).

**Amended in place:**
- **FR-SESS-5.** The 401/403 list becomes "a credentialed 401, a redirect to the
  detected login, the login form reappearing, JWT `exp`; confirmed on the stable
  protected resource (FR-SESS-23); re-logins limited by a refilling budget, then the
  identity is unknown and the run fails loudly. A 403 is a policy answer."
- **FR-SESS-15 (Basic).** "…its logout signal is a credentialed 401, confirmed on its
  base URL."
- **FR-SESS-16.** Listeners are told once per valid → invalid transition, and only when
  the loss was seen on a send.
- **FR-SESS-17 (`verify_live`).** The FR-SESS-23 rules above.
- **FR-SESS-18 (residuals).** Privilege-gated login redirects are suspected losses:
  confirmed live with a resource, unconfirmed without.
- **NFR-SESS-single-flight.** "… and one health check per (host, identity) for
  concurrent signals; a late answer from an earlier generation triggers neither."

## 8. Residual limits (stated)

- **R1. A 403 on expiry with no resource.** An app that answers a lost session with
  403 is recovered only when a resource is known (M2, TP4). With none, its 403s change
  nothing, and its probes read as policy blocks (inconclusive at the oracle, never
  negative). DRF's documented 403 is not measured here.
- **R2. No resource.** A public base with no protected landing, an adopted session,
  ecommerce-api, PFF, and every JSON/bearer login without a browser probe (§1.6-1.7).
  - Loss shapes are unconfirmed losses: FR-SESS-18's privilege-redirect residual
    stays, bounded by the bucket.
  - 403s and submissions change nothing.
- **R3. The TTL.** A live verdict covers same-URL signals for `health_ttl_s`. A session
  that dies inside the window is found at the next signal from another URL, from a
  foreign-header request, or after the window. Its probes in between are auth failures
  (not comparable at the oracle).
- **R4. A moved or broken resource.** A 404 or 5xx is inconclusive, so it pauses and
  then goes sticky. A refusal status recorded as 404 reads a deleted resource as LOST,
  which costs a re-login.
- **R5. The health GET is untraced and unbudgeted,** as the login handshake already is.
  It is counted in `health_report()`.
- **R6 (F3). A comparison that straddles a re-login is not detected** (strict xfail).
- **R7. A probe whose own answer was a 200 login page is still `application` to the
  oracle** (BUG-0529's R3 and R10). Its loss is detected and recovered here, but the
  oracle reads that probe's answer as an observation. This half of F1/F2 is
  out of scope.
- **R8. `_verify_authenticated` keeps today's acceptance:** a policy block fails the
  login; a throttle or 5xx accepts it.
- **R9. Consumers outside this mechanism.** The contract runner (static profiles), disco
  (defect 4) and greybox's static header are not covered.
- **R10. The crawler's message** for an inconclusive `verify_live` is now moot: it
  reads live (§3.10). Its text for a real loss is unchanged.
- **R11. Multipart bodies' field names are not read.**
- **R12. The pause waits in the sending thread.** Parallel senders of one identity wait
  to the same deadline.
- **R13. Login cost.** Rule 2 or 3 costs up to 3 GETs per candidate at a login (6 with
  the byte rule), and each isolated copy pays its own.
- **R14. A rotating session id churns anyway** (measured, §1.5). The seam adopts no
  response cookie (BUG-0112's divergence), and login verification already rotates the
  id. Only the health check's own rotation is handled.
- **R15. Account lockout is not modelled** (no lab has a policy, so it is unmeasured).
  - Each loss-driven re-login is one submitted POST, limited by the bucket.
  - Each JSON login adds one wrong-password control POST.
  - Both are counted per account.

## 9. Change-control drafts

### CC-SESS-0029 — A forbidden answer is never, by itself, a lost session (FR-SESS-23, BUG-0533) (2026-10-20)
- **Change:** §3, in `session/detect.py`, `session/manager.py` and `session/state.py`.
  About +440 / -45 LOC. The tests are listed in §6. The prototype directory is deleted.
- **Impact (other components / project):**
  - **CORE:** `Request.session_generation` (CC-CORE-0070), and SP-56's allowance list
    loses three rows.
  - **FUZZ:** every `SeamProbeSender` (the run's, the peer's, the mutation's, the
    blind-SQLi confirmer's) stops re-logging in on forbidden answers.
    `SessionHealthUnknown` ends a run as the `max_reauth` cap does.
  - **No FUZZ code changes. `_verify_main`'s behaviour is unchanged:** it trips on
    False and on a raise, as before. `verify_live` now returns False only for a real
    loss, so an unresolved throttle no longer trips it falsely (§3.10).
  - A copy's health-unknown counts toward the failed-logins breaker (§5.4).
  - **AUD:** `audit_page` swallows the sticky unknown per page, without traffic.
  - **CRAWL:** `verify_live`'s API is unchanged.
  - **SP-16:** gains `request_entry_names`; its one loss predicate is shared with
    `health_verdict`.
  - **A new shared-primitive row** (§10.5).
  - The consumers were found by grep (§5; PA-0152).
- **Risk (medium):**
  - A missed real loss: mitigated by the true-positive pins (TP1-TP6) and by
    unconfirmed losses without a resource.
  - A run that now ends loudly on an unknown identity: bounded and sticky, stated.
  - Lock order: §3.12, T24.
  - Login cost: R13.
  - A wrong resource (a public page): mitigated by the corrupted arm and M4(a), with T9
    and TP5/TP6.
- **Deliverables:**
  - [ ] detect.py — todo
  - [ ] manager.py — todo
  - [ ] state.py — todo
  - [ ] tests (markers removed) — todo
  - [ ] the prototype deleted — todo
  - [ ] FR-SESS-23 and the amendments — todo
  - [ ] the sweep recorded in BUG-0533 — todo
- **Effectiveness:** pending.

### CC-CORE-0070 — The request records its session generation; SP-56's guard list loses three session rows (FR-SESS-23, BUG-0533) (2026-10-20)
- **Change:**
  - `core/http.py::Request` gains `session_generation: int | None = None` (+4).
  - `tests/test_core_comparability.py::ALLOWED` drops the rows for `verify_live`,
    `_verify_authenticated` and `detect_logout`.
- **Impact:** SESS only. F3 would add FUZZ as a reader.
- **Risk (low):** an optional field with a None default.
- **Deliverables:**
  - [ ] field — todo
  - [ ] rows removed, T20 green — todo
- **Effectiveness:** pending.

## 10. Bookkeeping text (for the coordinator; this lane edits none of those files)

### 10.1 BUG-0533 (lands with the fix as `docs/bugs/BUG-0533-a-forbidden-answer-logged-the-session-in-again.md`)

- **Description:** a 403, a scope 401, a privilege-gated login redirect, or a credential
  submission's own 401 made the session manager invalidate the session. The next send
  logged in again.
- **Where encountered:** the owner's audit, defect 6. Measured at 15a8a27 (§1.2).
- **What it caused to fail:**
  - N forbidden probes made N logins (6 requests each), with no cap.
  - Every probe ran on a new session.
  - The cross-account peer re-logged in on each denied replay, including the lab's own
    secure twins.
  - A late answer from an earlier session cost one more login.
- **What the bug was:** `detect_logout`'s `status in (401, 403)`, acted on by `observe`
  with no confirmation, no generation and no submission fact. Nothing limited
  successful re-logins.
- **Root cause (Five Whys):**
  1. A login per 403? `observe` invalidated on `detect_logout`.
  2. Why "loss"? FR-SESS-5 listed 403.
  3. Why was a status taken as proof? The state change had no evidence standard: one
     answer's surface feature decided it, unconfirmed on a session-dependent resource
     and untied to the session the request carried.
  4. Why did SP-56 and PA-0529(3) not prevent it? They were enforced at the oracle, and
     the session manager was deferred (CC-SESS-0028; SP-56's allowance list).
  5. Why persistent? PA-0007's positive differential was required for login only.

  **Root cause:** a session-state change decided from one answer's surface feature,
  without positive evidence about that session or a binding to it.
- **Corrective action:** CC-SESS-0029, CC-CORE-0070.
- **Recurrence review:**
  - **BUG-0008 / PA-0007:** login from an ambient cookie. The same root cause, login
    side.
  - **BUG-0113:** its logout rule (any password field) **had no preventive action of its
    own**. PA-0113 covers base URLs, cookie scope and sub-path tests, not logout
    evidence.
  - **BUG-0122 / PA-0122:** a substring login redirect.
  - **BUG-0529 / PA-0529(3):** a submission's refusal read as a loss, fixed at the
    oracle only.
  - **Result:** a recurrence: the fourth time on logout detection.
- **Prior-preventive-action failure analysis:**
  - **PA-0122:** too narrow, the wrong layer (one signal's grammar).
  - **BUG-0113's rule:** too narrow and never made a PA (one signal's content).
  - **PA-0529(3):** not applied at the actor. Its own guard allow-listed
    `detect_logout`.
  - **PA-0007:** too narrow (login only).
  - **The common failure:** each constrained a signal or a reader, never the state
    change.
- **Preventive action:** PA-0533.
- **The sweep:** §5.

### 10.2 PA-0533

**PA-0533** strengthens `PA-0007`, `PA-0122` and `PA-0529(3)`, after BUG-0533: a 403
logged the session in again. Each earlier rule constrained one signal or one reader;
none constrained the state change.

1. **An identity's state changes only on evidence about that session.**
   - SP-56 classifies first. A throttle, gateway, 407 or incomplete answer never
     changes it.
   - A loss shape, a credentialed policy block or a submission's loss shape triggers a
     check of the session's stable protected resource. The resource's answer, not the
     probe's, decides.
   - Without a resource, only a non-submission loss shape counts, as an unconfirmed
     loss.
2. **Evidence is bound to the generation it is about**, and every write compare-and-sets
   on it.
3. **Re-logins draw on a refilling budget, and an unknown identity pauses, then goes
   sticky.** It never logs in or out on an inconclusive check.
4. **Enforced at the actor.** `_mark_lost` is the only writer of `valid = False`, and
   `detect_logout` is the one loss predicate: a whole-package AST guard, proven on
   synthetic offenders. The loss decisions leave SP-56's allowance list.

- Enforced by: tests/test_session_forbidden_answers.py::test_a_forbidden_answer_never_logs_in_and_checks_at_most_once, tests/test_session_forbidden_answers.py::test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in, tests/test_session_forbidden_answers.py::test_a_credential_submissions_answer_is_checked_never_an_unconfirmed_loss, tests/test_session_forbidden_answers.py::test_a_late_answer_from_an_earlier_session_is_ignored, tests/test_session_forbidden_answers.py::test_an_unknown_session_is_sticky_and_costs_nothing_after, tests/test_session_forbidden_answers.py::test_relogins_draw_on_a_refilling_budget, tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss, tests/test_session_forbidden_answers.py::test_the_loss_decision_guard_catches_synthetic_offenders, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner

### 10.3 ERROR_LOG line

`2026-10-20 — BUG-0533`:
- **Symptom:** a 403 (and a scope 401, a privilege-gated login redirect, a password
  check's 401) logged the session in again: N probes, N logins.
- **Cause:** `detect_logout`'s 401/403 rule, acted on without confirmation or a
  generation.
- **Remediation:** CC-SESS-0029 and CC-CORE-0070.
- **Status:** fixed.

### 10.4 CHANGELOG line

`2026-10-20`: forbidden answers no longer log the session in again. A suspected loss is
confirmed on a stable protected resource and bound to its session generation;
re-logins draw on a refilling budget; an unknown identity pauses, then fails loudly
(AU-SESS403, audit defect 6; CC-SESS-0029, CC-CORE-0070, BUG-0533).

### 10.5 SHARED_PRIMITIVES

- **SP-16:** `detect_logout` is the one loss predicate, through SP-56. Add
  `request_entry_names`.
- **SP-56:** add the session manager to its readers.
- **New row (number for the coordinator):** "Is an identity's session live now."
  - Owner: `fuzzlab/session/manager.py::SessionManager.check_health`, with
    `health_verdict`, `_mark_lost` and `_spa_probe`.
  - Guards: T19 and `test_every_owner_is_defined_once`.
  - Note: disco's defect-4 item may build on `health_verdict` (a known gap, not a
    consumer).

### 10.6 ARCHITECTURE

One sentence in the session manager's paragraph. No new component or dependency.

## 11. Open questions

- **Q1.** F3 is small but needs a CC-FUZZ number. Assign one to bring it in, or keep R6
  with its strict xfail.
- **Q2.** Should `health_report()` appear in `auto`'s run metrics? That is a FUZZ change.
- **Q3.** The defaults: TTL 30 s; a burst of 5, refilled at 1 per 120 s; a 300 s pause
  bound; a 600 s run budget.
- **Q4.** `audit_page`'s catch-all swallows `SessionHealthUnknown` page by page, cheaply
  because it is sticky. Should AUD re-raise `SessionAuthError` as a follow-up?

## 12. Verification of this revision

The run logs are in this lane's scratchpad,
`/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-sess403/`.
They are not committed. `au-sess403-prototype/run_reverts.sh <worktree>` reproduces
them.

- **The test module:**
  - base: 17 passed, 41 xfailed (`--runxfail`: 37 on counts or behaviour, 4 on an
    absent API);
  - prototype: 56 passed, with the 2 stated failures (§1.9).
- **The 37 reverts:** each fails every named test (`reverts_r2.log`, the first run).
  The `publicbase` revert re-run on T9[none] after T9[json] became a measurement.
- **The full re-run on the committed file (a4a3072):** `run_reverts.sh` again, end to
  end, one pytest at a time under the host lock (`reverts_r2_final.log`).
  - All 37 reverts print `OK`: every named test fails on its revert, 0 masked. This
    includes `publicbase`, on T9[none-None] alone.
  - The prototype as drafted: **2 failed, 56 passed**. The two are T19's whole-package
    assertion and F3's pin, both stated (§1.9).
  - The first run (`reverts_r2.log`) was on an earlier copy of the module. That copy
    still had T9[json] and no F3 pin, and its T19 assertion sat at line 1390, not 1415.
    That is why its prototype line read 1 failed, 57 passed. The re-run above is the
    result on the committed file.
- **The base, on the committed file (`r2_final.log`):**
  - markers on: 17 passed, 41 xfailed;
  - `--runxfail`: 41 failed, 17 passed. Each failure is on a count, a behaviour or an
    absent API, as §1.9 lists.
- **Six reverts added, and the whole runner again on 1f85bbf**
  (`reverts_r2_1f85bbf.log`).
  - A collection check found five tests that no revert named: T9[redirect],
    T9[basic], T19's synthetic proof, T19's whole-package assertion and F3.
  - `norule2` and `rule2_cookie_only` now name the two T9 cases. The four `guard_*`
    reverts name the synthetic proof.
  - **All 43 reverts print `OK`.** Each new one fails for its own reason:
    - each `guard_*` revert fails the synthetic assertion with a shorter offender
      list;
    - `norule2` and `rule2_cookie_only` fail on T9[basic] with `recorded: None`.
  - The prototype as drafted: **2 failed, 56 passed**, the same two.
- **The harness on the committed tree** (`scripts/verify_change.py --base 15a8a27` on
  fe15c23):
  - It selected the whole suite, because the merged lock changed `tests/conftest.py`:
    **406 files, all in one parallel pass, 0 serial.**
  - Result: **8168 passed, 0 failed, 0 errors, 42 skipped, 77 xfailed**, rc 0.
  - The new module's 41 marked tests are among the 77 xfailed. The whole-package
    guards accept the new test module and the prototype directory.
- **The harness again on 791728f** (the revert additions):
  - Result: **406 files, 8167 passed, 1 failed, 0 errors, 42 skipped, 77 xfailed**.
  - The failure: `tests/test_web_sitetree_browser.py::test_show_more_from_the_keyboard_keeps_focus_in_the_tree`
    (200 items, expected 250).
  - From fe15c23 to 791728f, `tests/` changed only in docstrings of this module. The
    prototype is never collected.
  - **Root-caused; it is a UI defect, not this item's.** Two layers:
    1. `web/sitetree.store_version` changes when a *reader* closes. Measured
       (`fingerprint_on_read_close.py`): a reader holds the store while the test's
       `Store` commits and closes, so the WAL keeps its frames. The reader's later last
       close checkpoints and deletes the WAL, and the fingerprint changes with no
       write. That contradicts the docstring's "reads never change the fingerprint".
       The previous test in file order (`test_a_refresh_keeps_focus_selection_and_loaded_pages`,
       run on the same worker under `--dist loadfile`) writes while its tab reads.
    2. `sitetree.js` `refreshGroup` then calls `setTail`, which replaces the "Show
       more" button. `lostFocus` covers only the removed tree items, so a focused
       button's focus falls to `<body>`. A click whose load is in flight goes stale and
       loads nothing.
  - **Reproduced deterministically** (`repro_sitetree_refresh/test_repro_show_more.py`,
    in the scratchpad, under the host lock):
    - the control gives `BUTTON`, 250;
    - a checkpoint-only fingerprint change between the focus and the Enter gives
      `BODY`, 200: the harness's exact failure.
  - Flagged to the coordinator: it needs its own bug number and an owner (UI).
