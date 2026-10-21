# DRAFT AU-SESS403: a forbidden answer is never, by itself, a lost session

- **Item:** `AU-SESS403`, audit defect 6 ("Every forbidden response can trigger
  another login").
- **Base:** `15a8a27`, with the branch tip `7ebf48a` (the host pytest lock, BUG-0532)
  merged in.
- **Status:** **implemented (Phase 2)**: revision 3, the owner's decisions D and D′ and
  review round 4's follow-ups, in `fuzzlab/` (CC-SESS-0029, CC-CORE-0070, CC-FUZZ-0107).
  The prototype is deleted; §13 records the implementation's verification.
  Phase 1's history:
  - Revision 1 went to the review gate. Both reviewers disagreed with it and endorsed
    the direction: SP-56 first, then a health check on a protected resource, then
    generation binding.
  - Revision 2 answered their merged list (M1-M10) and the adopted items.
  - The final review (round 3) found six blocking defects (B1-B6), each with a probe
    (P1-P6). The owner decided one design question (D).
  - This revision answers B1-B6 and D, and folds in the round's follow-ups. It stops
    for one confirming review before Phase 2.

**Numbers (pre-assigned, unchanged):**

| Number | Covers |
|---|---|
| CC-SESS-0029 | `session/detect.py`, `session/manager.py`, `session/state.py` |
| FR-SESS-23 | the new requirement (§7). FR-SESS-5, -15, -16, -17 and -18 and NFR-SESS-single-flight are amended in place. |
| BUG-0533 / PA-0533 | the bug record and the preventive action (§10). PA-0533 strengthens PA-0134 among others. |
| CC-CORE-0070 | `core/http.Request.session_generation` and `Request.session_lost` (D′), declared in FR-CORE-6 (§7), and three rows removed from SP-56's guard allowance list (`tests/test_core_comparability.py`) |
| CC-FUZZ-0107 / FR-FUZZ-65 | D′, the oracle part: `Probe.session_lost`, carried by `SeamProbeSender`, read by layer 1 (`require_observed`) (§3.15) |

## 0. What changed in revision 3

| Item | Change | Where |
|---|---|---|
| **B1** a throttle became the resource's refusal status (P1) | The refusal status admits only a non-2xx status below 500 that SP-56 classes as `application` or `policy-block`, read as the credentialed health GET will be read. `health_verdict` returns INCONCLUSIVE for an incomplete, throttle, gateway or 407 answer **before** it matches any refusal status. `adopt(refusal_status=)` is held to the same admission. | §3.4, §3.5, T2b, T2c |
| **B2** single-flight cover (P2) | The check takes its sequence number when its GET is **sent**. A live verdict covers only the signals seen before that point. A signal seen while the GET is in flight makes its own check. T M7 now expects at most two GETs. FR-SESS-23 reads "seen before its GET was sent". | §3.4, §3.6, §7, T M7, T M7d |
| **B3** compare-and-set against the current state (P4) | After the GET, under the health lock, the verdict is STALE unless `self._state[key] is state` and its generation is the one judged. STALE records nothing: no pause, no live mark, no `_mark_lost`, no row, no listener. `_mark_lost` makes the same check, so it never persists a replaced object over the live one's row. | §3.4, §3.7, T M7b, T M7c |
| **B4** the recurrence review | BUG-0134 / PA-0134 added: `observe` logged a session out on another origin's login page, the "not bound to this session" half of the root cause. Its prior-preventive-action failure analysis is written, and PA-0533 names PA-0134 as strengthened. | §10.1, §10.2 |
| **B5** PA-0533's enforcement | Rule (2) names T M7b and T M7c (and T M7d). Rule (1)'s throttle clause names T2 and T11 (and T2b, T2c). `run_reverts.sh` ends with a PA-0533 matrix: each revert that undoes a PA-0533 rule must fail at least one PA-named test. `nocas` fails two. | §10.2, §12 |
| **B6** CC-CORE-0070 | The FR-CORE-6 amendment that declares `Request.session_generation` beside `session_decision` is drafted, and is a CC-CORE-0070 deliverable. | §7, §9 |
| **D** identities with no protected resource (the owner's decision) | When such an identity's re-login budget is spent, it skips the re-login and carries on at once: no sleep, no `SessionHealthUnknown`, no abort. The next re-login is allowed when the bucket refills (1 per 120 s, burst 5). Probes in that window may run on a dead session. **Every request sent in that window is marked (`Request.session_lost`), and the oracle reads any answer to it as not comparable, whatever its class (D′, §3.15, FR-FUZZ-65); the candidate ends inconclusive.** Measured on `json` (30 probes of `/api/reports`) and `rotate_all`: 30 sends, 6 logins, 0 s asleep. A resource-backed identity keeps M8's pause and sticky unknown, and the bucket's bounded wait, and never sends on a lost state. | §1.6, §3.9, §3.15, §8 R16, T15b, TD1, TD2 |
| F1 per-hop timeout | The health GET has a 15 s timeout per hop. A timeout is no response: INCONCLUSIVE. | §3.4 |
| F2 `verify_live`'s wait (P3) | `verify_live` waits on its own. It never records a pause for the identity, its waits draw on their own budget (never `prepare`'s), and an inconclusive check never sets or clears a sticky unknown. | §3.10, T21c, T21d |
| F3 whose budget | Per run: a run's manager and its isolated copies share one pause budget and one credential-POST count. The peer identity has its own manager, so its own budget (stated). The re-login bucket is per (host, identity) per manager. | §3.8, §3.9 |
| F4 the request's generation | `prepare` sets it from the state it applied, never by re-reading the manager. The prototype does the same. | §3.3 |
| F5 the bucket and the login lock | The token is drawn under the login lock, in the same critical section as the login. A wait for a token holds no lock. | §3.9, §3.12 |
| F6 T19 | The guard also catches `object.__setattr__(x, "valid", v)` and `x.__setattr__("valid", v)`. It is proven on two new synthetic offenders and the `guard_nodunder` revert. | T19 |
| F7 credential POSTs | Counted per account (`"<host>/<identity>"`), each kind nested. TCP asserts the account key. A copy counts into its account. | §3.9, TCP |
| F8 | The stale line "at most two review rounds remain" is removed. | header |

## 0b. What changed in Phase 2 (the owner's decision D′ and review round 4)

Review round 4 confirmed B1-B6, D and every round-3 follow-up, measured probes Q1-Q7,
and raised the items below. Phase 2 implements them with the design.

| Item | Change | Where |
|---|---|---|
| **D′** (the owner's decision after Q1) | In D's window a probe on the known-lost session can get an `application` answer (a guest view, a 404, a non-login redirect), which the oracle admitted. Now `prepare` marks every request it sends on a lost-but-unrecovered state (`Request.session_lost`, CC-CORE-0070), `SeamProbeSender` carries the mark to the probe (`Probe.session_lost`), and layer 1 (`require_observed`) raises `NotComparable("... sent on a lost session")` for any answer to it, whatever its class: payloads, controls, baselines and replays alike. The candidate ends inconclusive. A resource-backed identity never sends on a lost state, so the mark never fires for it. | §3.15, §8 R16, TD1, TD2, TD3; CC-FUZZ-0107, FR-FUZZ-65 |
| Follow-up 1 (split `nocas`) | `nocas` is now the check's compare-and-set only, and `nomlcas` is `_mark_lost`'s. `nocas` fails T M7b (a pause recorded and counted for the replaced session) and T M7e (`verify_live` says False for a replaced session). `nomlcas` fails T M7f (Q2's shape: `_mark_lost` on a replaced state writes no row) and T M7h (an `adopt` landing between the check's compare and the mark: no listener, no row). T M7c, which either layer alone keeps green, is named for `cas_both`; a pause of another generation (T M7b2) for `pause_anygen`. PA-0533's line names T M7b2, T M7e, T M7f and T M7h. | §6, §10.2, §13 |
| Follow-up 2 (the compare-and-set is atomic with installs) | `_mark_lost` persists its row inside its lock. Every install -- `ensure`'s login and `adopt` -- goes through `_install`, which numbers the state, installs it and persists its row under the same lock (the persist moved out of `_established`, `_basic_login` and `_browser_login_state`). T M7g (Q3's shape, a slow store write, for a re-login and for an `adopt`): the rows' last word is the current session's. Reverts `persist_unlocked`, `install_unlocked`. | §3.7, T M7g |
| Follow-up 3 (a copy shares the run's budget and account) | TCP now logs an isolated copy in (it counts into the run's account) and a peer (another account). T13c: a copy's pause spends the run's pause budget, so the run's own pause ends early. Revert `copy_own_budget`. | §3.8, §3.9, TCP, T13c |
| Follow-up 4 (R2, R4) | A re-login during a throttle records no resource, so that session takes the no-resource path. | §8 R2, R4 |
| Follow-up 5 (the "F3" label clash) | "F3" stays revision 3's change-table label for *whose budget*. The residual of a comparison that straddles a re-login is R6 only (its pin: `_R6`). | §3.13, §6, §8 |
| D′'s sweep | Two consumers outside the oracle read answers through a session-managed seam and do not read the mark: the live WAF filter (MUT) and the blind-SQLi builder (FUZZ). Each is pinned by a strict xfail naming its owner (PA-0531(4)). | BUG-0533's sweep |

## 0c. What changed in review round 5 (the one revision round)

Both reviewers returned REVISE on f1d31dd with two blockers; everything else they
checked held. The owner's decision D′ was also extended to every consumer.

| Item | Change | Where |
|---|---|---|
| **Blocker 1** (D′ hole: a peer replay skips layer 1) | `CrossAccountReplayStrategy` sends through the peer's (and the anonymous) sender, which the oracle does not wrap in `_ObservedOnly`, and `_compared` called only `require_comparable`. Measured at f1d31dd with a peer whose probes carry the mark: a guest view gave a negative, an open object a `cross-account-replay` confirmation. Now `ConfirmationStrategy._compared` calls `require_observed` first, so every compared send meets layer 1 whichever sender made it. | §3.15, TD4 (revert `compared_skips_layer1`), CC-FUZZ-0107 |
| **Blocker 2** (a policy block costs one health GET per distinct path or header) | The cache was keyed by (generation, URL key) and bypassed by a foreign header, so behind a WAF that 403s every probe, 20 path payloads cost 20 health GETs and 20 `X-Forwarded-For` payloads 20 more. Now a policy block (no loss shape) is covered by any live verdict of its generation within `health_ttl_s`, whatever its URL or headers; a loss shape keeps the URL and foreign-header rule. Two dict lookups replace the linear scan, and only the latest live generation's entries are kept. | §3.6, T14p (revert `policy_cache_by_url`); T14 now uses a scope 401 as its "other URL" |
| D′ for every consumer | The live WAF filter: `FilterUnobserved`, never an allow or a block (CC-MUT-0404). The blind-SQLi builder: `Answer.session_lost`, `answer_class` reads it as `lost-session`, no baseline sample and no row, a lost 504 included (CC-FUZZ-0110). The two round-4 pins are passing tests. | §3.15, §8 R16 |
| The D window's log line | One warning, naming the identity and never a credential, when an identity enters D's window, once per window. `ensure`'s docstring states that it can return a state known to be lost. | §3.9, TD5 (revert `no_window_log`) |
| Claims and residuals | FR-FUZZ-65's timing case is synthetic (`SeamProbeSender` re-raises a timeout). New residuals R17 (Laravel 419), R18 (RFC 6750 `insufficient_scope`), R19 (concurrent pause waiters); R3 and R4 extended. The test module's docstring no longer claims keywords are filtered. The new shared-primitive row is SP-61. | §8, §10.5 |

Revision 2's own change table (M1-M10, ADOPT) is in this file's history
(`git show f3e731f:docs/components/03-session-manager/DRAFT-AU-SESS403.md`). Every item
in it still holds unless a row above changes it.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### 1.1 The probes

**`tests/test_session_forbidden_answers.py`** (70 tests, 46 functions)
- Real loopback apps, each a `ThreadingHTTPServer` on `127.0.0.1:0` through
  `require_loopback`, in nine shapes (`_App(mode=…)`):
  - `redirect`: PHP-like. An anonymous cookie before the login, a per-load login token,
    `/` → `/home.php` or `/login.php`.
  - `none`: no protected resource can be proved.
  - `static`: `/` → `/login` always; a logged-in `/login` → `/dashboard`.
  - `presence`: `/` answers any SID with 200.
  - `forbid`: a lost session gets 403 everywhere.
  - `basic`: HTTP Basic.
  - `json`: a JSON/bearer login from the page's script (FR-SESS-21).
  - `rotate` / `rotate_all`: a rotating session id.
  - `ratelimit` (new, B1): `/` answers anyone without a live session 429.
- Sends go through the real `SessionManager` with its default requests fetcher
  (`browser_login=False`), the real `HttpClient` and `SeamProbeSender`.
- Credentials are in memory: `FakeBackend` (D12).
- The manager's time is a fake clock (`clock`, `sleep`), passed only when the
  `SessionManager` accepts it, so the same tests run on the base.

**Counts are taken by the server, a listener or a store double:**
- **Logins:** successful logins, counted by the app.
- **Invalidations:** the FR-SESS-16 listener.
- **Checks:** the app counts GETs of its resource that carry the session and lack the
  login fetcher's browser headers. That is the health GET's wire signature: it is sent
  with the seam's headers, while the login fetcher sends browser headers.
- **Sessions:** the SID each probe carried, from the server's whole log (PA-0511).
- **Rows** (new, B3): the session rows the manager persists, recorded by a store double
  (`_RecordingStore`). T M7c first asserts the double recorded the login's and the
  adopt's rows, so the channel can carry the violation (PA-0311(2)).

**The prototype** (`docs/components/03-session-manager/au-sess403-prototype/`; Phase 1
only: deleted in Phase 2, kept in git at `fc57a9c`)
- `proto.py` patches this design onto `SessionManager` and `session.detect` at run time.
  It is never collected and is not part of `fuzzlab/`; Phase 2 deletes it.
- It re-implements `prepare` and `ensure`: copies of the base bodies plus the design,
  because F4 and F5 live inside them. Its login lock is re-entrant only so the wrapper
  can hold it around the base `ensure`.
- `REVERT=<name>` undoes one decision (50 names).
  - 45 undo a decision of the design. Six of them are new in revision 3:
    `throttle_refusal`, `throttle_verdict` (B1), `cover_at_record` (B2),
    `nores_waits` (D), `verifylive_clears_sticky`, `verifylive_budget` (F2). `nocas`
    now also undoes B3's check of the current state.
  - 5 (`guard_*`) weaken T19's own guard. `guard_nodunder` (F6) is new.
  - Every collected test is named by at least one revert, except T19's whole-package
    assertion and R6's pin (§6).
- `run_reverts.sh` runs every revert against its named tests, then the PA-0533 matrix
  (B5), then the design.
- This is reviewer B's masking technique, applied to every test.

**Other probes**
- `python3 -m tests.test_session_forbidden_answers` prints the tables below for
  whatever code is loaded. `scratchpad/au-sess403/smoke_proto.py` runs it with the
  prototype (`measure_r3_proto.out`) or without (`measure_r3_base.out`).
- `scratchpad/au-sess403/measure_r3.py` measures D: the reviewer's `json` and
  `rotate_all` fixtures, 30 probes each, default bounds (`measure_r3.log`).
- `scratchpad/au-sess403/fastapi_missing_auth.py`: an offline FastAPI check.

### 1.2 The base, per scenario (10 probes by the low-privilege identity)

`measure_r3_base.out` (revision 3's module, today's code; the same numbers as revision
2's `measure_r2_base.out`):

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
- **30 probes** (§1.6): `json` `/api/reports` makes **30** logins; `rotate_all` makes
  **30** logins.
- **Cost:** 6 requests per login on this app (revision 1's
  `scratchpad/au-sess403/cost.py`).

### 1.3 With the prototype (this design)

`measure_r3_proto.out`:

| Scenario | `redirect`: logins / invalidations / sessions / checks | `none`: logins / invalidations / sessions / checks |
|---|---|---|
| admin 403, WAF 403, CSRF 403 | 1 / 0 / 1 / **1** | 1 / 0 / 1 / **0** |
| 429 | 1 / 0 / 1 / 0 | 1 / 0 / 1 / 0 |
| scope 401; privilege login redirect | 1 / 0 / 1 / **1** | **6 / 6 / 6** / 0 (unconfirmed: no resource; D after the burst, R2, R16) |
| password 401; name-only 401 | 1 / 0 / 1 / **1** | 1 / 0 / 1 / 0 |
| admin 403, n = 1 / 5 / 20 | 1 login, 1 check each | |

- **Concurrency.** Four rounds of six concurrent 403s make 1 login (and 1 check with a
  resource).
- **A late answer** makes 2 logins and 1 invalidation (and 1 check with a resource:
  the real loss).
- **Every real expiry** is recovered with 2 logins and 1 invalidation.
- **30 probes** (§1.6): `json` and `rotate_all` each make 6 logins, with 0 s asleep.

### 1.4 The resource each login records

| Mode | Base | Design (prototype) | Why |
|---|---|---|---|
| `redirect` | None | `/` | anonymous and corrupted both stop at the redirect to `/login.php` |
| `static` | None | `/dashboard` | `/`'s credentialed walk stops at `/login` (M4(a)) |
| `presence` | None | `/home.php` | `/` answers the corrupted SID with 200 (M4(b)) |
| `forbid` | None | `/`, refusal status **403** | anonymous and corrupted both 403, a policy block: admitted (M5, B1) |
| `basic` | None | `/` | anonymous and corrupted both 401 |
| `ratelimit` | None | **`/home.php`** | `/`'s arms agree on 429, a throttle: not admitted (B1). The landing's arms are login redirects. |
| `none` | None | None | `/` is public; the login has no landing |
| `json` | None | **None** | `/` is the login page (an auth endpoint) and a JSON login has no landing |
| `rotate_all` | None | **None** (measured) | the login's own verification already rotates the id away from the state's copy, so every candidate's credentialed arm carries a dead id |

### 1.5 A rotating session id (ADOPT; measured)

- **`rotate_all`** (every authenticated request rotates the SID): it records **no
  resource** (§1.4), so its losses are unconfirmed and take D's path (§3.9).
  - 10 probes: **10 logins** on the base, **6** with the prototype (the burst of 5,
    then D). All 10 answers are 302.
  - 30 probes: 30 logins on the base; 6 logins, 0 s asleep, 30 sends with the
    prototype (§1.6).
  - The seam adopts no response cookie (`probesender.py:85-89`, a recorded
    divergence), and the login's own verification (`_verify_authenticated`) already
    rotates the id away from the state's copy. So such an app churns, bounded by the
    bucket. That is pre-existing, R14.
- **`rotate`** (only a live health GET rotates):
  - With adoption: the next send uses the new id, with 1 login and 1 check.
  - Without (`REVERT=noadopt`): the health check kills its own session and a second
    login follows.

### 1.6 JSON/bearer, and the owner's decision D

- A JSON login (FR-SESS-21) records no resource. Its base is the page holding the login
  form, which `_json_login` records as an auth endpoint (`manager.py:908`), and the
  JSON login has no redirect landing.
- So on JSON/bearer apps a credentialed 401 is an **unconfirmed** loss: a re-login,
  limited by the token bucket. A 403 does nothing.
- Juice Shop's browser login is the exception: rule 1's probe (FR-SESS-19).
- **D:** once the burst is spent, such an identity skips the re-login and sends at
  once on the session it has. Measured (`measure_r3.log`, 30 probes, default bounds,
  fake clock):

| Fixture | Base | Revision 2 (`REVERT=nores_waits`) | Revision 3 (D) |
|---|---|---|---|
| `json`, `/api/reports` (a scope 401 to a live bearer, every probe) | 30 sends, 30 logins, 0 s asleep | **12 sends, then `SessionHealthUnknown`**: 11 logins, **600 s asleep** | **30 sends**, 6 logins, 6 invalidations, **0 s asleep**; last answer 401 |
| `json`, `/api/me` (200) | 30 sends, 1 login | the same | the same |
| `rotate_all`, `/home.php` | 30 sends, 30 logins, 0 s asleep | **12 sends, then `SessionHealthUnknown`**: 11 logins, **600 s asleep** | **30 sends**, 6 logins, 6 invalidations, **0 s asleep**; last answer 302 |

- **Outcome:** the run goes on; nothing aborts, nothing sleeps. Probes 7-30 of each
  fixture (24 of 30) were sent on a session marked lost. On `json` that session was in
  fact live (the 401s were scope refusals); on `rotate_all` it was dead. Their answers
  (a credentialed 401, a login redirect) are SP-56 auth failures, which the oracle
  never admits as evidence (R16).
- 120 s later one token has refilled, and the next probe logs in once (T15b).
- The revision-2 column reproduces the reviewer's P5/P6 numbers.
- Neither fixture records a resource, so extending D to resource-backed identities
  (`measure_r3.py skip_all`) gives the same numbers there. It is not the design: M8 and
  the bucket's wait still apply to a resource-backed identity.

### 1.7 Which labs' logins get a resource (M10; repo sources only, nothing booted)

| Lab | Identity in the repo | What the sources say | Expected rule |
|---|---|---|---|
| bWAPP | `bwapp-bee`, base = the origin (`docs/ON_HOST_RUNBOOK.md:140,161`; BUG-0300) | `/` → 302 `/bWAPP/portal.php` (`lab/external/bwapp/apache-root.conf:6`); `portal.php` → 302 `login.php` anonymously, 200 logged in (`apache-root.conf:1-4`, `lab_fixtures/external.py:1106-1119`, `01-target-lab/requirements.md:6338`); login → 302 `portal.php` (`external.py:1119`) | **rule 2 on `/`**: anonymous and corrupted `PHPSESSID` both stop at the redirect to `login.php` |
| Juice Shop | `juice-user` (`ON_HOST_RUNBOOK.md:151,166`) | SPA; browser login (FR-SESS-19) | **rule 1** (the existing post-click differential; an offline fixture, `tests/_spa_login_fixture.py`; Juice Shop itself never exercised, FR-SESS-19's residual) |
| secdevlabs-gossip-world | `sdl-gossip-user`, `sdl-gossip-peer` (`01-target-lab/requirements.md:6410,6426`) | login → 302 `/gossip`; `/gossip` → 302 `/login` without a session (`tests/test_external_labs_static.py:1343-1371`, modelled on the live bring-up, CC-LAB-0305) | **rule 3** (landing `/gossip`) |
| secdevlabs-ecommerce-api | `sdl-ecommerce-user`, `-peer` (`requirements.md:6382-6383`) | JSON login from the page's script, cookie `sessionIDa5` (CC-SESS-0026) | **none** (like `json`): 401s are unconfirmed losses (D once the burst is spent), 403s nothing |
| PFF (the php_laravel lab, `lab/ground-truth`) | — | login → `redirect('/profile.php')` (`php_laravel/templates/complexities/single_statement.php.j2:41`, `__init__.py:975`). `/` is a public home (`stack/skeleton/routes/site.php:11`). `/profile.php` renders by `?user=`, not by session (`__init__.py:1016-1029`). The layout never changes with login state (`layouts/site.blade.php`). Only the id-lookup sink answers 401 without a session (`sinks/db_row_by_id_lookup.php.j2:8-11`). | **none expected**: no candidate tells a session apart |
| Generated stacks (spring_boot, go_net_http, ruby_rails, node_express, django, python_fastapi) | caller header or bearer | a handled 401 for a missing credential (`spring_boot/__init__.py:159`, `templates/sources/read_authorization_bearer_token.java.j2:11-14`, `go_net_http/__init__.py:381-473`, `ruby_rails/__init__.py:324`); no login form | **not consumers** (no login to detect). Their 403s are authorization denials (`identity_match_before_fetch.java.j2:10`, `object_lookup_authorization_check.go.j2:12`). |
| copy-n-paste, Security Crawl Maze | "no identity" (`requirements.md:6419`, `:6476-6480`) | — | not consumers |

None of these were measured live: booting was out of scope. The table is what the
sources predict.

### 1.8 Facts the design relies on

| Fact | Source | Result |
|---|---|---|
| `detect_logout` decides by status | `session/detect.py:421` | `status in (401, 403)` |
| `observe` acts at once | `manager.py:387-410` | invalidate, persist, tell |
| SP-56's classes | `core/comparability.py:69-90` | 403/451 policy-block; a credentialed 401 or login redirect that is not a submission is an auth-failure; 407 is an auth-failure whoever sent it; 429/503 throttle; 502/504 gateway |
| The oracle's admission | `oracle/probe.py:204-224` (`comparability`), `:249-262` (`require_comparable`, default `APPLICATION_ONLY`) | a credentialed 401 or login redirect is an auth failure: `NotComparable`. A 200 login page is `application` (R7). |
| A framework's missing-credential answer | `fastapi_missing_auth.py`, FastAPI 0.143.3 offline | all five built-in security dependencies answer **401**, never 403 |
| DRF answers a missing session with 403 | its docs | **not measured** (not installed); the design does not rely on it (M2 covers it when a resource is known; R1) |
| The seam adopts no response cookie | `tools/probesender.py:85-89` | a recorded divergence (BUG-0112) |
| The manager's fetch timeout | `manager.py:189-190, 195-196` | `timeout=15` per request (connect and read) |
| `verify_live` raises on an unapproved hop | `tests/test_session_origin_scope.py:435,451` | that contract is kept |
| `verify_live`'s callers | `tools/spider.py:1102, 1124, 2471, 2766` (through `_live_session_intact`, `:2521-2532`); `tools/probesender.py:581` (`_verify_main`) | the crawler calls it after reveal windows and dry submissions, so many times per crawl; `_verify_main` after the run's first copy login and every copy re-login |
| Each identity has its own manager | `harness/auto_cli.py:381-389`, `tools/probesender.py:1070-1079` (`make_probe_sender` → `make_auth_with_isolation` per identity) | the peer's manager is not the run's; isolated copies are built by the run's manager (`manager.py:530-563`) |
| A `SessionAuthError` from `prepare` ends a run | `probesender.py:219-242`, `oracle.py:470-510`, `auto_cli.py:240` | not mapped to "unobserved"; the run is marked aborted |
| The listeners fire inside the observing send | FR-SESS-16; `probesender.py:452-461,601-621` | the breakers attribute a culprit from the current send |
| The contract runner has no `SessionManager` | `disco/runner.py:243-330` | static auth profiles |
| The disco explorer checks only the page URL | `disco/explore.py:1251-1336` | defect 4 |

### 1.9 The test results

**On the base** (lock-serialised runs; `scratchpad/au-sess403/r3_base_runxfail.log`):
- 70 tests: **17 passed, 53 xfailed**.
- With `--runxfail`, 53 fail:
  - **43 on the measured counts or behaviour.** The 10/10/10 counts, 30 logins in 30
    probes, 3 logins for a late answer, 4 for concurrent rounds, `recorded None`, no
    health GET (`arrived` never set), DID NOT RAISE where a pause, a bucket or a sticky
    unknown should, no wait in `verify_live`, and listeners told on a 403.
  - **10 on an absent API:** `health_verdict` (T2c, six cases), `health_report`,
    `Request.session_generation`, `request_entry_names`, and `Probe.session_generation`
    (R6).
- The 17 that pass are pins:
  - T2 ×2, T4b, T5, T7;
  - T9[none], TP1, TP2, TP3, TP4, TP5;
  - TOFF, T18, T21b;
  - T10[451], T11, and T19's synthetic-offender proof.

**With the prototype:** **68 passed, 2 failed.**
- T19's whole-package assertion reads `fuzzlab/`'s source, which a run-time patch
  cannot change; it passes on the implementation.
- R6's strict-xfail pin is the stated residual.

**Every revert** fails every test named for it (§6, the revert column). There are 50,
and every collected test is named by at least one, except T19's whole-package assertion
and R6's pin. `run_reverts.sh` reports each revert on one line as
`selected N failed N`. The PA-0533 matrix and the runs on the committed files are in
§12.

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
| loss shape (§3.1), not a credential submission | **suspected**: `check_health` | **unconfirmed loss**: `_mark_lost` (counted); the re-login draws on the bucket, and D applies when it is empty (§3.9) |
| loss shape, credential submission (`login_facts` with `request_entry_names`) | `check_health` (M3) | nothing (never an unconfirmed loss) |
| credentialed policy block (403, 451) | `check_health` (cached; M2) | nothing |
| anything else (throttle, gateway, 407, incomplete, application) | nothing (counted by class) | nothing |

Before any check, the request's generation (§3.3) must be the state's. A stale signal is
ignored and counted. A signal on an invalid or paused generation is ignored.

### 3.3 Generations

- **`SessionState.generation`:** the next per-(host, identity) value at each login and
  each `adopt`. `adopt` numbers the state before it installs it, so the current state
  always has one.
- **`core.http.Request.session_generation`** (CC-CORE-0070, FR-CORE-6 amended, §7):
  `prepare` sets it **from the state it applied**, on the line where it applies that
  state's headers (F4). It never re-reads the manager afterwards: a concurrent re-login
  between the two would label the old session's request with the new generation.
- A request that does not say is read as the current generation (fail closed: it can
  only cause a check).

### 3.4 The health check: `check_health(host, identity, base_url=None, *, generation=None, signal_url=None, seen_seq=None, foreign=False, use_cache=True, pause=True)`

It returns `(Health(state, reason, generation, retry_after_s), transitioned)`.

**The request.**
- One GET of the stable protected resource.
- It carries `state.apply({})` (the session's own cookies and headers) and is sent with
  **the seam's headers** (ADOPT): `requests.request` per hop, no browser header set, as
  `core.http` sends.
- **Timeout (F1):** each hop has a 15 s timeout, the manager's existing fetch timeout
  (`manager.py:189-190`). That is `requests`' connect and read timeout; the read
  timeout bounds each wait for bytes, not the whole body. A timeout, or any other
  transport error, is no response: INCONCLUSIVE. A walk has at most
  `MAX_LOGIN_HOPS` + 1 = 6 hops.
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
public. The first row that holds decides:

| Answer | Verdict |
|---|---|
| stopped at a login redirect | **LOST** |
| SP-56 classes it `incomplete`, `throttle-or-unavailable` or `gateway`, or it is an auth failure for an uncredentialed request too (a 407) | **INCONCLUSIVE**, a throttle's `Retry-After` kept. **Before any refusal status is matched (B1)**: such an answer is never LOST, whatever was recorded. |
| `detect_logout` true (credentialed, not a submission; Basic: no content) | **LOST** |
| the resource's recorded refusal status (M5, §3.5), or a 2xx whose body hashes to the recorded refusal body | **LOST** |
| any other 2xx | **LIVE** |
| a policy block that is not the recorded refusal status, another status | **INCONCLUSIVE** |

`health_verdict` is total over any state it is handed (T2c), not only over the states a
login records, because it is public (§5.7) and `adopt` takes a resource.

**Single flight, the cover and compare-and-set (M7, B2, B3).**
- The check runs under a per-(host, identity) health lock. It judges the generation
  it was given: if the state has moved on before the GET, it returns `STALE` and
  changes nothing.
- **The cover (B2).** The manager keeps one sequence counter. `observe` takes a number
  when it sees a signal. The check takes a number **when it sends its GET**. A live
  verdict covers a signal only when the signal's number is lower than the GET's: the
  signal was seen before the GET was sent, so the GET's answer is later evidence about
  it. A signal seen while the GET was in flight is not covered: it waits for the lock
  and makes its own check.
  - So N concurrent signals make at most two GETs (T M7): the first, and one for the
    signals seen while it was in flight.
  - And a loss that happens while a GET is in flight is still acted on (T M7d, the
    reviewer's P2).
- **Compare-and-set against the current state (B3).** After the GET, still under the
  health lock, the verdict counts only if the judged object is still
  `self._state[(host, identity)]` **and** still of the generation judged. Otherwise it
  is `STALE` and records nothing: no live mark, no pause, no `_mark_lost`, no row, no
  listener (T M7b for an INCONCLUSIVE answer, T M7c for a LOST one, the reviewer's P4).
- A LOST verdict calls `_mark_lost(state, generation)`, which makes the same check
  (§3.7).
- An INCONCLUSIVE verdict sets the pause, keyed by its generation, unless `pause=False`
  (`verify_live`, §3.10). A pause found for an older generation never pauses the new
  one.
- The verdict is recorded **before the lock is released**.

### 3.5 The stable protected resource (M4, M5, B1)

One owner decides "this URL tells a live session from a lost one": `_spa_probe`, extended
(PA-0507(2)).

**The test it applies to a candidate:**
- **The credentialed arm** must be LIVE by `health_verdict` on the `stop_at` walk
  (M4(a)), not by `_verify_authenticated`'s acceptance.
- **The anonymous arm** (ambient cookies only) **and the corrupted arm** (M4(b);
  `_corrupted`: a flipped token, a random credential cookie) must agree as a refusal,
  in one of three ways:
  - both LOST by `health_verdict` (a login redirect, a 401, this login form);
  - or both the same **admitted** status, recorded as `probe_refusal_status` (M5).
    **Admitted (B1):** a non-2xx status below 500 that SP-56 classes as `application`
    or `policy-block`, read as the credentialed health GET will be read
    (`credentialed=True`, not a submission). So never 429 or 503 (throttle), 502 or 504
    (gateway), or 407. A candidate whose arms agree on anything else is not the
    resource, and the next candidate is tried (T2b: `/`'s arms agree on 429, so the
    landing is recorded);
  - or both the same stable 2xx body that differs from the credentialed one, which is
    recorded as `probe_refusal_digest` (today's byte rule).

**The candidates, by the first rule that holds:**
1. A browser login's post-click GETs (FR-SESS-19), as today.
2. **The operator's base URL**, for every session kind (form, JSON, Basic).
3. The post-login landing: the credential POST's redirect target, inside the origins,
   not an auth endpoint and not destructive.
4. For Basic, rule 2 is the base URL that challenged.

**`adopt(state, *, protected_probe=None, refusal_status=None)`** takes a resource
(ADOPT, for a captured session and for disco's future use). A `refusal_status` that is
not admitted is refused loudly (`SessionAuthError`), as a session with no origins is.

**With no resource**, the table in §3.2 applies: unconfirmed losses for loss shapes, and
nothing for 403s or submissions.

### 3.6 The live cache (M6)

A live verdict covers a later signal in two cases:
- **(a)** The verdict's GET was sent after the signal was seen (B2). This is the
  single-flight rule; a sequence counter orders signals and sends, never a clock.
- **(b)** For `health_ttl_s` (default 30 s), a loss shape of the **same generation and
  the same URL key** (`url_key`, origin and path), unless the request carries a
  **foreign header**.
- **(c)** *(Review round 5.)* For `health_ttl_s`, a **policy block** (a 403 or 451 that
  is no loss shape) of the **same generation**, whatever its URL or headers. A WAF that
  blocks every path or header payload then costs one check per window, not one per
  path (T14p). Only the latest live generation's entries are kept, in two dicts:
  `(generation, url key) -> at` and `generation -> at`.
  - Foreign means a header the session does not own: anything but `Cookie`,
    `Authorization`, the state's own header names, and the body's `Content-Type` and
    `Content-Length`.
  - The framing headers are exempt on purpose: otherwise every POST probe would bypass
    the cache. A header probe (`User-Agent`, `Referer`) is foreign.

**`verify_live` never reads the cache.**

### 3.7 Invalidation and listeners (FR-SESS-16, M6, M7, B3)

**`_mark_lost(state, generation) -> bool`** is the only writer of `valid = False`
(T19). Under `_observe_guard` it compare-and-sets on the **current state**: it changes
nothing and returns False unless `state` is still `self._state[(state.host,
state.identity)]` and still of `generation` (B3). So it never persists a replaced object
over the live one's row (T M7c, T M7f, T M7h). **Its persist happens inside that
critical section, and every install takes the same lock** (`_install`: `ensure`'s login
and `adopt` number the state, install it and persist its row under `_observe_guard`;
review round 4, follow-up 2). An invalidation of the state an install replaces therefore
lands wholly before it (its row first) or finds it replaced (no row): the rows' last word
is the current state's (T M7g). Its caller decides whether listeners are told:

| Path | `notify` | Why |
|---|---|---|
| `observe` (a confirmed or an unconfirmed loss on this send) | True | the culprit is the observing send; the breakers attribute it as today |
| a pause re-check inside a later `prepare` | **False** | no send caused it; a listener would attribute it to the wrong probe ("carry no culprit") |
| `verify_live` | False | as today ("listeners are not told") |

Listeners are called after the health lock is released, once per transition.

### 3.8 Pause, sticky unknown, budget (M8, F3)

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
    with no clock and no network, until a check gives a definite answer (`verify_live`
    live or lost; §3.10).

**Whose budget (F3).** The pause budget is **per run**:
- One object holds it, and `isolated_copy` hands the run's to every copy. A copy's
  pauses and bucket waits draw on the run's budget.
- The peer identity (`--peer-identity`) has its own manager (`make_probe_sender` per
  identity, §1.8), so its own budget. A run with a peer may pause up to 600 s on each
  identity. Sharing one budget across identities needs a FUZZ change, so it is stated,
  not done (Q5).
- `verify_live`'s waits have a budget of their own (§3.10).

**How it reaches the oracle.**
- During a pause, as a delay inside the next probe's send. The probe goes out only on a
  known-live or freshly logged-in generation.
- Past the bound, `SessionHealthUnknown` propagates the way today's `max_reauth` cap
  does: `_unobserved` returns None, and the oracle does not catch a `SessionAuthError`.
  The run ends marked aborted. No oracle change.
- A comparison that straddles a re-login is R6 (§3.13).

**How it reaches the runner: it does not.** The contract runner has no
`SessionManager`. SP-56 already makes a credentialed 401 or login redirect an `error`.

**Catch-alls on the way (PA-0138(3)):**
- `audit_page`'s per-page `except Exception` (`tools/fetcher.py:881`) swallows it, page
  by page. Because it is sticky, each later page raises at once, with no pause and no
  network. Each page prints "Fetch failed". Loud, cheap, and the audit finishes (§5.4).
- The PRG restore boundary (`oracle.py:405`) counts it as `prg_restore_failed`. The next
  send outside the boundary raises and ends the run.

### 3.9 The re-login budget (M10, D, F3, F5, F7)

- **A token bucket per (host, identity), per manager:** a burst of `relogin_burst` (5),
  refilled at 1 per `relogin_refill_s` (120 s).
  - An isolated copy has its own bucket; its `max_logins` (3) caps it below the burst
    anyway. The peer is another account, with its own manager.
- It is drawn only by **loss-driven** re-logins (after `_mark_lost`). The first login
  and a JWT `exp` refresh do not draw.
- **Drawn under the login lock (F5).** `ensure` re-checks the state under the login
  lock, refills the bucket, draws one token and logs in, all in one critical section.
  Two concurrent senders never draw two tokens for one loss.
- **An empty bucket, for an identity with a stable protected resource:** it waits for
  the next token, holding no lock, if the wait is within the pause bound and the run's
  budget, then takes the lock again and draws. Otherwise the identity goes **sticky
  unknown** (§3.8). Unchanged from revision 2 (T15).
- **An empty bucket, for an identity with no resource (the owner's decision D):**
  - No login, no wait, no `SessionHealthUnknown`, no abort. `ensure` returns the state
    as it is, and `prepare` sends the probe at once with that session's material.
  - The state stays marked lost (believed lost, unconfirmed). Further loss shapes on
    it are ignored, and no listener is told again.
  - The next `prepare` after a token has refilled (1 per 120 s) logs in once.
  - Probes in that window may run on a dead session. Every request so sent is marked
    (`Request.session_lost`), and the oracle reads any answer to it as not comparable,
    whatever its class (D′, §3.15, FR-FUZZ-65; R16). Measured in §1.6; T15b; Q1's shape
    in TD1.
- `max_reauth` (consecutive failed logins) and a copy's `max_logins` are unchanged.
- **Credential POSTs are counted per account (F7)** in
  `health_report()["credential_posts"]`, as `{"<host>/<identity>": {"submitted": n,
  "control": m}}`. The account is the credential store's key (D12).
  - `submitted`: each login's POST;
  - `control`: a JSON login's wrong-password control (`WRONG_SUFFIX`), which is a
    failed credential submission by design.
  - A run's isolated copies count into the same account (they share the run's
    counter); a peer is another account.

  An account-lockout policy is not modelled: no lab has one, so it is unmeasured (R15).

### 3.10 `verify_live` (M9, F2)

| Check result | `verify_live` |
|---|---|
| LIVE | True, and clears any sticky unknown |
| LOST | False; `_mark_lost(notify=False)` (as today), and clears any sticky unknown (a definite answer) |
| an unapproved hop | raises `SessionAuthError` (as today; pinned) |
| INCONCLUSIVE | it waits **on its own** and checks again: 5 s doubling to 60 s (`Retry-After` honoured), at most `max_pause_s` per call, and drawn from **its own budget** (a counter of `pause_budget_s`, 600 s per run, apart from `prepare`'s). Still inconclusive, or its budget spent: **True** (today's "not lost"), logged once. Never False on an inconclusive check. |
| STALE (the state was replaced while it checked) | True, logged: the session it was asked about has been replaced by a newer one |

On an inconclusive check, `verify_live`:
- never records a pause for the identity (`check_health(pause=False)`), so a later
  `prepare` never finds a pause whose bound `verify_live` already used up;
- never sets a sticky unknown, and **never clears one** (the reviewer's P3, T21c);
- never spends `prepare`'s budget (T21d).

**Why its own budget, not `prepare`'s.** The crawler calls `verify_live` after reveal
windows and dry submissions, and `_verify_main` after a copy's login (§1.8). Charging
those waits to `prepare`'s budget would let a crawler's checks in a slow spell end the
run's sends early. Leaving them unbudgeted would let them sleep without limit. Their
own counter bounds them (600 s per run) and leaves `prepare`'s intact.

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
- The bucket's token is drawn under the login lock (F5), in the critical section that
  logs in.
- **No path re-logs in while holding the health lock.** T24's revert,
  `relogin_under_health_lock`, makes `observe` do exactly that, which closes the cycle
  health → login → health. The test's observing send then never returns.
- The pause, the bucket and `verify_live`'s waits hold no lock.

### 3.13 R6: a comparison that straddles a re-login (a stated residual)

The coordinator approved this "if small". It is small (about 15 LOC in three FUZZ files):
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
| `session/manager.py` | `Health`, `health_verdict`, `check_health` (cover at send, compare-and-set on the current state), `_mark_lost`, `_navigate(stop_at=)`, the health fetcher, `_spa_probe`'s extension, candidates and admission, the pause, sticky unknown, the run's shared budgets, the bucket in `ensure` under the login lock (and D), generations set in `prepare`, `verify_live`'s own wait, `health_report`, `adopt(protected_probe=, refusal_status=)`; new keywords (`health_ttl_s`, `relogin_burst`, `relogin_refill_s`, `max_pause_s`, `pause_budget_s`, `clock`, `sleep`, `health_fetch_factory`) copied to copies | +420 / -45 |
| `session/state.py` | `generation`, `probe_refusal_status` | +10 |
| `core/http.py` | `Request.session_generation` | +4 |
| `tests/test_core_comparability.py` | three rows removed | -6 |
| tests | markers removed; the prototype directory deleted | -900 (prototype) |

### 3.15 D′: an answer on a session known to be lost is never evidence (CC-FUZZ-0107)

- **The mark (session layer).** `prepare` sets `Request.session_lost = not state.valid`
  on the state it applied. A state is applied while invalid only in D's window (§3.9:
  `ensure` returned it without a login), so the mark fires exactly there. It sits beside
  `Request.session_generation` (CC-CORE-0070, FR-CORE-6).
- **The carry (the seam sender).** `SeamProbeSender._dispatch` sets
  `Probe.session_lost` from the request, read and never recomputed. A PRG follow-up is
  dispatched the same way and carries its own request's mark.
- **Layer 1 (the oracle; SP-56's oracle reader).** `require_observed` checks the mark
  of the probe and of its follow-up **before** any class is read and raises
  `NotComparable("not comparable: the probe was sent on a lost session")`
  (`response_class = "lost-session"`). It runs in two places: the oracle's
  `_ObservedOnly`, around the run's own sender (payloads, controls, baselines, compared
  slots, the correlated send), and *(review round 5)* `ConfirmationStrategy._compared`,
  around every compared send whichever sender made it: the cross-account replay's peer
  and anonymous senders are not the run's (TD4). A timing send's read-timeout stand-in
  is checked the same way, but none is marked today: `SeamProbeSender` re-raises a
  timeout, so TD3's timing case is synthetic.
- **Outcome.** The mechanism gives no verdict; the candidate is `not-comparable`
  (inconclusive) unless another mechanism confirms on unmarked answers. The run goes on.
- **Never for a resource-backed identity**: its losses are confirmed and re-logged in,
  or it waits for a token, or it goes sticky unknown (TD2, revert `d_for_all`).
- **Every consumer reads the mark** (the owner's decision covers them all; review
  round 5): the live WAF filter raises `FilterUnobserved` (CC-MUT-0404); the blind-SQLi
  builder never takes such an answer as a baseline sample or a row, its 504 included
  (CC-FUZZ-0110). The auditor's and crawler's fetches read such answers for discovery
  only.

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
    (`harness/auto_cli.py:381-389`);
  - `tools/fetcher.py:957`;
  - `mutation/cli.py:75`;
  - `tools/blind_sqli_fuzzer.py:341` (`make_auth`) and `:374`;
  - every isolated copy.
- Writers of `.valid` (T19, whole package; assignment, `setattr`, `object.__setattr__`,
  a bound `__setattr__`, a `valid=` keyword):
  - `_mark_lost` (False);
  - `adopt`, `ensure` (the anonymous state), `_established`, `_browser_login_state`,
    `_basic_login` (True);
  - `proxy/session_capture.py:93` (`SessionCapture.state`, True).
- Readers of `.valid`: `prepare`, `ensure`, `verify_live`, `redacted`,
  `non_secret_state`, and `core/store.py:182`. A paused state stays valid; `prepare`
  reads the pause. A no-resource state in D's window stays invalid, and `ensure`
  returns it without a login (§3.9).
- Writers of the session row (`_persist`): only the current state's (B3).

**5.3 Listeners.** `SeamProbeSender._on_logout` (the header breaker) and
`_on_main_logout` (the single-session breaker): see §3.7. They are told in the observing
send only, once per transition. In D's window the state is already marked lost, so they
are not told again.

**5.4 `SessionHealthUnknown` and the catch-alls (M8).**

| Site | What it does with `SessionHealthUnknown` | Disposition |
|---|---|---|
| `tools/fetcher.py:881` (`audit_page`, `except Exception` per page) | swallows it, prints "Fetch failed" per page | Sticky makes each later page raise at once: no pause, no network. Loud per page, and the audit ends without traffic. A follow-up (AUD) could re-raise `SessionAuthError`; recorded. |
| `oracle/oracle.py:405` (the PRG restore boundary, PA-0086) | counts `prg_restore_failed`, logs the class | The next send outside the boundary raises at once and the run ends. |
| `tools/blind_sqli_fuzzer.py:388` (the top-level guard) | logs it, and the run ends | fine |
| `mutation/run.py` (only `FilterUnobserved` caught) | propagates, and the run ends | fine |
| `SeamProbeSender._on_copy` / `_create_copy` | a copy's `IsolatedHealthUnknown` is an `IsolatedLoginFailed`: the copy is released and its path goes anonymous; it **counts toward the failed-logins breaker** | Kept. A copy whose health cannot be known is a failed copy, and after `MAX_FAILED_ISOLATED_LOGINS` the run stops making copies (fail closed). Stated, no FUZZ change. |

A no-resource identity never raises it. `observe` never checks it, so it is never
paused (`verify_live`'s checks record no pause), and its empty bucket never waits (D).
Only a resource-backed identity can raise it.

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
- This item exposes `health_verdict` publicly (total over any state, T2c) and lets
  `adopt` take a resource. Defect 4's item may build on those; nothing here claims disco
  decides through this owner.

**5.8 Others.**
- The contract runner: not a consumer.
- greybox (`session_header` once; R9).
- `session print`.
- `harness/auto.py` / `pipeline.py`: no loss decision.

**5.9 Existing tests on these paths** (rerun by the harness in Phase 2; an expectation
change is listed with before and after, PA-0073(3)):
- `test_session_manager.py`, `test_logout_listener.py`, `test_forms_phase2.py`: their
  fixtures have no resource, so they behave as today until a fixture's identity loses
  more than 5 sessions in a row, where D applies.
- `test_login_form_isolation.py`: its `FakeApp` base redirects to its login, so rule 2
  records `/app/` and its losses are confirmed, with extra fetcher GETs.
- `test_session_origin_scope.py:435,451`: kept (fail fast).
- `test_session_persistence.py`, `test_session_browser_login.py`,
  `test_browserauth.py`, `test_json_login.py`.

## 6. Tests (`tests/test_session_forbidden_answers.py`; PA-0034(2))

How to read the columns:
- **"Base"** is how the test fails on the base: by the measured counts or behaviour, or
  by an absent API, or "pin" (it passes).
- **"Revert"** names the revert each test fails against. Phase 1 proved them on the
  prototype (`REVERT=<name>`, §12); **Phase 2 re-proved every one on the implementation**
  as a literal source edit of the real modules (§13). New or changed rows in revision 3
  are marked **(r3)**, in Phase 2 **(p2)**.

| Test | Layer | Base | Revert(s) |
|---|---|---|---|
| T1 `…forbidden_answer_never_logs_in_and_checks_at_most_once[{admin,waf,csrf}-403 × {redirect,none}]` | M2; SP-56 first | counts (10/10/10) | `403` (none: 10 logins), `nocache` (redirect: 10 checks), `policy_nocheck` (redirect: 0 checks) |
| T2 `…throttled_answer_never_triggers_anything[redirect,none]` | throttle is no signal | pin | `throttle` |
| **(r3)** T2b `…throttle_is_never_a_resources_refusal_status_nor_a_loss` | B1 (P1): the admission | `recorded (None, None)` | `throttle_refusal` (`/` recorded with 429) |
| **(r3)** T2c `…health_verdict_never_matches_a_throttle_gateway_407_or_incomplete_answer[0,429,503,502,504,407]` | B1: the verdict's order | API absent | `throttle_verdict` (LOST) |
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
| **(r3)** T M7 `…n_concurrent_signals_make_one_health_get` | M7, B2: **at most two** GETs | no GET | `noflight` (six GETs) |
| T M7b `…pause_found_for_an_older_generation_never_pauses_the_new_one` | M7, B3: INCONCLUSIVE branch | no GET | **(p2)** `nocas` (the check's compare-and-set only: a pause recorded, counted and logged for the replaced session) |
| **(p2)** T M7b2 `…pause_of_a_replaced_generation_never_delays_its_replacement` | a pause is keyed by its generation | -- | `pause_anygen` |
| **(r3)** T M7c `…lost_verdict_for_a_replaced_session_tells_no_listener_and_writes_no_row` | B3 (P4): LOST branch, listener and row | no GET | **(p2)** `cas_both` (either compare-and-set alone keeps it green: listener told, a row written over session 2's) |
| **(p2)** T M7e `…verify_live_asked_about_a_session_replaced_while_it_checked_answers_live` | B3: the check's compare-and-set, §3.10's STALE row | -- | `nocas` (`verify_live` says False) |
| **(p2)** T M7f `…mark_lost_on_a_replaced_state_changes_nothing_and_writes_no_row` | B3: `_mark_lost`'s own compare-and-set (Q2) | -- | `nomlcas` |
| **(p2)** T M7h `…an_adopt_between_the_checks_compare_and_the_mark_tells_no_listener` | B3: `_mark_lost`'s compare-and-set on the observing send | -- | `nomlcas` (listener told, a row after the adopt's) |
| **(p2)** T M7g `…a_slow_row_write_never_leaves_a_replaced_sessions_row_last[relogin, adopt]` | the compare-and-set atomic with installs (Q3) | -- | `persist_unlocked`, `install_unlocked` |
| **(r3)** T M7d `…loss_seen_while_a_check_is_in_flight_is_still_acted_on` | B2 (P2): the cover is the send | no GET | `cover_at_record` (the session stays valid, dead on the server) |
| T18 `…header_probe_bypasses_a_warm_cache_and_trips_the_breaker_on_its_own_send` | M6 | pin | `foreign` |
| T17 `…listeners_hear_only_a_lost_session_and_a_pause_recheck_has_no_culprit` | FR-SESS-16 | told 5 times | `notify_pause` |
| T24 `…health_and_login_locks_never_deadlock` | locks | no GET | `relogin_under_health_lock` (a real cycle) |
| T13 `…unknown_session_is_sticky_and_costs_nothing_after` | M8 | DID NOT RAISE | `nosticky` |
| T13b `…runs_pause_budget_ends_a_second_pause_early` | M8 | no sleeps | `nobudget` (55 s slept) |
| **(p2)** T13c `…an_isolated_copys_pauses_draw_on_the_runs_pause_budget` | F3: a copy shares the run's pause budget | -- | `copy_own_budget` |
| T15 `…relogins_draw_on_a_refilling_budget[100-raises, 300-200]` | M10, a resource-backed identity | DID NOT RAISE / no wait | `nobucket` |
| **(r3)** T15b `…no_resource_identity_whose_budget_is_spent_carries_on_at_once` | D | counts (30 logins) | `nores_waits` (sleeps, then raises), `nobucket` (30 logins) |
| **(r3)** TCP `…credential_posts_are_counted_and_the_json_control_too` | M10, F7: per account; **(p2)** a copy counts into its account, a peer is another | API absent | `nocount`, `copy_own_budget` |
| **(p2)** TD1 `…an_answer_on_a_session_known_lost_is_never_evidence` | D′ (Q1's shape): the guest cart is not comparable; the candidate ends inconclusive | -- | `nolostmark`, `oracle_ignores_lost` |
| **(p2)** TD2 `…a_resource_backed_identity_never_sends_on_a_lost_session` | D′'s other half: the base still re-logs in; the mark never fires | -- | `d_for_all` |
| **(p2)** TD3 `…layer_one_reads_any_answer_on_a_lost_session_as_not_comparable[×7]` | D′, layer 1: every class, a follow-up, a timing read timeout | -- | `oracle_ignores_lost` |
| **(p2, r5)** TD4 `…a_peer_replay_on_a_session_known_lost_is_never_evidence` | D′ through the peer's sender (blocker 1): a guest view and an open object both inconclusive | -- | `compared_skips_layer1` |
| **(p2, r5)** `…the_live_waf_filter_never_reads_an_answer_on_a_lost_session` | D′ at the live filter (the round-4 pin, closed) | -- | `livefilter_reads_lost` |
| **(p2, r5)** `…the_blind_sqli_builder_never_admits_an_answer_on_a_lost_session` | D′ at the builder: no sample, no row, a lost 504 included (the round-4 pin, closed) | -- | `bsqli_nomark`, `bsqli_class_ignores_lost`, `bsqli_504_kept` |
| **(r5)** T14p `…policy_blocks_on_many_paths_and_headers_cost_one_check_per_window` | blocker 2: one check per window for 403s on 40 paths and headers; a loss shape keeps its rule | -- | `policy_cache_by_url` |
| **(r5)** TD5 `…entering_ds_window_is_logged_once_per_window_without_a_credential` | D's log line | -- | `no_window_log` |
| T21 `…verify_live_waits_out_an_unknown_and_then_reads_live` | M9 | no GET | `verifylive_false` |
| T21b `…verify_live_never_reads_the_cache` | M6 | pin | `verifylive_cache` |
| **(r3)** T21c `…inconclusive_verify_live_never_clears_a_sticky_unknown` | F2 (P3) | DID NOT RAISE | `verifylive_clears_sticky` (the next send goes out) |
| **(r3)** T21d `…verify_lives_waits_never_spend_the_runs_pause_budget` | F2 | no wait | `verifylive_budget` (the send raises) |
| THOP `…unapproved_redirect_from_the_resource_fails_fast_and_never_pauses` | ADOPT | DID NOT RAISE | `hop_pauses` |
| TROT `…health_check_never_kills_a_rotating_session` | ADOPT | counts | `noadopt` |
| T22 `…prepare_records_the_generation_it_applied` | generations | API absent | `nogenrecord` |
| T23 `…request_entry_names…is_total` | SP-16 | API absent | `noentrynames` |
| T10 `…policy_block_never_as_a_loss[403, 451]` | the predicate | 403: counts; 451: pin | `403`, `policy_loss` |
| T11 `…keeps_its_loss_signals_and_never_reads_a_throttle` | the predicate | pin | `throttle`, `content_rule_off` |
| **(r3)** T19 `…only_the_owner_decides_a_session_loss` + `…guard_catches_synthetic_offenders` | PA-0533(4) | 2 offenders (`observe`, `verify_live`) | whole package: **(p2)** green on the implementation; `observe_writes_valid` (observe invalidates by writing `valid` itself) fails it. Synthetic (now with `object.__setattr__` and a bound `__setattr__`, F6): `guard_noassign`, `guard_nosetattr`, `guard_nodunder`, `guard_nokeyword`, `guard_nocall`; each edits the guard with one branch off. |
| R6 `…seam_probe_carries_the_session_generation_it_was_sent_on` | R6 (strict xfail) | API absent | — (a residual's pin; fails on the implementation too) |
| T20 `tests/test_core_comparability.py::…but_the_owner` (three rows removed) | CC-CORE-0070 | Phase 2 | **(p2)** `403`, `policy_loss`, `throttle` (each restores a status literal in `detect_logout`) |

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
  `prepare` records it on the request (`core.http.Request.session_generation`) from the
  state it applied.
  - A signal from another generation is ignored.
  - An unstated one is read as the current generation.
- **The health check** (`check_health`) is one GET of the resource, carrying the
  session and sent with the seam's headers, with a 15 s timeout per hop.
  - **The walk.** Redirects are walked by hand inside the session's origins and the
    transport floor, stopping at a login redirect. An unapproved hop that is not one
    raises at once (fail fast).
  - **The verdict** (`health_verdict`), first match: **lost** for a stop at a login
    redirect; **inconclusive** for an answer SP-56 classes as incomplete, throttle or
    gateway, or a 407, before any refusal is matched; **lost** for a loss shape or the
    resource's recorded refusal (status or body); **live** for any other 2xx;
    **inconclusive** otherwise.
  - **Cookies.** A live answer's rotated value of one of the session's own cookies is
    adopted.
  - **Single flight.** Single-flight per (host, identity). The verdict is recorded
    before the lock is released, and a live verdict covers every signal **seen before
    its GET was sent**. After the GET, the verdict counts only for the state object it
    judged, if that object is still the current one and of the generation judged;
    otherwise it is stale and changes nothing. Each write compare-and-sets on that
    current state and generation.
- **The cache.** For `health_ttl_s` (30 s), a live verdict also covers later signals of
  the same generation and URL key, except from a request that carries a header the
  session does not own (`Content-Type` and `Content-Length` excepted). `verify_live`
  never reads it.
- **The stable protected resource** is recorded at login: a URL whose credentialed
  answer is live on that walk, and whose anonymous and corrupted answers agree as a
  refusal: lost; or the same non-2xx status below 500 that SP-56 classes as the
  application's answer or a policy block (never a throttle, gateway or 407), recorded;
  or the same stable body, recorded.
  - Candidates: a browser login's post-click GETs; the operator's base URL (every
    session kind); the post-login landing.
  - `adopt` may take one, with a refusal status held to the same rule.
- **Lost.** `_mark_lost` is the only writer of `valid = False`. It compare-and-sets on
  the current state and generation, so it never persists a replaced state. It persists
  the state, and tells the listeners only when the loss was seen on a send (not from a
  pause re-check, not from `verify_live`).
- **Pause.** An inconclusive check changes nothing.
  - **The wait.** The identity is paused (5 s doubling to 60 s; `Retry-After` up to
    60 s; one log line when it starts). `prepare` waits it out, then checks again.
  - **The bounds.** Past `max_pause_s` (300 s), or the run's `pause_budget_s` (600 s),
    `prepare` raises `SessionHealthUnknown` (a copy: `IsolatedHealthUnknown`). That is
    sticky: every later `prepare` raises at once until a check gives a definite answer.
  - **Whose budget.** One budget per run, shared by the run's manager and its isolated
    copies. A peer identity has its own manager and its own budget.
- **Re-login budget.** Loss-driven re-logins draw on a token bucket per (host,
  identity): a burst of 5, refilled at 1 per 120 s, drawn under the login lock.
  - With the bucket empty, an identity **with** a stable protected resource waits for a
    token within the pause bound and budget, holding no lock; otherwise it goes sticky
    unknown.
  - With the bucket empty, an identity **without** one skips the re-login and sends at
    once on the session it has: no wait, no `SessionHealthUnknown`, no abort. It logs in
    again when a token has refilled.
  - Credential POSTs are counted per account (`submitted`, `control`), the run's
    isolated copies included.
- **`verify_live`** is a fresh check:
  - live: True;
  - lost: False and invalid;
  - an unapproved hop: raises;
  - inconclusive: it waits on its own, bounded by `max_pause_s` per call and by its own
    run budget (never `prepare`'s, never the identity's pause), and checks again; still
    inconclusive, it returns True, logged once. It never sets or clears a sticky
    unknown.
- **Reported.** `health_report()` gives counts per class and outcome, `prepare`'s and
  `verify_live`'s waited seconds, re-logins drawn and skipped, and credential POSTs per
  account. It holds no URL, header value or body.
- **Residuals:** R1-R16 (§8).
- **Enforced by:** T1, T2, T2b, T2c, T3, T4, T6, T9, T11, T12, T13, T13b, T14, T15,
  T15b, T17, T18, T19, T21, T21c, T21d, the M7 tests (T M7, T M7b, T M7c, T M7d) (names
  in §6).

**Amended in place:**
- **FR-SESS-5.** The 401/403 list becomes "a credentialed 401, a redirect to the
  detected login, the login form reappearing, JWT `exp`; confirmed on the stable
  protected resource (FR-SESS-23); re-logins limited by a refilling budget, then the
  identity is unknown and the run fails loudly, or, with no resource, the identity
  carries on until the budget refills. A 403 is a policy answer."
- **FR-SESS-15 (Basic).** "…its logout signal is a credentialed 401, confirmed on its
  base URL."
- **FR-SESS-16.** Listeners are told once per valid → invalid transition, and only when
  the loss was seen on a send.
- **FR-SESS-17 (`verify_live`).** The FR-SESS-23 rules above.
- **FR-SESS-18 (residuals).** Privilege-gated login redirects are suspected losses:
  confirmed live with a resource, unconfirmed without.
- **NFR-SESS-single-flight.** "… and at most two health checks per (host, identity) for
  concurrent signals; a late answer from an earlier generation triggers neither."
- **FR-CORE-6 (CORE; B6, CC-CORE-0070).** After the FR-SESS-20 sentence on
  `session_decision`, add: "*(CC-CORE-0070, FR-SESS-23:)*
  `Request.session_generation: int | None = None` is a declared field beside
  `session_decision`: the session addon's `prepare` sets it to the generation of the
  session state it applied, and the addon's `observe` reads it to ignore an answer
  from another generation. The seam itself never reads or changes it."
  (`docs/components/02-core-library/requirements.md:35-39`; it lands with the field in
  Phase 2, so the living spec never names a field that does not exist.)

## 8. Residual limits (stated)

- **R1. A 403 on expiry with no resource.** An app that answers a lost session with
  403 is recovered only when a resource is known (M2, TP4). With none, its 403s change
  nothing, and its probes read as policy blocks (inconclusive at the oracle, never
  negative). DRF's documented 403 is not measured here.
- **R2. No resource.** A public base with no protected landing, an adopted session,
  ecommerce-api, PFF, `rotate_all`, and every JSON/bearer login without a browser
  probe (§1.4-1.7).
  - Loss shapes are unconfirmed losses: FR-SESS-18's privilege-redirect residual
    stays, bounded by the bucket, and then by D (R16).
  - 403s and submissions change nothing.
  - **A re-login during a throttle records no resource** (review round 4, follow-up 4):
    a throttled candidate is never admitted (B1) and a throttled credentialed arm is not
    LIVE, so a session that logs in while the app throttles has no resource. That
    session moves to this no-resource path (unconfirmed losses, the bucket, then D),
    until a later login records one.
- **R3. The TTL.** A live verdict covers same-URL loss shapes for `health_ttl_s`, and
  every policy block of its generation (round 5). A session that dies inside the window
  is found at the next loss shape from another URL, from a foreign-header request, or
  after the window. Its probes in between are auth failures (not comparable at the
  oracle) or policy blocks; an app that ends a session with a 403 everywhere (`forbid`)
  is found only after the window, at most `health_ttl_s` later.
- **R4. A moved, broken or throttled resource.** A 404 or 5xx is inconclusive, so it
  pauses and then goes sticky. A refusal status recorded as 404 (admitted: SP-56 calls it
  the application's) reads a deleted resource as LOST, which costs a re-login. A
  resource throttled at a **re-login** is not recorded: the new session has no resource
  and moves to R2's no-resource path (unconfirmed losses, the bucket, then D), not to
  the pause (review round 4, follow-up 4). A resource that turns 403 for a policy reason
  (a WAF blocking the health GET, an IP ban): with 403 recorded as its refusal status it
  reads LOST, a re-login per loss bounded by the bucket; without, it is inconclusive,
  pauses and goes sticky (round 5).
- **R5. The health GET is untraced and unbudgeted,** as the login handshake already is.
  It is counted in `health_report()`.
- **R6. A comparison that straddles a re-login is not detected** (strict xfail).
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
- **R12. The pause and the bucket's wait happen in the sending thread.** Parallel
  senders of one identity wait to the same deadline.
- **R13. Login cost.** Rule 2 or 3 costs up to 3 GETs per candidate at a login (6 with
  the byte rule), and each isolated copy pays its own.
- **R14. A rotating session id churns anyway** (measured, §1.5). The seam adopts no
  response cookie (BUG-0112's divergence), and login verification already rotates the
  id, so `rotate_all` records no resource. Its churn is bounded by the bucket and then
  by D: 6 logins in 30 probes, then a token per 120 s. Only the health check's own
  rotation is handled.
- **R15. Account lockout is not modelled** (no lab has a policy, so it is unmeasured).
  - Each loss-driven re-login is one submitted POST, limited by the bucket: at most
    5 + ⌊t / 120 s⌋ in t seconds per identity, copies included in the count.
  - Each JSON login adds one wrong-password control POST.
  - Both are counted per account.
- **R16 (D, D′). A no-resource identity may send probes on a dead session once its
  re-login budget is spent; their answers are never evidence.**
  - **The window.** After the burst (5 loss-driven re-logins), each further
    unconfirmed loss leaves the identity sending on the session it has until the next
    token: at most 120 s per token (`relogin_refill_s`). So at most 5 + ⌊t / 120 s⌋
    re-logins in t seconds, and a real expiry in the window is recovered at most 120 s
    after the bucket emptied.
  - **Measured** (§1.6): on `json` and on `rotate_all`, 24 of 30 probes were sent in
    the window, with 0 s asleep. On `json` the session was in fact live (scope 401s);
    on `rotate_all` it was dead.
  - **What the oracle makes of them (D′, the owner's decision after review round 4).**
    Revision 3 relied on SP-56: a credentialed 401 or a login redirect is an auth
    failure, which the oracle's controls do not admit. Review round 4's Q1 measured the
    gap: a dead session's **guest view** (200, `application`), a 404 or a non-login
    redirect is admitted, and a payload's answer is not a control at all. So every
    request sent in the window is marked (`Request.session_lost`), the seam sender
    carries the mark to the probe (`Probe.session_lost`), and layer 1
    (`require_observed`) raises `NotComparable` for any answer to it, whatever its class
    -- payloads, controls, baselines and replays alike. The candidate ends
    inconclusive, never a pass, a negative or a finding (TD1: Q1's guest cart). R7's
    200 login page is covered in the window too.
  - **Every consumer reads the mark** (review round 5): the oracle through any sender
    (the peer replay included, TD4), the live WAF filter (CC-MUT-0404) and the blind-SQLi
    builder (CC-FUZZ-0110). The auditor's and crawler's fetches use such answers for
    discovery only (a guest view can only hide a point).
  - **`verify_live` in the window.** The state is marked lost, so `verify_live`
    returns False at once, as it does today right after any loss. If an isolated copy
    logs in during the window, `_verify_main` trips the single-session breaker: the run
    stops making copies (fail closed, never a wrong verdict). D makes that window last
    up to 120 s instead of one send. Not measured; no FUZZ change.

- **R17. Laravel's 419 after an expiry** ("page expired", a CSRF token from the old
  session) is SP-56's `application` answer: no loss shape and no policy block, so it
  triggers nothing. Its expiry is found at the next loss shape (a login redirect). Not
  measured; no lab answers 419.
- **R18. RFC 6750's `401` with `WWW-Authenticate: Bearer error="insufficient_scope"`**
  is still a credentialed 401: with a resource it is checked (and found live), without
  one it is an unconfirmed loss (the bucket, then D), as `json`'s scope 401 is. Reading
  the error code would be a new signal rule; not done.
- **R19. Concurrent pause waiters.** Several sends of one identity that meet the same
  pause each sleep to its deadline and each re-check (one GET each, serialised by the
  health lock, `use_cache=False`), and each charges its own sleep to the run's budget.
  Low impact: the oracle sends one probe at a time.

## 9. Change-control entries (landed)

The drafts landed, updated to what was built, in each component's log:
- `03-session-manager/change-control.md` **CC-SESS-0029** (with the re-derived existing
  expectations, PA-0073(3));
- `02-core-library/change-control.md` **CC-CORE-0070** (`session_generation`,
  `session_lost`, three allowance rows);
- `07-fuzzing-harness-and-oracle/change-control.md` **CC-FUZZ-0107** (D′).

The bug record is `docs/bugs/BUG-0533-a-forbidden-answer-logged-the-session-in-again.md`
(recurrence review: PA-0007, PA-0113, PA-0122, PA-0134, PA-0529(3); the sweep).

## 10. Bookkeeping text (for the coordinator; this lane edits none of those files)

### 10.1 BUG-0533

Landed with the fix (§9).

### 10.2 PA-0533

**PA-0533** — Strengthens `PA-0007`, `PA-0113`, `PA-0122`, `PA-0134` and `PA-0529(3)`,
after BUG-0533: a 403 logged the session in again. Each earlier rule constrained one
signal, one reader or one send path; none constrained the state change, and PA-0134 bound
a session's evidence to its origin only.
1. **An identity's state changes only on evidence about that session.** SP-56
   classifies first: a throttle, gateway, 407 or incomplete answer never changes it, and
   is never recorded or matched as a resource's refusal. A loss shape, a credentialed
   policy block or a submission's loss shape triggers a check of the session's stable
   protected resource, and the resource's answer decides. Without a resource, only a
   non-submission loss shape counts, as an unconfirmed loss.
2. **Evidence is bound to the session it is about:** to its origins (PA-0134), to its
   generation and the state object judged, and to the time it was taken (a verdict
   covers only the signals seen before its request was sent). Every write
   compare-and-sets on the current state and that generation, and is atomic with every
   install: the invalidation's row and every install's row are written under one lock.
3. **Re-logins draw on a refilling budget.** With it spent, an identity with a resource
   waits within its bounds or goes sticky unknown; an identity without one carries on at
   once, never sleeping or aborting. An unknown identity pauses, then goes sticky; it
   never logs in or out on an inconclusive check.
4. **Enforced at the actor.** `_mark_lost` is the only writer of `valid = False`, and
   `detect_logout` is the one loss predicate: a whole-package AST guard, proven on
   synthetic offenders. The loss decisions leave SP-56's allowance list.
5. **An answer to a request sent on a session known to be lost is never evidence**
   (the owner's decision D′): the session layer marks the request, the sender carries
   the mark, and **every consumer reads it**: the oracle's layer 1, applied to every
   compared send whichever sender made it, reads any answer to it as not comparable,
   whatever its class; the live WAF filter never records it as an allow or a block; the
   blind-SQLi builder never takes it as a sample or a row. A consumer found not reading
   it is fixed in the same change, or pinned by a strict xfail naming its owner
   (`PA-0531(4)`). (from BUG-0533)
- Enforced by: tests/test_session_forbidden_answers.py::test_a_forbidden_answer_never_logs_in_and_checks_at_most_once, tests/test_session_forbidden_answers.py::test_a_throttled_answer_never_triggers_anything, tests/test_session_forbidden_answers.py::test_a_throttle_is_never_a_resources_refusal_status_nor_a_loss, tests/test_session_forbidden_answers.py::test_health_verdict_never_matches_a_throttle_gateway_407_or_incomplete_answer, tests/test_session_forbidden_answers.py::test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle, tests/test_session_forbidden_answers.py::test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in, tests/test_session_forbidden_answers.py::test_a_credential_submissions_answer_is_checked_never_an_unconfirmed_loss, tests/test_session_forbidden_answers.py::test_a_late_answer_from_an_earlier_session_is_ignored, tests/test_session_forbidden_answers.py::test_a_pause_found_for_an_older_generation_never_pauses_the_new_one, tests/test_session_forbidden_answers.py::test_a_pause_of_a_replaced_generation_never_delays_its_replacement, tests/test_session_forbidden_answers.py::test_a_lost_verdict_for_a_replaced_session_tells_no_listener_and_writes_no_row, tests/test_session_forbidden_answers.py::test_a_loss_seen_while_a_check_is_in_flight_is_still_acted_on, tests/test_session_forbidden_answers.py::test_verify_live_asked_about_a_session_replaced_while_it_checked_answers_live, tests/test_session_forbidden_answers.py::test_mark_lost_on_a_replaced_state_changes_nothing_and_writes_no_row, tests/test_session_forbidden_answers.py::test_an_adopt_between_the_checks_compare_and_the_mark_tells_no_listener, tests/test_session_forbidden_answers.py::test_a_slow_row_write_never_leaves_a_replaced_sessions_row_last, tests/test_session_forbidden_answers.py::test_an_unknown_session_is_sticky_and_costs_nothing_after, tests/test_session_forbidden_answers.py::test_relogins_draw_on_a_refilling_budget, tests/test_session_forbidden_answers.py::test_a_no_resource_identity_whose_budget_is_spent_carries_on_at_once, tests/test_session_forbidden_answers.py::test_an_answer_on_a_session_known_lost_is_never_evidence, tests/test_session_forbidden_answers.py::test_a_resource_backed_identity_never_sends_on_a_lost_session, tests/test_session_forbidden_answers.py::test_layer_one_reads_any_answer_on_a_lost_session_as_not_comparable, tests/test_session_forbidden_answers.py::test_a_peer_replay_on_a_session_known_lost_is_never_evidence, tests/test_session_forbidden_answers.py::test_the_live_waf_filter_never_reads_an_answer_on_a_lost_session, tests/test_session_forbidden_answers.py::test_the_blind_sqli_builder_never_admits_an_answer_on_a_lost_session, tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss, tests/test_session_forbidden_answers.py::test_the_loss_decision_guard_catches_synthetic_offenders, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner

**Which named tests enforce which rule** (rules (1)-(4), and rule (5)'s `nolostmark` and
`oracle_ignores_lost`, proven by the PA-0533 matrix at d79d846 (33/33); round 5's
reverts were not run, and each round-5 test was shown failing on f1d31dd in one
invocation):

| Rule | Named tests | Reverts that undo it (each must fail at least one named test) |
|---|---|---|
| (1) classification first, the check decides | T1, T3, T4; the throttle clause: T2, T11, T2b, T2c; T20 | `403`, `policy_loss`, `throttle`, `throttle_refusal`, `throttle_verdict`, `noconfirm`, `nosubmission`, `submission_ignored`, `noentrynames`, `policy_nocheck` |
| (2) bound to the session; compare-and-set, atomic with installs | T6; T M7b, T M7b2, T M7c, T M7e, T M7f, T M7h; the cover: T M7d; installs: T M7g | `nogen`, `nogenrecord`, `nocas`, `nomlcas`, `cas_both`, `cover_at_record`, `pause_anygen`, `persist_unlocked`, `install_unlocked` |
| (3) the budget, the pause, sticky | T13, T15, T15b, TD2 | `nobucket`, `nores_waits`, `d_for_all`, `nosticky`, `inconclusive_lost`, `inconclusive_live` |
| (4) the actor | T19 (whole package), T19's synthetic proof, T20 | `guard_noassign`, `guard_nosetattr`, `guard_nodunder`, `guard_nokeyword`, `guard_nocall`, `observe_writes_valid` |
| (5) an answer on a lost session is never evidence, at every consumer | TD1, TD3, TD4, the live filter's and the builder's tests | `nolostmark`, `oracle_ignores_lost`, `compared_skips_layer1`, `livefilter_reads_lost`, `bsqli_nomark`, `bsqli_class_ignores_lost`, `bsqli_504_kept` |

### 10.3 ERROR_LOG entry

```
## 2026-10-20 — session manager (a forbidden answer logged the session in again; BUG-0533, a recurrence of BUG-0134's and BUG-0113's class)
- **Symptom:** a 403 (and a scope 401, a privilege-gated login redirect, a password check's 401) invalidated the session and the next send logged in again: N such probes made N logins, each probe on a new session, the peer re-logging in on each denied replay; a late answer from an earlier session logged the current one out.
- **Root cause:** `detect_logout`'s `status in (401, 403)`, acted on by `observe` at once: a session-state change decided from one answer's surface feature, without positive evidence about that session or a binding to it.
- **Remediation:** one loss predicate through SP-56; a check of the session's stable protected resource, a policy block covered by any live verdict of its generation for the cache window; generations and compare-and-set on the current state, atomic with installs; a pause and sticky unknown; a refilling re-login budget, with decision D for an identity with no resource and D′ (an answer sent on a session known lost is never evidence: not comparable at the oracle through any sender, never an allow or block at the live WAF filter, never a sample or row at the blind-SQLi builder) (CC-SESS-0029, CC-CORE-0070, CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404); BUG-0533, PA-0533.
- **Status:** Fixed
```

### 10.4 CHANGELOG line

```
- **What:** a forbidden answer no longer logs the session in again: SP-56 classifies first, a suspected loss is confirmed on the session's stable protected resource and bound to its session generation and current state (compare-and-set, atomic with installs), re-logins draw on a refilling budget, an identity with no protected resource carries on when it is spent with every answer in that window ignored by every consumer (the oracle through any sender, the live WAF filter, the blind-SQLi builder; decisions D and D′), a WAF that blocks every probe costs one health check per cache window, and an unknown identity pauses, then fails loudly (AU-SESS403, audit defect 6; CC-SESS-0029, CC-CORE-0070, CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404; BUG-0533, PA-0533). **Why:** every 403, scope 401, privilege-gated login redirect or password check's 401 cost a login and a new session (10 probes, 10 logins), the peer re-logged in on each denied replay, and a late answer from an earlier session logged the current one out.
```

### 10.5 SHARED_PRIMITIVES

- **SP-16, amend the mechanism and owner cells:** "Is a URL a login URL (session and
  auth state); **is an answer a loss of the session the request carried**
  (`detect_logout`, through SP-56; called only by `SessionManager.observe` and
  `health_verdict`); a request's entry names (`request_entry_names`)". Owner: add
  `fuzzlab/session/detect.py::detect_logout` and `::request_entry_names`. Guards: add
  `tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss`,
  `tests/test_session_forbidden_answers.py::test_the_loss_decision_guard_catches_synthetic_offenders`.
  From: add PA-0533.
- **SP-56, amend the readers:** "... the blind-SQLi builder, the live WAF filter **and
  the session manager (`detect_logout`, `health_verdict`, the refusal admission
  `admitted_refusal`, `_verify_authenticated`)**". Before any class: the oracle's
  `require_observed` (in `_ObservedOnly` and in `ConfirmationStrategy._compared`), the
  live filter and the builder's `answer_class` read the lost-session mark (FR-FUZZ-65).
  From: add CC-SESS-0029, CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404.
- **New row: SP-61** (the coordinator's number):
  `| SP-61 | Is an identity's session live now: the health verdict of one answer, the check of the stable protected resource (single flight, the cover at the send, compare-and-set on the current state), the one invalidation and every install under one lock, and the choice of the stable protected resource | `fuzzlab/session/manager.py::SessionManager.check_health` (with `health_verdict`, `admitted_refusal`, `SessionManager._mark_lost`, `SessionManager._install`, `SessionManager._spa_probe`) | `tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss`, `tests/test_session_forbidden_answers.py::test_the_loss_decision_guard_catches_synthetic_offenders`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0533 (CC-SESS-0029) |`
  Note for the row: disco's defect-4 item may build on `health_verdict` (a known gap,
  not a consumer).

### 10.6 ARCHITECTURE

In §3 (Session manager), after "...`verify_live` re-checks the run's session
(CC-SESS-0018, FR-SESS-17).", add:

```
A forbidden answer is never, by itself, a lost session (FR-SESS-23, CC-SESS-0029,
BUG-0533): `observe` classifies an answer through SP-56 first, and a suspected loss is
confirmed by one health check of the session's stable protected resource (chosen at
login by one owner, `_spa_probe`), bound to the session's generation and current state
(`check_health`, `health_verdict`, `_mark_lost`; every install under the same lock).
Re-logins draw on a refilling budget; an unknown identity pauses, then fails loudly
(`SessionHealthUnknown`); an identity with no resource carries on when the budget is
spent, and every request it sends then is marked lost (`Request.session_lost`), whose
answer no consumer takes as evidence: the oracle (any sender), the live WAF filter and
the blind-SQLi builder (FR-FUZZ-65; CC-FUZZ-0107, CC-FUZZ-0110, CC-MUT-0404).
```

No new component or dependency.

## 11. Open questions

- **Q1.** R6's fix is small but needs a CC-FUZZ number. Assign one to bring it in, or keep R6
  with its strict xfail.
- **Q2.** Should `health_report()` appear in `auto`'s run metrics? That is a FUZZ change.
- **Q3.** The defaults: TTL 30 s; a burst of 5, refilled at 1 per 120 s; a 300 s pause
  bound; a 600 s run budget (and `verify_live`'s own 600 s).
- **Q4.** `audit_page`'s catch-all swallows `SessionHealthUnknown` page by page, cheaply
  because it is sticky. Should AUD re-raise `SessionAuthError` as a follow-up?
- **Q5.** A run with a peer has two pause budgets (one per identity's manager). Should
  one budget span both? That needs a FUZZ change in `auto_cli.py`.

## 12. Verification of revision 3 (Phase 1, on the prototype)

Every run below is on the committed tree **9609d95** (clean), one pytest at a time
under the host lock. The logs are in this lane's scratchpad,
`/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-sess403/`,
and are not committed. `final_r3.sh <worktree> f3e731f` there reproduces all of them in
order. `au-sess403-prototype/run_reverts.sh <worktree>` (at `fc57a9c`; the directory is
deleted in Phase 2) reproduces steps 4-5.

1. **The test module on the base, markers on** (`r3_final_base.log`): **17 passed, 53
   xfailed**.
2. **The base with `--runxfail`** (`r3_final_base_runxfail.log`): **53 failed, 17
   passed**. 43 fail on a count or a behaviour and 10 on an absent API, as §1.9 lists.
3. **The collection check** (`collected_r3.txt`, `unnamed_r3.py`): 70 tests collected,
   68 named by a revert. The two unnamed are the stated ones: T19's whole-package
   assertion and R6's pin. No name in `run_reverts.sh` is unknown.
4. **The 50 reverts** (`reverts_r3_final.log`): **50 OK, 0 MASKED.** Every named test
   fails on its revert.
5. **The PA-0533 matrix** (B5; same log): **24 of 24 OK, 0 UNENFORCED.** Each revert
   that undoes a PA-0533 rule fails at least one test PA-0533 names:
   - rule (1): `403` 3, `policy_loss` 3, `throttle` 3 (T2 ×2, T11), `throttle_refusal`
     1 (T2b), `throttle_verdict` 6 (T2c), `noconfirm` 8, `nosubmission` 2,
     `submission_ignored` 2, `noentrynames` 1, `policy_nocheck` 3;
   - rule (2): `nogen` 2, `nogenrecord` 2, **`nocas` 2** (T M7b, T M7c; it failed none
     in the reviewer's matrix), `cover_at_record` 1 (T M7d);
   - rule (3): `nobucket` 3, `nores_waits` 1, `nosticky` 1, `inconclusive_lost` 1,
     `inconclusive_live` 1;
   - rule (4): each `guard_*` 1.
6. **The prototype as drafted** (same log): **68 passed, 2 failed**: T19's
   whole-package assertion and R6's pin (§1.9).
7. **Why each new or changed revert fails** (`reasons_r3_final.log`, `--tb=line`):

| Revert | Test | It fails on |
|---|---|---|
| `throttle_refusal` | T2b | the login recorded `('/', 429)` |
| `throttle_verdict` | T2c ×6 | `Health(state='lost', reason="the resource's refusal status (N)")` for 0, 429, 503, 502, 504 and 407 |
| `cover_at_record` | T M7d | `(True, [])`: the session stays valid and no listener hears the loss, while the server has ended it |
| `nocas` | T M7b | the next send on session 2 slept `[5.0]` |
| `nocas` | T M7c | the listener heard `['user']`, and a third row (session 1's, marked lost) was written over session 2's |
| `noflight` | T M7 | 6 GETs |
| `nores_waits` | T15b | `SessionHealthUnknown (re-login budget)` after the 120 s waits |
| `nobucket` | T15b | `(30, 30, [])`: 30 logins |
| `verifylive_clears_sticky` | T21c | DID NOT RAISE: the send after `verify_live` went out |
| `verifylive_budget` | T21d | `SessionHealthUnknown (pause budget)`: `verify_live` had spent 40 of `prepare`'s 50 s |
| `nocount` | TCP | `{}` |
| `guard_nodunder` | T19's synthetic proof | the offender list lacks the two `__setattr__` writes |

8. **D measured** (`measure_r3.log`, `measure_r3_proto.out`, `measure_r3_base.out`): §1.6.
   `json` and `rotate_all` each give 30 sends, 6 logins and **0 s asleep** with the
   design, against 12 sends, 600 s asleep and `SessionHealthUnknown` with revision 2's
   rule (`REVERT=nores_waits`).
9. **The harness** (`scripts/verify_change.py --base f3e731f` on 9609d95; `verify_r3.log`,
   `vc_r3/summary.json`):
   - 0 changed package files and 1 changed test file. It selected **67 test files**,
     this module included: **67 in one parallel pass, 0 serial**.
   - Result: **2827 passed, 0 failed, 0 errors, 1 skipped, 71 xfailed**, rc 0.
   - This module's 53 marked tests are among the 71 xfailed.
   - The one skip is `tests/test_packaging.py:179`, "bdist_wheel unavailable here
     (Debian setuptools bug)": the environment's, not this item's.

**Found and fixed during this revision's verification (before the commit).** T M7c's
"no row is written" half was vacuous under the prototype. `_manager` passed only the
keywords named in `SessionManager.__init__`'s signature, and the prototype's takes
`store` through `**kw`, so the store double was dropped and recorded nothing. `nocas`
still failed T M7c, but on the listener alone. `_manager` now passes every keyword to a
constructor that takes `**kwargs`. T M7c also asserts the double recorded the login's
and the adopt's rows before the check is released. `nocas` now fails it on both
halves (step 7).

## 13. Verification of the implementation (Phase 2)

Every run below is one pytest at a time under the host lock (BUG-0532). The scripts and
logs are in this lane's scratchpad,
`/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-sess403/impl/`,
and are not committed.

1. **The test module** on the implementation: **85 passed, 3 xfailed** (88 collected).
   The three are the stated pins: R6 (`_R6`) and D′'s two sweep pins (`_DPRIME_MUT`,
   `_DPRIME_BSQLI`), each failing for its stated reason with `--runxfail` (the live
   filter: DID NOT RAISE `FilterUnobserved`; the builder: `'application' !=
   'application'`). T19's whole-package assertion passes.
2. **Every named revert, re-proven on the implementation** (`reverts.py <repo> d79d846`,
   `reverts_d79d846.log`): each revert is a literal source edit of the real modules
   (or of T19's guard in the test module), applied in a detached worktree of the commit
   and reset after. **60 reverts, 60 OK, 0 MASKED**: every test named for a revert
   fails under it. They are revision 3's 50, with `nocas` split into `nocas` (the
   check's compare-and-set) and `nomlcas` (`_mark_lost`'s), plus `cas_both`,
   `pause_anygen`, `persist_unlocked`, `install_unlocked`, `copy_own_budget`,
   `d_for_all`, `nolostmark`, `oracle_ignores_lost` and `observe_writes_valid` (T19's
   whole-package assertion). The edit table is the script's `REVERTS`; every collected
   test is named by at least one revert except the three stated pins (checked by
   collection).
3. **The PA-0533 matrix on the implementation** (B5; each revert that undoes a PA-0533
   rule must fail at least one test PA-0533's Enforced-by line names, the whole set run
   each time): **33 of 33 OK, 0 UNENFORCED**. The first run stopped after 14 rows (the
   lane stopped its own runner; `reverts_d79d846.log`), and `matrix_rest.py` ran the
   other 19 on the same tree (`matrix_rest_d79d846.log`). PA-named tests failed per
   revert:
   - rule (1): `403` 4, `policy_loss` 4, `throttle` 4, `throttle_refusal` 1,
     `throttle_verdict` 6, `noconfirm` 11, `nosubmission` 2, `submission_ignored` 2,
     `noentrynames` 1, `policy_nocheck` 3;
   - rule (2): `nogen` 2, `nogenrecord` 2, `nocas` 2, `nomlcas` 2, `cas_both` 5,
     `cover_at_record` 1, `pause_anygen` 1, `persist_unlocked` 2, `install_unlocked` 2;
   - rule (3): `nobucket` 5, `nores_waits` 2, `d_for_all` 3, `nosticky` 1,
     `inconclusive_lost` 2, `inconclusive_live` 2;
   - rule (4): each `guard_*` 1, `observe_writes_valid` 5;
   - rule (5): `nolostmark` 1, `oracle_ignores_lost` 8.

   The same tree, no revert: 85 passed, 3 xfailed.
4. **The harness** (`scripts/verify_change.py --base 4ee8007 --wait-other 7200`):
   - on **6bb41bf** (the code, tests and docs before the merge of 01192c3): 6 changed
     package files, 7 changed test files; **157 test files, 157 in one parallel pass,
     0 serial; 4165 passed, 0 failed, 0 errors, 5 skipped, 25 xfailed**, rc 0
     (`vc_final/summary.json`). The skips are the environment's: `test_packaging.py:179`
     (bdist_wheel, Debian setuptools) and four live external-lab tests
     (`FUZZLAB_LIVE_EXTERNAL_LABS` unset). An earlier run on 6b41dd0 (before the pins)
     gave 4165 passed, 23 xfailed.
   - on **f1d31dd** (the same with 01192c3 merged: the harness queues on the host
     lock, BUG-0537): 6 changed package files, 8 changed test files; **157 test files,
     157 parallel, 0 serial; 4166 passed, 0 failed, 0 errors, 5 skipped, 25 xfailed**, rc
     0 (`vc_f1d31dd/summary.json`; the same five environment skips; the one more pass is
     01192c3's own test). `fuzzlab/` is identical on d79d846, 6bb41bf and f1d31dd.
5. **Why each new or changed revert fails** (`reasons.py`, `--tb=line`;
   `reasons_d79d846.log`, `reasons2_d79d846.log`):

| Revert | Test | It fails on |
|---|---|---|
| `nocas` | T M7b | the report: a stale verdict uncounted, a pause counted for the replaced session |
| `nocas` | T M7e | `verify_live` returned `[False]` for the session that replaced it |
| `nomlcas` | T M7f | a row (session 1's, invalid) written after the adopt's |
| `nomlcas` | T M7h | the listener heard `['user']` |
| `cas_both` | T M7c | a row written over session 2's (and the listener told) |
| `pause_anygen` | T M7b2 | `(200, [5.0], 1)`: the send on session 2 slept 5 s |
| `persist_unlocked`, `install_unlocked` | T M7g [relogin, adopt] | the rows end `[True, True, False]`: session 1's invalid row last |
| `copy_own_budget` | TCP | the run's account shows 1 submitted, not 2 |
| `copy_own_budget` | T13c | DID NOT RAISE: the run's pause resolved on its own budget |
| `nolostmark` | TD1 | no probe carries the mark |
| `oracle_ignores_lost` | TD1, TD3 ×7 | DID NOT RAISE `NotComparable` |
| `d_for_all` | TD2 | `(3, [])`: 3 logins, no wait: the fourth probe went out on the lost session |
| `observe_writes_valid` | T19 | `observe writes valid=non-constant` |

6. **Q1 before and after D′** (`q1/test_q1_before_after.py`, `q1/run_q1.sh`,
   `q1/q1.log`; the reviewer's guest-view JSON app: seven bounces, one cart probe, then
   the oracle with ReflectedXss on the cart):

| Code | Logins | The cart probe | SP-56 class | Layer 1 | Oracle |
|---|---|---|---|---|---|
| the base (fc57a9c, no prototype) | 7 | 200 `{"items":["book"]}` (a live session: every bounce re-logged in) | application | admitted | negative (a real observation) |
| revision 3's prototype | 6 | 200 `{"items":[]}`, the **guest view**, in D's window | application | admitted | **negative** (the false negative Q1 measured) |
| the implementation (D′) | 6 | 200 `{"items":[]}`, the guest view, `session_lost=True` | application | **NotComparable** ("sent on a lost session") | **inconclusive** (`not-comparable`) |

   Layer 2 (`require_comparable`) alone still classes the guest view `application`; in
   the oracle every send reaches layer 1 first (`_ObservedOnly`), which refuses it.
7. **The changed files** (`git diff --numstat 4ee8007 f1d31dd -- fuzzlab`):
   `session/manager.py` +899/-155, `session/detect.py` +71/-10, `oracle/probe.py`
   +20/-1, `core/http.py` +10, `session/state.py` +9, `tools/probesender.py` +4/-1
   (docstrings included).
