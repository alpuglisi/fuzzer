# BUG-0008 — Login "success" inferred from an anonymous session cookie (any credentials accepted)

- Date: 2026-09-21
- Status: fixed
- Severity: high (auth correctness — silent wrong-identity runs)

## Description
`SessionManager._login` treated the **presence of a session cookie** as proof that a
login succeeded. The lab (like any PHP app) calls `session_start()` on every page
(`includes/functions.php`), so the login-handshake fetcher's cookie jar already holds
an anonymous `PHPSESSID` after `_discover_login_form`'s initial GET — **before any
credentials are submitted**. On a *failed* login the app re-renders the login form
(HTTP 200, password field present) and sets no `$_SESSION['user_id']`, but:

1. `detect_session_credential(..., cookies=fetcher.cookies())` returned a `cookie`
   credential because *a* cookie existed (the anonymous one), regardless of outcome.
2. `_verify_authenticated` then probed `base_url` — the **public homepage** — which is
   never a login page whether or not you are authenticated, so it returned `True`.

Net effect: **any username/password combination "authenticated" successfully.** The
tool reported `Cookie: PHPSESSID=...` and the crawler logged "authenticated as admin
(1 cookie(s))" for a nonexistent user and for mismatched identities.

## Where encountered
Live on the host (`broken_auth.txt`): three runs of
`fuzzlab session set-credential ... && fuzzlab session print --identity admin` +
`fuzzlab crawl --identity admin`, with (a) `notreal`/wrong password, (b) `notreal`/`admin`,
(c) `admin`/`admin` — all printed a `PHPSESSID` cookie and all crawled "authenticated as
admin". The user reported: "It seems I am able to authenticate with any combination of
credentials."

## What it was NOT
This is **not** the lab's intended authentication-bypass vulnerability. `login.php`
correctly rejects plain wrong credentials (re-renders the form, sets no session user).
The lab's real auth bypass is via **SQL injection in the username field**
(`username: admin' -- -`), a separate, documented, intended lab vuln that plain wrong
credentials do not trigger. The false "authenticated" here is entirely a toolkit
false-positive and would occur against a perfectly secure app too.

## What it caused to fail
- `fuzzlab session print`/`crawl`/`auto --identity admin` ran as an **anonymous**
  session while believing (and logging) that they were authenticated as `admin`.
- Authenticated-only attack surface was never actually exercised under the intended
  identity; wrong credentials produced no error, violating the component's stated
  contract ("fail loud … never a silent unauthenticated run", FR-SESS-6).

## Root cause analysis
Five Whys:
1. Why did any credentials authenticate? `_login` accepted a session cookie as proof of
   login success.
2. Why was the cookie present on failure? PHP's `session_start()` issues an anonymous
   `PHPSESSID` on the first GET, so the jar was non-empty before login.
3. Why didn't verification catch it? `_verify_authenticated` probed `base_url`, a public
   page that is never a login page, so it always confirmed.
4. Why was cookie-presence used as the signal at all? The success decision conflated
   "a credential of some kind exists" (what `detect_session_credential` reports) with
   "the login succeeded" (a differential judgment the login response carries).
5. Why wasn't it caught in tests? `CookieLoginFetcher` set its cookie **only inside a
   successful `post()`**, so the jar was empty on failure — the fixture never modeled
   the real server's pre-login anonymous cookie, and the dead-wrong success path looked
   correct.

**Root cause:** authentication success was inferred from the presence of an *ambient*
credential (a cookie the server hands to anonymous users too) instead of from a
*positive differential signal* that the login response left the login page behind; the
test fixture omitted the real-world pre-login cookie, so the gap was invisible until a
live run.

## Corrective action
- `SessionManager._login` now rejects a login whose POST response is still a login page
  (`detect.is_login_page(resp.text)`) or answers `401/403`, **before** inspecting
  cookies. Cookie presence is no longer sufficient. On the lab this fails loud on wrong
  credentials (form re-rendered) and still succeeds on correct ones (redirect to
  `profile.php`, no password field). (CC-SESS-0008)
- `_verify_authenticated`'s docstring corrected to describe it as a secondary sanity
  check (it probes `base_url`, often public) — the primary success decision now lives in
  the POST-response check above.
- Regression tests: `AnonCookieLoginFetcher` models `session_start()` (anonymous cookie
  set on the first GET); `test_anon_cookie_does_not_mask_failed_login` asserts a wrong
  password fails loud despite the cookie, and `test_anon_cookie_still_allows_real_login`
  asserts correct credentials still authenticate.
- Sweep (PA-0002): the only auth-success decision in the codebase is the session
  manager's; the crawler (`spider.py`) and auditor (`fetcher.py`) obtain cookies via
  `manager.ensure(...)`, so they now inherit the fail-loud behavior and no longer log
  "authenticated as <id>" with an anonymous cookie.

## Preventive action
PA-0007 (see `docs/PREVENTIVE_ACTIONS.md`): never infer authentication (or
authorization) success from the mere presence of an ambient credential the server also
issues to anonymous users (a session cookie, an ambient token). Require a positive
differential signal that the protected action succeeded (left the login page, a
`2xx` on a page that is `401/403` when anonymous, an identity-specific marker).

Also a recurrence of PA-0006: the test fixture did not reproduce what the real upstream
produces (here, the server's pre-login anonymous cookie), so a broken path looked
healthy. Fixtures for auth/detection code must model the real server's ambient state,
not only the happy path.
