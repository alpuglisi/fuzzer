# BUG-0112 — Authenticated fuzzing never excluded auth endpoints (NFR-FUZZ-safe)

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0060, CC-CORE-0038)
- Severity: medium-high. An authenticated run could log itself out, or re-authenticate
  as another identity, mid-run. Later probes then ran as the wrong identity with no
  signal, and a crawl-sourced run probed destructive endpoints.

## Description
NFR-FUZZ-safe says "auth endpoints excluded from scope":
- `SessionManager` recorded the login form action, the login page and a guessed logout
  URL in `_auth_endpoints`, and exposed `is_auth_endpoint(url)`, but no code outside
  the tests called it;
- `run_auto` and `greybox-run` fuzzed every crawl point, `login.php` and `logout.php`
  included, with the session attached;
- greybox's requests session also kept cookies set by probe responses, so a payload
  that logged in planted another identity for later probes.

## Where encountered
The same preparation as BUG-0111 (the operator's loopback bWAPP), found while tracing
how an authenticated `fuzzlab auto --points crawl` would build its points.

## What it caused to fail
- NFR-FUZZ-safe;
- FR-SESS-5 (the session the run relies on);
- the identity attribution of every later finding in the run.

## What the bug was identified to be
The exclusion data existed, but the action it guards (sending a probe) never consulted
it.

## Root cause analysis
1. *Why fuzz login and logout with the session?* No sender or point builder asked
   `is_auth_endpoint`.
2. *Why unused?* T1.8 built the recording side ("record auth endpoints so fuzzing
   excludes them") and never the consuming side; its test checked only the recording.
3. *Why did nothing fail?* No test was tied to NFR-FUZZ-safe's clause.
4. *Why not seen?* Benchmarks run from ground truth and mostly anonymously.

**Root cause:** the same as BUG-0111. A safety NFR was not traced to the enforcing
action and a test that fails without it.

## Corrective action (CC-FUZZ-0060, FR-FUZZ-40)
- **Send-time gate:** `core.urls.check_send_url` is called first in every probe
  sender: Seam, Requests, greybox correlating, and blind-SQLi. A destructive URL is
  refused unless explicitly enumerated:
  - ground-truth points;
  - the `fuzz` tool's own `--url`.

  An AST guard (with a synthetic offender) requires the call.
- **Point selection:** `injection_points_from_store` leaves destructive crawl points out
  and reports them in `skipped_points`. This covers both `auto` and `greybox-run`.
- **Auth endpoints probed anonymously, from every source:**
  - `SeamProbeSender` logs in once before its first probe, then sends to an auth
    endpoint as `anonymous`. Its session is never attached or changed, and the count is
    recorded;
  - greybox drops its cookie for those URLs;
  - the requests-based senders clear their cookie jars per probe.
- **Tests:** in `tests/test_destructive_urls.py`:
  - each sender refuses `logout.php` and sends nothing;
  - the explicit allowance is honoured;
  - `login.php` is probed with no cookie, and the next probe still carries the session;
  - a failed login is a `SessionAuthError` before any probe;
  - destructive crawl points are skipped and reported;
  - ground-truth runs mark their points explicit;
  - the greybox cookie and jar behaviour;
  - the AST guard.

  The mutation check killed 31/31, together with BUG-0111.

## Recurrence review
The same as BUG-0111: the prior is BUG-0082/BUG-0084 and PA-0083(2). The analysis there
applies unchanged.

## Prior-preventive-action failure analysis
See BUG-0111. PA-0083(1) ("a safety gate sits at the action it guards") was itself
right. It was simply never applied to this NFR, because no mechanism surfaced the NFR as
unenforced.

## Preventive action
PA-0112 (shared with BUG-0111). Its guard now lists NFR-FUZZ-safe's enforced clauses and
names the open ones:
- the destructive-**payload** gate on auto/fuzz, which needs on-host benchmark
  verification;
- "no traffic off localhost", which conflicts with BUG-0050's authorized external
  targets and needs re-wording;
- untested CLI `--authorized`.

All three are reported to the operator.
