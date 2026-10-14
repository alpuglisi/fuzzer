# BUG-0122 — Any redirect containing "login" was read as a logout

- Date: 2026-10-14
- Status: fixed (CC-SESS-0019)
- Severity: medium. The failure was safe (nothing unsafe was sent), but it caused
  needless re-logins, false header-breaker trips, and lost header coverage.

## Description
`session/detect.detect_logout` treated a redirect as a logout when
`"login" in location.lower()`, or when the raw `login_url` text appeared in it. Both are
substring tests.

With the run's session, bWAPP's `ba_insecure_login.php` answers
`302 Location: ba_insecure_login_1.php`. That redirect was read as a logout, so:
- the run's session was marked invalid and logged in again;
- the logout listener fired, and the header breaker (FR-FUZZ-43) blamed the header
  probe just sent: "session bound to a probed header (User-Agent on
  /bWAPP/ba_insecure_login.php)";
- header probing stopped for the rest of the run, so the User-Agent and Referer XSS
  pages were never probed.

The `login_url in location` half never matched a relative `Location`.

## Where encountered
The first live bWAPP run of forms phase 2, on the integrated tree `d3ae108`: 47
findings, none lost against phase 1, but the run's header coverage was cut short.
Reproduced with curl against the sandbox.

## What it caused to fail
- the header breaker: false trips;
- session re-logins: wasted logins on every redirect to a URL containing "login";
- FR-FUZZ-43: its live effectiveness, since the header pages were not reached.

## What the bug was identified to be
A substring heuristic that decides session state from a URL.

## Root cause analysis
1. *Why was the redirect read as a logout?* The rule tested whether the text "login"
   appeared anywhere in `Location`.
2. *Why a substring test?* It predates the anchoring rule, and it was never revisited.
3. *Why did BUG-0113 not fix it?* BUG-0113 anchored only the content half of logout
   detection (`shows_login_form`) and left the redirect half as it was.
4. *Why did PA-0022 not prevent it?* PA-0022 (anchor keyword heuristics) was never
   enforced on session detection: there was no guard and no sweep. Its remedy, `\b`
   word boundaries, is also too weak for URLs. `\blogin\b` misses
   `ba_insecure_login_1` only because `_` is a word character, and it matches
   `ba-insecure-login.php`.

**Root cause:** rules that decide session or auth state from a URL were not required to
compare canonical URL keys or whole segments and tokens, and nothing enforced
anchoring.

## Corrective action (CC-SESS-0019)
`detect.redirect_is_logout(location, page_url, login_url)` resolves the `Location`
against the page URL. The redirect is a logout when either of these holds:
- **It is the session's own login URL** (`_same_login_url`): same host and path; an
  http→https upgrade on default ports is allowed; every query parameter of
  `login_url` is present with its value, so `index.php?page=login` routers work and
  extra parameters such as `next` are allowed.
- **It is any anchored login URL** (`looks_like_login_url`), kept even when a
  `login_url` is known (reviewer B):
  - the last non-empty path segment, lower-cased with its extension stripped, is
    `login`, `signin`, `sign_in`, `sign-in`, `log_in`, `log-in` or `logon`;
  - or, only when no `login_url` is known, that segment's final `name_tokens` token is
    `login`, `signin` or `logon` (`wp-login`, `user_login`). With a known one, bWAPP's
    `xss_login.php` and `ba_insecure_login.php` must not count (reviewer B);
  - or the path ends in `session(s)/new`;
  - or a front controller's routing parameter (`index.php?page=login.php`) names
    such a segment.

`ba_insecure_login_1.php`, `login_form.php` and `loginhistory` are not login URLs. The
401/403 rule and the anchored content rule are unchanged. Only a single hop is judged.

## Recurrence review
Two earlier bugs belong to the same class:
- **BUG-0020 → PA-0022:** keyword and substring heuristics must be anchored. That is
  the right rule, but it was never enforced on session or auth detection, and its `\b`
  remedy is too weak for URLs and identifiers.
- **BUG-0113:** it anchored the content half of logout detection only, which was too
  narrow.

An open defect of the same class is related: **BUG-0121**, unanchored *name* rules.
Ownership is split as follows:
- BUG-0122 owns the URL and `Location` rules;
- BUG-0121 owns the name rules: `_USERNAME_HINT` in `session/detect.py` (it picks the
  username field), the audit rules' name patterns, and `harness/auto`'s credential-name
  tokens, which are already token-anchored.

## Prior-preventive-action failure analysis
PA-0022 failed on three counts:
- **not enforced:** it had no guard and no sweep of `session/`;
- **wrong remedy for URLs:** `\b` is not an anchor for URLs or identifiers;
- **wrong layer:** it was written for hooks and lint rules, not for runtime
  session-state rules.

PA-0113 covered base URLs, not detection.

## Preventive action
**PA-0122** (strengthens PA-0022):
- rules that decide session or auth state, auth-endpoint membership or credential
  handling from a URL, a `Location` or a name compare canonical URL keys (with query
  parameters where a login is query-routed) or whole path segments and tokens, never
  substrings or `\b`;
- enforced by an AST guard over those modules, proven on a synthetic offender.

## PA-0002 sweep (by mechanism; pattern: AST `Compare(In/NotIn)` with a string-literal left side matching `login|logon|sign_?in|logout|sign_?out|auth|session|sso|passw|credential`, plus a grep for `re.compile` patterns of the same words)
| Site | Result | Disposition |
|---|---|---|
| `session/detect.py:215` redirect rule | instance | fixed |
| `session/detect.py:201` `"www-authenticate" in low` | exact header-key membership | cleared (mapping) |
| `session/manager.py` `"Authorization" in applied` | exact header-key membership | cleared (mapping) |
| `session/detect.py` `_USERNAME_HINT` (`user|email|login|…` regex) | unanchored *name* rule | owned by BUG-0121 (open) |
| `tools/probesender._identity_for` | `is_auth_endpoint` → `url_key` set membership | cleared |
| `harness/auto` credential and auth-endpoint names | `name_tokens` token sets | cleared |
| `tools/formnav`, `tools/navguard`, `tools/spider`, `core/urls` | token sets and `url_key`; no substring auth test | cleared |
| `tools/authhttp`, `tools/browserauth`, `session/state.py`, `session/cli.py` | none found | cleared |
| `tools/store_adapter.credential_change_reason` (`_CHANGE_SUBSTRINGS`, `sub in name.lower()`) | deliberate bare substring, exclusion-only | cleared: a documented PA-0022 "specifically intended" exception (a false match only excludes a form) |

The guard is `tests/test_logout_redirect.py::test_no_substring_test_decides_session_or_auth_state`.
It is proven on offenders in `test_the_guard_catches_a_synthetic_offender`. The oracle's
vulnerability detectors are out of scope by design.

## Residuals
- **A privilege-gated redirect to the real login page** (an admin-only page bouncing a
  valid user to `login.php`) still reads as a logout. A header probe on such a page
  trips the header breaker, which fails safe. Reviewer B proposed confirming with
  `verify_live` before the breaker trips; this is deferred and recorded on FR-FUZZ-43.
- **A page whose name ends in a login token** (`xss_login.php`) counts as a login URL
  only when the session's login URL is unknown. With a known one, only whole login
  segments count (reviewer B), checked against bWAPP's page names (PA-0022's vocabulary
  check).
- **Multi-hop logouts** (`/logout` → `/bye` → login) are judged on the first hop only,
  unless the final page shows the login form (the content rule).
- **The no-`login_url` fallback misses** `/auth`, `/sso`, IdP redirects, and routers
  whose parameter is not listed.
