# BUG-0113 — Authenticated tools truncated the operator's URL to its origin

- Date: 2026-10-13
- Status: fixed (CC-SESS-0016, CC-CRAWL-0012, CC-AUD-0030, CC-FUZZ-0061)
- Severity: medium. No authenticated crawl, audit or `fuzz` was possible against an app
  served under a path, and `auto --base-url <path>` built wrong URLs. It failed loudly,
  not silently.

## Description
Three places reduced the operator's URL to `scheme://netloc`, or joined paths as if
the app lived at the root:
1. **`tools/spider.py`:** `_auth_base_url = f"{scheme}://{netloc}"`. Login discovery
   tried `/`, `/login`, `/login.php` at the origin root, never the app's own
   `/bWAPP/login.php`, and never the start URL itself, which redirects to the login.
2. **`session/manager.py::prepare`:** `ensure(host, identity, _base_url(request.url))`,
   origin only. This affects every seam request: the auditor with `--identity`,
   `fuzz --identity`, and re-authentication after expiry in any authenticated run.
3. **`harness/auto.py::injection_points_from_store`:** `base_url.rstrip("/") + path`,
   with absolute stored paths. `--base-url …/bWAPP/` gave `/bWAPP/bWAPP/x.php`.
   Greybox's `points_from_store` inherits it.

## Where encountered
Live, against the operator's self-hosted, loopback-only bWAPP
(`http://127.0.0.1:8090/bWAPP/`), immediately after BUG-0110..0112:
```
fuzzlab crawl --start http://127.0.0.1:8090/bWAPP/portal.php --identity user
```
failed with "no login form found from http://127.0.0.1:8090".

## What it caused to fail
- FR-CRAWL-5 (an authenticated crawl);
- FR-SESS-2 / FR-SESS-5 (`prepare` and re-login);
- FR-FUZZ crawl-sourced points.

## What the bug was identified to be
The base URL and the origin were conflated, which is true only for apps served at the
root.

## Root cause analysis
1. *Why no login form?* Discovery started at the origin root, which is not the app.
2. *Why the origin?* The code derived a "base" by truncation instead of keeping the
   operator's URL.
3. *Why did nothing catch it?* Every lab we generate serves its app at `/`, so base and
   origin were always equal in every test.
4. *Why only our labs?* Nothing required a test with a sub-path deployment.

**Root cause:** the same as BUG-0110. Behaviour was checked only against the shape of
our own labs.

## Corrective action
- **The spider** discovers from its start URL.
- **`SessionManager`:**
  - `ensure(..., operator=False)`. Operator entry points pass `operator=True`: the
    session CLI, greybox, `playwright_auth`, `SeamProbeSender`'s pre-login, and the
    auditor's and `fuzz`'s new pre-logins;
  - operator bases are remembered per `(host, identity)` for re-login. Only they are
    exempt from the destructive-URL check during discovery;
  - `prepare`'s fallback is the request URL's **directory**, with no query or
    fragment, so a probe or its payload is never replayed and a derived base is never
    exempt;
  - a Basic session records `login_url=None`, so logout is the 401/403 signal, never a
    redirect to an app page.
- **"Logged out" means *this session's* login form** (found in the live run, after
  review). With a path base, the post-login probe can land on an app page that has a
  password form of its own: bWAPP's `ldapi.php`, `sqli_3.php`, `xmli_1.php` and
  `xss_login.php`. The coarse "any password input" rule then failed the login, and
  `observe` read `password_change.php` as a logout. Now
  `detect.shows_login_form(html, page, login_url, login_fields)` is the test: a password
  form posting to the session's login action, **or** one whose entry names are exactly
  the login form's (the login form re-rendered in place, posting to itself, which the
  reviewers required so that such a logout is never missed). The entry names are kept
  in memory on the session. It is used by the login-response check, the
  verification probe, and `detect_logout` (with the page URL). A Basic session skips
  page-content checks in both `observe` and verification; with no known login URL, the coarse rule remains.
  `tests/test_session_persistence.py`'s logout fixture now posts to `/login.php`.
- **`playwright_auth`** scopes cookies to the origin root, as `path=/`.
- **The auditor and `fuzz`** log in from their operator URL before the first fetch.
- **Crawl points** join absolute paths to the base URL's origin.
- **Tests:** `tests/test_subpath_apps.py` (19), including a real-browser
  sibling-page cookie test. Two tests were added in the implementation review: a
  cached operator call, and a sender with no base. 11 of the 12 fail on the pre-fix code; the destructive
  derived-base test guards a path that is new with this fix. The mutation check
  killed 23/23 (assertions or tests were added after three survivors).
- **Verified live:** the authenticated bWAPP crawl logs in as `bee` and skips
  `reset.php` and `logout.php`.

## Known limitation (stated, not changed)
Sessions and remembered bases are keyed per `(host, identity)` (D12). Two sub-path apps
on one host:port (`/bWAPP/` and `/dvwa/`) share them: use a distinct identity per app.
Cookies are scoped to the origin root, so a cookie a server scoped to `/bWAPP/` also
reaches other paths on that origin.

Logout recognition has two accepted residuals (reviewer B):
- **A changed re-render.** A login form re-rendered with different controls (a captcha,
  an error field) falls back to the action match.
- **Sessions reloaded from the store.** `login_fields` is kept in memory, so such a
  session uses the action rule alone. Adopted sessions with no login URL keep the
  coarse rule.

## Recurrence review
- **BUG-0110 / PA-0111:** the same root cause. PA-0111 failed to prevent this because
  it was **too narrow**: it required fixtures per rule for *emulated algorithms*
  (form serialisation, redirects, cookies), not for *deployment layout* assumptions.
- **BUG-0050** (the crawler scope hardcoded to loopback) is related: an assumption true
  of our lab and false of real targets.

## Prior-preventive-action failure analysis
PA-0111 was scoped to code that emulates a named algorithm. Base-URL handling is not
an algorithm, so it was never in scope, and no rule asked for a sub-path fixture. Its
third-party-shape clause would have caught this, had it applied to layout.

## Preventive action
- **PA-0113** (strengthens PA-0111): a base URL is never truncated to its origin. In
  detail:
  - query and fragment are dropped when a URL becomes a discovery base;
  - stored absolute paths join to the origin;
  - a session cookie's scope is the origin root unless the server says otherwise;
  - every component that takes an operator URL has a test with the app under a
    sub-path.
- **Sweep:**
  - `pipeline.py:103`, `web/app.py:119`, `proxy/server.py`, `proxy/repeater.py` and
    `oob.py` are origin-semantic by design;
  - `points_from_ground_truth` uses app-relative paths by contract;
  - the greybox, mutation and oracle `app_root` values are filesystem paths;
  - the only other site, the browser-cookie URL, is fixed here.
