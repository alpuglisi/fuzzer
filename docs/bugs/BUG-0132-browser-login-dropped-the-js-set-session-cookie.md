# BUG-0132 — A browser login handed the senders only the bearer, not the cookie its app set

- Date: 2026-10-14
- Status: fixed
- Severity: high (authenticated runs on a single-page app probed protected pages
  anonymously, with no error)

## Description
After a browser login (FR-SESS-19), the session manager's `SessionState` carried only
what `detect.detect_session_credential` found in the **login response**: for Juice
Shop, `Authorization: Bearer <jwt>` from the JSON body. Juice Shop's own JavaScript then
sets a `token` cookie (`document.cookie = 'token=' + jwt`) holding the same JWT. That
cookie is never in any response's `Set-Cookie`, so the manager never saw it, and the
requests-based senders (`prepare` through the `core/` seam) never sent it. The
browser crawl was fine: it adopts the login context's whole `storage_state`, cookies
included (FR-CRAWL-14).

## Where encountered
Live, on the operator's Juice Shop lab, with `fuzzlab auto --identity juice-user` after
the SPA-login merge (coordinator's verification, no token printed): the crawl reached
`/profile`, but the audit's probes of `/profile` (`username` → SSTI) and
`/profile/image/url` (`imageUrl` → SSRF) yielded 0 candidates and 0 attempts.

## What it caused to fail
Juice Shop's server-rendered `GET /profile` answers **500 with the bearer alone**, 200
with the `token` cookie alone, and 500 with neither. Every authenticated requests-based
send to a page that reads the cookie (the profile page and its image-URL form, both
in-class SSTI / SSRF targets behind login) was, in effect, unauthenticated. Nothing
failed loudly: the login itself was confirmed, because the protected probe (an API GET)
reads the bearer.

## What the bug was identified to be
`SessionManager._browser_login_state` built the session from the detected credential
only (`cookies=dict(detected.cookies)`, the cookies the login response set). The browser's
cookie jar, which the login context had already captured in `storage_state` (and kept on
`SessionState.browser_state` for the crawler), was not carried into `SessionState.cookies`.

## Root cause analysis
Five Whys:
1. *Why were the profile probes unauthenticated?* Their requests carried the bearer but
   not the `token` cookie that `/profile` reads.
2. *Why only the bearer?* The senders apply `SessionState.cookies` / `.headers`, and the
   browser login put only the detected credential there.
3. *Why only the detected credential?* FR-SESS-19 specified the credential as "detected
   from that request's response with the existing `detect_session_credential`": the
   server-rendered login's model, where the login response establishes the whole
   session. In a single-page app the session is completed **client-side, after** the
   response: the app's JS writes a cookie and localStorage that no response carries.
4. *Why did no test catch it?* The two consumers of one browser login were given
   different projections of it: the browser crawl the whole browser state, the
   requests senders a reduced one. Every fixture endpoint read only what the reduced
   projection kept (the bearer). The fixture's app did set the `token` cookie, but no
   endpoint read it, so the server side of the target's shape (an API that reads the
   header, pages that read the cookie) was half-modelled. The crawl test passed because
   the crawl has the full state.
5. *Why was a reduced projection acceptable at design time?* Handing a session from one
   client (the browser) to another (`requests`) was treated as "detect the credential",
   not as "carry over the client's session state". The browser sends its whole cookie
   jar for the host, script-set cookies included; the requests-based copy of the session
   emulated that browser behaviour by approximation (one response's credential), and the
   approximation was never checked against what the target's server actually reads.

**Root cause:** a session obtained in one client was handed to another as a lossy
projection derived from one response, instead of carrying over the client-side state the
first client holds for the host; and the fixture modelled what the target's login
writes, not what its server reads, so the loss was invisible.

## Corrective action
CC-SESS-0022 (and CC-CRAWL-0025 for the crawler's session check):
- `manager._jar_cookies`: the browser jar's cookies from the login's `storage_state`
  (already cleaned of the password by `browserlogin.drop_secret_values` and filtered to
  the login scope by `filter_storage_state`) whose domain matches the session's host,
  not expired, and not `secure` unless the session is https-only. They are merged into
  `SessionState.cookies` under the detected credential (`{**jar, **detected.cookies}`) and
  their names recorded in `SessionState.browser_cookies` (in memory). They then go
  through the session's one cookie path (`apply` / `prepare`: the session's host only,
  under its transport floor, FR-SESS-13). Re-login and isolated copies go through the
  same `_browser_login_state`.
- The FR-SESS-19 differential and `verify_live` replay `state.apply({})`, so they now
  carry the cookie too. `_corrupted` gives a cookie whose value equals the bearer token
  the **same** corrupted token (and every other credential cookie a random value; an
  ambient jar cookie such as a language choice keeps its value), so a corrupted request
  cannot stay authenticated through the cookie.
- `SessionManager.session_headers` (new) returns every header the session sends;
  `fuzzlab session print` prints each. `session_header` keeps its rule (the Cookie first),
  so for a browser login it now returns the cookie, and greybox gets it.
- The crawler's cookie check covers the session's credential cookies only
  (`BrowserSession.checked_cookies`): a jar cookie is the app's to change, like its
  localStorage (it is adopted through `storage_state` already).
- Tests (`tests/test_session_browser_login.py`): a fixture page `/profile` that answers 200
  only with the JS-set cookie, reached through the real seam (`HttpClient` with the
  manager) and through `session_headers` (it fails before the fix); the bearer alone
  gets 500; the cookie never reaches another host; host scope, expiry and `secure`;
  the corrupted arm; an API that reads only the cookie is confirmed and its revocation
  seen; re-login and an isolated copy carry their own cookie; no cookie value in repr,
  logs or the store.

## Recurrence review
Checked `docs/bugs/` (session, credential, cookie, browser-emulation and fixture bugs) and
`docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0110 / PA-0111** (the login form serialised unlike a browser): **same root-cause
  class.** A browser behaviour (there: building a form's entry list; here: which cookies
  a session carries, which a browser takes from its whole jar for the host, script-set
  ones included) emulated by approximation and checked only against fixtures that read
  what the approximation produced. PA-0111 names cookies among the behaviours it
  covers, and its clause 3 asks for a captured third-party target's shape.
- BUG-0008 / PA-0007 (login success from an ambient cookie): same detector, different
  cause (fail-open success inference). Not a recurrence; PA-0007's "reproduce the
  server's ambient state in fixtures" is related to clause 2 below.
- BUG-0007 / PA-0021 (credential host key derived differently by two paths): a cousin
  (two paths deriving one value differently); here two consumers got different
  projections of one session. Not the same defect.
- BUG-0098 / PA-0099 (an https session reused over http), BUG-0113 / PA-0113 (cookie
  scope and sub-paths), BUG-0123 / PA-0123 (browser scope, header confinement):
  constraints the fix respects (transport floor, host scope), different causes.
- FR-SESS-4 itself encodes the gap ("detect what the login response establishes").
Result: a recurrence of BUG-0110's root cause (PA-0111).

## Prior-preventive-action failure analysis
**BUG-0110 / PA-0111.** PA-0111 says code that emulates a browser behaviour "(form
submission, redirects, cookies, headers)" implements the named algorithm rule by rule,
with a rule table, a guard that every rule has a fixture, and at least one captured
third-party shape. It did not prevent this because:
1. **Wrong layer / too narrow in enforcement.** Its only mechanism, `core.forms.RULES`
   and its guard, covers form serialisation. Nothing enumerated the browser's
   session-state behaviours (which cookies go with a request) for the code that copies
   a session into another client, so "cookies" in PA-0111 had no enforcement.
2. **Not recognised as applying.** The browser login was designed as *detection*
   (FR-SESS-4/19: detect the credential), not as *emulation* of the browser's session,
   so PA-0111 was not read as covering it; the reviewers' checklist had no item for
   "does the requests-based copy carry everything the browser carries?".
3. **The third-party shape was captured from the client side only.** The fixture
   reproduced Juice Shop's login (JSON, JWT, `localStorage`, `document.cookie`) but not
   its server's reads (API: header; server-rendered pages: cookie), so clause 3 was met
   in letter, not in substance.
PA-0132 therefore moves the rule from "emulate an algorithm" to "carry the session",
names the handoff points, and makes fixtures model the server's reads per consumer.

## Preventive action
**PA-0132** (strengthens PA-0111 and PA-0006; see `docs/PREVENTIVE_ACTIONS.md`):
1. A session obtained in one client and used by another carries over all the session
   state the first client holds for the host, filtered by the scope, transport and
   secret rules. Never a projection derived from one response.
2. A session feature's fixture models what the target's server reads, per consumer, with
   a real-path test through each consumer (PA-0035).
3. The PA-0002 sweep lists every handoff point.

PA-0002 sweep (every place a session moves from one client to another; disposition):
- browser login → requests senders (`prepare`, the seam): **fixed** here.
- browser login → crawl browser (`browserauth.browser_session`, `storage_state`):
  complete (cookies and localStorage, in scope). Its cookie check now covers credential
  cookies only (CC-CRAWL-0025). Forms phase 4's `_readopt_session` re-adds both.
- crawl browser → selector-form API client (`spider._isolated_submit`,
  `storage_state=` of the live context): complete.
- browser login → auditor browser (`fetcher._start_browser`): cookies (the JS-set one
  included since this fix) and headers through the route, but **not localStorage**.
  **Not fixed here** (no AUD change number was assigned to this task); pinned by a strict
  xfail,
  `tests/test_session_browser_login.py::test_the_auditors_browser_adopts_a_browser_logins_local_storage`,
  and flagged to the coordinator.
- manual browser login → proxy capture → manager (`proxy.session_capture.adopt_into`):
  complete (built from the Cookie headers the browser actually sent).
- session → `fuzzlab session print` (`session/cli.py`): printed one header; now prints
  every header (`session_headers`).
- session → greybox (`greybox_cli`, `session_header`): carries a Cookie only, by design
  (greybox's targets are the generated labs, cookie sessions). It now receives the
  JS-set cookie; a bearer is not carried. This is pre-existing, recorded, and not in this
  class's reach for greybox's targets.
- session → M6 executor (`browserexec` `storage_headers`): no caller passes a session.
