# BUG-0559 — A browser context carrying a session sent a load's redirect hop, a form's submission and the page's own jumps to a host its cookies do not reach, and filed the anonymous landing as the identity's

- Date: 2026-10-22
- Status: fixed
- Severity: high

## Description
In an identity crawl with the browser engine (`engine='playwright'`), the legacy spider
checked whether the session's cookies reach a load's host only where the load starts
(`LocalSpider._session_host_refusal`, BUG-0545 review round 2). Every request made after
that point went out by the guard's own rule, which decides where a session may go by
**origin** (`cookie_scope` = `browserauth.header_scope_for` → `core.urls.in_origin_scope`),
and an origin folds the loopback aliases `localhost`, `127.0.0.1` and `[::1]` into one.
The browser sends a cookie by **host** (RFC 6265): a session cookie held host-only for
`127.0.0.1` never goes to `localhost`. So a redirect hop inside a load, a selector form's
submission (`_isolated_submit`'s browser branch, an API request) and a navigation the page
made itself (`location.replace`, a meta refresh) to such an alias went out without the
session, to what the crawl takes for the session's own origin, and the anonymous answer
(the app's login redirect) was filed as the identity's page -- `visited`, final, never
loaded again on resume. A subresource (an image, a `fetch`) went the same way. The
auditor's browser fetcher (`tools/fetcher.py`) and disco's explorer (`disco/explore.py`)
adopt a session the same way and had no reach check at all.

## Where encountered
- BUG-0545 review round 2's residual **R8** (CC-CRAWL-0056), measured by the SPIDER lane
  on its own fix (`scratchpad/lanes/SPIDER/r2/browser_hops.out`: the alias received
  `GET /pick?bug=1`, `?bug=2` and `GET /land` twice with no Cookie) and flagged instead of
  fixed: "the hop walk is `navguard`'s, a shared primitive's owner; this round's scope is
  the load gate".
- The round-2 adversarial check of S2-1 (`tasks/w2c89udnx.output`: "S2-1 is not fixed"):
  the redirect hop, the selector form, and a third path the lane's sweep did not list --
  client-side navigation (JS `location`, meta refresh) -- each sent the alias a protected
  request with `Cookie: ''`, followed it to an anonymous `/login`, and stored the result
  `(200, 'visited', '')` under the 127.0.0.1 URL and as `localhost/login`.
- The audit remediation's Gap 3 (item GAP-BROWSER), which assigned the fix to the owner.

## What it caused to fail
Measured on 7393c90 (one pytest invocation of `tests/test_browser_session_reach.py` with
7393c90's `navguard.py`, `spider.py`, `fetcher.py`, `disco/explore.py` and
`disco/cli.py` in place, then restored; `scratchpad/lanes/BROWSERALIAS/proof.log`:
10 failed, 1 passed):
- **Redirect hop** (`/go` → 302 → `http://localhost:PORT/secret?x=land`): the alias got
  `GET /secret?x=land` and two anonymous `GET /login` (3 requests, `Cookie ''`).
- **Selector form** (a GET form whose action is `http://localhost:PORT/pick`): the alias
  got `GET /pick?bug=1` and `GET /pick?bug=2` with no cookie.
- **A page's own jump**, `location.replace` and a meta refresh, with an image and a
  `fetch` to the alias on the same page: the alias got `/pixel.png`, `/data`,
  `/secret?via=...` and the anonymous `/login` (5 requests each).
- **The auditor's fetcher**: the alias got 9 requests (the direct page, the hop's
  landing, the page's jump, and the login redirects); `/go` was audited as the login
  page.
- **disco** (a storage state holding `sid` host-only for 127.0.0.1): the alias got 7
  requests with no cookie, and the explorer read the alias's anonymous answer as "the
  session was lost (a 302 redirect to a login page)" and **ended the authenticated
  exploration** -- an identity run cut short by its own anonymous request.
- The AST wiring guard found 4 offenders (the spider's, the fetcher's and disco's
  `guard_page` without the session's cookies, and the spider's form submission).
The three unit tests of the new API fail with `AttributeError` / `TypeError` (the
predicate was the spider's private `_cookie_reaches`; the route had no such parameter).

## What the bug was identified to be
- **A per-load check for a per-request carrier.** The reach of a cookie session was
  checked once, for the URL a load starts at, in one consumer. The browser sends a
  load's redirect hops, the page's own navigations, its subresources and the crawler's
  API submissions as separate requests, and each passes navguard's route (or
  `checked_api_request`) -- never `_visit`.
- **The route's session rule was an origin rule.** `make_route_handler`'s `cookie_scope`
  admits an in-scope request on the session's origins; the origins fold loopback
  aliases (correct for scope, BUG-0123, and for a header the route itself adds), so a
  host the cookie never reaches passed as the session's own.
- **The predicate lived in a consumer.** `_cookie_reaches` was born private in
  `tools/spider.py`; the fetcher and disco, which adopt the same `BrowserSession` shape,
  never had it, and SHARED_PRIMITIVES had no row for it.

## Root cause analysis
Five Whys:
1. *Why did the alias receive the hop, the submission and the jump without a cookie?*
   The only check that compared a cookie's domain with a host was `_visit`'s gate, at
   the start of a load; each of these requests is made after that point, and the guard
   that sees them (navguard's route; `checked_api_request` for the API submission)
   decided by origin.
2. *Why was the check at the start of a load?* BUG-0545's round 2 fixed R6 at "the one
   gate every load passes" (PA-0545(5)/(7)): its unit was the *load*. The browser's unit
   of sending is the *request*, and the one place every request passes is the guard's
   route, a shared primitive's owner (SP-01/02/38) outside the lane's file scope, so the
   lane measured the hop and the form and left them as residual R8.
3. *Why did the route's own rule not stop them?* It answers "may the session go there?"
   by origin (PA-0134(1): one predicate, `SessionState.origins`), which is right for a
   header the route adds itself, and wrong for a cookie, which the browser sends by
   host. One predicate served two carriers with different units.
4. *Why did the fetcher and disco have the same hole?* The reach predicate was written
   as a private helper of the consumer that met the defect first, not in the owner of
   the guard, with no SHARED_PRIMITIVES row; BUG-0545's sweep listed the other contexts
   "code read, not measured, not changed (other components)".
5. *Why was a consumer-side fix with a same-class residual accepted?* The round's brief
   fixed its scope to the load gate ("do not touch anything else"), and PA-0545(1)'s
   "never a residual left to another component" was read as a rule about send paths of
   the spider, not about the carrier's owner; the merge took R8 as a stated residual.

**Root cause:** where a cookie session reaches was decided per consumer, per load, by a
private spider predicate, while a browser sends per request and every request of a
guarded context passes one owner -- navguard's route and `checked_api_request` -- that
decided session reach by origin only. No shared primitive owned "does this request of
this context carry the session's cookies", so every guarded context that adopts a
session (the spider's, the auditor's, disco's) let an alias of the session's origin
through, and each tool filed the anonymous answer as the identity's.

## Corrective action
Commit ae73950 on `lane/BROWSERALIAS` (CC-CRAWL-0063 navguard and the spider,
CC-CRAWL-0064 disco, CC-AUD-0060 the auditor's fetcher; FR-CRAWL-43 new, FR-CRAWL-34
amended; SP-74):
- **The owner** (`fuzzlab/tools/navguard.py`): `cookie_reaches` (moved from the spider;
  RFC 6265 domain match), `held_session_cookies` (the session's cookies as a context
  that adopted them holds them), `unreached_session_cookies`, `session_host_refusal`
  (None for no session cookie and for an origin `cookie_scope` puts outside the
  session's: FR-SESS-20 keeps that one) and `SessionHostUnreached`.
  `make_route_handler` / `guard_page` take `session_cookies` and `on_session_unreached`:
  a request to such a host -- a navigation (top-level or frame), each redirect hop, a
  subresource -- is aborted right after the scope and destructive checks, before
  anything is fetched (a document with `ERR_ABORTED`, SP-02), and the hook is told
  `(url, kind, source, reason)`; `make_ws_handler` never connects such a socket;
  `checked_api_request(session_cookies=, cookie_scope=)` raises `SessionHostUnreached`.
- **The spider**: its gate asks the owner (`_session_cookies`); its guard passes the
  cookies; `_note_session_unreached` counts `session_host_unserved`, marks a load whose
  own target or redirect landing was refused (`_unreached_targets`, keyed by `url_key`
  and the host, since `url_key` folds aliases), so `_fetch_rendered` raises
  `HostNotServed` (stored `failed`, no static fallback), and queues a page's own refused
  jump for the gate; `_isolated_submit` passes the cookies to `checked_api_request` and
  turns a refusal into `HostNotServed` (counted, the form's enumeration stops).
- **The auditor's fetcher**: passes the cookies to its guard, refuses a page on such a
  host before navigating and a load whose hop was refused (no page, no static fallback),
  counts `session_host_unreached` by host.
- **disco**: `_SessionMaterial.session_cookies()` (a provider's credential cookies; a
  storage state's every cookie) passed to the context's guard; refusals counted in
  `ExploreReport.session_host_unreached` (explore.json), printed by `disco capture`.
- Measured before the design (`scratchpad/lanes/BROWSERALIAS/measure/reach.out`,
  Chromium 141): a cookie added by URL or by the bare domain `127.0.0.1` is sent to
  `127.0.0.1` and not to `localhost` on the same port, by the page and by an API request
  context built from the context's storage state; a dotted `.127.0.0.1` is held as host
  `127.0.0.1`; the route sees `location.replace` and a meta refresh as document
  navigations of the main frame.

**PA-0002 sweep, by primitive** -- every caller of `guard_page` / `make_route_handler` /
`checked_api_request` in `fuzzlab/`, with its disposition:
- `tools/spider.py::_guard` (the crawl context, authenticated): passes the cookies --
  refused, measured (the redirect, form and jump tests). Its unauthenticated contexts
  (`_submit_anonymously`, `_dry_submit_anonymously`) carry no session (`session=False`:
  nothing passed, nothing withheld).
- `tools/spider.py::_isolated_submit` (API): passes the cookies -- refused, measured.
- `tools/fetcher.py::_start_browser` (the auditor): passes the cookies -- refused,
  measured.
- `disco/explore.py::_new_context` (storage state or provider): passes the cookies --
  refused, measured (storage state). `disco/explore.py::_protected_get` (API, a storage
  state): its URL is a page the guarded context committed (`_find_protected_resource`),
  which the route now refuses on an unreached host, or it carries no session; exempt in
  the wiring guard with that reason.
- `disco/ede.py` (no storage state, no cookies), `tools/browserexec.py` (the M6
  executor: headers through the route only, no cookie; its API calls likewise),
  `session/browserlogin.py` (the login's own context: it adopts no session, it makes
  one): carry no session cookie -- shown by the wiring guard (none of them adopts one).
- A WebSocket of a guarded context: `make_ws_handler` refuses it (unit test).
The wiring rule is held for every future module by an AST guard
(`test_every_context_that_adopts_a_session_hands_its_cookies_to_the_guard`, proven on
synthetic offenders).

**Not this carrier, flagged (code read, not measured, not changed):**
- *The auditor's static engine* (`ContentFetcher._static_fetch` through the seam built
  by `tools/authhttp.make_auth`) carries the session through the session manager, not a
  cookie jar: its reach is the manager's `prepare`. With the CLI's default manager scope
  (`localhost` and `127.0.0.1`) the seam sends the session's cookie header to the alias
  (measured for the spider's seam by BUG-0545 round 2); with a scope that omits the
  alias, `prepare` applies nothing and the request would go anonymously. The spider
  refuses that case before the transport (`_SessionAddon`, BUG-0545 R6); the auditor's
  seam has no such addon. Owner: AUD / SESS (`make_auth`), for the orchestrator.
- *disco's new `explore.session_host_unreached` key* is not traced as a diagram event
  (FR-AUD-29 traces `out_of_scope` only; `tools/observe.py`). Additive; the refusals
  are in `explore.json` and the capture summary.
- *A session carried only in browser storage* (a `localStorage` token, no credential
  cookie): storage is per origin (scheme, host, port), so an alias page's script reads
  none of it and the page could render anonymous. Not a cookie, so SP-74 refuses nothing
  there (no session cookie: no refusal). Same class on another carrier; not measured.
  For the orchestrator (owner: navguard, a storage-origin reach beside SP-74).

## Recurrence review
Checked `docs/bugs/` (BUG-0123, BUG-0132, BUG-0134, BUG-0136, BUG-0138, BUG-0545) and
`docs/PREVENTIVE_ACTIONS.md` (PA-0123, PA-0132, PA-0134, PA-0138, PA-0545):
- **BUG-0545 R6 / review round 2 S2-1** -- the same bug: an identity load to a loopback
  alias of the session's origin sent without the session and filed as the identity's.
  Round 2 fixed the load's start (the gate) and left the requests inside the load (R8).
  **Match: a recurrence on a neighbouring path of the same carrier.**
- **BUG-0134 / PA-0134** -- the same root class (where a session goes, decided by one
  predicate at every send path), with the opposite failure: there the session went too
  far (another port); here the decision admitted a host the session's cookies do not
  reach. **Match (same root: the unit of the predicate).**
- **BUG-0123 / PA-0123(1)** (every request checked where it is made; the route walks
  each hop) -- the mechanism this fix uses; not a recurrence of it.
- **BUG-0138 / PA-0138(3)** and SHARED_PRIMITIVES rule 2 (a primitive's fix in its owner,
  swept to every caller) -- the reach predicate was a new mechanism two components must
  agree on, written in a consumer. **Match (the failure mode of the fix, not the bug).**

## Prior-preventive-action failure analysis
- **PA-0545(7) (BUG-0545 round 2): wrong layer.** It put the decision "at the one gate
  every load passes", and a browser load is many requests. The rule named the gate
  where a load starts as the place; the place every request passes is the guard's route.
- **PA-0545(1) (BUG-0545): not followed.** It says "'sends anonymously' is never a
  disposition, nor a residual left to another component", and R8 was exactly that: a
  measured anonymous send, flagged to the owner and merged as a residual. The rule had
  no enforcement for paths outside the lane's files (its tests cover the spider), and a
  brief's file scope overrode it in practice.
- **PA-0134(1) (BUG-0134): one predicate, the wrong unit for one carrier** (already
  noted by BUG-0545 round 2 for the gate). Its fix there was a second predicate in a
  consumer, not a carrier-aware decision in the owner, so the route kept the origin
  rule for cookies.
- **PA-0138(3) / SHARED_PRIMITIVES rule 2: not applied** to a *new* decision. Both are
  worded for a change to an existing primitive; a new predicate that every guarded
  context needs was not seen as one, got no row and no owner, and its sweep was "code
  read, not measured, not changed (other components)".

## Preventive action
PA-0559 (text in the lane's doc_texts; strengthens PA-0545(1) and (7), PA-0134(1) and
PA-0138(3)): where a session goes is decided per request at the one owner every request
of its carrier passes (for a browser, navguard's route, WebSocket handler and
`checked_api_request`), by the carrier's own rule (a cookie by RFC 6265 host/domain
match; never an origin rule that folds aliases); a decision two tools must agree on is
born in the owner with a SHARED_PRIMITIVES row and swept to every caller with a measured
disposition; a measured send of the bug's own class on a neighbouring path of the same
carrier is never a residual -- it is fixed in the owner or the item stops for the
orchestrator; each such path has a real-browser test asserting the unreached host
received nothing and no anonymous landing was stored. Enforced by the wiring guard and
its synthetic offenders, the route test on doubles, and the six real-browser tests of
`tests/test_browser_session_reach.py`.
