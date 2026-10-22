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


## Review round 1 (2026-10-22, on 72297c9; BA-1 = BA-4, BA-2 = BA-5, BA-3)

Five confirmed findings (one reviewer, a skeptic for each), three defects. Each is
reproduced by a test that fails on 72297c9 on its own assertion and passes after
(commit 1d7b5e6 on `lane/BROWSERALIAS-r1`; CC-CRAWL-0063, CC-CRAWL-0064 and CC-AUD-0060
"Review round 1"). A revision agent's uncommitted partial edits, lost to a container
restart, were read as a starting point; every line was re-verified and the design was
re-measured, not taken as it stood.

### What each was
- **BA-1, a storage state's ambient cookie aborted disco's start.** `disco capture
  --storage-state` built its session material with `credential_names=None`, so every
  cookie the state adopted counted as the session's, and `filter_storage_state` keeps
  every loopback spelling's cookies (it folds the aliases). With `sid` held for
  127.0.0.1 and an ambient `lang` for `localhost`, `session_host_refusal` refused the
  start host itself ("1 of 2"): the start navigation was aborted (`net::ERR_ABORTED`)
  and the run explored nothing. On 7393c90 the same state explored 127.0.0.1 with `sid`
  on every GET: a regression this lane made.
- **BA-2, an IPv6 cookie never reached its own host.** Chromium holds a cookie set for
  `http://[::1]:P/` with the domain `[::1]`, brackets included, and sends it there
  (measured on Chromium 141); `cookie_reaches` compared that with a URL's `hostname`,
  `::1`. A storage state saved on `[::1]` had every request to its own host refused,
  the start page included. The lane's measurement (`measure/reach.out`) never held an
  IPv6 cookie.
- **BA-3, a speculation-rules preload went past the route.** Chromium sends a
  speculation-rules prefetch from the browser process: neither the route nor a CDP
  interceptor sees it, and a later navigation to that URL is served from the prefetch,
  past the route too. Measured on 72297c9 (`scratchpad/lanes/BROWSERALIAS/r1meas2`,
  both the full browser and the headless shell): a session-carrying page's rule set --
  inline, named by a `Speculation-Rules` header, inserted by a script in any of five
  ways, in a shadow root, or inserted after the page replaced `Element.prototype.remove`
  -- sent the alias a cookie-less prefetch; same-origin document rules sent `/logout`
  with the session, past the destructive rule; a click then committed the alias's
  anonymous page; a popup with an opener prefetched for its own rule sets. The auditor's
  fetcher returned the alias's `Sign in` page as the identity's (200), and the spider
  sent the alias the same uncounted requests. The lane's docs said the guard "refuses
  every request the load makes".

### Root cause analysis (Five Whys, across the three)
1. *Why did these reach review?* Each lies outside what the lane measured: the reach
   measurement held IPv4 cookies by URL and bare domain only (no IPv6, no ambient
   cookie of another spelling); the route's coverage was measured for requests the
   page makes (navigations, hops, subresources, sockets, API calls), never for traffic
   the browser makes on its own.
2. *Why was the browser's own traffic not measured?* The lane took PA-0123(3)'s split
   as settled: "the launch arguments confine only what Chromium itself sends". That
   layer confines by *scope* (resolver rules per `host:port`), and a loopback scope
   admits all three spellings on its port, so the alias -- and any same-origin URL --
   passes it. Nothing confined Chromium's own traffic by session reach or by the
   destructive rule, and nobody listed which of Chromium's own requests a page can
   trigger.
3. *Why were the held forms and the ambient cookies not measured?* The predicate was
   designed from the RFC's text and checked on the shapes the bug showed (127.0.0.1 vs
   `localhost`); the inputs it is given -- every form a context holds a cookie in, and a
   storage state's cookies that are not credentials -- were not enumerated from the
   carrier.
4. *Why did disco treat every adopted cookie as a credential?* "Fail closed" was read
   as "when in doubt, more cookies are the session's"; with a per-name refusal rule,
   more names means more refusals of the session's *own* host, which fails open for
   coverage (the run explores nothing) and was never run with a second cookie.
5. *Why did the docs claim every request?* The claim was derived from the route's code
   (every routed request passes it), not from the browser's behaviour (which requests
   reach the route at all).

**Root cause:** the guard's completeness was established by reading the route, not by
measuring what the browser sends; and the reach predicate's inputs were taken from the
bug's own shapes, not enumerated from what the carrier produces (held forms, ambient
material).

### Corrective action
Commit 1d7b5e6 (CC-CRAWL-0063, CC-CRAWL-0064, CC-AUD-0060 "Review round 1"; FR-CRAWL-43,
FR-CRAWL-34, NFR-CRAWL-safe and NFR-AUD-safe edited in place):
- **BA-2:** `cookie_reaches` compares an IPv6 literal without brackets on both sides.
- **BA-1:** `Explorer._storage_session`: a storage state's session cookies are those that
  reach the start URL's host (`navguard.names_reaching`); a state none of whose cookies
  reaches it keeps them all (the start host is refused, never explored as the
  session's).
- **BA-3, in the owner:** every guarded context gets `navguard.PRELOAD_OFF_JS` before its
  pages run (each `<script type=speculationrules>` removed as it is inserted, open
  shadow roots included, with the functions it calls captured before the page runs);
  the route drops the `Speculation-Rules` header from every answer, gives a main-frame
  document's parser-inserted rule sets an inert type (closed declarative shadow roots),
  and answers a popup's first navigation -- which Chromium commits in the Window of its
  initial `about:blank`, where no init script runs again (measured for five popup
  shapes) -- with a same-URL trampoline, serving the answer it already fetched to the
  trampoline's request (sent once). **In the consumers** (defence in depth):
  `committed_session_refusal` before anything of a load is read -- the fetcher returns
  no page, the spider stores the load `failed`, disco reads no state and takes no
  protected resource there.
- Measured after, both binaries: nothing reaches the alias or `/logout` in any shape
  above, the click is refused and told, popups load their own page once and the opener
  can still script them (`after.*.out`, `edge.after.*.out`, `docopen.out`).

**PA-0002 sweep, by primitive:** every caller of `guard_page` now gets the preload
neutraliser in the owner (the spider, the auditor's fetcher, disco's explorer, disco
ede, the M6 executor, the browser login); no caller passes it or can omit it. Every
consumer that reads a guarded load's committed document as the session's: the fetcher's
`fetch`, the spider's `_goto_and_parse`, disco's `settled_fingerprint` (every state
read) and `_find_protected_resource` (the one place disco sends an API request for a
page URL it took from the browser) -- each checks it. Every comparison of a cookie
domain with a host in `fuzzlab/`: `navguard.cookie_reaches` (fixed);
`session/manager.py` and `session/browserlogin.py` fold the domain through
`canonical_host("http://" + domain + "/")`, which parses `[::1]` correctly (no change).

**Measured, not closed -- flagged to the orchestrator (PA-0559(4)):** a rule set that a
handler *inside a closed declarative shadow root* inserts into that root (an
`<img onerror>` there, `this.getRootNode()`, `appendChild`) is still prefetched with the
guard on, both binaries (`r1meas2/closeddyn.py`, `closeddyn.out`): no script outside
that root can see it, and the HTML layer sees only the parser's rule sets. Closing it
needs pre-insertion hooks on every DOM insertion and attribute API (about twenty), a
wider change than this round's; the consumers' committed-document check still keeps
any page such a prefetch serves from being read as the session's.

**Seen while measuring, another defect, not this bug's (flagged, not changed):** a
guarded page never loads a main-frame HTML document whose bytes are not UTF-8: the
route's `_note_received` reads it with Playwright's strict `APIResponse.text()`, the
`UnicodeDecodeError` escapes the route handler, the request is never fulfilled and the
navigation times out (`r1meas2/latin1.py`, `latin1.out`: an ISO-8859-1 page). Present
since BUG-0138's `_note_received`; for the orchestrator (no number held here).

### Recurrence review
- **BUG-0559 round 0 / PA-0559(2)** ("a cookie reaches a host by RFC 6265's domain
  match ... measured in the real browser"): followed for the shapes the bug showed,
  not for every held form -- BA-2 is its recurrence on an input it did not enumerate.
- **BUG-0123 / PA-0123(3)** (a browser is confined at two layers, each for what it
  actually sees): the launch-argument layer confines Chromium's own traffic by scope
  only; BA-3 is a send of that layer's class that scope admits (an alias of the
  session's host, a destructive same-origin URL). **Match: same root (a layer's
  coverage taken from its rule, not from what passes it).**
- **BUG-0545 / PA-0545(1)** (each disposition measured -- what the target received --
  never read from the path's rule): not followed for the guard's completeness claim.
- **BUG-0134 / PA-0134** (one predicate at every send path): not a recurrence.

### Prior-preventive-action failure analysis
- **PA-0123(3): too narrow.** It names what the launch arguments confine (Chromium's own
  traffic) by one rule, scope, and its tests reach for another port and an off-host
  address only. Session reach and the destructive rule were never asked of that layer,
  and the page-triggered part of Chromium's own traffic (preloads) was never listed.
- **PA-0559(2) (round 0): wrong unit.** It required the predicate to be measured, and the
  lane measured it on the bug's shapes; it did not require the inputs to be enumerated
  from the carrier (every held form, ambient cookies, every loopback spelling).
- **PA-0545(1): not followed** for a claim about a guard ("refuses every request"),
  which was read from the route's code.

### Preventive action
PA-0559 strengthened (amended text in the lane's doc_texts, items 6 and 7): a guard
that claims every request of a carrier passes it lists, by measurement, what the carrier
sends without asking the guard -- for a browser, what the page can make Chromium send on
its own (preloads, prefetches) -- and either confines each or proves it never triggered,
on both binaries a tool may run; and a reach predicate's inputs are enumerated from the
carrier (every form the browser holds a value in -- an IPv6 literal's brackets --, every
loopback spelling, and material that is not a credential), each with a test. Enforced by
the tests named in this section.


## Review round 2 (2026-10-22, on c6296bc; BB-1, BB-2, BB-3, BB-4)

The fix check of c6296bc confirmed round 1's repros fixed and found the same defects on
neighbouring paths (BB-1..BB-3); the lane's own two flags were BB-4. Each finding has a
test that fails on c6296bc for its stated reason and passes after (commits 59866a2 and
a2b8ed5 on `lane/BROWSERALIAS-r2`; CC-CRAWL-0063, CC-CRAWL-0064 and CC-AUD-0060
"Review round 2"). The charset defect (BB-4(2)) is recorded here, with no number of its
own, as the orchestrator decided.

### What each was
- **BB-1, a storage state whose session lives in `localStorage` aborted disco's start.**
  Round 1's `Explorer._storage_session` gave `credential_names = names or None`: when no
  adopted cookie reaches the start host, None -- "every adopted cookie is the session's".
  A state holding its token in the start origin's `localStorage` and one ambient `lang`
  cookie for the alias then had `lang` as its only credential, which refused 127.0.0.1
  ("1 of 1"): the start navigation was aborted (`net::ERR_ABORTED`) and the run explored
  nothing, where 7393c90 explored it (measured by the review, real Chromium). Round 1's
  own docstring said an ambient cookie "never makes the start host unreached"; no test
  held the empty case.
- **BB-2, disco's contract runner dropped an IPv6 storage-state cookie.**
  `disco/runner.py::Runner.auth_headers` (a `storage_state` auth profile) kept a cookie
  `if host == domain.lstrip(".") or host.endswith("." + ...)` -- round 0's comparison --
  so a state saved on `[::1]` (Chromium holds the domain `[::1]`) gave `{}` for
  `http://[::1]:8000/`: every case of the contract went out anonymous, `credentialed=
  False`, reported nowhere. Identical at 7393c90: it predates the lane, but round 1's
  sweep said it covered "every comparison of a cookie domain with a host in `fuzzlab/`"
  and missed it.
- **BB-3, a preload the page-reading layers cannot see still left the browser.** Three
  shapes, measured by the review on c6296bc, both binaries, with the guard told nothing:
  a closed declarative shadow root whose rule set's `type` is written with a character
  reference (`&#115;peculationrules`: the parser decodes it after the route read the
  text; `PRELOAD_OFF_JS` cannot see a closed root); a `window.open()` popup still on its
  initial `about:blank` given a rule set by its opener (no init script runs there); and
  a handler inside a closed declarative root inserting one (the lane's own `closeddyn`,
  flagged in round 1). The alias got cookie-less prefetches (and, through the auditor's
  fetcher, `GET /secret` and `/login` with `Cookie: ''`, uncounted) and 127.0.0.1 got
  `GET /logout?..` with `sid`, past the destructive rule.
- **BB-4(1)** is the third BB-3 shape; **BB-4(2)**: `navguard._note_received` read a
  main-frame HTML document with Playwright's strict UTF-8 `APIResponse.text()`; an
  ISO-8859-1 page raised `UnicodeDecodeError` out of the route handler, the request was
  never answered and the load failed (round 1's `r1meas2/latin1.out`: a goto timeout; in
  the pre-fix proof Playwright re-raised it into `goto`).

### Measured before the design (`scratchpad/lanes/BROWSERALIAS/r2meas`)
- **Launch switches** (`flags.py`, `switches.out`; Chromium 141.0.7390.37, the full
  browser and the headless shell, a bare context so only the switch acts): seventeen
  shapes in turn -- inline, header, same-origin document rules, prerender, created, type
  set late, fragment, `document.write`, open and closed `attachShadow`, open and closed
  declarative roots, the character-referenced type, the closed-root handler, an iframe,
  patched prototypes, the `about:blank` popup. Baseline: every shape but prerender and
  the iframe prefetched the alias and/or `/logout` (with `sid`).
  `--disable-blink-features=SpeculationRules,Prerender2,SpeculationRulesPrefetchWithSubresources,SpeculationRulesTargetHint,PrerenderUntilScript`,
  `--disable-features=Prerender2,PrefetchUseContentRefactor,SpeculationRulesPrefetchFuture,...`
  (twenty-four names, `NetworkPrediction` kept) and a `PreloadingConfig` holdback for
  every preloading type and predictor stopped none of them on either binary. The
  binary's symbols show why the Blink switch cannot: Chromium 141 has no runtime feature
  gating a rule set (`Prerender2`, `PrerenderUntilScript`, `SpeculationRulesTargetHint`
  and `SpeculationRulesPrefetchWithSubresources` only); the prefetch is decided in the
  browser process. **No switch stops it.**
- **The proxy's prerequisites** (`proxyproto.py`): with `--proxy-server=<a loopback
  recorder>` and `<-loopback>`, a guarded context still loads its pages through the
  route -- the Playwright driver never uses the switch -- and every same-origin prefetch
  reaches the recorder, not the target; Chromium attempts no cross-site prefetch at all
  with a proxy configured; a WebSocket the guard admits arrives as `CONNECT`; with
  Playwright's launch `proxy` (disco's capture) and our later switch, Chromium uses ours
  and the driver the launch option. The full browser also sends Google background
  traffic there (formerly `~NOTFOUND` by the resolver rules).
- **A redirect landing** (`redirect.py`): Playwright never routes the browser's
  re-request of a landing the route answered with a redirect to -- through a
  refuse-everything enforcer the redirected page never loaded (`title ''`, the full
  browser `ERR_HTTP_RESPONSE_CODE_FAILURE`). Hence the landing ticket below
  (`redirect.after.out`: `LANDED`, the landing fetched twice, as before).

### Root cause analysis (Five Whys, across the four)
1. *Why did these survive round 1?* Each round-1 fix closed the measured shapes at a
   layer chosen for them: BA-1 for the cookie case (a state with a credential cookie),
   BA-3 at the page (its text and its DOM, seen from outside), BA-2's sweep over the
   modules the lane had read.
2. *Why could the page layers not be complete?* They read the page before or beside the
   browser's own decision -- the parser decodes character references and builds closed
   shadow roots after the route read the text, and an `about:blank` window runs no init
   script -- while the prefetch is decided and sent by the browser process. A defence
   that sees less than the decision point is incomplete by construction; adding a
   spelling to the regex would have been the next residual.
3. *Why was the browser's own egress not enforced?* Round 1 measured that no launch
   switch stops a prefetch and stopped there; that Chromium's own traffic can be routed
   through a loopback hop of ours was already how disco's capture works (CC-CRAWL-0031),
   but it was not seen as a guard.
4. *Why BB-1?* `names or None` mapped the empty set onto None, whose meaning is the
   opposite ("every cookie"): the boundary of a derived credential set was not tested,
   though PA-0559(7) named exactly this failure.
5. *Why BB-2 and the charset defect?* The sweeps were by reading (modules the lane knew;
   the exceptions seen so far), not by a search over the package that a guard keeps
   true.

**Root cause:** round 1 fixed each finding's shapes at the layer that showed them -- the
page, the cookie case, the modules read -- instead of the class at the point where the
decision is made: the browser's own network egress, the empty-set boundary of the
credential set, and every instance of the comparison or decode in `fuzzlab/`, found by a
search a guard holds.

### Corrective action
Commits 59866a2, a2b8ed5 and d5c867f (the targeted run's four failures, each this change's:
two package guards and one test asserting `--no-proxy-server`; CC-CRAWL-0063 round 2)
(CC-CRAWL-0063, CC-CRAWL-0064, CC-AUD-0060 "Review round 2";
FR-CRAWL-43, FR-CRAWL-34, FR-CRAWL-11, FR-CRAWL-14's adoption clause, NFR-CRAWL-safe
and NFR-AUD-safe edited in place):
- **BB-3 (and BB-4(1)), the enforcer, in the one owner of launch arguments (SP-04):**
  `navguard.browser_launch_args` names this process's loopback enforcer as Chromium's
  proxy (`--proxy-server`, `--proxy-bypass-list=<-loopback>`, its address in the
  resolver rules); `--no-proxy-server` is gone. The enforcer (a daemon thread on
  127.0.0.1, one per upstream, started on first use) refuses every request Chromium
  sends itself (403, `enforcer_refusals()` by kind -- `preload` for a request carrying
  `Sec-Purpose`, `request`, `connect` -- logged by host) except a WebSocket the guard's
  socket handler admitted (`admit_socket`, called right before `connect_to_server`;
  tunnelled once) and the re-request of a redirect landing the route checked
  (`admit_landing`, called where the route answers a navigation with a redirect to it;
  forwarded once with `Connection: close`, never as a preload; an `https` landing admits
  one tunnel). With disco's capture proxy the enforcer is chained to it: the driver
  keeps the launch option, an admitted tunnel or landing goes through the recorder
  (recorded as before), and nothing else Chromium sends reaches it.
  `chromium_launch_kwargs` checks the chain. The page-reading layers (`PRELOAD_OFF_JS`,
  the header and HTML layers, the popup trampoline) and the consumers'
  `committed_session_refusal` stay as defence in depth. Measured after
  (`after.*.out`, all layers; `enforcer_only.*.out`, the page layers taken away): no
  shape reaches the alias or `/logout`, both binaries; the enforcer refused the
  same-origin preloads (cross-site ones are not attempted through a proxy).
- **BB-1:** `_storage_session` gives `credential_names=names` -- an empty set when no
  adopted cookie reaches the start host: no cookie is the session's, so SP-74 refuses
  nothing for it. The accepted trade-off stands (the review's note): a state started on
  `localhost` with `sid@127.0.0.1` and `lang@localhost` takes `lang` as the credential.
- **BB-2:** `Runner.auth_headers` keeps the state's cookies that `navguard.cookie_reaches`
  the target's host; `browserlogin.filter_storage_state` keeps a cookie that reaches a
  scope host in any spelling its origin folds (`navguard.origin_host_spellings`, new) --
  a host-only cookie of a parent domain, which the browser never sends to the scope's
  host, is no longer adopted.
- **BB-4(2):** `navguard.decoded_text(body, content_type)` (a byte-order mark's charset,
  else the `Content-Type`'s, else a `<meta>`'s, a Latin-1 label read as windows-1252;
  undeclared: UTF-8, else windows-1252, else byte for byte; never raising; the codec
  None when the declared charset is not lossless) and `response_text(response)`.
  `_note_received` decodes with it and never raises; `_fulfil_preload_free` re-encodes
  an inert rule set's page in the codec it was decoded with (never when lossy);
  `response_html` uses it.

**PA-0002 sweeps, by primitive and by grep:**
- *Chromium's own egress* (every caller of SP-04): every launch in `fuzzlab/` takes
  `browser_launch_args` (held by `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`):
  the spider, the auditor's fetcher, disco's explorer, disco ede, the M6 executor and
  the browser login all get the enforcer with no change of their own. What Chromium
  legitimately sends itself in a guarded context, by reading every `route.continue_`,
  `fallback` and redirect fulfil in `fuzzlab/` and measured: a WebSocket
  (`connect_to_server`, only in `make_ws_handler`: ticketed) and a redirect landing (the
  one 3xx fulfil, in `make_route_handler`: ticketed); `continue_` only for
  `data:`/`blob:`/`about:`; disco ede's `fallback` goes to the guard.
- *Cookie domain compared with a host* (grep of `get("domain"`, `["domain"]`,
  `endswith("." +` over `fuzzlab/`): `navguard.cookie_reaches` (the owner);
  `disco/runner.py::auth_headers` (fixed); `session/browserlogin.py::filter_storage_state`
  (fixed); `session/manager.py::_jar_cookies` -- **flagged, not changed** (the file is
  held by another lane, SESSROT): its domain side folds through `canonical_host`, and
  its host side formats `f"http://{host}/"` from a URL's `hostname`, which for an IPv6
  target is `::1`, so `canonical_host` gives None and BUG-0132's jar cookies are dropped
  there (the review's item 5; the same host-side formatting at `manager.py:1359` and
  `:1390`). An AST guard holds the rule for every other module, exempting `manager.py`
  by name with this reason.
- *A response body read as strict UTF-8* (grep of `.text()` in Python under
  `fuzzlab/`): `navguard._note_received` and `response_html` (fixed); the spider's
  harvest of a loaded stylesheet's/sitemap's URLs and disco's harvest of a script or
  stylesheet (fixed: a Latin-1 body was skipped); disco's `_protected_get` (fixed: a
  Latin-1 page made the health check INCONCLUSIVE). An AST guard holds it.

**Flagged to the orchestrator, not changed:**
- `manager._jar_cookies` and the host-side formatting at `manager.py:1359`/`:1390`
  (above; owner SESS, file held by SESSROT).
- `browserlogin.filter_storage_state` is component SESS; this lane holds no CC-SESS
  number, so its change is recorded under CC-CRAWL-0063's round 2 -- a CC-SESS entry
  (and FR-SESS text naming it, if any) is the orchestrator's to assign.
- For an `https` target the enforcer judges a tunnel by its host and port only: what
  Chromium sends inside a tunnel it was admitted for (a WebSocket's, a landing's) is not
  seen. Not measured (no https lab here).
- Disco's `explore.session_host_unreached` is still not a diagram event (round 0's
  flag), and the enforcer's refusals are counted per process (`enforcer_refusals`), not
  per tool run.

### Recurrence review
- **BUG-0559 round 1 (PA-0559(6), (7)) -- the same bug, recurring on neighbouring paths
  of the same carrier:** BB-3 is BA-3's class (a browser-process preload past the guard)
  on shapes the page layers cannot see; BB-1 is BA-1's class (non-credential material
  refusing the session's own host) at the empty-set boundary; BB-2 is BA-2's class (a
  cookie's IPv6 held form) in a comparison the sweep missed.
- **BUG-0123 / PA-0123(3):** the launch-argument layer is again the layer that confines
  Chromium's own traffic -- now by refusal at its egress, not only by name resolution.

### Prior-preventive-action failure analysis
- **PA-0559(6): wrong layer.** It required each thing the carrier sends without asking to
  be confined "by every rule the guard applies, or proven never triggered", and round 1
  confined preloads where the page is read -- a layer that cannot see what the parser
  and the browser decide -- with a stated residual (`closeddyn`) instead of moving to the
  layer where the browser sends.
- **PA-0559(7): not followed at the boundary.** It named "every adopted value is a
  credential when one extra value refuses the session's own host" as the failure, and
  the fix reintroduced it for the empty set; no test held a state with no credential
  cookie.
- **PA-0002 (with PA-0559(3)): followed by reading, not by search.** "Every comparison
  in `fuzzlab/`" was asserted from the modules the lane had read; nothing held it.

### Preventive action
PA-0559 strengthened (amended text in the lane's doc_texts, items 8-10): (8) a guard
against something the browser decides and sends itself is placed at the browser's own
egress (the enforcer every launch names), with the page-reading layers as defence in
depth only, and a guard's exceptions (tickets) are issued only where the guard already
checked the request; (9) a sweep's "every X in `fuzzlab/`" is a search over the package,
and an AST guard over the package holds it (the cookie-domain and strict-decode guards,
proven on synthetic offenders); (10) a credential set derived from material is tested at
its boundary (none of the material is a credential) as well as its cases, and the empty
set never stands for "all". Enforced by the round-2 tests in
`tests/test_browser_session_reach.py` and `tests/test_browser_scope.py`.

## Review round 3, final (2026-10-22, on 1b05e3f; BB-4's uncovered labels, the https redirect regression, BB-3's https neighbour)

The owner made this the final round: anything a later check finds is pinned with a
strict xfail and reported. The fix check of 1b05e3f confirmed round 2's repros fixed
(BB-3's every named shape on both binaries and through the real capture proxy; BB-4's
Latin-1 page) and found three defects of round 2's own making on inputs it had not
covered. BB-2's remaining item -- `session/manager.py::_jar_cookies` and the manager's
unbracketed IPv6 host (`manager.py:1359`, `:1390`) -- is not this round's: the
coordinator fixes `_jar_cookies`'s IPv6 bracket at the merge, and the file is not
touched here (the AST guard's named exemption stays until then). Each finding below has
a test that fails on 1b05e3f for its stated reason and passes after (commit 1c337dd on
`lane/BROWSERALIAS-r3`; CC-CRAWL-0063, CC-CRAWL-0064 and CC-AUD-0060 "Review round 3").

### What each was
- **BB-4, a charset label that is not a text encoding hung the route** (a regression of
  round 2 against the pushed code). `decoded_text` ran `codecs.lookup()` on the label
  the target declares and then `data.decode(codec)`, catching `UnicodeDecodeError` only.
  Python's registry also names codecs that are not text encodings (`hex`, `base64`,
  `rot13`, `zlib`, `bz2`, `uu`, `quopri`: `bytes.decode` raises `LookupError`) and text
  codecs that refuse a document (`idna`, `undefined`: `UnicodeError`, with `replace`
  too). `_note_received` caught `(AttributeError, Error, TypeError, ValueError)`, and
  `LookupError` is none of them: a page served `charset=hex`, or naming only `<meta
  charset=base64>`, raised out of the route handler, was never answered and its `goto`
  timed out -- pages that loaded at c6296bc. `charset=idna` raised out of `navigate`
  itself through `response_text`, which claimed never to raise and did not catch a
  decoder's error (two consumers, `explore.py:978` and `spider.py:2494`, did not catch
  it either). And a neighbouring strict read the round-2 sweep missed: disco's
  `carries_value` read Playwright's `req.post_data` (strict UTF-8) and dropped a Latin-1
  form's body on the error, so a submission carrying the filled value counted as not
  sent (BB-4(4)).
- **The https redirect regression** (round 2's enforcer). With a self-signed target and
  `ignore_https_errors=True` -- as disco runs -- a redirected navigation failed on both
  binaries with `net::ERR_TUNNEL_CONNECTION_FAILED`: `admit_landing` turned an https
  landing into one `admit_socket` ticket, the browser's first `CONNECT` used it, and
  Chromium's retry after the certificate error is a second `CONNECT`, which was refused.
  At c6296bc the landing loaded. Round 3's sweep found the same on the socket ticket: a
  `wss` WebSocket to a self-signed target never opened (`WS-ERR`; it opened at c6296bc).
- **The https tunnel reuse** (BB-3's neighbour). The tunnel admitted for a landing
  stayed in Chromium's keep-alive pool; a later same-origin speculation-rules prefetch
  (the charref closed-root rule set on the landing) rode it -- `GET /logout?tls` with
  `sid=S` and `Sec-Purpose: prefetch` on the landing's own client port -- past the route
  and past the enforcer, which judged the `CONNECT` only. The module doc's and
  `browser_launch_args`' claim that a destructive preload "is refused there whatever the
  page's markup" was false for https, and the landing re-requested through the tunnel
  also skipped the route's text layer. Plain http is not affected (`_forward` sends
  `Connection: close` and closes).

### Measured before the design (`scratchpad/lanes/BROWSERALIAS/r3meas`)
- `https_landing.py` (a TLS server on 127.0.0.1 with HTTP/1.1 keep-alive, its leaf from
  the test's own `LocalCA`; `/start` -> 302 -> `/land` carrying the charref closed-root
  rule set for `/logout?tls` and the alias; a context guarded with `sid@127.0.0.1`;
  Chromium 141.0.7390.37, both binaries). At 1b05e3f: `ignore` (self-signed,
  `ignore_https_errors=True`) -- `net::ERR_TUNNEL_CONNECTION_FAILED`; `nss` (the CA
  trusted in an NSS db under a scratch `HOME`, the driver trusting it through
  `NODE_EXTRA_CA_CERTS`) and `spki` (Chromium trusting the leaf key alone, TLS
  verification otherwise on) -- the landing loads and `/logout?tls` arrives with `sid=S`
  on the landing's client port, TLS 1.3 and TLS 1.2 (`tls12`); with the server offering
  `h2` Chromium chose it inside the tunnel (`net::ERR_HTTP2_PROTOCOL_ERROR` against the
  HTTP/1.1-only server); `wss` -- `WS-ERR` at 1b05e3f, `WS-OPEN` at c6296bc. No
  `--ignore-certificate-errors` was needed: the review's stand-in, never used here.
- `... trace`: the retry's `CONNECT` comes 4-12 ms after the first; a TLS 1.3 client
  abandoning a handshake on a certificate sends its alert as a small application-data
  record.
- `every_codec.py`: an ASCII page labelled with each of the 455 codec names Python
  registers, in the header and in a `<meta>`, through the guard: after the fix all 910
  loads reached their load state (36.7 s); at 1b05e3f `hex`, `base64`, `rot13`, `zlib`
  timed out or raised and `undefined` raised.
- Options for the reuse, measured against the review's repro: **closing an admitted
  landing tunnel once its one exchange is done**, read at the TLS record layer (chosen:
  the repro passes, both binaries, TLS 1.2 and 1.3, direct and through the capture
  proxy); **the route fetching and fulfilling an https landing itself** (not chosen:
  answered without the redirect the page shows the first URL -- `page.url` and relative
  links wrong, what the redirect exists to keep right -- and a trampoline navigation
  instead changes what `goto` returns to every consumer). Terminating TLS in the
  enforcer was ruled out: the browser would have to trust our CA (never weaken TLS).

### Root cause analysis (Five Whys)
1. *Why did round 2 break https redirects and leave the tunnel open?* Its tickets were
   designed and measured on plain http; for https it wrote "a tunnel is judged by its
   host and port only ... not measured (no https lab here)" as a flag.
2. *Why does "one `CONNECT` per ticket" not fit https?* Chromium opens and reuses a
   connection in ways the ticket did not model: a certificate error's retry is a new
   connection, and a finished exchange leaves the tunnel in the keep-alive pool for the
   next request to that origin (and HTTP/2 would multiplex it).
3. *Why was that not measured?* "No https lab" was taken as a reason not to measure,
   though a local TLS server is a few lines (the review built one).
4. *Why did the decoder raise?* Round 2 enumerated the charsets of its test pages, not
   the domain of its input: a label the target writes, looked up in a registry that
   also holds non-text codecs and codecs that refuse documents. Its AST guard banned
   the instance found (`.text()`), not the class (any strict decode of a Playwright
   body), so `post_data` stayed.

**Root cause:** round 2 measured its new mechanisms on the inputs it had in hand --
plain http, its test pages' charsets, the response-body accessor -- instead of
enumerating each mechanism's input domain: every scheme the enforcer carries and every
way the browser opens and reuses what a ticket admits; every label the codec registry
accepts; every strict-decoding body accessor.

### Corrective action
Commit 1c337dd (CC-CRAWL-0063, CC-CRAWL-0064, CC-AUD-0060 "Review round 3"; FR-CRAWL-43,
FR-CRAWL-34, FR-CRAWL-11, NFR-CRAWL-safe and NFR-AUD-safe's clause edited in place).
Pre-fix proof: one pytest invocation with 1b05e3f's `navguard.py` and `explore.py` in
place, then restored -- the ten round-3 tests failed, each as stated
(`scratchpad/lanes/BROWSERALIAS/r3proof/proof.log`). Targeted run on a51ca33 (the
harness's own selection, 101 files, one invocation): 4063 passed, 0 failed, 1 skipped,
55 xfailed (`r3proof/targeted.log`).
- **BB-4:** `decoded_text` treats a label as unknown when it names no text encoding
  (`_text_codec`: unknown to the registry, or `_is_text_encoding` false) or names a
  codec that refuses the document (strict decode raises anything but
  `UnicodeDecodeError`, or `replace` raises); the next label decides, else the
  undeclared order (UTF-8, else windows-1252, else byte for byte). Nothing a codec
  raises leaves it; `response_text` never raises; `_note_received` also catches
  `LookupError`. `carries_value` reads `post_data_buffer` through `decoded_text`.
- **The tunnels:** one ticket class (`_TunnelTicket`) for a WebSocket's and an https
  landing's tunnel: `CONNECT`s to its host and port are admitted until one tunnel
  carries the browser's traffic (`_claim`), at most four, the later ones within
  `_TICKET_RETRY_WINDOW_S` (3 s) of the first -- the retry after a certificate error
  is covered, and nothing later. `_HeldTunnel` reads the TLS record layer only (nothing
  decrypted or re-signed; TLS verification untouched): an alert-sized application-data
  record carries nothing (a TLS 1.3 client's alert on an abandoned handshake); a
  WebSocket's tunnel is claimed by its first larger record or plain byte and then
  relayed whole; an https landing's tunnel carries one exchange -- its request claims
  the ticket, the server answers, and the browser's next request on it is never
  forwarded: the tunnel is closed and counted (`enforcer_refusals()["reuse"]`), and
  the browser's retry finds no ticket. The ServerHello's `supported_versions` says
  whether the client's first application-data record is its TLS 1.3 `Finished`
  (unreadable: taken as TLS 1.2, which errs towards closing). `browser_launch_args`
  adds `--disable-http2`, so Chromium's own traffic is one request at a time on a
  connection (routed requests are the driver's and never see it). The module doc and
  `browser_launch_args`' doc now say what a tunnel is held to.

**PA-0002 sweeps:**
- *Every caller of a tunnel ticket* (`admit_socket`: `make_ws_handler`; `admit_landing`:
  `make_route_handler`'s redirect fulfil): both on the one ticket class; the socket's
  certificate retry was the same defect (fixed, tested). Every launch takes
  `browser_launch_args` (held by `test_every_browser_path_in_fuzzlab_is_scoped`), so
  every tool gets the switch and the tunnels.
- *Every reader of a charset label*: `decoded_text` is the one decoder (AST guard);
  its callers -- `_note_received`, `response_text` (`response_html`, the spider's and
  disco's harvests), disco's health check, and now `carries_value` -- inherit it.
- *Every strict decode of a Playwright body* (grep of `.text()`, `.post_data`,
  `.post_data_json` over `fuzzlab/`): `explore.py:761` (fixed); the AST guard now bans
  all three, proven on synthetic offenders. `session/browserlogin.py`'s reads with
  UTF-8 `replace` are lossy but never raise: not changed (the review did not count them).

**Residuals, stated (FR-CRAWL-43):** a ticket cannot tell whose `CONNECT` it admits: a
request of the browser to the same host and port in the milliseconds before the
browser's own connection (or within its retry window, before the exchange claims the
ticket) could take it -- round 2's one-`CONNECT` ticket had the same window; a
WebSocket's and an https landing's tickets admitted at the same moment for one host and
port may be matched in the other order; a landing request larger than one TLS record
whose later record follows a server record would be cut (fail closed); TLS 1.3 early
data is not read (off by default in Chromium 141); what a WebSocket's tunnel carries
after its upgrade is not seen; measured on a local TLS server only (no https lab).

### Recurrence review
- **BUG-0559 round 2 (PA-0559(8), (9)) -- the same bug class recurring on the same
  carrier:** the enforcer's exception (a ticket) let a preload through on the https
  scheme round 2 did not measure; the strict-decode guard round 2 wrote held the one
  accessor it had seen.
- **BUG-0559 round 1 (PA-0559(7)) -- the same root cause on another input:** round 1's
  rule that a predicate's inputs are enumerated from the carrier was not applied to the
  decoder's input, a label the target writes.

### Prior-preventive-action failure analysis
- **PA-0559(8): too narrow.** It placed the guard at the browser's egress and required
  each exception to be a ticket issued where the guard checked the request; it did not
  require the ticket to be measured against how the browser uses what it admits -- a
  certificate retry, the keep-alive pool, multiplexing -- on every scheme, so the https
  ticket admitted too little (the retry) and too much (the pool).
- **PA-0559(9): followed for the instance, not the class.** The guard banned `.text()`;
  `.post_data` is the same strict read of a Playwright body.
- **PA-0559(7): not applied beyond cookies.** "Inputs enumerated from the carrier" was
  read as cookie forms; the decoder's label domain is an input of the same kind.

### Preventive action
PA-0559 strengthened (texts in the lane's doc_texts, items 11 and 12): (11) an exception
a guard grants (a ticket) is measured against every way the browser uses what it admits
-- a certificate error's retry, the keep-alive pool, multiplexing -- on every scheme the
tools carry, against a local server of that scheme when no lab has one ("no lab" is
never a reason to flag instead of measure), and is bound to the one exchange it was
granted for; (12) code fed a value the target writes (a charset label) is tested over
the whole domain the library accepts, generated (every codec name the registry knows),
through the real path; a guard against a hazardous call bans the class (every strict
decode of a Playwright body), each proven on a synthetic offender. Enforced by the
round-3 tests in `tests/test_browser_session_reach.py`.

## After the owner's final round (2026-10-22, on 72497c9; the round-3 fix check's two open results)

The owner approved round 3 (72497c9) as the final round, with one rule: anything found
after it is pinned by a strict xfail, except a regression the batch itself introduced,
which is fixed in the batch (PA-0549(3c)). Round 3's fix check confirmed every named
repro fixed (BB-4's `hex`/`base64`/`idna`/`undefined` pages and the Latin-1 form; the
https landing, the certificate retry and the tunnel reuse, both binaries, through the
capture proxy) and returned two open results. This section records what was done with
each, on `lane/BROWSERALIAS-r4` from 72497c9 (CC-CRAWL-0063 and CC-AUD-0060 "After the
owner's final round").

### What each was
- **A regression, fixed: a large page labelled `charset=punycode` timed the route out.**
  Round 3's `decoded_text` rejected only a label naming no text encoding or a codec that
  raised, so every other text codec Python registers still decoded a target's body.
  `punycode` is one, and CPython's punycode decoder is super-linear (each decoded code
  point is an insertion into the string built so far). The check measured, at 72497c9,
  a 300 KB ASCII page labelled with it: `Page.goto: Timeout 5000ms exceeded` on the
  headless shell (4.66 s on the full browser), 500 KB `Timeout 15000ms exceeded` at
  disco's default navigation timeout; the route handler runs on the Playwright
  dispatcher, so everything else on it stalled too. c6296bc loaded the 300 KB page in
  0.18 s (it read a main-frame page as strict UTF-8 and failed only on non-UTF-8 bytes);
  1b05e3f also timed out -- round 2's decoder introduced it and round 3 did not cover
  it. The same decoder runs in disco's `carries_value`, inside its request handler, on
  a request body whose label the page chooses (300 KB: 4.57 s). Chromium itself does
  not know the label and loads the page at once.
- **A neighbour, pinned: a tunnel ticket its own connection never uses is taken by a
  prefetch.** Not a regression of the batch (the pushed code let that prefetch out
  anyway): a ticket is keyed by host and port and stays live `SOCKET_TICKET_TTL_S`
  (10 s). The check made two tickets whose connection never comes -- a WebSocket whose
  native constructor throws after the guard admitted it (Playwright's page-side mock
  does not validate the subprotocol `'not a token'`, so `make_ws_handler` calls
  `admit_socket` and `connect_to_server`, and the native constructor then throws), and
  an iframe's redirect landing that the route admits after the page removed the frame
  (the server holding the route's fetch of the landing 1.5 s) -- and a speculation-rules
  prefetch of `/logout` that a handler inside a closed declarative root inserts into
  that root: the prefetch's `CONNECT` took the ticket and `GET /logout` reached the
  server with `sid=S` and `Sec-Purpose: prefetch`, counted nowhere (both binaries, the
  review's certificate configuration and the spki trust, through the capture proxy; a
  socket ticket's tunnel then stays in Chromium's pool and carries later prefetches).
  So the claim in the module doc and `browser_launch_args` that a destructive preload
  is refused "whatever the page's markup" was false for https.

### Measured before the design (`scratchpad/lanes/BROWSERALIAS/r4meas`)
- `browser_labels.py` -> `labels.full.json` (Chromium 141.0.7390.37, full browser, no
  guard): `document.characterSet` and the decoded bytes 0x80..0xFF for all 618 labels
  (the 455 Python registers and the 228 WHATWG labels), in the header and in a
  `<meta>`. Every WHATWG label decoded by the encoding the standard names; every other
  label is unknown (Chromium then detects: an unlabelled page of those bytes read as
  IBM866); a `<meta>` naming any UTF-16 label is UTF-8 and `x-user-defined` windows-1252.
- `py_labels.py`: `codecs.lookup` resolves 154 of the 228 WHATWG labels; 74 (for
  example `windows-874`, `x-cp1252`, `iso88591`, `koi8`, `mac`, `x-sjis`, `x-euc-jp`,
  `cseuckr`, `windows-949`, `x-mac-cyrillic`, `unicode-1-1-utf-8`) resolve to nothing.
  Python names some WHATWG labels' encodings by a subset codec (`gb2312`, `shift_jis`,
  `euc_kr`, `big5`) or by the ISO code page a browser reads as a windows one
  (`iso8859-1`, `iso8859-9`, `iso8859-11`).
- `browser_multibyte.py` -> `multibyte.full.out`: Chromium against each candidate
  Python codec on characteristic sequences under a WHATWG label: Shift_JIS is
  `cp932`'s 12/13 (`shift_jis` 5/13), EUC-KR `cp949`'s 4/4 (`euc_kr` 3/4), GBK
  `gb18030`'s 5/6 (`gbk` 4/6, `gb2312` 2/6), Big5 `big5hkscs`'s 6/8 (`big5` 2/8),
  ISO-2022-JP `iso2022_jp_ext`'s 3/4 (`iso2022_jp` 2/4), EUC-JP `euc_jp` 4/7 (the 2004
  variants decode IBM extension rows as other characters), windows-874 `cp874`,
  `iso-8859-9` `cp1254`, `ibm866` `cp866`, `utf-16` UTF-16LE.
- `decoder_cost.out`: each codec the allow-list can choose decodes 1 MB of random bytes,
  of `a`, and of escape sequences in at most 42 ms, strict or with replacement, and
  raises nothing but `UnicodeDecodeError`.
- `costly.72497c9.out`, `route_body_timing.72497c9.out`: 72497c9's `decoded_text` on an
  ASCII body with a long run of letters after its last `-`, labelled `punycode`: 128 KB
  about 1 s, 256 KB 4-18 s with the host's load, 384 KB 9.8 s, 512 KB 82.5 s; `idna`,
  `unicode_escape`, `raw_unicode_escape` and `utf-7` stay linear on Python 3.13 (idna
  refuses a label over 1024 bytes). The tests use 384 KB.
- `post_body.py`: Playwright's `post_data_buffer` carries a guarded page's 512 KB fetch
  body whole, so `carries_value` can be tested on real requests.
- Pin measurements: `pin_ticket.repeat.out` (the pin's repro, 10 of 10 runs, both
  shapes, both binaries: `/logout?socket` / `/logout?landing` with `sid=S` and
  `Sec-Purpose: prefetch`); `pin_ticket.control.out` (the same with the admits made
  no-ops: no ticket, the prefetch's `CONNECT` refused, no `/logout`, 4 of 4);
  `pin_deltas.out` (the decoder's remaining deltas from Chromium by WHATWG encoding);
  `spider_static_text.out`, `spider_static_fetch.out` (the legacy spider's static
  engine, below).

### Root cause analysis (Five Whys, the regression)
1. *Why did a punycode-labelled page time the route out?* The route's decoder ran
   CPython's punycode codec on a 300 KB body, which took longer than the navigation's
   timeout.
2. *Why did that codec run at all?* Round 3 decided a label by subtracting from what
   Python's registry accepts -- codecs that are not text encodings, codecs that raise --
   so every text codec Python ships stayed allowed, `punycode`, `utf-7`,
   `unicode_escape`, EBCDIC and `utf-32` among them, though no browser decodes a
   document by any of them.
3. *Why was the cost not seen?* Round 3's generated tests covered every label but on
   small bodies: they proved "never raises", not "answers within its time". The hazard
   of a target-chosen codec is in the label and the body together.
4. *Why a deny-list?* The fix was shaped by the failures in hand (`LookupError`,
   `UnicodeError`); the reference that defines which labels mean anything -- the WHATWG
   Encoding Standard, which Chromium implements -- was not the starting point.

**Root cause:** the decoder's input domain was taken to be "labels Python knows",
filtered by what had failed, instead of "labels a browser knows", allowed by what the
browser does; and its tests bounded what can raise, not what can take time.

### Corrective action
Commit on `lane/BROWSERALIAS-r4` (CC-CRAWL-0063 and CC-AUD-0060 "After the owner's
final round"; FR-CRAWL-43, FR-CRAWL-34, NFR-CRAWL-safe and NFR-AUD-safe's clause edited
in place).
- **The decoder (`navguard`, SP-76's owner):** `decoded_text` decodes only by an encoding
  the WHATWG Encoding Standard defines. `_BROWSER_CODECS` is the allow-list: keyed by
  Python's name for a label (`codecs.lookup(label).name`) -- each browser encoding's own
  name, else its Python codec (`cp874`, `mac-cyrillic`), and every Python name its
  WHATWG labels resolve to -- each mapped to the Python codec that decodes as Chromium
  does, as measured: `iso8859-1`/`ascii`/`cp1252` windows-1252, `iso8859-9` `cp1254`,
  `iso8859-11`/`tis-620` `cp874`, `gbk`/`gb2312` `gb18030`, `big5` `big5hkscs`,
  `shift_jis` `cp932`, `euc_kr` `cp949`, `iso2022_jp` `iso2022_jp_ext`, `utf-16`
  UTF-16LE, the rest themselves. `_text_codec(label, meta=)` looks a label up there; a
  `<meta>` naming UTF-16 gives UTF-8 (HTML's prescan, measured). Any other label is
  unknown and the next label, else the undeclared order (UTF-8, windows-1252, byte for
  byte), decides. Every allowed codec is linear and never raises with replacement, and
  the broad catches stay as defence. `carries_value` and every other caller inherit it.
- **The neighbour:** not changed (the owner's rule). The module doc and
  `browser_launch_args` now state the gap and name its pin; FR-CRAWL-43,
  FR-CRAWL-34, NFR-CRAWL-safe and NFR-AUD-safe say the same.
- **Tests** (`tests/test_browser_session_reach.py`):
  `test_a_charset_label_decodes_only_by_an_encoding_a_browser_defines` (every codec name
  Python registers, header and `<meta>`: the codec used is one a browser encoding decodes
  by, a byte-order mark's or the undeclared order's; a costly codec's label on a 384 KB
  body is read by the undeclared order within 2 s; the measured mappings);
  `test_a_guarded_page_loads_a_document_whatever_charset_it_names` extended (a costly
  codec's label -- `punycode`, `idna`, `unicode_escape`, `raw_unicode_escape`, `utf-7`,
  every alias -- labels a 384 KB page, which loads through the route within the 5 s
  navigation timeout); `test_a_request_body_is_read_whatever_charset_it_names_within_its_budget`
  (real Chromium: a guarded page POSTs `q=zzfiller1`, 384 KB for a costly label, once
  per codec name Python registers; `carries_value` reads each real request within 2 s
  and sees the value, a UTF-16 label excepted). The round-2 unit test's Shift_JIS
  expectation is now `cp932`. **Pre-fix proof** (plain calls, no pytest session, the new
  test file over a `git archive` export of 72497c9;
  `scratchpad/lanes/BROWSERALIAS/r4meas/proof.72497c9.out`): all three fail at their
  assertions -- codecs outside the browser's (`cp037`, `cp1026`, `cp437`, ...);
  `[('label/punycode', 'Page.goto: Timeout 5000ms exceeded.')]`;
  `('punycode', True, 10.307)` (over the 2 s budget) and EBCDIC labels unseen.
- **Pins** (strict xfails, `raises=AssertionError`, real code, each shown failing at its
  stated assertion by a plain call):
  `test_a_ticket_its_own_connection_never_uses_admits_no_prefetch[socket|landing]-[full|shell]`
  (real Chromium, TLS verification on, the test trusting its own key only: the guard's
  real `admit_socket`/`admit_landing` recorded, the prefetch fired once the ticket is
  live; a precondition that does not hold is `pytest.fail`, never the pinned
  assertion; `assert logouts == []` fails with `/logout?socket` / `/logout?landing`,
  `sid=S`, `prefetch`; owner navguard SP-04);
  `test_a_document_reads_as_chromium_decodes_it_under_every_whatwg_label` (real
  Chromium, every WHATWG label: 139 of 228 labels read otherwise than Chromium shows --
  the 74 unresolved labels, the windows code pages' undefined bytes, KOI8-U's two bytes,
  the CJK decoders' recovery from invalid sequences, the replacement encoding; owner
  navguard SP-76); `test_the_static_engine_reads_a_page_whatever_charset_it_names`
  (offline, below).
- **The run:** one pytest invocation on the final tree (`FUZZLAB_REQUIRE_BROWSER=1`,
  `-n 3 --dist loadfile`; this file's tests, `tests/test_browser_scope.py` and every test
  file importing `fuzzlab.tools.navguard`, 14 files): 864 passed, 0 failed, 0 skipped,
  8 xfailed -- the six pins and two older ones -- in 587 s
  (`scratchpad/lanes/BROWSERALIAS/r4proof/targeted.log`; CC-CRAWL-0063).

**PA-0002 sweep, by primitive (every reader of a charset label a target writes):**
- `navguard.decoded_text` is the one decoder of a Playwright body (the AST guard
  `test_no_module_reads_a_response_body_as_strict_utf8`); its callers -- `_note_received`
  (the route), `response_text` (`response_html`, the spider's and disco's harvests),
  disco's `_protected_get` and `carries_value` -- all take the allow-list.
- **Found, not this batch's code, pinned:** the legacy spider's static engine
  (`LocalSpider._fetch_static`, with `_as_requests_response` for the seam's answers)
  reads requests' `Response.text` under the header's charset, three times a page, never
  through `decoded_text`. Measured (`spider_static_text.out`, `spider_static_fetch.out`):
  `charset=idna` and `charset=undefined` raise `UnicodeError` out of the read (the
  crawl loop files the page as an error -- the check's finding), `punycode` and EBCDIC
  labels read an ASCII page as other characters, and `punycode` runs super-linearly
  (384 KB: 18.6 s per read). It predates the batch (7393c90: `get_encoding_from_headers`
  and `resp.text` were there), so by the owner's rule it is pinned, not fixed:
  `test_the_static_engine_reads_a_page_whatever_charset_it_names` (offline strict
  xfail, owner the spider's static engine; the remedy reads the body through SP-76).
- **Found, not this batch's code, flagged to the orchestrator (not pinned in this
  round; PA-0559(4): the item stops there and the orchestrator decides):** the same
  mechanism -- requests' `Response.text`, which decodes a target's body by the
  header's charset with whatever Python codec it names (`str(content, charset,
  "replace")`; it catches only `LookupError` and `TypeError`, so `idna` and `undefined`
  raise, and `punycode` runs super-linearly: measured on requests' own property,
  `spider_static_text.out`) -- is read by other components' senders. A grep of `.text`
  on `requests` responses over `fuzzlab/` found, besides the spider's static engine:
  `session/manager.py:334`, `:429`, `:435` (the session manager's fetches; a file this
  lane may not touch), `tools/probesender.py:1286` (excluded too),
  `tools/fetcher.py:563` (the auditor's unauthenticated static fetch),
  `greybox/run.py:217`, `tools/blind_sqli_fuzzer.py:103`,
  `labgen/identifier_sqli_oracle.py:296` and `lab_fixtures/external.py:1090`; a grep
  by variable name may miss a reader. Each path was read, not driven: the property's
  cost and errors were measured, not each caller's handling of them. They predate the
  batch and sit with other owners (SESS, FUZZ, AUD, greybox, labgen); one fix point
  would be SP-60's bounded session (`core/bodyread.bound`), whose response hook could
  set `Response.encoding` from the same allow-list so every `.text` read inherits it --
  an owner's design decision, not taken here.

### Recurrence review
- **BUG-0559 round 3 (PA-0559(12)) -- the same defect recurring on the same function:**
  a label the target writes made the route handler miss the navigation's timeout,
  through a codec round 3's fix still allowed.
- **BUG-0559 round 2 (PA-0559(7), (9)) and BUG-0548 (PA-0548, a decode on the proxy's
  loop held it 104 ms per MiB) -- the same root cause:** a decode of a target's bytes on
  a path that must answer in bounded time, bounded by what had failed rather than by
  what the input can cost.

### Prior-preventive-action failure analysis
- **PA-0559(12): too narrow.** It required the decoder to be tested over the whole
  domain the library accepts for the label, generated, through the real path -- which
  round 3 did, for every label, on small bodies. It named the label as the input and
  "can raise" as the hazard; the cost lives in the label and the body together, and the
  domain to allow is the browser's, not the library's minus its failures.
- **PA-0536(1) and PA-0548(4) (a bound on untrusted input enforced inside the loop that
  does the work; a target's body decoded under a ceiling): not applied here.** They were
  written for body bytes read from the network and for the proxy's decode, and swept by
  library (`requests`, mitmproxy), not by "a codec the target chooses runs on its bytes".

### Preventive action
PA-0559 strengthened (text in the lane's doc_texts, item 13): **when a value the target
writes selects an implementation (a codec, a parser, a format), the selection is an
allow-list of what the browser (or the protocol's reference) does, measured, never what
the library accepts minus what failed; and the tests generate the hazard's whole input --
the selector and the data it runs on, at a size that shows a super-linear cost -- with a
time budget, through the real path.** Enforced by
`tests/test_browser_session_reach.py::test_a_charset_label_decodes_only_by_an_encoding_a_browser_defines`,
`::test_a_guarded_page_loads_a_document_whatever_charset_it_names` and
`::test_a_request_body_is_read_whatever_charset_it_names_within_its_budget`. The
neighbour and the spider's static engine are pinned by strict xfails (PA-0531(4),
PA-0550(7)); the other components' `requests` readers the sweep found are flagged to the
orchestrator with their files (PA-0559(4)), never stated as residuals.

## The label parser (coordinator, at the gaps merge, 2026-10-22)
- **Found by** the check of 4db0189: `_HEADER_CHARSET` (and `_META_CHARSET`) read the
  label as `charset\s*=\s*["']?\s*(...)`; two quantifiers over one whitespace run the
  target writes split it every way, so a Content-Type of `charset=` and 16 000 spaces
  took 4.7 s per read: 4.6 s per navigation through the route, and, in disco's
  `carries_value` (no header-size cap), 44.5 s for a 48 KB request Content-Type. The
  pushed tree (7393c90) read it at once: a regression this batch introduced in round 2
  (PA-0549(3c)), fixed in the batch.
- **Fix:** one character class between `=` and the label (`charset\s*=[\s"']*(...)`),
  linear; the labels a header or a meta writes (quoted, spaced) parse as before.
- **Test:** `tests/test_browser_session_reach.py::test_a_charset_label_after_a_long_whitespace_run_is_parsed_in_linear_time`
  (a 200 000-character run in a child with a 60 s bound: fails on 4db0189 at the bound,
  passes in 0.2 s).
- **Correction:** the allow-list decodes by an allowed codec any label Python resolves to
  it, including a few aliases Chromium does not know (`maccyrillic`, `mac_cyrillic`);
  "every other label is unknown" holds for labels outside the allowed codecs only. No
  WHATWG label reaches `mac-cyrillic` (Python cannot resolve `x-mac-cyrillic`): stated with
  the decoder's measured deltas.
- **Flagged, not pinned (pre-existing at 7393c90, outside the gap):** `requests`'
  `Response.text` decodes by the declared charset with the same hazard (punycode slow,
  idna raising) in the session manager, the probe sender, the auditor's fetcher,
  greybox, the blind-SQLi fuzzer, labgen's identifier oracle and the external-lab
  fixtures; the spider's static engine is pinned. One fix point is SP-60's
  `bodyread.bound` setting `Response.encoding` from the same allow-list: a follow-up for
  the owner.
