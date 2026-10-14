# BUG-0123 — The crawler's browser followed the lab off-origin (github.com)

- Date: 2026-10-14
- Status: fixed (CC-CORE-0044, CC-CRAWL-0015, CC-AUD-0033, CC-FUZZ-0066; sweep: CC-SESS-0020,
  CC-LAB-0253)
- Severity: high (safety). A lab-only tool sent requests to third parties on the open
  web (github.com in the Juice Shop crawl, a public blog in two earlier bWAPP crawls),
  and could reach any other service on the lab host. No credential or session cookie
  left the lab (see "What left the lab").

## Description
The rendered (Playwright) crawler, the auditor's rendered fetcher and the M6 browser
executor confined their browsers by `navguard.guard_page` only, and that guard
(BUG-0111) aborted **destructive** URLs only. Nothing checked where a browser request
went:
- a redirect, a subresource, a script's fetch, a popup, a WebSocket or a preconnect
  could go to any host and any port;
- Playwright never routes a redirect's later hops, so even the destructive check was
  blind to a redirect chain (`/a.php` → `302 /logout.php` was requested);
- the launch arguments did not stop name resolution or Chrome's background traffic;
- the API-request clients (`context.request.post` in the M6 executor, the spider's
  `pw.request.new_context().fetch`) were never scope-checked, and the executor's
  followed redirects.

The link queue was scoped (BUG-0050), but for a loopback start it admitted every
loopback **port**: another local service (the fuzzlab web UI, another lab) was in
scope.

## Where encountered
The first unauthenticated crawl of OWASP Juice Shop v20.3.0 on `127.0.0.1:3000`
(`fuzzlab crawl`, Playwright engine). The SPA links its open redirect
`/redirect?to=https://github.com/juice-shop/juice-shop`. The crawler navigated it, the
browser followed the redirect to github.com, rendered it (491 links parsed) and loaded
`github.githubassets.com` assets; the log line that gave it away was
`blocked destructive browser request https://github.githubassets.com/...install...`.
Further crawls, rendered audits and `--browser` runs were held until this fix landed.

## What left the lab
- **The Juice Shop crawl** (identity none): `GET https://github.com/juice-shop/juice-shop`
  and the github.com page's own subresources from `github.githubassets.com` (12 of them
  were blocked only because their names contain `install`; the rest loaded). Chrome
  sends a cross-origin `Referer` as the origin only (`strict-origin-when-cross-origin`),
  so github learned at most `http://localhost:3000/`. No lab cookie was sent: Juice
  Shop's cookies are host-scoped and the crawl was not logged in. The spider DB holds no
  off-scope row (checked: 0). The sandbox's egress proxy relayed the traffic; its
  status page lists failures only, so it gives no complete record.
- **The forms phase 1 and phase 2 bWAPP crawls** (2026-10-13 and 2026-10-14,
  `127.0.0.1:8090`, identity `user`): bWAPP's `http_response_splitting.php` links
  `?url=http://itsecgames.blogspot.com`, which redirects there. The browser rendered
  that public blog (196 links parsed) and loaded its Blogger CDN assets; one
  `blogger.googleusercontent.com` image was blocked only by a destructive token. The
  bWAPP session cookie is host-scoped (`127.0.0.1`) and was not sent; the `Referer` was
  at most the origin `http://127.0.0.1:8090/`. Both crawls also loaded
  `insecure_iframe.php`, whose iframes point at `http://<container address>/evil/`:
  the lab's own Docker bridge, off-origin but not off the lab.
- **Other bWAPP pages** carry off-host `<a>` links only (not followed by the queue);
  the Google Fonts stylesheet in their head is commented out. The rendered auditor runs
  fetched the same in-lab URLs; the logs show no off-host navigation by them.
- **Test runs:** the existing real-browser tests serve self-contained loopback pages;
  none references an off-host resource.

## What it caused to fail
- **NFR-CRAWL-safe / NFR-AUD-safe / NFR-FUZZ-safe:** the browser path was unconfined
  (scope) and blind to redirect hops (destructive URLs).
- **The project's lab-only rule** (CLAUDE.md "Safety"): traffic left the lab.

## What the bug was identified to be
A scope check placed at the link queue only. Every path that made a request on the
crawler's behalf without passing through the queue (the browser engine, its redirects,
subresources and sockets, the API-request clients) was unchecked.

## Root cause analysis
1. *Why did the browser load github.com?* The redirect target was never checked.
2. *Why not?* `guard_page` checked destructive tokens only. Scope was a link-queue
   property (`LocalSpider._in_scope`), and the browser sends requests the queue never
   sees.
3. *Why did BUG-0111's fix not cover it?* BUG-0111 traced the destructive clause of
   NFR-CRAWL-safe to the browser, and the "no traffic off localhost" clause of
   NFR-FUZZ-safe was marked "Not yet enforced" with a reason about the probe senders.
   The browser's scope was never a traced clause of its own, so its absence failed
   nothing.
4. *Why did the redirect hops escape even the destructive check?* Playwright's
   `route` sees only the first URL of a redirect chain. BUG-0111's real-browser test
   covered subresources and script fetches, not a redirect, so the gap was invisible.
5. *Why was another loopback port in scope?* BUG-0050 made loopback aliases one host
   and ignored the port, so the lab could link `localhost` ↔ `127.0.0.1`; the port was
   never part of the scope decision.

**Root cause:** outbound scope was enforced at one layer (the link queue) instead of
at every place a request is made, and "the target" was a host where it needed to be an
origin; nothing traced each clause of a safety NFR to its own enforcing test.

## Corrective action
- **CC-CORE-0044:** `core.urls.origin_scope(*urls)` and `in_origin_scope(url, origins)`
  are the one browser-scope predicate: canonical scheme, host and port, loopback aliases
  folded on the same port, `ws`/`wss` compared as `http`/`https`.
- **`tools/navguard.py` (CC-CRAWL-0015):**
  - `guard_page(target, ..., in_scope=...)`: `in_scope` is required. It routes the
    **context** (popups included) and WebSockets (`route_web_socket`; an out-of-scope
    socket is never connected). Scope is checked before the destructive rule, and
    `allow` never lifts scope.
  - The handler fetches every allowed request itself with `max_redirects=0` and walks
    a redirect chain hop by hop through the context's request client (sharing its
    cookies), each hop checked for scope and destructive tokens, at most
    `MAX_REDIRECTS`. A redirected GET/HEAD navigation is answered with one redirect to
    its checked landing URL, so `page.url` and relative links stay right (the browser
    then requests the landing page a second time); a chain that keeps a body (307/308)
    and any other request get the landing response itself, so no body is sent twice
    (reviewer B's repro).
  - **These fetches are made by the Playwright driver, not by Chromium** (reviewer A,
    verified live): the resolver rules below never confine them. The route predicate,
    checked before every fetch, is their only guard, so every caller fixes its scope
    before the browser starts.
  - `browser_launch_args(scope_urls, any_port_hosts=())`: `--no-proxy-server`,
    `--host-resolver-rules` mapping each scope `host:port` to itself and everything
    else to `~NOTFOUND` (verified live: it applies to IP literals and other ports), plus
    background networking, pings, DNS prefetch and network prediction off. It confines
    what Chromium itself sends (preconnect, prefetch, re-requested landing pages,
    background services, WebSockets), not the routed requests above.
  - `checked_api_request(in_scope, url)` before every API request; those requests pass
    `max_redirects=0`.
  - `release(context)` silences in-flight handlers at teardown.
- **Spider (CC-CRAWL-0015):** a loopback start's scope is its exact origin (another
  port is another service); an external start keeps BUG-0050's host rule. One
  predicate, `_in_scope`, gates the queue, redirects, the browser route and
  `_isolated_submit`. Out-of-scope browser requests are counted by host and summarised.
- **Auditor (CC-AUD-0033):** `ContentFetcher`'s scope is fixed once (the auth base's
  origin, else the first fetched URL's) and never re-derived (reviewer A: it moved with
  every URL, and the driver's fetches are not resolver-confined). A fetch outside it is
  refused before anything is sent, on both engines. The browser starts on the first
  fetch, with resolver rules for that scope.
- **M6 executor (CC-FUZZ-0066):** launched scoped to the observe and store origins; the
  stored plant is scope-checked and sent with `max_redirects=0`.

## Recurrence review
- **BUG-0111 → PA-0112:** BUG-0111 found NFR-CRAWL-safe unbuilt and built it at the
  queue, the static redirects and a browser route. PA-0112 requires each safety NFR to
  be traced to enforcing code and a test. This bug is a recurrence of the same class
  (a safety property enforced at one layer while another layer sends requests), and a
  second instance of a PA-0112 gap.
- **BUG-0050** (scope by host): the decision that made loopback ports interchangeable.
- **BUG-0114 → PA-0114:** the destructive list widened; same guard, different gap.

## Prior-preventive-action failure analysis
- **PA-0112 was followed but too coarse.** NFR-CRAWL-safe had an `Enforced by:` line,
  so the NFR passed the traceability guard. That line traced the destructive clause;
  the browser's scope was nowhere a clause, and NFR-FUZZ-safe's "no traffic off
  localhost" was recorded as not enforced with a reason that named the probe senders
  only. PA-0112 traced NFRs, not each clause per sending layer.
- **Wrong layer (BUG-0111's fix):** scope was a property of the link queue; the
  browser's request path never consulted it. The first cut of this fix repeated the
  pattern in miniature: the auditor's route scope moved with each fetched URL while
  only the resolver rules were fixed, and those never confine the driver's fetches
  (caught in review).
- **Not tested where it matters:** BUG-0111's real-browser test had no redirect and no
  off-host resource, so neither gap could fail it.

## Preventive action
**PA-0123** (strengthens PA-0112 and PA-0002; related BUG-0050, BUG-0111):
1. Every outbound path, browser-initiated and API-request included, is scope-checked
   where the request is made, never only where the URL was chosen.
2. Scope is an origin (scheme, host, port), via the one predicate.
3. Browsers are confined at the route (context-wide, redirect hops walked) **and** at
   the network (launch arguments), each enforced by an AST guard and a real-browser
   test that fails, never skips, under `FUZZLAB_REQUIRE_BROWSER=1`.
4. Each clause of a safety NFR is traced on its own, per sending layer.

## PA-0002 sweep (by mechanism: every Playwright launch, route, `goto` and API-request call; every `requests`/`urllib` call that can follow a redirect)
| Site | Before | Disposition |
|---|---|---|
| `tools/spider.py` `_start_browser` | unscoped launch, page route, destructive only | fixed (context route, scope, launch args) |
| `tools/spider.py` `_isolated_submit` | API request, not scope-checked (`max_redirects=0` already) | fixed |
| `tools/spider.py` `_in_scope` (loopback) | any loopback port | fixed (exact origin) |
| `tools/spider.py` `_fetch_static` | hand-followed, `_in_scope` per hop | inherits the port-aware scope |
| `tools/fetcher.py` `ContentFetcher` browser | unscoped launch, page route | fixed |
| `tools/fetcher.py` `_static_fetch` | hand-followed, same canonical origin | cleared |
| `tools/browserexec.py` `run` | unscoped launch; plant followed redirects | fixed |
| `session/manager.py` `_post_credentials` | first post-login hop checked, later hops followed by `fetcher.get` (default `allow_redirects=True`) unchecked | **fixed** (CC-SESS-0020): walked by `_navigate`, every hop checked |
| `labgen/identifier_sqli_oracle.py` `default_http_runner`, `_build_url` | `requests.get` followed any redirect; an absolute `endpoint_path` bypassed `assert_loopback` | **fixed** (CC-LAB-0253): same-origin hops only; origin check |
| `session/manager.py` `_navigate` (discovery, `verify_live`, the post-login probe) | hand-walked, `_navigation_ok` per hop | cleared (host-level scope, FR-SESS-13) |
| `core/http.py` `HttpClient` | `allow_redirects=False`; host-level `scope_hosts` | cleared (no redirects; host scope by design) |
| `tools/probesender.py`, `tools/blind_sqli_fuzzer.py`, `greybox/run.py` senders | no redirects; `check_send_url` (destructive), host scope where on the seam | cleared for redirects; the raw senders' missing host scope is NFR-FUZZ-safe's recorded "not yet enforced" clause |
| `proxy/` (engine, Repeater, socket and h2 transports) | forward to any host by design (FR-PROXY-5), loopback listener | cleared (by design, dual-use, default off) |
| `labgen/conformance/*` harnesses | `_NO_REDIRECT_OPENER`, fixed loopback base | cleared |
| `labgen/conformance/django_live_boot.external_http_probe` | `urlopen` follows redirects to a fixed external URL | cleared (an intended external reachability probe of a constant) |
| `labgen` scanner oracles (sqlmap, nuclei, ZAP subprocesses) | `assert_loopback` on the target; hops inside the tools are theirs | residual (outside fuzzlab's control) |
| `tools/pattern_corpus_sourcing.py` (`git`) | fixed or operator remote | cleared (not a target request) |

Stated exceptions to PA-0123(2) (host-level scope): an external crawl (BUG-0050), the
core HTTP seam's `scope_hosts`, and the session's credential and navigation scope
(FR-SESS-12/13); each allows another port on an in-scope host.

The guard is `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`,
proven on synthetic offenders (`test_the_browser_guard_catches_synthetic_offenders`),
with the launch sites pinned (`test_the_launch_sites_are_the_three_known_ones`).

## Residuals
- **A redirected GET navigation's landing page is requested twice:** once while its
  chain is checked, once by the browser. A one-time-token or other stateful GET landing
  sees two requests.
- **The browser's second request to that landing page is not routed.** The resolver
  rules confine it to scope, but if the server now answers it with a redirect the new
  hops are followed natively and not checked for destructive tokens.
- **A 307/308 navigation's `page.url` stays the first URL** (its landing response is
  served under it), so relative links on that page resolve against the first URL.
- **Walked hops carry the context's headers and cookies, not the browser's request
  headers** (only `content-type` is copied). A site whose hop needs `Accept` or a
  custom header may answer differently: coverage, not safety.
- **An auditor whose `--base-url` is on a separate auth origin** refuses every page
  fetch (fails closed, logged "outside the audit scope"): its audit finds nothing.
- **With `--no-proxy-server`, a browser in a container whose only egress is a proxy
  cannot reach an external target at all.** It fails safe; the static engine is the
  fallback.
- **An external (non-loopback) crawl is scoped by host** (BUG-0050): any port, both
  schemes and `www.` stay in scope, at the queue, the route and the resolver.
- **The scanner oracles' own redirects** (sqlmap, nuclei, ZAP subprocesses) are
  outside fuzzlab's control; only their loopback target is checked.
- **Playwright before WebSocket routing** would leave sockets to the resolver rules
  alone; a warning is logged.
