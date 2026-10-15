# BUG-0149 — Browser egress the route never sees: "a window lets only safe GETs through" was false for four shapes

- Date: 2026-10-15
- Status: fixed (three shapes); one shape open and pinned (a SharedWorker's fetch)
- Severity: high (a safety claim of NFR-CRAWL-safe, FR-CRAWL-16 and FR-CRAWL-17 did not hold)

## Description
The crawler's reveal window (FR-CRAWL-16) and the query windows (FR-CRAWL-17) claim
that inside them "only safe GETs" reach the server: no write, no navigation, no
WebSocket message. The claim was enforced at one layer, the context route
(`navguard.make_route_handler(window=)`) and the WebSocket route. Measured in real
Chromium (1194, Playwright 1.63), four egress shapes never pass that route, so a page
open in a window could still write to the server:
- a `navigator.sendBeacon` made on `pagehide`;
- a `fetch(..., {keepalive: true})` made on `pagehide`;
- `fetchLater(...)`;
- a fetch made by a **SharedWorker** (never routed at all; a dedicated worker's fetch
  is routed).

A `sendBeacon` made while the page is live does reach the route (resource type `ping`)
and was aborted.

## Where encountered
The DISC-CAPTURE lane's mandatory measurement (MULTI_AGENT_ORCHESTRATION §7) before
relying on the route for "capture-and-abort": a loopback server that counts every
request by method, and a context route that aborts every non-GET
(`scratchpad/capture-measure/measure.py`, kept as `tests/test_capture_egress.py`).

## What it caused to fail
Nothing in the suite: no test page used these shapes. On a real app, a reveal or a
query load whose page sends analytics or a "save draft" on `pagehide` (the crawl
leaves every window's page for `about:blank`, which fires `pagehide`) would have sent
that write, while the window's counts said "no write". The same holds for the whole
crawl under capture-and-abort, whose claim is "zero app writes".

## What the bug was identified to be
The guard confined requests where the **route** sees them, and assumed every request a
page can make passes the route. Chromium sends keepalive-class requests made during
page dismissal, and a shared worker's requests, outside the Playwright route.

## Root cause analysis
Five Whys:
1. Why could a window's page write? Its `pagehide` beacon was sent by the browser
   without passing the route that enforces the window.
2. Why did the route not see it? Playwright routes requests of live frames and of
   dedicated workers; a keepalive request outlives its page, and a shared worker is a
   separate target the context route does not attach to (measured; not documented by
   Playwright for these cases).
3. Why was that not known? The window's design listed the request kinds it refuses
   (navigations, fetch/XHR, subresources, WebSockets), not the egress shapes a page can
   use; nothing enumerated "every way a page can send" and measured each.
4. Why was no shape-by-shape test written? PA-0123 required each outbound path to be
   scope-checked "where the request is made" and listed the paths it knew (navigations,
   redirect hops, subresources, popups, WebSockets, API clients). Its real-browser
   tests reach for other ports and hosts, not for writes, and the list was taken as
   complete.
5. Why was the list taken as complete? A browser-confinement rule was stated as a list
   of mechanisms, not as a property ("nothing reaches the server") measured at the
   server for every egress shape.

**Root cause:** a send-side safety claim of the browser guard was verified per
mechanism the guard knew, never as a server-side count over the platform's full set of
egress shapes, so shapes that bypass the route were invisible.

## Corrective action
CC-CRAWL-0032 (capture-and-abort, DISC-CAPTURE phase A):
- `fuzzlab/tools/capture.py::CAPTURE_INIT_JS`, installed in every crawl context by
  `navguard.install_capture_script`: `sendBeacon` becomes a recorder (it returns true,
  sends nothing, and reports the beacon through a binding); `keepalive` is stripped from
  `fetch` (init objects and `Request`s), so the request is an ordinary one the route
  sees and aborts; `fetchLater` throws.
- The WebSocket hold now covers the whole crawl.
- `tests/test_capture_egress.py::test_no_write_reaches_the_server_from_any_egress_shape`
  counts, at a real loopback server, the non-GET requests of each shape (fetch, XHR,
  form POST navigations to self / `_blank` / an iframe, beacons and keepalive on
  `pagehide`, `fetchLater`, a WebSocket message, a dedicated worker, EventSource, a
  307, a GraphQL mutation, a stream body, a multipart upload): zero for each.
- **Open:** a SharedWorker's fetch still reaches the server. It is pinned by
  `tests/test_capture_egress.py::test_a_shared_workers_write_never_reaches_the_server`
  (strict xfail with the measured reason) and its non-vacuity twin
  `test_the_shared_worker_page_is_measured_to_send`, and reported to the coordinator;
  no substitute mechanism was built (mechanism fidelity).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a guard that assumed the route
sees every request:
- **BUG-0123 / PA-0123**: the same root cause one layer apart. Playwright never routes
  a redirect's later hops, and Chromium's own traffic (preconnect, DNS prefetch) never
  passes the route; the guard had assumed the route saw all. PA-0123 fixed those two
  paths and added launch-argument confinement.
- BUG-0111 / PA-0112 (destructive URLs in the browser), BUG-0134 / PA-0134 (session
  per origin): guards at the route, no egress-shape assumption beyond PA-0123's.
- None other.

## Prior-preventive-action failure analysis
PA-0123 (from BUG-0123) did not prevent this because it was **too narrow** and **stated
as a list**: "every outbound path is scope-checked where the request is made: browser
navigations, redirect hops, subresources, popups, WebSockets, and API-request clients".
It enumerated the paths known at the time and its enforcement (an AST guard over launch
and guard sites; real-browser tests for another port and an off-host address) proved
each listed path, not the property. It also scoped the property to *where* a request may
go (scope), not *whether* a write may go at all, so a write that bypasses the route
inside the origin was outside both its wording and its tests.

## Preventive action
**PA-0155** (strengthens PA-0123): a browser send-side safety claim ("no write", "only
GETs", "nothing reaches X") is enforced as a **server-side count** over the platform's
full set of egress shapes, in real Chromium, failing (never skipping) under
`FUZZLAB_REQUIRE_BROWSER=1`; a shape the mechanism cannot close is pinned by a strict
xfail with its measured reason, never omitted; a new egress shape found anywhere joins
that list. Enforced by
`tests/test_capture_egress.py::test_no_write_reaches_the_server_from_any_egress_shape`
and `tests/test_capture_egress.py::test_the_shared_worker_page_is_measured_to_send`.

PA-0002 sweep (by mechanism: every guard whose claim is about what the browser sends):
- the crawl contexts (`spider._guard`, every context the crawl opens, the
  unauthenticated submission context included): fixed (the init script, the capture
  route hook, the crawl-wide WebSocket hold);
- the browser login (`session/browserlogin`): out of scope by design (it must send its
  login POST); its claim is about credentials' destination, enforced by
  `request_refusal`; a `pagehide` beacon there carries no credential the route would
  have refused (residual, stated);
- the M6 executor (`tools/browserexec`): its claim is the opposite (it is meant to
  send probes); no "no write" claim to sweep;
- the auditor's rendered fetch (`audit`): its route refuses destructive URLs only; it
  makes no "no write" claim (residual, stated: an app's `pagehide` beacon there is sent
  as before);
- SharedWorker egress: open in every context (pinned above).
