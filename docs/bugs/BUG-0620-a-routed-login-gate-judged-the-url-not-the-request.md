# BUG-0620 — The routed-login auth gate judged a probe's URL, not the request it sends

- Date: 2026-11-20
- Status: fixed (CC-SESS-0612)
- Severity: high (a safety gate, NFR-FUZZ-safe): a probe of a front controller's login
  page could go out with the run's session.

## Description
CC-SESS-0611 (`f5d47ef`) narrowed `SessionManager.is_auth_endpoint` for a front
controller's routed login (`/index.php?page=login.php`): a URL matched only when it
carried every query pair of the login. But a crawled point's URL is the bare path
(`/index.php`); its route travels in its sibling entries (`page=login.php`), which the
sender places after the gate has judged the URL. The bare URL named no route, so the
gate said "not an auth endpoint" and the login form's probes were sent **with** the
session. Before CC-SESS-0611, path-only matching sent them anonymously.

## Where encountered
The orchestrator's review round 1 of lane PHPX (`d321289`), reading
`_front_controller_route`'s docstring ("a crawled point carries its query as sibling
entries") against the gate's callers. Reproduced: `is_auth_endpoint("…/index.php")` was
False with `…/index.php?page=login.php` recorded.

## What it caused to fail
NFR-FUZZ-safe for a front controller's crawled login form and for a body that routes to
the login (`$_REQUEST`, POST over GET). Not observed in a run: the AFTER runs of
CC-LAB-0343 used ground-truth points (route in the URL), and the crawl run's login form
was not reached by a confirming probe; no account was logged out (no evidence either way
for the crawl run's login-form probes).

## What the bug was identified to be
`SeamProbeSender._send` called `_identity_for(url)` with the URL only; the gate's new
rule read a URL that, for a crawled point, is not the request sent; and an URL naming no
route defaulted to "not the endpoint" (fail open).

## Root cause analysis (Five Whys)
1. Why was the login probe sent with the session? The gate returned False for
   `/index.php`.
2. Why? The narrowed rule needed the URL to carry `page=login.php`, and this URL carried
   no route.
3. Why did the URL lack it? A crawled point keeps its query in `base_entries`; the
   sender binds them after the identity is chosen.
4. Why did the gate not see the entries? Its callers pass a URL only, and I narrowed the
   gate without checking what each caller passes.
5. Why was "no route" not treated as a possible login? The rule was written for the
   inputs I had measured (ground-truth URLs), and its default was "not an auth
   endpoint" -- **root cause: a safety gate was narrowed against the input shape of one
   caller, with a fail-open default for inputs it could not judge.**

## Corrective action
CC-SESS-0612: (a) `_same_routed_page` fails closed: a URL on the router path that names
no route is the auth endpoint; (b) `SeamProbeSender._identity_for(url, entries)` judges
the request as sent (`probesender._as_sent`: the URL with each route pair of its entries,
and the bare URL unless those pairs give it its route); `_send` passes its entries. The
other callers pass a full request URL (`fetch`'s page and route URL, the PRG target, the
health candidates, greybox's request URL): a bare one now fails closed. A routed logout
(`index.php?do=logout`) is refused by SP-09 before any send and is an auth endpoint by
(a). Measured live (CC-SESS-0612).

## Recurrence review
Checked `docs/bugs/` for auth-endpoint and gate bugs (BUG-0112, BUG-0122, BUG-0131,
BUG-0134, BUG-0544) and PA-0083, PA-0112, PA-0131, PA-0134, PA-0138. Same root cause
family: **BUG-0112** (the exclusion existed but the action never consulted it) and
**BUG-0131** (a gate judged a lossy rendering of its input, not the whole input).

## Prior-preventive-action failure analysis
PA-0083(1) puts a gate at the action, and PA-0131(1) has a gate judge its whole input in
its own grammar. The gate was at the action (the send), so PA-0083 held; PA-0131 was
written for texts embedded in URLs and did not name a request whose parts arrive
separately (URL now, entries later) -- too narrow. Neither said what narrowing a gate
requires, and neither demanded a fail-closed default for an input the rule cannot
judge. I also did not follow CLAUDE.md §7 (a change to a shared mechanism sweeps every
caller and what it passes): I swept readers of the finding URL, not the gate's callers.

## Preventive action
PA-0620 (strengthens PA-0083 and PA-0131): a change that makes a safety gate refuse
less (1) judges the request as sent at every caller -- its whole input, every part that
can carry the decisive value -- with a test per caller; (2) defaults to refusing any
input the new rule cannot judge; (3) is measured live with the gate's own counter.
Sweep (PA-0002): every caller of `is_auth_endpoint` checked (above); no other gate was
narrowed in this lane.
