# BUG-0754 — The browser guard dropped the page's own request headers on a same-origin redirect hop

- **Status:** open — found and root-caused by lane NEWLABS2-CRAPI (2026-11-20); the
  corrective action belongs to the owner of `fuzzlab/tools/navguard.py`, which this
  lane may not edit. Flagged to the orchestrator.
- **Links:** ERROR_LOG 2026-11-20 (crAPI crawl); PA-0754; CC-LAB-0438; related
  BUG-0559 / PA-0559 (the same hop walk, the session's cookies).

## 1. Description

When a guarded browser page's script sends a request that answers a redirect, the
route handler in `navguard` fetches each hop itself (`route.fetch(max_redirects=0)`,
then `api.fetch(nxt, ...)` per hop) so every hop passes the scope and destructive
checks. The hop's headers are built from scratch: the body's `content-type` (for a
body-carrying method) and `session_headers(nxt)` (the run's session manager's headers).
Every header the page itself set on the request -- an SPA's
`Authorization: Bearer <token>` read from localStorage -- is dropped on the second hop,
also when the hop stays on the same origin. A browser keeps them there (the Fetch
standard strips `Authorization` only on a cross-origin redirect).

## 2. Where encountered

The first crawl of OWASP crAPI (`fuzzlab disco capture --storage-state ...`, run
`crawl1`, CC-LAB-0438). The SPA's contact-mechanic page sends
`GET /workshop/api/mechanic` with its bearer; Django's APPEND_SLASH answers
`301 Location: /workshop/api/mechanic/`; the guard's hop to `/workshop/api/mechanic/`
went without `Authorization` and got 401 (capture: action `harvest-34`, the 301 with
`authorization: __REDACTED__`, the 401 hop with no Authorization).

## 3. What it caused to fail

disco read the 401 as the session being lost (SP-56: an auth failure; unconfirmed, no
session provider) and ended the authenticated exploration: 16 states, **0 actions**, 0
submissions. The crawl run scored tp=0 on crAPI partly for this reason. Any bearer-token
SPA whose API redirects on the same origin (trailing-slash normalisation is a Django,
Rails and many-framework default) loses its session the same way under disco and under
the legacy spider's browser engine (both route through `navguard`).

## 4. What the bug was identified to be

`fuzzlab/tools/navguard.py` (the hop loop around line 750 at 82910aae): `hop =
{"content-type": ...} if keep_body else {}`, then `hop.update(session_headers(nxt))`;
`req.headers` (the page's own request headers) never reach `api.fetch` for a hop.

Measured (2026-11-20, `scratchpad/crapi/cs/redirect_probe.py`, plain Playwright with no
route): a page `fetch('/workshop/api/mechanic', {headers: {Authorization: ...}})` ends
`200`, `redirected: true` at `/workshop/api/mechanic/` -- Chromium carried the header
across the same-origin hop. Through the guard the same hop answered 401.

## 5. Root cause analysis (Five Whys)

1. Why did disco stop exploring? It saw a 401 and took the session as lost.
2. Why a 401? The redirect hop to `/workshop/api/mechanic/` carried no bearer.
3. Why no bearer? The guard re-issues each hop itself and builds its headers from the
   session manager only.
4. Why only the session manager's? The hop walk was written for cookie-session apps
   (BUG-0123, BUG-0559): the browser's jar and the manager's headers were the only
   credentials considered; a credential the page's script attaches per request was not.
5. Why was that not caught? The hop walk's tests use cookie sessions and redirects
   without page-set headers; no test compares a guarded hop's headers with what the
   browser itself sends on the same redirect (no measurement of the browser's
   behaviour was the reference).

**Root cause:** a component that replaces the browser's own redirect handling did not
take the browser's redirect behaviour (which request headers survive a hop) as its
contract.

## 6. Corrective action

Not made here (`navguard.py` is another lane's). Needed: forward the page request's
own headers on a same-origin hop as the browser does (Fetch standard, HTTP-redirect
fetch: `Authorization` removed only when the origin changes; the body's headers kept
only when the method keeps the body), still subject to `session_headers`' scope and the
withheld-host path; a test that drives a page `fetch` with a page-set header through a
same-origin 301 and asserts the hop carries it, and one through a cross-origin 301
asserting it does not.

## 7. Recurrence review

`docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` searched for the hop walk:
BUG-0123 (the browser left the origin: the walk was added), BUG-0559 / PA-0559 (a
browser session was sent by request to hosts its cookies do not reach: the walk's
withheld-host path), BUG-0545 (the legacy spider's loads). None concerns the page's own
headers on a hop; same mechanism (the guard's hop walk), different defect.

## 8. Prior-preventive-action failure analysis

PA-0559 fixed which **session** credentials a hop may carry and where; it did not ask
which **page** headers a hop must keep. Its rule was scoped to credentials fuzzlab
owns, so a credential the app's own script attaches was outside it (too narrow, by
construction). PA-0754 extends the same walk's contract to the browser's own behaviour.

## 9. Preventive action

PA-0754 (docs/PREVENTIVE_ACTIONS.md).
