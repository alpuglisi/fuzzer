# BUG-0060 — UA/Accept/Accept-Language mismatch causes real 403s from external WAFs (second recurrence of BUG-0059's root cause)

- Date: 2026-09-25
- Status: fixed
- Severity: medium (crawl/audit/probe traffic against an affected target is outright
  rejected with `403`, worse than BUG-0059's silent-empty-response symptom)

## Description

After `BUG-0059`'s fix (setting a realistic `User-Agent`), a crawl from the web UI
against a real external, authorized test target started returning `403 Forbidden`
instead of the earlier `200`-but-`0`-links symptom.

## Where encountered

Reported live by the operator, running the crawler (via the web UI) against their own
external authorized test lab, on a local machine (not this sandbox).

## What it caused to fail

Every request to the affected target is rejected outright (`403`), which is worse for a
caller than `BUG-0059`'s silent empty result — but it is the same underlying gap
surfacing one layer further in: this target's protection checks more of the request
than just the `User-Agent`.

## What the bug was identified to be

`BUG-0059`'s fix set `User-Agent` alone, leaving every other header at `requests`' own
defaults: `Accept: */*` and no `Accept-Language` at all. Verified directly (constructing
a `requests.Session` with the fixed UA and inspecting the prepared request headers):

```
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

A `User-Agent` claiming Chrome, paired with `Accept: */*` and no `Accept-Language`, is
an internally inconsistent request no real Chrome browser ever sends (a real Chrome
navigation sends a specific multi-type `Accept` list and an `Accept-Language`). This
exact mismatch is a documented signal several WAF/bot-mitigation products (Cloudflare,
Akamai, PerimeterX, and similar) check for and block outright, independent of the UA
string itself being a plausible one — explaining why fixing only the UA moved the
target's response from silently serving reduced content (`BUG-0059`) to actively
rejecting the request (`403`, this bug).

## Root cause analysis

Five Whys:
1. Why did the crawl get a 403 after the UA fix? The target's WAF rejected the request.
2. Why did the WAF reject it? The request's `Accept`/`Accept-Language` headers did not
   match what its claimed `User-Agent` (Chrome) would actually send.
3. Why was only the `User-Agent` fixed and not the other headers? `BUG-0059`'s own
   investigation stopped at the first, most obviously fingerprintable header
   (`requests`' UA is the most famous of these) without checking whether `requests`'
   *other* default headers were equally inconsistent with a real browser.
4. Why wasn't this caught in `BUG-0059`'s own verification? That fix's verification was
   offline only (this sandbox cannot reach arbitrary external hosts); the UA-only fix
   was plausible and fixed the originally-reported symptom's most visible cause, but was
   never checked against a header-consistency-aware WAF, which only a real external
   target the operator subsequently tried surfaced.
5. Why is this a systemic gap, not one target's peculiarity? Every bare
   `requests.Session()` this codebase creates inherits the same defaults
   (`Accept: */*`, no `Accept-Language`) regardless of what `User-Agent` is set on top —
   the gap is in `requests`' own baseline, not anything target-specific.

**Root cause:** `BUG-0059`'s preventive action (`PA-0061`) was scoped to "set a
realistic User-Agent," not "make every header of the request internally consistent with
a real browser" — a narrower fix than the actual gap (client fidelity as a whole, not
one header). The same root cause (a bare `requests.Session()` fingerprintable as
non-browser traffic) produced a second, distinct symptom once one layer of it was
patched.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Match found (same root-cause
class, direct recurrence): `BUG-0059`/`PA-0061`.** `PA-0061`'s own wording ("set a
realistic User-Agent") is the prior preventive action that did not prevent this
recurrence — it fixed the most visible instance of "this client doesn't look like a
browser" without generalizing to "this client's headers, taken together, must look like
a browser's."

## Prior-preventive-action failure analysis

`PA-0061` correctly identified the bug *class* (bare `requests.Session()` instances
fingerprintable as non-browser traffic) and correctly found and fixed all 6 call sites
of it, but scoped the *fix* too narrowly — to the `User-Agent` header specifically,
because that was the header the original symptom (`BUG-0059`) most directly implicated.
It did not ask "what else does `requests` leave at a non-browser default that a real
browser would also set," which is exactly the gap this bug exploits. The new preventive
action below supersedes `PA-0061` by re-scoping the rule to the full, internally
consistent header set, not one header in isolation.

## Corrective action

Replaced the single `DEFAULT_USER_AGENT` string's direct use with a new
`fuzzlab.core.http.DEFAULT_BROWSER_HEADERS` dict (still built on the same UA string,
now alongside a matching `Accept`, `Accept-Language`, `Sec-Fetch-*` set, and
`Upgrade-Insecure-Requests`) applied via `session.headers.update(...)` at all 6 of the
same call sites `BUG-0059`/`PA-0061` already fixed: `fuzzlab/tools/spider.py`,
`fuzzlab/tools/fetcher.py`, `fuzzlab/tools/blind_sqli_fuzzer.py`,
`fuzzlab/tools/probesender.py`, `fuzzlab/greybox/run.py`, `fuzzlab/session/manager.py`.

Verified offline: re-inspected the prepared request headers from a `DEFAULT_BROWSER_HEADERS`-configured
session — `Accept`, `Accept-Language`, and the `Sec-Fetch-*`/`Upgrade-Insecure-Requests`
set are now present and consistent with the UA. `tests/test_spider_scope.py` (12),
`tests/test_probesender.py`, `tests/test_session_manager.py`, `tests/test_greybox.py`,
`tests/test_greybox_live.py`, and `tests/test_oracle_greybox.py` (83 total across these
six) all pass unchanged. Live re-verification against the operator's own external
target that returned the `403` is the operator's own follow-up (this sandbox's outbound
network is proxied/restricted).

Scope note: this and `BUG-0059` both make this project's own HTTP clients look more
like a real browser to a target the operator owns or is otherwise authorized to test
(per this project's own D11/lab-only policy) — confirmed with the operator directly
before implementing, since a header-consistency fix aimed at defeating WAF
fingerprinting is dual-use and requires that authorization context.

## Sweep (PA-0002)

Same 6 call sites as `BUG-0059`'s own sweep (`spider.py`, `fetcher.py`,
`blind_sqli_fuzzer.py`, `probesender.py`, `greybox/run.py`, `session/manager.py`) — all
already route through the one shared constant, so widening that constant's content
(rather than adding new call sites) closes this gap everywhere at once. No further bare
`requests.Session()` instances found beyond the ones `BUG-0059` already enumerated.

## Preventive action

`PA-0062` (see `docs/PREVENTIVE_ACTIONS.md`) — supersedes/strengthens `PA-0061`.
