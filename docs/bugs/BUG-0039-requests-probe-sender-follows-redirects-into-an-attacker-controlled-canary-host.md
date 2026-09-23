# BUG-0039 — `RequestsProbeSender.send()` follows redirects, so a real open-redirect confirmation crashes instead of confirming

## Description

While mapping category 5's `open_redirect` vuln class into
`fuzzlab.core.runmode._VULN_TO_CATEGORY` (`CC-CORE-0021`) — the first time
this project has ever attempted a real, live `OpenRedirectStrategy`
confirmation against a real target — a direct reproduction against
Booking.com's real vulnerable twin raised an uncaught `requests.exceptions.
ProxyError`/`ConnectionError` instead of returning a confirmed `Verdict`.

## Where encountered

A standalone reproduction script (`OpenRedirectStrategy().confirm(...)`
against a real, locally-booted `LiveBootHarness` instance for
`LABGEN-BC-0001`, using the real, unmodified `RequestsProbeSender`), run
before drafting `CC-CORE-0021`'s change-control entry, per this project's
own "verify live before landing" discipline (`BUG-0034`'s/`CC-CORE-0020`'s
own precedent for `ssti`'s mapping).

## What it caused to fail

`OpenRedirectStrategy.confirm()` sends a canary URL
(`https://oracle<token>.example/cb`) as the payload and expects the raw
HTTP response's `Location` header back, to check whether it starts with
the canary. `RequestsProbeSender.send()` calls `requests.Session.request()`
with no `allow_redirects` argument, which defaults to `True` — so instead
of returning the 302/301 response itself, `requests` tries to *follow* the
redirect to the attacker-controlled canary host, which this sandbox's
egress proxy (correctly) refuses to reach, surfacing as an uncaught
`ProxyError`. Against a real, unrestricted network the same code would
either hang, error identically on an unreachable canary host, or — worse —
silently return whatever page the redirect happened to resolve to,
misreporting the `Location` header entirely. Every existing caller of
`RequestsProbeSender` (every confirmation strategy, and `fuzzlab.harness.
multitarget`'s own scoring runs) was silently exposed to this on any
target with even one real redirect-based sink, not just `open_redirect`.

## What the bug was identified to be

`fuzzlab.core.http`'s authenticated HTTP client (`SeamProbeSender`'s own
transport) already sets `allow_redirects=False` on every request it
builds — confirmed by reading that module directly. `RequestsProbeSender`
(the standalone, unauthenticated sender — used by every Phase E
`multitarget.py` test and by any unauthenticated confirmation run) never
had the matching setting. This is a real inconsistency between this
project's two `Sender` implementations, not a deliberate difference: no
comment, requirement, or test anywhere records `RequestsProbeSender`
following redirects as intentional.

## Root-cause analysis (Five Whys)

1. **Why did the live reproduction crash?** `requests` tried to connect to
   the confirmation canary's own fake host after following the redirect
   `RequestsProbeSender` never told it to stop at.
2. **Why did `RequestsProbeSender` let it follow the redirect?** Its
   `send()` never passes `allow_redirects=False` to `requests.Session.
   request()`, so the library default (`True`) applies.
3. **Why was this never caught before now?** `RequestsProbeSender` has
   existed and been used by several Phase E `multitarget.py` tests across
   multiple categories, but none of those categories' own manifests
   include a redirect-based sink (`open_redirect` is a category-5-only
   class in this project's corpus) — so no prior real confirmation run
   ever actually exercised a code path that produces a `Location` redirect
   at all. `tests/test_probesender.py`'s own fakes never modeled a
   redirecting response either.
4. **Why did nothing else catch the two senders' inconsistent
   `allow_redirects` handling?** There is no test or contract asserting
   the two `Sender` implementations behave identically for a candidate a
   strategy is scoped to run against either one — each was tested only
   against its own fakes, in isolation, with no cross-implementation
   parity check.
5. **Root cause:** `RequestsProbeSender` was authored without the
   `allow_redirects=False` setting `fuzzlab.core.http`'s own client
   already carries, and no test exercised a redirect-producing response
   against it to surface the gap — first actually reached by this
   project's first real open-redirect confirmation attempt.

## Corrective action

Added `"allow_redirects": False` to `RequestsProbeSender.send()`'s request
kwargs, matching `fuzzlab.core.http`'s own client. Updated
`tests/test_probesender.py`'s `_FakeSession.request()` to accept and
record the new kwarg, and added an assertion that it is always `False`.
Verified against the real reproduction: the vulnerable twin now returns a
real, confirmed `Verdict` (`sink: location-header`, the canary URL), and
the secure twin correctly returns `None`. `pytest tests/test_probesender.py`:
4 passed (up from 2 passed / 2 failed against the unmodified fake).

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of this bug, or a different bug with the same root cause:

- No prior bug or `PA-NNNN` addresses redirect-following behavior, or
  cross-`Sender`-implementation parity, specifically. This is a genuinely
  new failure mode, not a recurrence of an existing one — no
  prior-preventive-action-failure analysis applies.

## Preventive action (`PA-0041`)

Added to `docs/PREVENTIVE_ACTIONS.md`: **when a project maintains more
than one implementation of the same seam/protocol (here,
`fuzzlab.oracle.probe.Sender`: `SeamProbeSender` and `RequestsProbeSender`),
a security-relevant transport setting adopted in one implementation (redirect-
following, TLS verification, timeout behavior, etc.) must be applied to
every other implementation of that same seam in the same change, not left
to be discovered independently per-implementation the first time a vuln
class that happens to exercise it is built.** Sweep (`PA-0002`): grepped
`fuzzlab/` for every class implementing `Sender`'s `send()` signature —
only these two exist; no further instances found.
