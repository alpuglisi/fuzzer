# BUG-0690 — The M6 browser planted stored XSS without the run's session

- Date: 2026-11-20
- Status: fixed
- Severity: high (every stored-XSS case behind a login is missed on every cookie- or
  token-session target; a false "did not fire" negative fed to the ML stages; no false
  positive)

## Description

In `fuzzlab auto --identity <id> --browser`, the run's HTTP probes carry the identity
through `SeamProbeSender`, but the M6 browser executor (`PlaywrightBrowserExecutor`) was
built by the CLI with no arguments and opened its browser context with no session. Its
stored-XSS plant (`context.request.fetch`, a form or JSON POST) and its observe page load
went out anonymously. On an app whose plant endpoint needs a login, the plant was answered
by a redirect to the login page, nothing was stored, the observe page was the login page,
and the visit returned `executed=False` -- read as "observed, did not fire", a negative.

Sweep finding (same bug class): `greybox_cli._cookie_for` kept only a `Cookie:` session
header and returned `None` for anything else, so a bearer-token identity ran greybox fully
anonymous and a browser login's `Authorization` beside its cookie was dropped.

## Where encountered

Lane NODE, live on OWASP NodeGoat (`lab/external/nodegoat/`, 2026-11-20):
`fuzzlab auto --points ground-truth --identity nodegoat-user --peer-identity nodegoat-peer
--browser --score --authorized` missed NGOAT-0008 (profile stored XSS, plant
`POST /profile`, observe `/dashboard`): the trace's plant step got 302 → `/login` while
the run's other probes to the same URL got 200. Reproduced and measured beyond one lab by
lane XSSPLANT (CC-LAB-0395; numbers there and in CC-FUZZ-0680).

## What it caused to fail

Every stored-XSS candidate whose plant or observe page needs the run's session, on every
lab with a login (NodeGoat NGOAT-0008/NGOAT-0011 class; any cookie- or bearer-session
target), was missed and recorded as a negative. DOM-XSS loads of authenticated pages were
likewise observed logged out.

## What the bug was identified to be

- `fuzzlab/harness/auto_cli.py`: `browser = PlaywrightBrowserExecutor()` -- no session.
- `fuzzlab/tools/browserexec.py::_in_browser`: `browser.new_context(service_workers=
  "block")` adopted nothing; `guard_page(headers=self._headers)` only ever carried a
  test-only `storage_headers`, and even those never reached the plant, since
  `context.request.fetch` bypasses the route.
- The plant's answer was never read: a login redirect was taken as a stored payload.
- `fuzzlab/greybox/greybox_cli.py::_cookie_for`: a non-Cookie session → `None`, no error.

## Root cause analysis

Five whys:
1. Why was NGOAT-0008 missed? The plant `POST /profile` was answered 302 → `/login`, so
   nothing was stored.
2. Why? The plant carried no session cookie: the browser context had none.
3. Why had it none? The executor has no notion of the run's identity: the CLI built it
   with no arguments, and the executor never asked the session layer for anything. Its
   only session input (`storage_headers`) was a header-only hook used by tests.
4. Why did no test or guard catch it? PA-0545(1) ("every send path carries the identity or
   refuses") was enforced by the spider's own tests; the SP-74 wiring guard
   (`reach_offenders`) only inspects modules that already adopt a session, so a context
   that never adopts one is invisible to it; and every M6 test ran an anonymous executor
   against an anonymous page, so the plant's own answer was never asserted.
5. Why was the plant's answer not read? M6 was designed as "execution or nothing" on the
   observe page, and a plant that failed to store was assumed to raise; a 302 is a
   successful HTTP exchange, so it flowed on to an observation of the wrong page.

**Root cause:** a component a run builds that sends to the target got its session (none)
from its own construction instead of from the run's sender, and no whole-package guard
asks every browser context whether it adopts the session or is anonymous by design.

## Corrective action

CC-FUZZ-0680, CC-SESS-0650 (and CC-FUZZ-0681 for greybox):
- `SeamProbeSender.browser_session_route(urls)` (SP-125, FR-SESS-650): the run's sender
  decides the session a visit carries -- its own manager and identity, or anonymous where
  its own gates send a probe anonymously (an auth endpoint, an isolated path).
- `PlaywrightBrowserExecutor(session_route=...)` (FR-FUZZ-680): `_visit_session` adopts the
  route's session through `browserauth.browser_session` / `context_options` /
  `apply_to_context` before the driver starts; `guard_page` gets the session's scoped
  headers, cookie scope and cookies (SP-74); the API plant passes
  `checked_api_request(session_cookies=, cookie_scope=)`, carries the session's headers on
  its own origins only and is refused (not observed, never sent) on another origin.
- `_plant_landed` (FR-FUZZ-681): a form/JSON plant whose answer SP-56 does not class as
  the application's own is `NotObserved`, never a negative.
- `auto_cli` passes `session_route=getattr(sender, "browser_session_route", None)`.
- Greybox (FR-FUZZ-682): `_cookie_for` reads every session header and refuses
  (`SessionAuthError`, a usage error before any side effect) a session it cannot carry
  whole.

Tests: `tests/test_m6_session.py` (real browser, real `SessionManager` and seam sender
on a loopback cookie-session site: plant and observe carry the cookie and execute; the
pre-fix executor's plant arrives without it -- pre-fix proof on that assertion:
`AssertionError: [('POST', '/profile', False), ('GET', '/dashboard', False)]`; the
auth-endpoint and isolation gates; `_plant_landed` per SP-56 class; the CLI wiring);
`tests/test_browser_context_session.py` (the PA-0690 guards); and
`tests/test_greybox_session_carry.py`. Three fake-Playwright doubles that returned `None`
from `context.request.fetch` (never real Playwright's behaviour) now answer 200; the
trace test that pins a status-less double expects `NotObserved`.

## Recurrence review

Checked `docs/bugs/` for send paths that drop or mis-scope a session (BUG-0112, BUG-0113,
BUG-0132, BUG-0134, BUG-0545, BUG-0557, BUG-0559) and `docs/PREVENTIVE_ACTIONS.md`
(PA-0112, PA-0132, PA-0134, PA-0545, PA-0559). **Match: BUG-0545 / PA-0545(1)** -- the
same root cause in another component: the legacy spider's static engine sent anonymously
in an authenticated crawl. BUG-0559 / PA-0559 is related (where a held session may go),
not the same defect.

## Prior-preventive-action failure analysis

PA-0545(1) states the right rule ("an authenticated tool's every send path carries the
identity or refuses, loudly"), but it **was not enforced beyond the spider**: its
`Enforced by` tests are all `tests/test_spider_static_identity.py`, and its PA-0002 sweep
listed the spider's send paths only, so the M6 executor (another component's send path in
an authenticated run) and greybox were never listed. The existing whole-package guard
nearby (SP-74's `reach_offenders`) is **the wrong layer** for it: it checks how a module
that adopts a session wires it, and is silent about a module that adopts none. So the rule
held only where a reviewer remembered it.

## Preventive action

PA-0690 (strengthens and supersedes PA-0545(1)'s enforcement): every browser context
fuzzlab opens adopts the session through the one adoption helper or is declared anonymous
with its reason (whole-package AST guard); every component a run builds that sends to the
target takes its session from the run's sender (every `PlaywrightBrowserExecutor` passes
`session_route=`); a send path that can carry only part of a session refuses loudly; a step
whose answer is not the application's own did not happen.

Sweep (PA-0002), by primitive -- every browser context and every sender a run with an
identity builds (subagent sweep, verified):
- `browserexec._in_browser` -- **dropped the identity; fixed**.
- `spider._start_browser`, `fetcher._start_browser`, `disco/explore._new_context`,
  `spider._isolated_submit` -- adopt the session (unchanged).
- `spider._dry_submit_anonymously`, `spider._submit_anonymously`,
  `browserlogin._drive`, `disco/ede.run` -- anonymous by design, now declared in
  `ANONYMOUS_CONTEXTS` with reasons; API contexts `spider._isolated_request`,
  `explore._new_context`'s isolated request and `_protected_get` are FR-SESS-20 /
  SP-74 cases already guarded.
- `greybox_cli._cookie_for` -- **dropped a non-Cookie identity; fixed (refuses)**.
- Peer accounts, blind-SQLi, mutation, OOB/DB-fault/coverage strategies, plugins -- send
  through a sender built from the run's identity (unchanged).
- Latent, not wired to any CLI: `harness/multitarget.run_targets(browser=)` shares one
  executor across targets; a future caller must give it each target's route (covered by
  the executor guard only at construction). `disco/runner.auth_headers` returns `{}` for a
  malformed operator profile: operator input, not `--identity`; left as an open gap.
