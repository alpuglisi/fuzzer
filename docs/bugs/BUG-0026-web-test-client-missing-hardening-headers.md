# BUG-0026 — Sibling UI lanes' web tests built a bare TestClient that U6's control-plane hardening middleware rejects

## Description

Four UI build lanes developed concurrently with, and merged after, lane U6 (control-plane
hardening middleware) each wrote their own web test-client fixture as a bare
`TestClient(create_app(cfg))`, with no `Origin`/`Sec-Fetch-Site`/`X-Fuzzlab-Client` headers
and no `base_url` matched to what the app treats as its own address. Once U6's
`ControlPlaneHardening` ASGI middleware (`fuzzlab/web/app.py`) merged into the shared
branch, every one of those bare-client tests started failing: the middleware's Host
allow-list and same-origin gate correctly treat a header-less client request as a forged
cross-origin one and reject it (421/403), exactly as designed — the tests, not the
middleware, were wrong.

## Where encountered

During orchestrated integration of the fuzzlab web-UI parallel build
(`docs/UI_IMPLEMENTATION_PLAN.md`, Wave 0/Wave 1), while rebasing each lane's branch onto
`claude/new-session-3ejtjt` after U6 (control-plane hardening) had already merged.

## What it caused to fail

- `tests/test_web_findings.py` (lane U2, Findings workbench) — 17 of its tests failed
  immediately after rebasing onto the branch tip containing U6.
- `tests/test_web_overview.py` (lane U1, Overview dashboard) — 5 tests failed the same way.
- A sweep (see Preventive action) of the still-unmerged lanes found the identical defect,
  not yet caught by any full-suite run, in:
  - `tests/test_web_ml.py` (lane U4, ML tab)
  - `tests/test_web_diagnostics.py` (lane U5, Diagnostics + store explorer)

`tests/test_web_intercept_browser.py`/`tests/test_web_proxy_history_browser.py` (lane U3)
were checked and are unaffected — they drive a real Chromium instance against a live
server, never construct a `TestClient` directly, so they never hit this defect.

## What the bug was identified to be

Each lane's `_client()`/`_web_client()`-equivalent test fixture called
`TestClient(create_app(cfg))` directly instead of routing through the one shared
`tests/_web_client.py::web_client()` helper — because that helper did not exist yet when
each lane's test file was written. U6 introduced both the middleware and the one fixture
that satisfies it in the same lane, in its own isolated worktree, concurrently with
U1/U2/U4/U5 — none of which could see it.

## Root cause analysis (Five Whys)

1. **Why did four lanes' tests fail against the merged U6 code?** Their `TestClient`
   instances don't send the `Origin`/`Sec-Fetch-Site`/`X-Fuzzlab-Client` headers
   `ControlPlaneHardening` now requires on every request, and don't use a `base_url` the
   middleware's self-derived Host check accepts.
2. **Why don't they send those headers?** Each lane wrote its own bespoke
   `TestClient(create_app(cfg))` fixture independently, with no shared convention to route
   through.
3. **Why was there no shared convention already in place when they were written?** The
   hardening middleware — and the one fixture needed to satisfy it — did not exist until
   lane U6 landed, and U6 was built in a separate, isolated git worktree in parallel with
   U1/U2/U4/U5.
4. **Why did the parallel build allow four lanes to write test-client fixtures unaware of
   a cross-cutting concern a concurrent sibling lane was introducing?** The build-lane
   dispatch (`docs/UI_IMPLEMENTATION_PLAN.md` §1, the orchestration policy) judged lane
   independence at the level of *production* file ownership (each lane's own new
   templates/JS/CSS/routes) and never named the shared *test-infrastructure* contract a
   sibling lane (U6) was about to impose on every other lane's HTTP tests.
5. **Root cause:** the orchestration treated "no two lanes edit the same file" as
   sufficient for independence, but a global ASGI middleware is a cross-cutting contract
   that every test client implicitly depends on regardless of which files it edits — so
   four lanes each wrote locally-correct test fixtures that were never validated against
   U6's gate until they were rebased in after the fact, one lane at a time.

## Corrective action

Switched `tests/test_web_findings.py` (U2), `tests/test_web_overview.py` (U1),
`tests/test_web_ml.py` (U4), and `tests/test_web_diagnostics.py` (U5) to build their
client via the shared `tests/_web_client.py::web_client()` helper — the same convention
U6 already applied to every pre-existing web test file it touched. U1's and U2's fixes
landed in commits `59229d1` and `039e480` respectively (already merged to
`claude/new-session-3ejtjt`); U4's and U5's fixes landed in their own lane commits ahead
of their pending integration. Verified via targeted (`pytest tests/test_web_*.py`) and
full-suite reruns after each fix — all green at the accepted baseline.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of the same
bug, or a different bug with the same root cause. `BUG-0021` also concerns `TestClient`,
but its root cause is thread-affinity of a cached sqlite connection reused across ASGI
worker threads — unrelated to this bug's cause (a missing shared fixture for a new
cross-cutting middleware contract). No prior `BUG-NNNN` or `PA-NNNN` addresses "a
cross-cutting runtime contract introduced by one parallel build lane, silently required
by sibling lanes' tests, that isn't a file-ownership conflict." **None found** — this is a
new bug class, not a recurrence, so no prior-preventive-action failure analysis applies.

## Preventive action

See `PA-0028` in `docs/PREVENTIVE_ACTIONS.md`.
