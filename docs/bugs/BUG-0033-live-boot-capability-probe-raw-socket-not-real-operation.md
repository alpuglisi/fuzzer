# BUG-0033 — `live_boot_available()`'s capability probe tested raw TCP
reachability, not the real, proxied composer-install path it exists to
predict, so a hung real install could pass the probe and then hang the test

- Date: 2026-09-22
- Status: fixed
- Severity: medium (a capability probe reporting "yes, safe to run the real
  operation" when the real operation can actually hang converts a fast,
  honest skip into a silent, indefinite hang of the test suite)

## Description

`fuzzlab.labgen.conformance.live_boot.live_boot_available()` is the one
authoritative capability probe `tests/test_labgen_conformance_live_boot.py`
(and `..._mariadb.py`) gate on via `@pytest.mark.skipif` before constructing
a `LiveBootHarness`, which then runs a real `composer install --no-dev`
against Packagist. The probe's network-reachability check
(`_network_reachable()`) opened a bare `socket.create_connection((host,
443), timeout=5.0)` to `repo.packagist.org` and reported "available" the
instant that raw TCP connect succeeded. That is not the operation the probe
exists to predict: this project's sandboxed CI environment requires outbound
HTTPS to go through a configured proxy (`HTTPS_PROXY`/`https_proxy`, per
`/root/.ccr/README.md`) for the request to actually complete — a bare
`socket.create_connection` to port 443 can succeed (or at least not raise
within the probe's own short timeout) via a path a real `composer install`
does not use, without saying anything about whether the *actual* dependent
operation (composer's own HTTP client, going through the proxy, doing a real
Packagist metadata resolution and package download) will complete in
bounded time.

## Where encountered

Reported via a background lane doing unrelated Phase 2 corpus-collection
documentation work, which incidentally ran a plain `pytest -q` (no `-m "not
slow"` filter) and observed
`tests/test_labgen_conformance_live_boot.py::test_live_boot_forms_manifest_serves_real_pages`
hang indefinitely instead of completing or skipping.

## What it caused to fail

A live-boot test invoked without the `not slow` marker filter could hang the
pytest process indefinitely rather than either running to completion or
skipping cleanly with a clear reason — the two only acceptable outcomes for
a `pytest.mark.skipif`-guarded real-network integration test.

## What the bug was identified to be

`_network_reachable()` (the network half of `live_boot_available()`) probed
a **different, easier operation** (a raw TCP handshake to port 443, no TLS,
no HTTP, no proxy) than the one it gates (`composer install`'s real,
proxied, TLS/HTTP Packagist round trip). The two can and do diverge: a raw
socket connect can report success on a path (direct, unproxied egress) that
a real HTTPS client configured to require the proxy does not take, so the
probe's "yes" was not evidence that the real operation would succeed, let
alone succeed within any bounded time.

## Root cause analysis (Five Whys)

1. **Why did the test hang instead of running or skipping?** Because
   `live_boot_available()` returned `True` (the probe passed) even though
   the real `composer install` this test then ran was not guaranteed to
   complete in bounded time on the environment the reporting lane hit.
2. **Why can the probe pass while the real operation is not bounded?**
   Because the probe (`_network_reachable`) and the real operation
   (`composer install`) use genuinely different network code paths: a bare
   `socket.create_connection` versus composer's own HTTP client, which is
   proxy-aware (respects `HTTPS_PROXY`) and does a real TLS handshake plus
   an HTTP request/response cycle, not just a TCP three-way handshake.
3. **Why weren't they kept in sync — i.e., why does the probe not just call
   composer itself?** Because `_network_reachable()` was written to be a
   *fast, generic* "is the internet reachable" check (mirroring a common,
   reasonable-looking pattern for gating network-dependent tests), not
   specifically re-derived from what `composer install` itself actually
   requires to succeed. A raw socket connect reads as "the least amount of
   work that answers the question," but it answers a related, not the
   same, question.
4. **Why did this gap go unnoticed since `CC-LAB-0054` first introduced
   the probe?** Because in most environments this project runs in
   (including this reporting session's own primary sandbox, where this bug
   could not be reproduced on demand — see the Corrective Action section)
   raw TCP reachability and full proxied HTTPS-through-composer reachability
   agree: either both work or both fail. The divergence is a property of a
   *specific* sandbox network configuration (egress that completes a raw
   TCP handshake but does not carry a real, unproxied TLS session to
   completion, or does so far more slowly than the probe's 5-second
   timeout allows) — exactly the kind of environment-conditional gap a
   capability probe exists to catch, but this one didn't, because it wasn't
   testing the actual dependency.
5. **Root cause.** The capability probe was built as a **proxy signal**
   (literally: a stand-in measurement believed to correlate with the real
   capability) rather than by **exercising the actual operation path**
   end-to-end through the same client/transport the real, gated operation
   uses. A proxy signal is only as good as the correlation holding in every
   environment the probe runs in, and this project's own sandboxed CI
   environment is exactly a case where it does not hold (a proxy-only
   egress topology the raw-socket check cannot observe).

## Corrective action

`fuzzlab/labgen/conformance/live_boot.py` (`CC-LAB-0059`/`FR-LAB-56`):

- Replaced `_network_reachable()` (a bare `socket.create_connection`) with
  `_composer_network_probe()`, which runs `composer show -a --no-interaction
  psr/log` from a scratch cwd (no local `composer.json`/lockfile touched) —
  the cheapest composer subcommand that still performs a real Packagist
  metadata round trip through **composer's own HTTP client**, the same
  client and the same proxy-honoring code path `composer install` itself
  uses. `live_boot_available()` now gates on this instead.
- The probe enforces its own bounded timeout
  (`NETWORK_PROBE_TIMEOUT_S = 20.0`, overridable) via `subprocess.run`'s
  `timeout=`, and treats a `subprocess.TimeoutExpired` (or any `OSError`
  starting the process) as `False` — unavailable/skip, never a raised
  exception and never a hang.
- `_run()` (every real subprocess step of the live-boot pipeline —
  `composer install`, `artisan key:generate`) now wraps
  `subprocess.TimeoutExpired` in a clear `LiveBootError` naming the command
  and elapsed bound, instead of letting it propagate uncaught. Every call
  site already passed an explicit `timeout=` (`composer install`:
  `install_timeout=240.0`; `artisan key:generate`: `30.0`), so this is a
  clarity fix, not a new timeout — PA-0035 (below) requires this bounded-
  and-error-clearly discipline to be **enforced at the shared helper**,
  never left to each call site to remember correctly on its own.
- New regression coverage:
  `tests/test_labgen_conformance_live_boot_probe.py` (7 tests, not
  skip-guarded — they exercise the probe's and `_run`'s own
  failure-handling via monkeypatched `subprocess.run`, so they must run on
  every host, including one with no composer/php/network at all):
  probe-returns-`False`-on-timeout (direct regression for this bug's own
  failure mode), on missing composer, on a real nonzero exit; probe passes
  its `timeout=` through to `subprocess.run` (never relies on composer's
  own internal timeout); `_run` turns a `TimeoutExpired` into a
  `LiveBootError` rather than propagating it or hanging; `_run`'s normal
  pass-through path is unchanged.

## Verification / reproduction note

The reported hang could **not** be reproduced on demand in this session's
own primary sandbox: `python3 -m pytest -q
tests/test_labgen_conformance_live_boot.py::test_live_boot_forms_manifest_serves_real_pages`
ran to completion in ~21s, and a direct raw-socket-vs-proxied-TLS comparison
(`socket.create_connection` to `repo.packagist.org:443`, then a real TLS
handshake and HTTP request over that same raw socket, then `composer
diagnose`) all succeeded quickly in this particular sandbox instance. This
is consistent with the Five Whys' step 4 finding: the divergence is a
property of a *specific* sandbox network topology (this reporting lane's),
not a deterministic, always-reproducible defect in this one — reported
honestly as intermittent/environment-state-dependent, investigated instead
via code reading (confirming `_network_reachable()`'s mechanism genuinely
differs from `composer install`'s, and confirming via `composer diagnose`'s
own output in this session's sandbox that composer's real connectivity
check explicitly goes through a configured `HTTP proxy with https` step
that a bare `socket.create_connection` cannot observe at all). The fix does
not depend on reproducing the hang: it removes the raw-socket proxy signal
unconditionally, in favor of exercising the real client on the real
dependency, which is correct regardless of whether this particular sandbox
happens to also pass the old check.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause,
before deciding the preventive action.

- **`BUG-0028`** (this module's only prior bug report,
  `docs/bugs/BUG-0028-live-boot-harness-silently-followed-redirects-and-lacked-eloquent-timestamp-columns.md`)
  is in the same module and shares the general family "this harness's
  behavior diverged from what it claims to prove," but its actual mechanism
  is different: BUG-0028 was about the harness **silently transforming an
  already-obtained real response** (redirect-following) and **a seeded
  fixture missing columns a real dependent behavior needed** — both post-
  hoc, applying to a request/response the harness had already begun to
  serve. This bug is about a **pre-flight capability probe** measuring the
  wrong operation entirely, before any request is ever sent. Same module,
  same general "verify what you claim" spirit, but a genuinely different
  defect shape — not a strict recurrence of BUG-0028's specific mechanism,
  so this report does not treat it as one.
- **PA-0025** ("a tool-oracle wrapper... must independently verify... that
  the tool actually reached and exercised the target, never infer 'secure'
  purely from the absence of a positive match") is the closest existing
  doctrine in spirit: both are "a wrapper's conclusion must reflect what the
  real underlying thing actually did, not be inferred from an easier-to-
  observe stand-in." PA-0025 is explicitly scoped to *tool-oracle output
  classification* (a security tool's exit code/absence-of-match, e.g.
  sqlmap/commix), not to a pre-flight environment-capability probe gating
  whether a test even runs. Extending PA-0025's literal wording to cover
  probes would stretch its stated scope past what it was written to police
  (exactly the same reasoning `BUG-0028`'s own recurrence review used to
  decline stretching PA-0025 there); this report instead writes a new
  preventive action that names the shared doctrine explicitly and applies
  it to this new probe shape.
- **PA-0030** ("a harness... must not silently apply a client default that
  transforms what the server actually sent") governs *response* fidelity
  once a real operation has already run; it does not address whether a
  *pre-flight* probe accurately predicts that the operation will run at
  all. Not the same mechanism.
- No prior `BUG-NNNN`/`PA-NNNN` addresses a capability probe that exercises
  a different, easier operation than the one it gates. This is a new
  preventive action (`PA-0035`), not a strengthening of an existing one —
  though it explicitly generalizes PA-0025's fail-closed "verify the real
  thing, not a proxy for it" doctrine to a new context (capability probes),
  the way PA-0028/PA-0029/PA-0030 each already generalize an earlier PA to
  a new context without literally superseding it.

## Preventive action

**PA-0035** (new) — recorded in `docs/PREVENTIVE_ACTIONS.md`; see that file
for the full text and the PA-0002 sweep this bug's fix performed.
