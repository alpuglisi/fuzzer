# BUG-0049 — the `FzlCoverage` grey-box middleware's `db_fault` never fired, because Laravel's `Illuminate\Routing\Pipeline` renders a controller `QueryException` to a 500 response before it can propagate back to the middleware's `catch`

## Description

The grey-box side channel (`FzlCoverage` middleware, T3.1/T3.4) is supposed to
set `db_fault=true` in its per-request JSON file when a request triggers an
error-based SQL fault, so error-based SQLi separates from benign traffic
(Phase 3 exit, `ON_HOST_RUNBOOK.md` Part E, T3.7). It never did: an error-based
SQLi on `/login.php` (`username='`) returned HTTP 500 with a real SQL syntax
error, yet the written side-channel file always carried `db_fault=false`,
`db_error=""`. `greybox_e2e.sh`'s step-3 self-test caught it and aborted:

```
FAIL: error-based SQLi did not set db_fault — check that the app throws on SQL errors
```

## Where encountered

On-host run of `ON_HOST_RUNBOOK.md` Part E, 2026-09-24, after fixing the
readiness gate (`BUG-0048`) let the self-test run at all.

## What it caused to fail

The Phase 3 grey-box exit (T3.7) could not be met: "error-based SQLi is
distinguishable via `attempt.db_fault`" was structurally impossible, because
`db_fault` was always 0. (Coverage-novelty reward still worked; only the
DB-fault half was dead.) The auto oracle's own HTTP-level error-signature
detection is independent of this side channel and was unaffected.

## What the bug was identified to be

The middleware wrapped `$next($request)` in `try { … } catch (QueryException)`
and relied on the exception *propagating out of `$next()`*. Under Laravel, the
HTTP kernel runs global middleware through `Illuminate\Routing\Pipeline`, whose
per-stage `carry()` wraps the inner dispatch in its own `try/catch` and calls
`handleException()` → the exception handler's `render()` **at the innermost
router-dispatch boundary**. So a controller `QueryException` is caught and
converted to a 500 `Response` *below* `FzlCoverage` in the call chain;
`FzlCoverage`'s `$next($request)` therefore *returns a Response, never throws*,
and its `catch (QueryException)` can never run. The migrated controllers go
through the query builder / `whereRaw()` exactly as intended (the vulnerable
`/login.php` cell `whereRaw("username = '".$username."'")` genuinely throws) —
the detection *mechanism*, not the vulnerability, was wrong for the framework.

## Root cause analysis (Five Whys)

1. Why was `db_fault` always false? The middleware's `catch (QueryException)`
   around `$next()` never executed.
2. Why did it never execute? `$next($request)` returned a (500) Response instead
   of throwing.
3. Why did it return instead of throw? Laravel's `Illuminate\Routing\Pipeline`
   catches the controller exception at the innermost dispatch boundary and
   renders it, so no exception unwinds back up through the global middleware.
4. Why did the middleware assume propagation? It was a direct re-homing of the
   hand-built app's `includes/cov.php` shim, which caught a raw PHP
   `mysqli`/fatal that *did* propagate; the Laravel equivalent's exception
   *does not* reach global middleware the same way, and that framework
   difference was not accounted for when the shim became middleware in the
   `L-P3.3c-CUT` cutover.
5. **Root cause:** a fault-detection mechanism was ported from one runtime
   (raw PHP, exceptions propagate to the outer handler) to another (Laravel,
   the routing pipeline intercepts and renders controller exceptions
   internally) on the assumption that "an uncaught exception propagates to my
   `catch`" holds in both — it does not, so the ported mechanism silently
   observed nothing.

## Corrective action

- Capture the fault where Laravel actually surfaces it: registered an
  `$exceptions->report(function (\Illuminate\Database\QueryException $e) …)`
  hook in `bootstrap/app.php` (the handler *does* invoke `report()` for the
  exception — it was already being logged), which records the message into a
  request-scoped static `FzlCoverage::$dbError`.
- `FzlCoverage::handle()` resets that static before `$next()` and, after
  `$next()`, sets `db_fault`/`db_error` from it. The original `try/catch` is
  kept only as belt-and-suspenders for an exception that genuinely propagates.
  The report callback returns void (does not return `false`), so Laravel's
  default exception logging is unchanged; both pieces are self-gated on the
  `X-Fzl-Cov` header, so the default app and every ground-truth label are
  unaffected.
- Verified live: benign `product.php?id=1` → `db_fault=false`; error-based SQLi
  on `login.php` → `db_fault=true` with the SQL message captured. Part E then
  passes its T3.7 exit (payload reward 0.969 > baseline 0.200; `db_fault=1` on
  `sqli-error`/`sqli-boolean` attempts). See CC-LAB-0236.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. Prior grey-box bugs
exist — `BUG-0009` (fragile pcov *name-string* capability guard) and `BUG-0016`
(new-code reward starved by a global frontier; its PA: "a diagnostic must key on
the actual condition it names"). Both are in this subsystem but have different
root causes: `BUG-0009` was a capability *probe* using a brittle string;
`BUG-0016` was a reward-shaping baseline; neither concerns a fault-detection
mechanism that assumes a framework's exception-propagation model. This is a new
root cause. Notably, `BUG-0009`'s preventive discipline *worked here*: the
`greybox_e2e.sh` self-test (which BUG-0009 hardened into a loud, capability-
verifying check) is exactly what surfaced this bug instead of letting Part E
silently report a dead signal.

## Preventive action

**PA-0051** (see `docs/PREVENTIVE_ACTIONS.md`) — when porting an
observation/interception mechanism across runtimes or frameworks, verify the
control-flow assumption it depends on (here: "an unhandled exception propagates
to my outer `catch`") actually holds in the destination — frameworks that
render exceptions internally (Laravel's routing pipeline) break it; prefer the
framework's own surfacing hook (`report()`), and keep a capability self-test
that fails loud when the signal is dead.
