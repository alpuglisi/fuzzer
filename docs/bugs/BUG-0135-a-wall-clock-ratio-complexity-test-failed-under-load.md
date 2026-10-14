# BUG-0135 — A complexity test asserted a wall-clock ratio and failed under load

- Date: 2026-10-14
- Status: fixed (CC-CRAWL-0027 review amendment)
- Severity: low. No product code was wrong. A test failed on a correct, linear
  scanner, and the same fragile shape had just been written a second time.

## Description
`tests/test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies` (forms
phase 3, CC-CRAWL-0016) checked that `spa.scan_routes` is linear by timing it on 512 KiB
and 1 MiB near-miss bodies and asserting `t_large < 3.5 * t_small`. The FR-CRAWL-17
lane's new `tests/test_spa_query.py::test_the_scan_is_linear_on_4mb_adversarial_bodies`
(8cf7fbe) asserted the same kind of ratio for `spa.scan_query_params`.

## Where encountered
- The FR-CRAWL-17 lane's related-test run: 1 failure out of 577. The test then passed
  5/5 alone, 2/2 in suite order, and in a full re-run of its file.
- The coordinator's run under concurrent lane load: it failed once again. The bound was
  3.5 and the measured ratio about 2.0 in normal runs; under load it went over 3.5.
- Code review round 1 of 8cf7fbe: reviewer B (B-S3) and reviewer A (A-M3) both found it.

## What it caused to fail
The test suite went red without any defect in the code under test. That costs re-run
time, and it teaches people to ignore the test. The ratio test could also pass on a
quadratic scanner when a fast run of the small body and a slow one of the large one
happened to cancel out.

## What the bug was identified to be
A complexity claim (linear time) was tested by comparing two wall-clock measurements on
a shared machine. Scheduler noise, GC pauses and other processes change each timing by
different amounts, so the ratio is not a property of the code.

## Root cause analysis
Five Whys:
1. *Why did it fail?* Other processes or a GC pause slowed the 1 MiB runs more than
   the 512 KiB runs. The ratio went over 3.5 while the scanner stayed linear.
2. *Why could load decide the outcome?* The assertion compared two wall-clock times.
   The code exposed no count of the operations it performs.
3. *Why did the scanner expose no operation count?* Its tests were written to show
   "doubling roughly doubles the time" (reviewer A9's request in forms phase 3). Taking
   "time" literally was the shortest path.
4. *Why didn't PA-0095 stop that?* PA-0095(2) asks for "a test bounding its operation
   count", but it names only "a per-candidate or per-flow path", it does not forbid a
   wall-clock ratio, and nothing checks it. The phase 3 author and then the FR-CRAWL-17
   lane (in this same project, after PA-0095 existed) both wrote a timing ratio.
5. *Why was it not enforced?* PA-0095 came with tests for its own case
   (`tests/test_ml_anomaly.py`'s comparison counter), not with a guard over how
   complexity tests are written.

**Root cause:** the project's complexity rule (PA-0095(2)) asked for operation
counts only for the one kind of code it was written for. It did not forbid the
wall-clock ratio, and nothing enforced it. So "linear" was tested by timing, which
depends on the machine's load.

## Corrective action
In the CC-CRAWL-0027 review amendment:
- `spa.StepCounter` holds a scan's operation counts: `steps` (every character, token
  or loop turn its Python-level walker examines) and `scanned` (the characters its
  `str.find` calls covered, including the bounded window and look-back searches).
- `spa.scan_routes(..., counter=)` and `spa.scan_query_params` (`QueryScan.steps`,
  `.scanned`) report these counts. The query walker also enforces its step budget
  (`MAX_QUERY_STEPS`) with them.
- `test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies` now asserts
  `ops(2n) <= 2 * ops(n) + slack` on both counts. The wall-clock bound stays only as an
  absolute smoke alarm (`< 10 s`).
- `test_spa_query.py`: `test_doubling_a_body_at_most_doubles_the_operations` checks
  every adversarial shape on both counts, with no budget. A second test checks that on
  each 4 MB body the walker stays within its step budget and the finds stay within one
  pass per anchor kind.
- **Proven:** a deliberately quadratic walker fails the oracle on three shapes (the
  window bound removed, `hi = len(text)`). So does a quadratic `scan_routes` (its
  `<Route` look-back made unbounded). Both results are deterministic and do not depend
  on machine load.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0094 / PA-0095:** a quadratic tie count. PA-0095(2) required "a test bounding
  its operation count" on per-candidate or per-flow paths. **Same root-cause family:**
  the right test for a complexity claim is an operation count. This is a recurrence of
  PA-0095's intent, in a place its wording did not name.
- **BUG-0101 / PA-0102:** extended PA-0095 to I/O (byte caps, deadlines). It is about
  bounds, not about how tests measure them. Not a match.
- **BUG-0095 / PA-0096:** typed boundaries with extreme inputs. Not a match.
- No earlier bug about a flaky timing test.

## Prior-preventive-action failure analysis
PA-0095 (from BUG-0094) failed to prevent this for two reasons:
1. **Too narrow.** It named "a per-candidate or per-flow path". The crawler's script
   scanners run once per loaded script, so neither the phase 3 author nor the
   FR-CRAWL-17 lane read the rule as applying to them. It also said what to assert (an
   operation count) but not what to avoid: a wall-clock ratio looked like an acceptable
   stand-in.
2. **Not enforced.** It shipped with tests for its own function only. Nothing fails when
   a test asserts a complexity claim through a timing ratio. Per PA-0020 / PA-0033, a
   rule that depends on remembering to apply it needs a mechanical check.

## Preventive action
**PA-0135** (strengthens PA-0095(2) and supersedes its scope):
1. Every complexity claim ("linear", "bounded", "at most doubles") is tested on an
   **operation count** that the code itself exposes. Wherever the code under test has
   one, it is never tested through a wall-clock ratio. A wall-clock bound is allowed
   only as a generous **absolute** smoke alarm.
2. Code with a complexity claim exposes its operation counts (here `spa.StepCounter`),
   counting both its Python-level steps and the span of its C-level searches.
3. The oracle is proven on a deliberately quadratic variant (PA-0034(2)).
4. Enforced by an AST guard, `tests/test_no_wall_clock_ratio.py`. It fails on any test
   under `tests/` that compares two wall-clock measurements scaled against each other
   (`t2 < 3.5 * t1`), or a ratio of them. Deadlines (`now < start + 10`) and absolute
   bounds stay allowed. The guard is proven on BUG-0135's own lines and on synthetic
   offenders.

**Sweep (PA-0002), by mechanism:** every test under `tests/` that reads a clock, checked
with the guard and by reading each timing assertion:
- `tests/test_spa_routes.py:76` (this bug) and `tests/test_spa_query.py` (8cf7fbe's
  copy): converted to operation counts. Both of their old forms are flagged by the
  guard.
- `tests/test_labgen_ruby_rails_webhook_signature_live_boot.py:183`
  (`naive_late / naive_early > 2.0`, `secure_ratio < 1.5`): **timing, kept.** The
  property under test is a timing side channel, measured by the Ruby process itself
  (`Process.clock_gettime`). It is not a complexity claim, and no operation count can
  express it. It is `slow`-marked. Its load sensitivity is a residual for its component
  (LAB).
- `tests/test_labgen_node_bff_app.py:281/293` (ReDoS floors and ceilings in ms):
  timing is the property under test, and the bounds are absolute. Kept.
- `tests/test_labgen_go_live_boot.py:623` and
  `tests/test_labgen_spring_boot_netflix_session_refresh_live_boot.py:83` (a token
  delta within `elapsed_ns * 50`): checks that a timestamp tracks real time, with a 50×
  slack. Not a complexity ratio. Kept.
- `tests/test_identifier_predicate.py:87` (`< 2.0 s` per ReDoS-shaped value): an
  absolute bound for a regex, whose engine exposes no operation count. Allowed by
  PA-0135(1) as a smoke bound. Kept.
- Deadlines in `tests/test_procutil.py` and
  `tests/test_labgen_spring_boot_absent_input_live_boot.py`, and the absolute bounds in
  `tests/test_proxy_upstream_and_flush.py` and `tests/test_oracle_oob.py`: not
  complexity claims. Kept.
