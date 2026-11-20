# BUG-0651 — Every pre-installed Chromium lookup named one layout and silently fell back

- Date: 2026-11-20
- Status: fixed
- Severity: low (the tests still ran, on Playwright's own browser lookup)

## Description
Eleven test helpers and `scripts/verify_change.py` look for a pre-installed Chromium with
`/opt/pw-browsers/chromium-*/chrome-linux/chrome` and, when found, pin it through
`PLAYWRIGHT_CHROMIUM_EXECUTABLE`. Playwright's builds since 2025 install under
`chrome-linux64/`, so on such an image every lookup matched nothing and the pin was
silently skipped.

## Where encountered
Lane PERF's container (`chromium-1243/chrome-linux64/chrome`), found by the subagent
writing `tests/test_m6_slow_sinks.py` (BUG-0650's regression tests).

## What it caused to fail
Nothing visible: each real-browser test ran on whatever Chromium Playwright itself
resolved (here the same build 1243). The helpers' intent -- run the operator's
pre-installed binary, the one the harness reports -- was unmet, and nothing said so; on
an image whose Playwright expects a build that is not installed, the tests would have
skipped or failed although a usable binary was present.

## What the bug was identified to be
A path literal for one install layout, copied into twelve places instead of one lookup.

## Root cause analysis (Five Whys)
1. Why was the pin skipped? The glob matched no file.
2. Why? The binary is under `chrome-linux64/`, the glob names `chrome-linux/`.
3. Why did nothing notice? A miss falls through to Playwright's own lookup, which found
   a browser, so every test passed.
4. Why twelve copies? Each browser test file wrote its own lookup (PA-0003's
   one-implementation rule was not applied to test helpers).
5. **Root cause:** a platform fact (Playwright's install layout) was hard-coded, unmeasured
   on the image in use, and its failure mode was silent.

## Corrective action
Every lookup now globs `chromium-*/chrome-linux*/chrome` (both layouts): the eleven test
helpers and `scripts/verify_change.py`. Guard: `tests/test_chromium_glob_guard.py`.

## Recurrence review
Checked `docs/bugs/` and `PREVENTIVE_ACTIONS.md` for a platform path or capability probe
that fell through silently: PA-0035 / PA-0065 (probe the real operation; under
`FUZZLAB_REQUIRE_BROWSER=1` a skip is a failure) and PA-0126(1) (one launch helper for
Chromium's configuration). None names the binary lookup; PA-0126(1) covers the launch
kwargs (which read `PLAYWRIGHT_CHROMIUM_EXECUTABLE`), not how tests find the binary.
Not a recurrence of the same bug; the same family as PA-0035 (a proxy check standing in
for the real operation). No prior PA failed here.

## Preventive action
PA-0651: a lookup of a pre-installed browser matches every layout the pinned Playwright
range installs, enforced by a whole-package guard proven on a synthetic offender. PA-0002
sweep: done (twelve sites, all fixed; none in `fuzzlab/`).
