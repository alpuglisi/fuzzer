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

## Correction (2026-11-20, after the merge harness of d565523)
"What it caused to fail: nothing visible" was wrong. With no binary pinned, Playwright
launched its own headless shell (`chromium_headless_shell-1243`), not the full Chrome
build, and five `tests/test_navigation_aborts.py` tests fail there
(`test_a_failed_navigation_returns_after_its_own_error_page[1-3]`,
`test_a_navigation_overtaken_by_an_error_page_waits_for_it`,
`test_an_error_page_ends_the_previous_document`). Lanes NODE, PHPX and PERF reported them
as "known failures" from a newer Chromium; ERROR_LOG 2026-11-20 (b) put them down to
Playwright 1.63 / Chromium 1243 against SP-01's 1.56 / 141 measurement. Measured: on tree
2be7a50, unchanged, with `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/opt/pw-browsers/chromium-1243/
chrome-linux64/chrome`, `tests/test_navigation_aborts.py` passes 89 of 89; the harness of
d565523 (this fix merged with 7a1ef32) is 114 files, 4568 passed, 0 failed. Severity is
medium, not low: the fall-back changed which browser five SP-01 tests measured.

## Superseded (2026-11-20, merging the integration tip 9cabe61)
Superseded by lane NAV's BUG-0670 and BUG-0671 (PA-0670, PA-0671), which found the same
lookup and measured further. The root cause above and the "Correction" are both
incomplete:
- **The tests' binary choice was wrong, in either direction.** The product, with no
  operator setting, launches Playwright's default binary, the **headless shell**. The
  globs pointed the suite at the **full** Chromium, a binary the product does not run;
  this fix (931311b) re-aimed them there. BUG-0671: a test launches the product's binary
  and measures a binary difference on each binary by name, never chooses one by install
  path (guard: `tests/test_browser_binary_choice.py`).
- **The product was broken on its default binary.** On the headless shell an empty-body
  4xx/5xx answer loads as a normal page instead of failing onto an error page, so SP-01's
  guarantee did not hold where the product runs (BUG-0670). The five
  `test_navigation_aborts` failures were that product defect showing through, not only a
  test artefact; pointing the tests at full Chrome would have hidden it. NAV fixed the
  product (`navguard` aborts a guarded top-level empty-error answer, so both binaries show
  the error page).
- Resolved at the merge in NAV's favour: 931311b's glob change in the eleven test helpers
  and `scripts/verify_change.py` is dropped (NAV's versions kept),
  `tests/test_chromium_glob_guard.py` is deleted (NAV's guard flags any install path),
  `tests/test_m6_slow_sinks.py` launches the product's binary, PA-0651 is marked
  superseded by PA-0671.

