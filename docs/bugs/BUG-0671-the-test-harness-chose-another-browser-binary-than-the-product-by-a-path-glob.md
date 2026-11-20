# BUG-0671 — The test harness chose another browser binary than the product, by a path glob that stopped matching unnoticed

- Date: 2026-11-20
- Status: fixed (lane NAV; CHANGELOG 2026-11-20, CC-CRAWL-0640's deliverables)
- Severity: medium (verification). No traffic or safety rule affected; every browser
  test ran on a binary the product does not launch by default, and switched binary
  without a word when the install layout changed. Paired with BUG-0670, which it hid.
- Records: ERROR_LOG 2026-11-20, PA-0671, F-670; BUG-0670.

## Description
`scripts/verify_change.py::chromium_executable` and eleven test helpers
(`tests/_browser.py::launch_browser_or_skip`, `tests/test_navigation_aborts.py::_chromium_or_skip`,
`tests/_spa_fixture.py`, `tests/test_put_patch.py`, `tests/test_disco_compose.py` (two),
`tests/test_destructive_urls.py`, `tests/test_browser_session_reach.py`,
`tests/test_session_origin_scope.py`, `tests/test_browser_scope.py`,
`tests/test_external_labs_live.py`) each globbed
`/opt/pw-browsers/chromium-*/chrome-linux/chrome` and, on a match, set
`PLAYWRIGHT_CHROMIUM_EXECUTABLE` (or `executable_path`) to it: the **full** Chromium.
The product, with no operator setting, launches Playwright's default headless binary,
the **headless shell** (`navguard.chromium_launch_kwargs` adds an executable only when
the operator set one). So the suite verified another binary than the product runs.

## Where encountered
Lane NAV (2026-11-20), root-causing the five "DID NOT RAISE" failures of
`tests/test_navigation_aborts.py` every lane had carried as known since the container
moved to Playwright 1.63 / build 1243. That build installs
`/opt/pw-browsers/chromium-1243/chrome-linux64/chrome` (measured: `ls /opt/pw-browsers`;
the earlier container's build 1194, ERROR_LOG 2026-10, used `chrome-linux/`). The glob
matched nothing, the harness set nothing, and every browser test launched the headless
shell 157.0.8103.78 instead of the full Chromium.

## What it caused to fail
- Every browser test moved binary silently (full -> headless shell) at the layout change.
- BUG-0670 (an empty 4xx/5xx is a page on the shell, an error page on the full browser)
  surfaced as five unexplained red tests, normalised as "known failures" by every lane,
  instead of as a measured difference between binaries.
- Before the change, the product's default binary was never the one the suite ran, so a
  shell-only behaviour (BUG-0670's) could ship untested.

## What the bug was identified to be
A binary choice made on the test side, by an install-path glob, differing from the
product's choice, and failing open: no match meant "another binary", with no message.

## Root cause analysis (Five Whys)
1. Why did five SP-01 tests start failing with no product change? Their premise (an
   empty 404 commits the error page) holds on the full Chromium only, and they began
   running on the headless shell.
2. Why did they change binary? The glob that pointed them at the full Chromium stopped
   matching when Playwright's layout became `chrome-linux64/`.
3. Why did nothing notice? A no-match fell through to Playwright's default with no
   message; nothing asserted which binary a test ran on.
4. Why did tests choose a binary at all? Each helper (and the harness) carried its own
   copy of "use the pre-installed full build if present", written when the pinned
   Playwright could not find its own build (ERROR_LOG 2026-10, build 1194), and never
   removed when that reason went away.
5. Why was the product's own binary not the tested one? PA-0126 made **product**
   launch sites take their binary from one helper (`chromium_launch_kwargs`), but its
   guard scans `fuzzlab/` only; the test harness and helpers were outside it.
- **Root cause:** a second, test-side binary choice, by a fail-open path glob, outside
  PA-0126's one-helper rule.

## Corrective action
- Every glob removed: the harness sets no binary (`scripts/verify_change.py::pytest_env`);
  the test helpers use the operator's `PLAYWRIGHT_CHROMIUM_EXECUTABLE` if set, else
  Playwright's default -- the product's binary.
- A fact that differs between binaries is measured on each **by name**:
  `tests/_browser.py::CHROMIUM_BINARIES` (`shell`: Playwright's default; `full`:
  `channel="chromium"`), `guarded_chromium(pw, binary, base)`; used by
  `tests/test_chromium_navigation_outcomes.py` and
  `tests/test_navigation_error_answer.py`.
- `tests/test_browser_binary_choice.py`: no Python file in `fuzzlab/`, `scripts/` or
  `tests/` names a browser install path (proved on synthetic offenders; fails on the
  base, d492b9d, on the twelve sites above).

## Sweep (PA-0002)
`grep -rn "pw-browsers\|ms-playwright\|chrome-linux"` over `fuzzlab/`, `scripts/`,
`tests/` (all file types): the twelve sites above, all fixed; none in `fuzzlab/`.
Docs mention paths only in history (bug reports, ERROR_LOG), left as written.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a binary choice that drifted
or a fail-open environment probe: **BUG-0126 / PA-0126** (the M6 executor ignored the
operator's binary: a launch configuration copy that drifted) -- same root cause class
(a second binary choice), product side. Also related: PA-0035 (probe the real
operation) and PA-0065 (a browser test fails, never skips, when it cannot run) --
neither concerns *which* binary runs.

## Prior-preventive-action failure analysis
PA-0126(1) ("every Chromium launch takes its whole configuration from one helper") was
**too narrow in scope**: it named product launch sites, and its guard
(`tests/test_browser_scope.py::test_the_launch_sites_are_the_four_known_ones`) scans
`fuzzlab/` only. The tests then re-made the binary choice themselves (setting the very
environment variable the helper reads) from a path glob, so the product and the suite
used one helper but not one choice. PA-0035/PA-0065 made a missing browser fail loudly,
but a *different* browser passed silently.

## Preventive action
PA-0671 (strengthens PA-0126(1)): the binary a test runs is the product's (the
operator's setting, else Playwright's default); no file of `fuzzlab/`, `scripts/` or
`tests/` chooses a binary by install path; a browser fact that differs between binaries
is measured on each binary by name, and its measurement record names the binary and
version, not only the version.
