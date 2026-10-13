# BUG-0063 — No chart in the control panel ever rendered: `chart.js` passed uPlot two class tokens

- Date: 2026-10-13
- Status: fixed
- Severity: medium (every chart on the ML and Diagnostics tabs was blank, and on the ML
  tab the first throw also blanked every later panel, including tables. Advisory/
  diagnostic UI only: no store data, finding or label was affected.)

## Description
`fuzzlab/web/static/js/chart.js::createChart`, the shared charting layer (FR-UI-12),
passed uPlot the option `` class: `fl-chart fl-chart--${type}` ``. uPlot 1.6.32 treats
`class` as one class token. `addClass(root, opts.class)` calls `classList.add(c)`
(`static/vendor/uplot/uPlot.esm.js:85-90`, called at `:2940`), so a value with a space
throws `InvalidCharacterError`. `new uPlot()` therefore threw for **every** chart.

## Where encountered
Found on 2026-10-13 while browser-checking `CC-UI-0035` (ML tab labels). The page was
rendered in real Chromium (`/opt/pw-browsers/chromium`) against a seeded store:
- `/ml`: 0 `.uplot` charts, plus the page error "Failed to execute 'add' on
  'DOMTokenList': The token provided ('fl-chart fl-chart--line') contains HTML space
  characters".
- `/diagnostics`, after picking a run and a metric: the same error, 0 charts.
- The same results on a worktree of `origin/main` @ `0800e42`, so the bug predates that
  session's changes. It has been present since the charting layer was added in
  `CC-UI-0031` (2026-09-22).

## What it caused to fail
- **ML tab:**
  - None of the ten charts rendered: reliability, PR curve, rank bars, score and
    uncertainty histograms, the scatter, the conformal split and its histogram, the
    anomaly and disagreement histograms, and bandit density.
  - `initMl` calls the panel renderers in sequence. The throw inside the first
    (`renderClassifier`) therefore aborted the rest, so ranker, conformal, anomaly,
    disagreement, bandit and mutation never rendered at all, tables and summaries
    included.
- **Diagnostics tab:** the cross-run trend chart and the intra-run series chart never
  rendered.
- **Hidden behind the first throw:** these surfaced only once it was fixed, and are
  fixed in the same change:
  1. `diagnostics.js` passed its own x-series (`[{}, …]` / `[{}]`), which
     `createChart` already prepends. The result was one series more than there were
     data columns, so uPlot threw "reading 'length'", and the y series was mislabelled.
  2. The series chart drew step indices as timestamps (no `scales.x.time = false`).
  3. Both Diagnostics charts passed `ariaLabel`, an option `createChart` never reads
     (it reads `caption`), so they had no accessible name.
  4. `chart.js` set the mount's label only once. Diagnostics reuses its mount for every
     metric, so it would have kept the first metric's name.
  5. `chart.js` gave each mount `role="img"`. An `img`'s children are presentational,
     which hid the visually hidden data table, built for screen-reader users, from
     assistive tech.

## What the bug was identified to be
An adapter around a vendored library (`chart.js` around uPlot) passed an option in a
shape the library does not accept (two tokens where uPlot expects one class name). Two
callers (`diagnostics.js`) then misused the adapter's own contract. None of this code
had ever been executed in a browser by any test.

## Root cause analysis
Five Whys:
1. Why did no chart render? `new uPlot()` threw on construction.
2. Why did it throw? `chart.js` passed a value uPlot's `class` option does not accept
   (a space-separated pair, where uPlot calls `classList.add` once).
3. Why did that ship? The charting layer (`CC-UI-0031`) was checked only through
   Python `TestClient` tests of the `/api/ml/data` payload and of the served markup.
   Those tests never execute JavaScript. `CC-UI-0031`'s effectiveness entry says
   "every panel renders from a seeded store", which was true of the *payload*, not of
   the page.
4. Why did no browser test catch it? The repo's only real-browser tests
   (`test_web_launcher_browser.py`, `test_web_repeater_browser.py`) cover `/launcher`
   and `/proxy`, not the chart pages. They assert on DOM text, not on page or console
   errors. They also `importorskip("playwright")` at module level and skip when Chromium
   can't launch. `CC-UI-0026` records "2 skipped (Playwright-gated browser tests skip
   when Chromium isn't installed)", so where the verification runs happened, even those
   two never ran.
5. Why was the skip acceptable? PA-0005 allows a real-path test to be "skippable when it
   needs an environment feature". Nothing required that such a test actually run
   somewhere before a UI change counted as verified.

**Root cause:** the panel's client-side behavior had no test that ran in a real browser
and failed on a page or console error. Its only browser tests were optional, skipped
silently where verification happened, and covered two pages. So a construction-time
exception in the shared charting layer, and three caller bugs behind it, were invisible
to every test that ran.

## Corrective action
Delivered in `CC-UI-0036` (`docs/components/12-diagnostics-and-ui/change-control.md`),
after a 3/3-agreed pre-change review:
- `chart.js`:
  - passes `class: "fl-chart"` (one token) and adds `fl-chart--<type>` to `u.root`
    inside `build()`, so `rebuild()` keeps it;
  - gives the mount `role="figure"`;
  - owns and refreshes the `aria-label` it set (never a template-authored one), and
    removes it when there is no caption.
- `diagnostics.js` passes only its y series, plus `xLabel`, `caption`, and `x.time =
  false` for the series chart.
- `ml.js` runs each panel through `renderSafely`, so a failing panel shows "Could not
  render this panel (see the browser console)" and the panels after it still render.
- `tests/_browser.py` holds the shared harness. `FUZZLAB_REQUIRE_BROWSER=1` turns any
  skip (no web extra, no Playwright, no launchable Chromium) into a failure. The two
  existing browser tests use it.
- New `tests/test_web_pages_browser.py` (7 tests), in real Chromium:
  - every HTML GET route (walked from `app.routes`) plus the not-found page has zero
    page errors, console errors and CSP violations;
  - every chart mount in each available ML panel renders;
  - the Diagnostics charts render and relabel;
  - panel isolation holds;
  - BUG-0064's checks pass.
- With the `fuzzlab/` changes reverted, all 6 behavior tests fail; with only
  `diagnostics.js` reverted, the Diagnostics test fails. Web and ML suites under
  `FUZZLAB_REQUIRE_BROWSER=1`: 354 passed, 0 skipped.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0005 / PA-0005** ("a real code path that test doubles bypass everywhere must
  still have at least one test exercising the real implementation (skippable when it
  needs an environment feature)"). **Same root cause.** `TestClient` is the double for
  the browser: it renders templates but never runs their JavaScript or applies the CSP.
  The browser tests that existed were the skippable kind PA-0005 allows.
- **BUG-0009 / PA-0010** ("loads ≠ works: verify the actual produced signal end to
  end"). Related. The served markup "loaded"; nothing checked that a chart was drawn.
- **BUG-0024 / PA-0026** (an adapter around a third-party function must enumerate the
  value-shape preconditions of every parameter). Related to the proximate cause:
  `chart.js` is an adapter around uPlot. PA-0026 is scoped to "explicit-allowlist
  adapters" built to defend a known silent mishandling, which `chart.js` was not
  thought of as.
- **BUG-0033 / PA-0035** (a capability probe must exercise the real operation). That
  rule is already respected here: the old tests skipped on a real `chromium.launch()`
  failure. The gap was what happens *after* an honest skip.

**Result: a recurrence of the BUG-0005 / PA-0005 class.**

## Prior-preventive-action failure analysis
PA-0005 did not prevent this, for three reasons:
1. **Escape hatch with no backstop.** PA-0005 allowed "skippable when it needs an
   environment feature" and stopped there. A skippable test that skips in every
   environment where verification happens is no test at all. Here both browser tests
   skipped during the very change (`CC-UI-0026`) that introduced the CSP. Nothing
   required the skip to fail somewhere.
2. **Too narrow in what it named.** It is framed around Python dependencies and backends
   ("every library imported at runtime … a third-party backend the code instantiates").
   Client-side JavaScript and templates served to a browser were never read as "a real
   code path that test doubles bypass". `TestClient` was not recognized as a double.
3. **Not mechanized.** Nothing made "the chart pages run in a browser" a checked
   condition. Coverage was whatever pages someone had written a browser test for, and
   `CC-UI-0031`/`0032` added two chart pages without one.

## Preventive action
**PA-0065** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0005 for the web UI and
closes its escape hatch. Shared with BUG-0064, which has the same root cause:
1. Every HTML page is smoked in a real browser. `tests/test_web_pages_browser.py` walks
   `app.routes`, so a new page is covered automatically and an unfillable or
   unclassified page fails the walk. It asserts zero page errors, console errors and
   CSP violations.
2. A skip must fail somewhere. `FUZZLAB_REQUIRE_BROWSER=1` turns every browser-test
   skip into a failure. A change touching `fuzzlab/web/templates/` or
   `fuzzlab/web/static/` is verified with it set, and its change-control entry quotes
   the browser tests' pass count (not "skipped").
3. A "renders" or "works in the UI" claim in a change-control effectiveness entry needs
   a real-browser run. A payload or markup test supports only "the data is served".
4. An adapter around a vendored library passes each option in exactly the shape the
   vendored source handles (read that source, as here `addClass` → `classList.add`),
   extending PA-0026's precondition check to such adapters.

**PA-0002 sweep:**
- Every other option `chart.js` passes to uPlot (`id`, `padding`, `legend`,
  `cursor.drag`, `scales`, `paths.bars`, `points`) was checked against the vendored
  source and is handled as passed. `class` was the only misuse.
- Every `createChart` caller was checked: `ml.js`'s series specs are correct, and
  `diagnostics.js` is fixed above.
- The same root cause also produced BUG-0064, filed separately because its mechanism
  (the CSP) and its fix differ.
