# BUG-0538 — The site-map browser tests' item locator was quadratic and starved the page under parallel load
- Date: 2026-10-20
- Status: fixed (AU-SITETREE, `3fb76bb`)
- Severity: medium (tests only). Three live-view browser tests failed intermittently under the harness's parallel load; one failure on `7ebf48a` had been put down to the product.

## Description
`tests/test_web_sitetree_browser.py::Tab.item(label)` was `page.locator('li[role="treeitem"]', has=page.locator(':scope > .st-row > .st-label', has_text=...))`. Playwright evaluates a `has=` filter inside every candidate's subtree, and tree items nest, so one resolution was quadratic in the tree: ~1.9 s of a renderer core with 250 items. Every action's actionability check and every `expect` retry re-resolves it.
## Where encountered
`test_a_refresh_keeps_focus_selection_and_loaded_pages` (the confirming review's run on `7ebf48a` + counters; a broad run on `e55379d`), `test_show_more_pressed_while_a_refresh_loads_its_group_is_kept[after]` and `test_show_more_loads_one_page_per_click_and_works_from_the_keyboard` (4 of 11 loaded runs), only with the browser files in one `-n 4` pass. Possibly also the harness failure that opened BUG-0534 (`test_show_more_from_the_keyboard_keeps_focus_in_the_tree`, 200 of 250): not provable after the fact (DRAFT §1.6).
## What it caused to fail
A "Show more" page not shown within `expect`'s 5 s ("2 × locator resolved"; an idle page resolves 9 × in 5 s); a refresh's request not issued within 15 s. No product defect: the same cost profile on `7ebf48a`.
## What the bug was identified to be
A test helper whose cost grew quadratically with the page; under four browser workers on four cores each step took seconds of renderer CPU and fixed timeouts overran. Measured: DRAFT-AU-SITETREE §5.6 (page-side clocks, per-process CPU, a step-by-step replay on both trees).
## Root cause analysis
Five Whys in DRAFT-AU-SITETREE §5.6. **Root cause:** a test helper whose cost grows quadratically with the page under test, invisible on an idle host, turned every fixed timeout in the site-map browser tests into a load-dependent race; nothing measured a test's own cost, and the test's event timestamps (delivered by Playwright's sync API only inside its calls) could not show it.
## Corrective action
`Tab.item` matches the label elements and steps up (`xpath=../..`): ~10 ms per resolution; guard G5 (`tests/test_web_live_focus.py`) makes any `has=`/`has_not=` in a browser test a reviewed allowance; evidence of loaded runs after the fix in DRAFT §11.5.
## Recurrence review
`docs/bugs/` searched for load, timeout, flaky, parallel, renderer, locator, wall clock: BUG-0135 (a wall-clock ratio under load), BUG-0526 (a bound over a span holding a browser start), BUG-0511 (arrival order), BUG-0143 (a concurrency-only failure set aside). **Same class: a test's oracle that depends on scheduling under the harness's load.**
## Prior-preventive-action failure analysis
PA-0526 covers an explicit clock bound around a run that starts a browser or driver; it does not cover Playwright's own timeouts, nor a test helper's own cost (too narrow). PA-0135 covers complexity claims of product code, not test helpers (wrong layer). PA-0149(2) (reproduce a concurrency-only failure before setting it aside) was followed here and found it.
## Preventive action
PA-0538 (below).
