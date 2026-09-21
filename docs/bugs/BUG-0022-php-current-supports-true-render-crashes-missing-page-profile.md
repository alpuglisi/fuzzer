# BUG-0022 — `php_current.supports()` returns `True` for a shape whose only illustrative-manifest cell has no page profile, so `render()` crashes

- Date: 2026-09-21
- Status: fixed
- Severity: low

## Description

`fuzzlab.labgen.emitters.php_current.PhpCurrentEmitter.render()` raised
`ValueError: LABGEN-EX-0004: php_current has no page profile for route
'/example/profile.php'` when rendering `lab/manifests/example_phase0_scaffold.yaml`'s
`LABGEN-EX-0004` cell (`xss`, `html_body`), even though
`PhpCurrentEmitter.supports("xss", SinkContext(family="html_body", ...))`
returns `True` for that cell. Per the `Emitter` interface's own documented
contract (`fuzzlab/labgen/emitter.py`, T-LAB0.4), a caller checks
`supports()` and skips a cell it rejects, and is entitled to expect
`render()` to succeed on a cell it accepts.

## Where encountered

Building T-LAB0.7's Tier-3 whole-lab-regeneration check
(`fuzzlab.labgen.conformance.tier3.regenerate_and_diff_emitter`,
`tests/test_labgen_conformance_tier3.py`) and running it, for the first
time, against the *entire* illustrative manifest rather than the two cells
(`LABGEN-EX-0001`/`0002`) the original T-LAB0.4 task's own tests happened
to exercise.

## What it caused to fail

`test_regenerate_and_diff_emitter_passes_for_the_illustrative_manifest`
raised `ValueError` instead of passing. No production/runtime path was
affected (nothing in this repo drives `php_current` over the whole
illustrative manifest today), but the defect meant `supports()`'s own
documented contract — "a caller skips a cell this emitter rejects; it does
not need to defend against `render()` failing on one it accepted" — did not
actually hold for every cell in an existing Phase-0 manifest.

## What the bug was identified to be

`CC-LAB-0022` (the real-page-sample extension) added `("xss", "html_body")`
to `PhpCurrentEmitter._MODULE_SET_BY_SHAPE`, which is exactly what
`supports()` consults — so `supports()` started returning `True` for any
`xss`/`html_body` cell, including ones that predate that change. But
`CC-LAB-0022` only added a `_PAGE_PARAMS` entry for the *real* page
(`/profile.php`); it did not add one for the pre-existing *illustrative*
manifest's matching cell (`LABGEN-EX-0004`, route `/example/profile.php`,
added earlier under `CC-LAB-0019`/T-LAB0.4). `render()` looks up
`_PAGE_PARAMS` by `cell.route.path` and, finding no entry, raises rather
than silently guessing — the right behavior for that one call, but nothing
enforced that every already-supported shape's every already-existing
manifest occurrence still had the metadata it needs.

## Root cause analysis

Five whys:

1. *Why did `render()` raise?* — No `_PAGE_PARAMS` entry existed for
   `/example/profile.php`.
2. *Why was there no entry?* — `CC-LAB-0022`'s author (a prior instance of
   this same lane, in the same worktree lineage) added a profile only for
   the real page it was working from (`/profile.php`), not for the
   pre-existing illustrative cell that happened to share the same
   `(vuln_class, sink_context.family)` shape.
3. *Why didn't `supports()` catch this instead of `render()`?* — `supports()`'s
   signature (`vuln_class`, `sink_context`) carries no route; the shape can
   be generically supported while a *specific* cell's render-only metadata
   (table/column/param names, or here a stored-field expression) is still
   missing. This is a real, structural gap between "this emitter knows the
   general shape" and "this emitter has what it needs for this exact cell."
4. *Why wasn't this caught before landing `CC-LAB-0022`?* — That change's
   own test suite (`tests/test_labgen_php_current_real_pages.py`) only
   exercised the *new* real-page manifest's cells; nothing in that change
   re-ran the *existing* illustrative manifest's full cell set through the
   now-expanded `supports()`/`render()` pair.
5. *Why did nothing re-run the existing manifest?* — No test in the
   codebase, before this task, rendered an *entire* manifest file's cell
   list through an emitter and asserted success/determinism across all of
   it — only individual, hand-picked cells were exercised directly.

**Root cause:** adding a new `(vuln_class, sink_context.family)` shape to
`PhpCurrentEmitter`'s module-set registry silently widens what `supports()`
accepts for *every* existing manifest, but nothing checked that every
existing manifest's cells of that shape also have the per-page metadata
`render()` needs — because no test exercised a whole manifest's cell list,
only individually chosen cells.

## Corrective action

Added the missing `_PAGE_PARAMS["/example/profile.php"]` entry to
`fuzzlab/labgen/emitters/php_current/__init__.py` (`CC-LAB-0027`), matching
the real `/profile.php` entry's shape (`var_name`, `stored_expr`,
`css_class`). Verified via
`tests/test_labgen_conformance_tier3.py::test_regenerate_and_diff_emitter_passes_for_the_illustrative_manifest`,
which now renders (and byte-diffs) **every** cell in
`lab/manifests/example_phase0_scaffold.yaml`, not a hand-picked subset —
and an equivalent test for `lab/manifests/phase0_real_pages_sample.yaml`.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause
("widening a registry silently breaks something a test only partially
covers"). The closest prior entries are BUG-0009/PA-0008/PA-0009 (a
capability-detection/build-verification gap) and BUG-0016/PA-0017 (a
self-test metric that didn't isolate the capability it claimed to prove) —
both about a *check* not actually proving what it claimed, which is
adjacent but not the same root cause (this bug is about *coverage*: no
check existed at all over the *whole* manifest, not that an existing check
was measuring the wrong thing). No prior bug shares this exact root cause
(a per-shape capability registry and a per-route metadata registry that
must stay in lockstep, with no test enumerating "every route of a supported
shape"). Treated as a new root cause; no prior-preventive-action failure
analysis section is needed.

*(Numbered `BUG-0022`/`PA-0024` rather than this task's own worktree numbers
`BUG-0021`/`PA-0023` at merge time — this lane's worktree was based on a
commit predating the `CC-PROXY-0016` fix, which had already independently
claimed `BUG-0021`/`PA-0023` for an unrelated `RepeaterController`
cross-thread SQLite race by the time this branch was reconciled into trunk.
No content changed; purely a numbering fix, including the in-code comment
above `_PAGE_PARAMS["/example/profile.php"]` in
`fuzzlab/labgen/emitters/php_current/__init__.py`, which now cites
`BUG-0022` instead of the worktree-local `BUG-0018`/`BUG-0021` it
inconsistently referenced across its own authoring.)*

## Preventive action

**PA-0024** (added to `docs/PREVENTIVE_ACTIONS.md`): whenever an emitter's
"supports this shape" registry (or equivalent capability declaration) is
extended, the same change must render **every** cell of every existing
manifest that could newly match that shape — not just the new manifest/cells
the change was written for — and this must be a standing test, not a
one-time manual check. `tests/test_labgen_conformance_tier3.py`'s two
whole-manifest `regenerate_and_diff_emitter()` tests (covering both
`lab/manifests/example_phase0_scaffold.yaml` and
`lab/manifests/phase0_real_pages_sample.yaml`) are that standing test for
`php_current`; a future third Phase-0/Phase-1 manifest must be added to
that same coverage, and a future second emitter must ship an equivalent
whole-manifest Tier-3 test of its own, not rely on this one.
