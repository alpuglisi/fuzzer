# BUG-0500 — `canonical_origin` raises on a malformed authority; one stored target row took every origin reader down

- Date: 2026-10-15
- Status: fixed at the reader boundary (CC-CORE-0501); the source fix in `core/urls.py` is
  a follow-up (the file is locked by another session) and is pinned by a strict xfail
- Severity: low. No current writer stores such a `base_url` (the pipeline builds it from
  an already-parsed URL), but the store is a shared contract and one legacy or hand-made
  row made every site tree request, ML holdout sealing and training on that store, and
  migration 19's backfill fail.

## Description
`core.urls.canonical_origin` documents: "``None`` when it has no usable host or port --
``None`` never matches anything". For a malformed authority it raises instead:
`urlsplit` raises `ValueError` ("Invalid IPv6 URL" for `http://[::1`; "netloc ...
contains invalid characters under NFKC normalization" for `http://a＃b`) before the
function reaches its own hostname check.

## Where encountered
Code review of the site tree (CC-UI-0500; reviewers A6 and B3, both reproduced): a
`target` row with `base_url = 'http://[::1'` made `/api/sitetree/children`, `/node` and
`/facets` return 500, through `core.runtarget.run_origins` and `sitetree._load_runs`.

## What it caused to fail
Every reader that canonicalises stored target URLs: the site tree (all routes), ML's
`holdout._run_origins` (holdout sealing, `sealing_for_run`, training on that store) and,
on a legacy store below migration 19, `migrations._backfill_holdout_seal` (the store
would fail to open). A node key carrying such an origin also gave 500, not 400.

## What the bug was identified to be
A function whose docstring promises a sentinel for unusable input is not total: one
grammar layer it parses (`urlsplit`'s authority parsing) raises on malformed input, and
nothing catches it.

## Root cause analysis
Five whys:
1. Why did the site tree fail? `run_origins` called `canonical_origin` on a stored
   `base_url` and it raised.
2. Why did it raise? `urlsplit` rejects a malformed IPv6 bracket or an NFKC-invalid
   netloc with `ValueError`; `canonical_origin` calls it unguarded.
3. Why was that not caught by its tests? They cover well-formed edge cases (default
   ports, loopback aliases, IPv4-mapped IPv6, a missing host, an out-of-range port --
   which `parts.port` raises and the function does catch) but no input malformed in the
   URL grammar's own structural characters.
4. Why did the readers not guard it? Each trusted the docstring's "``None`` for an
   unusable URL"; there was no single boundary for "a stored URL's origin".
5. Why was the docstring trusted without a test? PA-0096 asks for tests at numeric and
   size extremes at a typed error boundary and for total *validation predicates*; a
   normaliser that returns a sentinel was read as neither.

**Root cause:** a sentinel-returning normaliser's totality was a prose claim, tested only
on well-formed edge cases, and stored-data readers called it directly instead of through
one total boundary.

## Corrective action
`core.runtarget.origin_of(base_url)`: `canonical_origin` with only its documented failure
(`ValueError`) turned into ``None``; `run_origins` (so ML's `_run_origins`) and the site
tree (`_load_runs`, `parse_key` -> 400) go through it. A run with such a row reads
"origin unreadable". Tests: `tests/test_web_sitetree.py::
test_a_malformed_stored_base_url_is_an_unreadable_origin_not_a_crash` (tree, facets,
`run_origins`, ML `_run_origins`), `::test_hostile_requests_are_400_not_500`. The source
fix belongs in `core/urls.py` (locked): pinned by `tests/test_core_runtarget.py::
test_canonical_origin_is_total_for_malformed_authorities` (`xfail(strict=True)`).
CC-CORE-0501, CC-UI-0503.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a boundary documented as total
that raised on unforeseen input, and for readers of stored data that crash on one bad
row:
- **BUG-0095 / PA-0096** -- a saved model with `10**1000` escaped the loader as a raw
  `OverflowError`; PA-0096: (1) a typed error boundary is tested at every numeric extreme
  and with oversized inputs, (2) validation predicates are total. **Same root cause** (a
  claimed-total boundary, untested on the inputs that break it).
- BUG-0107 / PA-0108 (stored JSON read at one parser; malformed rows quarantined) --
  related: the "one boundary per stored value" half of this bug.
- BUG-0131 / PA-0131(2) (gates fed the structural characters of every grammar their input
  passes through) -- related: the grammar-malformed input class, but scoped to gates.

## Prior-preventive-action failure analysis
PA-0096 (from BUG-0095) did not prevent this because it was **too narrow** in two ways:
its extremes list is numeric and size-only (huge integers, NaN, inf, oversized bytes) and
names no input malformed in the parsed grammar; and its totality clause covers
"validation predicates", so a normaliser returning a sentinel (`canonical_origin`) was not
seen as in scope. PA-0131(2) names grammar-structural inputs but only for gates. Neither
was applied to `core/urls.py`'s normalisers, and neither asked stored-data readers to
share one total boundary (PA-0108 asked it for JSON only).

## Preventive action
**PA-0500** (strengthens PA-0096, generalises PA-0131(2) and PA-0108(1)):
1. A function whose contract promises a sentinel (``None`` / ``False`` / empty) for
   unusable input is total, and its tests feed the malformed inputs of **every grammar it
   parses** -- for a URL: an unclosed or bad IPv6 bracket, an NFKC-invalid netloc, a
   non-numeric or out-of-range port, a lone surrogate, control characters -- and assert
   the sentinel.
2. A reader of **stored** data normalises each stored value through one total boundary
   for that value (here `core.runtarget.origin_of`), so a malformed row degrades to
   "unreadable", never takes the reader down.
3. The PA-0002 sweep is by mechanism: every caller of the non-total function, with a
   disposition (below).

PA-0002 sweep (callers of `canonical_origin`):
| Caller | Input | Disposition |
| --- | --- | --- |
| `core/runtarget.run_origins` | stored `target.base_url` | fixed (`origin_of`) |
| `web/sitetree` (`_load_runs`, `parse_key`) | stored rows; request node keys | fixed (`origin_of`; 400) |
| `ml/holdout._run_origins` | stored rows | fixed (through `run_origins`) |
| `core/migrations._backfill_holdout_seal` | stored rows (legacy stores) | shipped migration, never edited: covered by the source fix (follow-up) |
| `ml/dataset.target_runs` | operator `--target` | not stored data; a malformed value raises at the CLI (a usage error); left, noted |
| `core/urls` (`origin_scope`, `in_origin_scope`, `url_key`), `session/*`, `tools/*` | live URLs, mostly already parsed upstream | files locked by another session: covered by the source fix (follow-up, strict xfail) |
