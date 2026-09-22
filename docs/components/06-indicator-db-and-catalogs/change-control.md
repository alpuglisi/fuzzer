# Indicator Database and Payload Catalogs — Change Control Log

Component code: **IND**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-IND-0003 — Regression coverage for the indicator↔rule↔reference registries (2026-09-22)
- Change: `build_sql_db.py` had zero test coverage. Added `tests/test_indicator_db.py`
  guarding the invariant the module's own comment states but nothing previously
  enforced: every `INDICATORS` `indicator_type` has a matching `fetcher.py` `RULES`
  handler key (and vice versa — no orphaned handler), every `reference` category
  names an existing `references/<reference>/` directory, and
  `build_indicator_database()` writes exactly the declared indicator set and is
  idempotent (re-running doesn't duplicate rows). No code change — `audit_page()`
  already degrades gracefully at runtime via its `unhandled` set, but nothing
  caught a drift between the two registries silently narrowing rule coverage.
- Impact (other components / project): a future edit that adds/renames an
  `indicator_type` or a `RULES` key without updating the other, or a `reference`
  pointing at a nonexistent `references/` folder, now fails a fast unit test instead
  of silently landing in the auditor's `unhandled` set (or a broken payload lookup)
  and only being noticed on a live run.
- Risk (level; mitigation): none — test-only. Mitigated by confirming all 5 new
  tests currently pass (the registries already agree; this is a durability
  guardrail, not a fix for a live drift).
- Deliverables:
  - [x] `tests/test_indicator_db.py` (5 tests) — done.
- Effectiveness (assessed 2026-09-22): effective — the tests currently pass, proving
  the guardrail doesn't false-positive on the real data, and will fail loudly on
  the next indicator/rule/reference drift.

### CC-IND-0002 — Relocated to packaged data path (2026-09-21)
- Change: `php_indicators.db` moved to `fuzzlab/tools/data/php_indicators.db` and
  `build_sql_db.py` (now `fuzzlab/tools/build_sql_db.py`) defaults its output to
  that packaged path (via `fuzzlab.tools.paths`). `references/` catalogs unchanged.
  Phase 0 T0.1.
- Impact (other components / project): the auditor resolves the indicator DB from
  the package (CC-AUD-0002); regeneration writes back to the same packaged file.
  Data content unchanged (still 28 indicator types with reference categories).
- Risk (level; mitigation): low — a relocation plus default-path change; verified
  by regenerating the DB to the packaged path and loading it from the auditor.
- Deliverables:
  - [x] Move DB into packaged data dir; builder writes there by default (T0.1) — done.
  - [ ] Per-payload metadata + versioning recorded on the run — todo.
- Effectiveness (assessed 2026-09-21): effective — `python -m
  fuzzlab.tools.build_sql_db` regenerates the packaged DB and the auditor loads it.

### CC-IND-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `build_sql_db.py` generates
  `php_indicators.db` with all 28 indicator types, each mapped to a `references/`
  category via an added reference column; the `references/` payload catalogs exist.
- Impact (other components / project): the auditor's rule coverage depends on this
  DB (the earlier 7-type DB left 21 auditor rules dormant; the 28-type rebuild
  activated them). The scheduler and fuzzer will read payload families and metadata
  from here.
- Risk (level; mitigation): low. Static data; the main historical risk (indicator
  DB narrower than the auditor's rules) is resolved by the 28-type rebuild.
  Remaining gap — richer per-payload metadata for the scheduler — is additive.
- Deliverables:
  - [x] 28 indicator types + reference column; DB regenerated — done.
  - [x] `references/` payload catalogs present — done.
  - [ ] Per-payload metadata (family, DBMS, context prereq, destructive) — todo.
  - [ ] Catalog/indicator DB versioning recorded onto the run — todo (Phase 0).
  - [ ] Family priors exposed for the scheduler — todo (Phase 4).
- Effectiveness (assessed or pending): effective — verified all 28 auditor rules
  now resolve to an indicator/reference after the rebuild (no dormant rules).
  Scheduler-facing metadata pending.
