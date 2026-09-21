# Indicator Database and Payload Catalogs — Change Control Log

Component code: **IND**. Entry format and required fields: see `../README.md`.
Newest first.

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
