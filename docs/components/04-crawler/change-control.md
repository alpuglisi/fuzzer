# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CRAWL-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `spider.py` renders
  JavaScript via Playwright, captures fetch/XHR endpoints, resets/reuses its own
  SQLite results, and fixes the earlier port-scope bug. Standalone; not yet on the
  shared store or session manager.
- Impact (other components / project): feeds the auditor and fuzzer; currently
  writes its own database rather than the shared store, and crawls unauthenticated.
- Risk (level; mitigation): low. Present gaps (no shared store, no auth, no
  template dedup) are addressed in Phase 0 (store migration) and Phase 2
  (hardening); no current risk to other components beyond its own DB format.
- Deliverables:
  - [x] JavaScript rendering + XHR capture — done.
  - [x] Reset-by-default and `--resume`; port-scope fix — done.
  - [ ] Migrate to the shared store — todo (Phase 0 T0.8).
  - [ ] Session-manager integration + per-identity crawl — todo (Phase 1).
  - [ ] Template dedup, hybrid crawl, state-machine — todo (Phase 2).
- Effectiveness (assessed or pending): effective for JS discovery — verified that
  the Playwright engine finds all 10 JS pages the static engine missed. Remaining
  items pending.
