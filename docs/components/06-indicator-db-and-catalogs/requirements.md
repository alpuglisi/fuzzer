# Indicator Database and Payload Catalogs — Requirement Specification

Component code: **IND** · Status: `[built; to extend]` · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #6; `DECISIONS_AND_ROADMAP.md` (D9); `./change-control.md`.

## 1. Purpose
Provide the static knowledge the tools reason over: the indicators the auditor
matches on, and the payload catalogs (with metadata) the scheduler and fuzzer draw
from.

## 2. Scope
- **In:** the indicator database (`php_indicators.db`) and its builder
  (`build_sql_db.py`); the `references/` payload catalogs; per-payload metadata.
- **Out:** deciding which payload to send (scheduler) and confirming a hit
  (oracle).

## 3. Functional requirements
- **FR-IND-1** Map indicator types to `references/` categories, covering all 28
  indicator types the auditor evaluates, each with a reference back to its source
  category.
- **FR-IND-2** Store payload catalogs organized by family, with per-payload
  metadata: family, target DBMS, context prerequisites, and a destructive flag.
- **FR-IND-3** Rebuild the database deterministically from source via
  `build_sql_db.py` (regeneration is reproducible).
- **FR-IND-4** Expose payload families and priors so the scheduler can seed its
  arms from the catalog.

## 4. Non-functional requirements
- **NFR-IND-static** Read-only at run time; no run-time mutation except by the
  mutation engine writing new candidates back (Phase 8).
- **NFR-IND-versioned** Catalog and indicator DB carry a version recorded onto the
  run so results are reproducible.
- **NFR-IND-safe** Destructive payloads are flagged so the default-off gate can
  exclude them.
- **NFR-IND-no-leak** Catalog identifiers used at run time carry no vulnerability
  class name where a tool-visible artifact would leak it (D9).

## 5. Interfaces and data contracts
Read as static data (SQLite + files on disk). The auditor reads indicators; the
scheduler and fuzzer read payloads and family metadata; the mutation engine may
write new payload candidates back into the catalog/attempts (Phase 8).

## 6. Dependencies (components)
None (static data).

## 7. Acceptance criteria
- All 28 indicator types resolve to a reference category.
- Payloads carry family/DBMS/context/destructive metadata usable by the scheduler.
- `build_sql_db.py` regenerates `php_indicators.db` byte-for-byte from source.

## 8. Open questions
- Catalog schema for context prerequisites (how the fuzzer checks a payload's
  precondition before sending).
- Whether payload provenance/licensing needs to be tracked per entry.
