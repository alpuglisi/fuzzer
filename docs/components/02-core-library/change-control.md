# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0003 — Migration 2: self-describing findings (2026-09-21)
- Change: added migration 2, which ALTERs `finding` to add `url`, `method`, and
  `param` columns so a confirmed finding carries its own location and the
  integration harness can score by `(url, method, param, vuln_class)` without a
  candidate/parameter join. Registered as a new, higher-numbered migration (the
  registry is append-only; migration 1 is untouched).
- Impact (other components / project): the store schema head is now version 2; the
  harness (T0.7) reads these columns. Additive only — existing rows/columns
  unchanged; a fresh store applies 1 then 2.
- Risk (level; mitigation): low — additive `ALTER TABLE ADD COLUMN`. Mitigated by
  the idempotent migration runner and tests; the two foundation tests that pinned
  version 1 were updated to assert the current head rather than a literal.
- Deliverables:
  - [x] Migration 2 (finding url/method/param) + registry entry — done.
  - [x] Update version-pinning tests to the head version — done.
- Effectiveness (assessed 2026-09-21): effective — a fresh store reports version 2,
  re-migration is a no-op, and the harness scores from finding rows (22/22 tests).

### CC-CORE-0002 — Phase 0 core library implemented (2026-09-21)
- Change: created the `fuzzlab` package with a `core/` subpackage and built the
  Phase 0 foundations — the project store (`store.py`) with WAL/foreign-key
  pragmas and content-addressed bodies; a numbered, forward-only, idempotent
  migration runner (`migrations.py`) creating the core tables from the store
  contract (reserving grey-box coverage/fault columns); layered config
  (`config.py`, defaults → file → env → overrides) with a stable run hash and
  redaction; structured JSON logging (`obs.py`); the request budget + per-host
  timing mutex (`budget.py`); and a session-aware, scope-enforcing HTTP seam
  (`http.py`). Adds `pyproject.toml`. Realizes Phase 0 tasks T0.1, T0.3, T0.4.
- Impact (other components / project): every tool now has a real `core/` to
  import (D6) and the shared store exists as the integration bus (D5). Establishes
  the store schema other components will read/write (T0.8 migrates them onto it).
  No external interface beyond the store contract; the schema is versioned so
  later changes are additive migrations.
- Risk (level; mitigation): medium — the most depended-on component. Mitigated by
  numbered forward-only migrations (idempotent, transactional), a versioned
  feature store, config validation (e.g. timing_concurrency must be 1), and unit
  tests covering migrations idempotency, config precedence/hash/redaction, budget
  caps, the timing mutex, and HTTP scope enforcement + flow recording.
- Deliverables:
  - [x] Package layout with `core/` (T0.1) — done.
  - [x] Store + migrations (T0.3) — done.
  - [x] Config, logging, budget+mutex, HTTP seam (T0.4) — done.
  - [x] Versioned feature extractor `features.py` + golden tests (T0.5) — done.
  - [x] Foundation unit tests (12) passing — done.
  - [ ] Session manager replaces the HTTP-seam addon stub — todo (Phase 1).
- Effectiveness (assessed 2026-09-21): effective — `python -m pytest` is green
  (12/12); a fresh store migrates to version 1 and re-migration is a no-op; config
  hash is deterministic; the timing mutex serializes per host in a threaded test.

### CC-CORE-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented; the
  existing tools currently carry their own ad-hoc storage and helpers.
- Impact (other components / project): once built, every tool depends on it; it
  establishes the store as the integration bus (D5) and removes duplicated
  storage/logging/HTTP logic from the tools (D6). Until then, tools remain
  loosely coupled through separate SQLite files.
- Risk (level; mitigation): medium — this is the most depended-on component, so a
  bad schema or API is expensive to change later. Mitigated by numbered
  migrations, a versioned feature store, and building it first (Phase 0) before
  much depends on it.
- Deliverables:
  - [ ] Package layout with `core/` — todo (Phase 0 T0.1).
  - [ ] Store + migrations — todo (Phase 0 T0.3).
  - [ ] Config, logging, budget+mutex, HTTP seam — todo (Phase 0 T0.4).
  - [ ] Versioned features + golden tests — todo (Phase 0 T0.5).
- Effectiveness (assessed or pending): pending — not yet built.
