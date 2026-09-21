# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0008 — Single home for URL path-normalization (`urls.to_path`) (2026-09-21)
- Change: added `fuzzlab/core/urls.py::to_path(url)` — the one shared function that
  normalizes a result URL to path form (`/product.php`), the convention every
  stored, ground-truth-cross-referenced URL must follow. The oracle's finding
  writer and `tools/store_adapter` (which had a private `_path` duplicate) both now
  call it; the duplicate is removed.
- Impact (other components / project): fixes BUG-0003 (the oracle stored full URLs,
  so scored pipeline runs reported every true finding as a false alarm). Any future
  writer of a cross-referenced URL imports `to_path` rather than re-implementing the
  rule (PA-0003). No schema change; behavior change is that oracle findings are now
  stored in path form like every other URL.
- Risk (level; mitigation): low — a pure, well-tested normalization helper.
  Mitigated by the pipeline tests (scored TP/FP now correct) and the existing
  store-adapter/harness tests (unchanged, still green). Suite 108/108.
- Deliverables:
  - [x] `core/urls.py::to_path` with the convention documented in-module — done.
  - [x] Oracle + store_adapter call it; local duplicate removed — done.
  - [x] BUG-0003 investigation + PA-0003 recorded — done.
- Effectiveness (assessed 2026-09-21): effective — the previously-failing scored
  pipeline test passes and no writer stores a verbatim URL for cross-referencing.

### CC-CORE-0007 — Run-mode category resolver (D14/D15) (2026-09-21)
- Change: added `core/runmode.py` — the pure decision logic for category selection
  and the no-ground-truth fail-safe. `resolve_run(mode, ...)` returns a `RunPlan`
  (categories, scored, source): automatic + ground truth → auto-derived + scored
  (D14); automatic + no ground truth → explicit selection required or **fail loud**,
  unscored (D15); manual → user selection, defaulting to all known categories,
  unscored (D14). `categories_from_vuln_classes` normalizes ground-truth classes
  (e.g. `sqli`→`sql-injection`, `xss-*`→`xss`) to reference-style categories; unknown
  categories/modes fail loud. Dependency-light (callers pass the ground-truth and
  known categories in), so no layering inversion.
- Impact (other components / project): the launcher/harness and tools call this to
  scope the auditor rules (T2.3 `categories` filter), payload sources, and oracle
  strategies (T2.9), and to enforce the D15 fail-safe. No schema change.
- Risk (level; mitigation): low — pure function; the safety-relevant path (D15) is
  fail-closed (raises rather than guessing/blasting). 7 unit tests cover D14 lab
  auto-derive (scored), manual selection/default, D15 fail-loud + unscored, and
  unknown-category/mode errors.
- Deliverables:
  - [x] `runmode.py` resolver + normalization + 7 tests — done.
  - [ ] Wire into the launcher/harness (scope tools; scored vs unscored) — todo (with T2.8/UI).
- Effectiveness (assessed 2026-09-21): effective in unit tests — each D14/D15 branch
  resolves correctly and fails loud on unsafe/unknown input. Suite 105/105.

### CC-CORE-0006 — Migration 4: rule-evaluation logging (negatives) (2026-09-21)
- Change: added migration 4 (an `evaluation` table + indexes) recording every
  per-(injection point, rule) evaluation with its outcome (`fired` 0/1), so the
  store holds negatives, not just hits. Supports the auditor's T2.3 rules-as-data
  engine.
- Impact (other components / project): the auditor writes here; the ranker/ML
  (later) train on the negatives. Schema head is now version 4; additive.
- Risk (level; mitigation): low — additive table + indexes; idempotent migration
  runner + tests. (The version-pinning tests already derive the head from the
  registry per PA-0001/PA-0002, so migration 4 needed no test edits.)
- Deliverables:
  - [x] Migration 4 (`evaluation` table + indexes) — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 4;
  the auditor engine writes fired + not-fired evaluations (98/98 tests green).

### CC-CORE-0005 — Migration 3 + session-state store methods (2026-09-21)
- Change: added migration 3 (a `session_state` table for **non-secret** session
  metadata — host, identity, kind, valid, login/logout URLs, token_exp) and Store
  methods `upsert_session_state`/`get_session_state`/`all_session_states`. Supports
  T1.7 persistence. Secrets (cookies/tokens/creds) are never stored — the table has
  no column for them.
- Impact (other components / project): the session manager (#3) persists non-secret
  state here; the diagnostics UI can later read it. Schema head is now version 3;
  additive migration, existing data untouched.
- Risk (level; mitigation): low — additive table + upsert. Mitigated by the
  idempotent migration runner and tests. Discovered BUG-0002 (a test still
  hardcoding the schema head `== 2`); fixed to derive from the registry and added
  PA-0002 (sweep for a bug class when adding its preventive action).
- Deliverables:
  - [x] Migration 3 (`session_state`) + Store methods — done.
  - [x] Fix BUG-0002 + PA-0002 — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 3,
  session state round-trips, suite 71/71 green.

### CC-CORE-0004 — Per-host credential store implemented (2026-09-21)
- Change: implemented `fuzzlab/core/credentials.py` (T1.1, D12) — a
  `CredentialStore` keyed by `(host, identity)` over `keyring`, with backend
  resolution (OS Secret Service → encrypted-file via `keyrings.alt` at
  `FUZZLAB_KEYRING_PATH`/`FUZZLAB_KEYRING_PASSPHRASE` → gated lab-only env fallback
  `FUZZLAB_CRED_<HOST>_<IDENTITY>`). Backend is injectable; `Credential` masks its
  password in `repr`. Exported from `core`. Added `keyring`/`keyrings.alt` deps;
  dropped the planned PyJWT dep (JWT `exp` is read by base64url-decoding the
  payload — no crypto dependency).
- Impact (other components / project): the session manager (component #3) draws
  per-host credentials from here; no other component affected. Secrets never enter
  the project store or repo (config holds references only).
- Risk (level; mitigation): medium — mishandled credentials are high-impact.
  Mitigated by keyring-only storage, password-masked repr, redaction discipline,
  and the env fallback being default-off and lab-scope-gated. The real
  encrypted-file backend is environment-dependent (needs a working `cryptography`);
  the store's own logic is covered by tests with an injected in-memory backend.
- Deliverables:
  - [x] `CredentialStore` (set/get/require/delete), per-host keying — done.
  - [x] Backend resolution incl. encrypted-file + gated env fallback — done.
  - [x] 6 unit tests (per-host, env-fallback gating, repr masking) — done.
  - [ ] Live check of the encrypted-file backend on a host with `cryptography` — todo.
- Effectiveness (assessed 2026-09-21): effective — 6/6 tests green; credentials
  round-trip per host, env fallback honored only when enabled + in scope, password
  never appears in `repr`.

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
