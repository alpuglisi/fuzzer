# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0018 — Add `metric_series` table + `open_store()`/WAL + `log_scalar`/`MetricLogger` (2026-09-22)
- Change: additive migration 11 creates `metric_series(id, run_id, source, key, step, ts,
  value)` — per-step time-series metrics (training curves, bandit posterior/regret,
  coverage growth, mutation reward/novelty), complementing the existing per-run
  `run_metrics` table. Two indexes: `(run_id, source, key, step)` for a single series,
  `(source, key, run_id, step)` for cross-run overlay queries. `value REAL NOT NULL`;
  non-finite values are rejected at emit time (dropped + `warnings.warn`), never stored —
  no `is_nan` column, no NaN read-branch anywhere. Added a central `open_store()`
  connection helper (`journal_mode=WAL`, `busy_timeout=10000`, `synchronous=NORMAL`,
  `foreign_keys=ON`, `sqlite3.connect(path, timeout=10.0)`); existing `connect()` callers
  are unaffected (`journal_mode=WAL` is idempotent — a harmless no-op on an already-WAL
  store). Added `log_scalar(store, run_id, source, key, step, value, ts=None)`
  (single-point, validated write) and `MetricLogger(store, run_id, source, flush_every=200,
  flush_interval=1.0)` (buffered context manager; flushes via `executemany` under
  `BEGIN IMMEDIATE ... COMMIT`; flushes on `__exit__` including on exception) as the sole
  write path into `metric_series`.
- Impact (other components / project): backend prerequisite (Phase 4b / UI lane B0) for a
  future diagnostics UI tab to chart per-step metrics; also hardens the shared store's
  SQLite concurrency model (WAL + `BEGIN IMMEDIATE` discipline) ahead of concurrent
  readers/writers (UI polling, labgen, crawler, etc.). Consumed by FUZZ (`CC-FUZZ-0019`),
  ML (`CC-ML-0009`), and MUT (`CC-MUT-0008`).
- Risk (level; mitigation): low — additive schema change with a thin, idempotent
  connection-setup helper; no existing store consumer's connection behavior changed.
  Mitigated by the unchanged full suite (1395 passed / 23 skipped, same 6 pre-existing
  environmental/unrelated failures as before this change) plus new migration/WAL/
  `log_scalar`/`MetricLogger` unit tests.
- Deliverables:
  - [x] Migration 11 (`metric_series` + both indexes) — done.
  - [x] `open_store()` (WAL/busy_timeout/synchronous/foreign_keys) — done.
  - [x] `log_scalar` + non-finite rejection — done.
  - [x] `MetricLogger` buffered emitter — done.
- Effectiveness (assessed 2026-09-22): effective — migration applies cleanly to both a
  fresh store and an already-populated pre-migration store; `PRAGMA journal_mode == 'wal'`
  smoke test passes; four downstream components (ML/FUZZ/MUT, see their own entries) wired
  real emitters against the new API with no regression.

### CC-CORE-0017 — Credentials keyed by bare hostname (BUG-0007) (2026-09-21)
- Change: `CredentialStore` now normalizes the host to its bare hostname
  (`_norm_host`: strips scheme/port) on `set`/`get`/`require`/`delete`, so credentials
  saved as `127.0.0.1`, `127.0.0.1:8080`, or `http://127.0.0.1:8080/` all resolve to the
  same key — matching how the session layer looks them up (`urlparse(url).hostname`). The
  `require` error message now prints the exact `set-credential` command with the
  normalized host.
- Impact (other components / project): fixes the on-host `CredentialError` where
  `set-credential --host 127.0.0.1:8080` stored a key the crawler's hostname lookup
  (`127.0.0.1`) missed (BUG-0007). No API change; existing hostname-only usage is
  unaffected (normalization is a no-op there).
- Risk (level; mitigation): low — normalization at the store boundary; the session layer
  and `HttpClient` scope already use `hostname`. Mitigated by
  `tests/test_credentials.py::test_host_is_keyed_by_hostname_regardless_of_port_or_scheme`.
  Suite 392 passed / 4 skipped.
- Deliverables:
  - [x] `_norm_host` normalization + actionable `require` message — done.
- Effectiveness (assessed 2026-09-21): effective — save-with-port / look-up-by-hostname
  now agree; the runbook was corrected to `--host 127.0.0.1`.

### CC-CORE-0016 — Migration 10: active-plugin recording (Phase 10 T10.1) (2026-09-21)
- Change: migration 10 adds the `run_plugin` table (append-only registry; head → 10):
  one row per active plugin per run (`run_id, name, version, priority`), so a run records
  exactly which plugins/versions produced its results (NFR-PLUG-reproducible).
- Impact (other components / project): the PLUG component's `PluginManager.record()`
  writes here; the reproducibility report (T10.4) reads it. Additive; a zero-plugin run
  writes no rows. Version-pinning tests derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one additive table + index. Mitigated by
  `tests/test_plugins.py::test_migration_10_adds_run_plugin` and `test_record_writes_active_plugins`.
  Suite 360 passed / 4 skipped.
- Deliverables:
  - [x] Migration 10 (`run_plugin`) — done.
- Effectiveness (assessed 2026-09-21): effective — active plugins persist per run.

### CC-CORE-0015 — Migration 9: flow protocol tag (Phase 9 T9.1) (2026-09-21)
- Change: migration 9 adds a `protocol` column to `flow` (append-only registry; head → 9)
  so history distinguishes `http/1.1` / `h2` / `ws` flows. Additive; existing rows read as
  NULL and the proxy's `HistoryWriter` defaults new rows to `http/1.1`.
- Impact (other components / project): lets the PROXY component record WebSocket and (later)
  HTTP/2 flows alongside HTTP/1.1 without touching existing rows. Version-pinning tests
  derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one nullable column. Mitigated by
  `tests/test_proxy_ws.py::test_migration_9_adds_flow_protocol`. Suite 328 passed / 4 skipped.
- Deliverables:
  - [x] Migration 9 (`flow.protocol`) — done.
- Effectiveness (assessed 2026-09-21): effective — WebSocket flows persist with their
  protocol tag.

### CC-CORE-0014 — Migration 8: mutation-engine payload variants (Phase 8 T8.1) (2026-09-21)
- Change: migration 8 adds the `payload_variant` table (append-only registry; head → 8):
  the provenance of each accepted mutation — `base_payload`, `variant`, the `operators`
  chain (JSON), `sink_context`, `bypassed_rule`, the `semantics_ok` verdict, and any
  `coverage_gain`. Variants are still sent through the `attempt` path; this is for reuse
  and analysis (decision 3 of the Phase 8 plan).
- Impact (other components / project): gives the MUT component its write-back target
  (FR-MUT-6) without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — additive table + index. Mitigated by
  `tests/test_mutation_operators.py::test_migration_8_adds_payload_variant`. Suite 289
  passed / 4 skipped.
- Deliverables:
  - [x] Migration 8 (`payload_variant`) — done.
- Effectiveness (assessed 2026-09-21): effective — the table is present for T8.5's
  variant write-back.

### CC-CORE-0013 — Migration 7: candidate ranker scores (Phase 7 T7.2) (2026-09-21)
- Change: migration 7 adds advisory `rank_score` and `rank_uncertainty` columns to
  `candidate` (append-only registry; head → 7), kept separate from the Phase-5
  `candidate.score` so the ranker and the detection classifier coexist.
- Impact (other components / project): gives the ML ranker (A.2) its store columns
  without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive nullable columns. Mitigated by
  `tests/test_ml_ranker.py::test_migration_7_adds_rank_columns`. Suite 266 passed / 3 skipped.
- Deliverables:
  - [x] Migration 7 (`candidate.rank_score`, `candidate.rank_uncertainty`) — done.
- Effectiveness (assessed 2026-09-21): effective — the ranker writes advisory ranks into
  the new columns.

### CC-CORE-0012 — Migration 6: proxy flow history (Phase 6 T6.3) (2026-09-21)
- Change: migration 6 extends `flow` with `host`, `in_scope`, and byte-exact
  `req_raw_sha`/`resp_raw_sha` (raw wire bytes content-addressed via `body`), adds the
  `flow_fts` FTS5 index and a `repeater_tab` table (append-only registry; head → 6).
- Impact (other components / project): gives the PROXY component the store contract for
  FR-PROXY-3/FR-PROXY-4 (searchable history with raw bytes; persisted repeater tabs)
  without changing any existing table's rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive columns/tables with NULL defaults (ADD
  COLUMN … REFERENCES is valid because the default is NULL). Mitigated by
  `tests/test_proxy_history.py::test_migration_6_schema`. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (`flow` raw bytes + FTS5 + `repeater_tab`) — done.
- Effectiveness (assessed 2026-09-21): effective — the proxy history writer round-trips
  byte-exact raw bytes and FTS search works over the new index.

### CC-CORE-0011 — Migration 5: bandit cost columns (Phase 4 T4.4) (2026-09-21)
- Change: migration 5 adds `cost_sum`/`cost_n` to `bandit_posteriors` (append-only
  registry; head → 5), so the bandit's per-(context, arm) mean cost persists next to the
  reward posterior for cost-normalized selection.
- Impact (other components / project): the SCHED bandit's `load`/`save` now round-trip
  cost; no other reads change. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes 5.
- Risk (level; mitigation): low — additive columns with defaults. Suite 183 passed / 2 skipped.
- Deliverables:
  - [x] Migration 5 (`cost_sum`, `cost_n`) — done.
- Effectiveness (assessed 2026-09-21): effective — cost persists across runs
  (`tests/test_scheduler.py::test_cost_persists_across_stores`).

### CC-CORE-0010 — Headless credential backend on `cryptography` (BUG-0005) (2026-09-21)
- Change: reimplemented the D12 encrypted-file credential backend in
  `fuzzlab/core/credentials.py`. It was `keyrings.alt.file.EncryptedKeyring` (needs
  PyCrypto/pycryptodome, undeclared and absent → crash on first use). It is now
  `_CryptographyFileBackend`: a single AES-Fernet-encrypted JSON file, key derived
  from `FUZZLAB_KEYRING_PASSPHRASE` via PBKDF2-HMAC-SHA256 over a random per-file
  salt, `0600` perms, atomic write, loud failure on a wrong passphrase — built on
  `cryptography` (the intended lib, already present). Declared `cryptography>=42,<51`
  in `pyproject.toml`.
- Impact (other components / project): fixes BUG-0005, which blocked every headless
  authenticated run (`fuzzlab session set-credential` / `--identity`). The session
  manager (component 03) consumes the store unchanged; the injectable-backend seam and
  the OS-keyring/env-fallback paths are unchanged. File format is new (`FZLB1` magic);
  no prior headless store existed to migrate.
- Risk (level; mitigation): medium — credentials are high-impact. Mitigated by
  encryption at rest (Fernet/AES128-CBC+HMAC), `0600` perms, ciphertext-verified in a
  test, password-masked `repr`, and new real-backend tests (round-trip, persistence,
  wrong-passphrase) that exercise the actual `cryptography` path and skip only when the
  native lib is unavailable. Suite 126 passed / 2 skipped.
- Deliverables:
  - [x] `_CryptographyFileBackend` (Fernet+PBKDF2, atomic, 0600) — done.
  - [x] `cryptography` declared; `keyrings.alt` EncryptedKeyring dependency dropped — done.
  - [x] Real round-trip/wrong-passphrase tests (skippable) — done.
  - [ ] Confirmed on the host: `set-credential` + `session print` + `--identity` run — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests where `cryptography` works;
  to be confirmed on the Fedora host (where the crash was seen) after `pip install -e .`.

### CC-CORE-0009 — Grey-box consumer layer (offline scaffolding, Phase 3) (2026-09-21)
- Change: added `fuzzlab/greybox/` — the consumer side of Phase 3 grey-box
  instrumentation, built behind injected-source protocols so it is fully testable
  without a lab: `coverage.py` (`CoverageSource` + `InMemoryCoverageSource` fake,
  `app_lines` filter, `CoverageFrontier` novelty tracking, coverage encode/decode),
  `dbfault.py` (`DbFaultSource` + fake), `reward.py` (`GreyboxSignal` + `shaped_reward`
  multi-tier: screening / coverage-novelty / db_fault), `reset.py` (`LabControl`
  protocol + `FakeLabControl`), `confirm.py` (the pure M10 decision), and
  `recorder.py` (`record_attempt_signals` filling the reserved `attempt.coverage`
  /`attempt.db_fault`/`reward` columns). No schema change (columns were reserved in
  migration 1).
- Impact (other components / project): gives Phase 3 turnkey seams — the on-host work
  is reduced to backing the protocols with live pcov/DB-fault/reset sources
  (`docs/ON_HOST_TASKS.md`) and wiring M10 into the oracle/pipeline (FUZZ). The
  shaped reward is the input the Phase 4 bandit will consume. Safety unchanged
  (live readers bind loopback-only; grey-box corroborates, oracle stays sole
  finding-writer).
- Risk (level; mitigation): low — pure, dependency-light logic with no live I/O in
  this layer. Mitigated by 17 offline tests (app-line filtering, frontier novelty +
  saturation, reward ordering incl. the new-code-scores-higher exit property, M10 per
  class, recorder writing the reserved columns end-to-end). Full suite 125/125.
- Deliverables:
  - [x] `fuzzlab/greybox/` package (coverage/dbfault/reward/reset/confirm/recorder) — done.
  - [x] `tests/test_greybox.py` (17 tests) — done.
  - [ ] Live sources + M10 oracle/pipeline wiring + exit measurement — on-host (T3.1/3.5/3.6/3.7).
- Effectiveness (assessed 2026-09-21): effective offline — the reward math, frontier,
  filtering, M10 decision, and column persistence are verified with fakes; live
  confirmation pending the instrumented lab.

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
