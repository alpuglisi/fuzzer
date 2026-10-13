# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0038 — `core.urls.destructive_reason` / `check_send_url` (BUG-0111/0112); NFR traceability (PA-0112) (2026-10-13)
- Change:
  - `core/urls.py` gains:
    - `destructive_reason(url)`: decoded, camelCase-split, whole-token and pair
      matching against `DESTRUCTIVE_TOKENS` / `DESTRUCTIVE_PAIRS`; `format` is
      excluded;
    - `url_key(url)`: canonical origin plus path;
    - `check_send_url(url, explicit)`, raising `DestructiveUrlRefused`;
  - `requirements.md` gains traceability lines for NFR-CORE-no-bypass (not yet
    enforced) and NFR-CORE-secrets (partly).
- Impact:
  - **CRAWL, AUD, FUZZ, SESS:** they use the rule (their own entries);
  - no store or schema change.
- Risk: low. The rule only adds refusals. False positives cost coverage, recorded
  (`password_reset`).
- Deliverables:
  - [x] the rule and the gate — done
  - [x] tests: positives (encoded, camelCase, pairs), negatives — done
  - [x] FR-CORE-28 — done
- Review: reviewers A and B, draft v1 (changes required) → v2 (AGREED, both).
  - **Adopted:** the extended token list and decoding (A3/B5), canonical allowance
    keys (B nit).
  - **[DEV] `format` excluded:** accepted by both.
- Effectiveness: verified by `tests/test_destructive_urls.py`; the mutation check
  killed 31/31.

### CC-CORE-0037 — `core.forms`: HTML form entry-list serialisation (BUG-0110) (2026-10-13)
- Change:
  - new `fuzzlab/core/forms.py`:
    - `form_entries(form)` returns an ordered `FormEntries` list of `(name, value)`
      pairs, following §4.10.21.4;
    - `submitter` / `submitter_overrides`, `owned_controls` (form ownership,
      including `form=`), `select_values`, `option_value`, `textarea_value`,
      `default_value`, `is_disabled`;
  - `RULES` lists each implemented rule with its spec step (PA-0111);
  - `FormEntries.get` returns the last value for a name (what `$_POST` and `dict()`
    see); `replace` sets a name in place.
- Impact:
  - **SESS:** the login detector uses it;
  - **AUD:** `tools/fetcher.py` uses `default_value`;
  - no store or schema change.
- Risk: low. A new pure module; every rule has a fixture, and the mutation check killed
  26/26.
- Deliverables:
  - [x] `core/forms.py` — done
  - [x] `tests/test_form_entries.py` (rule-table guard plus a fixture per rule) — done
  - [x] FR-CORE-27 — done
- Review: reviewers A and B both AGREED the BUG-0110 draft with required changes, and all
  were adopted:
  - **A:** form ownership, listbox and optgroup rules, the first enabled submitter
    stated as a deviation, the unnamed image submitter, the FR ids, the PA wording, the
    sweep widened to redirects and cookies;
  - **B:** ordered pairs instead of first-wins, presence-not-truthiness fixtures, a
    machine-checked rule table, submitter overrides refused.
  - **Implementation round:** both AGREED. Both found that a disabled `selected`
    option was replaced by the first enabled one (a browser sends nothing for it); that
    is fixed (`select-selected-disabled-not-sent`). Their nits are recorded as module
    limitations: duplicate form ids and `_charset_`.
- Effectiveness: verified live. `session print` against the loopback bWAPP now
  authenticates.

### CC-CORE-0036 — One fail-closed storage-redaction boundary (BUG-0099/0100); recorder redacted; durable-or-told fsync (BUG-0105); keyring lock and verified delete (BUG-0108/0109); evidence parser (BUG-0107); migration 19 (BUG-0104) (2026-10-13)
- Change:
  - **`core/redaction.py` (BUG-0099 / BUG-0100).** It gains the storage boundary:
    - `redact_query` / `redact_url` / `redact_body` and the per-type helpers, moved
      from `proxy/redact.py`;
    - `MAX_REDACT_BYTES`, `MAX_JSON_DEPTH`;
    - the whole-body scan `mentions_sensitive_name`;
    - sniffing (`body_kind`);
    - the omission markers.
  - **`core/http.py`.** `_record` redacts the URL and both bodies (a case-insensitive
    content type). `send` calls `session.authorize` after a plugin changes the URL.
  - **`core/secretfile.py` (BUG-0105).** `_fsync_dir` skips only `UNSUPPORTED_ERRNOS` or
    a missing `O_DIRECTORY`; otherwise `DurabilityUnknown` after the rename.
  - **`core/credentials.py` (BUG-0108 / 0109).** A lock (thread + `flock` on
    `<keyring>.lock`) is held across load → save; `delete` verifies the entry is gone;
    `DurabilityUnknown` becomes a `CredentialError` saying "retry is safe".
  - **`core/evidence.py` (new, BUG-0107):** `parse_evidence` / `display_evidence`.
    `core/anomaly_flags` uses the display form.
  - **`core/migrations.py` (BUG-0104).** Migration 19 adds `holdout_seal` and
    `holdout_seal_meta`. `POST_STEPS = {19: _backfill_holdout_seal}` runs in the
    migration's own `BEGIN IMMEDIATE` transaction.
- Impact (other components / project):
  - **PROXY** re-exports the redaction functions.
  - **ML** reads and writes `holdout_seal` and uses the evidence parser.
  - **SESS:** `authorize`.
  - **PLUG** (CC-PLUG-0009): the guard allow-list.
  - **Contract changes:**
    - schema version 19;
    - FR-CORE-6's "raw bytes" becomes "redacted bodies";
    - an unparseable or oversized redactable body is stored as a marker.
- Risk: medium (a schema migration with a backfill). Mitigated by:
  - the migration being transactional;
  - an upgrade test from 18;
  - six concurrent upgraders backfilling once;
  - readers proven write-free.
- Deliverables:
  - [x] storage boundary + recorder — done
  - [x] directory-fsync swallow list — done
  - [x] keyring lock + verified delete — done
  - [x] evidence parser — done
  - [x] migration 19 + backfill — done
  - [x] tests: `test_storage_redaction`, `test_secretfile`, `test_holdout_seal_table`,
        `test_dataset_evidence` — done
  - [x] FR-CORE-6 / FR-CORE-25 amended, FR-CORE-26 added — done
- Implementation divergence: none.
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-CORE-0035 — Plural-aware secret names (BUG-0090); complete, fsynced, atomic secret files (BUG-0096) (2026-10-13)
- Change:
  - **`core/redaction.py` (BUG-0090).** `_fold` drops a trailing plural `s` only when
    the folded form is itself sensitive (`passwords`, `secrets`, `sessions`, `jwts`,
    `pwds`, `apiKeys`). `keys` follows `key`'s rule. `passes`, `passage`, `hotkeys`,
    `monkeys` and `keystrokes` stay readable, and `pass` is never folded to `pas`.
    Accepted harmless false redactions: the whole names `codes` / `pins`, and
    `session_count`.
  - **`core/secretfile.py` (BUG-0096).**
    - `write_secret` loops `os.write` over a `memoryview` until complete, raises
      `OSError` on no progress, and `fsync`s.
    - New `create_secret`: `O_EXCL|O_NOFOLLOW` 0600; a partial file is removed on
      failure.
    - New `replace_secret`: a unique temp file (via `create_secret`), `os.replace`, and a
      guarded directory `fsync`. On error the temp file is removed and the original is
      untouched.
  - **`core/credentials.py`:** the encrypted-file keyring saves through
    `replace_secret` instead of a fixed `.tmp` name plus an unconditional replace.
- Impact (other components / project):
  - **PROXY** (CC-PROXY-0020): the redactor and the CA use these.
  - **Logs:** `core.obs` redaction gains the plural fold through the shared predicate.
  - No interface removed: `write_secret` keeps its signature.
- Risk: low. Each helper is tested with a real kernel short write (`RLIMIT_FSIZE`, in a
  child process), injected zero-progress, rename failures and symlinks. The keyring
  round-trip and its failure path are tested.
- Deliverables:
  - [x] plural fold — done
  - [x] `write_secret` loop + fsync; `create_secret`; `replace_secret` — done
  - [x] keyring on `replace_secret` — done
  - [x] tests: `test_secretfile` (new), `test_proxy_redaction` (names) — done
  - [x] FR-CORE-25 amended — done
- Implementation divergence: none.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-CORE-0034 — Shared safety helpers (`core.net`, `core.redaction`, `core.secretfile`); atomic, race-safe migrations (BUG-0080, BUG-0084, BUG-0079 sweep, BUG-0087) (2026-10-13)
- Change:
  - **`core/net.py` (BUG-0080):** `is_loopback_host` (`localhost`, 127/8, `::1`,
    IPv4-mapped) and `require_loopback`. This is the one listener gate (FR-CORE-25).
  - **`core/redaction.py` (BUG-0084):** `is_sensitive_name` by name token.
    `core.obs` uses it. **Behaviour change:** log extras `author` and `tokenizer` are
    no longer redacted; `key`, `api_key` and `session_id` now are.
  - **`core/secretfile.py` (BUG-0079):** `write_secret`, which creates the file 0600
    with `O_NOFOLLOW` and `fchmod`s it before writing. The encrypted keyring backend
    (`core/credentials.py`) uses it, a sweep fix (it used to write, then chmod), and
    creates its directory `0700`.
  - **Migrations (BUG-0087).** `migrate` applies each migration in an explicit
    `BEGIN IMMEDIATE` transaction:
    - the version is re-read inside the lock;
    - statements run one by one (`split_statements`, via SQLite's
      `complete_statement`);
    - `COMMIT`, or `ROLLBACK` and re-raise;
    - `isolation_level` is restored in a `finally`.

    `open_store` sets `busy_timeout` first and retries the WAL switch (`_set_wal`,
    10 s), which bypasses the busy handler (FR-CORE-24).
- Impact (other components / project):
  - PROXY, SESS, the web app and the oracle's OOB listener use the helpers.
  - No schema change: the migrations build the identical schema, as a test asserts.
- Risk: low-medium. The migration runner is on every store open. A
  schema-equals-reference test, a failure-injection test, and a 4-process race test
  cover it.
- Deliverables:
  - [x] `core.net`, `core.redaction`, `core.secretfile` — done
  - [x] atomic migrations and the WAL retry — done
  - [x] tests: `test_migrations_atomic`, `test_loopback_listeners`, the keyring mode in
        `test_credentials`, obs in `test_proxy_redaction` — done
  - [x] FR-CORE-24 / FR-CORE-25 added — done
- Implementation divergence: the WAL-switch retry was added after the race test still
  failed on "database is locked" (reviewer B had predicted it), and `core.secretfile`
  was split out when the sweep found the keyring backend.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-CORE-0033 — `pending` oracle status (BUG-0071); `Store.mark_aborted` (BUG-0078) (2026-10-13)
- Change:
  - `core.oracle_status.PENDING = "pending"`, and `UNLABELLED` now includes it. The
    pipeline writes it for every confirmable row before the oracle loop. A row a crash
    never reached is therefore unlabelled (never training data), but still scored,
    ranked and anomaly-scored.
  - `Store.mark_aborted(run_id, exc)` records `notes = "aborted: <Type>: <msg>"` (or
    `"aborted: exit N"` for `SystemExit`, truncated to 500 characters) after a rollback
    of any half-written statement. It is best effort and never masks the error being
    handled. It is used by `fuzzlab auto`, `greybox-run` and `run_targets`.
- Impact (other components / project):
  - **The status vocabulary gains one value** (no migration: `oracle_status` is free
    text). Every reader goes through `UNLABELLED` (`ml/dataset.py`, `ml/train.py`,
    `web/mlview.py`, `web/results.py`, swept).
  - The `run.notes` column, already shown in the runs list and the report, now carries
    abort reasons.
- Risk: low.
- Deliverables:
  - [x] `PENDING` — done
  - [x] `Store.mark_aborted` and its test — done
  - [x] FR-CORE-14 note — done
- Review: the review-phase draft agreed 3/3. `mark_aborted` moved into core from the
  CLI during implementation, so the three guarded paths share it (PA-0003).
- Effectiveness (assessed 2026-10-13): effective offline. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **26 of 26** review-batch mutants killed (one survivor, the ranker reader passing the classifier's score column, was killed after adding `test_each_family_reader_backs_a_legacy_row_with_its_own_score_column`). Every new regression test fails on the pre-fix code. Suite results: see the related suites (83 files: auto, pipeline, plugins, ML, web incl. real-browser, report, oracle, scheduler, CLI, contract writers, lint, no-ML, packaging, harness, store, migrations, diagnostics; `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1054 passed, 1 skipped, before the last three tests were added, which pass with their files; greybox / multitarget / auto / store / CLI: 143 passed. The non-labgen and full-suite runs were still in progress at commit time and are recorded in a follow-up entry.

### CC-CORE-0032 — Packaging ships every tracked data file (BUG-0068); FR-CORE-22 (2026-10-13)
- Change:
  - **Package data.** `pyproject.toml` `[tool.setuptools.package-data]` drops the
    per-directory, non-recursive globs for one recursive rule, `"*" = ["**/*", "**/.*"]`.
  - **Deny-list.** `[tool.setuptools.exclude-package-data] "*"` names what never ships:
    - caches;
    - `.env` and its `.local` / `.production` / `.development` / `.staging` / `.test`
      variants;
    - `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*id_rsa*`;
    - `*.sqlite*` and `*.db-journal`, `-wal`, `-shm`;
    - OS and editor junk.

    These are fnmatch patterns, so `*` crosses `/`. `**/` patterns do nothing in
    setuptools 68 (measured).
  - **The FR-ML-6 no-ML switch** is documented as two lines.
  - **`pyflakes` added to the `dev` extra** (for `tests/test_lint.py`).
  - **New `tests/test_packaging.py` (8 tests):**
    - build_py equality with the tracked set;
    - executable bits kept;
    - the deny-list matching no tracked file;
    - planted secrets and junk never built, while `.env.example` is;
    - an untracked store/secret guard (a disk walk minus `git ls-files`);
    - sdist ships every tracked file, with modes;
    - the wheel (skips with the Debian `install_layout` reason unless
      `FUZZLAB_REQUIRE_WHEEL=1`);
    - the no-ML switch removes exactly `fuzzlab/ml/`.
- Impact:
  - **Every non-editable install** now has the web UI's templates and assets, the lab
    generator's trees and skeletons, and all packaged data.
  - **The FR-ML-6 knob** gains its required second line.
  - **The project-level `pyproject.toml`** is recorded here because FR-CORE-22 states
    the distribution contract.
  - No runtime code changes.
- Risk: low-medium.
  - **Shipping more could ship something unintended.** Mitigated by the deny-list (proven
    by planted files), the converse check, and the untracked-file guard.
  - **Residual, stated:** a stray `*.db` or an unlisted `.env` variant can't be denied
    by setuptools, so release builds come from a clean checkout (runbook).
- Deliverables:
  - [x] package-data rule + deny-list — done
  - [x] tests — done
  - [x] FR-CORE-22 — done
  - [x] BUG-0068 report, ERROR_LOG, PA-0070 — done
  - [x] runbook "Release builds" — done
- Implementation divergence:
  - `*.env.staging` and `*.env.test` were added to the deny-list (A3/B3 nits).
  - The untracked guard walks the disk (A4), so it also sees ignored files.
- Review: pre-change review gate cleared 3/3 over drafts v1 and v2 (the proposing agent
  plus 2 independent reviewer agents; every issue adopted). The decisive items were
  A1/B1: the recursive rule re-shipped `fuzzlab/ml` as data under the documented no-ML
  exclude. Both reviewers reproduced it.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (95 files: ML, auto, web incl. real-browser, plugins, report,
    no-ML incl. the real no-ML build, harness, multitarget, pipeline, diagnostics, core,
    CLI, store, migrations, packaging, lint, contract writers, on-host script, greybox,
    store adapter, session, labgen CLI, mutation, oracle;
    `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1249 passed, 3 skipped,
    11 failed.
    - 10 failures are `test_labgen_cli.py` tests, among the 33 known environmental
      failures (no scipy, sklearn or gitleaks).
    - The 11th, the multitarget live-boot test, failed with a connection reset from its
      locally booted server while two other suites held the CPU. It passes alone
      (2 passed).
  - **Mutation check** (a staged git copy, bytecode caches cleared): all 21 batch-5
    mutants are killed. Three were first mis-anchored by shell expansion in the
    mutation script and were re-run correctly. Killed:
    - old per-directory globs; no dotfiles;
    - deny-list missing pem / env; an over-broad deny pattern; a one-line no-ML switch;
    - report union missing models / stage metrics / flow;
    - the anomaly version on the read-only path, or missing;
    - flow-version duplicates; prioritizer / pipeline version missing;
    - CSV / greybox schema missing;
    - `_check_sql` never failing; the reveal not opt-in; a literal 5 in the budget check;
    - a lint regression; the dropped `Probe` import.

### CC-CORE-0031 — Migration 18 (flow anomaly columns); candidate features in `core/features.py` (2026-10-13)
- Change:
  - **Migration 18** adds `flow.anomaly_score REAL` and `flow.anomaly_flag INTEGER`.
  - **`core/features.py`** gains `CANDIDATE_FEATURE_NAMES`,
    `CANDIDATE_FEATURE_VERSION = 1` and `extract_candidate_v1`, with their regexes. They
    were moved verbatim from `ml/dataset._features`, and the body diff is empty. They
    import no ML.
  - **Golden file.** `tests/data/candidate_features/v1_golden.json` holds 45 cases, all
    captured from the old function **before** the move: cases 1–12 from the working
    tree, cases 13–45 (one per name-regex alternative) from commit 7a2b3d7, the last
    commit before it.
- Impact:
  - The schema head moves 17 → 18. It is additive.
  - ML reads the vector from core under its old names (FR-ML-5, partly met: recomputed
    on read).
  - The response extractor's `FEATURE_VERSION` is independent.
- Risk: low. Identity is proven by the golden vectors, and the name order is pinned.
- Deliverables:
  - [x] migration 18 — done
  - [x] extractor moved — done
  - [x] FR-CORE-20/21 — done
  - [x] tests: golden vectors (core and the ML alias), names / version, the no-ML
    import AST check (`tests/test_candidate_features_core.py`, 3), and migration 18
    columns (`tests/test_ml_batch4.py`) — done
- Review: covered by CC-ML-0021's 3/3 pre-change review (A6, A8, B4-5). Pre-assigned
  number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (61 files incl. real-browser, no-ML, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 953 passed. Batch-4 files (`test_ml_batch4.py`, `test_candidate_features_core.py`, `test_no_ml.py`, `test_web_ml_context.py`): 57 passed after the mutation-driven additions. Its mutants are among CC-ML-0021's 28, all killed.

### CC-CORE-0030 — Migration 17: the sealed holdout tables; `core/sealed.py` (2026-10-13)
- Change:
  - **Migration 17** adds two tables, plus an index on `holdout_metric.run_id`:
    - `holdout_metric(id, run_id → run, model_id → model, holdout_version, key, value)`;
    - `holdout_reveal(id, run_id → run, holdout_version, revealed_at)`.
  - **New `core/sealed.py`:**
    - `SEALED_TABLES`;
    - `write_metrics(store, run_id, model_id, version, metrics)` (no commit; the
      trainers commit);
    - `reveal(store, run_id) -> {metrics, reveals, version}`, which records a reveal
      row only when there are metrics. The count is store-wide per version.
  - It has no ML import, so a reveal works without the ML package.
- Impact:
  - The schema head moves 16 → 17. It is additive, and no existing table changes.
  - **ML (CC-ML-0020)** writes `holdout_metric`.
  - **UI (CC-UI-0045)** hides both tables.
  - **FUZZ (CC-FUZZ-0053)** `reveal-holdout` reads through `reveal`.
  - **PLUG (CC-PLUG-0007)** guard: INSERT on `holdout_metric` is allowed.
  - Nothing reads `holdout_metric` except `reveal`.
- Risk: low. The migration only adds tables, and the version tests read
  `max(MIGRATIONS)`.
- Deliverables:
  - [x] migration 17 — done
  - [x] `core/sealed.py` — done
  - [x] FR-CORE-19 — done
  - [x] tests: reveal counter, nothing-to-reveal, sealed surfaces
    (`tests/test_ml_holdout_calibration.py`) — done
- Review: covered by CC-ML-0020's 3/3 pre-change review (A1, B3v2-1, the final B nit
  2). Pre-assigned number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (58 files: ML, auto, web incl. real-browser, plugins, report, no-ML, harness, multitarget, pipeline, diagnostics, core, CLI, store, migrations; `FUZZLAB_REQUIRE_BROWSER=1`): 901 passed. `tests/test_ml_holdout_calibration.py`: 42 passed. Its mutants are among CC-ML-0020's 27, all killed.

### CC-CORE-0029 — `oracle_status` vocabulary in one place; canonical target origin; migration 16 (2026-10-13)
- Change:
  - **New `fuzzlab/core/oracle_status.py`** holds `CHECKED`, `SKIPPED_BUDGET`,
    `NO_CONFIRMER` and `UNLABELLED = {SKIPPED_BUDGET, NO_CONFIRMER}`. `harness/pipeline.py`,
    `ml/dataset.py` and `ml/train.forward_skip_reason` import them, replacing duplicate
    literals (PA-0003).
  - **`core/urls.canonical_origin(url) -> str | None`.**
    - It lower-cases scheme and host, strips a trailing dot, and normalises the host
      through `ipaddress` (compressed form; IPv4-mapped IPv6 → IPv4).
    - `localhost` and `::1`, in any spelling, become `127.0.0.1`. Other 127/8 hosts
      stay distinct.
    - The default port is made explicit; userinfo, path, query and fragment are
      dropped. A URL without a scheme reads as `http`.
    - It returns `None` (never matches) for an empty or missing host, or for a
      non-numeric or out-of-range port.
  - **Migration 16** adds `candidate.score_oof REAL` and `candidate.rank_score_oof REAL`.
    Head 15 → 16 (BUG-0067).
- Impact:
  - **Behaviour:** pipeline runs are unchanged. Target matching for earlier-run training
    and budget ordering now joins loopback aliases (CC-ML-0018).
  - **PA-0063 reader audit:** the new columns are read only per row, by the run page and
    the ML tab (per run), through `train.gate_input`.
  - **IDs:** FR-CORE-17 (oracle_status vocabulary) and FR-CORE-18 (canonical origin and
    migration 16).
- Risk: low. Additive.
- Deliverables:
  - [x] `oracle_status`, `canonical_origin`, migration 16 — done
  - [x] Tests — done: 20 `canonical_origin` cases, including every alias and edge case
    from review; target-run matching; the migration head derived from `MIGRATIONS`.
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-CORE-0028 — Migration 15: `run_plugin.config` / `status` / `error` (2026-10-13)
- Change: `ALTER TABLE run_plugin ADD COLUMN config TEXT`, `status TEXT` and
  `error TEXT`. They are nullable; legacy rows are NULL. Head 14 → 15.
- Impact:
  - A run now records how each attached plugin, the ML stages included, was configured
    and how it ended (CC-PLUG-0005).
  - **PA-0063 reader audit:** the only reader is `report.py` (`build_report`). It is per
    run and filtered by `run_id`, so it matches its reader's scope.
  - The optional-ML helper was moved to `fuzzlab/plugins/optional.py` during review, so
    `core/` does not mention `fuzzlab.ml`.
  - FR-CORE-16 is added.
- Risk: low. Additive.
- Deliverables:
  - [x] Migration 15 — done
  - [x] Tests: the head is derived from `MIGRATIONS` and the columns exist
    (`test_plugins_post_run.py::test_migration_15_adds_run_plugin_config_status_error`);
    legacy rows read NULL (`test_report.py`) — done
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective offline. Migration 15 is applied at head; config, status and error are written and read back; legacy rows read NULL. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set.

### CC-CORE-0027 — Migration 14: `model.params` + `model.params_sha256` (2026-10-13)
- Change: `_M0014`:
  ```sql
  ALTER TABLE model ADD COLUMN params TEXT;         -- canonical JSON of the trained model
  ALTER TABLE model ADD COLUMN params_sha256 TEXT;  -- sha256 of exactly that text
  ```
  - The migration is additive. Rows trained before it read NULL and are "not
    reloadable" (no backfill is possible).
  - Only the ML trainers write these columns.
- Impact: ML writes them; UI and report read them through ML's loader. ARCHITECTURE's
  store-contract `model` row is updated.
- Risk: low; additive.
- Deliverables:
  - [ ] `_M0014` + registry — done
  - [ ] Migration test — done
  - [ ] FR-CORE-15 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; both reviewers independently found BUG-0066; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — a fresh store is at head 14 with `model.params` / `params_sha256` (`tests/test_ml_persist.py::test_migration_14_adds_the_model_params_columns`, head derived from `MIGRATIONS`). Full suite at `a3b782d` (2026-10-13, whole `tests/`, `FUZZLAB_REQUIRE_BROWSER=1`): 2915 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same environmental labgen tests as at `369e887` (diffed, identical set); none is caused by this change.

### CC-CORE-0026 — Migration 13: candidate oracle status + anomaly score/flag (2026-10-13)
- Change: `fuzzlab/core/migrations.py` gains `_M0013`, appended as `(13, _M0013)`:
  ```sql
  ALTER TABLE candidate ADD COLUMN oracle_status TEXT;   -- 'checked' | 'skipped_budget' | 'no_confirmer'
  ALTER TABLE candidate ADD COLUMN anomaly_score REAL;   -- ECOD outlier score (advisory)
  ALTER TABLE candidate ADD COLUMN anomaly_flag INTEGER; -- 1 = in the flagged top fraction
  ```
  - The migration is additive, and existing rows read NULL.
  - `oracle_status` NULL means "unknown": written before migration 13, or by a writer
    outside the pipeline (`tools/store_adapter.py:119`). It keeps today's semantics,
    i.e. it is treated as oracle-labelled.
  - Only the pipeline writes `oracle_status`, and only `ml/anomaly.detect_anomalies`
    writes the anomaly columns. Neither is a `finding` label.
- Impact (other components / project):
  - ML and FUZZ consume the new columns.
  - Head-version tests derive the head from `MIGRATIONS`
    (`test_ml_ranker.py:43`, `test_plugins.py:45`).
  - ARCHITECTURE's store-contract `candidate` row is updated.
- Risk: low. The migration is additive and idempotent through `schema_version`.
- Deliverables:
  - [ ] `_M0013` + registry — done
  - [ ] Test: a fresh store has the columns, and a store at 12 migrates to 13 with NULLs — done
  - [ ] FR-CORE-14 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; the budget-ordering objective was put to the user, who chose `score` as the default; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — a fresh store is at head 13 with `oracle_status`, `anomaly_score`, `anomaly_flag` (`tests/test_ml_budget_and_scope.py::test_migration_13_adds_the_candidate_columns`, head derived from `MIGRATIONS`); head-version tests in `test_ml_ranker.py`/`test_plugins.py` pass unchanged. Full suite (2026-10-13, whole `tests/` at `369e887`, `FUZZLAB_REQUIRE_BROWSER=1`): 2868 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same labgen `--check`/fingerprint-gate tests that fail identically on `origin/main` in this environment (no scipy, scikit-learn or `gitleaks` binary); none is caused by this change.

### CC-CORE-0025 — Add `DEFAULT_BROWSER_HEADERS` (full header set, not UA alone) to `fuzzlab/core/http.py` (2026-09-25, BUG-0060/PA-0062)
- **Change:** adds `DEFAULT_BROWSER_HEADERS` (a dict: `DEFAULT_USER_AGENT` plus a
  matching `Accept`, `Accept-Language`, `Sec-Fetch-*` set, and
  `Upgrade-Insecure-Requests`) to `fuzzlab/core/http.py`, applied in place of
  `DEFAULT_USER_AGENT` alone at the same 6 call sites `CC-CORE-0024` introduced.
- **Why:** `CC-CORE-0024`'s UA-only constant fixed `BUG-0059`'s symptom but left every
  other header at `requests`' own non-browser defaults, which a WAF checks for as an
  internal-consistency signal independent of the UA string — see `CC-CRAWL-0010`/
  `BUG-0060` for the full incident; this entry is CORE's own half, the widened shared
  constant.
- **Verification:** offline — inspected a `DEFAULT_BROWSER_HEADERS`-configured
  session's prepared request headers directly; covered indirectly by the 6 importing
  tools' own test suites (83 tests total) continuing to pass.
- **Scope:** additive/widened constant only, no change to `HttpClient`'s own
  behavior/contract (`requirements.md` unaffected).

### CC-CORE-0024 — Add shared `DEFAULT_USER_AGENT` constant to `fuzzlab/core/http.py` (2026-09-25, BUG-0059/PA-0061)
- **Change:** adds `DEFAULT_USER_AGENT` (a realistic Chrome-on-Linux UA string) to
  `fuzzlab/core/http.py`, so every tool that opens its own bare `requests.Session()`
  sets the same header from one place instead of a hand-copied literal per call site
  (PA-0027).
- **Why:** `requests`' own default UA (`python-requests/x.y`) caused a real,
  live-reported failure (crawl returns `200` but `0` links against a real external
  target) — see `CC-CRAWL-0009`/`BUG-0059` for the full incident; this entry is CORE's
  own half, the shared constant 6 call sites across `fuzzlab/tools/`,
  `fuzzlab/greybox/`, and `fuzzlab/session/` now import and apply.
- **Verification:** offline only — no existing CORE test exercises `http.py`'s module
  constants directly; covered indirectly by `tests/test_spider_scope.py` (unaffected)
  continuing to pass after the importing side (`spider.py`) changed.
- **Scope:** additive constant only, no change to `HttpClient`'s own behavior/contract
  (`requirements.md` unaffected).

### CC-CORE-0023 — Map `csv_formula_injection` to the new `csv-formula-injection` category in `_VULN_TO_CATEGORY` (FR-CORE-13) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"csv_formula_injection": "csv-formula-injection"`. Mirrors `CC-CORE-0022`'s own `price_integrity_bypass` precedent: a genuinely new rule+strategy pair (`R-CSV-FORMULA-INJECTION`/`CsvFormulaInjectionStrategy`, built in `CC-FUZZ-0030` — that entry's own record has the full review-gate history: three blocking adequacy-review findings, all fixed pre-implementation) was needed, not a reuse of an existing one. This entry is the CORE-owned half: the one dict-entry mapping that lets `fuzzlab.harness.pipeline`'s own `evaluate()`/`category_to_oracle_class()` dispatch reach the new strategy at all for ground-truth-sourced runs.

  Live-verified end to end, mirroring `CC-CORE-0021`/`CC-CORE-0022`'s own discipline: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment scores `tp=3, fn=0, fp=0` — all three of this app's own ground-truth cases now match, closing its detection coverage entirely.

  This is the last of category 5's four classes for Booking.com's own ground truth — no further mapping is scoped for this app (only Expedia's own `insecure_deserialization` remains unmapped in this category, and it has no verified confirmer yet, flagged as requiring larger cross-cutting infrastructure work per this category's own change-control history, not attempted here).

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `2/3 -> 1.0`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (FUZZ component owns the new strategy/rule — see `CC-FUZZ-0030` for that component's own entry), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions).
- Risk (level; mitigation or accepted-risk justification): low. One dict entry, scoped and precedented by `CC-CORE-0020`/`0021`/`0022`. The real risk (a wrong or over-broad confirmer) was retired by `CC-FUZZ-0030`'s own pre-change review gate before this mapping was added; live end-to-end verification and the full whole-repo suite (see Effectiveness) confirm zero regressions.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["csv_formula_injection"]` — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/02-core-library/requirements.md`: `FR-CORE-13` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met. Real, verified result: `tp=3, fn=0, fp=0` against Booking.com's real, locally-booted deployment, recall `2/3 -> 1.0`. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0022 — Map `price_integrity_bypass` to the new `price-integrity-bypass` category in `_VULN_TO_CATEGORY` (FR-CORE-12) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"price_integrity_bypass": "price-integrity-bypass"`. Unlike `CC-CORE-0021`'s own `open_redirect` mapping (which reused a pre-existing rule+strategy pair), this class needed a genuinely new one — `R-PRICE-INTEGRITY`/`PriceIntegrityBypassStrategy`, built in `CC-FUZZ-0029` (this component's own FUZZ counterpart entry has the full record: pre-change review findings, canary design, live verification). This entry is the CORE-owned half: the one dict-entry mapping that lets `fuzzlab.harness.pipeline`'s own `evaluate()`/`category_to_oracle_class()` dispatch reach the new strategy at all for ground-truth-sourced runs.

  Live-verified end to end, mirroring `CC-CORE-0021`'s own discipline: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment scores `tp=2, fn=1, fp=0` for the real vulnerable twin (`LABGEN-BC-0005`) — a real, correctly-attributed true positive alongside `open_redirect`'s own (`CC-CORE-0021`), not a coincidence.

  Scoped to `price_integrity_bypass` only, not category 5's remaining unmapped class (`csv_formula_injection`): it has no verified confirmer yet (no `ConfirmationStrategy`/`Rule` pair exists for CSV-formula-injection detection) — mapping it now would only relabel an honest false negative as a mis-wired one, not a real improvement, matching `CC-CORE-0020`/`CC-CORE-0021`'s own established scoping discipline.

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `1/3 -> 2/3`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (FUZZ component owns the new strategy/rule — see `CC-FUZZ-0029` for that component's own entry), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions).
- Risk (level; mitigation or accepted-risk justification): low. One dict entry, scoped and precedented by `CC-CORE-0020`/`CC-CORE-0021`. The real risk (a wrong or over-broad confirmer) was retired by `CC-FUZZ-0029`'s own pre-change review gate before this mapping was added; live end-to-end verification and the full whole-repo suite (see Effectiveness) confirm zero regressions.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["price_integrity_bypass"]` — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/02-core-library/requirements.md`: `FR-CORE-12` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met. Real, verified result: `tp=2, fn=1, fp=0` against Booking.com's real, locally-booted deployment, recall `1/3 -> 2/3`. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0021 — Map `open_redirect` to the existing `open-redirect` category in `_VULN_TO_CATEGORY` (FR-CORE-11) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"open_redirect": "open-redirect"`. Mirrors `CC-CORE-0020`'s own `ssti` precedent exactly: a real rule (`R-OPEN-REDIRECT`, `fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "url|next|redirect|return|dest|goto|continue|target"` — matches Booking.com's real `return_to` param via its `return` alternative) and a real confirmation strategy (`OpenRedirectStrategy`, `fuzzlab/oracle/strategies.py`) already existed and were already correctly scoped for category 5's real cell (`LABGEN-BC-0001`, `CC-LAB-0210`) — purely a missing mapping, not a missing detector.

  **Two real, distinct code defects were found and fixed during this entry's own live-verification step** (per its own newly-added `PA-0042`, run before landing rather than trusting `confirm()`'s return value alone):
  1. **`BUG-0039`**: `RequestsProbeSender.send()` never set `allow_redirects=False` (unlike `fuzzlab.core.http`'s own authenticated client, which already does), so a real confirmation attempt against Booking.com's real vulnerable twin raised an uncaught `requests.exceptions.ProxyError` instead of returning a `Verdict` — `requests` tried to follow the strategy's own canary redirect target into an attacker-controlled/unreachable host. Fixed additively (`allow_redirects=False` added to that one sender, matching the other). No prior category's ground truth included a redirect-based sink, so no real confirmation run had ever reached this code path before.
  2. **`BUG-0040`**: after fixing `BUG-0039`, the confirmed finding still scored as a false positive (`tp=0, fp=1`), not a hit — `OpenRedirectStrategy.vuln_class` was `"open-redirect"` (hyphenated, matching this strategy's own `category` attribute) while every ground-truth case for this class (this project's `labels.schema.json` enum, every `open_redirect` manifest's `class:` field, `lab/safety_matrix.yaml`'s own `open_redirect` concern) uses `"open_redirect"` (underscored) — `fuzzlab.harness.scoring.score()`'s exact-key match never linked the two. Every sibling strategy (`SqliErrorStrategy`, `ReflectedXssStrategy`, `SstiStrategy`, etc.) already gets this right; `OpenRedirectStrategy` was an isolated inconsistency, latent since it was first authored (no `open_redirect` ground truth existed anywhere in this project to catch it until category 5's own work). Fixed: `vuln_class` corrected to `"open_redirect"`; `category` left unchanged (a separate, correctly-hyphenated namespace every strategy already uses consistently).

  Re-verified live, end to end, after both fixes: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment now scores `tp=1, fn=2, fp=0` for the real vulnerable twin (`LABGEN-BC-0001`) — a real, correctly-attributed true positive, not a relabeled false negative.

  Scoped to `open_redirect` only, not category 5's other three built classes (`csv_formula_injection`/`price_integrity_bypass`/`spel_injection`): none has a verified confirmer yet (no `ConfirmationStrategy`/`Rule` pair exists for CSV-formula-injection, business-logic price trust, or SpEL-evaluation-context detection) — mapping them now would only relabel an honest false negative as a mis-wired one, not a real improvement, matching `CC-CORE-0020`'s own established scoping discipline.

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `0 -> 1/3`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/tools/probesender.py` (`BUG-0039`'s fix — affects every confirmation strategy and every Phase E `multitarget.py` test across every category, additively; no existing passing test's expectations changed except `test_probesender.py`'s own fake, updated to assert the new setting), `fuzzlab/oracle/strategies.py` (`BUG-0040`'s fix, `OpenRedirectStrategy.vuln_class` only — no other strategy touched), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions). Both bug fixes are corrective, not new capability — component FUZZ (07) owns `fuzzlab/oracle/` and `fuzzlab/tools/probesender.py`; see that component's own change-control log for its own entry cross-referencing these same two bugs.
- Risk (level; mitigation or accepted-risk justification): low for the mapping itself (one dict entry, scoped and precedented). The `RequestsProbeSender` fix (`BUG-0039`) is the widest-blast-radius change in this entry — touches every existing caller of that sender — but is strictly *safer* than the prior behavior (was: crash or silently-wrong redirect-following; now: matches the already-correct authenticated client's own behavior) and the full whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own Phase E tests.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["open_redirect"]` — done
  - [x] `fuzzlab/tools/probesender.py`: `BUG-0039` fix — done
  - [x] `fuzzlab/oracle/strategies.py`: `BUG-0040` fix — done
  - [x] `tests/test_probesender.py`: updated fake + new assertion — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/bugs/BUG-0039-*.md`/`BUG-0040-*.md`, `ERROR_LOG.md`, `docs/PREVENTIVE_ACTIONS.md` (`PA-0041`/`PA-0042`) — done
  - [x] `docs/components/01-target-lab/requirements.md`/`docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-CORE-11`, cross-referenced from LAB's own Phase E entries — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. Live-verified end to end through the real scoring pipeline before landing (`PA-0042`'s own new rule, applied to itself): real `tp=1, fn=2, fp=0` against Booking.com's real, locally-booted deployment. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0020 — Map `ssti` to the existing `server-side-template-injection` category in `_VULN_TO_CATEGORY` (FR-CORE-10) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"ssti": "server-side-template-injection"`. This closes, for the `ssti` class specifically, a gap `CC-LAB-0138` (category 3, TrackerNest Phase E) flagged but did not fix: TrackerNest's real SSTI cell (`LABGEN-SSTI-0001`, OGNL evaluation of a raw query parameter) was scoring recall=0 purely because its ground-truth `vuln_class` (`"ssti"`) had no entry in this map, so `resolve_run`'s ground-truth-derived category set never included it and `evaluate()` never nominated a candidate for it — despite a real rule (`R-SSTI`, `fuzzlab/audit/rules_data/default_rules.json`, `category: server-side-template-injection`, `when: {location_in: [query, body]}`) and a real confirmation strategy (`SstiStrategy`, `fuzzlab/oracle/strategies.py`, already wired to that same category via `category_to_oracle_class`) already existing and already correctly scoped for this exact point shape (`macroExpr`, `location=query`).

  Scoped to `ssti` only, not all 6 of category 3's new classes: `xxe`/`insecure_deserialization`/`webhook_signature_bypass`/`ssrf`/`outbound_header_injection` have no confirmer built yet — mapping any of them now would only relabel an honest false negative as a mis-wired one (`evaluate()` would nominate a candidate `category_to_oracle_class()` returns `None` for, still never confirmed), not a real improvement, so they stay unmapped until each has its own verified confirmer (adequacy review's own finding, incorporated).

  `_VULN_TO_CATEGORY` is read only via `.get()` inside `to_category()`; nothing else iterates its keys or checks its size, so adding one key cannot affect any other, already-mapped class's behavior (checked directly, not assumed).

  Verified for real, not assumed: booted TrackerNest's real vulnerable SSTI cell live and sent `SstiStrategy`'s own existing payload set (`_ssti_payloads`, unmodified) directly against it — two of the five payloads (`{{a*b}}`, `#{a*b}`) genuinely evaluate under OGNL (`{{7*7}}` → `Rendered macro result: [[49]]`; OGNL's own list/map-literal syntax happens to nest the arithmetic result inside brackets/a map, but the product substring still appears and the un-evaluated expression string does not, which is exactly `SstiStrategy.confirm()`'s own pass condition: `product in text and expr not in text`) — so the existing strategy confirms this real vulnerability with zero changes to its own payload set or confirm logic. Also booted the real secure twin (`LABGEN-SSTI-0002`) with the same payloads and confirmed it never returns anything containing the product (`"Unknown macro"` for all payloads tested), so this mapping introduces no false-positive risk for that twin. Also checked no other ground truth anywhere in this now-consolidated branch uses `vuln_class: "ssti"` (only `lab/ground-truth-trackernest/labels.json` does, across all 10 `lab/ground-truth*/` directories currently on this branch), so this mapping's behavior change is scoped to exactly the one case it's meant to fix.

  Updates two of `CC-LAB-0138`'s/`CC-LAB-0140`'s own Phase E tests. `tests/test_labgen_spring_boot_trackernest_multitarget.py`: `tp==0`/`recall==0.0` → `tp==1`/`fp==0`/`fn==2`/`precision==1.0`/`recall≈1/3`, docstring corrected. `tests/test_multitarget_category3_combined.py`: the adequacy review caught a real gap in the first draft here — its single shared `for outcome in outcomes: assert tp==0` loop checked both targets identically, but only TrackerNest's outcome changes (Huddle Hub's own three classes remain entirely unmapped); restructured into per-target assertions (`trackernest_outcome.tp==1`/`recall≈1/3`, `huddlehub_outcome.tp==0`/`recall==0.0`), and the module's own docstring/inline comment corrected to state this precisely rather than the blanket "every class unmapped" framing the first draft would have left stale.
- Impact: Component 2 (CORE) primary; Component 1 (LAB)'s own two Phase E tests updated as a direct consequence (documented above, not a silent side effect). No change to `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (both already correctly built for this category; this entry only connects a third mapping this project's own docs already named as the missing piece).
- Risk: Low. One additive dict entry; verified against real running code (both twins) before landing, not just unit-level reasoning.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py` `_VULN_TO_CATEGORY["ssti"]` entry — done
  - [x] `tests/test_runmode.py`: `test_categories_from_vuln_classes_maps_ssti` + `test_categories_from_vuln_classes_leaves_unmapped_classes_unchanged` — done, both passing
  - [x] `tests/test_labgen_spring_boot_trackernest_multitarget.py`/`tests/test_multitarget_category3_combined.py` assertions + docstrings updated — done, re-run and passing (real `mvn package`/`java -jar` + real `composer install`/`artisan serve` boots)
  - [x] `docs/components/02-core-library/requirements.md` FR-CORE-10 entry — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met. `tests/test_runmode.py`'s 2 new unit tests pass. All 3 of `CC-LAB-0138`'s/`CC-LAB-0139`'s/`CC-LAB-0140`'s own Phase E tests re-run for real after this change: TrackerNest's own test now shows `tp=1`, `fn=2`, `precision=1.0`, `recall=1/3` (was `tp=0`/`recall=0.0`); the combined test correctly shows TrackerNest at `tp=1`/`recall≈1/3` and Huddle Hub still at `tp=0`/`recall=0.0`, with `generalizes` still correctly `False` (needs both scored targets above zero recall, not just one); Huddle Hub's own individual test unaffected (re-run, unchanged, still passing). Full non-slow suite re-run post-merge (this branch is now consolidated with categories 1/2/4/5's own work): 1838 passed, 52 skipped, 18 failed — every failure the same pre-existing `gitleaks`-binary/`scikit-learn`-dependency environment gap present before this change (more instances than category 3's own earlier baseline of 15, because the merged tree now has more manifests hitting the same missing-dependency gate — verified: identical failure shape, `2 gate(s) FAILED: secret scanner ... / metadata leakage gate ...`), zero regressions attributable to this entry.
- Pre-change review gate: drafted, reviewed by 2 independent agents (accuracy: all 6 specific factual claims checked — including an independent re-run of the exact live-boot reproduction against both real twins — found ACCURATE, no inaccuracies; adequacy: 6 findings — an undercounted test-update scope in `test_multitarget_category3_combined.py` (the real gap above, now fixed), a missing one-sentence statement of the dict-mutation-safety reasoning, a missing one-sentence statement of why only `ssti` and not the other 5 classes, a missing `Effectiveness: pending` placeholder line, an under-specified "unit coverage" deliverable (now named exactly), and a missing deliverables-checklist line for the docstring/comment corrections — all incorporated). 3/3 agreement reached by incorporating every concrete finding from both reviews without contesting any of them; implementation proceeds on this revised entry, matching this component's own gate discipline in full (unlike `CC-LAB-0138`-`0140`'s own acknowledged after-the-fact deviation).

### CC-CORE-0019 — Migration 12: `saved_views` table (U2-table, Findings workbench) (2026-09-22)
- Change: migration 12 (append-only registry; head → 12) adds
  `saved_views(id, table_key, name, spec_json, is_pinned, created_at,
  updated_at)` — a durable, server-side store for named filter/sort/column
  specs a person saves in a faceted workbench (the Findings workbench,
  `CC-UI-0029`, is the first caller; `table_key` names the logical dataset the
  view is over, e.g. `"finding"`, so other workbenches can reuse the same
  table later rather than inventing their own). `spec_json` is opaque to the
  store — it is only ever read/written as JSON by `fuzzlab.web.savedviews`,
  never queried by field. One index, `idx_saved_views_table(table_key)`, for
  the one read pattern (`GET /api/views?table=`). Additive; no existing
  table/column changed. **Note on bookkeeping numbering:** this CC-CORE number
  was not in lane U2's pre-assigned block (`docs/PARALLEL_LANE_BUILD_PLAN.md`
  reserved only `CC-UI-0029` for U2) — the lane's own scope statement
  (`fuzzlab/web/app.py` read route(s) plus the shared UI files) did not
  foresee needing a new store table. `CC-CORE-0019` was computed as "highest
  existing + 1" at the time this entry was written (mirroring how `B0`'s
  `metric_series` migration got both a `CC-CORE-0018` and a `CC-UI` entry);
  per PA-0031, an integrator merging this lane alongside others touching
  `02-core-library/change-control.md` should re-verify no other lane claimed
  `CC-CORE-0019` in the meantime before merging, rather than assuming this
  number is uncontested.
- Impact (other components / project): additive only. UI-owned data (view
  definitions a person authored in the panel), not a `finding`/`attempt`/
  `candidate`/flow result table, so it does not touch `NFR-UI-read-only`
  ("the UI writes no result tables") — see `CC-UI-0029`'s own impact note for
  why this is the one deliberate write path that requirement still allows.
  No other component reads or writes this table.
- Risk (level; mitigation): low — one additive table + one index, written only
  through `fuzzlab.web.savedviews`'s four functions (`list_views`/`get_view`/
  `create_view`/`update_view`/`delete_view`), each parameterized (no string-built
  SQL). Mitigated by `tests/test_web_findings.py`'s saved-view round-trip tests
  (direct store functions and the `/api/views` HTTP surface) and the existing
  `tests/test_core_foundations.py::test_migrations_are_idempotent` pattern
  (re-run here implicitly via every other store-backed web test creating a
  fresh store on migration 12).
- Deliverables:
  - [x] Migration 12 added to the append-only `MIGRATIONS` registry — done.
  - [x] `fuzzlab.web.savedviews` CRUD module — done.
  - [x] Round-trip tests (store-level + HTTP) — done.
- Effectiveness (assessed 2026-09-22): effective — saved views persist across
  store reopens and are visible to any reader of the same store file, unlike
  the `localStorage`-only alternative R-03 explicitly rejected for this data.

### CC-CORE-0018 — Migration 11: `metric_series` table + `open_store()`/`log_scalar`/`MetricLogger` (B0-table, Phase 4b) (2026-09-22)
- Change: migration 11 (append-only registry; head → 11) adds `metric_series(id, run_id,
  source, key, step, ts, value)`, the generic cross-run scalar-series sink for per-step
  emitters (GBT/logistic training curves, bandit posterior/regret, coverage-frontier
  growth, `MutationSearch` reward/novelty, stage wall-clock/throughput — those emitters
  themselves are separate lanes, not part of this change). `run_id INTEGER REFERENCES
  run(id)` (the store's actual runs table is `run`, singular — matches every other
  migration; R-05's "`runs(id)`" phrasing was generic, not a literal table name);
  `value REAL NOT NULL`; two indexes for the two read patterns: `idx_metric_series_run
  (run_id, source, key, step)` (one series within a run) and
  `idx_metric_series_overlay (source, key, run_id, step)` (cross-run overlay). Also:
  added `fuzzlab.core.store.open_store()`, the central WAL-configured connection
  constructor R-08 calls for (`journal_mode=WAL`, `busy_timeout=10000`,
  `synchronous=NORMAL`, `foreign_keys=ON`, connect-time `timeout=10.0`); `connect()` is
  now a thin backward-compatible alias for it (previously `connect()` set
  `busy_timeout=5000` with no connect-time `timeout=` — now centralized and raised to
  match R-08's resolved design). Added `log_scalar(store, run_id, source, key, step,
  value, ts=None)` (accepts a `Store` or a raw connection from `open_store()`) and
  `MetricLogger(store, run_id, source, flush_every=200)`, a buffered context-manager
  writer that batches an `executemany` every `flush_every` rows and flushes on
  `__exit__`/exception. Both reject non-finite (`NaN`/`inf`) values — dropped with a
  `UserWarning`, never written — per R-05 (no `is_nan` column, no NaN read-branch).
- Impact (other components / project): additive only; no existing table, column, or
  pragma value that any current caller depended on changed in a breaking way (raising
  `busy_timeout` 5000→10000 and adding connect `timeout=10.0` only widens the lock-wait
  window). This is the **table-only** slice of the B0 lane — the GBT/logistic,
  bandit-loop, coverage-frontier, and `MutationSearch` emitters that will write through
  `log_scalar`/`MetricLogger` are separate, later lanes (reserved `CC-ML-0009`,
  `CC-SCHED-0005`, `CC-FUZZ-0021`, `CC-MUT-0011` per
  `docs/PARALLEL_LANE_BUILD_PLAN.md`), not built here. The diagnostics UI (U5) reads this
  table once it lands.
- Risk (level; mitigation): low — one additive table + two indexes + a new always-central
  connection constructor that the existing `connect()` now simply delegates to. Mitigated
  by `tests/test_core_foundations.py::test_migrations_are_idempotent` (now also asserts
  `metric_series` exists), `test_open_store_is_wal_smoke` (R-08's required WAL smoke
  test), `test_metric_series_schema_and_indexes`, `test_log_scalar_roundtrip`,
  `test_log_scalar_accepts_raw_connection`, `test_log_scalar_rejects_non_finite`
  (parametrized NaN/+inf/-inf), `test_metric_logger_flushes_every_n`, and
  `test_metric_logger_drops_non_finite_and_flushes_on_exception`. Full suite (excluding
  pre-existing, unrelated collection failures in this environment from a missing
  `covertable` package and an unavailable `starlette.testclient` — both present before
  this change, confirmed via `git stash`): 486 passed / 2 skipped / 2 pre-existing
  failures unrelated to this change (`test_web_commandspec.py`, same `covertable`-driven
  registration gap, reproduced identically on the pre-change tree).
- Deliverables:
  - [x] Migration 11 (`metric_series` table + both indexes) — done.
  - [x] Central `open_store()` (WAL/busy_timeout/synchronous/foreign_keys/timeout),
    `connect()` kept as an alias — done.
  - [x] `log_scalar()` + `MetricLogger` (buffered, `flush_every=200` default,
    non-finite rejection) — done.
  - [x] R-08 WAL smoke test — done.
  - [ ] Per-component emitters (GBT/logistic, bandit-loop, coverage-frontier,
    `MutationSearch`) — explicitly out of scope for this lane; separate dispatches.
- Effectiveness (assessed 2026-09-22): effective — migration is additive/reversible-safe
  (no data touched, no column type changed), the full suite is unaffected, and the write
  path (`log_scalar`/`MetricLogger`) is ready for the emitter lanes to adopt.

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
