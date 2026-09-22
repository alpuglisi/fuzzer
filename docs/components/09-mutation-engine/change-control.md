# Mutation Engine — Change Control Log

Component code: **MUT**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-MUT-0009 — Read `payload_variant` back in as live-attempt candidates (close a confirmed wiring gap) (2026-09-22)
- Change: a change-control/roadmap audit confirmed (by grep, not inference) that
  `payload_variant` (written by `fuzzlab/mutation/{run.py,catalog.py}`) was never read
  back in anywhere in the scheduler/candidate/fuzzer attempt pipeline — the live
  `attempt` path (`fuzzlab/greybox/run.py::run_greybox`) only ever sent its fixed
  `DEFAULT_PROBES`. New `fuzzlab/scheduler/variants.py` (SCHED component; see mirrored
  CC-SCHED-0005) adds `load_variant_candidates`/`variant_probe_specs`, which read
  `payload_variant` rows — optionally scoped by `vuln_class`/`sink_context`/`run_id`,
  bounded by `limit`, and excluding non-semantics-preserving rows by default — and map
  them to `greybox.run.ProbeSpec`s (`family="mut:<vuln_class>:<row id>"`, so an
  `attempt.payload_family` traces back to its exact `payload_variant` row). This mirrors
  the existing catalog candidate-source seam (`catalog_families`/`catalog_priors`
  reading `references/<cat>/payloads/*.txt`) but reads the mutation engine's DB-backed
  catalog instead of files. Wired into the CLI: `fuzzlab greybox-run --mutation-variants`
  (default off) and `--mutation-limit` (default 25) merge these probes **additively**
  into `run_greybox`'s probe set — never replacing the defaults — scoped to the run's
  known vuln classes when any are known (ground-truth points), else pooled across all
  recorded variants. No new gate needed: `greybox-run` already refuses to run at all
  without `--authorized` (D11), unconditionally, so the new candidate source inherits
  the same authorization gate as every other request-sending path in this project —
  verified by a dedicated test that `--mutation-variants` alone (no `--authorized`)
  still refuses.
- Impact (other components / project): SCHED (new module, exported from
  `fuzzlab.scheduler`) and the greybox CLI (`fuzzlab/greybox/greybox_cli.py`) both
  changed; this entry is mirrored in `docs/components/08-payload-scheduler/
  change-control.md` (CC-SCHED-0005) per CLAUDE.md's per-component change-control rule.
  Requirements: FR-MUT-8 (this doc) and FR-SCHED-9 (mirrored). No schema change (reads
  the existing migration-8 `payload_variant` table); no change to default behavior
  (opt-in flag, off by default, so every existing `greybox-run` invocation is
  unaffected).
- Risk (level; mitigation): low-medium — this is a new path that can send real requests
  (mutation-engine variants against the live lab), but it is default-off, additive
  (never replaces the existing probes), bounded by `--mutation-limit`, and gated by the
  same unconditional `--authorized` check every other `greybox-run` probe already goes
  through. Mitigated by `tests/test_scheduler_variants.py` (10 tests: round-trip of a
  real `payload_variant` row; vuln_class/sink_context/run_id scoping; `semantics_ok`
  filtering on by default; `limit`; the `ProbeSpec` shape and family->row traceability;
  vuln_class->probe-kind mapping; and an end-to-end test that seeds a real row, converts
  it, and drives a real `run_greybox` call against a test-double sender, asserting the
  resulting `attempt` row's `payload_family`/`reward`/`db_fault` and that the actual
  mutation-engine payload string — not the base payload — was sent) and
  `tests/test_greybox_cli_mutation_variants.py` (4 tests: the new flags parse and
  default off; `--authorized` is still required with `--mutation-variants` set; `main()`
  merges the real variant into the probe set additively when the flag is set; `main()`
  uses only the defaults, ignoring an existing `payload_variant` row, when the flag is
  not set). Full suite: 1591 passed, 8 skipped, 12 deselected (no regressions).
- Deliverables:
  - [x] `fuzzlab/scheduler/variants.py` (`VariantCandidate`, `load_variant_candidates`,
    `variant_probe_specs`) — done.
  - [x] Exported from `fuzzlab.scheduler` — done.
  - [x] `fuzzlab greybox-run --mutation-variants`/`--mutation-limit`, additive wiring
    into `run_greybox`, `--authorized`-gated — done.
  - [x] Round-trip + CLI-wiring tests (no regressions) — done.
  - [x] FR-MUT-8, FR-SCHED-9, `docs/ARCHITECTURE.md` Phase 8 status — done.
- Effectiveness (assessed 2026-09-22): effective — a real `payload_variant` row now
  reaches a real `attempt` row through the live grey-box path via the new,
  `--authorized`-gated, default-off, additive candidate source; the previously-confirmed
  gap (variants written but never read back in) is closed for the offline/test-double
  path. Live-lab confirmation that this measurably improves attempt yield is future
  on-host work, not claimed here.

### CC-MUT-0008 — Fix `SemanticsValidator` fail-open on untrusted SQL comment-append; fix AST case-sensitivity (2026-09-22)
- Change: `fuzzlab/mutation/semantics.py` — added `introduces_line_comment(original,
  mutated)` (true when `mutated` carries a `--` marker `original` didn't) and made
  `SemanticsValidator.preserves()` refuse (return `False`) any *untrusted* mutation for
  a SQL-like `vuln_class` that introduces one, before the AST/canonical checks run —
  those checks cannot see that a `--` comment truncates everything after it once the
  fragment is concatenated into the real query, so they were fail-opening on it
  (`sqlglot` discards comments as non-semantic trivia; `canonicalize()` only strips
  bounded `/* */` block comments). `trusted=True` is unaffected — still accepted by
  provenance. Also fixed `_ast_equiv()` to compare `pa.sql().lower() == pb.sql().lower()`
  instead of raw `sqlglot` node `==`, which was case-sensitive and wrongly rejected a
  genuinely meaning-preserving `case-toggle` variant (SQL keywords/unquoted identifiers
  are case-insensitive; `canonicalize()` already lowercases for the same reason).
- Impact: fixes the two chronically-failing tests
  (`tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics`,
  `::test_sql_equivalent_needs_trusted_provenance`) without special-casing their literal
  inputs — the fix is a general fail-closed rule plus a general case-normalization fix.
  Both `fuzzlab/mutation/learn.py` and `fuzzlab/mutation/search.py` call
  `SemanticsValidator.preserves()` directly and inherit the corrected behavior with no
  code change of their own (PA-0002 sweep: no other equivalence/validator predicate
  exists in `fuzzlab/mutation/`). No schema change; no new dependency; no traffic.
  New regression tests derive the checked operator set from `default_operators()`
  (PA-0027 discipline) rather than a hardcoded operator-id literal.
- Risk (level; mitigation): low — a validator-only correctness fix, narrower in one
  direction (rejects more) and case-normalizing in the other (accepts a previously
  wrongly-rejected true positive). Mitigated by the full suite: 1494 passed, 8 skipped,
  0 failed (was 2 failed before this change, same suite otherwise).
- Deliverables:
  - [x] `introduces_line_comment()` + fail-closed gate in `preserves()` — done.
  - [x] Case-insensitive `_ast_equiv()` — done.
  - [x] `docs/bugs/BUG-0026-semantics-validator-fail-open-on-untrusted-sql-comment.md`
    (Five Whys RCA) — done.
  - [x] `docs/PREVENTIVE_ACTIONS.md` PA-0028 — done.
  - [x] Regression tests in `tests/test_mutation_operators.py` — done.
- Effectiveness (assessed 2026-09-22): effective — both previously-chronic failures
  pass, the full suite is green, and the fix is structural (a rule over any `--`-
  introducing transform, checked against the operator registry) rather than a literal
  special-case for the two test inputs.

### CC-MUT-0007 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/mutation/cli.py` now factors its argparse setup into `build_parser()`;
  `main()` keeps the `p` reference (so `p.error(...)` still works) and delegates parsing.
  Behavior-preserving — same flags, defaults, and both gates (`--authorized`,
  `--allow-destructive`).
- Impact: lets the web launcher introspect `mutate-run`'s flags (CC-UI-0011), including the
  destructive-gate detection. No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds `mutate-run`'s spec
  from this parser (destructive_gate derived from `--allow-destructive`).

### CC-MUT-0006 — Live WAF-evasion last mile: HttpFilter + `fuzzlab mutate-run` (T8.7 on-host) (2026-09-21)
- Change: built the Phase 8 on-host last mile so runbook Part J is a one-command flow. New
  `fuzzlab/mutation/livefilter.py::HttpFilter` implements the mutation `Filter` seam
  (`caught`/`evaluate`) against the **live** lab WAF — it sends the payload through a probe
  sender and maps the block status (HTTP 403) to "caught", parsing matched rule ids from
  the block page. New `fuzzlab/mutation/run.py::run_mutation` + `fuzzlab mutate-run`
  (`fuzzlab/mutation/cli.py`, dispatched in `cli.py`): per base payload, run
  `MutationSearch` against the live filter and, when the base is blocked and a
  semantics-preserving variant evades, record it via the destructive-gated
  `record_search_result` (`payload_variant`). `make_coverage_fn` wires a coverage function
  over the Part E grey-box side channel so `coverage_gain` (new app lines the variant
  reaches) is measured live. Orchestration `scripts/waf_evasion_e2e.sh`.
- Impact (other components / project): the mutation engine — previously import-only — is
  now driven end to end against the running lab; it reuses the existing `Filter` seam,
  `MutationSearch`, validator, and `record_variant` unchanged (only a new live `Filter`
  impl + a runner). Depends on the lab WAF (D16, CC-LAB-0006) being enabled and, for the
  coverage half, the Part E instrumentation (CC-LAB-0009 / CC-FUZZ-0016). The destructive
  gate (NFR-MUT-safe) still governs what is recorded.
- Risk (level; mitigation): medium — it sends attack payloads at the live lab. Mitigated
  by: `--authorized` gating the run, loopback-only, the destructive-payload gate on
  write-back (default refuses), semantics validation before a variant counts as a bypass
  (no false "bypass"), and the script always restoring the WAF to OFF (even on error) so
  the lab returns to its default state and ground-truth labels stay valid. Tests
  (`tests/test_mutation_live.py`): HttpFilter block/allow mapping + rule-id parsing, and
  `run_mutation` finding + recording a preserving bypass against a fake WAF while NOT
  recording when the base is unblocked. Suite 415 passed / 5 skipped.
- Deliverables:
  - [x] `HttpFilter` (live `Filter` seam) + rule-id parsing + tests — done.
  - [x] `run_mutation` + `fuzzlab mutate-run` CLI + coverage wiring — done.
  - [x] `scripts/waf_evasion_e2e.sh` (enable → evade → verify → restore off) — done.
  - [x] Runbook Part J rewritten; MUT requirements status updated — done.
  - [ ] Oracle-confirm the accepted variant is a real finding (nice-to-have) — todo.
- Effectiveness (assessed 2026-09-21): effective offline — the driver finds and records a
  semantics-preserving bypass against a modeled WAF and refrains when the base is not
  blocked. The live evasion + before/after (base 403, variant 200) is driven by
  `scripts/waf_evasion_e2e.sh` against the real WAF on-host.

### CC-MUT-0005 — Variant write-back + destructive gate; gated LLM scaffold (T8.5/T8.6) (2026-09-21)
- Change: `fuzzlab/mutation/catalog.py` records accepted variants' provenance to the
  `payload_variant` table (operator chain, `bypassed_rule`, `semantics_ok`,
  `coverage_gain`) via `record_variant`/`record_search_result`, and enforces the
  **destructive gate** (`is_destructive`): a destructive-looking variant is refused —
  never persisted or sent — unless `allow_destructive` is explicitly set (default off,
  matching `core/config.py`; NFR-MUT-safe). `fuzzlab/mutation/llm.py::LlmExpander` is the
  FR-MUT-5 scaffold: **default off**, **never calls an external service** (an injected
  offline generator or nothing), and everything it produces is **quarantined for human
  review** — nothing is trusted until approved (NFR-MUT-offline).
- Impact (other components / project): FR-MUT-6 write-back (into the new
  `payload_variant` table; live runs also send variants through the fuzzer's `attempt`
  path) and the safe, gated expansion path. This completes the mutation engine's
  **offline** stack; the live filter-bypass + coverage exit (T8.7) is on-host.
- Risk (level; mitigation): low — additive writes behind the destructive gate; the LLM
  path is off and offline. Mitigated by 7 tests (`tests/test_mutation_catalog.py`):
  destructive detection; non-destructive persists; the gate refuses by default and
  persists only on explicit opt-in; `record_search_result`; LLM default-off and
  disabled-ignores-generator; enabled quarantines for review and approval moves entries.
  Suite 317 passed / 4 skipped.
- Deliverables:
  - [x] Variant write-back to `payload_variant` + destructive gate (T8.5) — done.
  - [x] Gated, offline, default-off LLM expansion scaffold (T8.6) — done.
  - [ ] Exit: variants bypass the live WAF + reach new code vs the catalog (T8.7) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — variants persist with
  provenance behind the destructive gate and the LLM path stays off/offline/quarantined;
  the live coverage + bypass exit is on-host.

### CC-MUT-0004 — Bandit-scheduled, coverage-guided search (T8.4) (2026-09-21)
- Change: `fuzzlab/mutation/search.py::MutationSearch` searches for a
  **semantics-preserving** variant that evades the filter and reaches new code. Operators
  are chosen with the reused `ThompsonBandit` (reward = evasion + coverage novelty, and
  **zero for any meaning-changing variant**), the search hill-climbs (accepts an improving
  variant as the new working point), reads coverage through an injected `coverage_fn`
  (offline fake; live grey-box source), and is budget-bounded + reproducible under a fixed
  seed (NFR-MUT-bounded). With no `coverage_fn` the objective is pure evasion and it stops
  at the first preserving bypass.
- Impact (other components / project): FR-MUT-4 — the search that combines the operators
  (T8.1), context-typed generation (T8.2), and filter learning (T8.3) under the bandit and
  the grey-box signal. Reuses the scheduler and the grey-box `CoverageFrontier`; the live
  coverage-guided run is on-host. Feeds the write-back (T8.5).
- Risk (level; mitigation): low — pure logic behind seams; the reward structurally
  refuses meaning-changing variants. Mitigated by 7 tests (`tests/test_mutation_search.py`):
  reward is zero when meaning changes; pure-evasion finds a preserving bypass; coverage-
  guided accumulates novelty and evades; determinism under seed; budget bound; the bandit
  is actually updated; already-uncaught base returns immediately. Suite 310 passed / 4 skipped.
- Deliverables:
  - [x] `MutationSearch` (bandit operator selection + coverage hill climbing) (T8.4) — done.
  - [ ] Variant write-back + destructive gate (T8.5); gated LLM scaffold (T8.6); exit (T8.7) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the search finds evading,
  semantics-preserving, coverage-gaining variants deterministically within budget; the
  live coverage exit is on-host.

### CC-MUT-0003 — Context-typed XSS + filter model & bypass learning (T8.2/T8.3) (2026-09-21)
- Change: `fuzzlab/mutation/xss.py` generates **context-typed** XSS candidates keyed on
  the auditor's sink context (`html`/`html-attribute`/`url-attribute`/`js`, from
  `oracle/context.py`), and is **filter-aware** — given the blocked signatures it drops
  caught candidates and keeps working ones (e.g. `<svg onfocus=…>` when `<script>`/
  `onerror=` are filtered), falling back to the full list if all are blocked.
  `fuzzlab/mutation/filtermodel.py::FilterModel` mirrors the PHP lab WAF from the
  **shared** `waf-rules.json` (block/sanitize/log) so filter learning is testable offline
  (one ruleset, two consumers). `fuzzlab/mutation/learn.py::FilterLearner` observes what
  the filter blocks/strips and runs a bounded BFS over operator chains for a
  **semantics-preserving** variant the filter does not catch (`learn_bypass`,
  shallowest-first, preserving over trusted).
- Impact (other components / project): realizes FR-MUT-2 (context-typed generation) and
  FR-MUT-3 (filter-transformation learning) against the D16 WAF, offline. The `Filter`
  protocol lets the same learner run live (canary round-trips through the HTTP/proxy seam)
  later. Feeds the bandit/coverage search (T8.4) and the write-back (T8.5). No store
  change.
- Risk (level; mitigation): low — pure logic over the shared ruleset; advisory; nothing
  sent. Mitigated by 14 tests (`tests/test_mutation_xss.py`, `tests/test_mutation_filter.py`):
  context mapping; context-appropriate + filter-aware payloads (drop blocked, keep working,
  all-blocked fallback); PHP→regex; filter catches naive / misses classic bypass; the
  three modes; evading operators found; `learn_bypass` yields a shallow semantics-preserving
  evasion, no-ops when already uncaught; sanitize-mode transform observation. Suite 303
  passed / 4 skipped.
- Deliverables:
  - [x] Context-typed, filter-aware XSS generator (T8.2) — done.
  - [x] Offline `FilterModel` + `FilterLearner` bypass discovery (T8.3) — done.
  - [ ] Bandit/coverage search (T8.4); write-back (T8.5); LLM scaffold (T8.6); exit (T8.7) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the generator yields
  filter-avoiding context-typed payloads and the learner finds semantics-preserving
  bypasses of the lab WAF; live canary learning + the coverage exit are on-host.

### CC-MUT-0002 — Operator framework + semantics validator (T8.1) (2026-09-21)
- Change: started the mutation engine. `fuzzlab/mutation/operators.py` defines typed,
  **semantics-preserving** operators (`url-encode`, `ws-alt`, `sql-comment`,
  `case-toggle`, and the vetted-equivalent `sql-equivalent`), each declaring the vuln
  classes it applies to and returning deterministic distinct variants; `apply_chain`
  composes them. `fuzzlab/mutation/semantics.py::SemanticsValidator` refutes
  meaning-changing mutations via canonicalization (single URL-decode, strip SQL inline
  comments, collapse whitespace, lowercase) with an AST-equivalence path over `sqlglot`
  (skip-guarded where the build is absent, like `cryptography`). Vetted-equivalent
  swaps (tautologies) are accepted by provenance (`trusted=True`), not re-derived. Wrote
  `docs/PHASE_8_PLAN.md`. Declared `sqlglot` (and the previously-missing `h11`) in
  `pyproject.toml` (PA-0005).
- Impact (other components / project): gives Phase 8 its meaning-preserving substrate —
  the operators that defeat naive filters and the validator that guarantees NFR-MUT-
  semantics — that the context-typed XSS (T8.2), filter learning (T8.3), and
  bandit/coverage search (T8.4) build on. Migration 8's `payload_variant` table (see
  CC-CORE-0014) is ready for the write-back (T8.5). No behavior change to other tools.
- Risk (level; mitigation): low — pure, dependency-light string logic; the AST path is
  optional and skip-guarded; nothing is sent. Mitigated by 11 tests
  (`tests/test_mutation_operators.py`, 1 skipped for absent `sqlglot`): migration-8
  schema; class filtering; every surface variant preserves semantics; URL-encode
  round-trips; whitespace/comment evasive-but-equivalent; no-op returns empty; the
  vetted-equivalent operator needs `trusted` provenance; the validator rejects meaning
  changes; canonicalization; deterministic chains. Suite 289 passed / 4 skipped.
- Deliverables:
  - [x] Typed semantics-preserving operators + `apply_chain` (T8.1) — done.
  - [x] `SemanticsValidator` (canonical + AST, skip-guarded) (T8.1) — done.
  - [ ] Context-typed XSS (T8.2); filter learning (T8.3); bandit/coverage search (T8.4);
        variant write-back (T8.5); gated LLM scaffold (T8.6); on-host exit (T8.7) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — operators produce evasive
  variants that the validator confirms preserve meaning, and it rejects meaning changes;
  the live filter-bypass + coverage exit is on-host.

### CC-MUT-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  payloads today come only from the static catalog.
- Impact (other components / project): once built, it feeds new candidates back
  into the catalog/attempts, so its variants flow through the scheduler, fuzzer,
  and oracle like any payload. Its search depends on grey-box coverage (LAB) and
  the scheduler for operator selection; it benefits from the auditor's sink-context
  typing for XSS generation.
- Risk (level; mitigation): medium — meaning-changing mutations produce false
  candidates and waste budget; generated payloads could be destructive. Mitigated
  by a semantics-preservation validator, the default-off destructive gate applying
  to generated payloads, budget-bounded reproducible search, and keeping any LLM
  expansion offline and human-gated. Scheduled late (Phase 8), after the oracle,
  scheduler, and grey-box exist.
- Deliverables:
  - [ ] AST parsing + typed semantics-preserving SQL operators — todo (Phase 8).
  - [ ] Context-typed XSS generation — todo (Phase 8).
  - [ ] Filter-transformation learning from canaries — todo (Phase 8).
  - [ ] Bandit-scheduled operators + coverage-guided hill climbing — todo (Phase 8).
  - [ ] Gated offline LLM catalog expansion (default off) — todo (Phase 8).
  - [ ] Write new candidates back to catalog/attempts — todo (Phase 8).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  coverage reached beyond the static catalog and by the semantics validator's
  rejection of meaning-changing transformations.
