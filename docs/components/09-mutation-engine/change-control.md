# Mutation Engine — Change Control Log

Component code: **MUT**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-MUT-0010 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/mutation/cli.py::build_parser()` gained `--dry-run` (via the
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). `main()` checks `args.dry_run`
  first — before the `--authorized` gate and before resolving `--base` payloads —
  and calls `fuzzlab/cli_dryrun.report("mutate-run", args)`, reusing the web
  launcher's existing dry-run plan/report logic (`fuzzlab/web/commandspec.spec()` +
  `fuzzlab/web/runner.build_argv()`/`display_command()`, CC-UI-0013/0015), then
  returns 0 before `make_probe_sender`/`Store`/`mrun.run_mutation` are ever called.
  No payload is sent. Unchanged when `--dry-run` is absent.
- Impact (other components / project): MUT only, plus an incidental UI effect — see
  CC-UI-0027 (introspected `build_parser()` surfaces the new checkbox in the web
  launcher automatically; `fuzzlab/web/app.py` untouched). No schema/store change; no
  interaction with Wave C1's `CC-MUT-0009` M8-wiring (different code paths —
  `fuzzlab/mutation/run.py`'s attempt-path wiring vs. this CLI's flag).
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect. Mitigated by `tests/test_cli_dry_run.py` (mutate-run case: flag present,
  report printed, `mrun.run_mutation`/`Store.__init__`/`make_probe_sender` patched to
  raise if called) and the unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `mutate-run`'s parser — done.
  - [x] Short-circuit ahead of the `--authorized` gate in `main()`, calling the
    shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab mutate-run --dry-run`
  prints the planned argv/command and returns 0 without constructing a sender,
  `Store`, or running the mutation search; verified directly and via the new tests.
### CC-MUT-0009 — Reach the main harness's attempt path, not just `mutate-run` (Lane C1/M8-wiring) (2026-09-22)
- Change: companion entry to `CC-FUZZ-0019` (see that entry for the full
  mechanism — this one records the MUT-side of the same change). T8.5's "emit
  accepted variants into the attempt path" previously only reached the
  standalone `fuzzlab mutate-run` CLI's own attempt/summary loop
  (`fuzzlab/mutation/run.py::run_mutation`); `fuzzlab/mutation/operators.py`
  (T8.1), `semantics.py` (T8.1) and `catalog.record_variant` (T8.5) are now also
  called directly from `fuzzlab/greybox/run.py` (the FUZZ component's own
  harness), so `greybox-run` generates, probes, and — via the same destructive-
  gated `record_variant` — writes back mutation variants too, without going
  through `mutate-run`/`MutationSearch`/`HttpFilter`'s live-WAF-learning loop at
  all (that remains `mutate-run`'s job; this is a lighter, offline-generated
  variant set bounded by `max_mutation_variants` per attack probe, screened by
  whether it actually hit/reached new code when the harness sent it — no
  separate live WAF-caught/evaded round-trip like `MutationSearch` runs). No
  code in `fuzzlab/mutation/` itself changed; this is purely a new consumer of
  its existing public surface (`default_operators`, `SemanticsValidator`,
  `record_variant`).
- Impact (other components / project): `payload_variant` (migration 8) now has
  two writers — `mutate-run` (unchanged) and `greybox-run` (new, opt-in). Both
  go through the same `record_variant`/destructive-gate function (PA-0003:
  single shared write path), so the gate and schema stay consistent across
  writers. FUZZ (`greybox/run.py`) gained an import-time dependency on this
  component; no circular import (this component's own live-search code path
  only imports `fuzzlab.greybox.run` inside a function body, for
  `mutation/run.py::make_coverage_fn`, which is unaffected).
- Risk (level; mitigation): low — no existing MUT code changed, only a new
  external caller of already-tested functions (`default_operators`,
  `SemanticsValidator.preserves`, `record_variant`, all covered by
  `tests/test_mutation_operators.py` and `tests/test_mutation_catalog.py`
  already). The `url-encode` operator is deliberately skipped by the new
  caller (double-encoding over the probe transport — see `CC-FUZZ-0019`); no
  change to which operators `mutate-run` itself uses.
- Deliverables:
  - [x] No `fuzzlab/mutation/` source changes required — verified the existing
    public surface (`default_operators`, `SemanticsValidator`, `record_variant`)
    is sufficient for the new caller — done.
  - [x] `tests/test_greybox_live.py` regression tests proving the new caller
    round-trips correctly through `record_variant`/`payload_variant` (see
    `CC-FUZZ-0019` for the list) — done.
  - [x] `docs/components/09-mutation-engine/requirements.md` FR-MUT-6 updated
    in place to reflect the now-dual write-back path — done.
  - [x] CHANGELOG.md line (shared with `CC-FUZZ-0019`) — done.
- Effectiveness (assessed 2026-09-22): effective — `payload_variant` rows now
  originate from `greybox-run` when `--mutation-variants` is passed, proven by
  `test_run_greybox_consumes_mutation_variants_into_attempt_path`, with no
  change to `mutate-run`'s own behavior or existing MUT test suite (still
  green).

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
