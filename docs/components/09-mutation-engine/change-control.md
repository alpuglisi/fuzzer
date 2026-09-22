# Mutation Engine — Change Control Log

Component code: **MUT**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-MUT-0012 — Robustness: `mutation/cli.py` clean error handling (2026-09-22)
- Change: `mutation/cli.py::main()` had zero exception or `KeyboardInterrupt`
  handling anywhere — unlike `blind_sqli_fuzzer.py`'s equivalent driver, a
  network error or Ctrl-C during the live WAF probing `mrun.run_mutation()`
  performs produced a raw traceback. Wrapped the `Store`/`run_mutation` block in
  `try/except`: `KeyboardInterrupt` → clean message noting any bypasses already
  recorded stay in the store (the `Store` context manager's own commit-on-exit
  behavior already made this true; the fix is reporting it cleanly, not new
  persistence logic), exit 0; any other exception → clean `p.error()` message,
  exit 2 (matching the `--authorized`/no-base-payloads guards already using
  `p.error()` in this file).
- Impact (other components / project): none — additive exception handling only;
  `run_mutation`'s own semantics (destructive gate, `--confirm-oracle`, the
  oracle/advisory split) are untouched.
- Risk (level; mitigation): low. Mitigated by 3 new tests in
  `tests/test_mutation_cli.py` (this file had zero prior coverage — every
  existing `test_mutation_*.py` file tests the operators/search/catalog/filter
  modules, never `mutation/cli.py`): a `KeyboardInterrupt` during `run_mutation`
  is reported cleanly; a network error exits cleanly via `p.error()`; the
  existing `--authorized` gate still refuses before sending anything.
- Deliverables:
  - [x] Exception/`KeyboardInterrupt` handling around `main()`'s run — done.
  - [x] `tests/test_mutation_cli.py` (3 tests) — done.
- Effectiveness (assessed 2026-09-22): effective — all 3 new tests pass; the
  existing `test_mutation_*.py` suites (64 tests) pass unchanged.

### CC-MUT-0011 — Advanced evasion operators: `double-url-encode` + `unicode-fullwidth` (2026-09-22)
- Change: two new `ANY`-class, provably meaning-preserving `MutationOperator`s.
  `double-url-encode` percent-encodes the payload twice (many WAFs decode once
  before pattern-matching; some backends/proxies decode recursively).
  `unicode-fullwidth` substitutes every ASCII punctuation/letter/digit character
  (0x21-0x7E) with its Unicode "fullwidth form" (U+FF01-FF5E, the standard
  +0xFEE0 offset) — a WAF signature matching ASCII literally misses it, while a
  backend or database engine that NFKC-normalizes still sees the original
  character. Both register in `operators.py::_ALL` like every other operator, so
  `default_operators()`, `MutationSearch`, `FilterLearner`, and `mutate-run`
  consume them automatically with zero additional wiring (verified: no other
  module hardcodes the operator id list).
  `SemanticsValidator.canonicalize()` (`mutation/semantics.py`) was extended to
  make both **provably** meaning-preserving rather than merely claimed so:
  URL-decoding is now a bounded fixpoint loop (was a single `unquote()` pass) so a
  multiply-encoded variant still normalizes back to the original, and NFKC
  normalization was added (folds fullwidth/compatibility Unicode forms to ASCII).
  The two normalizations are **interleaved in one fixpoint loop**, not run as two
  separate passes — testing an `apply_chain` composition of the two new operators
  (double-encode, then fullwidth) surfaced a real bug in a first draft that ran
  them as sequential passes: fullwidth-substituting an already percent-encoded
  string's literal `%`/digits (`%2520` -> `％２５２０`) needs an NFKC pass before
  `unquote` can recognize the escape again, and the reverse composition
  (fullwidth, then percent-encoding its UTF-8 bytes) needs `unquote` before NFKC
  can fold it — a single-order two-pass design silently failed one of these two
  composition orders. `test_apply_chain_is_deterministic_and_preserving`, an
  existing test that runs every operator in a chain, caught this immediately.
  A single-layer-encoded input still reaches its fixpoint after one iteration
  (unchanged from before), so this is additive to every existing operator/test.
  A third technique, null-byte insertion, was designed and then deliberately
  **dropped** from this change: unlike the encoding tricks above, its real-world
  effect (string truncation in some legacy backends) is not provably meaning-
  preserving in general, and teaching `canonicalize()` to treat a null byte as
  inert (the same way it treats a vetted `/* */` comment) would be dishonest about
  what the technique actually does on a real target — the exact class of unsound
  "looks equivalent but isn't" acceptance `BUG-0027`/`CC-MUT-0010` just hardened
  this validator against, in the same session.
- Impact (other components / project): none outside MUT — additive operators and
  a strictly more capable (never less capable) canonicalizer. `payload_variant`
  rows recorded via `mutate-run` now include these operators when selected by the
  scheduler/search; no schema change.
- Risk (level; mitigation): low — new operators only trigger when selected; the
  canonicalize change is additive (verified: every existing `test_mutation_*.py`
  test — 64 total across the component — passes unchanged). Mitigated by: 6 new
  operator-specific tests (`double-url-encode` round-trips through two decodes and
  is not already recoverable by one decode; `unicode-fullwidth` NFKC-normalizes
  back to the original and widens every non-space char; a no-op guard for a
  payload the operator can't change; the double-encode-then-fullwidth composition
  bug reproduced and now passing); 2 new `canonicalize()` tests (a 2x and 3x
  URL-encoded payload both unwind correctly; a fullwidth payload folds back to
  ASCII); the existing generic "every surface variant preserves semantics" test
  (both SQLi and XSS) automatically covers the new operators with zero test
  changes, since it iterates `default_operators()`.
- Deliverables:
  - [x] `double-url-encode` + `unicode-fullwidth` operators — done.
  - [x] `canonicalize()` bounded, interleaved unquote+NFKC fixpoint — done.
  - [x] Null-byte insertion designed, then rejected as architecturally unsound
    for this validator — documented, not built.
  - [x] Tests (8 new: 6 operator-level, 2 canonicalize-level) — done.
- Effectiveness (assessed 2026-09-22): effective — both operators produce
  distinct-looking variants that `SemanticsValidator.preserves()` correctly
  accepts individually and in the composition that first exposed the ordering
  bug; every pre-existing mutation test still passes.

### CC-MUT-0010 — Fix (BUG-0027): `SemanticsValidator` AST verdict overrode canonicalize (2026-09-22)
- Change: `fuzzlab/mutation/semantics.py::SemanticsValidator.preserves()` now checks
  `canonicalize()` equality first and treats it as authoritative when it decides;
  a decisive `sqlglot` AST-equivalence verdict is consulted only when canonicalize
  disagrees, and only when the two payloads don't differ in `--` line-comment
  presence (new `_comment_provenance_differs()` helper) — AST equality is provably
  blind to comments (both `--` and `/* */` are lexer trivia to it) and so cannot be
  trusted to vouch for a `--` difference canonicalize deliberately doesn't recognize
  as safe. Fixes two long-standing, previously-logged-but-undiagnosed test failures:
  a case-toggle surface variant was wrongly rejected (AST is case-sensitive;
  canonicalize isn't), and an unvetted `-- x` comment append was wrongly accepted as
  meaning-preserving (fail-open — the more serious direction, since it let the
  validator rubber-stamp an arbitrary, unvetted transformation).
- Impact (other components / project): `MutationSearch`/`FilterLearner`
  (`fuzzlab/mutation/search.py`, `fuzzlab/mutation/learn.py`) both gate accepted
  variants through this validator — they now correctly accept case-toggle variants
  and correctly refuse a payload whose only "safety" was AST's comment-blindness.
  No change to the operator set, the `Candidate`/`Oracle` contract, or any other
  component; the fix is contained to `preserves()`'s internal decision order.
- Risk (level; mitigation): low — narrows an over-permissive path (comment
  fail-open) and widens an over-strict one (case fail-closed) without touching any
  other call site's signature. Mitigated by the two pre-existing failing tests now
  passing, two new targeted regression tests (`test_ast_never_approves_an_unvetted_
  line_comment_injection`, `test_ast_never_rejects_a_case_toggle_canonicalize_
  already_accepts`), and the full `tests/test_mutation_*.py` suite (48 passed).
- Deliverables:
  - [x] `preserves()` reordered: canonicalize authoritative, AST only widens and
    never on a comment-provenance difference — done.
  - [x] `_comment_provenance_differs()` helper — done.
  - [x] Regression tests (both directions) — done.
  - [x] Full bug protocol: `BUG-0027`, `PA-0029`, `ERROR_LOG.md` entry (closes the
    2026-09-21 "found, not fixed" line) — done.
- Effectiveness (assessed 2026-09-22): effective — both previously-failing tests now
  pass; full project suite green modulo the pre-existing, unrelated LAB-track
  failures (unaffected by this change).

### CC-MUT-0009 — Oracle-confirm a recorded bypass, optionally (CC-MUT-0006 nice-to-have) (2026-09-22)
- Change: `run_mutation` takes an optional `oracle=` parameter (default `None`,
  behavior unchanged); when given, every recorded WAF-bypass variant triggers an
  **independent** `Oracle.confirm()` check at the same (url, param, method,
  location), scoped to `vuln_class` as the confirmation category. This is not a
  literal replay of the accepted variant's exact payload — a `ConfirmationStrategy`
  always crafts its own probe (no strategy takes a caller-supplied payload) — so it
  answers "does the oracle also confirm this class of vulnerability here," a
  related but distinct question from "did this exact variant trigger it." The
  oracle remains the sole finding-writer: `run_mutation` itself writes no `finding`
  row, only `Oracle.confirm()` does when store/run_id are attached to the `Oracle`
  instance. Wired into `fuzzlab mutate-run` as an opt-in `--confirm-oracle` flag
  (`fuzzlab/mutation/cli.py`), auto-surfaced in the launcher UI's form via the
  existing `build_parser()`→command-spec path — no UI-side change needed.
  `summary["oracle_confirmed"]` (a count) and each result's `oracle_confirmed`
  (`None` when no oracle was given, else `True`/`False`) report the outcome.
- Impact (other components / project): purely additive and opt-in — omitting
  `oracle=`/`--confirm-oracle` leaves every existing caller's behavior identical
  (verified by a dedicated test). Matches the existing oracle/advisory split
  (CC-FUZZ-0016's M10 pattern): mutation stays advisory, the oracle stays the
  fail-closed finding-writer. No schema change.
- Risk (level; mitigation): low — opt-in, and reuses the already-tested
  `Oracle.confirm()` seam unchanged. Mitigated by 3 new tests
  (`tests/test_mutation_live.py`): omitting `oracle=` writes zero findings and
  leaves `oracle_confirmed` `None` (pre-existing behavior untouched); a fake
  sender that also leaks a SQL error on the oracle's own probes gets confirmed
  and writes exactly one `finding`; a fake sender that evades the WAF but never
  leaks a SQL error is correctly NOT confirmed (no finding written).
- Deliverables:
  - [x] `run_mutation(..., oracle=None)` — independent oracle re-check on a
    recorded bypass — done.
  - [x] `--confirm-oracle` CLI flag + summary/result reporting — done.
  - [x] Tests: no-oracle unchanged, confirmed writes a finding, not-confirmed
    writes none — done.
- Effectiveness (assessed 2026-09-22): effective — the oracle correctly
  distinguishes "evaded the WAF" from "the oracle also independently confirms a
  vulnerability here," and only the latter ever produces a `finding` row.

### CC-MUT-0008 — Emit reward/novelty metric_series from MutationSearch (2026-09-22)
- Change: `MutationSearch` (`fuzzlab/mutation/search.py`) takes optional `store`/`run_id`
  constructor args; when given, `search()` emits per-step `reward`/`novelty`
  metric_series points (source `mutation`) via a buffered `core.store.MetricLogger`.
  `run_mutation()` (`fuzzlab/mutation/run.py`) passes its own `store`/`run_id` through.
- Impact (other components / project): read-only consumer of the CORE `metric_series`
  table/API (CC-CORE-0018); a future UI diagnostics tab (Phase 4b) can chart mutation
  search progress. No change to `MutationSearch`'s existing operator-selection, coverage-
  climbing, or catalog-write behavior (FR-MUT-4/FR-MUT-6) — additive instrumentation
  only, absent by default (no store/run_id → no-op).
- Risk (level; mitigation): low — additive, optional-by-default. Mitigated by the
  unchanged full suite (1395 passed / 23 skipped, same 6 pre-existing unrelated
  failures) plus new unit tests over the emitted rows.
- Deliverables:
  - [x] `MutationSearch` optional `store`/`run_id` + per-step emission — done.
  - [x] `run_mutation()` passes `store`/`run_id` through — done.
- Effectiveness (assessed 2026-09-22): effective — emitted reward/novelty series match
  the search's own step-by-step behavior in the new tests, with no change to the
  existing search/catalog-write path.

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
