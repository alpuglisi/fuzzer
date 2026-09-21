# Mutation Engine — Change Control Log

Component code: **MUT**. Entry format and required fields: see `../README.md`.
Newest first.

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
