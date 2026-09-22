# Mutation Engine — Requirement Specification

Component code: **MUT** · Status: `[built — operators/validator/XSS, filter model + learner, bandit/coverage search, destructive-gated variant write-back, and the live HttpFilter + fuzzlab mutate-run driver; live WAF evasion verified on-host]` (Phase 8) · Last updated: 2026-09-21 · see CC-MUT-0006

Related: `ARCHITECTURE.md` #9; `DECISIONS_AND_ROADMAP.md` (D1, Phase 8);
`./change-control.md`.

## 1. Purpose
Generate new, semantics-preserving payload variants that defeat input filters and
reach new code, expanding coverage beyond the static catalog — guided by grey-box
feedback and the scheduler.

## 2. Scope
- **In:** AST-based payload transformation, context-typed generation,
  filter-transformation learning, coverage-guided search, gated offline catalog
  expansion.
- **Out:** deciding which candidate to attack (scheduler) and confirming a hit
  (oracle).

## 3. Functional requirements
- **FR-MUT-1** Parse SQL payloads to an AST (`sqlglot`) and apply typed,
  **semantics-preserving** operators (encoding, whitespace, comment insertion,
  case, equivalent constructs) that do not change the payload's meaning.
- **FR-MUT-2** Generate context-typed XSS payloads matched to the sink context the
  auditor recorded (HTML body vs attribute vs JS string, etc.).
- **FR-MUT-3** Learn the target's filter transformations from canary round-trips
  (what gets stripped/encoded) and adapt payloads accordingly.
- **FR-MUT-4** Select operators via the bandit scheduler and climb the grey-box
  coverage signal (coverage-guided hill climbing).
- **FR-MUT-5** Optionally expand the catalog with an offline, **gated** LLM step
  (default off; human-reviewed before entries are trusted).
- **FR-MUT-6** Write new payload candidates back into the catalog/attempts.
- **FR-MUT-7** When given `store`/`run_id`, `MutationSearch.search()` emits per-step
  `reward`/`novelty` metric_series points (source `mutation`) via
  `core.store.MetricLogger` (CC-CORE-0018), so a future diagnostics UI tab can chart
  search progress. Absent a store or run id, behavior is unchanged.
- **FR-MUT-8** When given an `oracle=` (optional; default `None`, behavior
  unchanged), `run_mutation` independently re-checks each recorded WAF-bypass
  variant via `Oracle.confirm()` at the same endpoint, scoped to `vuln_class` —
  an independent re-check via the oracle's own confirmation strategies, not a
  literal replay of the variant's exact payload. `run_mutation` itself never
  writes a `finding` row; only a confirming `Oracle.confirm()` does, preserving
  the oracle/advisory split (FR-FUZZ-5). Surfaced as `fuzzlab mutate-run
  --confirm-oracle`. *(Realized: CC-MUT-0009.)*

## 4. Non-functional requirements
- **NFR-MUT-semantics** A mutation must preserve intended semantics; a validator
  rejects transformations that change meaning. `SemanticsValidator.preserves()`
  treats canonicalize-equivalence as authoritative for the recognized surface-
  operator envelope; a decisive AST-equivalence verdict may only widen acceptance
  beyond canonicalize, never on a difference that turns on `--` comment presence
  (AST discards all comment styles as trivia and cannot vouch for that
  distinction). Fixed after shipping the opposite invariant (a decisive AST verdict
  could override canonicalize either way): BUG-0027, CC-MUT-0010.
- **NFR-MUT-safe** Never emit destructive payloads through the default-on path;
  the destructive gate still applies to generated payloads.
- **NFR-MUT-bounded** Search is budget-bounded and reproducible under a fixed seed.
- **NFR-MUT-offline** The LLM expansion path is offline and gated; nothing is sent
  to an external service without explicit opt-in.

## 5. Interfaces and data contracts
Reads catalog payloads and canary/filter observations; reads coverage signals and
scheduler operator choices; writes new payload candidates back to the
catalog/`attempt` path.

## 6. Dependencies (components)
`core/`, indicator DB & catalogs, payload scheduler, oracle, grey-box
instrumentation. (A lab WAF is a prerequisite decision for evaluating filter
evasion, not a component dependency.)

## 7. Acceptance criteria
- Produces variants that reach code the static catalog did not (measured by
  coverage) on the lab.
- Semantics validator rejects meaning-changing transformations.
- Generated payloads respect the destructive-gate and lab-only posture.

## 8. Open questions
- Whether the lab needs a configurable WAF to exercise filter-evasion learning.
- Operator set and how to bound the semantics-preservation proof per operator.
- Trust/review workflow for LLM-expanded catalog entries.
