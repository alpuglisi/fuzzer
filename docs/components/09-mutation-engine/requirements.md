# Mutation Engine — Requirement Specification

Component code: **MUT** · Status: `[built — operators/validator/XSS, filter model + learner, bandit/coverage search, destructive-gated variant write-back, and the live HttpFilter + fuzzlab mutate-run driver; live WAF evasion verified on-host]` (Phase 8) · Last updated: 2026-09-22 · see CC-MUT-0008

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
- **FR-MUT-7** The semantics validator (`SemanticsValidator.preserves()`) must
  fail **closed**, not open, on any transform whose safety cannot be decided from
  the compared fragment alone — concretely, a mutation that introduces a SQL `--`
  line comment (whose effect is on whatever follows it once concatenated into the
  real, larger query, which the isolated fragment cannot show) is refused unless
  explicitly accepted via vetted provenance (`trusted=True`), regardless of what
  AST or canonical-form comparison of the fragment would otherwise conclude. Added
  after BUG-0026 (CC-MUT-0008) found the validator accepting such a mutation by
  default; see PA-0028.

## 4. Non-functional requirements
- **NFR-MUT-semantics** A mutation must preserve intended semantics; a validator
  rejects transformations that change meaning. This includes fail-closed handling
  of transforms unprovable from the compared fragment alone (see FR-MUT-7).
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
