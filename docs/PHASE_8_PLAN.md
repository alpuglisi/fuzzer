# Phase 8 — Mutation engine (plan, for review)

Generate **new, semantics-preserving** payload variants that defeat the lab's input
filters and reach new code — expanding beyond the static `references/` catalog, guided
by the bandit scheduler and the grey-box coverage signal. The mutation engine proposes
payloads; it never decides what to attack (scheduler) or whether a hit is real (oracle).

*Draft for review — nothing built yet. Component **MUT** (#9). Requirements:
`docs/components/09-mutation-engine/requirements.md` (FR-MUT-1..6). Target: the
configurable lab WAF (D16). See `DECISIONS_AND_ROADMAP.md` (D1, Phase 8).*

## Goal

Given a base payload the lab WAF blocks or sanitizes, the engine finds a
**semantics-preserving** variant that (a) evades the filter and (b) reaches application
code the static catalog did not — within a bounded, reproducible search — while a
validator rejects any transform that changes meaning and the destructive gate stays on.

## Exit criterion

Against the **enabled** lab WAF (D16): the engine produces variants that bypass the
filter where the base payload is blocked/sanitized **and** reach new code (grey-box
coverage) versus the static catalog; the semantics validator rejects meaning-changing
transformations; generated payloads respect the destructive gate and lab-only posture.

## Principles (this phase)

- **Semantics first (NFR-MUT-semantics).** Every operator is typed and
  meaning-preserving; a validator proves/refutes it per mutation. A mutation that
  changes meaning is discarded, never sent.
- **Offline-testable seams.** The operators, the semantics validator, the context-typed
  generator, the filter model, and the search loop are built and unit-tested here with
  injected fakes (a `FilterModel` over the shared WAF ruleset; the grey-box coverage
  seam). The live coverage-guided run and the WAF-bypass exit are **on-host**, like
  Phases 3/4/6/7.
- **Reuse, don't reinvent.** Operator selection reuses the built `ThompsonBandit`;
  confirmation is the oracle's; coverage is the grey-box consumer seam; sink contexts
  come from the auditor's `oracle/context.py`.
- **Dependency-light + gated.** `sqlglot` powers the SQL-AST path (declared; its tests
  skip-guard where the native build is unavailable, like `cryptography`); string-level
  operators need no dependency. The LLM expansion path is offline, default-off, and
  human-reviewed (NFR-MUT-offline).
- **Safe (NFR-MUT-safe).** Generated payloads route through the same default-off
  destructive gate; lab-only, scope-enforced.

## Design decisions to confirm (review points)

1. **`sqlglot` handling.** Declare `sqlglot` as a dependency for the SQL-AST operators
   and the AST-equivalence semantics check; **skip-guard** those tests where it (or its
   native build) is unavailable, exactly as the credential/CA tests do for
   `cryptography`. String-level SQL operators (comments/whitespace/case/encoding) and all
   XSS/traversal/cmdi operators are pure and always tested. *(Proceeding this way unless
   you object.)*
2. **Filter model as the offline seam (FR-MUT-3).** Model the lab WAF offline with a
   `FilterModel` that applies the **shared** `waf-rules.json` (block/sanitize/log), so
   filter-transformation learning is testable here; live, the same learner observes real
   canary round-trips through the proxy/HTTP seam. One ruleset, two consumers.
3. **Where variants land (FR-MUT-6). `[decided]`** Accepted variants are sent through the
   existing **`attempt`** path (they are payload attempts the fuzzer sends) **and** a
   compact provenance record — which operator chain produced the variant, which WAF rule
   it bypassed, the validator verdict, any coverage gain — is persisted in a new additive
   **`payload_variant`** table (migration 8) for reuse and analysis.
4. **LLM expansion (FR-MUT-5).** Scaffold the gate/interface only — default off, offline,
   entries quarantined for human review before they are trusted. No external calls. Full
   use deferred (later/on-host).

## Tasks

- **T8.1 — Operator framework + semantics validator `[done, offline]`.**
  `fuzzlab/mutation/operators.py` — typed, semantics-preserving operators (URL/hex/char
  encoding, whitespace alternates, inline comments, case toggling, equivalent
  constructs), each declaring the classes/contexts it applies to.
  `fuzzlab/mutation/semantics.py` — a validator: AST-equivalence for SQL via `sqlglot`
  (skip-guarded), conservative rule-based checks for the string paths. Bounded, seeded.
- **T8.2 — Context-typed XSS generator `[planned]` (FR-MUT-2).**
  `fuzzlab/mutation/xss.py` — generate break-outs matched to the auditor's recorded sink
  context (`html`/`html-attribute`/`url-attribute`/`js`, from `oracle/context.py`),
  preferring constructs that avoid currently-blocked signatures.
- **T8.3 — Filter model + transformation learning `[planned]` (FR-MUT-3).**
  `fuzzlab/mutation/filtermodel.py` (the shared-ruleset seam) + `learn.py`: send canaries,
  infer what the filter strips/encodes/blocks, and prefer operators that evade it.
- **T8.4 — Bandit-scheduled, coverage-guided search `[planned]` (FR-MUT-4).**
  `fuzzlab/mutation/search.py` — operator arms selected via `ThompsonBandit` (context =
  class + sink/filter-state; reward = evasion + coverage gain), coverage-guided hill
  climbing against the grey-box seam; budget-bounded and reproducible under a fixed seed.
- **T8.5 — Variant write-back + safety gate `[planned]` (FR-MUT-6, NFR-MUT-safe).**
  `fuzzlab/mutation/catalog.py` — emit accepted variants into the attempt path (and the
  chosen persistence per decision 3), routed through the destructive gate; lab-only.
- **T8.6 — Gated offline LLM expansion `[planned, scaffold/off]` (FR-MUT-5).**
  `fuzzlab/mutation/llm.py` — interface + review/quarantine gate, default off, offline;
  no external calls. Full use deferred.
- **T8.7 — Exit `[on-host]`.** With the lab WAF enabled: variants bypass the filter where
  the base is blocked **and** reach new code (coverage) vs the static catalog; the
  validator rejects meaning-changing transforms.

## Component mapping

- **MUT (9)** — the new `fuzzlab/mutation/` package.
- **SCHED (8)** — `ThompsonBandit` for operator selection (reused).
- **FUZZ/oracle (7)** — the oracle confirms; the auditor's sink-context typing feeds T8.2.
- **Grey-box (1/3)** — the coverage seam drives hill climbing (live signal on-host).
- **LAB (1)** — the D16 WAF is the filter-evasion target.
- **CORE (2)** — migration 8 adds the `payload_variant` provenance table (decision 3).

## Out of scope for Phase 8 (deferred)

- Real LLM calls (the expansion path stays gated/off and offline this phase).
- Deciding what to attack (scheduler) or confirming a hit (oracle).
- A second/real WAF beyond the D16 lab filter; heavier mod_security-style rules.
- Formal per-operator semantics proofs beyond the validator's AST-equivalence /
  conservative checks.
