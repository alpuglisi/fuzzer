# Mutation Engine — Requirement Specification

Component code: **MUT** · Status: `[built — operators/validator/XSS, filter model + learner, bandit/coverage search, destructive-gated variant write-back (reachable from both fuzzlab mutate-run and the main greybox-run harness), the live HttpFilter + fuzzlab mutate-run driver (live WAF evasion verified on-host), and optional MutationSearch reward/novelty telemetry into metric_series]` (Phase 8; B0 emitter sub-lane) · Last updated: 2026-10-17 · see CC-MUT-0402

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
  Reachable from two callers as of `CC-MUT-0009`: the standalone `mutate-run`
  CLI's live WAF-evasion search (`fuzzlab/mutation/run.py`, unchanged), and the
  main grey-box harness's own attempt loop (`greybox/run.py::run_greybox`,
  FUZZ component #7, FR-FUZZ-8, opt-in) — both go through the same
  destructive-gated `catalog.record_variant` (PA-0003: one shared write path).
- **FR-MUT-7** The semantics validator (`SemanticsValidator.preserves()`) must
  fail **closed**, not open, on any transform whose safety cannot be decided from
  the compared fragment alone — concretely, a mutation that introduces a SQL `--`
  line comment (whose effect is on whatever follows it once concatenated into the
  real, larger query, which the isolated fragment cannot show) is refused unless
  explicitly accepted via vetted provenance (`trusted=True`), regardless of what
  AST or canonical-form comparison of the fragment would otherwise conclude. Added
  after BUG-0026 (CC-MUT-0008) found the validator accepting such a mutation by
  default; see PA-0028.
- **FR-MUT-400** *(default store; `CC-MUT-0400`, 2026-10-15).* `fuzzlab mutate-run`, also
  reached as `fuzzlab train mutate`, takes an optional `--store` (FR-CORE-400).
  - The store is created on first use and reused.
  - An explicit empty `--store` is a usage error right after parsing (before
    `--dry-run`).
  - A missing directory is a usage error after `--authorized`, before any sender or
    store.
  - The summary and the dry run name the resolved store.

- **FR-MUT-10 (runtime payload synthesis, `CC-MUT-0402`, 2026-10-17, D70)**
  `fuzzlab disco generate` turns a disco inventory (FR-CRAWL-20) into an execution
  contract (FR-FUZZ-51), and **with `--llm` only** asks an LLM for test cases per
  endpoint (`fuzzlab.disco.generate`):
  - the prompt (`SYSTEM_PROMPT`) asks, without prose, for type, boundary, structural,
    syntax and logic (authorization, ordering, one-time, negative quantity) cases, each
    with a rationale, an oracle and a destructive flag, at most `--max-cases` (12);
  - the answer is held to `CASES_SCHEMA` by structured output (closed objects, request
    values as strings: a body as JSON text, parameters as name/value pairs);
  - determinism: the default model, `claude-opus-5-5`, takes no sampling parameters (a
    temperature is a 400), so variance is bounded by the output schema, a terse prompt
    and `effort: "low"`; a classifier decline is retried server-side
    (`fallbacks: "default"`), and one that still declines is reported per endpoint;
  - every case is converted and validated before it is kept, and a dropped one is
    counted by reason (`unparseable`, `truncated`, `unconvertible`, `schema`,
    `foreign-endpoint`, `out-of-scope`, `reference`, `over-cap`): it references only its
    endpoint and its dependencies' producers, names no out-of-scope URL, uses defined
    auth profiles, extracts every `{{variable}}` before use;
  - what is sent: schemas, formats, observed ranges, enums, header *names*, dependency
    edges -- never a captured header value or a session (captured values were redacted
    at capture);
  - the API key comes from the SDK's own resolution, or from the keyring
    (`--api-key-identity`, D12);
  - class `injection` is reserved for a rule-pack producer: the LLM is not asked for
    injection payloads.

## 4. Non-functional requirements
- **NFR-MUT-semantics** A mutation must preserve intended semantics; a validator
  rejects transformations that change meaning. This includes fail-closed handling
  of transforms unprovable from the compared fragment alone (see FR-MUT-7).
- **NFR-MUT-safe** Never emit destructive payloads through the default-on path;
  the destructive gate still applies to generated payloads. *(CC-MUT-0012, BUG-0082:)*
  the gate sits at the **send** (FR-MUT-9), not only at the record.
  - Enforced by: `mutation.catalog.refuse_destructive` at the send — `tests/test_destructive_send_gate.py::test_a_destructive_base_is_never_sent_nor_any_variant`, `tests/test_destructive_send_gate.py::test_a_variant_that_turns_destructive_is_not_sent`, `tests/test_destructive_send_gate.py::test_the_live_filter_refuses_at_the_send_itself`, `tests/test_destructive_send_gate.py::test_obfuscated_destructive_payloads_are_refused`, `tests/test_mutation_catalog.py::test_destructive_gate_refuses_by_default`
  - Enforced by (through `fuzzlab train mutate`; CC-MUT-0400): `tests/test_train_cli.py::test_train_mutate_keeps_the_destructive_gate_off_by_default`
- **NFR-MUT-bounded** Search is budget-bounded and reproducible under a fixed seed.
- **NFR-MUT-offline** The LLM expansion path is offline and gated; nothing is sent
  to an external service without explicit opt-in.
  - Enforced by: `LlmExpander` default off — `tests/test_mutation_catalog.py::test_llm_expander_default_off`, `tests/test_mutation_catalog.py::test_llm_disabled_ignores_generator`
  - Not yet enforced: no static no-network check for `mutation/llm.py` (offline by construction: the generator is injected). (BUG-0111 sweep.)
  - Clause (Phase 2 test-case synthesis, FR-MUT-10, CC-MUT-0402): `fuzzlab disco
    generate` sends nothing to the LLM API without `--llm`; with it, only schemas, never
    a captured header value or a session.
  - Enforced by (Phase 2): `disco.cli._generate` (`--llm`), `disco.generate.prompt_payload` — `tests/test_disco_cli.py::test_synth_then_generate_without_llm_sends_nothing_and_makes_a_valid_contract`, `tests/test_disco_contract.py::test_the_prompt_carries_schemas_never_header_values_or_sessions`
- **NFR-MUT-dry-run** `fuzzlab mutate-run` accepts `--dry-run`: plans and prints
  the exact argv/command it would run and sends nothing (no payload/probe), for
  headless use outside the web UI. Reuses the web launcher's dry-run plan/report
  logic (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_mutate_run_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_mutate_run_dry_run_reports_plan_and_sends_nothing`
  - Enforced by (through `fuzzlab train mutate`; CC-MUT-0400): `tests/test_train_cli.py::test_train_mutate_dry_run_sends_nothing`, `tests/test_cli_default_store.py::test_mutate_dry_run_creates_nothing_and_names_the_store`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.

- **FR-MUT-8** `MutationSearch` optionally emits its per-step reward and novelty
  signal into `metric_series` (`source="mutation"`, `key="reward"`/`"novelty"`,
  `step`=1-based search step) via an injected `fuzzlab.core.store.MetricLogger`
  (`metric_logger=` constructor parameter, default `None`). `fuzzlab mutate-run`
  (`fuzzlab/mutation/run.py::run_mutation`) always attaches one, shared across
  every base payload's search under the run's `run_id`. Purely observational —
  never read back by the search/selection logic itself (CC-MUT-0011).

- **FR-MUT-9 (send-time destructive gate, CC-MUT-0012, BUG-0082)** With
  `allow_destructive` off, no destructive payload leaves the process.
  - **The check.** `catalog.refuse_destructive` refuses a payload whose raw text or
    either normalised form (URL / entity decoding, comments, `+`, NUL, whitespace,
    case) matches the signature.
  - **The live filter** (`HttpFilter`) raises `DestructiveRefused` at its send, and the
    search skips refused variants (counted as `refused`, never as a WAF block).
  - **`run_mutation`** skips a destructive base entirely, and `run_greybox` checks
    every probe (FR-FUZZ-8). The CLIs print the refused counts.

- **FR-MUT-401 (the live WAF filter decides only on an observation, `CC-MUT-0403`,
  2026-10-20, BUG-0529)** `HttpFilter` decides "caught" and "allowed" only on an answer
  that observed the WAF:
  - the block status (403 by default) is caught, as before;
  - a throttle-or-unavailable (429, 503), gateway (502, 504) or incomplete answer (a
    sender's status-0 stand-in), classified by SP-56 (FR-CORE-507), raises
    `FilterUnobserved` -- never a block, an allow or a bypass;
  - any other answer is an allow (a 401 included: the WAF let it through);
  - *(CC-MUT-0404, FR-FUZZ-65, BUG-0533's decision D′:)* an answer whose request was
    sent on a session its manager knew to be lost (`Probe.session_lost`) raises
    `FilterUnobserved` **before** its status is read: never a block or an allow,
    whatever it answered (a guest view, a 403).

  `run_mutation` contains it per base: the base's search ends, it is counted in
  `summary["unobserved"]` with its reason, and no bypass is recorded for it; `fuzzlab
  mutate-run` prints the count and an `[UNOBSERVED]` line. The coverage sends are not
  classified (a throttled one scores no novelty; no bypass rests on it).
  - Enforced by: `tests/test_oracle_comparable_controls.py::test_a_live_filter_never_reads_a_non_observation_as_allowed`,
    `tests/test_oracle_comparable_controls.py::test_a_throttled_variant_is_never_an_evasion`,
    `tests/test_session_forbidden_answers.py::test_the_live_waf_filter_never_reads_an_answer_on_a_lost_session`.
## 5. Interfaces and data contracts
Reads catalog payloads and canary/filter observations; reads coverage signals and
scheduler operator choices; writes new payload candidates back to the
catalog/`attempt` path. Optionally writes per-step scalar telemetry
(`MutationSearch` reward/novelty) to the shared `metric_series` table via
`fuzzlab.core.store.MetricLogger`/`log_scalar` (FR-MUT-8, CC-MUT-0011).

## 6. Dependencies (components)
`core/`, indicator DB & catalogs, payload scheduler, oracle, grey-box
instrumentation. (A lab WAF is a prerequisite decision for evaluating filter
evasion, not a component dependency.) As of `CC-MUT-0009`, this component is
also depended **on** by FUZZ (#7): `greybox/run.py` calls
`default_operators`/`SemanticsValidator`/`catalog.record_variant` directly. As of
`CC-MUT-0011`, `MutationSearch`/`run_mutation` optionally depend on CORE's
`metric_series`/`MetricLogger` (B0, CC-CORE-0018) for reward/novelty telemetry.

## 7. Acceptance criteria
- Produces variants that reach code the static catalog did not (measured by
  coverage) on the lab.
- Semantics validator rejects meaning-changing transformations.
- Generated payloads respect the destructive-gate and lab-only posture.

## 8. Open questions
- Whether the lab needs a configurable WAF to exercise filter-evasion learning.
- Operator set and how to bound the semantics-preservation proof per operator.
- Trust/review workflow for LLM-expanded catalog entries.
