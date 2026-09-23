# Fuzzing Harness and Oracle — Requirement Specification

Component code: **FUZZ** · Status: `[built fuzzer; oracle built (black-box M1/M2/M3/M5/M8; M10 grey-box wiring layer built, live sources on-host); harness generalization ongoing; greybox-run consumes mutation-engine variants (opt-in); coverage-frontier growth emitted to metric_series]`
· Last updated: 2026-09-23 · see CC-FUZZ-0026

Related: `ARCHITECTURE.md` #7; `DECISIONS_AND_ROADMAP.md` (D1, D5, D7, Phase 2/3,
Phase 8); `./change-control.md`.

## 1. Purpose
Send payloads at candidates, extract per-attempt features and reward, and — via a
deterministic **oracle** — confirm vulnerabilities. The oracle is the single
source of truth for labels; everything downstream (findings, training rows,
rewards) derives from it.

## 2. Scope
- **In:** the generalized harness (`template + injection_point + payload_source +
  oracle`); attempt feature/reward extraction; the **class-pluggable** deterministic
  oracle covering the web-app attack vectors in `references/` (mechanisms +
  injection-class mapping in `../../architecture/oracle-confirmation.md`).
- **Out:** choosing the next payload family (scheduler) and scoring/screening
  attempts (ML classifier). The oracle does not guess; ML never writes labels.

## 3. Functional requirements
- **FR-FUZZ-1** Generalize `blind_sqli_fuzzer.py` into a harness parameterized by
  `template`, `injection_point`, `payload_source`, and `oracle`, so one harness
  serves multiple vulnerability classes.
- **FR-FUZZ-2** For each send, record an `attempt` row with a versioned feature
  vector and a reward signal.
- **FR-FUZZ-3** The oracle is **class-pluggable** across web-app attack vectors,
  not time-based only: a `ConfirmationStrategy` per vulnerability class selects from
  a shared set of deterministic **mechanisms** — differential timing, error
  signature, boolean/response differential, evaluation marker, reflected-canary-in-
  context, browser execution, file-content marker, out-of-band callback,
  redirect-target control, and grey-box (when on). Strategy is chosen by
  `(vuln_class, sink_context)`. The mechanism set and the injection-class →
  mechanism mapping (from `references/`) are specified in
  `../../architecture/oracle-confirmation.md`.
- **FR-FUZZ-3a** Timing confirmation is **differential** (rising-delay across
  several requested delays; median/MAD baseline), never a single absolute
  measurement.
- **FR-FUZZ-4** Confirm via the mechanism(s) each class registers (e.g. error
  signature for error-based SQLi, evaluation marker for SSTI, browser execution for
  stored/DOM XSS), and via grey-box coverage / DB-fault signals when instrumentation
  is on (D7). Ambiguity is "not confirmed," never a guess (fail-closed).
- **FR-FUZZ-5** The oracle is the **only** writer of `finding` labels; keep
  detection (the measurement) decoupled from the payload's label to avoid circular
  labeling. New classes register via a built-in strategy registry now, and the
  plugin system's `register_oracle` hook (component #13) later.
- **FR-FUZZ-6** Require an explicit `--authorized` flag and lab-only scope before
  sending anything.
- **FR-FUZZ-7** Serialize timing-sensitive sends at concurrency 1 per host via the
  shared budget mutex.
- **FR-FUZZ-8** The live grey-box run (`greybox/run.py::run_greybox`) can, opt-in
  (`--mutation-variants` / `mutation_variants=True`, off by default), also probe
  each point's sqli/xss attacks with a bounded set of the mutation engine's
  semantics-preserving variants (component #9, MUT), through the same
  attempt/reward/coverage path as the built-in probes; a variant that hits or
  reaches new code is written back to `payload_variant` via MUT's existing
  destructive-gated `catalog.record_variant` — the harness's own consumer of
  Phase 8 T8.5's write-back path, alongside the standalone `mutate-run` CLI.
  Added by `CC-FUZZ-0019` (Lane C1/M8-wiring).
- **FR-FUZZ-9** `run_greybox()` emits the run-wide `CoverageFrontier`'s growth
  to `core/store.py`'s `metric_series` table (component #2, CORE) once per
  attempt, via a buffered `MetricLogger(store, run_id, source="coverage")`
  and the private `_record_coverage_metric()` helper: `key="coverage/lines"`,
  `step=` the running attempt count, `value=` the frontier's current `.size`.
  Always on (no flag — read-side-only addition, no new traffic or behavior
  change to the attempt path itself); additive alongside the pre-existing
  `greybox_frontier_size` end-of-run `run_metrics` total, which is unchanged.
  Added by `CC-FUZZ-0021` (lane B0's coverage-frontier emitter, Wave 1b,
  sequenced after `CC-FUZZ-0019`/`CC-FUZZ-0020` per the file-overlap note in
  `docs/PARALLEL_LANE_BUILD_PLAN.md`).
- **FR-FUZZ-10** The oracle supports **M8 out-of-band (OOB) callback** confirmation
  for blind injection classes with no observable direct-response difference. Scope
  and contract:
  - `fuzzlab.oracle.oob.OobListener` is a loopback-only (`127.0.0.1`/`localhost`
    only; any other host raises) local HTTP callback tracker. It binds no socket
    until `start()` is called (default-off — never binds implicitly), mints
    unguessable per-probe tokens (`register()`), gives the URL to embed in a payload
    (`callback_url(token)`), and reports whether that exact token was later
    requested (`wait_for(token, timeout)`, `hits(token)`). It is a process-local test
    fixture for this lab — no DNS component, no external reachability, no
    persistence — never a general-purpose, publicly reachable interaction/
    collaborator service (Safety, `CLAUDE.md`).
  - `CommandInjectionOobStrategy` (`fuzzlab.oracle.strategies`) is a
    `ConfirmationStrategy` for `vuln_class="command-injection"`,
    `category="command-injection"`, `mechanism="oob-callback"`. It takes an
    `OobListener` by injection (constructor arg, default `None`) exactly like the M6
    `BrowserExecutor` seam: with a listener, it embeds a fresh canary URL in a
    shell-fetch payload (`curl`/`wget`) per attempt and confirms iff that token is
    requested before `timeout`; without one, it no-ops (`confirm()` returns `None`
    immediately, no probe sent) — fail-closed, and it never constructs a listener of
    its own.
  - Wiring: `default_strategies(oob=None)`, `Oracle(oob=None)`,
    `run_pipeline(oob=None)`, `run_auto(oob=None)` all take the listener as an
    optional keyword that defaults to `None` (no behavior change for existing
    callers). `fuzzlab auto --oob` is the only place that constructs and `start()`s a
    real `OobListener`; it is default-off and torn down (`stop()`) at the end of the
    run regardless of outcome.
  - Applies alongside the existing M1 timing strategy for the same category (both
    `applies()` on `category="command-injection"`); the oracle tries the cheaper M1
    timing check first, then M8, so a target that suppresses timing signal but still
    executes the shell fragment is still confirmable.
  - Other blind classes named in `docs/architecture/oracle-confirmation.md` Tier 3
    (blind SSRF, blind XXE, blind insecure-deserialization) can register their own
    `ConfirmationStrategy` against the same `OobListener` seam later — M8 the
    *mechanism* is now built and pluggable; wiring every blind class onto it is
    tracked as future work, not blocked on anything.
  - Added by `CC-FUZZ-0023`, merged in from `claude/trusting-noether-heon0n`
    (renumbered from that branch's own `FR-FUZZ-8` — see the change-control
    entry's provenance note for why).
- **FR-FUZZ-11** The oracle supports **M10 grey-box confirmation** for sql-injection
  and xss, layered as a secondary mechanism alongside the black-box strategies for
  those categories. This requirement covers the *wiring layer* only — the pure
  decision (`fuzzlab.greybox.confirm.greybox_confirms()`/`m10_evidence()`) and the
  `CoverageSource`/`DbFaultSource` protocols were already built and unit-tested
  (Phase 3 T3.1–T3.5); what this adds is the seam that lets `Oracle.confirm()`
  actually consult them:
  - `GreyboxConfirmationStrategy` (`fuzzlab.oracle.strategies`) is a
    `ConfirmationStrategy` with `mechanism="grey-box-coverage"`; `applies()` scopes
    it to `category in ("sql-injection", "xss")` (cross-cutting like M8 alongside
    M1, not one class). It takes an optional `CoverageSource` and an optional
    `DbFaultSource` by constructor injection (both default `None`) exactly like the
    M6 `BrowserExecutor` / M8 `OobListener` seams: with neither source, `confirm()`
    returns `None` immediately (no probe sent, fail-closed).
  - With at least one source injected, it still needs the `sender` passed into
    `confirm()` to expose `send_correlated(url, param, value, *, method, location)
    -> (Probe, request_id)` (the contract already established for the live
    grey-box run, `fuzzlab/greybox/run.py`'s `RequestsCorrelatingSender`) so the one
    probe it sends can be matched back to the coverage/DB-fault side channel by a
    fresh `X-Fzl-Cov` id; without a `send_correlated`-capable sender it no-ops too.
    It resolves `vuln_class` from the candidate (or `category_to_oracle_class`),
    looks up the sink's app file by URL, and calls `greybox_confirms()`/
    `m10_evidence()` for the verdict/evidence — the oracle stays the sole
    finding-writer.
  - Wiring: `default_strategies(coverage=None, dbfault=None)`,
    `Oracle(coverage=None, dbfault=None)`, `run_pipeline(coverage=None,
    dbfault=None)`, `run_auto(coverage=None, dbfault=None)` all take the sources as
    optional keywords defaulting to `None` (no behavior change for existing
    callers). `fuzzlab auto --greybox-coverage-file DIR` /
    `--greybox-dbfault-file DIR` construct `FileCoverageSource`/`FileDbFaultSource`
    against that on-host pcov/DB-fault side channel directory; both default off.
  - **Honesty about live capability:** this wiring layer is offline-buildable and
    fully unit-tested with `InMemoryCoverageSource`/`InMemoryDbFaultSource`
    (`tests/test_oracle_greybox.py`). It does **not** by itself make M10 live in a
    real run: the CLI flags construct `FileCoverageSource`/`FileDbFaultSource`
    against the lab's on-host pcov/DB-fault side channel, but no shipped sender yet
    implements `send_correlated` against a live target (the `RequestsProbeSender`/
    `SeamProbeSender` used by `fuzzlab auto` do not), so `--greybox-coverage-file`/
    `--greybox-dbfault-file` currently no-op against a live target until a
    correlating oracle probe sender is built — that plumbing (attaching a real
    `X-Fzl-Cov` header per oracle probe against the instrumented lab) remains
    on-host last-mile work (`docs/ON_HOST_TASKS.md`).
  - Added by `CC-FUZZ-0024`, merged in from `claude/trusting-noether-heon0n`
    (renumbered from that branch's own `FR-FUZZ-9` — see the change-control
    entry's provenance note for why).

- **FR-FUZZ-12** *(M1 timing-differential ReDoS confirmation,
  `CC-FUZZ-0025`, 2026-09-22).* The oracle supports **M1 differential
  timing** confirmation for the `regular-expression` (ReDoS, CWE-1333)
  reference category, closing the gap
  `docs/architecture/oracle-confirmation.md` previously listed only as
  deferred:
  - `RegexDosStrategy` (`fuzzlab.oracle.strategies`): `vuln_class="redos"`,
    `mechanism="differential-timing"`, `category="regular-expression"`.
    Registered in `default_strategies()` and `_CATEGORY_TO_CLASS`.
  - A genuinely new M1 *variant*, not a new template list for the existing
    `ConfirmationStrategy._confirm_timing` helper: that helper's shape
    (used by `SqliTimingStrategy`/`CommandInjectionStrategy`) requires an
    explicit, attacker-*requested* delay it checks the target both exceeds
    AND tracks (`SLEEP({d})`/`sleep {d}`, `elapsed >= d - tolerance`). A
    ReDoS payload has no requested duration — the blowup is an emergent
    property of the target's own content, which this strategy neither sees
    nor controls (only the pattern is attacker-supplied). `RegexDosStrategy`
    instead escalates across `_REDOS_TEMPLATES` (several independent,
    single-nesting-level classic catastrophic-backtracking shapes) and
    confirms when **at least two** independently clear a robust-baseline
    threshold (`Baseline.exceeds`, `floor`/`k` overridden per-strategy to
    this mechanism's own bounded, tens-to-low-hundreds-of-milliseconds
    probe magnitude) — substituting "two independent evil shapes" for
    "two requested durations."
  - Stated limitation: this can only detect ReDoS when the target's own
    content already contains a run of the character class a template
    targets — inherently probabilistic against an arbitrary black-box
    target, unlike every other M1 use in this component (each of which
    supplies its own exact requested delay). Documented in the class's own
    docstring and in `docs/architecture/oracle-confirmation.md`'s new
    "`regular-expression` (ReDoS, CWE-1333)" section, not silently equated
    with the SQLi/command-injection M1 uses.
  - A nesting-depth-escalation alternative (deepening a single evil shape
    per rung, so a fixed content run-length could still produce a rising
    trend the way two requested delays do) was calibrated and explicitly
    rejected: it compounds the already-exponential blowup so violently
    that even one extra level of nesting hung well past any CI-safe bound
    against ordinary content.
  - Proof status: `RegexDosStrategy`'s decision logic is unit-tested
    against a deterministic fake sender (`tests/test_oracle_redos.py`),
    same convention this component's other timing/M8/M10 strategies use.
    The underlying mechanism itself (a real regex engine really blowing up
    on these templates, and escaping really preventing it) is proven with
    real Node.js execution and real measured wall-clock timing in
    `docs/components/01-target-lab/requirements.md`'s `FR-LAB-69`
    (`tests/test_labgen_redos.py`), not re-proven here. Not yet run against
    a live external target or wired into `fuzzlab/harness/multitarget.py`
    (both out of this requirement's scope).
- **FR-FUZZ-13** *(`CC-FUZZ-0026`, 2026-09-23).* A ground-truth point whose
  tainted value is carried in a request **header**
  (`Case.location`/`InjectionPoint`'s `location="header"`) is honestly,
  distinctly reported as not-yet-auditable — never conflated with the
  client-only/DOM skip reason. `fuzzlab.harness.auto.points_from_ground_truth`
  gives it its own skip reason naming the real gap (no header-injection
  point type or header-capable probe sender exists yet), rather than the
  factually wrong "needs browser execution" DOM reason. **Not itself a new
  capability**: no header point is audited by this change, only correctly
  labeled as unauditable. Building real header-injection support (a
  header-aware `InjectionPoint` shape, plus a header-capable sender
  alongside `RequestsProbeSender`/`SeamProbeSender`) is real, sized
  follow-on work this requirement does not cover.

- **FR-FUZZ-14** *(`CC-FUZZ-0027`, 2026-09-23).* `RequestsProbeSender.send()`
  disables redirect-following (`allow_redirects=False`), matching
  `fuzzlab.core.http`'s own authenticated client — a confirmation strategy
  reading a raw `Location` header (`OpenRedirectStrategy`) needs the
  redirect response itself, and a redirect target can be attacker-
  controlled/unreachable (`BUG-0039`). `OpenRedirectStrategy.vuln_class` is
  `"open_redirect"` (underscored), matching this project's established
  ground-truth `vuln_class` convention every sibling strategy already
  follows — `category` (`"open-redirect"`, hyphenated) is unchanged, a
  separate namespace (`BUG-0040`). Both verified live end to end against a
  real target; see `CC-CORE-0021`/`FR-CORE-11` for the real scored proof.

- **FR-FUZZ-15** *(`CC-FUZZ-0028`, 2026-09-23).* `SpelInjectionStrategy`
  (`fuzzlab/oracle/strategies.py`) confirms `spel_injection` (CWE-917) via
  a `T(java.lang.Math).abs(-n)` type-reference canary — a bare-arithmetic
  canary (`SstiStrategy`'s own mechanism) was rejected pre-implementation
  by the adequacy review: `SimpleEvaluationContext` (the real secure-twin
  fix) restricts type/method/bean access but not literal arithmetic, so
  a bare-arithmetic canary would confirm on the SECURE twin too, a
  guaranteed false positive. New `Rule` `R-SPEL-INJECTION` (`name_regex:
  "sort|sortby|filter|order|expr|expression"`, grounded in Expedia's real
  `sortBy` parameter), new `_VULN_TO_CATEGORY["spel_injection"]`/
  `_CATEGORY_TO_CLASS["spel-injection"]` entries (both required —
  `fuzzlab.harness.pipeline`'s own dispatch gate needs the second one or
  every candidate is silently dropped, a completeness gap the accuracy
  review caught pre-implementation). Live-verified end to end: `tp=1,
  fn=0, fp=0` against Expedia's real deployment, including an explicit
  secure-twin check confirming no false positive. Category 5's second
  real detection — combined with `open_redirect`'s own (`FR-CORE-11`),
  the Phase E combined test now scores `generalizes=True` for real (two
  independently-mapped classes, two different stacks).

- **FR-FUZZ-16** *(`CC-FUZZ-0029`, 2026-09-23).* `PriceIntegrityBypassStrategy`
  (`fuzzlab/oracle/strategies.py`) confirms `price_integrity_bypass` (no
  CWE — a business-logic/trust-boundary defect, grounded in the real
  QloApps `Cart::getOrderTotal()` trust pattern this shape was modeled
  on) by sending an attacker-chosen amount canary and checking whether the
  response echoes it back verbatim (`"charged_amount":"<canary>"`,
  matched after stripping whitespace, not a bare substring search — an
  unanchored match was rejected pre-implementation by the adequacy
  review). The canary always has three decimal places, structurally
  incompatible with the real rate table's own two-decimal-place values
  (`89.00`/`149.00`/`249.00`, also excluded explicitly as defense in
  depth) — a random two-decimal canary was rejected pre-implementation by
  the same review as a real, non-negligible collision risk, not just an
  improbable one. The vulnerable twin (`LABGEN-BC-0005`) has an empty
  transform pipeline (no named "trusted amount" op to detect); the real
  differential is the secure twin's own server-side rate-table
  recomputation, which the vulnerable twin never performs — the accuracy
  review caught and corrected an earlier draft's fictitious
  `ClientTrustedAmountTransform` framing pre-implementation. New `Rule`
  `R-PRICE-INTEGRITY` (`name_regex: "amount|price|total|cost|charge"`,
  `method_in: ["POST"]`, grounded in Booking.com's real `amount`
  parameter), new `_VULN_TO_CATEGORY["price_integrity_bypass"]`/
  `_CATEGORY_TO_CLASS["price-integrity-bypass"]` entries (both required —
  the same completeness gap `FR-FUZZ-15` already documents). Live-verified
  end to end: `fuzzlab.harness.multitarget.run_targets` against
  Booking.com's real deployment now scores `tp=2, fn=1, fp=0` (recall
  `1/3 -> 2/3`), the real inserted `bookings` row's own `total_amount`
  independently proven by `tests/test_labgen_price_integrity.py`'s
  live-boot test before this mapping landed. Category 5's third real
  detection.

- **FR-FUZZ-17** *(`CC-FUZZ-0030`, 2026-09-23).* `CsvFormulaInjectionStrategy`
  (`fuzzlab/oracle/strategies.py`) confirms `csv_formula_injection`
  (CWE-1236) by sending a canary prefixed with each of OWASP's four
  CSV-formula trigger characters (`=`, `+`, `-`, `@`) in turn and checking
  whether the response echoes it back unescaped, anchored to the actual
  CSV cell boundary (`f"{payload},"`, not merely "right after a
  newline" — an unanchored match was rejected pre-implementation by the
  adequacy review as a false-positive risk against any response that
  merely echoes the payload after a newline for an unrelated reason).
  Trying all four trigger characters, not just `=`, was also required by
  the same review — a single-character canary risked a false negative
  against a real neutralizer that only escapes a subset. New `Rule`
  `R-CSV-FORMULA-INJECTION` (`name_regex:
  "label|name|comment|note|description|title"`, `method_in: ["GET"]`,
  grounded in Booking.com's real `label` export parameter), new
  `_VULN_TO_CATEGORY["csv_formula_injection"]`/
  `_CATEGORY_TO_CLASS["csv-formula-injection"]` entries. Live-verified end
  to end: `tp=3, fn=0, fp=0` against Booking.com's real deployment — this
  app's own full ground truth, zero false negatives. Category 5's fourth
  real detection, closing Booking.com's own toolkit-side detection
  coverage entirely.

## 4. Non-functional requirements
- **NFR-FUZZ-precision** Oracle precision is measured and prioritized; a confirmed
  finding must reproduce.
- **NFR-FUZZ-deterministic** Given the same target state and inputs, oracle
  verdicts are reproducible (state reset via snapshot/restore between iterations).
- **NFR-FUZZ-safe** Destructive payload classes off by default; auth endpoints
  excluded from scope; no traffic off localhost.
- **NFR-FUZZ-labeled-output** Emits labeled results (e.g. CSV) with opaque case IDs
  for benchmarking and ML training (D9, D10).
- **NFR-FUZZ-dry-run** `fuzzlab fuzz`, `fuzzlab auto`, and `fuzzlab greybox-run`
  accept `--dry-run`: plans and prints the exact argv/command that would run and
  sends nothing (no probe, no oracle confirmation, no coverage/DB-fault side-channel
  read, no `Store`/CA/sender construction), for headless use outside the web UI.
  Bypasses the `--authorized` gate for the preview itself (nothing is sent either
  way), and reuses the web launcher's dry-run plan/report logic
  (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper. `fuzz`/`auto` were added by `CC-FUZZ-0020` (lane
  D0a); `greybox-run` — including the `--mutation-variants`/
  `--max-mutation-variants`/`--allow-destructive` flags `CC-FUZZ-0019` (Lane
  C1/M8-wiring) added — was added by `CC-FUZZ-0022` (lane D0b), sequenced after
  C1 since both touch `fuzzlab/greybox/greybox_cli.py`.

## 5. Interfaces and data contracts
Reads `candidate` rows (and scheduler choices); writes `attempt` rows (features,
reward) and, via the oracle, `finding` rows (labels, evidence). Reads grey-box
coverage/fault signals when available. Authenticates via the session manager;
sends via the `core/` HTTP client. Optionally (FR-FUZZ-8) reads mutation-engine
operators/validator (component #9, MUT) and writes accepted variants to
`payload_variant` via MUT's `catalog.record_variant`. Writes `metric_series`
rows (`source="coverage"`, `key="coverage/lines"`) via `core/store.py`'s
`log_scalar`/`MetricLogger` (FR-FUZZ-9).

## 6. Dependencies (components)
`core/`, session manager, payload scheduler, indicator DB & catalogs; grey-box
instrumentation for reward and coverage/fault labels; mutation engine (MUT,
optional — FR-FUZZ-8). (The oracle itself depends on `core/` and the target lab,
plus grey-box signals when available.) `core/store.py`'s `metric_series` table
and `log_scalar`/`MetricLogger` writer API (FR-FUZZ-9).

## 7. Acceptance criteria
- Confirms the lab's known blind-SQLi injection points with the differential
  oracle and no false positives on the secure controls.
- Emits `attempt` rows with versioned features and a reward usable by the bandit
  and classifier.
- `finding` rows are written only by the oracle and reproduce on re-run.

## 8. Open questions
- Oracle interface for pluggable vulnerability classes (register-oracle hook
  shape).
- Timing-threshold calibration per target/network profile.
- Reward shaping when grey-box signals are unavailable (black-box fallback).
