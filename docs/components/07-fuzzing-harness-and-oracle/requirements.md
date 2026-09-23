# Fuzzing Harness and Oracle — Requirement Specification

Component code: **FUZZ** · Status: `[built fuzzer; oracle built (black-box M1/M2/M3/M5/M8; M10 grey-box wiring layer built, live sources on-host); harness generalization ongoing; greybox-run consumes mutation-engine variants (opt-in); coverage-frontier growth emitted to metric_series]`
· Last updated: 2026-09-23 · see CC-FUZZ-0028

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
- **FR-FUZZ-13** *(`CC-FUZZ-0026`, 2026-09-23; superseded in part by
  `FR-FUZZ-15` below).* A ground-truth point whose tainted value is
  carried in a request **header** (`Case.location`/`InjectionPoint`'s
  `location="header"`) was honestly, distinctly reported as
  not-yet-auditable — never conflated with the client-only/DOM skip
  reason. **Superseded**: `FR-FUZZ-15` closed the underlying gap (a real
  header-injection point type and header-capable sender now exist), so a
  header point is a real, audited point today, not a skip reason. This
  entry is kept for history — it correctly named the gap at the time.

- **FR-FUZZ-18** *(`XxeInBandMarkerStrategy`/`XxeOobStrategy`;
  `CC-FUZZ-0031`, 2026-09-23).* The oracle supports real **XXE (CWE-611)
  confirmation**, paired with `FR-AUD-10`'s candidate-generation rule,
  closing TrackerNest's and Netflix's shared structural detection zero:
  - `XxeInBandMarkerStrategy` (`mechanism="in-band-external-entity-
    marker"`) and `XxeOobStrategy` (`mechanism="oob-external-entity-
    fetch"`), directly modeled on the SSRF pair. A `SYSTEM` external
    entity is pointed at the injected `OobListener`'s own loopback
    callback URL; the in-band layer confirms when the immediate response
    echoes the minted token, the OOB layer falls back to a real callback
    hit for blind XXE (entity resolved but not reflected). Two documented
    wrapper XML shapes tried in-band before the OOB fallback.
  - **Explicit, docstring-stated safety scope**: the entity value is
    always `OobListener`'s own minted callback URL, never a real
    filesystem URI or other host — required because XXE's `SYSTEM`
    mechanism is trivially adaptable to a genuine local-file-read
    primitive, unlike SSRF's URL-only shape this pattern is otherwise
    modeled on.
  - Calls `sender.send()` directly rather than extending the shared
    `_send()` helper with an unexercised override parameter (an adequacy-
    pass correction, YAGNI) — XXE's own ground truth is `rendering=
    "server"` (not `server-json`), so each strategy declares its own
    fixed `content_type="application/xml"` at the call site.
  - **Surfaced two pre-existing multitarget tests that never actually
    exercised SSRF detection** (`tests/test_labgen_php_laravel_huddlehub_
    multitarget.py`, `tests/test_multitarget_category3_combined.py`
    both never passed `oob=` to `run_targets`, so every OOB-dependent
    strategy had been failing closed there since `FR-FUZZ-14` landed) —
    fixed and re-verified against real boots, not a production defect.
  - Verified live against TrackerNest's real booted twins, both directly
    and through the real `fuzzlab.harness.multitarget` pipeline:
    TrackerNest's real, scored recall moves from 1/3 to 2/3.

- **FR-FUZZ-17** *(`InsecureDeserializationTypeConfusionStrategy`;
  `CC-FUZZ-0030`, 2026-09-23).* The oracle supports real
  **insecure-deserialization (CWE-502) confirmation**, paired with
  `FR-AUD-9`'s candidate-generation rule, closing one of Netflix's two
  remaining structural detection zeros:
  - `InsecureDeserializationTypeConfusionStrategy` (`vuln_class=
    "insecure_deserialization"`, `mechanism="polymorphic-type-
    confusion"`): a two-probe differential over Jackson's `WRAPPER_ARRAY`
    polymorphic-type format. Probe A names a real, always-present JDK
    class (`java.util.HashMap`) and must succeed (200); probe B names a
    freshly-minted, guaranteed-nonexistent class and must fail
    *specifically* by echoing that exact class name back — proof of
    genuine attacker-controlled class resolution, ruling out an endpoint
    that simply validates nothing. Deliberately no real gadget-chain/RCE
    payload sent, ever (this project's own no-new-dual-use-infra
    posture, the same reasoning §8 records for why the URLDNS follow-on
    was shelved for this same class).
  - **A real, previously dormant defect found and fixed**:
    `fuzzlab.harness.auto.points_from_ground_truth` never propagated
    `sink_context` from the ground truth's scoring `Case` onto the
    audited point at all — harmless until this was the first rule ever
    keyed on `sink_context_in`, at which point it silently zeroed out
    every such candidate. Fixed by looking up the matching `Case` by
    `(url, method, param)` identity.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"insecure_deserialization": "insecure-deserialization"` — the
    second instance of the exact gap `FR-FUZZ-16` found for
    `access_control`. A structural guard
    (`test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`)
    now catches a third instance automatically, scoped to only
    categories with a real audit rule (so it does not flag the
    MeadowMart app's own deliberately-deferred `redos`/
    `prototype_pollution` gap).
  - Verified live against Netflix's real booted twins; through the real
    `fuzzlab.harness.multitarget` Phase E wiring, Netflix's real, scored
    recall moves from 0 to 1/2, and the project's own cross-target
    `generalizes` definition (recall > 0 on ≥ 2 scored targets) is met
    for the first time.

- **FR-FUZZ-16** *(`AccessControlIdorStrategy`; `CC-FUZZ-0029`, 2026-09-23).*
  The oracle supports real **access-control (IDOR/BOLA) confirmation**,
  paired with `FR-AUD-8`'s candidate-generation rule, closing `CC-LAB-0178`'s
  open question:
  - `AccessControlIdorStrategy` (`vuln_class="access_control"`,
    `mechanism="identity-differential"`): sends two unrelated id values;
    confirms only when both return HTTP 200, echo the requested id back in
    a non-empty body, contain no generic denial phrase (`\b`-anchored,
    PA-0022), and the two bodies differ — else fails closed. A generic
    differential in the same family as `SqliBooleanStrategy`/
    `SsrfInBandMarkerStrategy`, not a lab-specific hardcode.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"access_control": "access-control"` — required for the rule/strategy
    to actually be selected by a ground-truth-driven run (the vuln_class
    and category slugs genuinely differ here, unlike `ssrf`).
  - **Documented, not eliminated, false-positive class**: a legitimate
    endpoint that echoes an arbitrary id back without gating anything
    sensitive by ownership will still confirm (pinned by
    `test_documented_false_positive_class_a_public_echo_endpoint_does_
    confirm`) — stated in the strategy's own docstring per the pre-change
    review's adequacy pass, mitigated only by `R-ACCESS-CONTROL`'s
    narrowed rule scope (`FR-AUD-8`), not by the strategy itself. This is
    the project's first strategy for this class; broader validation
    against a second, differently-shaped target is expected before it is
    trusted beyond this lab.
  - Verified live against Twitch's real booted twins
    (`test_real_boot_proves_the_access_control_idor_strategy_end_to_end`);
    Twitch's real, scored `multitarget` recall moves from 1/3 to 2/3.

- **FR-FUZZ-15** *(header points become real, audited points; a
  content-type-aware whole-body sender; `CC-FUZZ-0028`, 2026-09-23).*
  Closes `FR-FUZZ-13`'s own gap and one of `FR-LAB-99`'s three flagged
  follow-on items:
  - A `location="header"` point is now included by
    `fuzzlab.harness.auto.points_from_ground_truth` and sent for real by
    both `RequestsProbeSender`/`SeamProbeSender`: the value goes out as a
    request header named the literal `param` (matching `CC-LAB-0174`'s own
    established convention that `param` *is* the literal header name for a
    header-carried case).
  - A `param="body"`/`location="body"` point gets a declared
    `body_content_type` **only** when its ground truth marks
    `rendering="server-json"` (reusing the existing `rendering` field, no
    new schema needed) — e.g. `NFLX-0001` (JSON), never TrackerNest's
    `TNEST-0002`/`TNEST-0003` (XML / binary Java-serialized, `rendering=
    "server"`, unaffected, still form-encoded exactly as before). This
    field threads through `fuzzlab.audit.engine.InjectionPoint` →
    `evaluate()`'s evidence → `fuzzlab.oracle.probe.Candidate` →
    `ConfirmationStrategy._send()` → the sender's new `content_type`
    keyword, which sends the raw body at that content type instead of
    form-encoding `{param: value}`.
  - **A real defect found and fixed before landing**:
    `fuzzlab.harness.auto._CountingSender` (every real `run_auto` call
    wraps its sender in this request-cost counter) did not accept or
    forward `content_type` — it would have silently dropped it, reverting
    every whole-body-JSON send back to form-encoding the moment it ran
    through the real pipeline rather than a sender unit test. Fixed, with
    a direct unit test pinning it
    (`test_counting_sender_forwards_content_type`).
  - **Not itself detection capability**: no new audit rule or oracle
    strategy is added here. `webhook_signature`/`insecure_deserialization`
    still have none (see §8's open questions for the concrete, corrected
    reasoning on each, from the pre-change review's adequacy pass).

- **FR-FUZZ-14** *(`CC-FUZZ-0027`, 2026-09-23).* The oracle supports real
  **SSRF confirmation**, cheapest-first, paired with `FR-AUD-7`'s
  candidate-generation rule:
  - `SsrfInBandMarkerStrategy` (`vuln_class="ssrf"`, `mechanism=
    "in-band-fetch-marker"`): a single request, no wait. Points the
    candidate at an injected `OobListener`'s callback URL (reused as a
    marker responder) and confirms iff the *same* response echoes the
    minted token back — the shape this project's own SSRF lab cells
    actually have (`go_net_http`'s `unchecked_url_fetch`:
    `io.Copy(w, resp.Body)`).
  - `SsrfOobStrategy` (`mechanism="oob-fetch-callback"`): the fallback for
    a target that fetches but never echoes the body. Same `OobListener`
    seam as `FR-FUZZ-10`'s `CommandInjectionOobStrategy` (optional
    constructor injection, fail-closed no-op without one), but the
    injected value is the callback URL sent directly — an SSRF sink's own
    HTTP client fetches whatever URL it's given, no shell wrapping
    needed. Default timeout 3.0s (vs. `CommandInjectionOobStrategy`'s
    1.5s): a real fetch round trip can plausibly take longer than a local
    shell `curl` even when genuinely vulnerable.
  - `OobListener` (`fuzzlab/oracle/oob.py`) now echoes the minted token as
    its response body on a matching `GET`/`POST` (previously always
    empty) — additive; `record()`/`hits()`/`wait_for()` never read this
    body, so `CommandInjectionOobStrategy`'s existing OOB-only usage is
    unaffected. `do_HEAD` still sends no body (correct HTTP semantics).
  - `default_strategies()` registers both, in-band before OOB
    (cheapest-first, matching every other category's own stacking); adds
    `_CATEGORY_TO_CLASS["ssrf"] = "ssrf"`.
  - `fuzzlab.harness.multitarget.run_targets()` gained `oob`/`coverage`/
    `dbfault` keyword passthrough to `run_auto()` (previously silently
    dropped, though `run_auto()` already accepted them) — needed so a
    `TargetSpec`-driven multitarget run can actually use this new
    capability. Additive: all three default `None`, no existing caller
    affected.
  - **Proven against a real target, not just unit tests**: category 4's
    own `tests/test_multitarget_category4.py` confirms the real SSRF cell
    (`LABGEN-GO-0003`) end to end via a real, started `OobListener`
    threaded through `run_targets()` against the real live-booted Go app.

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
- (`CC-FUZZ-0028`, 2026-09-23) **`fuzzlab/greybox/run.py`'s
  `RequestsCorrelatingSender` has the same `location="body"`
  form-encode-only branch `RequestsProbeSender`/`SeamProbeSender` had
  before `FR-FUZZ-15`, and was not given the same content-type
  awareness.** Low risk today — `GreyboxConfirmationStrategy` only scopes
  to `sql-injection`/`xss`, neither of which reaches a whole-body point —
  but a real, latent gap the moment a future grey-box-confirmable category
  does. Give it the same `content_type` handling when that happens, not
  before (no consumer to test it against yet).
- (`CC-FUZZ-0028`, 2026-09-23; re-examined and corrected 2026-09-23;
  **resolved** `CC-FUZZ-0030`/`CC-AUD-0018`, 2026-09-23, by a different,
  non-DNS mechanism) **No `insecure_deserialization` audit rule/oracle
  strategy exists.** ~~This lab's own cells have no working
  `ysoserial`-style RCE gadget chain ... a URLDNS-style gadget-chain-free
  proof ... checked directly against this project's own `OobListener` and
  found not to fit it as sketched ... Left open~~. The URLDNS OOB/DNS-
  listener path recorded above remains genuinely not viable without new
  infrastructure and was never built — but a materially simpler,
  single-request, no-new-infra mechanism was found instead: Jackson's
  `WRAPPER_ARRAY` polymorphic-type format lets a black-box probe observe
  *class-resolution* itself (not code execution) as a two-probe
  differential (a real benign class succeeds; a freshly-minted
  nonexistent one fails with an attributable, class-name-echoing
  rejection) — `R-INSECURE-DESERIALIZATION`/
  `InsecureDeserializationTypeConfusionStrategy` (`FR-AUD-9`/`FR-FUZZ-17`),
  verified live against Netflix's real booted twins. This proves the
  CWE-502 mechanism (attacker-controlled type id reaches class
  resolution/instantiation), deliberately not a demonstrated RCE gadget
  chain — narrower than a full exploit proof, but real detection where
  there was none, without the DNS-listener infrastructure expansion the
  URLDNS path would have required.
- (`CC-LAB-0175`/`FR-LAB-98`, `CC-FUZZ-0028`, 2026-09-23) **No
  webhook-signature timing oracle.** Both twins behave identically for any
  single request (the divergence is comparison timing:
  `naive_string_compare`'s `==` short-circuits on the first differing
  byte, `hmac.Equal` does not), so this needs a genuinely new,
  statistical, multi-request timing-differential mechanism — not a
  two-sample rising-delay check like `ConfirmationStrategy._confirm_timing`
  (built for a chosen SLEEP-style delay, not a sub-millisecond
  byte-position side channel). A concrete sketch for future work: probe
  pairs comparing response time for a candidate signature matching zero
  leading bytes of a locally-known-correct one vs. matching many leading
  bytes, aggregated over enough paired samples for a real statistical test
  (e.g. Mann-Whitney U or Welch's t-test) rather than a fixed threshold —
  the same class of judgment call `RegexDosStrategy` (`CC-FUZZ-0025`) already
  needed its own, different-from-`_confirm_timing` mechanism for. Not
  attempted here.
- Oracle interface for pluggable vulnerability classes (register-oracle hook
  shape).
- Timing-threshold calibration per target/network profile.
- Reward shaping when grey-box signals are unavailable (black-box fallback).
