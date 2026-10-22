# Fuzzing Harness and Oracle — Requirement Specification

Component code: **FUZZ** · Status: `[built fuzzer; oracle built (black-box M1/M2/M3/M5/M8; M10 grey-box wiring layer built, live sources on-host); harness generalization ongoing; greybox-run consumes mutation-engine variants (opt-in); coverage-frontier growth emitted to metric_series]`
· Last updated: 2026-10-17 · see CC-FUZZ-0089

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
  - **Evaluation markers** *(M4 and kin: `SstiStrategy`, `GoTemplateSstiStrategy`,
    `SpelInjectionStrategy`, `SqliEvaluationMarkerStrategy`; BUG-0117, edited in place by
    `CC-FUZZ-0079`, BUG-0133).* A value the probe makes the server compute must appear as
    a whole number, and the probe's own literal must not be echoed: "evaluated, not just
    reflected". The echo is judged on the parsed page (`strategies._echo`): the literal
    disqualifies anywhere but a form control's value (an `<input value>`, a `<textarea>`,
    a selected `<option>`: an edit form showing the stored input back), and when it is in
    a form control the number must appear outside every form control. A second, fresh
    value must likewise appear in the response to its own probe (BUG-0117). Limits: a
    page listing earlier values as unselected options refuses, and a number split
    across elements (`593<b>541</b>`) is in no single parsed part and cannot confirm
    (fail-empty false negatives).
    - Enforced by: `tests/test_evaluation_marker_echo.py::test_each_evaluation_marker_judges_the_echo_by_where_it_is`,
      `tests/test_evaluation_marker_echo.py::test_the_prg_edit_form_confirms_like_juice_shops_profile`,
      `tests/test_evaluation_marker_echo.py::test_no_strategy_judges_its_literal_by_a_raw_substring`,
      `tests/test_evaluation_marker_echo.py::test_input_echo_with_a_fixed_number_equal_to_probe_1s_never_confirms`,
      `tests/test_evaluation_marker_echo.py::test_input_echo_on_a_dense_number_page_never_confirms`
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
  destructive-gated `catalog.record_variant` (*CC-FUZZ-0057, BUG-0082:* and every
  probe, base or variant, is checked by `refuse_destructive` **before it is sent**;
  refusals are counted as `destructive_refused`) — the harness's own consumer of
  Phase 8 T8.5's write-back path, alongside the standalone `mutate-run` CLI.
  Added by `CC-FUZZ-0019` (Lane C1/M8-wiring). *(CC-FUZZ-0080, FR-SESS-20, BUG-0134:)*
  an authenticated grey-box run hands `RequestsCorrelatingSender` the session's
  canonical origins with its cookie (`cookie_origins`, from `greybox_cli._cookie_for`):
  the cookie is attached only to a probe on one of them (a cookie without origins is
  refused at construction); a probe on another origin goes without it, its
  `Probe.session` is `"anonymous (out of origin)"`, the attempt's features carry
  `session`, and the run counts it (`summary["session_out_of_origin"]`, the
  `greybox_session_out_of_origin` metric when non-zero, the CLI summary).
  `greybox-run --auth-origin ORIGIN` (repeatable; bare, in scope) hands the session
  manager the operator's auth origins (FR-SESS-20, R5).
  *(CC-FUZZ-0109, BUG-0536:)* `RequestsCorrelatingSender`'s session reads bounded
  (FR-CORE-536). A body the reader stopped comes back as a typed
  `greybox.run.UnobservedProbe` (its `reason`), never as the status-0 "request error"
  probe whose text would be scored. `run_greybox` never scores it, records an attempt
  for it, accepts it as a mutation variant or adopts it as the point's baseline; it
  counts it (`summary["unobserved"]`, the `greybox_unobserved` metric when non-zero).
  Enforced by `tests/test_bounded_reads.py::test_greybox_never_scores_records_or_adopts_an_incomplete_probe`.
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
  - `fuzzlab.oracle.oob.OobListener` is a loopback-only (`core.net.is_loopback_host`,
    CC-CORE-0034; any other host raises) local HTTP callback tracker. *(CC-FUZZ-0057,
    BUG-0089:)* its callback serves `proof(token)`, an HMAC under a per-listener
    secret that appears nowhere in the URL. In-band SSRF / XXE confirmation requires
    the proof, never the token, so a page merely reflecting the URL does not confirm. It binds no socket
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
  `FR-FUZZ-19` below).* A ground-truth point whose tainted value is
  carried in a request **header** (`Case.location`/`InjectionPoint`'s
  `location="header"`) was honestly, distinctly reported as
  not-yet-auditable — never conflated with the client-only/DOM skip
  reason. **Superseded**: `FR-FUZZ-19` closed the underlying gap (a real
  header-injection point type and header-capable sender now exist), so a
  header point is a real, audited point today, not a skip reason. This
  entry is kept for history — it correctly named the gap at the time.

- **FR-FUZZ-24** *(`PredictableTokenSourceStrategy`; `CC-FUZZ-0038`,
  2026-09-23).* The oracle supports real **predictable session-token
  (CWE-330) confirmation**, paired with `FR-AUD-12`'s candidate-
  generation rule, closing Twitch's `TWCH-0005` structural detection
  zero (`CC-LAB-0181`'s own deliberately-separated follow-on):
  - `PredictableTokenSourceStrategy` (`vuln_class=
    "weak_token_entropy"`, `mechanism="timestamp-derived-token"`): two
    ordinary probes; parses each response's `session_token` field;
    confirms iff both parse as base-10 integers with a non-negative
    delta under a fixed 10-second-in-nanoseconds ceiling (a generous,
    jitter-immune backstop, not a precise measured-elapsed-time bound).
  - **Primary false-positive defense named explicitly**: the hex-vs-
    decimal parse gate, not delta-window tightness — a real
    `crypto/rand`-sourced 64-character hex token essentially never
    parses as an all-decimal integer (`(10/16)^64 ≈ 8.6e-14`).
  - `Verdict.evidence` never records a full raw token value — only an
    8-character prefix of each plus the computed delta, since these are
    the target's own issued session-token-shaped values.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"weak_token_entropy": "weak-token-entropy"` — the fifth instance of
    the recurring underscore/hyphen gap, caught automatically by the
    structural guard test.
  - Verified live against Twitch's real booted twins; through the real
    `fuzzlab.harness.multitarget` Phase E wiring, Twitch's real, scored
    recall moves from 3/5 to 4/5.

- **FR-FUZZ-25** *(`MassAssignmentPrivilegedFieldStrategy`; `CC-FUZZ-0039`,
  2026-09-23).* The oracle supports real **mass-assignment (CWE-915)
  confirmation**, paired with `FR-AUD-13`'s candidate-generation rule,
  closing Twitch's `TWCH-0006` structural detection zero (`CC-LAB-0182`'s
  own deliberately-separated follow-on) — this project's first-ever
  detection capability for the `mass_assignment` class at all:
  - `MassAssignmentPrivilegedFieldStrategy` (`vuln_class=
    "mass_assignment"`, `mechanism="privileged-field-injection"`): two
    probes over a hardcoded, known JSON body field (`is_partner`);
    confirms only on a `false`-to-`true` transition of that field
    between probe A (intended fields only) and probe B (intended fields
    plus the privileged field) — never a bare "does it ever read true"
    check.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"mass_assignment": "mass-assignment"` — the sixth instance of the
    recurring underscore/hyphen gap, caught automatically by the
    structural guard test.
  - A real ground-truth defect (`param="is_partner"` instead of the
    whole-body-point `param="body"` convention, which starved the
    strategy of the `content_type="application/json"` it needs) was
    found and fixed before landing, by actually running the real
    `run_targets()` pipeline rather than trusting fake-sender unit tests
    alone.
  - Verified live against Twitch's real booted twins; through the real
    `fuzzlab.harness.multitarget` Phase E wiring, Twitch's real, scored
    recall moves from 4/6 to 5/6.

- **FR-FUZZ-26** *(`UnrestrictedFileUploadContentTypeTrustStrategy`;
  `CC-FUZZ-0040`, 2026-09-23).* The oracle supports real **unrestricted
  file upload (CWE-434) confirmation**, paired with `FR-AUD-14`'s
  candidate-generation rule, closing `CC-LAB-0186`'s own deliberately-
  separated follow-on for Twitch's `TWCH-0009` structural detection zero
  — this project's first-ever detection capability for the
  `unrestricted_file_upload` class, and its first real
  `multipart/form-data` probe of any kind:
  - `UnrestrictedFileUploadContentTypeTrustStrategy` (`vuln_class=
    "unrestricted_file_upload"`, `mechanism=
    "extension-content-type-trust-differential"`): a real, hand-encoded
    `multipart/form-data` two-probe differential. Probe A uploads a file
    named `probe.svg` (a plausible image extension) whose actual bytes
    are an inert marker (`<!DOCTYPE html><p>FUZZLAB-MARKER-...</p>`, per
    `NFR-AUD-safe` — never an executing `<script>` tag) that is NOT valid
    image content of any kind; confirms only if the upload is accepted
    (2xx), the marker is echoed back verbatim, and the response's own
    `Content-Type` header is in a named, bounded script-executable set
    (`text/html`/`image/svg+xml`/etc — never a bare "isn't a safe raster
    type" heuristic, which would over-claim on a harmless-but-unusual
    type like `application/octet-stream`). Probe B (the false-positive
    defense) independently uploads a file named `control.png` whose
    bytes are a real, minimal, valid PNG; confirms only if that upload is
    *also* accepted and its own `Content-Type` is a genuine safe raster
    type — ruling out both a legitimate SVG-accepting endpoint (which
    would also serve `image/svg+xml` for a *real* SVG, correctly) and a
    generically-permissive/broken target that serves every upload with
    the same dangerous type regardless of content.
  - Both twins' real response shape was verified directly against the
    real Go templates before designing this (`fuzzlab/labgen/emitters/
    go_net_http/templates/sinks/no_extension_check.go.j2`/
    `extension_allowlist_mime_check.go.j2`): the vulnerable/secure
    difference is observable directly in the upload's own POST response
    (no separate GET-the-served-file round trip is needed), so this
    strategy never chases a redirect or a second request.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"unrestricted_file_upload": "unrestricted-file-upload"` — the
    seventh instance of the recurring underscore/hyphen gap, checked and
    fixed proactively this time (the structural guard test,
    `test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`,
    was also re-run and stays green).
  - A real, additive `Sender` extension was needed and made narrowly:
    `RequestsProbeSender`/`SeamProbeSender` (`fuzzlab/tools/
    probesender.py`) now encode a `location="body"` value as latin-1
    (a lossless 1:1 byte<->codepoint mapping, the same convention
    `fuzzlab.proxy`/`fuzzlab.web` already use for raw bytes) instead of
    utf-8 whenever `content_type` starts with `"multipart/"` — the
    project's existing whole-body sender path only ever carried text
    (JSON/XML), and utf-8 would corrupt any byte >= 0x80 in this
    strategy's own real binary PNG control probe. Scoped to the
    multipart branch only; every existing JSON/XML whole-body sender
    path is unaffected (re-verified: `test_probesender.py` and the
    mass-assignment/insecure-deserialization/XXE strategy suites all
    still pass unmodified).
  - Verified live against Twitch's real booted twins
    (`LABGEN-GO-0017`/`0018`) via a dedicated live-boot strategy test;
    through the real `fuzzlab.harness.multitarget` Phase E wiring,
    Twitch's real, scored recall moves from 7/9 to 8/9 (only
    `webhook_signature`'s own permanently-infeasible timing side channel
    remains undetected).

- **FR-FUZZ-27** *(`PriceTrustDifferentialStrategy`; `CC-FUZZ-0041`,
  2026-09-23).* The oracle supports real **price/amount integrity
  bypass (CWE-807) confirmation**, paired with `FR-AUD-15`'s candidate-
  generation rule, closing `CC-LAB-0188`'s own deliberately-separated
  follow-on for Netflix's `NFLX-0005` structural detection zero — this
  project's first-ever detection capability for the
  `price_integrity_bypass` class (a real implementation already exists
  on two stacks, `php_laravel`'s Booking.com checkout, `CC-LAB-0212`, and
  `spring_boot`'s Netflix plan-change endpoint, `CC-LAB-0188`, but
  neither had any detection before this entry):
  - `PriceTrustDifferentialStrategy` (`vuln_class=
    "price_integrity_bypass"`, `mechanism=
    "client-price-trust-differential"`): a two-probe differential over
    the JSON body's own `monthly_charge` field, needing no prior
    knowledge of the target's real price (which a genuine black-box
    fuzzer never has) — it sends the same `plan_tier` twice with two
    deliberately different, implausible amounts (`0.01`, then
    `999999.99`) and confirms only if the server's own reported charge
    tracks *both* submitted amounts exactly; a target whose reported
    charge stays identical across both probes (the secure,
    server-recomputed shape) fails closed, correctly, rather than being
    treated as ambiguous evidence. The same "does the sink's own output
    move with this specific input" reasoning `MassAssignmentPrivileged
    FieldStrategy`'s own two-probe differential already uses for a
    boolean field, generalized here to a numeric one.
  - **Design checked against `MassAssignmentPrivilegedFieldStrategy`'s
    own docstring/pattern before designing from scratch**, per this
    task's own explicit instruction: both hardcode the sink's own known
    field name(s) directly in the strategy (`is_partner` there,
    `monthly_charge`/`plan_tier` here), both gate on
    `content_type == "application/json"` and fail closed otherwise, and
    both require a matching-but-distinct two-probe result rather than a
    bare single-probe 200 as evidence.
  - `R-PRICE-TRUST-DIFFERENTIAL`'s own `sink_context_in` is deliberately scoped
    to `["payment_charge"]` only, not also `"sql"` — see `FR-AUD-15` for
    the false-candidate-explosion risk this avoided.
  - **A real, pre-existing ground-truth defect found and fixed during
    this entry's own real end-to-end pipeline verification, not
    silently left for a later discovery**: `NFLX-0005`'s ground truth
    (`CC-LAB-0188`) originally used `param="monthly_charge"` (a
    per-named-field convention modeled on `NFLX-0004`'s own query-param
    case), but `fuzzlab.harness.auto.points_from_ground_truth` only
    marks a `location="body"` point's Content-Type as
    `application/json` when `param == "body"` exactly (the same gate
    `CC-LAB-0182`'s own `mass_assignment` ground truth already had to
    satisfy) — a per-field `param` name for a body point silently
    starves this strategy of the JSON point it needs when driven through
    the real harness, even though the strategy's own dedicated unit/
    live-boot tests (which construct a `Candidate` directly) never hit
    this gate and so never revealed it. Corrected in place in
    `lab/ground-truth-netflix-clone/` (living-doc discipline) to
    `param="body"`, the same whole-body convention `NFLX-0001`-`0003`
    use — verified directly: `points_from_ground_truth` now reports
    `body_content_type="application/json"` for this point. This same
    correction also fixed a **real regression this task's own first
    (lab) commit had silently introduced** into `tests/
    test_multitarget_category4.py`'s `@pytest.mark.slow` tests (not
    caught by the non-slow suite run before that commit, since both
    affected tests are slow-marked): adding `NFLX-0005` to the ground
    truth changed the Netflix app's own total positive count from 4 to
    5, which on its own (before this entry's cell/strategy were added to
    that test) dropped `test_both_apps_run_through_multitarget_for_real`'s
    and `test_netflix_multi_cell_boot_confirms_all_positives`'s own
    recall assertions from correct to failing (`1/4`/`4/4` no longer
    matched reality) — found by actually re-running the slow suite
    during this entry's own work, not assumed clean from the non-slow
    run alone, and fixed here by updating both tests' own assertions and
    extending the multi-cell boot to include `LABGEN-JV-0009`. A second,
    structurally identical regression was then found the same way, by a
    full non-slow-suite re-run after that fix (not assumed sufficient on
    its own): `tests/test_auto.py::test_points_from_ground_truth_sets_
    body_content_type_only_for_json_cases` hardcoded Netflix's own
    whole-body-JSON point count at 3; updated to 4, with the new point's
    own `body_content_type` asserted explicitly.
  - Unit tests (`tests/test_oracle_strategies_price_integrity.py`, 10
    tests, fake-sender based, mirroring `test_oracle_strategies_mass_
    assignment.py`'s own vulnerable/secure-twin pattern): the vulnerable
    `client_trusted_amount` twin confirms; the secure
    `server_recomputed_amount` twin fails closed; a false-positive-
    avoidance case (a target that always returns the same fixed low
    amount) fails closed; a non-JSON candidate, a missing-field
    response, and a rejected probe B each fail closed; the rule matches/
    doesn't-match/doesn't-match-an-unrelated-sink-context cases; and the
    registration check.
  - Real, executed live-boot proof
    (`tests/test_oracle_strategies_price_integrity_live_boot.py`, driven
    through the real `RequestsProbeSender` against a real booted
    `LABGEN-JV-0009`/`0010` cell pair, never a fake sender): the
    strategy confirms the vulnerable twin and correctly fails closed on
    the secure twin.
  - Verified live through the real `fuzzlab.harness.multitarget` Phase E
    wiring (`test_netflix_multi_cell_boot_confirms_all_positives`,
    extended): Netflix's real, scored recall in that multi-cell boot
    moves from 4/4 to 5/5.
  - **Cross-stack generalization, verified live (`CC-LAB-0189`,
    2026-09-23, updated in place)**: `go_net_http` gained its own first
    `price_integrity_bypass` instance (`TWCH-0010`, Twitch's channel-
    subscription-purchase endpoint) using the same fixed `plan_tier`/
    `monthly_charge` field names this strategy already hardcodes, as a
    deliberate design choice made specifically to prove reuse. This
    strategy needed **zero** new code to confirm the new `go_net_http`
    vulnerable twin and correctly fail closed on its new secure twin --
    the first proof this strategy generalizes across stacks in the
    direction `spring_boot` -> `go_net_http` (this entry's own original
    proof, above, was single-stack; `FR-LAB-142`'s `AccessControlIdor
    Strategy` proof went the other direction, `go_net_http` ->
    `spring_boot`). Verified through the real `fuzzlab.harness.
    multitarget` pipeline (`tests/test_multitarget_category4.py::
    test_both_apps_run_through_multitarget_for_real`, extended): Twitch's
    real, scored recall in that boot moves from 8/9 to 9/10.

- **FR-FUZZ-28** *(`GoTemplateSstiStrategy`; `CC-FUZZ-0042`,
  2026-09-23).* The oracle supports real **SSTI confirmation on Go's
  `text/template` syntax** — closing `CC-LAB-0196`'s own honestly-
  documented detection gap for Twitch's `TWCH-0012` (`/channels/
  commands`, `go_net_http`'s first `ssti`/`template_render` instance),
  reusing `R-SSTI`'s existing candidate-generation rule as-is (it
  already nominates on `sink_context`/location, not per-mechanism, so no
  audit-side change was needed):
  - **The gap this closes.** The existing `SstiStrategy`'s
    `_ssti_payloads()` wraps an infix arithmetic expression (`a*b`) in
    five template-engine delimiter styles. That marker technique is
    structurally incompatible with Go's `text/template`: its action
    grammar has NO infix arithmetic operators at all (verified via a
    real `go run` check and a real booted target,
    `tests/test_labgen_go_live_boot.py::test_ssti_go_text_template_
    syntax_mismatch`/`test_ssti_strategy_does_not_generalize_to_go_
    text_template`), so two of the five payloads fail to parse outright
    and the other three are echoed back as inert literal text.
  - `GoTemplateSstiStrategy` (`vuln_class="ssti"`, `mechanism=
    "go-template-len-marker"`) uses a different marker technique
    entirely, built on `text/template`'s own builtin functions (`len`,
    `index`, `printf`/`print`, the comparison functions), none of which
    need an infix arithmetic operator: `{{ len "AAA...A" }}` (a literal
    string of `N` `A` characters) evaluates to the decimal integer `N`
    only if the engine genuinely parses the action and invokes the
    builtin. `N` is randomized fresh per probe (3-digit range,
    `secrets.randbelow(900) + 100`, matching `SstiStrategy`'s own `a`/
    `b` range).
  - **False-positive defense, a differential over a single-probe
    heuristic** (this project's own established preference, per
    `InsecureDeserializationTypeConfusionStrategy`'s own docstring): a
    single probe's random 3-digit `N` coincidentally already appearing
    somewhere in an unrelated normal response is a real, if small, risk.
    So this strategy sends TWO independent probes with two distinct
    random lengths `N1 != N2` and confirms only when ALL hold: neither
    probe's own literal payload is echoed back verbatim (rules out dumb
    reflection); probe 1's response contains `N1` as a whole decimal
    token (word-boundary matched); probe 2's response contains `N2`
    likewise; and NEITHER response also contains the OTHER probe's
    length as a whole token (a cross-contamination guard against a
    cached/stale/echo-everything response that would otherwise pass the
    first three checks without actually computing a fresh,
    request-specific `len()` each time).
  - *(CC-FUZZ-0084 amendment, BUG-0139's PA-0002 sweep:)* **two quoting forms.**
    - The probe's string literal is Go's interpreted string, `{{ len "AAA..." }}`,
      in a first two-probe round. When that round does not confirm, a second round
      uses Go's raw string, `{{ len `AAA...` }}`. It has fresh lengths and the same
      rules: both probes evaluated, no cross-bleed, the BUG-0133 echo rules.
    - So a data path that filters or escapes `"` before the template is parsed is no
      longer a guaranteed miss.
    - A raw-string confirmation's evidence says `string_form: raw (backtick)`.
    - **Cost:** 2 requests to confirm by the `"` form (as before); 4 to confirm by
      the raw string or to give no verdict (the worst case, up from 2).
  - **Design decision: a new strategy under the same category, not a
    widened `SstiStrategy`** — checked against this project's own
    established architecture (`default_strategies()`'s own registration
    order, `Oracle.confirm()`'s multi-strategy-per-category dispatch)
    before deciding, not assumed. `Oracle.confirm()` already tries every
    strategy whose `category` matches a candidate in order, stopping at
    the first confirming verdict, with no code change needed to add a
    second strategy under the same `category` — the same
    "cheaper/broader mechanism first, specialized fallback for a syntax
    family the first one structurally cannot reach next" layering
    `SsrfInBandMarkerStrategy`/`SsrfOobStrategy` and M1 timing/
    `CommandInjectionOobStrategy` already establish. Folding this into
    `SstiStrategy.confirm()` itself would make every non-Go target pay
    for two additional wasted requests on top of its own five, and would
    conflate two structurally different marker techniques in one method,
    against this project's one-mechanism-per-strategy convention.
    Registered directly after `SstiStrategy` in `default_strategies()`
    (category `server-side-template-injection`): `SstiStrategy` is tried
    first (broader existing coverage across the arithmetic-evaluating
    engines this lab already has), and this strategy is the fallback
    specifically for the syntax family `SstiStrategy` cannot parse into
    evaluation at all.
  - **JSON whole-body-point support, gated and hardcoded like this
    project's own established convention** (`PriceIntegrityBypass
    Strategy`'s `monthly_charge`/`plan_tier`, `MassAssignmentPrivileged
    FieldStrategy`'s `is_partner`): for a `content_type ==
    "application/json"` candidate, the marker expression is wrapped as
    `{"template": "<expr>"}` — this lab's own `user_supplied_template_
    compile` sink shape. A non-whole-body candidate (a plain named
    query/form param) sends the marker expression directly, unwrapped.
    A differently-shaped JSON whole-body SSTI sink (a different field
    name) has nothing for this strategy to build and correctly fails
    closed rather than misfiring.
  - Unit tests (`tests/test_oracle_vectors.py`, fake-sender based,
    mirroring `SstiStrategy`'s own test structure in the same file): the
    vulnerable case (a fake sender that genuinely evaluates `len`)
    confirms; a mere-reflection sender, a static/fixed-response sender
    (including one containing unrelated decimal digits, the false-
    positive class this strategy's own docstring names explicitly), and
    a stale/cross-contaminated sender (one that always echoes back the
    first probe's own result) each fail closed.
  - Real, executed live-boot proof
    (`tests/test_labgen_go_live_boot.py::test_go_template_ssti_
    strategy_closes_the_generalization_gap`, driven through a real
    `GoLiveBootHarness` boot of `LABGEN-GO-0023`/`0024`, never a fake
    sender): the strategy confirms the real vulnerable twin and
    correctly fails closed on the real secure twin (which only ever
    does a fixed-map lookup and never evaluates `len` on caller input).
  - **Existing coverage re-verified unmodified, not assumed unaffected**:
    `spring_boot`'s TrackerNest SSTI live-boot tests
    (`tests/test_labgen_spring_boot_live_boot.py::
    test_ssti_vulnerable_twin_evaluates_ognl_expression_for_real`/
    `test_ssti_secure_twin_never_evaluates_the_tainted_value`) and its
    real-pipeline SSTI coverage
    (`tests/test_labgen_spring_boot_trackernest_multitarget.py`, which
    drives `TNEST-0001` through `SstiStrategy` via the real
    `fuzzlab.harness.multitarget` pipeline) were re-run directly against
    a real boot and stay green — `GoTemplateSstiStrategy` is additive
    only (a new, separately-scoped strategy tried after `SstiStrategy`
    in the same category), never touching `SstiStrategy`'s own code.
  - Verified through the real `fuzzlab.harness.multitarget` pipeline
    (`tests/test_multitarget_category4.py::
    test_both_apps_run_through_multitarget_for_real`, extended): Twitch's
    `TWCH-0012` is now a real, confirmed finding; ground-truth
    cardinality stays 12 positives (a pure detection increment, not a
    lab-side change), `tp` moves from 9 to 10, and Twitch's own real,
    scored recall moves from `9/12` to `10/12` (only `webhook_signature`
    and `path_traversal` remain undetected, each for its own distinct,
    tracked reason).
  - Enforced by (two quoting forms; CC-FUZZ-0084, BUG-0139): `GoTemplateSstiStrategy.confirm` / `QUOTES` — `tests/test_go_ssti_quoting.py::test_a_filtered_double_quote_is_confirmed_by_the_raw_string`, `tests/test_go_ssti_quoting.py::test_a_confirmation_by_the_double_quoted_form_costs_what_it_did`, `tests/test_go_ssti_quoting.py::test_an_echo_only_page_is_never_confirmed_in_either_form`, `tests/test_go_ssti_quoting.py::test_the_raw_string_round_keeps_the_echo_rules`, `tests/test_go_ssti_quoting.py::test_a_stale_raw_string_render_is_never_confirmed`

- **FR-FUZZ-29** *(`HttpHeaderInjectionCrlfStrategy`; `CC-FUZZ-0045`,
  2026-09-23).* The oracle supports real **CRLF response-header-injection
  (CWE-113) confirmation** for `http_header_injection`, paired with
  `FR-AUD-16`'s candidate-generation rule, closing `CC-LAB-0198`'s own
  deliberately-deferred detection follow-on for Twitch's `TWCH-0013`
  (`/channels/redirect?destination=`) — this project's own last known
  real category-4 detection gap:
  - `HttpHeaderInjectionCrlfStrategy` (`vuln_class=
    "http_header_injection"`, `mechanism=
    "crlf-response-header-injection-differential"`): a two-probe
    differential over a per-call random header name/token. Probe A
    (malicious) sends `f"fuzzlab-ok\r\n{header_name}: {token}"`;
    confirms only if the response genuinely carries a header named
    `header_name` (case-insensitive lookup, matching
    `OpenRedirectStrategy`'s own `_header` convention) whose value is
    `token`. Probe B (control) sends the identical text with the `\r\n`
    replaced by a single space; requires the same header to be ABSENT —
    ruling out a target that turns an arbitrary input substring into a
    response header for some unrelated reason, not specifically CRLF
    splitting.
  - **Verified empirically before design, not assumed** (read
    `fuzzlab/labgen/emitters/go_net_http/templates/sinks/
    raw_socket_response_write.go.j2`, the vulnerable twin's own
    `http.Hijacker` mechanism, first): booted the real app and sent a
    real `RequestsProbeSender` probe directly — `requests` (via
    `urllib3` -> `http.client`'s own header parser) parses a genuinely
    spliced-in extra header line exactly like any other real header, with
    no merging/normalization defeating observation for this payload shape
    (one injected header, no second blank-line-terminated fake response).
    A raw-socket/`http.client`-level probe, the alternative this task's
    own instructions asked to consider, turned out unnecessary in
    practice.
  - Known limitation, not silently swept under the rug: detects CRLF
    injection observable as an extra header on the SAME response the
    probe's own request received — a full response-SPLITTING attack (a
    second `\r\n\r\n` terminating the current response and smuggling an
    entirely separate fake response to a downstream cache/proxy) is a
    related but stronger primitive this strategy does not separately
    verify, since this project's own lab shape only instantiates the
    single-extra-header variant.
  - Real, executed live-boot proof (`tests/test_labgen_go_live_boot.py::
    test_http_header_injection_strategy_closes_the_crlf_detection_gap`,
    driven through a real `GoLiveBootHarness` boot, never a fake sender):
    confirms the real vulnerable twin (`LABGEN-GO-0025`) and correctly
    fails closed on the real secure twin (`LABGEN-GO-0026`, which rejects
    the identical payload with HTTP 400).
  - Verified through the real `fuzzlab.harness.multitarget` pipeline
    (`tests/test_multitarget_category4.py::
    test_both_apps_run_through_multitarget_for_real`, extended): Twitch's
    `TWCH-0013` is now a real, confirmed finding; ground-truth cardinality
    stays 15 (a pure detection increment), `tp` moves from 12 to 13, and
    Twitch's own real, scored recall moves from `12/15` to `13/15` (only
    `webhook_signature` and `path_traversal` remain undetected, each for
    its own distinct, already-tracked reason).
  - Wiring this into the real pipeline surfaced and fixed a second,
    independent defect (`BUG-0046`/`PA-0048`): `fuzzlab/harness/auto.py::
    points_from_ground_truth`'s `sink_context_by_point` lookup silently
    collapsed `TWCH-0013`/`TWCH-0015`'s shared `destination` sink's two
    distinct `sink_context` values down to one, discarding `"header"` —
    fixed by keeping every distinct value per point and emitting one
    audited point per value, verified harmless against `fuzzlab.harness.
    scoring.score`'s own set-based, vuln_class-keyed dedup and against a
    full non-slow-suite + multitarget/live-boot re-run (no new
    regressions).

- **FR-FUZZ-30** *(`PathTraversalFsPathReadStrategy`; `CC-FUZZ-0046`,
  2026-09-23).* The oracle supports real **path-traversal (CWE-22,
  `fs_path_read` sink context) confirmation** for `path_traversal`,
  paired with `FR-AUD-17`'s candidate-generation rule, closing
  `CC-LAB-0190`'s own deliberately-deferred detection follow-on for
  Twitch's `TWCH-0011` (`GET /clips/export?filename=`) — this project's
  own last known real, TRACKED category-4 detection gap (only
  `webhook_signature`'s own confirmed-infeasible CWE-347 timing side
  channel remains):
  - `PathTraversalFsPathReadStrategy` (`vuln_class="path_traversal"`,
    `mechanism="passwd-file-content-marker-differential"`): a `../`-
    traversal payload must make the response body contain the target's
    own real, PRE-EXISTING `/etc/passwd` content (`root:.*:0:0:`); a
    control probe with no traversal separators at all (`"passwd"`) must
    NOT show that marker. Nothing is planted on the target's filesystem
    — this only reads a file that already exists there, the same
    standard, safe, purely-read black-box technique this project's own
    `fuzzlab/labgen/nuclei_oracle.py` already bundles for a different
    sub-purpose (`lab/nuclei-templates/path-traversal-etc-passwd.yaml`).
  - **Corrects a mischaracterization made when detection was originally
    deferred** (`FR-LAB-145`, `CC-LAB-0190`): that deferral reasoned "a
    path-traversal strategy cannot plant its own canary on the target's
    filesystem... probing well-known OS paths is not a safe/realistic
    black-box signal," conflating this concern with a canary-PLANTING
    design (the SSRF/XXE pattern via an `OobListener`). That reasoning
    never applied to the read-a-pre-existing-file technique actually
    used — `path_traversal` was tracked as "genuinely unbuilt, an open
    follow-on," not confirmed infeasible the way `webhook_signature` is
    for its own distinct, unrelated reason.
  - **Verified empirically against the real, live-booted vulnerable/
    secure twins before design, not assumed**: the vulnerable twin
    (`LABGEN-GO-0021`) returns real `/etc/passwd` content (HTTP 200) for
    `filename=../../../../../../../../etc/passwd`; the secure twin
    (`LABGEN-GO-0022`, `realpath_confine`) rejects the identical payload
    outright (HTTP 403) — the existing, already-escalating
    `_TRAVERSAL_PAYLOADS` list (shared with the pre-existing,
    differently-named `PathTraversalStrategy`/`"file-inclusion"` class,
    which matches no current ground truth and is left untouched) already
    reaches real OS-file content at this lab's confinement depth, with
    no new traversal-depth tuning needed.
  - Real, executed live-boot proof (`tests/test_labgen_go_live_boot.py::
    test_path_traversal_strategy_closes_the_fs_path_read_detection_gap`,
    driven through a real `GoLiveBootHarness` boot and a real
    `RequestsProbeSender`, never a fake sender): confirms the real
    vulnerable twin and correctly fails closed on the real secure twin.
  - Verified through the real `fuzzlab.harness.multitarget` pipeline
    (`tests/test_multitarget_category4.py::
    test_both_apps_run_through_multitarget_for_real`, extended): Twitch's
    `TWCH-0011` is now a real, confirmed finding; ground-truth
    cardinality stays 15 (a pure detection increment), `tp` moves from
    13 to 14, and Twitch's own real, scored recall moves from `13/15` to
    `14/15`.

- **FR-FUZZ-23** *(`JwtAlgNoneConfusionStrategy`; `CC-FUZZ-0037`,
  2026-09-23).* The oracle supports real **JWT algorithm-confusion
  (CWE-347) confirmation**, paired with `FR-AUD-11`'s candidate-
  generation rule, closing Twitch's `TWCH-0004` structural detection
  zero (`CC-LAB-0180`'s own deliberately-separated follow-on):
  - `JwtAlgNoneConfusionStrategy` (`vuln_class=
    "jwt_algorithm_confusion"`, `mechanism="alg-none-bypass"`): a
    two-probe differential over a header-carried Bearer token. Probe A
    (an unsigned `alg:none` token, a freshly-minted marker carried in
    its `channel_id` claim — the literal field the real sink echoes)
    must return 200 with the marker echoed back; probe B (the same
    marker, claiming `HS256` with a garbage signature) must return a
    real auth-rejection status (401/403 specifically, not merely
    "not 200") — ruling out both a generically-permissive endpoint and
    an unrelated parsing-crash false positive.
  - **A real defect found by the accuracy-review pass before
    implementation**: an earlier draft carried the marker in an
    arbitrary `{"marker": ...}` JSON field, which the real sink
    template silently drops (only `channel_id`/`role` are unmarshaled)
    — would have made the strategy permanently return `None` against a
    real boot despite passing every unit test with a hand-built fake
    sender. Corrected before any code was written.
  - `fuzzlab.core.runmode._VULN_TO_CATEGORY` gained
    `"jwt_algorithm_confusion": "jwt-algorithm-confusion"` — the fourth
    instance of the recurring underscore/hyphen gap, caught automatically
    this time by the structural guard test added for the second instance.
  - Verified live against Twitch's real booted twins; through the real
    `fuzzlab.harness.multitarget` Phase E wiring, Twitch's real, scored
    recall moves from 2/4 to 3/4.

- **FR-FUZZ-22** *(`XxeInBandMarkerStrategy`/`XxeOobStrategy`;
  `CC-FUZZ-0035`, 2026-09-23).* The oracle supports real **XXE (CWE-611)
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
    strategy had been failing closed there since `FR-FUZZ-18` landed) —
    fixed and re-verified against real boots, not a production defect.
  - Verified live against TrackerNest's real booted twins, both directly
    and through the real `fuzzlab.harness.multitarget` pipeline:
    TrackerNest's real, scored recall moves from 1/3 to 2/3.

- **FR-FUZZ-21** *(`InsecureDeserializationTypeConfusionStrategy`;
  `CC-FUZZ-0034`, 2026-09-23).* The oracle supports real
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
    second instance of the exact gap `FR-FUZZ-20` found for
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

- **FR-FUZZ-20** *(`AccessControlIdorStrategy`; `CC-FUZZ-0033`, 2026-09-23).*
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
  - **Cross-stack generalization now verified** (`CC-LAB-0187`,
    2026-09-23): the "broader validation against a second,
    differently-shaped target" this requirement's own note called for
    has now happened — driven with zero new code against Netflix's first
    `access_control` page (`spring_boot`, `LABGEN-JV-0007`/`0008`,
    `/api/account/billing`), confirming the vulnerable twin and
    correctly failing closed on the secure twin
    (`tests/test_labgen_spring_boot_account_billing_live_boot.py::
    test_real_boot_proves_the_access_control_idor_strategy_generalizes_to_spring_boot`).
    Netflix's own real, scored recall moves from 3/3 to 4/4 in the
    multi-cell live-boot test. This is the first time this strategy has
    been proven to generalize across two genuinely different stacks
    (`go_net_http` and `spring_boot`), not just across routes on the
    same stack (`CC-LAB-0183`'s own `channel_id`/`/channels/subscribers`
    proof).

- **FR-FUZZ-19** *(header points become real, audited points; a
  content-type-aware whole-body sender; `CC-FUZZ-0032`, 2026-09-23).*
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

- **FR-FUZZ-18** *(`CC-FUZZ-0031`, 2026-09-23).* The oracle supports real
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

- **FR-FUZZ-31** *(`PriceIntegrityBypassStrategy` anchor; `CC-FUZZ-0047`, 2026-09-25;
  backfilled CC-FUZZ-0055 — the change landed with CC-LAB-0239 but this requirement was
  never written).* The price-integrity-bypass confirmation (`price_integrity_bypass`,
  `LABGEN-BC-0005`/`0006`) is anchored to the confirmation page's
  `data-charged-amount="<canary>"` HTML attribute (after whitespace stripping), an exact
  anchored match rather than a bare substring. The canary has three decimal places and
  excludes the real rate-table values (`89.00`/`149.00`/`249.00`). It replaced the
  earlier `"charged_amount":"<canary>"` JSON-fragment anchor when the checkout response
  became an HTML page.
- **FR-FUZZ-32** *(confirmation budget + anomaly tripwire; `CC-FUZZ-0048`,
  2026-10-13).* The automatic pipeline records an `oracle_status` on every candidate
  (FR-CORE-14). The CLI also offers a post-run `--anomaly` step.
  - **`fuzzlab auto --confirm-budget N`** sends at most N **distinct** candidates to the
    oracle. A confirmation key is `(url, param, method, location, category)`; duplicate
    rows share one key, one confirmation and one status.
  - **Order:** `--budget-method {score,uncertainty,committee,random}`, default `score`,
    from `fuzzlab.ml.active.prioritize` (FR-ML-11).
  - **Skipped candidates** are `skipped_budget`. They are never counted as oracle
    rejections or training negatives. A scored run counts them as misses.
  - **Fallback:** with no usable earlier labels for the target, the budget is not
    applied, every candidate is confirmed, and the summary says so
    (`pipeline_confirm_budget_fallback=1`).
  - **Metrics:** `pipeline_oracle_rejected` is counted per key (checked keys minus
    confirmed keys). The pipeline also records `pipeline_oracle_checked`, `_skipped`,
    `_no_confirmer`, `_checked_keys`, `pipeline_confirmable_keys` and
    `pipeline_confirm_budget`.
  - **Without a budget** *(amended CC-FUZZ-0056, BUG-0072)*, each confirmation key is
    confirmed **once, on its first row in row order, whatever the verdict**. Later rows
    of the key send the identical `Candidate`, so they are marked `checked` with no
    probe. Row order (the bandit's) is kept. Findings ≤ distinct confirmed keys, and
    confirmations == distinct keys, in every mode. (It used to confirm every row,
    writing duplicate findings.)
  - **Crash safety** *(CC-FUZZ-0056, BUG-0071)*: before the oracle loop, every candidate
    gets a status that is never read as a label: `no_confirmer` (final) or `pending`.
    The statuses gathered so far are flushed in a `finally`, so a crash leaves unreached
    rows `pending` (unlabelled), never NULL.
  - **`--anomaly [--anomaly-contamination F]`** runs the persisted ECOD tripwire after
    the run (FR-ML-12) and prints the top flagged candidates. *(CC-FUZZ-0052:)* `F` is
    an upper bound — at most that fraction, whole tie groups only — and the summary
    prints `note: <reason>` when ties left fewer flagged.
  - All flags appear in the launcher form, as number inputs, via `commandspec`.
- **FR-FUZZ-32a** *(usage checks before side effects; `CC-FUZZ-0056`, BUG-0078).*
  `fuzzlab auto` resolves its run plan with `harness.auto.plan_run`, the function
  `run_auto` uses: the D15 fail-safe, and `--points ground-truth` without a contract.
  It also checks the environment (`--browser` needs Playwright; greybox side-channel
  paths must exist), **before opening the store**. A usage error leaves no run row.
  A failure after the run starts (an OOB bind, a crash) records `run.notes = "aborted:
  …"` via `Store.mark_aborted`, then re-raises. `greybox-run` and `run_targets` follow
  the same rule.
- **FR-FUZZ-33** *(`--train-on`; `CC-FUZZ-0049`, 2026-10-13).* `fuzzlab auto --train-on
  {run,earlier}` (default `run`) chooses what `--score` / `--rank` train on.
  - It needs `--score` and/or `--rank`, otherwise it is a usage error.
  - **`earlier`** trains on earlier runs against the same target, never this run's
    labels (FR-ML-14).
  - **Trained summary:** how many earlier labelled candidates from which runs, "not on
    this run's labels", the share of this run's candidates seen in training, and the
    forward metric with its baseline (or why there is none).
  - **Refused summary:** "NOT scored" / "NOT ranked" with the reason, pointing at
    `--train-on run`. Nothing is written.
  - The launcher shows the flag as a choice field via `commandspec`.
- **FR-FUZZ-34** *(ML attached as plugins; `CC-FUZZ-0050`, 2026-10-13).*
  - **Plugins.** `fuzzlab auto`'s ML flags attach the built-in ML stage plugins
    (FR-ML-6). `run_auto` records the plugin set, takes the budget prioritizer from the
    plugins when none is passed, and dispatches `after_run` and `finalize` after the
    pipeline, so `run_targets` gets them per target run.
  - **Usage errors** are raised before the store is opened (exit 2): ML flags without
    the ML package, `--confirm-budget` with no prioritizer available, and two
    prioritizers.
  - **Summary.** It is unchanged for successful stages (golden-tested). A failed or
    missing requested stage prints `FAILED`. A failed prioritizer prints the
    row-order budget line.
  - **Exit 1** when a post-run plugin or the prioritizer failed, or a requested stage
    did not run.
  - With no ML flags and no `--plugins`, no plugin manager is created.
- **FR-FUZZ-35** *(saved models, hybrid; `CC-FUZZ-0051`, 2026-10-13).*
  - **`--train-on saved`** scores and ranks with saved earlier models, without training
    (FR-ML-15). `--model-id` / `--ranker-model-id` pin one: they need `--score` /
    `--rank` and `--train-on saved`.
  - **`--hybrid`** adds the ECOD anomaly feature to the classifier. It needs `--score`
    and is a usage error with `--train-on saved`.
  - **Summary.** It names the saved model and its training runs, or the refusal reason.
- **FR-FUZZ-36** *(holdout, calibration, reveal; `CC-FUZZ-0053`, 2026-10-13).*
  - **`--holdout`** passes `holdout=True` to the classifier, ranker and budget stages
    (FR-ML-19); it needs `--score`, `--rank` or `--confirm-budget`. The summary prints
    only label-free facts: how many of the run's endpoints are held out, and whether
    sealed metrics were written (or why not) — never a holdout number.
  - **`--calibrate {none,platt}`** (default `none`) Platt-calibrates the classifier
    (FR-ML-20); it needs `--score` and is a usage error with `--train-on saved`. The
    summary prints the out-of-fold ECE / Brier raw → cross-fitted, or why nothing was
    calibrated.
  - Each appears in a stage's recorded config only when set, so a run without them
    records exactly the config it always did.
  - **`fuzzlab reveal-holdout [--store S] --run N`** (also `fuzzlab train
    reveal-holdout`; `--store` optional since FR-FUZZ-400) prints a run's sealed holdout
    metrics and the store-wide reveal count for that membership version (core only, no
    traffic, no ML package needed); "nothing to reveal" records no reveal. Not in the
    web launcher, so a reveal is always a deliberate command.
- **FR-FUZZ-37** *(ranker objective, anomaly method, flow anomalies; `CC-FUZZ-0054`,
  2026-10-13).*
  - **`--rank-objective {pointwise,pairwise,auto}`** (FR-ML-21) needs `--rank` and is a
    usage error with `--train-on saved`; the summary prints the objective and its
    run-wide per-fold NDCG / P@k (or the pointwise fallback).
  - **`--anomaly-method {ecod,iforest}`** (FR-ML-22) needs `--anomaly`; the summary line
    reads `anomaly (iforest): …` (unchanged for ECOD).
  - Both appear in a stage's config only when not the default.
  - **`fuzzlab flow-anomaly [--store S] --run N [--method] [--contamination] [--seed]`**
    (FR-ML-23) writes the run's flow anomaly columns (no traffic, no `--authorized`),
    prints per-host counts and the top flagged flows, and says contamination is a
    forced per-host fraction. Reached through `import_ml`: without ML it exits 2 with
    the "not installed" message. Registered in the launcher (`sends_traffic=False`).
- **FR-FUZZ-38** *(on-host run through the CLI; feature-version record; `CC-FUZZ-0055`,
  2026-10-13).*
  - `scripts/on_host_full_run.sh` and `docs/ON_HOST_RUNBOOK.md` exercise every ML step
    through the shipped CLI (never the ML package directly; guarded by
    `tests/test_on_host_script.py`): budgeted runs with an **asserting** check
    (`_check_sql`: no fallback, `min(5, confirmable)` keys checked), `--rank-objective
    auto`, `--calibrate platt --holdout`, `--plugins --anomaly` in one run,
    `--anomaly-method iforest`, `fuzzlab flow-anomaly`. The holdout reveal runs only with
    `REVEAL_HOLDOUT` set. New steps are marked "[not yet executed on host]".
  - The pipeline records `pipeline_budget_feature_version` (the candidate feature
    version the budget order model read; none for `random`) — BUG-0069.
  - Attempt writers name their own feature schema inside `features_json` (`_schema`:
    `greybox/1`, `fuzz-csv/1`); `attempt.feature_version` stays NULL (BUG-0069 sweep).

- **FR-FUZZ-46** *(open-redirect confirmation; `CC-FUZZ-0067`, 2026-10-14, BUG-0124).*
  `OpenRedirectStrategy` sends a plain canary `https://oracle<tok>.example/cb`. Only
  when it does not land and the candidate carries a redirect seed (FR-AUD-21) does it
  send one more, `https://oracle<tok2>.example/cb?fzlb=<seed>`, for an allowlist that
  checks containment (Juice Shop's `/redirect`). A probe confirms when its `Location`
  or meta-refresh target, resolved against the probed URL (scheme-relative included),
  is `http`/`https` with our token host (one trailing dot allowed) and path `/cb` (or `/cb/`): the host is the signal, never a
  prefix (PA-0122). Cost: +1 request per seeded candidate whose plain probe failed.
  A meta refresh counts only in a response rendered as HTML (`CC-FUZZ-0072`, BUG-0127;
  `tests/test_open_redirect_seed.py::test_a_meta_refresh_in_a_non_html_response_never_confirms`).
- **FR-FUZZ-47** *(JSON body points; `CC-FUZZ-0068`, 2026-10-14, forms phase 3, lane
  J).*
  - **Sending.** `SeamProbeSender` and `RequestsProbeSender` place a `json` point
    (FR-CORE-36): the whole body rebuilt from its entries, types kept, with the leaf
    set to the payload as a string, sent `Content-Type: application/json` to the
    point's URL and method. A leaf that cannot be placed (a malformed name or entry
    list, a path through another leaf) is refused with `UnplaceableLocation` before any
    send. **greybox** (`RequestsCorrelatingSender`) and the **M6 executor** do not place
    `json`: greybox raises `UnplaceableLocation` and `greybox-run` never receives JSON
    points (reported); the executor gives no verdict before starting a browser: it
    raises `UnplaceableLocation` for every placement it refuses, never returns an
    observation (BUG-0523, `CC-FUZZ-0103`).
  - **Siblings.** `oracle._FormBoundSender` binds a `json` candidate's other leaves to
    every probe of it. They were stored through `redact_leaf` and pass `_send_value`
    (`neutral_value`) in the point builder: a url leaf goes as `http://127.0.0.1/`, a
    host as `127.0.0.1`, an identifier-like or sensitive leaf as `""`/`null`, a password
    as `""`.
  - **Oracle.** Strategies are location-agnostic through `_send`; the SQLi engines get
    a JSON point like a body point (its string families included). A mechanism that
    raises `UnplaceableLocation` gives no verdict; a candidate no mechanism could place
    is `inconclusive` (`unplaceable`), never a negative. **A candidate that names its
    deciding mechanism** (`decided_by`, an arm: FR-AUD-30, for a stored case's
    observe point and a ground-truth DOM point; kept only when every row of its
    confirmation key names the same one) is placed only by that mechanism
    (`oracle._decides`: no candidate naming one is decided by a strategy without
    an `arm`); another mechanism's confirmation still confirms it, but its
    not_confirmed is no negative. It is `inconclusive` (`unplaceable`) when its
    deciding mechanism refused, gave no verdict, or did not run (reason "deciding
    mechanism <arm> did not run"); the reason is the decider's own first. A
    non-deciding mechanism's `inconclusive` verdict or `ProbeUnobserved` still makes
    the candidate inconclusive when the decider placed and did not confirm
    (conservative; that mechanism is named). No strategy catches
    `ValueError` or broader around a send (an AST guard), so a refusal is never read as
    "not vulnerable".
  - **Reporting `inconclusive`** — "could not be decided: a cost cap stopped a started
    check, or no mechanism could place the point". The pipeline writes
    `oracle_unplaceable` (the unplaceable rows) and `oracle_inconclusive_<mechanism>`
    row counts; `fuzzlab auto` prints each undecided key with its mechanism
    (`unplaceable` and the refusal's reason, or the capped mechanism and its families
    not started) and an `unplaceable:` line only when non-zero; the web run page names
    each mechanism with its count.
  - **Findings on fragment points** keep their route: `oracle.finding_url` writes them at
    `core.urls.to_route_path` (`/#/search`), so one parameter on two routes is two
    findings. Every other finding stays at `to_path`.
  - **Crawl fragment points.** In a crawl-sourced `fuzzlab auto` run, an HTTP send at
    location `fragment` is refused (`_FragmentGuard`); only DOM XSS (M6) places it, in
    the hash route's own query (`/#/search?q=<payload>`).
  - **DELETE.** Never imported (FR-AUD-22), and every probe sender refuses a DELETE at
    send unless its URL was explicitly enumerated (`check_send_url(method=)`).
  - **Login bodies.** A captured body with a password field is probed only on an
    isolated session or anonymously (its path is isolated, FR-FUZZ-44); the password
    is never a point and is sent `""`.
  - **Residuals (stated):**
    - probes complete real requests: a captured row-creating POST (feedback, basket
      item, review) creates a row per probe, and with `--fuzz-json-writes` a PUT/PATCH
      updates the row it targets, **with the run's session**, so on the operator's
      account in an authenticated run — a **disposable lab account is recommended** for
      authenticated runs;
    - a numeric or bool leaf is sent as a string, so a type-validated leaf may draw a
      400 and not confirm (a false negative; a typed variant is the stated next option);
    - operator/object payloads (NoSQL `{"$ne": …}`): sent by `NoSqlOperatorStrategy`
      since FR-FUZZ-54; every other mechanism sends strings;
    - reflected XSS is not nominated on a JSON leaf; stored XSS through a JSON body is
      confirmed only for a ground-truth case whose store point is enumerated
      (FR-FUZZ-56), not yet for a crawled one;
    - a JSON request needing a fresh token per request (a CAPTCHA answer, a CSRF
      header) does not confirm;
    - a fragment probe sends only the probed route parameter, not the route's others.
- **FR-FUZZ-48** *(the M6 browser executor on a real browser; `CC-FUZZ-0071`,
  2026-10-14, BUG-0126).* `PlaywrightBrowserExecutor` launches with the one Chromium
  launch configuration (`navguard.chromium_launch_kwargs`: the operator's
  `PLAYWRIGHT_CHROMIUM_EXECUTABLE`, scoped args). A browser or Playwright driver that
  cannot start is no verdict from the browser mechanisms (`UnplaceableLocation`); after
  `MAX_LAUNCH_FAILURES` (2) in a row it is remembered for the run: never a crash, never
  a negative; other mechanisms still decide. The sentinel is a context binding, so a
  hit is kept when the page navigates afterwards; it is the only evidence, called with
  the probe's fresh token. A dialog is dismissed and never counted (CC-FUZZ-0074,
  BUG-0129). After `load` the executor waits up
  to `SETTLE_MS` (4 s), ending on the hit, so a sink that a single-page app renders
  after its own API calls is seen; a page that closes under the wait is "not yet",
  never an error. *(CC-FUZZ-0084, BUG-0139, with its review D62:)* **The payload set**
  is six HTML payloads calling the sentinel with the probe's fresh token, ordered by
  reach:
  1. `<img src=x onerror="__fzlbHit('TOKEN')">`;
  2. the same with backticks (no single quote);
  3. `<img src=x onerror=__fzlbHit(String.fromCharCode(...))>` of the token's
     character codes: no quote, no `/`, `#` or `?`, and no whitespace in the call, so
     a path-segment sink carries it whole;
  4. – 6. an attribute break-out, `<svg onload>` and `<script>`, each with `'TOKEN'`.

  So a sink whose data path breaks on a quote (a server-side string evaluation that
  answers 500 on `'`) or on a `/` is never a guaranteed miss. The token must be
  alphanumeric (`_token` draws hex). When `MAX_NOT_OBSERVED` stops the loop, the first
  untried fully quote-free payload still gets one load (review B-S1). **Cost:** a
  negative waits the full window per payload: up to 6 loads per unconfirmed candidate,
  about 24 s (about +50% M6 time against the old 4). An unobservable page costs at most
  3 loads (2 plus the quote-free last try). On a quote-sensitive path a confirmation
  now typically comes at payload 2 or 3. A browser is launched per probe; this is
  stated,
  with one browser per candidate a possible later saving (CC-FUZZ-0073, reviewers A
  and B). Without a browser the DOM and stored XSS strategies give no verdict at **any**
  location, and an unplaceable DOM location or a stored candidate with no store URL is
  no verdict too (CC-FUZZ-0073).
  *(CC-FUZZ-0082, BUG-0136:)* the executor's guard aborts a refused navigation (out
  of scope, destructive) with ERR_ABORTED, which keeps the page; before, Chromium's
  error page replaced it. Measured on a real browser, for a page that navigates by
  script to a refused URL:
  - after `load`, with a sink firing later: now executed=True; before, executed=False
    (a false negative);
  - after `load`, with no sink: executed=False, as before;
  - a sink that fires and then navigates: executed=True, as before;
  - **during parsing or at `DOMContentLoaded` (before `load`):** the page never loads;
    with no hit it is not observed, and the candidate is inconclusive (BUG-0137,
    below). Before BUG-0136 the error page loaded and the run reported executed=False.
  - **the target's own redirect refused:** not observed, so inconclusive (BUG-0137);
    it was a raise.
  *(CC-FUZZ-0083, BUG-0137, with its review fixes D54:)* **a page the executor could
  not observe is inconclusive, never a negative and never the end of the run.**
  - **Navigation.** The plant and the observe navigation each wait for the commit
    (`wait_until="commit"`), then for `load` for at most `LOAD_WAIT_MS` (3 s,
    suppressed). A load that a refused navigation superseded is not waited out: before,
    it cost `timeout_ms` (8 s) and then a raise.
  - **Settle.** The sentinel wait lasts `SETTLE_MS` from the end of that load wait.
    Once `load` fires (recorded by `page.once("load")`), it lasts a full `SETTLE_MS`
    from `load`, capped at `timeout_ms` + `SETTLE_MS` after the commit, so a slow
    page's sink is still seen. Only a Playwright error ends the wait early.
  - **Per probe.** A Playwright error or timeout of the context set-up, the plant or
    the observe navigation raises `NotObserved` (a subclass of `UnplaceableLocation`,
    in `oracle/browser.py`). So does a page that never reached `load` by the end of the
    sentinel wait.
    - Both apply only with no hit. Pending sentinel calls are pumped before deciding,
      and hits are read again after the load check; a hit recorded at any point is
      executed=True.
    - The reason is the error's class and the first line of its text with every
      quoted string and every `scheme://` token removed, capped at 120 characters. It
      never includes a URL, which carries the payload, whatever the message's shape
      (`Navigation to "<url>" is interrupted ...`, `net::ERR_ABORTED at <url>`, a
      timeout's call log). The run's inconclusive detail (`PipelineResult.inconclusive`)
      carries it as `reason`.
  - **Per candidate.** `_BrowserXssStrategy` tries its next payload after a
    `NotObserved`, and stops after `MAX_NOT_OBSERVED` (2) in a row; that is the cost
    bound: an unobservable page costs at most 2 browser loads, each up to
    `LOAD_WAIT_MS` + `SETTLE_MS`.
    - A hit from any payload confirms.
    - No hit, with at least one payload not observed: `Verdict(False, ...,
      inconclusive=True, evidence {"not_observed": reason})`. The FR-FUZZ-45 path
      reports it inconclusive when nothing confirms, for query and fragment points
      alike, so it never enters the ML negatives.
    - Every payload observed, no hit: `None`, a negative, as before.
    - A browser that cannot start, after a payload went unobserved: still the
      inconclusive verdict, not a propagated "no verdict".
  - **What still stops at once.** A browser that cannot start, or one marked
    unavailable, is the plain `UnplaceableLocation` (BUG-0126). So are the strategies'
    placement refusals (BUG-0115).
  - **The driver's stop.** A Playwright error from stopping the driver is logged and
    contained; it never replaces a result or a no-verdict. After
    `MAX_LAUNCH_FAILURES` (2) failed stops in a row, the browser is unavailable for the
    run.
  - **Errors.** Only Playwright errors are caught (PA-0106); any other exception
    propagates. `browser.close()` failing on a dead browser is suppressed.
  - **One helper (BUG-0138).** The plant and observe navigations and the load check
    go through `navguard.navigate(..., wait_until="load", wait_ms=LOAD_WAIT_MS)` and
    `navguard.load_state_reached`, the crawl's own rule (CC-CRAWL-0030). A superseded
    load ends 300 ms after the refused navigation is reported.
  - Enforced by: `tests/test_browser_scope.py::test_the_m6_executor_uses_the_configured_chromium`,
    `tests/test_browser_scope.py::test_a_browser_that_cannot_start_is_no_verdict_never_a_crash_or_negative`,
    `tests/test_browser_scope.py::test_the_m6_executor_sees_a_sink_that_fires_after_load`,
    `tests/test_browser_scope.py::test_a_driver_that_cannot_start_is_no_verdict_too`,
    `tests/test_browser_scope.py::test_browser_xss_without_a_browser_is_no_verdict_at_any_location`,
    `tests/test_browser_scope.py::test_browser_xss_that_cannot_place_its_probe_is_no_verdict`,
    `tests/test_browser_scope.py::test_a_hit_before_the_page_navigates_is_kept`,
    `tests/test_browser_scope.py::test_an_apps_own_dialog_is_never_a_hit`
  - Enforced by (a refused navigation keeps the page; CC-FUZZ-0082, BUG-0136): `navguard.make_route_handler` (`_abort_code`) under `PlaywrightBrowserExecutor.run` — `tests/test_navigation_aborts.py::test_m6_a_sink_that_fires_before_a_refused_navigation_is_executed`, `tests/test_navigation_aborts.py::test_m6_a_refused_navigation_before_the_payload_runs_is_a_negative`, `tests/test_navigation_aborts.py::test_m6_a_sink_that_fires_after_a_refused_navigation_is_executed`, `tests/test_navigation_aborts.py::test_m6_a_target_whose_own_redirect_is_refused_is_no_verdict`
  - Enforced by (the payload set's quoting shapes; CC-FUZZ-0084, BUG-0139): `oracle.strategies._xss_exec_payloads` — `tests/test_m6_payload_quoting.py::test_the_sentinel_call_comes_in_three_quoting_shapes`, `tests/test_m6_payload_quoting.py::test_a_token_that_could_break_its_quoting_is_refused`, `tests/test_m6_payload_quoting.py::test_a_sink_behind_a_single_quoted_evaluation_is_confirmed`, `tests/test_m6_payload_quoting.py::test_each_payload_against_the_quote_sensitive_path`, `tests/test_m6_payload_quoting.py::test_an_escaped_render_is_never_confirmed`, `tests/test_m6_payload_quoting.py::test_a_json_echo_is_never_confirmed`, `tests/test_m6_payload_quoting.py::test_only_the_fully_quote_free_payload_passes_a_stricter_path`, `tests/test_m6_payload_quoting.py::test_the_quote_free_payloads_at_a_query_point`, `tests/test_m6_payload_quoting.py::test_the_quote_free_payload_is_still_tried_after_the_unobserved_stop`
  - Enforced by (a page the executor could not observe is no verdict, never the end of the run; CC-FUZZ-0083, BUG-0137): `PlaywrightBrowserExecutor.run` (`wait_until="commit"`, `LOAD_WAIT_MS`, `except PlaywrightError`) — `tests/test_m6_navigation_failures.py::test_a_before_load_navigation_is_no_verdict_well_under_the_timeout`, `tests/test_m6_navigation_failures.py::test_a_hit_after_a_before_load_navigation_counts`, `tests/test_m6_navigation_failures.py::test_a_page_that_cannot_load_never_ends_the_pipeline`, `tests/test_m6_navigation_failures.py::test_a_playwright_error_is_no_verdict_and_names_no_url`, `tests/test_m6_navigation_failures.py::test_any_other_error_is_not_swallowed`
  - Enforced by (per payload, inconclusive, the driver's stop, a slow page's settle; BUG-0137 review D54): `_BrowserXssStrategy.confirm` (`NotObserved`, `MAX_NOT_OBSERVED`), `PlaywrightBrowserExecutor._stop_driver` / `_wait_for_token` — `tests/test_m6_navigation_failures.py::test_a_later_payload_is_tried_after_an_unobserved_one`, `tests/test_m6_navigation_failures.py::test_two_unobserved_payloads_in_a_row_stop_and_are_inconclusive`, `tests/test_m6_navigation_failures.py::test_a_partly_observed_candidate_without_a_hit_is_inconclusive`, `tests/test_m6_navigation_failures.py::test_every_payload_observed_without_a_hit_is_a_plain_negative`, `tests/test_m6_navigation_failures.py::test_a_browser_that_cannot_start_stops_at_once`, `tests/test_m6_navigation_failures.py::test_a_failed_driver_stop_keeps_the_result`, `tests/test_m6_navigation_failures.py::test_a_driver_that_never_stops_cleanly_makes_the_browser_unavailable`, `tests/test_m6_navigation_failures.py::test_a_sink_that_fires_after_a_slow_load_is_seen`
  - Enforced by (the reason carries no URL; a late launch failure; M6's inconclusive in the oracle's order; review of 1702c29): `browserexec._failure_reason`, `_BrowserXssStrategy.confirm`, `pipeline._confirm` — `tests/test_m6_navigation_failures.py::test_the_reason_never_carries_a_url_or_the_payload`, `tests/test_m6_navigation_failures.py::test_a_launch_failure_after_an_unobserved_payload_is_still_inconclusive`, `tests/test_m6_navigation_failures.py::test_an_m6_inconclusive_first_never_hides_a_later_confirmation`, `tests/test_m6_navigation_failures.py::test_the_first_inconclusive_is_kept_before_an_m6_one`
- **FR-FUZZ-49** *(post/redirect/get observation; `CC-FUZZ-0078`, 2026-10-14).* A
  server-side confirmer whose signal is on the page a POST redirects to (Juice Shop:
  `POST /profile username=#{11*13}` → `302 /profile` without `143`; `GET /profile`
  shows `143`) observes that page.
  - **Opt-in, per strategy run (P1).** `ConfirmationStrategy.prg` marks the strategies
    that read the observed page: `SstiStrategy`, `GoTemplateSstiStrategy` (M4),
    `SpelInjectionStrategy`, `ReflectedXssStrategy` (M5), `SqliErrorStrategy` (M2),
    `PathTraversalStrategy` and `PathTraversalFsPathReadStrategy` (the passwd marker).
    For each such strategy's run `Oracle.confirm_outcome` wraps the sender in
    `oracle._PrgRun`, which sets the `Sender` property `prg=True` on **every** send of
    the run (probes, controls, baselines, second samples), only when the sender says
    it can (`probe.accepts_prg`: `prg_capable`, delegated by every wrapper). Never
    opted in (P7): `SqliTimingStrategy`, `SqliBooleanStrategy`, the differential
    engines, `OpenRedirectStrategy`, header injection, timing; a timing send never
    follows, whatever it asks.
  - **Trigger (P2).** A 301/302/303 after any method, or a 307/308 after a GET only (a
    307/308 re-sends a POST body: not followed, no observation). One hop: a follow-up
    answered with a redirect (or a timeout) is no observation.
  - **The follow-up (P3)** is the sender's own plain GET of the `Location` (resolved
    against the probe's own URL, never the placed one: FR-FUZZ-64, FR-FUZZ-69;
    fragment dropped; no payload, no siblings, no
    `_FormBoundSender` binding) through every gate: the probed URL's own origin
    (`canonical_origin`), `check_send_url`, `transaction_reason`,
    `account_endpoint_reason`, not a login page (`redirect_is_logout`: normal 3xx
    handling applies), not an auth endpoint, not an isolated path from the run's
    session, not once the header breaker stopped a header probe's run
    (`probesender.prg_target`, the one rule; `SeamProbeSender._prg_session_gate`). It
    goes on the probe's own route: the run's session, the path's isolated copy (a copy
    that cannot re-log in gives no observation), or anonymous; through the client
    (scope, `RequestBudget`, session `observe`) and the header breaker as part of its
    probe. The emulated redirect rules are listed with their Fetch / RFC 9110 steps in
    `probesender.PRG_RULES`, each with a fixture (PA-0111).
  - **Representation (P4).** The raw 3xx stays the probe (`status`, `headers`,
    `text`); the follow-up is a separate whole `Probe` in `probe.followed` (with its
    `url`); `probe.prg` says `observed`, `unobserved` or `skipped: <reason>`. Opt-in
    strategies judge `strategies._observed(probe)` (= `probe.followed or probe`)
    whole: `_renders_as_html`, signatures and markers from one response. Open
    redirect (`_lands_on`), header injection and timing read the raw probe.
  - **Attribution (P5).** Each follow-up is read right after its own send. M4/SpEL:
    when response 2 is a follow-up, product (canary) 1 must be absent from it. M2 and
    the passwd markers: a signature seen only through a follow-up needs every control
    observed through its own follow-up without it; a control the app rejected (no
    follow-up) is a refusal.
  - **Classification (P6).** A reflection confirmed only through a follow-up is
    recorded `xss-stored` (evidence `observation: "prg"`) when the follow-up's URL
    carries neither the payload nor its token in any reflected form (raw, percent,
    form `+`, HTML-entity, JSON-escaped; `strategies._rode_the_redirect`); when it does,
    the payload rode the redirect and it is `xss-reflected` with `observation:
    "prg-redirect"` (coordinator's refinement); an M2 confirmation only
    through a follow-up carries `observation: "prg"`, `second_order: true`; other
    strategies add `observation: "prg"`.
  - **Cost (P8).** A follow-up is one more request of its probe
    (`Probe.follow_up_sends`): counted by `_CountingSender` (the run's `requests`) and
    `_CostCounter` (the bandit's cost), spent from the client's `RequestBudget`. The
    pipeline reports `prg_follow_ups` (after a POST-family probe), `prg_follow_ups_get`,
    `prg_unobserved`, `prg_restores` and `prg_restore_failed` when non-zero; `fuzzlab auto` prints them on
    one line only then. A run with no PRG redirect keeps its metrics (the
    `score_only` golden summary is byte-identical with a PRG-capable sender).
  - **Stored state (P9).** After a candidate's run that made a follow-up after a
    POST-family probe, one benign send of the form's own default for the field (or the
    importer's text filler) at the point, without PRG (counted `prg_restores`; not for
    a raw whole body or a header point). The restore is total: the verdict is decided
    first, and a restore send that raises is contained, counted `prg_restore_failed`
    and logged with the host and the error's class only (an interrupt propagates).
  - **Residuals (stated):** the last payload (or the restore value) stays in the lab
    account; a payload that breaks the page makes later checks of that page false
    negatives; history pages hold earlier tokens (fresh tokens and P5 reject them, at
    the cost of a false negative); a 307/308 after a POST is never observed; an
    anonymous follow-up carries no cookie the 3xx set, so an anonymous flow keeping
    the value in a session the POST just created is not observed;
    `SqliEvaluationMarkerStrategy` is not opted in (not in the agreed list); the restore
    is itself a submission, so it adds one more write per candidate whose run made a
    POST-family follow-up; its value is the crawl-time form default, which may be a
    stale earlier value if the crawl saw an already-mutated page (a cost in
    cleanliness, not safety).
  - Enforced by: `tests/test_prg_observation.py::test_prg_ssti_confirms_only_through_the_follow_up`,
    `tests/test_prg_observation.py::test_every_send_of_a_prg_run_asks_for_the_follow_up`,
    `tests/test_prg_observation.py::test_a_reflection_confirmed_only_through_the_follow_up_is_stored_xss`,
    `tests/test_prg_observation.py::test_a_payload_that_rode_the_redirect_is_reflected_xss`,
    `tests/test_prg_observation.py::test_a_restore_that_raises_never_changes_the_outcome`,
    `tests/test_prg_observation.py::test_a_json_follow_up_echoing_the_payload_never_confirms_m5`,
    `tests/test_prg_observation.py::test_a_rejected_control_refuses_m2`,
    `tests/test_prg_observation.py::test_a_history_page_still_showing_product_1_is_no_attribution`,
    `tests/test_prg_observation.py::test_a_stored_quote_from_an_earlier_strategy_never_confirms_m4_m5_m2`,
    `tests/test_prg_observation.py::test_payload_independent_follow_ups_never_confirm_an_opt_in_strategy`,
    `tests/test_prg_observation.py::test_golden_impact_is_zero_with_prg_enabled`,
    `tests/test_sender_conformance.py::test_every_wrapper_forwards_every_protocol_argument`,
    `tests/test_sender_conformance.py::test_every_wrapper_reports_its_inner_senders_prg_capability`,
    `tests/test_sender_conformance.py::test_every_sender_that_declares_prg_makes_the_follow_up`,
    `tests/test_prg_observation.py::test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms`
    (FR-FUZZ-69)
- **FR-FUZZ-50** *(a probe with no response; `CC-FUZZ-0088`, 2026-10-15, BUG-0147;
  edited in place by `CC-FUZZ-0109`, BUG-0536).* A probe whose connection is reset or
  aborted, or whose body is cut off or undecodable, or whose body the bounded reader
  stopped (`core.bodyread.BodyIncomplete`: over a ceiling, past its deadline, a coding
  it cannot bound; FR-CORE-536), is "not observed" (`oracle.probe.ProbeUnobserved`),
  classified only by `tools/probesender._unobserved`. Both senders' sessions read
  bounded, so no `Probe` carries a short body. A stopped body is never re-sent and never
  a timeout stand-in: a body that kept arriving proves no delay.
  - A refused, DNS, TLS or proxy failure is not: it fails loudly.
  - A timeout keeps its rule: a status-0 probe of the full timeout in
    `RequestsProbeSender`, the body's read included; it raises in `SeamProbeSender`.
  - `RequestsProbeSender` re-sends an idempotent (GET/HEAD/OPTIONS) probe once when
    its connection failed with no response (never a cut-off or undecodable body), and
    the re-send is counted in the run's requests and the mechanism's cost.
  - An isolated copy whose login gets no response is a failed copy login.
  - The oracle makes it no verdict from that mechanism: the others still run; the
    candidate is inconclusive (`unobserved`, with its reason in the run's detail)
    unless one confirms; and the run continues.
  - A PRG follow-up with no response is `unobserved` on its probe, which keeps its own
    response.
  - Out-of-band mechanisms still wait for their callback.
  - A stopped listener is no verdict.
  - A baseline probe with no response leaves the target row unprobed.
  - *(Note, CC-FUZZ-0105, FR-FUZZ-63.)* The same branch takes `NotComparable` (a
    `ProbeUnobserved`): a response that is not the application's own answer ends the
    mechanism with no verdict, the inconclusive mechanism `not-comparable`. A timeout's
    status-0 stand-in is an observation only on a timing send and only as a **read**
    timeout (`Probe.timeout == "read"`); a connect timeout, or a stand-in whose kind its
    sender did not say, is not comparable.

  Enforced by `tests/test_probe_unobserved.py`.

- **FR-FUZZ-400** *(training and benchmark group; `CC-FUZZ-0400`, 2026-10-15).*
  `fuzzlab train <sub>` holds the training/benchmark runs (`docs/CLI_WORKING_VS_TRAINING_DESIGN.md`).
  - **`train run <url>`** is the `auto` engine with every one of its flags.
    - The target is the first argument, or `--base-url`; exactly one of them.
    - `--store` is optional (FR-CORE-400).
    - It refuses (exit 2, before anything is created) a run with no training or
      benchmark choice **that takes effect**, detected by presence on the command line
      (`training_choices`):
      - `--ground-truth`, `--points ground-truth`, `--mode manual`, `--holdout`,
        `--hybrid`;
      - `--score`/`--rank`, unless `--train-on saved`;
      - `--calibrate` other than `none`;
      - `--rank-objective` other than `pointwise`;
      - with `--confirm-budget`: `--budget-seed`, or a non-`score` `--budget-method`.

      `--train-on` alone and the working defaults never count (review A1).
    - The checks run in this order: an empty `--store` or empty target; then D-9; then
      `--dry-run`; then `--authorized`.
    - It refuses a run without `--authorized`.
    - The user's argv is forwarded to the engine verbatim, except that the resolved store
      goes last (BUG-0401). No usage error leaves a store file or a run row.
    - It prints the store, and for `--holdout` a store-qualified `train reveal-holdout`
      hint.
  - **`train models`** lists saved models (FR-ML-400).
  - **`train reveal-holdout`, `train flow-anomaly`, `train mutate`** are the commands
    formerly named `reveal-holdout`, `flow-anomaly` and `mutate-run`. The old names
    still work, with a one-line stderr note.
  - `reveal-holdout` and `flow-anomaly` take an optional `--store` and refuse a missing
    one. The reveal names its store before the reveal is counted, and the header names
    the run.
- **FR-FUZZ-401** *(command taxonomy; `CC-FUZZ-0400`, 2026-10-15).* `fuzzlab/cli_taxonomy.py`
  classifies every command into a group (working, lab-only / training and benchmark /
  lab / other). It classifies every flag of every command's parser:
  - **B:** both.
  - **T:** training. Ground truth, `--mode`, `--points`, training data, fit choices,
    modulators, holdouts, experiment seeds.
  - **W\*:** narrowed in working runs. `--score`/`--rank` apply a saved model there,
    and `--budget-method` is `score` only.
  - **L:** needs our instrumented lab.

  `copy_parser` copies actions, never re-types them. It refuses (`CopyError`) any
  source shape it cannot carry faithfully: mutually exclusive groups, `set_defaults`,
  `argument_default`, `allow_abbrev=False`, other prefix characters, fromfile prefixes,
  subcommands, or a restricted non-single-value option. A discovered round trip over
  every action of every parser proves each copy parses exactly like its source
  (PA-0400). A working namespace is completed by `working_namespace`: `--train-on` is
  `saved` when `--score`/`--rank` is given (a working run applies a saved model) and the
  engine's own `run` otherwise, so every working namespace passes the engine's rules. A working command built with `working_parser` refuses every T
  and L flag by name
  (exit 2, the value consumed, naming `fuzzlab train run`; ground truth "is never part
  of a working run"). It restricts W\* values. The classification guard fails on an
  unclassified, stale or arrived-pending dest.
  *Phase 2 (gated on BUG-0138):* `fuzzlab scan <url>`. It crawls into a private temp
  directory, then runs the engine in automatic mode (so D15 stays in `resolve_run`) with
  the default store. It requires `--authorized` before the crawl.

- **FR-FUZZ-51 (the execution contract, `CC-FUZZ-0089`, 2026-10-17, D70)** A YAML or JSON
  document (`contract_version: "1.0"`, `fuzzlab.disco.contract`) names the run (id, target
  `base_url`, `scope_allowlist` of URLs or `host:port`, limits `rps` / `timeout_ms` /
  `max_body_bytes`, an optional `reset_hook`), the auth profiles (`none`, `bearer`,
  `basic`, `cookie`, `header`: a `keyring:<identity>` or `env:<NAME>` ref, never the
  secret, D12; `storage_state`: a file), the endpoints (from a disco inventory: method,
  path template, origin, content type, path parameters with their dependency source,
  request and response schemas, the browser's static headers, auth, provenance), the
  test cases (class, rationale, auth profile, setup steps with `extract` JSONPaths, the
  request with `{{variables}}`, `raw_body` for syntax cases, the oracle's
  `expect_status_class` and `findings_if` rules: `status_class`, `status_in`,
  `body_matches`, `latency_ms_gt`, `response_schema_drift`, `state_check`; `safety`),
  and `results`. `load_contract` is the one reader: the schema, then every reference,
  variable, scope and secret check, each failure a typed `ContractError` before anything
  is sent.
- **FR-FUZZ-52 (the contract runner, `CC-FUZZ-0089`, 2026-10-17, D70; edited in place by
  `CC-FUZZ-0105`, 2026-10-20, BUG-0528, BUG-0529)** `fuzzlab disco run --authorized`
  executes a contract (`fuzzlab.disco.runner.Runner`):
  - per case, in order: setup steps in order (a failing step is an `error`, not a
    finding), variables extracted by JSONPath, then the request;
  - a case's query values are placed by SP-42's standalone rule
    (`core.urls.place_query_param`, FR-FUZZ-64): a name the endpoint's own query has is
    set in place, a new one appended, encoded as before (CC-FUZZ-0105, BUG-0531's
    sweep);
  - every send is gated at the send: scope on the final URL; `check_send_url` (SP-09);
    no redirect followed; the body read up to `max_body_bytes` (on the wire and
    decoded) within `timeout_ms`, checked at every receive, by the one bounded reader
    (`core.bodyread.read_body`, FR-CORE-536; BUG-0536, which closes BUG-0528's
    residual R6); its session is `bodyread.watched`, so the watchdog also cuts a
    dripped status line or header at `timeout_ms` (a `deadline` timeout), and it
    advertises only codings the reader can bound (`bodyread.advertise`); sends spaced
    to `rps`. A case marked destructive is `skipped` unless
    `--allow-destructive` (then its own URL is the explicit allowance); a `reset_hook`
    runs around it only with `--allow-reset-hook`, through `procutil.run_bounded`;
  - credentials go only to the base URL's origin; evidence is redacted
    (`core.redaction`);
  - **Completeness** *(replaces "a send with no complete response is an `error` …",
    CC-FUZZ-0105).* An exchange is complete when its status line, its headers and its
    whole body arrived within `timeout_ms` and `max_body_bytes` (`Exchange.incomplete`).
    An incomplete one -- no response, a timeout before or after the headers, a body cut
    off, a body over the cap, a cut 5xx included -- is never a pass, a baseline, a match
    on what was read, a setup success or a satisfied state check: it is an `error`
    "incomplete response: <why>" for that case and the run goes on (SP-34 classifies the
    exceptions). Its one finding: a **read** timeout, or the runner's own deadline
    passing while the answer was read, under a `latency_ms_gt` rule whose bound is at
    most `timeout_ms`; a **connect** timeout never proves latency. The response is
    closed on every exit. An incomplete body is never written to evidence (`"body":
    "omitted (incomplete)"`, `body_bytes`, `incomplete`). An unreachable target stops
    the run with the results so far written.
  - **Every complete answer is classified once** (SP-56, FR-CORE-507) with FR-SESS-22's
    facts: the request is credentialed when the profile's credential is in its final
    headers (a case's own replacing header, a forged or empty token, is not the
    profile's); its own names are the query keys and the JSON body's keys.
    - **Throttle or unavailable** (429, 503) is judged only where `status_in` names its
      status.
    - **Auth failure** of a credentialed request (a 401, a 407, a redirect to a login
      page; not a credential submission's own refusal) is an `error` "credentials not
      accepted (…)" unless `status_in` names its status. Without the credential, a 401
      or a login redirect is the endpoint's own answer.
    - **Policy block** (403, 451) is judged where `expect_status_class` holds `4xx` or
      `status_in` names its status (any case type).
    - **Gateway** (502, 504) is judged under the 5xx rule.
    - Otherwise each is an `error`; none is matched merely by being outside the
      expected class.
  - the oracle: the case's rules plus a 5xx and `LEAK_PATTERNS` (stack traces, database
    errors) that the endpoint's baseline did not show; an answer outside
    `expect_status_class` is matched. **The baseline** is the endpoint's first complete
    application answer below 400 that passed (CC-FUZZ-0105).
  - **Contract patterns run bounded** *(CC-CRAWL-0054, BUG-0536, audit defect 27).*
    - A case's `body_matches` are matched on its answer and its baseline in one worker
      process (`runner.search_bounded`: `python -I -S` through `procutil.run_bounded`),
      killed with its tree after `MATCH_SECONDS` (5 s).
    - When they could not be evaluated (the time limit, no worker, an answer of
      another shape), the case is an `error` "body_matches not evaluated within 5 s
      (inconclusive)" unless other evidence matched. It is never a no-match.
    - No contract pattern is matched in the runner's process; the reviewed
      `LEAK_PATTERNS` are.
    - Enforced by: `tests/test_bounded_reads.py`
      (`test_a_catastrophic_pattern_is_an_error_never_a_hang_nor_a_no_match`,
      `test_body_matches_still_match_and_miss_through_the_worker`,
      `test_the_matcher_never_runs_a_contract_pattern_in_the_runners_process`,
      `test_the_worker_payload_is_json_and_its_answer_is_shape_checked`,
      `test_the_contract_runner_cuts_a_dripped_body_at_its_deadline`).
  - **Setup steps** *(CC-FUZZ-0105)* must be complete application answers below 400 and
    not a redirect to a login page (a failed login), except a step whose path creates
    or resets an account (`account_submission`): its redirect to the login page is its
    success.
  - **State checks** *(CC-FUZZ-0105)* are satisfied, violated or **unobserved**, each
    unobserved one with its reason: not prepared; refused at the send; incomplete; not a
    complete application 2xx; not JSON; not evaluable. A pass needs every state check
    satisfied. An unobserved one is an `error` "state check N not observed: <why>" (N
    counts the case's state checks), or, beside a finding, is listed in the result's
    `unobserved` (`{"check": N, "reason": …}`).
  - the ledger: one JSON line per case as it completes (`test_case`, `endpoint`,
    `class`, `status`, `latency_ms`, `verdict` pass/finding/error/skipped, `matched`,
    `reason`, `evidence` refs; `response_class` and `unobserved`, CC-FUZZ-0105); the
    verdict counts are printed.
  - Enforced by: `tests/test_disco_runner_outcomes.py` (58 tests: every rule above,
    with its pins), `tests/test_disco_contract.py`.
- **FR-FUZZ-53 (a disco run as auto's input, `CC-FUZZ-0090`, 2026-10-18, D70)**
  `fuzzlab auto --disco-run DIR` (repeatable) consolidates each `fuzzlab disco capture`
  run directory into the run's store as crawl points (`store_adapter.import_disco`,
  FR-AUD-23), with or without `--spider-db`; the import counts add to the crawl's in
  the summary. A directory with no `capture.jsonl` is a usage error before the store
  is opened. `--fuzz-json-writes` applies to it as to a spider DB. Header points
  (`--header-points`) still count the spider DB's pages only.
- **FR-FUZZ-54 (NoSQL operator injection, `CC-FUZZ-0092`, 2026-10-19)** A class
  `nosqli` (category `nosql-injection`, sink context `nosql`; rule `R-NOSQLI-JSON`,
  JSON-leaf points) confirmed by `NoSqlOperatorStrategy` (`operator-differential`): the
  point's whole JSON body (`core.jsonbody.body_with`, typed values) with every string
  leaf a fresh literal (B), the target leaf `{"$in": []}` (V, matches nothing) or
  `{"$ne": <random>}` (D, matches anything), the other string leaves `{"$ne": ...}` in V
  and D so the target leaf alone decides; confirmed when V answers like B and D does
  not, over the shared engine's replicated, randomly ordered rounds. A server that
  rejects or stringifies objects answers V and D alike: no verdict. Only a JSON-leaf
  point with its body carries the probe. A ground-truth point may carry `json_body`
  (the body its endpoint takes; `param` one of its leaves): `auto` then audits it as a
  JSON-leaf point with those siblings.
- **FR-FUZZ-55 (cross-account access control, `CC-FUZZ-0093`, 2026-10-19)**
  `fuzzlab auto --identity A --peer-identity B` (both accounts stored; checked before
  the store opens: another account, both usernames present, neither contains the other)
  adds `CrossAccountReplayStrategy` (`access_control`, `cross-account-replay`, before
  the single-session `AccessControlIdorStrategy`): for a GET query point with the value
  the crawl saw A use, A's response must be *A's view* (200, A's username, not B's) and
  the same request with another value must not be; B's replay, then the
  unauthenticated control's, getting A's view twice confirms (evidence: who and the
  statuses, no data). Without `--peer-identity` it no-ops. Known false positive: a
  shared resource that names its owner. Scoped by `R-ACCESS-CONTROL`.
- **FR-FUZZ-56 (PUT and PATCH in a ground truth, `CC-FUZZ-0095`, 2026-10-19)** A
  ground-truth case or point may be `PUT` or `PATCH` (the schemas' method enum; never
  `DELETE`, which stays refused at every send, FR-FUZZ-47). `points_from_ground_truth`
  probes such a point like a POST one (a `json_body` point as a JSON leaf) **only with
  `fuzzlab auto --fuzz-json-writes`**, the opt-in crawled PUT/PATCH requests already
  need (each probe updates what the request targets); without it the point is skipped
  with `"<METHOD> probed only with --fuzz-json-writes"`. The methods the opt-in gates
  are one set, `store_adapter.WRITE_METHODS` (SP-41). A DOM point (client-only,
  fragment, `rendering: js`) is a GET page: one with another method is skipped, never
  rewritten into a GET (BUG-0115).
  - **Stored XSS through the app's own store request.** A stored case's store request
    is the ground truth's point at its `source_url` with the case's param: its method,
    and for a `json_body` point a JSON body carrying the other leaves (`InjectionPoint`
    / `Candidate` `store_method`, `store_location="json"`, `store_entries`; the auditor's
    evidence carries them). A PUT/PATCH store needs `--fuzz-json-writes` as above. With
    no such point, the store request stays a form POST. The M6 executor plants with
    `context.request.fetch` at that method (a JSON body built by `jsonbody.body_for`),
    scope-checked and never redirected; it refuses before any browser starts a store
    method outside POST/PUT/PATCH, a non-GET query store, a store in a header, cookie,
    path or fragment, or a JSON leaf the body lacks -- raised as no verdict
    (`UnplaceableLocation`, BUG-0523), so the stored case is `inconclusive`.
    Checked on a real browser: a chat that accepts only a JSON PUT is confirmed, and the
    old form POST to it gives no verdict.
- **FR-FUZZ-57 (path-segment parameters, `CC-FUZZ-0096`, 2026-10-19)** A ground-truth
  point or case at `location: "path"` names its parameter as one whole segment of its
  URL template (`/ticket/{id}`; refused at load otherwise). `auto` keeps the template as
  the point's URL, so findings and scoring use the template path; every probe sender
  places the value with `core.urls.place_path_param` (the segment replaced,
  percent-encoded as one segment; the send-time safety check judges the template, never
  the payload) or refuses (`UnplaceableLocation`), never relocating it to the query
  (BUG-0115); greybox and the M6 executor refuse a path point. `R-ACCESS-CONTROL-PATH`
  draws the access-control strategies onto a GET path segment with an id-shaped name
  (`id`, `uuid`, `guid`, `*_id`, `*Id`); `CrossAccountReplayStrategy` takes path
  points as query points. *(CC-FUZZ-0097:)* a crawl gives path points too (FR-AUD-26);
  `injection_points_from_store` builds them at the base origin plus the template path,
  carrying the crawled value as their entry when it was kept.
- **FR-FUZZ-58 (runs that log no account in, `CC-FUZZ-0096`, 2026-10-19)** `fuzzlab auto
  --no-login` (needs `--identity`): `--identity` and `--peer-identity` only name the
  accounts whose stored usernames (the cross-account markers) and account values
  (FR-LAB-309) the run uses; every probe is sent without a session, and
  `CrossAccountReplayStrategy` makes only its unauthenticated replay (its evidence says
  `anonymous`). For an app whose login fuzzlab cannot perform and whose objects need
  none. Without it, a login that fails stops the run. (secDevLabs ecommerce-api, which
  first needed it, logs in since FR-SESS-21.)
- **FR-FUZZ-59 (crawl points at their own origin, `CC-FUZZ-0098`, 2026-10-19)**
  `injection_points_from_store`, the login-form isolation keys and the header points
  read each stored page or endpoint with `core.urls.stored_absolute` (FR-AUD-27): a
  path under the run's origin, an absolute row at its own origin. A row on another
  origin that is not loopback (`is_loopback_origin`) is never probed: skipped with
  "another origin, not loopback (D11)". The run's session goes only to its own origins
  (FR-SESS-20), so such probes go without it unless `--auth-origin` names the origin.

- **FR-FUZZ-60 (the pipeline's trace, `CC-FUZZ-0099`, 2026-10-19)** `run_auto` (with
  `trace_events=True`, the default; `fuzzlab auto --no-trace` turns it off) records into
  the active `core.trace` recorder, or one it opens:
  - `run.start` (the run's origins, the identity by name) and `run.end` (`complete`
    or `aborted: <error class>`), in a `finally`.
  - Every send, through `harness.tracing.TracingSender` directly around each real
    sender the run hands a strategy: its own sender and, for the cross-account check
    (FR-FUZZ-55), the peer account's (identity: its name) and the unauthenticated one
    (`anonymous`) (BUG-0513). One `exchange` event with its test, strategy and role (from the execution
    context), the point's method, redacted URL, parameter name and location, the
    value's digest and length and a 64-character preview (none for a sensitive
    parameter), and the outcome -- `response` with status, time and redirect target
    (`redirect`; `location` stays where the value was injected, BUG-0517);
    `timeout`; `unobserved` (no response, BUG-0147); `not_sent` (refused before
    sending); `error` with its class. A PRG follow-up the sender sent is its own
    exchange (`follow-up`, `parent` = the probe), observed or not (BUG-0510). Each
    earlier try of an exchange is its own `retry` event (FR-FUZZ-61); before
    CC-FUZZ-0100 a re-send was only counted (`resent`). The M6 browser's requests are
    made by the Playwright driver and Chromium, never through a sender: they are
    recorded per visit as `browser.step` (FR-FUZZ-62, BUG-0520), not as `exchange`.
  - Each confirmation key is a test (`t1`, `t2`, ... in the pipeline's order):
    `test.start` (the point, category, rule, candidate ids) and `test.end` (`confirmed`,
    `inconclusive`, `not_confirmed`, `stopped`, or `error` when it raised).
  - Each strategy run in `Oracle._confirm_outcome` is a `strategy_scope`: its sends are
    collected, and `test.strategy` records its outcome (`confirmed`, `not_confirmed`,
    `inconclusive`, `unobserved`, `unplaceable`) with exactly those exchange keys, and
    `decides` (BUG-0523): whether the run decides its candidate (`oracle._decides`,
    FR-FUZZ-47); true on a confirmation, which counts whoever made it.
  - `finding` (written by `_write_finding`, keyed `finding:<id>`) cites its test, its
    strategy and exactly the exchanges of that strategy run, and (FR-FUZZ-62) its
    browser and out-of-band steps (`steps`), as `test.strategy` does.
  - Roles are set only where the code knows them: `baseline` (the pipeline's
    fingerprint send, a differential's B0/B, a timing check's samples), `control` (a
    differential's V, the SQL error check's controls), `mutation` (a differential's D,
    timing delays, the SQL error check's payloads), `restore` (a PRG restore),
    `follow-up`, `retry` (FR-FUZZ-61); every other send is `probe`.

- **FR-FUZZ-61 (each HTTP try is its own evidence, `CC-FUZZ-0100`, 2026-10-19)**
  - **Recorded where the try happens.** A probe sender records every try it actually
    made, at its try loop, as `oracle.probe.attempt_record` dicts: `n` (1-based),
    `outcome` (`response`, `timeout`, `unobserved`, `error`), `status` (a response
    only), `elapsed_ms` and `error` (an exception class name). There is never a URL,
    header or body.
  - **Where the tries travel.** On the outcome: `Probe.attempts`,
    `ProbeUnobserved.attempts`, or `note_attempts` on an exception re-raised unchanged
    (`attempts_of` reads them).
  - **What counts as a try.** A try that failed before the request left the client is
    none: an invalid header value, or for the seam an error in the session's `prepare`
    (a login on the way).
  - **Per sender.**
    - `RequestsProbeSender`: both tries of a GET/HEAD/OPTIONS re-sent after a reset,
      and the final one.
    - `SeamProbeSender`: never re-sends, so at most one try per dispatch.
    - A sender that records none (a test double) leaves the list empty.
  - **The follow-up that was sent.** `Probe.prg_sent` is the PRG follow-up the sender
    sent, observed or not: `url`, `outcome`, `status`, `elapsed_ms`, `error` and its
    own `attempts`.
  - **What the trace writes.** `TracingSender` writes each earlier try of an exchange
    (the probe or its follow-up) as an `exchange` event with role `retry`. Its
    `parent` is that exchange's key, and it has `attempt` and its own outcome, status
    and time. It is written before the exchange, in the same scope, and joins the
    strategy run's cited exchanges.
  - **The exchange itself** keeps its final outcome, and gains `attempts` (the count)
    and `resent` = `attempts - 1`.
  - **Unchanged:** what is sent and how often, `Probe.resent`, `followed`, `prg`, the
    run's `requests` and every verdict.

- **FR-FUZZ-62 (the browser and out-of-band confirmations' own steps, `CC-FUZZ-0102`,
  2026-10-19; BUG-0520)**
  - **Recorded where each step happens, correlated explicitly.** With an active
    recorder, the M6 executor (`tools/browserexec.PlaywrightBrowserExecutor`) and the M8
    wait (`oracle/strategies._await_callback`) record the steps they perform.
    - Each step carries the test and strategy from `trace.current()`, read on the
      strategy's own thread or greenlet.
    - Its key joins the strategy run's `steps` (`trace.emit_step`), which
      `test.strategy` and `finding` cite.
    - `t` is the stamp the step took: Python's receipt of the driver's event for a
      browser callback, or `OobHit.received_at` for a callback to the listener. Two
      stamps less than 100 ms apart are not ordered.
    - Playwright callbacks only note. A visit's events are emitted once, after the
      browser is closed and the driver stopped, and are contained: they never replace
      the visit's result.
    - Without a recorder, no listener, callback or stamp is added.
  - **`browser.step`** (M6): one visit is one `run` call. Every step carries `test`,
    `strategy`, `visit`, `step` and `outcome`.

    | `step` | other keys | `outcome` |
    | --- | --- | --- |
    | `launch` (failed only) | `error` (a class) | `failed` |
    | `store` | `method`, `url`, `origin`, `param`, `location` (`body`/`json`: an API request; `query`: a browser navigation), `value_sha`, `value_len`, `value_preview`, `status`, `elapsed_ms`, `error`, `detail` (a refusal) | `response`, `no_status`, `not_sent`, `timeout`, `error` |
    | `navigate` (the observe navigation) | the same keys, `location` `query`/`fragment`, `value_sent` (false for a fragment); `elapsed_ms` includes the bounded load wait | as `store` |
    | `refused` (the visit's first refused request, HTTP or WebSocket) | `url`, `origin`, `detail` (the rule's word, or `out of scope`) | `not_sent` |
    | `load` | `after_commit_ms`, or `superseded` | `fired`, `not_fired` |
    | `sentinel` | `after_load_ms` (null when there was no `load`) | `fired` |
    | `page` | `answered`, `failed`, `refused` | `counted` |
    | `end` | `detail`; `window_ms`, `waited_ms` when the sentinel wait ran | `executed`, `not_executed`, `not_observed`, `unplaceable`, `error` |

    - A placement refusal ends `unplaceable` at the refusal, never from the returned
      observation.
    - A raise is checked for `NotObserved` before `UnplaceableLocation`.
    - A launch failure's `detail` is "browser unavailable (<class>)", and
      `_unavailable`'s is "browser unavailable for this run"; never the exception's
      text.
    - URLs go through `trace.safe_ref`. Values are digested and previewed as in an
      `exchange` (no preview for a sensitive parameter).
  - **What `page` counts:**
    - `answered`: the page's `response` events (what the guard fulfilled, its redirect
      to a checked landing included; what Chromium fetched itself, such as the landing
      re-request; the observe document, and a query store's document);
    - `failed`: its `requestfailed` events, less one per guard refusal of the same URL.
      A failed request may have reached the server;
    - `refused`: every guard refusal, route and WebSocket. Never sent.
  - **The send equation** (enforced, PA-0520). Per visit, the server received:

    > the API `store` steps not `not_sent` + `answered` + `failed` + the redirect hops
    > the guard fetched itself

    The last term is unseen for every request type; it is the documented gap.
  - **`oob.wait`** (M8): one per out-of-band wait. It carries `test`, `strategy`,
    `url` (the canary, through `safe_ref`), `window_ms`, `waited_ms`, `outcome`
    (`received` or `none`), `after_wait_ms` (null when the hit records no time; negative
    when the callback came during the send) and `remote`.
    - `t` is `received_at`, or the end of the wait.
    - The planting send is the strategy run's `exchange` before it, in the recorder's
      order.
  - **Drawn** (in the test's and the finding's sequences, `report.diagram`; FR-UI-511).
    A step that did not happen (no `load`, no hit, a refusal, no callback, not sent,
    not observed) is a note or a lost arrow, never a reply or "executed".
  - **Counted.** *Executed* also counts a test's `store` and `navigate` steps that are
    not `not_sent`. In the testing overlay they are the M6 browser's own flow
    (`trace.M6_BROWSER`), apart from the tool's exchanges.
  - **Not traced:**
    - each page request one by one;
    - the guard's own redirect-hop fetches;
    - in-scope WebSockets;
    - popups' requests;
    - Chromium's background traffic;
    - a callback after its window;
    - the in-band marker checks' callbacks;
    - `FakeBrowserExecutor`.
  - **Unchanged (tested):** what is sent, every `ExecObservation`, verdict, finding,
    candidate status and request count, and the listener's hits. The windows are
    unchanged by construction.
- **FR-FUZZ-63 (a control counts only when it is the application's answer,
  `CC-FUZZ-0105`, 2026-10-20, BUG-0529)**
  - **Every response a mechanism reads is an observation** (layer 1,
    `oracle.probe.require_observed`, applied by the oracle's `_ObservedOnly` to every
    strategy run, the correlated send included): a throttled or unavailable answer (the
    probe or its PRG follow-up), a non-timing send's incomplete answer (a sender's
    status-0 stand-in), or a timing send's stand-in that is not a **read** timeout ends
    the mechanism with `NotComparable`.
  - **A payload whose PRG follow-up got no observation** (`PRG_UNOBSERVED`) keeps its
    own response (FR-FUZZ-50) and the other payloads still run; a run that then decides
    nothing is not comparable, never a negative. A compared send's (a control's)
    unobserved follow-up matters only where its strategy needs it: when the signature
    was seen through a follow-up, the control's must be observed too ("observed
    alike"), or the mechanism is not comparable. A direct signature never needs it.
  - **A control, a baseline sample, a compared slot or a replay** (layer 2,
    `ConfirmationStrategy._compared` -> `require_comparable`) counts only when its SP-56
    class (FR-CORE-507, with FR-SESS-22's facts; the response the strategy judges, a PRG
    follow-up's when there is one) is one its strategy declares for that role:
    | Strategy | Compared | Admits |
    |---|---|---|
    | SqliError, PathTraversal, PathTraversalFsPathRead, HttpHeaderInjectionCrlf | the benign control | application |
    | the differential engine (SqliBoolean) | B0, V, B / D | application / application or policy block |
    | NoSqlOperator | B, V, D | application |
    | `_confirm_timing` (SqliTiming, CommandInjection), RegexDos | the baseline samples | application |
    | CrossAccountReplay | the owner's own request, the other-value control, each replay | application or policy block |

    A gateway is admitted nowhere. A probe's credential is its sender's per-probe fact
    (`Probe.credentialed`): `RequestsProbeSender` and an anonymous seam send say False,
    a seam send on a session True; an unknown one counts as carried. A follow-up
    carries its request's fact. A replay's is its role's: the peer's carried, the
    unauthenticated one's not -- so a credentialed peer's refused credential is never a
    denial, and an unauthenticated 401 is.
  - **Outcome:** the candidate is **inconclusive** (`not-comparable`, its reason under
    `evidence["unobserved"]`, a role and a class, never a URL or payload) unless another
    mechanism confirms; never confirmed on such a control and never a negative. The
    scheduler is charged the mechanism's cost without a reward (`charge`,
    CC-SCHED-0007). `fuzzlab auto` lists it as "a response was not the application's own
    answer".
  - **Discovery (M9):** every default strategy is classified by how it reads controls
    (`tests/test_oracle_comparable_controls.py::CONTROL_READING`); every send of a
    control reader, and of the shared engine its row names, is `_compared` or a literal
    `trace.role("mutation")` send.
  - **The blind-SQLi builder** (`tools/blind_sqli_fuzzer.py`) neither averages a
    non-application sample (nor a login redirect) into its baseline nor writes a row for
    a payload answered by anything but the application; a payload's 504 stays a timing
    observation; a baseline with no application sample is `BaselineNotComparable`, not
    "could not reach".
  - Enforced by: `tests/test_oracle_comparable_controls.py` (117 tests, the discovery
    table and send guard included), `tests/test_oracle_sqli_string.py::test_a_site_that_throttles_mid_differential_is_not_comparable_never_a_negative`.
- **FR-FUZZ-65 (an answer on a session known to be lost is never evidence,
  `CC-FUZZ-0107`, `CC-FUZZ-0110`, `CC-MUT-0404`, 2026-10-20, BUG-0533; the owner's
  decision D′ after AU-SESS403's review round 4, extended in round 5)**
  - **The mark.** When the session manager sends a request on a state it already knows
    to be lost and cannot yet recover -- FR-SESS-23's D window: an identity with no
    stable protected resource whose re-login budget is spent -- `prepare` marks the
    request (`core.http.Request.session_lost`, FR-CORE-6). `SeamProbeSender` carries the
    mark, read and never recomputed, to the probe it returns (`Probe.session_lost`); a
    PRG follow-up carries its own request's mark.
  - **Layer 1** (`oracle.probe.require_observed`) raises `NotComparable("... sent on a
    lost session")` for any answer to a marked request, the probe's own or its
    follow-up's, **whatever its SP-56 class** (a guest view, a 404, a non-login
    redirect, a 401, a 403), before any class is read. Its `response_class` is
    `lost-session` (`LOST_SESSION`). It is applied to every send a strategy reads, from
    two places: the oracle's `_ObservedOnly` (the run's own sender: payloads, controls,
    baselines, compared slots, the correlated send) and `ConfirmationStrategy._compared`
    (every compared send, **whichever sender made it**: a cross-account replay's peer
    and anonymous senders are not wrapped by the oracle; review round 5). A timing
    send's read-timeout stand-in is checked the same way, but no live marked stand-in
    exists today: `SeamProbeSender` re-raises a timeout (TD3's timing case is
    synthetic).
  - **Outcome:** the mechanism gives no verdict and the candidate is **inconclusive**
    (`not-comparable`) unless another mechanism confirms on unmarked answers: never a
    pass, a negative or a finding from such an answer. The run goes on (D); the scheduler
    is charged as for any not-comparable arm (FR-FUZZ-63).
  - **Never fires for a resource-backed identity:** its loss is confirmed and re-logged
    in under the bucket, or it waits, or it goes sticky unknown; it never sends on a lost
    state (FR-SESS-23).
  - **Every consumer reads the mark** (the owner's decision D′ covers all of them):
    - the oracle, above;
    - the live WAF filter: `FilterUnobserved`, never an allow or a block (FR-MUT-401,
      CC-MUT-0404);
    - the blind-SQLi builder (`tools/blind_sqli_fuzzer`): `Answer.session_lost` from the
      seam send, `answer_class` reads it as `lost-session` (never a baseline sample), and
      no row is written for it, a lost session's 504 included (CC-FUZZ-0110).

    The auditor's and crawler's fetches read such answers for discovery only (a guest
    view can only hide a point; stated). R6 (a comparison that straddles a re-login) is
    separate and stays pinned.
  - Enforced by: `tests/test_session_forbidden_answers.py::test_an_answer_on_a_session_known_lost_is_never_evidence`,
    `tests/test_session_forbidden_answers.py::test_a_peer_replay_on_a_session_known_lost_is_never_evidence`,
    `tests/test_session_forbidden_answers.py::test_layer_one_reads_any_answer_on_a_lost_session_as_not_comparable`,
    `tests/test_session_forbidden_answers.py::test_the_live_waf_filter_never_reads_an_answer_on_a_lost_session`,
    `tests/test_session_forbidden_answers.py::test_the_blind_sqli_builder_never_admits_an_answer_on_a_lost_session`,
    `tests/test_session_forbidden_answers.py::test_a_resource_backed_identity_never_sends_on_a_lost_session`.
- **FR-FUZZ-64 (one query placement for every sender, `CC-FUZZ-0106`, 2026-10-20,
  BUG-0531)**
  - **One owner.** Every sender places a query value through `core.urls` (FR-CORE-501,
    SP-42): `RequestsProbeSender`, `SeamProbeSender` (every session route), greybox's
    `RequestsCorrelatingSender`, both blind-sqli senders, and the M6 browser executor
    (its observe navigation, its GET store step and an SPA hash route's query). The
    crawler's SPA seed builder places its route query through the same owner
    (CC-CRAWL-0053).
  - **A repeated name follows two rules** (per-occurrence points are BUG-0530's
    residual R1; the request context records which rule a point is sent by, FR-FUZZ-66):
    - a **standalone** URL (no entries) addresses the **first occurrence** of the name,
      in place (`place_query_param`);
    - **bound** entries (a link set, a form; the oracle's binder, unchanged) replace
      **every occurrence**, through `core.urls.bind_query`, for the HTTP senders and
      the M6 executor alike. The M6 GET store step is always standalone: a `StoreStep`
      carries no query siblings (its `entries` are a JSON store body's leaves).
  - **Every untouched part keeps** its position, its `=` (or its absence) and its raw
    text, up to the HTTP client's own rewriting (measured on requests 2.34.2 and
    Chromium 141.0.7390.37, pinned by a real-browser test). An absent name is appended
    once. The payload is `quote_plus`-encoded (`safe=""`), so a query-less URL gets the
    same bytes as before.
  - **No sender adds a second pair** for a name already present. There is no
    duplicate-parameter probe.
  - **A PRG follow-up** (FR-FUZZ-49) of a query point is resolved against the probe's
    own URL, never the placed one.
  - **Checks.** `tests/test_sender_conformance.py` checks every sender byte for byte on
    the URL `requests` prepares; `tests/test_query_placement.py` checks every sender end
    to end on a loopback echo server, Chromium under the measured relation, and holds
    the AST guard that keeps query building in `core.urls`.
  - **A crawled DOM query point** is loaded in the browser with its bound siblings
    (CC-FUZZ-0106 part 2): `DomXssStrategy` passes a query point's `base_entries`, when
    it has any, as `ExecRequest.entries`, and the executor binds them with
    `bind_query`, so the browser and the bound HTTP senders send the same query. The
    browser load is an observation, never a comparison control (FR-FUZZ-63's
    `_compared` does not apply to it).
  - **Stated gaps:**
    - a standalone operator URL with a repeated name probes its first occurrence only
      (0 of 157 ground-truth rows carry a query; BUG-0530 residual R1);
    - a stored link set's siblings are sent from their stored decoded values, so `flag`
      becomes `flag=` and `%20` becomes `+`, and `store_adapter.query_pairs` drops empty
      parts (BUG-0530 residual R2, pinned);
    - a non-UTF-8 query name is stored decoded with `errors="replace"`, so it never
      matches its URL's own raw occurrence and is appended as `%EF%BF%BD` (BUG-0530
      residual R2);
    - the M6 trace records no siblings; a form-body store request sends none;
    - query builders in other items' code, each pinned by a strict xfail naming its
      owner: `labgen/oracle_wrapper` (LAB). (`store_adapter.import_disco`'s was fixed
      by AU-REQID8, CC-AUD-0056: a form body is kept as ordered pairs.)
      (`disco/runner.py`'s was fixed by AU-OUTCOME, CC-FUZZ-0105: `Runner.prepare`
      places each case query value through `place_query_param`; `tools/spa.query_url`'s
      by CC-CRAWL-0053.)
    - *(Resolved, CC-FUZZ-0113:)* a **path** point's PRG follow-up re-requested the
      placed path (AU-PRGPATH, BUG-0542); see FR-FUZZ-69.
- **FR-FUZZ-66 (one test per request context, `CC-FUZZ-0111`, 2026-10-21, BUG-0530)**
  It supersedes FR-FUZZ-42's residual "one confirmation per (url, param, method,
  location)" and FR-FUZZ-43's "the first crawled link wins".
  - **The identity (SP-57, `core.reqctx`, version 1).** A request context holds the
    origin, path, the URL's raw query parts and fragment, the method and location, the
    target (a name; a JSON leaf's path; a header name), the placement rule (bound: every
    occurrence; standalone: the first), the sibling entries as sent with the target's
    slot as a placeholder, the content type, the setup steps run before each send (a
    stored case's store request; a fresh-binding fetch, FR-FUZZ-67), a sibling the
    replay refuses, and the run's identity scope. It never holds `sink_context`, the
    rule, the deciding mechanism, the category or a value beyond the target's digest
    (the *seed*).
  - **One key.** The point builder keeps one point per (context, seed); the pipeline
    confirms once per `confirmation_key`: the context's id and the category, plus the
    seed for the categories whose strategies read the original value
    (`SEED_CATEGORIES`: access-control, open-redirect, command-injection,
    nosql-injection). Rows share a test only when they send the same wire request and
    make the same observations; a row is marked by its own key's test only.
  - **Carried.** The audit engine stamps every candidate's evidence with
    `identity_scope` and `context_id`; the `Candidate` carries `context_id` and
    `context_key`; the `test.start` and `finding` trace events carry
    `request_context`; the finding's evidence records `context_id` and `context_key`,
    which the ML label join reads (FR-ML-401).
  - **Older rows** get their context on read, computed from the same evidence fields
    (their identity scope reads as unrecorded); nothing is migrated.
  - **Greybox** sends no siblings (FR-FUZZ-8), so `greybox.run.points_from_store` keeps
    one point per request it sends (url, param, method, location), in order: contexts
    that differ only in siblings are one greybox request (review round 1, BUG-0530).
  - **Stated gaps:** a repeated name is bound by the every-occurrence rule (R1, pinned);
    a stored link set's untouched siblings are sent from decoded values (R2, pinned); a
    POST action's query parameters are not points (AU-REQID-POSTQ, pinned); contexts the
    crawler's own form signature merges never reach the store (CRAWL, pinned; its
    request signature was fixed by SPIDER9, BUG-0546); `rules_fired` is still counted per (run, path, param).
- **FR-FUZZ-67 (stored evidence is never a replay template, `CC-FUZZ-0111`, 2026-10-21,
  BUG-0544)**
  - **The recipe.** Each stored sibling set records the page it came from and the names
    of its entries whose stored value is a placeholder -- blanked by redaction (a CSRF
    token or any sensitive name, an identifier-like value; FR-CORE-32, migration 25).
    Names and a page only: never a value (D12). *(Review round 1:)* the page is stored
    only when `core.redaction.page_url_is_clean` holds -- the strongest URL redactor
    leaves it unchanged, it holds no redaction placeholder and no empty query value --
    and only on the point's own origin; otherwise the set has no page.
    *(BUG-0556, review round 1:)* a crawl point whose **own URL** holds a value
    redaction replaced (`core.redaction.holds_placeholder`: an endpoint's own query --
    a POST form's action query, a captured request's URL query -- stored by name, never
    by value) is built with a `replay_refusal`: no setup step re-obtains an endpoint's
    own query, so the test is `UNBOUND` with that reason before any strategy runs and
    nothing is sent, never with the placeholder or a blank (PA-0544(1)/(3);
    `harness.auto._redacted_url_refusal`).
  - **Bound before each send.** The oracle's binder fetches that page through the
    sender's `fetch`, on the probe's own session route, finds the form or link the page
    offers now for the same origin, path, method and entry names
    (`core.forms.page_template_entries`), and binds the named entries' current values
    into that send only, in memory. An object selector the crawl saw blanked is resolved
    the same way. *(Review round 1:)* the fetch is a request like any other:
    - it is gated on its own URL -- the send gate; on the authenticated seam an auth
      endpoint or another isolated path is never fetched with the run's session;
    - it is made on the session the bound send carries: same origin, no session note;
      *(review round 2:)* the seam records the route its GET actually went out on (the
      client and identity label: the run's session, the path's isolated copy, or
      anonymous) as the fetch's carry token, and the bound send carrying it is refused
      (`PrerequisiteUnavailable`, so `UNBOUND`) when it would leave on another route or
      identity -- e.g. when the copy's re-login on that fetch logged the run's session
      out and the single-session breaker sent the path anonymous, or the copy could not
      log in again for the send; *(review round 3:)* the token also records the session
      generation the fetch's `prepare` applied (`Request.session_generation`, read,
      never recomputed) and whether the manager saw that session lost on the page's own
      answer (it told its listeners a loss of the identity while the GET was in flight,
      FR-SESS-16; `prepare`'s own flag on the fetch is still False then). The bound send
      is refused **before anything is sent** -- no re-login, no request -- when the
      page's own answer lost the session (the next `prepare` would log in again, and the
      page's token is the lost session's), and its answer is **not read** when its
      `prepare` applied another generation than the fetch's (a re-login between the
      fetch and the send: a time expiry, a loss found while a pause was waited out,
      another send's loss). Either way `PrerequisiteUnavailable`, so `UNBOUND`, never a
      negative; a copy's re-login on such a send is still verified (FR-FUZZ-44);
    - the anonymous `RequestsProbeSender` holds the page's cookies in memory under a
      one-time token and loads them only into the send whose bound entries carry it
      (every other send discards them first, BUG-0112); the authenticated seam carries
      no cookie a probe's or a page's answer set on any route, so a page that sets one is
      refused (a health check's adopted rotation is the stated gap N-R3-2 below).
  - **Every send of the candidate's own request** (its URL and method) is bound or
    refused, whatever its shape: a raw or JSON body, entries a strategy built, another
    location (review round 1).
  - **Never a placeholder, never a stand-in.** When the values cannot be rebuilt -- no
    page, an unclean or other-origin page, a sender that cannot fetch, a gated page, no
    answer, a non-2xx, lost-session or session-noted answer, a cookie the route cannot
    carry, no matching form or link, a captured JSON body (no page holds its leaves; such
    a candidate is unbound before any strategy runs), a fresh value naming a host outside
    the lab (the FR-AUD-20 predicate, failing closed on the value's tail too: an
    allow-list of the tail's grammar since review round 3), a bound send whose route is
    not its page fetch's or whose page's own answer lost the session, a bound send on
    another session generation than its page fetch's (its answer unread) -- nothing is
    sent and the test is inconclusive (`UNBOUND`) with the reason,
    never a negative. A sibling naming a host outside the lab is never sent and never
    replaced by loopback (FR-AUD-20, which fails closed: `value_shape.names_outside_lab`):
    its point carries a `replay_refusal` and is inconclusive before any strategy runs.
    The fingerprint baseline skips such points, header points never carry such a query,
    and the M6 browser refuses a query point needing a binding.
  - **Stated gaps:** a password field stays empty by policy (FR-FUZZ-44, D12); on the
    authenticated seam a form page that sets a cookie is unbound (the seam adopts no
    response cookie, and its pooled transport's jar keeps none, FR-CORE-509; the page
    fetch is a bodiless GET pooled under the probe route's own key), and so is a CSRF-protected login form whose page is an auth
    endpoint fetched on a session route; a captured JSON body's redacted leaf is never
    rebuilt; a store row from before migration 25 has no recipe. *(Review round 3; the
    round-2 residual "the route check does not compare the session's generation" is
    closed:)* a session's generation is known only once `prepare` has run inside the
    client's send, so a bound send whose own `prepare` logged in again has gone out --
    on the new session, with the old session's token, to the lab -- before it is
    refused; its answer is never read. A loss the manager tells its listeners on the
    page's own answer is refused before that. **Stated gap** (BUG-0544 residual N-R3-2,
    after the final round; owner FUZZ with SESS): a health check that answers LIVE
    adopts a rotated session cookie in place, in the same generation
    (`session.manager._adopt_rotation`; through `verify_live`, which `_verify_main` runs
    after any copy login or re-login, a policy block's `check_health`, or a pause's LIVE
    re-check in `prepare` -- the re-check above is covered only when it finds a loss),
    and the token compares only route, identity, generation and loss. So a bound send
    after such a check carries the old cookie's token on the new cookie, and its 403 is
    read as a negative, not unbound; pinned by the strict xfail
    `tests/test_replay_bindings.py::test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send`.
- **FR-FUZZ-68 (the template stage folds only true duplicates, `CC-FUZZ-0112`,
  `CC-CORE-0074`, 2026-10-21, BUG-0547)** When a caller gives `run_pipeline` the pages'
  HTML (`pages_html`), the stage before the audit folds injection points through
  `core.dedup.fold_points`:
  - **Folded only when it is the same work.** A point is dropped only when an earlier
    kept point is on a page of the same DOM template **and** has the same
    `core.dedup.wire_request_key`: every field of the point (endpoint URL, parameter,
    method, location, sibling entries, content type, sink, store step, origin, value
    shapes, base value, redirect seed, deciding mechanism, and any field added later) as
    given. Only a standalone query point's injected slot (no siblings, no store step) is
    taken as sent, placed by the one query placement (FR-FUZZ-64, SP-42), so
    `/item?id=1` and `/item?id=2` probing `id` are one request.
  - **A shared template alone never folds two points.** Another endpoint, parameter,
    location, method, form action or sibling value keeps both.
  - **An unknown page is never a duplicate.** A URL with no HTML, or HTML with no tag
    structure, is its own template: its points fold only with an identical point on the
    same URL.
  - **Reported.** The metrics carry `dedup_points_in`, `dedup_folded`,
    `dedup_unknown_pages` (also `pipeline_dedup_*` run metrics) and `dedup_key`
    (`core.dedup.FOLD_KEY`); nothing is reported, and nothing folded, when no pages are
    given.
  - **SP-57 is a member of this key (AU-REQID78).** `wire_request_key` holds the
    request-context identity (SP-57, `core.reqctx.point_key`, FR-FUZZ-66) as a member
    (`context`) and adds every other point field as given, so a fold never joins two
    request contexts: the fold must also keep apart the fields that change which rules
    fire or which mechanism decides (sink, value shapes, origin, deciding mechanism)
    and a store field without a store step, which the request context deliberately
    leaves out. Both normalise a standalone query slot the same way (the first
    occurrence, SP-42). A URL the identity cannot parse has no context member (None)
    and is keyed as given. `FOLD_KEY` is `template+wire-request-v2` since this member
    joined the key.
  - **Stated gap:** a PRG follow-up of a fragment-only `Location` is resolved against the
    point's unplaced URL (FR-FUZZ-64), so two folded standalone points could differ in that
    one follow-up's target.
  - **Checks:** `tests/test_dom_dedup_folding.py`.
- **FR-FUZZ-69 (a path point's PRG follow-up never re-sends the payload, `CC-FUZZ-0113`,
  2026-10-21, BUG-0542)** A PRG follow-up (FR-FUZZ-49) is resolved against the probe's
  **own** URL at every location, never the request that carried the payload: the URL
  itself for a body, header or JSON point, a query point's URL without its payload
  (FR-FUZZ-64), and a **path** point's template (`/p/{id}/view`). One rule
  (`probesender.prg_target`) for both probe senders; the placed URL still routes and
  attributes the follow-up (the seam's isolated copy, the header breaker), as it did the
  probe.
  - **A target that keeps the path point's own segment** (`{id}`) names the resource the
    payload is in: a browser would fetch it with the payload (`#top` ->
    `/p/<payload>/view`, `edit` -> `/p/<payload>/edit`, `?tab=2`, `./`). That request is
    never the page the probe's own request led to, and no payload-free URL names it. It
    is refused before any send: `Probe.prg` is `skipped: the follow-up would re-send the
    payload`, with no `followed`, no `prg_sent` and no request counted
    (`follow_up_sends` 0). The strategy reads the probe's own response, as for any
    refused follow-up.
  - **A target the server wrote with the placed value in its path** (an absolute path or
    URL built from the request, as an app redirecting to the resource just posted
    writes it: `/p/<payload>/edit`) is refused the same way, with the same
    `Probe.prg`. It is the same browser request as `edit`, so the decision is the same
    for every spelling of it: the value is matched as whole segments of the target's
    path, as written and percent-decoded (a server that re-encodes `*` as `%2A`, or the
    reverse, is still caught; a value with a `/` written raw spans its segments,
    `probesender._re_sends`). Its answer is never the
    page the POST led to: a page that renders its own URL would read as the POST's
    stored result, and M4 confirmed through it with `observation: "prg"` (review round
    1 of CC-FUZZ-0113, PRGPATH-R1; `strategies._rode_the_redirect` is read by M5 XSS
    only, so the strategies did not classify it).
  - **A target that leaves the segment** (`../list`, an absolute path or URL without the
    placed value) is fetched exactly where a browser goes. Resolution is structural, so
    the template and the placed URL give the same target. The sender never adds the
    payload to a follow-up.
  - `probesender.PRG_RULES` states both divergences from the browser
    (`location-relative`: the probe's own URL; `own-segment-never-refetched`), each with
    a fixture.
  - **Decision: resolve against the unplaced URL, not "unobserved".** Nothing is sent,
    and `PRG_UNOBSERVED` means a follow-up went out and gave no observation, which
    `Probe.prg_sends` counts as a request (FR-FUZZ-49 P8). So the refusal is a gate's
    `skipped:`, like an another-origin or login-page target.
  - **Stated residuals:** such a path point's PRG-only signal is not observed, so a run
    that decides nothing is a negative, as for every refused follow-up. A reflection
    reachable only through a relative redirect is found at the target's own point, not
    through this one. A payload made only of dot segments (`.`, `..`) is refused where
    a browser would normalise it away. A value the target's path holds as whole
    segments for another reason (a payload `list` and `Location: /p/list`) is refused
    too: the sender cannot tell the two apart, and nothing is sent. A placed value the
    server wrote only into the target's query (`/p/list?from=<payload>`) is not the
    point's resource: it rode the redirect and is taken as written, as at every other
    location (FR-FUZZ-49 P6).
  - Enforced by: `tests/test_query_placement.py::test_a_path_points_prg_follow_up_never_carries_the_payload`,
    `tests/test_query_placement.py::test_no_prg_follow_up_carries_the_payload_at_any_location`,
    `tests/test_query_placement.py::test_the_prg_location_table_covers_every_placeable_location`,
    `tests/test_query_placement.py::test_a_location_the_server_wrote_with_the_payload_is_refused`,
    `tests/test_prg_observation.py::test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms`,
    `tests/test_prg_observation.py::test_a_path_points_follow_up_that_leaves_its_segment_still_confirms`,
    `tests/test_prg_observation.py::test_prg_rule` (`own-segment-never-refetched`)
## 4. Non-functional requirements
- **NFR-FUZZ-precision** Oracle precision is measured and prioritized; a confirmed
  finding must reproduce.
- **NFR-FUZZ-deterministic** Given the same target state and inputs, oracle
  verdicts are reproducible (state reset via snapshot/restore between iterations).
- **NFR-FUZZ-safe** Destructive payload classes off by default; auth endpoints
  excluded from scope; no traffic off localhost.
  - Clause (in-app login forms; FR-FUZZ-44, CC-FUZZ-0064): the run's session is never
    sent to a path with an in-app login form **for store-sourced (crawl) points in
    `fuzzlab auto`**; such sends use an isolated session or none, and credential-change
    forms are never imported.
  - Enforced by (in-app login forms): `SeamProbeSender` isolated routing,
    `injection_points_from_store`'s default drop, `form_skip_reason` — `tests/test_login_form_isolation.py::test_a_login_form_is_confirmed_on_an_isolated_session_and_the_run_session_survives`, `tests/test_login_form_isolation.py::test_credential_change_forms_stay_excluded`, `tests/test_login_form_isolation.py::test_a_password_control_is_never_a_point_whatever_its_name`, `tests/test_login_form_isolation.py::test_without_isolated_the_points_are_dropped_and_reported`, `tests/test_login_form_isolation.py::test_greybox_never_gets_login_form_points`, `tests/test_login_form_isolation.py::test_a_rejected_isolated_login_falls_back_to_anonymous_once`, `tests/test_login_form_isolation.py::test_a_failed_copy_relogin_falls_back_with_no_session_at_all`, `tests/test_login_form_isolation.py::test_verify_live_carries_the_session_to_the_session_host_only`, `tests/test_login_form_isolation.py::test_a_copy_must_differ_from_every_live_copy`, `tests/test_login_form_isolation.py::test_a_single_session_app_trips_the_breaker_after_one_copy_login`, `tests/test_login_form_isolation.py::test_a_lazy_single_session_logout_trips_the_breaker`
  - Not yet enforced (in-app login forms): `fuzz --identity` and `mutate-run --identity`
    send to the operator's own `--url` with the run's session; an operator who points
    them at an in-app login form must run them without `--identity`.
  - Enforced by (auth endpoints, destructive URLs; CC-FUZZ-0060): `core.urls.check_send_url` in every probe sender, crawl-point filtering, anonymous auth-endpoint sends — `tests/test_destructive_urls.py::test_every_probe_sender_calls_the_send_gate`, `tests/test_destructive_urls.py::test_crawl_sourced_runs_never_fuzz_a_destructive_url_and_report_it`, `tests/test_destructive_urls.py::test_an_auth_endpoint_is_probed_without_the_session_and_the_session_survives`, `tests/test_destructive_urls.py::test_greybox_sender_gates_drops_the_cookie_on_auth_endpoints_and_clears_the_jar`, `tests/test_forms_phase1.py::test_credential_parameters_from_links_are_never_fuzzed`, `tests/test_forms_phase1.py::test_object_selecting_hidden_fields_and_csrf_are_pinned_not_fuzzed`
  - Enforced by (destructive payloads off by default, greybox): `tests/test_destructive_send_gate.py::test_greybox_never_sends_a_destructive_probe`
  - Enforced by (oracle SQLi probes are AND-only, quote-balanced and non-destructive; CC-FUZZ-0065): `tests/test_oracle_sqli_string.py::test_every_new_sqli_probe_matches_its_closed_template_exactly`, `tests/test_oracle_sqli_string.py::test_the_grammar_pair_compiles_and_fails_as_designed`
  - Enforced by (scope set): `tests/test_core_foundations.py::test_http_scope_enforced`
  - Enforced by (the `--authorized` lab-only gate through `fuzzlab train run`; CC-FUZZ-0400): `tests/test_train_cli.py::test_train_run_without_authorized_sends_nothing`, `tests/test_train_cli.py::test_no_usage_error_leaves_a_store_or_a_run_row`
  - Enforced by (the M6 browser stays on its observe and store origins; CC-FUZZ-0066, BUG-0123): `PlaywrightBrowserExecutor.run` scoped launch, context guard, scope-checked plant with `max_redirects=0` — `tests/test_browser_scope.py::test_the_m6_browser_is_launched_scoped_and_plants_without_redirects`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`
  - Enforced by (forms phase 2, CC-FUZZ-0063): header names checked at the CLI and at every sender's header branch, the header breaker, siblings never carrying the app's own host or an identifier, settings pickers never fuzzed — `tests/test_forms_phase2.py::test_header_point_names_are_validated`, `tests/test_forms_phase2.py::test_every_sender_refuses_a_denied_header_unless_explicit`, `tests/test_forms_phase2.py::test_every_header_branch_calls_the_header_gate`, `tests/test_forms_phase2.py::test_a_session_bound_to_user_agent_trips_the_breaker_after_one_relogin`, `tests/test_forms_phase2.py::test_a_crawled_hostname_is_never_sent`, `tests/test_forms_phase2.py::test_neutral_value_errs_toward_loopback`, `tests/test_forms_phase2.py::test_a_header_point_url_never_carries_the_apps_own_host`, `tests/test_forms_phase2.py::test_identifier_like_link_values_are_blanked_and_never_stored`, `tests/test_forms_phase2.py::test_link_sets_with_a_credential_or_destructive_entry_are_not_bound`, `tests/test_forms_phase2.py::test_settings_named_post_selectors_are_skipped`, `tests/test_forms_phase2.py::test_a_picker_seen_setting_a_cookie_is_not_fuzzed`
  - Enforced by (forms phase 3, captured JSON requests; CC-AUD-0035 / CC-FUZZ-0068): DELETE, unflagged PUT/PATCH, destructive, transaction, cross-origin, credential-change and settings requests never imported (`store_adapter.captured_request`); a JSON login body probed only on an isolated or anonymous session, its password never a point and sent empty; siblings redacted and neutral; a DELETE refused again at every sender; a crawled fragment payload never sent over HTTP; greybox never sent a JSON point — `tests/test_json_points.py::test_each_refusal_is_never_imported`, `tests/test_json_points.py::test_put_and_patch_import_only_with_the_flag_and_a_safe_url`, `tests/test_json_points.py::test_malformed_unsupported_and_cross_origin_requests_are_refused`, `tests/test_json_points.py::test_the_credential_change_rule_is_one_function_shared_with_forms`, `tests/test_json_points.py::test_a_password_leaf_on_any_segment_is_isolated_sent_empty_and_never_a_point`, `tests/test_json_points.py::test_the_password_gate_holds_without_the_sensitive_name_pin`, `tests/test_json_points.py::test_object_selectors_sensitive_and_identifier_leaves_are_pinned`, `tests/test_json_points.py::test_a_json_login_sqli_is_confirmed_on_an_isolated_session_only`, `tests/test_json_points.py::test_a_json_login_sqli_is_confirmed_anonymously_by_the_plain_sender`, `tests/test_json_points.py::test_json_siblings_are_never_sent_as_placeholders_or_stand_ins`, `tests/test_json_points.py::test_json_siblings_naming_loopback_are_sent_as_the_app_gave_them`, `tests/test_json_points.py::test_every_sender_refuses_a_crawl_sourced_delete_at_send_time`, `tests/test_json_points.py::test_a_crawled_fragment_payload_never_reaches_the_server`, `tests/test_json_points.py::test_a_destructive_spa_route_is_never_a_point`, `tests/test_json_points.py::test_a_second_hash_in_a_spa_route_hides_nothing_from_point_selection`, `tests/test_json_points.py::test_a_destructive_route_behind_a_second_hash_is_never_a_point`, `tests/test_json_points.py::test_greybox_refuses_a_json_point_and_never_gets_one_from_the_store`, `tests/test_sender_conformance.py::test_every_sender_places_a_json_leaf_in_the_rebuilt_body`, `tests/test_sender_conformance.py::test_the_form_bound_sender_places_a_json_leaf_in_the_rebuilt_body`, `tests/test_json_points.py::test_a_leaf_absent_from_a_captured_body_is_refused_never_appended`, `tests/test_json_points.py::test_server_side_rules_never_fire_on_a_fragment_point`, `tests/test_json_points.py::test_no_strategy_masks_an_unplaceable_send`, `tests/test_json_points.py::test_the_masking_guard_catches_a_synthetic_offender`, `tests/test_json_points.py::test_a_fragment_point_no_mechanism_can_place_is_inconclusive_never_a_negative`
  - Enforced by (the M6 executor's storage headers go through its guarded route only, in scope; CC-FUZZ-0076, FR-CRAWL-14's mechanism): `PlaywrightBrowserExecutor.run` → `navguard.guard_page(headers=)` — `tests/test_browser_scope.py::test_no_browser_context_gets_session_headers_outside_the_route`, `tests/test_browser_scope.py::test_session_headers_are_added_by_the_route_only_in_scope`
  - Clause (PRG follow-ups; FR-FUZZ-49, CC-FUZZ-0078): a post/redirect/get follow-up
    is one plain GET, never a re-sent body or payload, only to the probed URL's own
    origin, never to a destructive, transaction, account, login-page or auth-endpoint
    target, never from the run's session to an isolated path, always on the probe's
    own session route, never on a timing send, one hop.
  - Enforced by (PRG follow-ups): `probesender.prg_target` and
    `SeamProbeSender._prg_session_gate` at the send — `tests/test_prg_observation.py::test_a_refused_target_is_never_fetched`, `tests/test_prg_observation.py::test_a_307_after_post_is_not_followed_but_after_get_it_is`, `tests/test_prg_observation.py::test_a_second_redirect_is_no_observation`, `tests/test_prg_observation.py::test_a_redirect_to_the_login_page_is_not_followed`, `tests/test_prg_observation.py::test_a_redirect_to_an_auth_endpoint_is_not_followed`, `tests/test_prg_observation.py::test_a_main_session_probe_redirected_to_an_isolated_path_is_not_followed`, `tests/test_prg_observation.py::test_an_isolated_post_is_followed_on_the_same_copy`, `tests/test_prg_observation.py::test_an_anonymous_probe_follows_anonymously`, `tests/test_prg_observation.py::test_no_follow_up_once_the_header_breaker_stopped_header_probes`, `tests/test_prg_observation.py::test_a_timing_send_never_follows`, `tests/test_prg_observation.py::test_sqli_timing_and_boolean_never_cause_a_follow_up`, `tests/test_prg_observation.py::test_prg_rule`, `tests/test_query_placement.py::test_no_prg_follow_up_carries_the_payload_at_any_location` (never a re-sent payload, at every location; FR-FUZZ-69, BUG-0542)
  - Not yet enforced (BUG-0301, deferred to the owner of `core/urls.py`, CC-CORE-0301): the send gate `check_send_url` lets through Juice Shop's `GET /rest/user/change-password?current=&new=&repeat=` (changes the session user's password; `current` is optional) and `/dataerasure` (files an erasure request, clears the token cookie). An imported change-password URL, or the erasure form once crawled, would be fuzzed. Pinned by strict xfails: `tests/test_destructive_routes_external_labs.py::test_juice_change_password_url_is_refused_at_the_send_gate`, `tests/test_destructive_routes_external_labs.py::test_juice_dataerasure_form_is_never_imported`; the compensating controls are checked by `tests/test_destructive_routes_external_labs.py::test_bug_0301_compensating_controls_hold_meanwhile`.
  - Not yet enforced: the destructive-**payload** gate on the `auto`/`fuzz` senders (their payload lists are non-destructive today; wiring it needs on-host benchmark verification); "no traffic off localhost" for the probe senders (scope is the operator's target, and BUG-0050 deliberately allows authorized external hosts, so the clause needs re-wording or a loopback gate; the browser part is enforced above, BUG-0123); the CLI `--authorized` refusal is untested for fuzz/auto/greybox-run/mutate-run/proxy. (BUG-0111 sweep; reported to the operator.) The existing SQLi timing templates include an OR form (`1' OR SLEEP(d)-- -`) and comment-terminated forms that can widen a WHERE or strip trailing predicates in a write (BUG-0118, open).
  - Clause (the contract runner, FR-FUZZ-52, CC-FUZZ-0089): every send is gated at the
    send -- scope, the destructive URL and method gate, no redirects, a byte cap -- a
    destructive case is skipped by default, credentials reach only the base origin, and
    disco issues HTTP nowhere else.
  - Enforced by (the contract runner): `disco.runner.Runner.send` / `run_case` / `prepare` — `tests/test_disco_contract.py::test_the_send_gate_refuses_out_of_scope_and_destructive_urls_at_the_send`, `tests/test_disco_contract.py::test_a_destructive_case_is_skipped_and_sends_nothing`, `tests/test_disco_contract.py::test_credentials_go_only_to_the_base_origin`, `tests/test_disco_contract.py::test_setup_extracts_and_the_oracle_flags_a_logic_bug`, `tests/test_disco_contract.py::test_a_body_is_read_up_to_its_cap`, `tests/test_disco_contract.py::test_the_runner_needs_authorized`, `tests/test_disco_isolation.py::test_disco_sends_http_only_through_the_runner_s_gated_send`, `tests/test_disco_isolation.py::test_the_send_guard_catches_synthetic_offenders`
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
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_fuzz_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_auto_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_greybox_run_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_fuzz_dry_run_reports_plan_and_sends_nothing`, `tests/test_cli_dry_run.py::test_auto_dry_run_reports_plan_and_sends_nothing`, `tests/test_cli_dry_run.py::test_greybox_run_dry_run_reports_plan_and_sends_nothing`
  - Enforced by (through `fuzzlab train run`; CC-FUZZ-0400): `tests/test_train_cli.py::test_train_run_dry_run_sends_nothing`, `tests/test_train_cli.py::test_a_dry_run_creates_nothing_and_names_the_store`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.
- **NFR-FUZZ-response-fidelity** *(`CC-FUZZ-0043`, `BUG-0044`/`PA-0046`)*
  Every sender that builds a `Probe` (or a timing measurement) a
  `ConfirmationStrategy`/timing oracle inspects as "the real target's
  response" must report that response as the target actually sent it for
  the specific request the strategy issued — never a client library
  default's silent transformation of it (redirect-following in
  particular, mirroring `PA-0030`'s harness-level rule, now widened to
  cover senders too) — unless following that transformation is the
  literal thing the strategy needs to observe. `RequestsProbeSender`
  (`fuzzlab/tools/probesender.py`), `RequestsCorrelatingSender`
  (`fuzzlab/greybox/run.py`), and `RequestsSender`
  (`fuzzlab/tools/blind_sqli_fuzzer.py`) all now pass
  `allow_redirects=False` explicitly, matching `fuzzlab.core.http`'s own
  authenticated (`SeamProbeSender`) path, which already did. Found the
  hard way: `OpenRedirectStrategy` needs the FIRST, un-followed response's
  own `Location:` header, and a caller-controlled value echoed into a
  real `Location:` header can resolve to a self-referencing redirect
  (e.g. a bare `#...`-fragment value), which a redirect-following sender
  chases forever until `requests.exceptions.TooManyRedirects` crashes the
  whole run. A component whose job genuinely is to follow redirects (a
  login-flow fetcher discovering an authenticated session, a crawler
  discovering pages) is explicitly NOT covered by this requirement —
  the discriminator is whether the caller is a confirmation/timing
  oracle that needs the un-followed response.
  The PRG follow-up (FR-FUZZ-49, `CC-FUZZ-0078`) keeps this: the probe is still
  the un-followed response, untouched; the follow-up is a separate request
  made only when a strategy run asks for it, kept as a separate `Probe`
  (`probe.followed`), one hop, never a client library default.

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
- (`CC-FUZZ-0032`, 2026-09-23) **`fuzzlab/greybox/run.py`'s
  `RequestsCorrelatingSender` has the same `location="body"`
  form-encode-only branch `RequestsProbeSender`/`SeamProbeSender` had
  before `FR-FUZZ-15`, and was not given the same content-type
  awareness.** Low risk today — `GreyboxConfirmationStrategy` only scopes
  to `sql-injection`/`xss`, neither of which reaches a whole-body point —
  but a real, latent gap the moment a future grey-box-confirmable category
  does. Give it the same `content_type` handling when that happens, not
  before (no consumer to test it against yet).
- (`CC-FUZZ-0032`, 2026-09-23; re-examined and corrected 2026-09-23;
  **resolved** `CC-FUZZ-0034`/`CC-AUD-0018`, 2026-09-23, by a different,
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
- (`CC-LAB-0175`/`FR-LAB-98`, `CC-FUZZ-0032`, 2026-09-23; **empirically
  re-examined** `CC-FUZZ-0035` follow-on, 2026-09-23) **No
  webhook-signature timing oracle — now confirmed genuinely infeasible
  with this project's current wall-clock-HTTP measurement, not just
  theoretically hard.** Both twins behave identically for any single
  request (the divergence is comparison timing: `naive_string_compare`'s
  `==` short-circuits on the first differing byte, `hmac.Equal` does not),
  so a real oracle needs a statistical, multi-request timing-differential
  mechanism. A concrete sketch was recorded (probe pairs comparing
  response time for a candidate signature matching zero leading bytes of
  the locally-known correct one, against one matching many leading bytes,
  aggregated over enough paired samples for a real statistical test) —
  **this session actually measured it live, not just reasoned about it**:
  booted `LABGEN-GO-0001` for real, computed the true HMAC-SHA256 for a
  fixed request body against the stack's own fixed demo secret, and sent
  400 real HTTP requests per prefix-match length (0/16/32/48/62 of 64 hex
  chars), randomly interleaved (not batched by length, to rule out a
  connection-warmup/scheduler-warmup confound — an un-interleaved first
  pass showed a monotonic-looking trend that was purely this artifact,
  caught before being mistaken for a real signal). Interleaved result: no
  detectable relationship between prefix-match length and latency at all
  — min/median/trimmed-mean all land within the same few-hundred-
  microsecond noise band regardless of how many leading bytes matched
  (e.g. min latency 178–190µs across every prefix length tested). Go's
  `==` per-byte comparison time is real but nanosecond-scale; ordinary
  HTTP-over-loopback jitter (goroutine scheduling, GC, socket syscalls) is
  2–3 orders of magnitude larger and completely swamps it even in this
  idealized same-machine environment with zero real network latency — a
  real target reachable only over an actual network would be worse, not
  better. Confirms this needs either (a) a fundamentally different
  measurement channel than wall-clock HTTP round-trip time (e.g. a
  grey-box timing source reading server-side instrumentation directly,
  the same class of seam `fuzzlab.greybox` already establishes for
  coverage/DB-fault signals — not attempted, would need new
  infrastructure), or (b) many orders of magnitude more samples than this
  session's own quick 400-per-arm probe with proper outlier-robust
  statistics, likely impractical for a fast test suite. Not a "not
  attempted yet" gap anymore — a "attempted, measured, confirmed
  infeasible at this layer" one. Left open for a future session with a
  genuinely different architecture, not a bigger sample size of the same
  approach.
- Oracle interface for pluggable vulnerability classes (register-oracle hook
  shape).
- Timing-threshold calibration per target/network profile.
- Reward shaping when grey-box signals are unavailable (black-box fallback).
- **FR-FUZZ-39** *(structural reflected-XSS confirmation; `CC-FUZZ-0057`, 2026-10-13,
  BUG-0083).* `ReflectedXssStrategy` types where a marker lands, from the observed
  response (never `candidate.sink_context`, which no strategy reads, guarded by an AST
  test). It sends at most 3 break-outs, and confirms only on their structural effect in
  the parsed response:
  - **script:** the token in JavaScript **code** state. The fail-closed lexer handles
    strings, comments and regex literals.
  - **attribute:** in order:
    - a `javascript:` URL in an executing attribute, lexed after percent-decoding;
    - `javascript:` at the scheme position;
    - an **injected attribute**, with the quote read from the raw text.
  - **text:** an injected **element** with no inert ancestor (`textarea`, `title`,
    `script`, `style`, `xmp`, `noscript`, `iframe`, `noembed`, `noframes`,
    `plaintext`, `template`). RCDATA is broken out of by its closing tag.
  - **Document type** *(amended in place, `CC-FUZZ-0072`, 2026-10-14, BUG-0127)*: a
    break-out confirms only in a response a browser renders as HTML (`text/html`,
    `application/xhtml+xml`, or no Content-Type) and not served as a download
    (`Content-Disposition: attachment`, CC-FUZZ-0073); a JSON, text or script echo never
    does (`tests/test_oracle_xss_structural.py::test_a_reflection_confirms_only_in_a_response_rendered_as_html`).
    Stated false negatives: script-capable `text/xml` / `application/xml` /
    `image/svg+xml` responses. An untyped `nosniff` response is still treated as
    rendered.

  Verified against the four lab XSS sink templates, each vulnerable and as its secure
  twin.
  - **Executability (CC-FUZZ-0058, BUG-0093).** A `<script>` counts as JavaScript only
    when `context.script_executes` says its inline body runs. The rules are the HTML
    standard's:
    - **type:** `type` is empty, or a JavaScript MIME essence matched exactly
      (case-insensitive, whitespace stripped, so a type with parameters is a data
      block), or `module`. With no `type`, `language` is absent or empty, or
      `"text/"+language` is such an essence;
    - **no `src`**, even an empty one;
    - **not `nomodule`** on a classic script;
    - **no inert ancestor.**

    A marker in a script that never runs is text in a raw-text element: its only try is
    `</script><TOK>` with element evidence. `javascript:` URLs count only with no inert
    ancestor. **Stated limit:** structural state is not proof of execution, and
    client-rendered `text/template` blocks are a false negative here. Browser-backed
    confirmation (M6) is the stronger path.
  - **Regex versus division (CC-FUZZ-0059, BUG-0102)** is decided from the previous
    token:
    - **regex** after a punctuator, a `REGEX_KEYWORDS` keyword (`return`, `typeof`,
      `case`, `default` …) or an `if` / `while` / `for` / `with` head's `)`;
    - **division** after an identifier (`this` / `null` / `true` …), a number, a
      string, a regex, `]`, another `)` or a postfix `++` / `--`;
    - a `/` after `}` makes the source UNSURE.

    A real ECMAScript parser, or browser-sentinel confirmation (M6), remains the
    stronger path.
- **FR-FUZZ-40** *(auth endpoints and destructive URLs; `CC-FUZZ-0060`, 2026-10-13,
  BUG-0112; NFR-FUZZ-safe).*
  - **Send-time gate.** Every probe sender (`SeamProbeSender`, `RequestsProbeSender`,
    greybox's `RequestsCorrelatingSender`, the blind-SQLi fuzzer's senders) calls
    `core.urls.check_send_url` first. It refuses (`DestructiveUrlRefused`) a URL
    `destructive_reason` flags unless it was explicitly enumerated:
    - `run_auto` and `greybox-run` allow the ground-truth point (and store) URLs;
    - `fuzz` allows its own `--url`;
    - crawl-sourced runs allow nothing.

    An AST guard requires the call in every HTTP probe sender.
  - **Point selection.** `injection_points_from_store` (used by `auto` and
    `greybox-run`) leaves out destructive crawl points and reports each in
    `metrics["skipped_points"]`. `fuzzlab auto` prints them. A SPA hash route is
    destructive by its fragment too (`/#/logout`), which is judged as a whole text
    (`core.urls.text_destructive_reason`), never re-joined into a URL, so a second `#`
    in it hides nothing (`/#/a#/logout`; `CC-FUZZ-0077`, BUG-0131).
  - **Auth endpoints are probed without the session.** An authenticated sender logs
    in once before its first probe; a probe to one of the session's auth endpoints
    (the login page and form action, `SessionManager.is_auth_endpoint`) is sent
    anonymously, so it can neither log the run out nor re-authenticate it. This covers
    every source, ground truth included, and the count is recorded as
    `metrics["auth_endpoint_anonymous_sends"]`. Logout is excluded by
    `destructive_reason`, because the recorded logout URL is a guess.
  - **No cookie carries over.** The requests-based senders clear their jar before
    each probe, so a probe response's `Set-Cookie` never rides on later probes.
- **FR-FUZZ-41** *(sub-path targets; `CC-FUZZ-0061`, 2026-10-13, BUG-0113).*
  Crawl-sourced points join their stored absolute paths to `--base-url`'s origin, so
  the base may carry the app's path (`.../bWAPP/`). Authenticated senders (`fuzz`,
  `SeamProbeSender`) log in from the operator's URL before the first probe.
  - Not yet enforced (ground-truth points, BUG-0300; deferred to the owner of `harness/auto.py`, CC-FUZZ-0300): `points_from_ground_truth` (and greybox's `points_with_classes`) join a ground-truth url to the whole base URL, so a base under a sub-path doubles it (`…/bWAPP/` + `/bWAPP/x.php` → `/bWAPP/bWAPP/x.php`). Ground-truth runs must pass the origin as `--base-url` until the fix lands. Pinned by strict xfails: `tests/test_base_url_subpath_registry.py::test_ground_truth_points_join_absolute_paths_to_the_origin`, `tests/test_base_url_subpath_registry.py::test_greybox_ground_truth_points_join_absolute_paths_to_the_origin`.
  - Enforced by (PA-0300: every function that takes an operator base URL has a sub-path test or a named bug): `tests/test_base_url_subpath_registry.py::test_every_base_url_function_is_registered`, `tests/test_base_url_subpath_registry.py::test_every_registry_pointer_is_a_real_subpath_test`, `tests/test_base_url_subpath_registry.py::test_the_registry_guard_catches_synthetic_offenders`
- **FR-FUZZ-45** *(string-context SQLi confirmation; `CC-FUZZ-0065`, 2026-10-14,
  BUG-0117).*
  - **(a) The differential engine.**
    - **Sequence:** B0, a screen of V and D in a drawn order, then 6 rounds of
      (V, D, B) in a drawn permutation, with fresh tokens each round. There is exactly
      one draw per round, from fixed tables, and a round is judged after all of it is
      sent.
    - **Confirms when:** every V and B is `same` as B0, every D is not, and every D is
      `same` as the first D.
    - **Bound:** for any response sequence that does not depend on the probe values,
      and any comparison predicate, P[confirm] ≤ (1/2)(1/3)^6 = 1/1458 per family, and
      < 3/1458 per candidate. Expected false confirmations per run are therefore at
      most candidates × 3/1458.
    - **Request count:** it does not depend on the drawn order on targets whose
      responses do not depend on earlier probes.
    - *(Note, CC-FUZZ-0105, FR-FUZZ-63.)* Every slot is compared: B0, V and B must be
      application answers, D an application answer or a policy block (V carries D's
      characters, so no lexical filter singles D out). Any other answer stops the
      engine `not-comparable`: inconclusive, never a negative.
  - **(b) `SqliBooleanStrategy`'s families,** in this fixed order:
    - **numeric:** `1` / `1 AND 1=1` / `1 AND 1=2`, compared by length;
    - **string-grammar:** `v` / `v' AND 't' LIKE 't` / `v' AND 't' LIKE t'`;
    - **string-evaluation:** `1` / `1' AND 't' LIKE 't` / `1' AND 'u' LIKE 't`.

    The string families compare status plus the body with reflections stripped.
    Tokens are `fz`/`q` + 6 hex, never a SQL literal prefix.
    - **Cost:** the cap is 30, and that is also the reachable maximum. A family
      starts only with 21 requests left. Screens that all fail cost 9.
    - **Cap exhaustion:** when the cap stops a family from starting after an earlier
      one passed its screen, the verdict is **inconclusive**. The candidate becomes
      `inconclusive` (unlabelled), never a negative. Under the scheduler, the arm gets
      reward 0 and its real cost.
    - **Whole-body points:** string families are skipped on raw whole-body points.
  - **(c) `SqliEvaluationMarkerStrategy`:** `0'+(SELECT a*b)+'0`.
    - Two products, each shown (digit-bounded) in the response to the probe that
      computed it, with the literal absent.
    - At most 2 requests.
    - Never the `||` form.
  - **Error signatures (BUG-0117):** count only when absent from the quote-free,
    non-numeric controls. At most 4 probes + 2 controls.
  - **Out of scope:**
    - `HY000` is corroboration only, never a signature;
    - SQLite `randomblob` timing is rejected, because of memory;
    - OR and comment-terminated probes are excluded (the existing timing templates
      are BUG-0118).
  - **Safety:** every new probe is quote-balanced and AND-only, with no comment, `OR`,
    `||`, `;` or backslash.
    - **Predicate contexts:** V selects the baseline's rows.
    - **Value contexts (INSERT/UPDATE):** V, the evaluation probes and C write a
      coerced value to the baseline's own row. That is up to 3 rows per screen per
      family, about 11 on sqli_12, and at most 38 from these strategies. Other
      strategies on the point also write.
    - **The grammar D never executes.**
  - **Limits (false negatives, never FPs):**
    - LIKE contexts where `%1%` matches differently;
    - pages reflecting the base `1`;
    - double-quoted contexts;
    - pages that change on every request;
    - a cap exhausted on noise.
- **FR-FUZZ-42** *(forms as injection points; `CC-FUZZ-0062`, 2026-10-13).*
  - **Points.** Crawled forms become points.
  - **Siblings** *(amended in place by FR-FUZZ-43, `CC-FUZZ-0063`, 2026-10-14; it
    supersedes CC-FUZZ-0062's binding in these respects).* Every probe of a form field
    sends the form's **browser-default entry list, with empty free-text fields filled
    as a user would type them** — or, for a crawled link's parameter, **that link's
    query**. The URL and e-mail fillers use never-resolving `.invalid` names and are
    sent as they are. *(Amended by FR-FUZZ-67, `CC-FUZZ-0111`, 2026-10-21:)* a default
    naming loopback is sent as given; one naming a host outside the lab is never sent,
    as given or as a stand-in, and its point is inconclusive (FR-AUD-20). A
    sensitive-named or identifier-like value is stored `""` as a placeholder, bound
    fresh before each send, never sent blank. The spider record keeps the raw
    defaults, and `Oracle.confirm` binds the entries.
  - **Never fuzzed:** credential-named parameters from crawl or form sources (ground
    truth is unaffected), submitters, sensitive names, and hidden object selectors.
  - **Never imported:** multipart and destructive forms, and password-bearing forms
    other than in-app login forms (FR-FUZZ-44 supersedes the phase 1 blanket
    password exclusion). ~~POST selector forms~~ *(superseded by FR-FUZZ-43: a POST
    selector is skipped only when a control is settings-named, its select name is
    too short, or the crawler saw it act as a settings form).*
  - **Residuals:**
    - probes complete real submissions, so rows, users or mail are created;
    - ~~forms needing a fresh CSRF token do not confirm~~ *(superseded by FR-FUZZ-67:
      the token is fetched fresh in the probe's session before each send)*;
    - fillers ignore `maxlength` / `pattern`;
    - ~~one confirmation per (url, param, method, location)~~ *(superseded by
      FR-FUZZ-66: one confirmation per request context)*.
- **FR-FUZZ-43** *(forms phase 2: link siblings, header points, POST selectors;
  `CC-FUZZ-0063`, 2026-10-14).*
  - **Link siblings.** A crawled URL's query is a sibling set (a `form` row with
    `enctype` NULL, `core.forms.is_link_set`). A set with two or more names is bound to
    ~~its parameters that no form binds (forms win; the first crawled link wins)~~
    *(superseded by FR-AUD-31 / FR-FUZZ-66: each set is its own context with its own
    rows)*. Values pass `store_adapter.redact_sibling` (a sensitive name or an
    identifier-like raw value is stored `""`, a placeholder bound fresh before each
    send, FR-FUZZ-67). A set with a destructive or credential entry is not
    stored or bound (its parameters stay lone points).
  - **Header points** (`fuzzlab auto --header-points [NAMES]`, crawl points only, **off
    by default**; alone: User-Agent, Referer). One point per crawled 2xx GET page and
    name, after every other point. The URL carries the page's representative query
    (its first link set that holds no placeholder and no host outside the lab,
    FR-FUZZ-67; none: the page alone): a placeholder or a stand-in is never sent. Names pass `core.http.header_point_refusal` (framing,
    routing, method-override and credential headers refused) at the CLI, before the
    store is opened, and again at every sender's header branch
    (`check_send_header`; ground-truth points are explicit). With an identity, header
    points whose lower-bound cost exceeds `budget_total` are refused before the store
    is opened.
  - **Header breaker.** `SeamProbeSender` listens to its main manager's logouts
    (FR-SESS-16). A logout seen on a header probe's response, or on the first main
    send after one, stops every later header probe of the run (`HeaderPointsStopped`,
    raised before the send), unless an isolated copy login (lane B) happened since.
    At most one re-login follows; the stopped points stay `pending` and are reported
    (`metrics["header_breaker"]`, `skipped_points`).
  - **POST selector forms** are fuzzed unless a control name carries a
    `formnav.settings_word`, the select name has fewer than 3 characters, or the
    crawler saw the picker act as a settings form (FR-CRAWL-10). GET selectors are not
    subject to that rule. A POST picker repeated at several actions is fuzzed once (the
    first crawled).
  - **Never relocated** (BUG-0115, PA-0115). A sender or executor that cannot place a
    payload at the point's location refuses; greybox places header probes in headers;
    DOM XSS applies only to query/fragment points; the pipeline's fingerprint probe goes
    through the first query (else form-body) point at its own method with its
    siblings, never a header point. The probe senders' unknown-location
    fallback is pinned by a strict xfail (not fixed; needs a scored ground-truth run).
  - **Reporting.** A breaker trip is reported in `metrics["header_breaker"]` even when no
    later header probe raises; invalid plugin rules are counted in
    `metrics["invalid_plugin_rules"]` / `run_metrics` and printed by `fuzzlab auto`.
  - **Ground-truth evaluation rows.** The 4 `tests/data/auto_summary` goldens' extra
    negatives (+46 = 2 × 23 points) come from the origin-gated header rules evaluating
    on ground-truth points, where they can never apply; they are rule negatives in
    `evaluation`, not training rows (candidates are unchanged).
  - **Residuals:** pages that log a header grow the lab DB per probe; a page that
    changes state on a plain visit is visited once per header probe; a site-wide
    picker routed to different per-page handlers is probed at one page; an
    identifier-like sibling is sent blank, so a gate needing it does not confirm; an
    e-mail default is sent as is (it may trigger mail); a privilege-gated redirect of
    the run's session to the real login page after a header probe trips the breaker
    (fails safe; confirming with `verify_live` first is deferred, BUG-0122).
- **FR-FUZZ-44** *(in-app login forms on an isolated session; `CC-FUZZ-0064`,
  2026-10-14).*
  - **Imported:** a form with exactly one password control, exactly one text, email or
    tel field and nothing else typed (`login_shaped`), unless it is a credential-change
    form. Its password-control names are stored (`form.password_fields`, FR-CORE-31).
  - **Credential-change forms are never imported** (they change the account, which
    isolation cannot protect): two or more password controls; a password-control name
    containing `new`, `conf`, `change`, `reset`, `old`, `curr`, `repeat`, `retype`,
    `verify` or `again` (a bare substring, deliberately: a false match only excludes);
    an action path, sent submitter or hidden name tokenising to `change`, `new`, `set`,
    `reset`, `update`, `edit`, `modify`, `register`, `signup`, `create`, `forgot`,
    `recover`, `activate`, `password`, `passwd`, `pwd`, `pass`, `save`, `admin`,
    `manage`, `account`, `profile` or `users`; or a hidden object selector. Other
    password forms (settings, CAPTCHA) are not imported either.
  - **The password is never fuzzed:** a password control is never a parameter, whatever
    its name, and no parameter on that path with a password-control name is a point.
    Its sibling value is `""`, as stored; the operator's password is never sent there.
  - **Isolated paths:** `isolated_paths_from_store` gives the `url_key` of every path
    with such a form (any method, any point source). `injection_points_from_store`
    drops their points and reports them unless the caller passes `isolated=`; `run_auto`
    registers them with `sender.isolate`, or drops them when the sender cannot isolate.
    greybox-run therefore never receives them.
  - **Sending.** In `SeamProbeSender`, after the destructive gate and the auth-endpoint
    rule (which wins), a send to an isolated path goes on that path's own isolated
    session (FR-SESS-17), created lazily, kept for the run and labelled
    `<identity>#isolated:<n>`; otherwise anonymously, with the reason reported. The run's
    session is never sent there. `RequestsProbeSender` is isolated by construction.
  - **Fallbacks to anonymous (reported):** no isolated-client factory; a rejected,
    non-distinct or capped copy login, at creation or re-login; more than
    `MAX_ISOLATED_SESSIONS` (32) copies; a tripped breaker.
  - **Breakers (run-wide):**
    - *single-session:* the run's session fails `verify_live` after the run's first copy
      login or any copy re-login, or the run's manager reports a logout of the run's
      identity on one of the run's session's origins while a copy is live (a logout
      listener registered, once, before the first copy login; *CC-FUZZ-0080,
      FR-SESS-20:* compared by canonical origin, never host, so another app's logout
      on another port of the host never trips it; lane A's header breaker likewise). Copies are dropped; every isolated path goes
      anonymous; the run's session re-logs in once.
    - *failed-logins:* after 2 failed copy logins, no new copies.
  - **Budget and records.** Isolated sends spend the run's `RequestBudget`; copy logins,
    like the run's own, go through the fetcher and are not budgeted.
    `metrics["isolated_sessions"]` (`isolation_report()`) carries counts, the breaker
    and per-path reasons — fixed texts, never a failure message, URL or credential
    value; `fuzzlab auto` prints it.
    `isolated_copy_logins()` is public (lane A's header breaker reads it).
  - **Out-of-origin sends** *(CC-FUZZ-0080, FR-SESS-20, BUG-0134).* A send the session
    manager made without the session because its origin is not one of the session's
    comes back with `Probe.session = "anonymous (out of origin)"`, copied from the
    decision `prepare` recorded on the request (the declared field
    `Request.session_decision`, CC-CORE-0054; review rounds 1-2, R6/T4; never
    recomputed); the oracle (`oracle._SessionNotes`, around every strategy run) stamps any
    such note on the verdict's `evidence["session"]` (confirming or inconclusive);
    `SeamProbeSender.session_out_of_origin` (the run's manager and every copy) becomes
    `metrics["session_out_of_origin"]`, which `fuzzlab auto` prints. `fuzzlab auto
    --auth-origin ORIGIN` (repeatable; bare, in scope; a usage error before any side
    effect) goes to the run's session manager (FR-SESS-20, R5).
  - **Accepted false positives** (a real login form excluded: a missed finding, never a
    safety risk): Rails `/sessions/new`, Devise `/users/sign_in`, `/admin/login`,
    `/account/login`, `/my-account`, a login button valued `Save`, and bWAPP's
    `ba_weak_pwd.php` and `ba_pwd_attacks_2.php`.
  - **Residuals:**
    - `verify_live` refuses any hop to another host, so an app whose base page
      redirects to an SSO or auth origin always trips the single-session breaker and
      all its isolated paths go anonymous (reviewer B; fails closed);
    - after a probe re-binds a path's throwaway session, later probes of that same path
      run as whichever user it was bound to;
    - per-user state a login handler changes (last login, failed-attempt counters) is
      not isolated; per-IP rate limiting may throttle the lab client;
    - a logout of the run's session unrelated to the copies, while a copy is live, also
      trips the single-session breaker (fails closed); the main-path probe that observed
      it got a login page;
    - an unrecognised, short, low-entropy equal session id is accepted as distinct
      (FR-SESS-17).
