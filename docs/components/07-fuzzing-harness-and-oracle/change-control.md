# Fuzzing Harness and Oracle — Change Control Log

Component code: **FUZZ**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-FUZZ-0025 — Build the M1 timing-differential ReDoS oracle mechanism (`RegexDosStrategy`) (2026-09-22)
- Change: built `RegexDosStrategy` (`fuzzlab/oracle/strategies.py`), the
  `("regular-expression", "redos")` confirmation strategy
  `docs/architecture/oracle-confirmation.md` previously listed only as
  deferred ("could use M1 timing later"). Companion change to
  `CC-LAB-0076` (`docs/components/01-target-lab/change-control.md`), whose
  `node_express` ReDoS lab cells needed a real confirmation mechanism.
  - Registered `category = "regular-expression"` (the reference-folder name
    the oracle-confirmation doc's own "out of scope" list already used),
    `vuln_class = "redos"`, `mechanism = "differential-timing"` (M1); added
    to `default_strategies()` and `_CATEGORY_TO_CLASS`.
  - This is a genuinely new M1 *variant*, not a reuse of the existing
    `ConfirmationStrategy._confirm_timing` helper (already shared by
    `SqliTimingStrategy`/`CommandInjectionStrategy`) with a new template
    list: `_confirm_timing`'s templates each embed an explicit,
    attacker-*requested* delay (`SLEEP({d})`/`sleep {d}`) it checks the
    target both exceeds AND tracks; a ReDoS payload requests no duration at
    all (the blowup is an emergent property of the target's own content,
    which the strategy neither sees nor controls). `RegexDosStrategy`
    instead escalates across `_REDOS_TEMPLATES` -- several independent,
    single-nesting-level classic catastrophic-backtracking shapes -- and
    confirms when **at least two** independently clear a robust-baseline
    threshold (`Baseline.exceeds`, reused from `fuzzlab/oracle/baseline.py`,
    with `floor`/`k` overridden per-strategy to this mechanism's own
    bounded, tens-to-low-hundreds-of-milliseconds probe magnitude rather
    than `_confirm_timing`'s multi-second-tuned defaults). Full design
    rationale, including the nesting-depth-escalation alternative that was
    calibrated and explicitly rejected as unsafely explosive, is in
    `docs/architecture/oracle-confirmation.md`'s new "`regular-expression`
    (ReDoS, CWE-1333)" section and the class's own docstring.
  - `docs/architecture/oracle-confirmation.md` updated: new section
    describing the built mechanism (moved out of the "Out of scope" list at
    the bottom, which is updated to say so).
- Impact (other components / project): additive only -- one new strategy
  class, two registry entries (`default_strategies()`,
  `_CATEGORY_TO_CLASS`), no existing strategy's behavior changed. Consumed
  by `CC-LAB-0076`'s `node_express` ReDoS cells as the class this shape
  needs when scanned live; not yet wired into any live scanning run against
  an external target, and not wired into `fuzzlab/harness/multitarget.py`
  (both out of this change's scope).
- Risk (level; mitigation or accepted-risk justification): Medium,
  documented plainly rather than understated. Unlike every other M1 use in
  this file (SQLi/command-injection, each of which supplies its own exact
  requested delay), this mechanism's confirmation is inherently
  probabilistic against an arbitrary black-box target: it can only detect
  ReDoS when the target's own content happens to contain a run of the
  character class one of `_REDOS_TEMPLATES` targets, which the strategy has
  no way to know in advance. Mitigated by using several templates
  targeting different common run shapes (letters, digits, an alternation)
  to raise the odds, and by stating this limitation explicitly in the
  class's own docstring and in the architecture doc rather than presenting
  this mechanism as equivalent-confidence to the SQLi/cmdi M1 uses. The
  probe-magnitude side of the risk (an uncalibrated timing probe either
  never firing or blowing up unboundedly against a real target) is
  mitigated by the `floor`/`k` calibration recorded in `CC-LAB-0076` and by
  every template in `_REDOS_TEMPLATES` being single-nesting-level only
  (nesting-depth escalation was calibrated and rejected specifically
  because of its unbounded-blowup risk).
- Deliverables:
  - [x] `RegexDosStrategy` class + `_REDOS_TEMPLATES` — done
  - [x] Registered in `default_strategies()` / `_CATEGORY_TO_CLASS` — done
  - [x] Unit tests against a deterministic fake sender
    (`tests/test_oracle_redos.py`: confirms on a vulnerable fake, stays
    fail-closed on a secure/escaped fake, on a single-slow-reading fake,
    and on a within-jitter fake) — done
  - [x] `docs/architecture/oracle-confirmation.md` updated from "deferred"
    to describe the real, built mechanism — done
  - [x] `requirements.md` (`FR-FUZZ-12`) — done
- Effectiveness (assessed 2026-09-22): unit tests pass and correctly
  distinguish a simulated vulnerable target (confirms, needs >=2 templates
  above threshold) from a simulated secure one (does not confirm) and from
  ordinary jitter (does not confirm on a single slow reading or a
  within-tolerance gap). The underlying real-world mechanism (that a real
  regex engine really does blow up on these templates, and that escaping
  really does prevent it) is proven with real execution in `CC-LAB-0076`'s
  `tests/test_labgen_redos.py`, not re-proven here (this entry's own tests
  are decision-logic tests against a fake sender, consistent with how this
  file's other M1/M8/M10 strategies are tested). Not yet assessed against
  a live external target.
### CC-FUZZ-0026 — Give header-carried ground-truth points their own honest skip reason (2026-09-23)

- Change: `fuzzlab.harness.auto.points_from_ground_truth` treated a
  header-located ground-truth point (``location="header"``) as a
  client-only/DOM point, skipping it under the reason string
  ``"client-only/DOM (needs browser execution, M6)"`` — factually wrong: a
  header-carried value has nothing to do with DOM rendering or a browser,
  it is simply not yet expressible by this function's point model or by
  any of `fuzzlab.tools.probesender`'s senders. Found while wiring category
  4's Twitch app into Phase E (`CC-LAB-0176`): its webhook-signature case
  (`TWCH-0001`, `lab/ground-truth-twitch-clone/`) is the project's first
  header-located ground-truth point, and the misleading reason string
  surfaced immediately on inspection. Fixed with a distinct `is_header`
  branch and its own reason
  (``"header-carried injection point (no header-capable point/sender
  wiring yet, FR-FUZZ-13)"``), never folded into the DOM reason. Building
  actual header-injection support (a point type + a header-capable sender)
  is real, sized follow-on work, not attempted here — this change only
  makes the current, correct "cannot be audited yet" outcome honestly
  labeled.
  - **Not routed through the bug protocol**: the *behavior* was already
    correct (the point was, and still is, excluded from probing either
    way) — only the *diagnostic reason string* was inaccurate. No test
    asserted a wrong result, no crash, no regression; this is a clarity
    fix to a message, not a defect in what the function does. Recorded
    here in full regardless, per this component's own bookkeeping
    discipline.
  New/changed files:
  - `fuzzlab/harness/auto.py` (`points_from_ground_truth`)
  - `tests/test_auto.py` (`test_points_from_ground_truth_gives_header_points_their_own_skip_reason`)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md` (`FR-FUZZ-13`, new)
- Impact (other components / project): none outside this function's own
  return value (`skipped`'s reason strings) — the set of points actually
  audited is unchanged (header points were already excluded before this
  change), so no scoring/detection behavior changes for any existing
  ground truth. `tests/test_auto.py`'s own pre-existing assertion (every
  default-lab skip reason ends in `"M6)"`) still holds unchanged, since the
  default `lab/ground-truth/` has no header-located points.
- Risk (level; mitigation or accepted-risk justification): **low**. A
  message-accuracy fix with no behavior change to what is audited;
  verified by re-running the full non-slow suite (1606 passed, same 15
  pre-existing unrelated failures) and category 4's own real live-boot
  Phase E test.
- Deliverables:
  - [x] `points_from_ground_truth` gives header-located points their own,
    accurate skip reason
  - [x] New test proving the reason string is accurate and distinct from
    the DOM/browser one
  - [x] Full non-slow suite re-verified green (no new failures, one new
    pass)
- Effectiveness (assessed 2026-09-23): met — `TWCH-0001`'s skip reason no
  longer claims a browser is the blocker.

### CC-FUZZ-0024 — Wire M10 grey-box confirmation into the oracle pipeline (2026-09-22)
- Change: built the seam layer for the M10 grey-box mechanism whose pure decision
  logic (`fuzzlab/greybox/confirm.py::greybox_confirms()`/`m10_evidence()`) and
  source protocols (`fuzzlab/greybox/coverage.py::CoverageSource`,
  `fuzzlab/greybox/dbfault.py::DbFaultSource`, plus their `InMemory*` fakes and live
  `File*` readers) were already built and unit-tested in an earlier Phase 3 lane.
  Added `GreyboxConfirmationStrategy` to `fuzzlab/oracle/strategies.py`: mechanism
  `grey-box-coverage`, `applies()` scoped to `category in ("sql-injection", "xss")`
  (a cross-cutting secondary layer, same pattern as M8 alongside M1 for
  command-injection — not one class). It takes an optional `CoverageSource` and an
  optional `DbFaultSource` by constructor injection (both default `None`) and
  no-ops (`confirm()` returns `None`, no probe sent) when neither is given — same
  seam shape as the M6 `BrowserExecutor`/M8 `OobListener`. When at least one source
  is given, it further requires the `sender` to expose `send_correlated(url, param,
  value, *, method, location) -> (Probe, request_id)` (the contract already
  established for the live grey-box run driver, `fuzzlab/greybox/run.py`'s
  `RequestsCorrelatingSender`) so its one probe can be matched back to the
  coverage/DB-fault side channel by a fresh `X-Fzl-Cov`-style id; without a
  `send_correlated`-capable sender it also no-ops (fail-closed, never a guess).
  Wired into `default_strategies(coverage=None, dbfault=None)`,
  `Oracle(coverage=None, dbfault=None)` (`fuzzlab/oracle/oracle.py`),
  `run_pipeline(coverage=None, dbfault=None)` (`fuzzlab/harness/pipeline.py`), and
  `run_auto(coverage=None, dbfault=None)` (`fuzzlab/harness/auto.py`); `fuzzlab
  auto` gained `--greybox-coverage-file DIR`/`--greybox-dbfault-file DIR` (default
  off, same shape as `--oob`), which construct `FileCoverageSource`/
  `FileDbFaultSource` against that directory only when passed.
- **Provenance note**: this lane was originally built on the diverged branch
  `claude/trusting-noether-heon0n` as `CC-FUZZ-0020`/`FR-FUZZ-9` (its own local
  numbering), independently of this branch's Wave 1a–3 dispatch. Cherry-picked and
  renumbered on merge into this branch — `CC-FUZZ-0020` and `FR-FUZZ-9` here
  already belonged to this branch's own D0a (`--dry-run` on `fuzz`/`auto`) and
  B0's coverage-frontier `metric_series` emitter, an unrelated same-numbered
  collision from independent, non-communicating concurrent work (see
  `docs/PREVENTIVE_ACTIONS.md` PA-0031 — pre-assigned numbers only prevent
  collisions *within* one dispatch; they cannot prevent collisions against a
  wholly separate branch neither dispatch knew existed). No functional content
  changed from the original commit; only IDs and cross-references were
  renumbered (`CC-FUZZ-0020`→`0024`, `FR-FUZZ-9`→`11`) and this note added.
- Impact (other components / project): FUZZ only — additive. `Oracle.__init__` and
  `default_strategies()`/`run_pipeline()`/`run_auto()` gained optional
  `coverage=None`/`dbfault=None` keywords; every existing caller that omits them is
  unaffected (no behavior change, same as `oob=None`/`browser=None`). Sql-injection
  and xss candidates that the black-box strategies leave unconfirmed can now be
  confirmed via covered-sink (+DB-fault for sqli) evidence, *once* both an
  instrumented lab's coverage/DB-fault side channel and a correlating oracle probe
  sender exist — neither exists yet in this repo, so in a live `fuzzlab auto` run
  today the new flags construct real `FileCoverageSource`/`FileDbFaultSource`
  readers but the strategy still no-ops (the shipped `RequestsProbeSender`/
  `SeamProbeSender` do not implement `send_correlated`). That live correlating
  sender and the on-host pcov/DB-fault shim remain out of scope here (on-host
  last-mile work, `docs/ON_HOST_TASKS.md`) — this change is deliberately scoped to
  the offline-buildable wiring layer only, not the live plumbing.
- Risk (level; mitigation): low — pure additive wiring with every new keyword
  defaulting to `None`/off, so no existing caller's behavior changes (verified by
  the full fast suite staying green). The one new behavior (sending a probe) is
  gated behind *both* an injected source and a `send_correlated`-capable sender, so
  it cannot fire against any sender or run configuration that exists in this repo
  today. Mitigated further by: (1) fail-closed by construction — `confirm()`
  returns `None` on either gate missing or when `greybox_confirms()` itself returns
  `False`, never a guess; (2) `applies()` scoped tightly to the two categories
  `greybox_confirms()` actually has a rule for, so it never masquerades as a
  confirmer for classes it cannot judge; (3) tests on the real strategy against
  real `InMemoryCoverageSource`/`InMemoryDbFaultSource` fakes (not mocks of this
  strategy's own code, per PA-0005), including the full `Oracle.confirm()` pipeline
  end to end.
- Deliverables:
  - [x] `GreyboxConfirmationStrategy` (M10, categories `sql-injection`/`xss`,
    constructor-injected `CoverageSource`/`DbFaultSource`, fail-closed no-op
    without a source or a correlating sender) — `fuzzlab/oracle/strategies.py` —
    done.
  - [x] Wired into `default_strategies()`, `Oracle`, `run_pipeline()`, `run_auto()`,
    and `fuzzlab auto --greybox-coverage-file`/`--greybox-dbfault-file` — done.
  - [x] Tests with real `InMemoryCoverageSource`/`InMemoryDbFaultSource` fakes (not
    mocks of our own code): `tests/test_oracle_greybox.py` (12 tests) — done,
    re-run clean against this branch's tree (22/22 with `test_oracle_oob.py`
    combined) at merge time.
  - [x] `requirements.md` `FR-FUZZ-11` added; `docs/ARCHITECTURE.md` Oracle status
    note updated — done.
  - [x] Full suite green on this branch's merged tree — done (see merge commit).
  - [ ] Live correlating oracle probe sender (a `send_correlated`-capable
    `RequestsProbeSender`/`SeamProbeSender` variant attaching a real `X-Fzl-Cov`
    header) and the on-host pcov/DB-fault shim behind `FileCoverageSource`/
    `FileDbFaultSource` — on-host last-mile, tracked in `docs/ON_HOST_TASKS.md`,
    not started here.
- Effectiveness (assessed 2026-09-22): effective for the wiring layer —
  `tests/test_oracle_greybox.py` proves the strategy confirms sqli only with both
  sink-covered and db-fault evidence, confirms xss with sink-covered evidence
  alone, no-ops without a source, no-ops without a `send_correlated`-capable
  sender, is registered in `default_strategies()`, and integrates through the full
  `Oracle.confirm()` pipeline. Live-target effectiveness is unverified and
  unverifiable in this sandbox — it depends on on-host infra this change does not
  build (tracked above, not a regression this lane introduced).

### CC-FUZZ-0023 — Build M8 out-of-band (OOB) callback mechanism (2026-09-22)
- Change: implemented the previously-unbuilt M8 mechanism from
  `docs/architecture/oracle-confirmation.md` — out-of-band callback confirmation for
  blind injection classes with no direct response difference. Added
  `fuzzlab/oracle/oob.py::OobListener`: a loopback-only (`127.0.0.1`/`localhost`
  only — raises `ValueError` on any other host), in-memory, per-run HTTP callback
  tracker (`register()` mints an unguessable token, `callback_url()` gives the URL to
  embed in a payload, `wait_for()` polls for a hit); it binds no socket until
  `start()` is called (default-off, mirroring the M6 `BrowserExecutor`/proxy/desync
  dual-use gating pattern in this project — not a general-purpose, publicly reachable
  collaborator-style service). Added `CommandInjectionOobStrategy` (mechanism
  `oob-callback`, category `command-injection`) to `fuzzlab/oracle/strategies.py`:
  embeds a fresh canary URL in `curl`/`wget` shell-fetch payloads and confirms only if
  that exact token is later requested; it takes the listener by injection and no-ops
  (returns `None`, no probe sent) when none is given, so it never reaches for a real
  listener on its own. Wired into `default_strategies(oob=...)`, `Oracle(oob=...)`
  (`fuzzlab/oracle/oracle.py`), `run_pipeline(oob=...)`
  (`fuzzlab/harness/pipeline.py`), and `run_auto(oob=...)`
  (`fuzzlab/harness/auto.py`); `fuzzlab auto` gained `--oob` (default off, same shape
  as `--browser`), which constructs and starts the listener only when passed and
  tears it down in a `finally` block after the run.
- **Provenance note**: this lane was originally built on the diverged branch
  `claude/trusting-noether-heon0n` as `CC-FUZZ-0019`/`FR-FUZZ-8` (its own local
  numbering), independently of this branch's Wave 1a–3 dispatch. Cherry-picked and
  renumbered on merge — `CC-FUZZ-0019` and `FR-FUZZ-8` here already belonged to
  this branch's own C1/M8-wiring lane (an unrelated, same-numbered lane about
  wiring mutation-engine *variants* into the attempt path — a task-numbering
  coincidence with oracle mechanism "M8", not the same M8). No functional content
  changed from the original commit; only IDs and cross-references were renumbered
  (`CC-FUZZ-0019`→`0023`, `FR-FUZZ-8`→`10`) and this note added.
- Impact (other components / project): FUZZ only — additive. `Oracle.__init__` and
  `default_strategies()`/`run_pipeline()`/`run_auto()` gained an optional `oob=None`
  keyword; every existing caller that omits it is unaffected (no behavior change,
  same as `browser=None`). Blind command injection (Tier 3,
  `docs/architecture/oracle-confirmation.md`) now has a working M8 confirmer
  alongside the existing M1 timing one — `applies()` scopes both to the
  `command-injection` category, so the oracle tries timing first, OOB second, and a
  target that suppresses timing signal but still executes the shell fragment (fetches
  the canary) is now confirmable. No schema change (findings already carry an
  arbitrary `mechanism` string). No traffic sent unless `--oob`/`--authorized` are
  both given, and the listener never leaves loopback.
- Risk (level; mitigation): low-medium — a new local network listener is more
  sensitive than a pure library change. Mitigated by: (1) the loopback-only guard in
  `OobListener.__init__` (raises before binding on any non-loopback host); (2)
  default-off at every layer (constructor argument defaults to `None`; CLI flag
  defaults to `False`); (3) no DNS component, no external reachability, no
  persistence beyond the process — it cannot function as a general-purpose OOB
  interaction/collaborator service; (4) real tests exercising the actual socket (not
  a mock) confirm it only ever records a hit for the exact token requested and never
  cross-wires tokens; (5) fail-closed by construction — `confirm()` returns `None` on
  timeout or when no listener is injected, never a guess.
- Deliverables:
  - [x] `OobListener` (loopback-only, default-off, real HTTP listener + token
    register/callback_url/wait_for) — `fuzzlab/oracle/oob.py` — done.
  - [x] `CommandInjectionOobStrategy` (M8, category `command-injection`) — done.
  - [x] Wired into `default_strategies()`, `Oracle`, `run_pipeline()`, `run_auto()`,
    and `fuzzlab auto --oob` — done.
  - [x] Tests on the real listener and the real strategy (not mocks of our own code):
    `tests/test_oracle_oob.py` (10 tests) — done.
  - [x] `requirements.md` `FR-FUZZ-10` added; `docs/ARCHITECTURE.md` Oracle status
    note updated — done.
  - [x] Full suite green on this branch's merged tree — done (see merge commit).
- Effectiveness (assessed 2026-09-22): effective — `tests/test_oracle_oob.py` proves
  the listener records a real hit end to end (real socket, real HTTP request via
  `urllib`), times out cleanly on a benign/secure target, does not cross-wire two
  concurrent tokens, and that `Oracle.confirm()` reaches a `mechanism="oob-callback"`
  verdict through the full pipeline wiring (not the strategy in isolation). Full
  fast suite on this branch's merged tree: see the merge commit for the exact count.

### CC-FUZZ-0022 — `--dry-run` CLI flag on `greybox-run` (lane D0b) (2026-09-22)
- Change: `fuzzlab/greybox/greybox_cli.py::build_parser()` gained `--dry-run` (via
  the shared `fuzzlab/cli_dryrun.add_dry_run_flag()`), and `main()` checks
  `args.dry_run` first — before the `--authorized` gate and before any
  `contract.load()`/points-sourcing/`Store()`/sender/coverage-source/dbfault-source/
  lab-control construction — and calls `fuzzlab/cli_dryrun.report("greybox-run",
  args)`, reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then returns 0 before any probe/side-
  channel read happens. No traffic is sent. `greybox-run` was already registered
  in `fuzzlab/web/commandspec.py`'s `_REGISTRY` (introspecting
  `greybox_cli.build_parser()` directly), so the planned argv/display
  automatically reflects every flag on the parser — including the
  `--mutation-variants`/`--max-mutation-variants`/`--allow-destructive` flags Lane
  C1/M8-wiring (`CC-FUZZ-0019`) added to this same parser — with no separate
  wiring needed for those three flags specifically. Sequenced after Wave C1
  (genuine file overlap on `fuzzlab/greybox/greybox_cli.py`, per the build plan's
  D0b entry), on top of `CC-FUZZ-0019`. Deliberately bypasses the `--authorized`
  requirement for the dry-run preview itself (nothing is sent either way,
  mirroring D0a's `CC-FUZZ-0020` and the web launcher's own dry-run route).
  Unchanged when `--dry-run` is absent. Completes lane group B's D0
  (`--dry-run` on every CLI entry point); D0a (`CC-FUZZ-0020`, plus CC-CRAWL-0007/
  CC-AUD-0015/CC-MUT-0010/CC-PROXY-0017/conditional CC-UI-0027) covered the other
  six commands.
- Impact (other components / project): FUZZ only, plus an incidental UI effect —
  `greybox-run`'s introspected `build_parser()` now surfaces a `--dry-run` checkbox
  in the web launcher automatically alongside the pre-existing mutation-variant
  flags (no `fuzzlab/web/app.py` change; the web launcher already has its own
  dry-run route, unaffected by this CLI-level flag). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect, placed ahead of the `--authorized` check by design (documented above so
  it isn't mistaken for a gate bypass on real execution). Mitigated by
  `tests/test_cli_dry_run.py` (new greybox-run cases: flag present; the plan
  reflects `--mutation-variants`/`--max-mutation-variants`/`--allow-destructive`
  when passed; `run_greybox`/`points_from_store`/`RequestsCorrelatingSender`/
  `Store.__init__`/`import_spider` patched to raise if called; a case also asserts
  `would_execute: False` is reported when `--authorized` is absent) and the
  unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `greybox-run`'s parser — done.
  - [x] Short-circuit ahead of the `--authorized` gate in `main()`, calling the
    shared `cli_dryrun.report()` — done.
  - [x] Dry-run preview correctly reflects the C1-added mutation-variant flags —
    done (verified via `introspect()`'s generic parser walk, no special-casing
    needed; covered by a dedicated test).
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab greybox-run --dry-run`
  prints the planned argv/command (including any mutation-variant flags passed)
  and returns 0 without constructing a `Store`, sender, coverage/dbfault source, or
  lab control, and without reading `--ground-truth`/`--spider-db`; verified
  directly and via the new tests.
### CC-FUZZ-0021 — coverage-frontier `metric_series` emitter (lane B0, Wave 1b) (2026-09-22)
- Change: `fuzzlab/greybox/run.py::run_greybox()` now emits a per-attempt
  `metric_series` row tracking the run-wide `CoverageFrontier`'s growth,
  additive alongside the pre-existing `greybox_frontier_size` `run_metrics`
  end-of-run total. New private helper `_record_coverage_metric(logger, step,
  frontier)` writes `source="coverage"`, `key="coverage/lines"`, `step=`
  the running attempt count, `value=` the frontier's current `.size` — per
  `docs/UI_IMPLEMENTATION_PLAN.md` §3 (B0)'s resolved schema notes (R-05),
  which name `coverage/lines` as the worked example key for this exact
  source. `run_greybox()` opens one `fuzzlab.core.store.MetricLogger(store,
  run_id, source="coverage")` at the top of the run (alongside the existing
  `frontier = CoverageFrontier()`), calls `_record_coverage_metric` once per
  attempt right after `summary["attempts"] += 1`, and flushes it once at the
  end of the run before the summary is returned. Follows the same
  small-function-slotted-into-the-loop pattern lane C1 established in this
  file (`mutation_variant_probes` / `_record_accepted_variant`) specifically
  so this sub-lane could land cleanly after it. No existing coverage-tracking
  or attempt-path behavior changed — this is additive metric emission only;
  `frontier`, `summary`, the `attempt`/`run_metrics` writes, and the
  mutation-variant wiring (`CC-FUZZ-0019`) are all untouched.
- Impact (other components / project): FUZZ only for the write path (new
  dependency on `fuzzlab.core.store.MetricLogger`/`metric_series`, landed by
  `CC-CORE-0018`). Enables — but does not itself build — a future UI reader
  (`docs/UI_IMPLEMENTATION_PLAN.md`'s U5 lane, "metric_series tab" /
  Datasette-style store exploration) to chart per-run coverage-frontier
  growth. This is the one B0 emitter sub-lane the build plan
  (`docs/PARALLEL_LANE_BUILD_PLAN.md`, "B0/C1 file-overlap risk" note) flagged
  as needing to land after C1's M8-wiring (`CC-FUZZ-0019`) rather than in
  parallel with it, since both touch `run.py`'s attempt/summary loop; it was
  dispatched only after confirming `CC-FUZZ-0019`/`CC-FUZZ-0020` were already
  merged into the base branch. No interface/contract change to
  `run_greybox()`'s signature or return value (`summary` dict unchanged).
- Risk (level; mitigation): low — purely additive write path (one buffered
  `MetricLogger` per run, flushed once at the end plus its own
  `flush_every=200` periodic flush; non-finite values are dropped with a
  warning by `log_scalar`/`MetricLogger.log` itself, never reaching this
  component). No change to reward shaping, screening, M10 confirmation, or
  the `attempt`/`run_metrics` tables. `MetricLogger` holds `store.conn` for
  the lifetime of one `run_greybox()` call on the same thread that already
  drives every other `store.conn` write in this function, so PA-0023
  (thread-affine `sqlite3` connection handles) does not apply — no new
  cross-thread caching is introduced.
- Deliverables:
  - [x] `_record_coverage_metric()` helper + wiring into `run_greybox()`'s
    attempt loop and end-of-run flush — done.
  - [x] Tests: `tests/test_greybox_live.py::test_run_greybox_emits_coverage_metric_series`
    and `::test_run_greybox_coverage_metric_series_isolated_per_run` — done.
  - [x] Confirmed lane C1's existing tests in `tests/test_greybox_live.py`
    pass unmodified (18/18, including the 16 pre-existing C1/base tests) —
    done.
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    updated in place with the new emission behavior — done.
  - [x] `CHANGELOG.md` line — done.
- Effectiveness (assessed 2026-09-22): intent achieved — `run_greybox()` now
  writes `coverage/lines` rows to `metric_series` per attempt, verified by
  the new tests reading them back directly from the store (values match the
  frontier's growth exactly, isolated correctly per `run_id`), with no
  regression in any pre-existing `test_greybox_live.py`/`test_greybox.py`
  test.

### CC-FUZZ-0020 — `--dry-run` CLI flag on `fuzz` + `auto` (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/blind_sqli_fuzzer.py::build_parser()` and
  `fuzzlab/harness/auto_cli.py::build_parser()` both gained `--dry-run` (via the
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). Both `main()`s check
  `args.dry_run` first — before the `--authorized` gate — and call
  `fuzzlab/cli_dryrun.report("fuzz", args)` / `report("auto", args)` respectively,
  reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then return 0 before any sender/`Store`/
  oracle is constructed. No probe or confirmation traffic is sent. Deliberately
  bypasses the `--authorized` requirement for the dry-run preview itself (nothing is
  sent either way, mirroring the web launcher's own dry-run route, which also does
  not require `authorized`). Unchanged when `--dry-run` is absent. This is one
  reserved number covering both commands since they land in a single lane/commit
  (per the plan's numbering note); `fuzzlab greybox-run` is explicitly out of scope
  here — that is lane D0b's `CC-FUZZ-0022`, sequenced after Wave C1's `CC-FUZZ-0019`
  M8-wiring lane, which this lane does not touch.
- Impact (other components / project): FUZZ only, plus an incidental UI effect — see
  CC-UI-0027 (introspected `build_parser()` surfaces the new checkbox for both `fuzz`
  and `auto` in the web launcher automatically; `fuzzlab/web/app.py` untouched). No
  schema/store change; no interaction with Wave C1's M8-wiring (different files:
  that lane touches `fuzzlab/greybox/run.py`/`greybox_cli.py`, this lane does not).
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect, placed ahead of the `--authorized` check by design (documented above so it
  isn't mistaken for a gate bypass on real execution). Mitigated by
  `tests/test_cli_dry_run.py` (fuzz + auto cases: flag present, report printed,
  `establish_baseline`/`run_fuzzing_cycle` and `run_auto`/`Store.__init__` patched to
  raise if called; a fuzz case also asserts `would_execute: False` is reported when
  `--authorized` is absent, i.e. the preview correctly reflects that a real run would
  be refused) and the unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `fuzz`'s and `auto`'s parsers — done.
  - [x] Short-circuit ahead of the `--authorized` gate in both `main()`s, calling the
    shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs, for both commands —
    done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab fuzz --dry-run` and
  `fuzzlab auto --dry-run` both print the planned argv/command and return 0 without
  constructing a sender, `Store`, or oracle; verified directly and via the new tests.
### CC-FUZZ-0019 — Wire mutation-engine variants into `greybox-run`'s attempt path (Lane C1/M8-wiring) (2026-09-22)
- Change: `docs/PHASE_8_PLAN.md`'s T8.5 ("emit accepted variants into the attempt
  path") only reached the standalone `fuzzlab mutate-run` CLI
  (`fuzzlab/mutation/cli.py`/`fuzzlab/mutation/run.py`) — confirmed before this
  change: no `mutation`/`variant` references anywhere in `fuzzlab/greybox/run.py`
  or `fuzzlab/greybox/greybox_cli.py`. `fuzzlab/greybox/run.py` now wires the
  mutation engine into the **main harness's own** attempt loop:
  - New `mutation_variant_probes()` (function boundary kept separate from the main
    loop, per the build-plan's note that a later lane adds a `metric_series`
    emitter to this same file): given the point's existing sqli/xss `ProbeSpec`s,
    applies up to `max_variants` of the mutation engine's operators
    (`fuzzlab/mutation/operators.py`, T8.1) per base payload and keeps only the
    ones the semantics validator (`fuzzlab/mutation/semantics.py`, T8.1/
    NFR-MUT-semantics) judges meaning-preserving. Skips the `url-encode` operator
    here specifically, since the probe transport (`requests`' `params=`/`data=`)
    would percent-encode an already-percent-encoded value a second time.
  - `run_greybox(..., mutation_variants: bool = False, max_mutation_variants: int
    = 2, allow_destructive: bool = False)`: when `mutation_variants` is set, each
    point's ordered probe list is extended with that point's mutation variants,
    which then go through the **exact same** send/screening/reward/coverage/
    `record_attempt_signals` path as any other probe (one `attempt` row each,
    tagged `mutation_variant: true` in `features_json`, `payload_family =
    "mutation:<operator-id>"`).
  - New `_record_accepted_variant()`: a mutation-derived probe that actually hit
    (screening > 0) or reached new code (`new_lines > 0`) when probed live is
    written back to `payload_variant` via the existing, destructive-gated
    `fuzzlab.mutation.catalog.record_variant` (NFR-MUT-safe unchanged — same
    gate, same default-off `allow_destructive`) — exactly the write-back T8.5
    describes, now reachable from `greybox-run` too, not only `mutate-run`.
  - New summary/`run_metrics` counters: `mutation_variants_probed`,
    `mutation_variants_recorded` (`greybox_mutation_variants_probed`/
    `_recorded`, only recorded when the flag is on).
  - `greybox_cli.py`: new opt-in flags `--mutation-variants`, `--max-mutation-
    variants` (default 2), `--allow-destructive` (mirrors `mutate-run`'s own
    flag). The existing `--authorized` gate is unchanged and still required
    before anything is sent — this lane does not touch or weaken it; the new
    traffic is additional probes sent through the same already-gated sender, not
    a new unauthenticated path.
  - Default behavior is unchanged: `mutation_variants` defaults to `False`, so
    `greybox-run` without the new flag sends exactly the same probes as before
    (verified by a dedicated regression test).
- Impact (other components / project): FUZZ (`greybox/run.py`,
  `greybox_cli.py`) now has a direct, opt-in dependency on MUT
  (`fuzzlab.mutation.catalog`/`operators`/`semantics`) at import time — no
  circular import (MUT's own live-search path only imports `greybox.run` inside
  a function body, for its `make_coverage_fn`). `payload_variant` rows can now
  originate from a `greybox-run`, not only a `mutate-run`; existing readers of
  that table (`catalog.list_variants`) are unaffected — same schema
  (migration 8), no new columns. No change to the oracle's finding-writing path
  or to M10 (`greybox/confirm.py`) — mutation variants feed the attempt path
  exactly like any other probe, they are not a new confirmation mechanism.
- Risk (level; mitigation): low — additive and off by default. The new code path
  only runs when `--mutation-variants` (or `mutation_variants=True`) is passed;
  every existing call site and test keeps its old behavior (`ProbeSpec` gained
  two trailing-default fields, `base`/`operators`, so old positional/keyword
  construction is unaffected). Extra live traffic when opted in is bounded by
  `max_mutation_variants` per attack probe (NFR-MUT-bounded) and still requires
  `--authorized`. Mitigated by dedicated regression tests (below) plus the full
  suite green.
- Deliverables:
  - [x] `mutation_variant_probes()` in `fuzzlab/greybox/run.py` — done.
  - [x] `run_greybox(mutation_variants=..., max_mutation_variants=...,
    allow_destructive=...)` wiring + `_record_accepted_variant()` write-back —
    done.
  - [x] `greybox_cli.py` `--mutation-variants`/`--max-mutation-variants`/
    `--allow-destructive` flags, passed through; summary print updated — done.
  - [x] Tests in `tests/test_greybox_live.py`:
    `test_mutation_variant_probes_generates_preserving_variants`,
    `test_mutation_variant_probes_none_for_unclassed_kind`,
    `test_run_greybox_consumes_mutation_variants_into_attempt_path` (asserts
    extra `attempt` rows + `payload_variant` write-back with correct
    provenance), `test_run_greybox_mutation_variants_off_by_default`
    (backward-compat regression) — done.
  - [x] CHANGELOG.md line — done.
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md` updated
    (new FR-FUZZ-8) — done.
  - [ ] T8.7's on-host exit criterion (WAF-enabled live verification) — out of
    scope for this lane per the build plan; left for a later on-host pass.
- Effectiveness (assessed 2026-09-22): effective offline — confirmed via grep
  that `fuzzlab/greybox/run.py`/`greybox_cli.py` had zero mutation/variant
  references before this change; after, `run_greybox` sends mutation-engine
  variants through the attempt path and records the accepted ones to
  `payload_variant` when opted in, proven by the new tests
  (`tests/test_greybox_live.py`), with the no-flag default path unchanged
  (regression test). On-host WAF-evasion verification (T8.7) is a separate,
  later exit check, not this lane's scope.

### CC-FUZZ-0018 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: the fuzz/oracle activities factor their argparse setup into `build_parser()`, with
  `main()` delegating — `fuzzlab/tools/blind_sqli_fuzzer.py` (`parse_args()` delegates;
  `prog="fuzzlab fuzz"`), `fuzzlab/harness/auto_cli.py`, and `fuzzlab/greybox/greybox_cli.py`
  (both keep the `p` reference so `p.error(...)` still works). Behavior-preserving — same
  flags, defaults, gates, and parsing.
- Impact: lets the web launcher introspect the fuzz/auto/greybox-run flags (CC-UI-0011).
  No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()` on fuzz/auto/greybox-run; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds these specs from the
  real parsers (authorized gate derived from the `--authorized` flag).

### CC-FUZZ-0017 — Fix (BUG-0016): per-point differential coverage in `greybox-run` (2026-09-21)
- Change: `greybox/run.py::run_greybox` now credits an attack's coverage as a **per-point
  differential** — baselines are sent first to establish each point's benign coverage, and
  an attack's `new_lines_vs_baseline` drives the reward novelty and the summary
  `newcode_reward`. The global `CoverageFrontier` is retained only for the run-wide
  exploration total (`greybox_novel_lines`/`frontier_size`), not for per-attempt reward, so
  the benign baseline no longer consumes the novelty (it now scores ~0, a true control).
  Added a `coverage_lines_seen` total + metric; `greybox_cli` prints it and only warns
  ("no application coverage captured") when it is 0 (the real shim-not-wired case) instead
  of the old contradictory `newcode <= baseline` NOTE.
- Impact (other components / project): fixes the self-contradictory Part E output (step-5
  NOTE vs step-6 PASS) and makes the T3.7 "reaching new code → higher reward" property
  actually demonstrable (attack-vs-baseline), not incidentally passed via db_fault. No
  schema change; `attempt.features_json` now carries `new_lines_vs_baseline`/`cov_lines`.
  The Part F runbook exit was reframed (verify the bandit by posteriors; oracle-probes
  metric is a follow-up) — same BUG-0016 class.
- Risk (level; mitigation): low — reward is now a cleaner controlled comparison; the exit
  still passes and is more meaningful. Tests (`tests/test_greybox_live.py`): baseline earns
  0, attack new-code is per-point, and a regression proves a 2nd point's attack still
  scores new lines when those lines were globally seen by the 1st point. Suite 416 passed /
  6 skipped.
- Deliverables:
  - [x] Per-point differential coverage + `coverage_lines_seen`; corrected NOTE — done.
  - [x] Tests incl. the global-frontier-starvation regression — done.
  - [x] Part F runbook reframe; RCA `docs/bugs/BUG-0016-*`; PA-0017 — done.
  - [ ] Oracle-probes-per-finding metric so Part F can show the bandit's request savings — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — benign baselines score 0, an
  attack reaching new branches scores strictly higher, and the shim-not-wired NOTE only
  fires on genuinely empty coverage. On-host re-run via `scripts/greybox_e2e.sh`.

### CC-FUZZ-0016 — Live grey-box last mile: file-backed sources + `greybox-run` (T3.2–T3.7) (2026-09-21)
- Change: built the on-host "run" side of Phase 3 so `docs/ON_HOST_RUNBOOK.md` Part E is a
  single command. New live implementations behind the existing seams:
  `greybox/coverage.py::FileCoverageSource` and `greybox/dbfault.py::FileDbFaultSource`
  read the lab shim's per-request side channel (one JSON file per `X-Fzl-Cov` id, holding
  both covered app lines and a `db_fault`/`db_error` marker); `greybox/reset.py::
  ScriptLabControl` drives `labctl.sh snapshot|restore` (fail-loud). New driver
  `greybox/run.py` (`run_greybox`, `RequestsCorrelatingSender`, `GreyboxPoint`,
  point builders) sends a benign baseline + SQLi/XSS probes per point, reads coverage
  novelty + db_fault, folds them via the already-built `shaped_reward`, writes an
  `attempt` row enriched through `record_attempt_signals`, resets between stateful points,
  and records grey-box `run_metrics`. Exposed as `fuzzlab greybox-run`
  (`greybox/greybox_cli.py`, `cli.py`), requires `--authorized`.
- Impact (other components / project): realizes the T3.2–T3.7 exit (a new-code request
  scores strictly higher; error-based SQLi sets `db_fault=1`) without touching the shared
  oracle. M10 is **advisory** in the driver (counts where grey-box would confirm via
  `greybox/confirm.py`); the oracle stays the sole, fail-closed finding-writer, and folding
  M10 into `Oracle.confirm` with a per-candidate sink line remains a follow-up (the
  contract has `vuln_class`/`sink_context` but no sink line). Depends on the target-lab
  instrumentation (CC-LAB-0009). Note (design correctness): the DB-fault signal is read
  from the same per-request side-channel file as coverage, not by tailing the MariaDB log,
  so it is attributed to exactly one request (no race).
- Risk (level; mitigation): low — all new code is additive and lab-only (gated on
  `--authorized`); the sources fail safe (missing/half-written files → no coverage / no
  fault, never a raise). Mitigated by 11 offline tests (`tests/test_greybox_live.py`):
  file sources incl. cid sanitization/missing-file, `ScriptLabControl` sequencing +
  fail-loud, `run_greybox` reward ordering + db_fault propagation + enriched rows +
  run_metrics + reset sequencing, and the correlating sender's header. Suite 405 passed /
  4 skipped.
- Deliverables:
  - [x] `FileCoverageSource` / `FileDbFaultSource` (live readers) — done.
  - [x] `ScriptLabControl` (live DB snapshot/restore) — done.
  - [x] `run_greybox` driver + `fuzzlab greybox-run` CLI — done.
  - [x] Offline tests; runbook Part E rewritten to the one-command flow — done.
  - [ ] Fold M10 into `Oracle.confirm` with a per-candidate sink line (T3.6 deepening) — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — enriched attempts show the
  reward-ordering and db_fault exit properties end to end offline. The live on-lab exit is
  driven by `scripts/greybox_e2e.sh` (self-tests the side channel, then runs the pass).

### CC-FUZZ-0015 — Bandit orders oracle mechanisms in the confirm loop (T4.3) (2026-09-21)
- Change: `Oracle` takes an optional `scheduler`; `confirm` now orders its **applicable
  mechanisms** via `scheduler.order(context, arms)` (arm = `vuln_class:mechanism`,
  context = `category:sink|location`) and `update`s the scheduler per tried mechanism
  (1.0 on confirm, 0.0 on a tried-but-failed one), stopping at the first confirmation.
  So the productive mechanism is front-loaded and its confirmation short-circuits the
  expensive ones (e.g. skip the timing probes when error/boolean confirm). Threaded
  through `run_pipeline`/`run_auto`; `fuzzlab auto --bandit` constructs a
  `ThompsonBandit` (priors from `arm_priors`), loads posteriors from the store before
  the run and saves them after (persisted learning across runs). `ConfirmationStrategy`
  gained the `arm` id. Default (no scheduler) is unchanged (fixed cheapest-first order).
- Impact (other components / project): the Phase 4 request-reduction lever — fewer
  oracle probes once the bandit learns which mechanism confirms per context. No effect
  unless `--bandit`/a scheduler is passed. Posteriors live in `bandit_posteriors`.
- Risk (level; mitigation): low/medium — reordering changes which probes run, but the
  oracle stays fail-closed (ordering never changes *whether* something is confirmable,
  only the order tried) so no FP. Mitigated by tests: a trained bandit reaches the
  confirming mechanism with fewer probes than a fresh one; the oracle updates the
  scheduler; no-scheduler keeps the fixed order; `run_auto --scheduler` learns and
  persists. Suite 179 passed / 2 skipped.
- Deliverables:
  - [x] `Oracle` scheduler ordering + per-arm updates; `strategy.arm` — done.
  - [x] `run_pipeline`/`run_auto` scheduler passthrough; `auto --bandit` load/save — done.
  - [x] Tests (fewer probes when trained; updates; no-scheduler unchanged; persistence) — done.
  - [ ] On-lab exit (T4.6): bandit vs uniform on hits-per-1000-requests — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — a trained bandit cuts wasted
  probes and posteriors persist; the live request-reduction measurement is on-host.

### CC-FUZZ-0014 — Stored-XSS auto-wiring (source_url → store endpoint) (2026-09-21)
- Change: `auto`'s ground-truth sourcing now also emits **stored-XSS** observe points,
  taken from the ground-truth *cases* (`vuln_class=xss-stored` with a `source_url`),
  which the enumerated *points* file does not carry. Each becomes an `InjectionPoint`
  on the render URL with `store_url`/`store_param` set to the case's `source_url`
  (CC-AUD-0013 added those fields + their candidate-evidence); the pipeline threads
  them into the `Candidate`, and `StoredXssStrategy` plants the payload at the store
  endpoint and observes the render page (M6). Audited only with a browser; without one
  the stored point is reported as a skipped gap.
- Impact (other components / project): closes the last DOM/stored detection gap in
  `auto` — with `--browser`, `profile.php` stored XSS (planted via `edit_profile.php`)
  is confirmed as `xss-stored` and scores against PFF-0005. No effect without a browser.
- Risk (level; mitigation): low/medium — stored probing writes to the store endpoint
  (state-changing; reset the lab). Oracle stays fail-closed (no FP). Live stored XSS on
  an auth-gated store endpoint needs the browser executor to carry the session — an
  on-host wiring detail (pass `--identity`'s header to the executor). Mitigated by tests
  (`tests/test_auto.py`: stored confirmed with a store-scoped fake, fp=0; store point
  present only with a browser, carrying the store endpoint). Suite 162 passed / 2 skipped.
- Deliverables:
  - [x] Stored-XSS observe points from cases; `InjectionPoint` store fields + evidence — done.
  - [x] Tests (stored confirmed via browser; browser-gated point) — done.
  - [ ] Live: pass the authenticated session to the browser executor for the store step — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the stored point is wired
  from the contract and confirmed as `xss-stored`; live run needs the browser + session.

### CC-FUZZ-0013 — M6 browser execution: stored + DOM XSS (2026-09-21)
- Change: added the browser-execution mechanism (M6). New `fuzzlab/oracle/browser.py`
  seam — `BrowserExecutor` protocol, `ExecRequest`/`StoreStep`/`ExecObservation`, a
  shared `SENTINEL`, and a `FakeBrowserExecutor` for offline tests. New strategies
  `DomXssStrategy` (`xss-dom`) and `StoredXssStrategy` (`xss-stored`), category `xss`,
  that build a tokened payload calling the sentinel and confirm only when the token
  actually *fires* in the browser (execution, not reflection — fail-closed). The live
  `PlaywrightBrowserExecutor` is `fuzzlab/tools/browserexec.py` (on-host; lazy import).
  Strategies are now scoped by `Candidate.category` (a category can have several
  strategies; `applies()` falls back to `vuln_class` for direct use), so the `xss`
  category fans out to reflected + DOM + stored. `Oracle(browser=...)`,
  `run_pipeline(browser=...)`, `run_auto(browser=...)`, and `fuzzlab auto --browser`
  thread the executor through; `Candidate` gained `category` and stored-XSS
  `store_url`/`store_param`. `auto`'s ground-truth sourcing includes the DOM points
  when a browser is present (else they stay skipped), and `R-XSS-REFLECT` now nominates
  on `fragment` too (CC-AUD-0012) so DOM fragment points get candidates.
- Impact (other components / project): closes the DOM-XSS detection gap — `auto
  --browser --ground-truth` now confirms `reviews.php#author` and `feedback.php?ref`.
  Without `--browser` nothing changes (M6 no-ops → those stay fn), so the existing
  benchmark is unaffected. Stored XSS (`profile.php` via `edit_profile`) has a working
  strategy but needs the point→case source_url to populate `store_url`; auto-wiring
  that is a follow-up (the injection-points contract has no source_url), so stored XSS
  is still fn in auto for now.
- Risk (level; mitigation): medium — M6 drives a real browser and, when enabled, runs
  a DOM probe on every non-reflecting xss candidate (the oracle tries reflected first,
  so server-reflected params short-circuit). The oracle stays fail-closed (only a
  fired token confirms → no FP on escaped pages). Mitigated by the injected seam
  (offline-tested), lab-only/loopback usage, and tests: DOM confirm/fail-closed/no-
  browser/ fragment-placement, stored store-then-observe + needs-store-endpoint,
  oracle-with-browser writes an `xss-dom` finding, and `auto --browser` confirms the
  DOM points with fp=0. Suite 154 passed / 2 skipped.
- Deliverables:
  - [x] `oracle/browser.py` seam + fake; DomXss/StoredXss strategies — done.
  - [x] Category-scoped `applies`; `Candidate.category`/store fields — done.
  - [x] browser threaded through Oracle/pipeline/auto + `--browser`; live executor — done.
  - [x] Tests (`tests/test_oracle_browser.py`, auto browser path) — done.
  - [ ] Live run with `--browser` on the host (Playwright) — on-host.
  - [ ] Stored-XSS auto-wiring: map points→cases to fill `store_url` — follow-up.
- Effectiveness (assessed 2026-09-21): effective in tests — DOM XSS confirms via a
  fired sentinel and writes an `xss-dom` finding; escaped pages are not confirmed; the
  `auto --browser` benchmark picks up the DOM points with fp=0. Live Playwright run and
  stored-XSS wiring pending.

### CC-FUZZ-0012 — Four more deterministic oracle vectors (2026-09-21)
- Change: added `ConfirmationStrategy` classes for four more injection classes, each
  fail-closed and confirming on a positive marker: **open redirect** (M9 —
  redirect-target-control: the param controls a `Location` header or meta-refresh
  target), **SSTI** (M4 — evaluation-marker: `${a*b}` / `{{a*b}}` / `<%= a*b %>` etc.
  evaluate to the product, with the literal expression absent), **path traversal/LFI**
  (M7 — file-content-marker: an `/etc/passwd` `root:...:0:0:` signature), and **command
  injection** (M1 timing — shell `sleep` with rising delay). Factored the rising-delay
  timing logic into a shared `ConfirmationStrategy._confirm_timing` reused by SQLi and
  command injection. Registered all four in `default_strategies()` and mapped their
  categories in `category_to_oracle_class`. `R-SSTI` now nominates on location
  (CC-AUD-0011) so it fires when its category is active.
- Impact (other components / project): grows the oracle's coverage from 2 classes
  (SQLi, reflected XSS) to 6. Because categories are scoped by the run plan (D14), the
  new vectors add zero cost to the SQLi/XSS lab benchmark — they run only when their
  category is selected (manual `--categories`) or present in a target's ground truth.
  These classes are not in the puppy-fort lab, so no effect on its score; they extend
  the toolkit to other targets/labs. Payloads are detection markers (arithmetic,
  `sleep`, `/etc/passwd` read, a canary redirect), not destructive.
- Risk (level; mitigation): low — additive, class-scoped via `applies()`, oracle stays
  fail-closed. Mitigated by 10 tests in `tests/test_oracle_vectors.py` (each vector:
  confirm the true case + reject a benign/reflection-only case; category wiring) and
  the refactor keeping SQLi timing green. Suite 145 passed / 2 skipped.
- Deliverables:
  - [x] OpenRedirect / SSTI / PathTraversal / CommandInjection strategies — done.
  - [x] Shared `_confirm_timing`; `default_strategies` + category map updated — done.
  - [x] Tests (confirm + fail-closed per vector; category mapping) — done.
  - [ ] Live confirmation against a lab that has these classes (e.g. a validation lab
    or added puppy-fort cases) — on-host / Lab track.
- Effectiveness (assessed 2026-09-21): effective in tests — each vector confirms its
  positive and stays fail-closed on the benign case; live confirmation pending a target
  with these vulns.

### CC-FUZZ-0011 — POST-body injection through the oracle + senders (2026-09-21)
- Change: the oracle can now test **POST body** params, not just GET query. Threaded
  `method`/`location` (already on `Candidate`) into confirmation: a `_send` helper on
  `ConfirmationStrategy` routes every probe and passes `method`/`location` only for
  non-default (POST/body) candidates, so existing GET/query senders and test fakes are
  unaffected. `RequestsProbeSender` and `SeamProbeSender` now issue a POST with a
  form-encoded body when `location="body"` (via `session.request` / a seam `Request`
  with body + `Content-Type`). The pipeline builds candidates with `method`/`location`
  from the evaluation evidence, and `auto`'s ground-truth sourcing now includes POST
  points (only client-only/DOM points remain skipped, pending M6). `_CountingSender`
  forwards the new kwargs.
- Impact (other components / project): the ground-truth benchmark now audits the 16
  POST points too (mostly secure controls → richer negatives; the one POST positive is
  `login.php` auth-bypass SQLi, which may confirm via the quoted timing templates). The
  finding writer already records `method`, so POST findings score against the POST
  ground-truth cases. Only browser-execution (M6) points (stored/DOM XSS) remain out of
  reach. Note: POST probing is state-changing on some endpoints (register/checkout/
  add_to_cart) — reset the lab between runs; destructive payload classes stay off.
- Risk (level; mitigation): medium — POST requests mutate lab state and add traffic.
  Mitigated by lab-only scope + `--authorized`, the oracle staying fail-closed (secure
  POST controls are not confirmed → no FP), the backward-compatible `_send` (GET/query
  senders unchanged), and tests: RequestsProbeSender/SeamProbeSender POST-body
  (form-encoded body, no query string), oracle-threads-POST, and the GT filter now
  including POST. Suite 135 passed / 2 skipped.
- Deliverables:
  - [x] `_send` helper threads method/location; senders issue POST body — done.
  - [x] Pipeline candidate carries method/location; auto GT filter includes POST — done.
  - [x] Tests (probe senders POST; oracle POST threading; GT filter) — done.
  - [ ] Live run: confirm the 16 POST controls stay fp=0 and whether `login.php`
    auth-bypass SQLi confirms (timing) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — POST candidates are probed
  over POST with a form body and the secure POST controls are not confirmed; live
  numbers (and whether login confirms) pending on the host.

### CC-FUZZ-0010 — `auto`: ground-truth point sourcing + oracle-rejection negatives (2026-09-21)
- Change: `fuzzlab auto` can source injection points from the enumerated ground-truth
  contract (`points_from_ground_truth`), not only the crawl. A new `--points`
  flag (`auto`|`crawl`|`ground-truth`, default `auto` = ground-truth when a contract
  is given, else crawl) selects the source. Ground-truth sourcing filters to points
  the current pipeline can test (GET/query, server-rendered) and reports the rest
  (POST body, fragment, client-only/DOM) as explicit skipped gaps rather than silent
  misses. `run_pipeline` now also counts oracle-rejected candidates (nominated but not
  confirmed) as negatives (`oracle_rejected`), so the dataset's negatives stay
  meaningful after R-XSS-REFLECT was broadened (CC-AUD-0009).
- Impact (other components / project): the scored run is now a real **detection
  benchmark** decoupled from crawl coverage — it tests every enumerated point, so the
  oracle's true tp/fp is measured (the crawl-only run under-covered, inflating fn).
  The skipped gaps name the next capabilities precisely: POST-body injection and
  browser-execution (M6) for stored/DOM XSS. Discovery runs (`--points crawl`) still
  measure the end-to-end tool including crawl coverage.
- Risk (level; mitigation): low/medium — more points audited means more probes, but
  scoped to testable GET/query points; the oracle stays fail-closed (no FP). Mitigated
  by `tests/test_auto.py` (GT-point filtering; GT-source scored run beats crawl
  coverage with fp=0; crawl-source path; D15 paths). Suite 132 passed / 2 skipped.
- Deliverables:
  - [x] `points_from_ground_truth` + `--points` selector + skipped-gap reporting — done.
  - [x] `run_pipeline` negatives include oracle-rejected candidates — done.
  - [x] Tests for both point sources + the skipped gaps — done.
  - [ ] Live GT-benchmark run on the host (expect tp for the GET/query SQLi + reflected
    XSS; fn for POST SQLi + stored/DOM XSS until those capabilities land) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the GT-sourced run audits
  all enumerated GET/query points, scores fp=0, and lists the POST/DOM gaps; live
  numbers pending on the host.

### CC-FUZZ-0009 — `fuzzlab auto`: automatic-mode entry point wired live (T2.8) (2026-09-21)
- Change: added `fuzzlab/harness/auto.py` (`run_auto`, `injection_points_from_store`,
  `_CountingSender`) and `fuzzlab/harness/auto_cli.py`, wired as `fuzzlab auto`.
  `run_auto` builds injection points from a crawl consolidated into the store (one
  point per endpoint+param, full URL with no query so the sender adds `?param=value`),
  resolves the run plan (D14 categories from ground truth + scored, or D15 fail-safe),
  wraps the probe sender in a request counter, and runs `run_pipeline` (scoped rules
  eval with negatives → oracle confirm → target fingerprint → score → request
  metrics). The CLI consolidates an existing `spider_results.db`, requires
  `--authorized`, and prints the plan, counts, findings, score, and request cost.
- Impact (other components / project): gives the automatic-mode path a real runnable
  entry (the missing half of the manual tool chain) — it writes the `target`,
  `evaluation` (negatives), and oracle `finding` rows and scores against ground truth,
  which the standalone tools did not. Uses the real requests/seam probe sender
  (`make_probe_sender`), so it also runs authenticated (`--identity`). This is the
  "live wiring" T2.8 left open in CC-FUZZ-0008.
- Risk (level; mitigation): medium — it sends confirmation probes at a live target.
  Mitigated by the `--authorized` gate, the oracle's fail-closed confirmation, the
  D15 no-ground-truth fail-safe (loud, unscored), category scoping, and 4 offline
  tests (`tests/test_auto.py`: point building, scored end-to-end with request
  counting, D15 fail-loud, D15 unscored-with-categories). Suite 130 passed / 2 skipped.
- Deliverables:
  - [x] `run_auto` + `injection_points_from_store` + request-counting sender — done.
  - [x] `fuzzlab auto` CLI (import crawl, `--authorized`, D14/D15, summary) — done.
  - [x] Offline tests (scored, fail-safe, unscored) — done.
  - [ ] Run against the live lab; compare requests-per-finding to a Phase-1 baseline — on-host.
  - [ ] DOM-skeleton dedup for distinct-URL same-template pages (needs the crawler to
    store rendered HTML) — follow-up; endpoint-keying already collapses query-param
    variants (e.g. product.php?id=1..10 → one point), so it is not needed for this lab.
- Effectiveness (assessed 2026-09-21): effective in tests — automatic mode produces
  oracle findings, logs negatives, records the target fingerprint and request cost,
  and scores TP/FP against ground truth; live run + the fewer-requests comparison
  pending on the host.

### CC-FUZZ-0008 — Automatic-mode pipeline wired end-to-end (Phase 2 T2.8) (2026-09-21)
- Change: added `fuzzlab/harness/pipeline.py::run_pipeline`, the library-level
  composition of an automatic run: dedup injection points by DOM-skeleton template
  cluster (T2.6) → fingerprint the target from a baseline probe and record the
  `target` row (T2.5) → evaluate the rules-as-data engine scoped to the `RunPlan`
  categories, logging negatives (T2.3 / D14 / D15) → confirm each candidate with
  the deterministic oracle (sole finding-writer) via
  `oracle.category_to_oracle_class` → score against ground truth only when the plan
  is scored (D15 fail-safe) → record request-efficiency metrics. Exported
  `category_to_oracle_class` from `fuzzlab.oracle`. This completes the
  "same wiring in the generalized harness / automatic pipeline" deliverable left
  open in CC-FUZZ-0007. Fixed a path-form defect surfaced by the scored pipeline
  (see Risk; BUG-0003 / CC-CORE-0008).
- Impact (other components / project): gives the web UI / automatic-test path one
  entry point that runs the whole Phase 2 loop with an injected sender (fully
  testable offline). The live crawler/auditor browser-fetch edits that feed it real
  pages/HTML remain the on-host last mile. Store schema unchanged.
- Risk (level; mitigation): medium — composing five stages exposed a real
  integration bug: the oracle stored findings with full URLs while ground truth is
  keyed on path form, so a scored run reported `tp=0, fp=3`. Root-caused (BUG-0003),
  fixed by centralizing URL normalization in `fuzzlab/core/urls.py::to_path`
  (CC-CORE-0008) and calling it at every finding writer; preventive rule PA-0003.
  Mitigated further by three pipeline tests (scored end-to-end with TP/FP checks;
  unscored per D15; dedup collapses same-template pages).
- Deliverables:
  - [x] `run_pipeline` composing dedup→fingerprint→scoped-eval→confirm→score/metrics — done.
  - [x] `category_to_oracle_class` exported and used to select confirmers — done.
  - [x] Path-form fix + shared `to_path` (BUG-0003 / PA-0003) — done.
  - [x] Tests (`tests/test_pipeline.py`: scored, unscored, dedup) — done.
  - [ ] Wire `run_pipeline` into the live crawler/auditor browser-fetch loops and
    measure request reduction against the running lab — todo (on-host last mile).
- Effectiveness (assessed 2026-09-21): effective in tests — the pipeline produces
  three oracle findings on the lab fixture, the harness scores them TP with 0 FP
  (after the path-form fix), negatives are logged, and unscored runs report findings
  without TP/FP/FN. Live confirmation pending a lab. Suite 108/108.

### CC-FUZZ-0007 — Oracle wired in as the sole finding-writer (Phase 2) (2026-09-21)
- Change: routed confirmation through the oracle. Added `fuzzlab/tools/probesender.py`
  (`SeamProbeSender` authenticated / `RequestsProbeSender` standalone; `make_probe_sender`)
  adapting tool HTTP to the oracle's `Sender` (full `Probe`: text/headers/elapsed).
  The fuzzer's `--store` path now, after recording attempts, calls
  `Oracle.confirm` on its target candidate — the oracle writes the `finding`.
  `store_adapter.import_fuzz_csv` no longer writes findings (attempts only); the
  earlier provisional `timing-only` finding path is removed. The attempt `reward`
  still records the fuzzer's timing screening.
- Impact (other components / project): findings are now deterministic oracle
  verdicts, not timing-only; the integration harness scores oracle findings. Closes
  the screen→confirm loop for the fuzzer (before the scheduler/classifier exist).
  Store schema unchanged.
- Risk (level; mitigation): medium — the oracle sends its own confirmation probes
  (extra requests) and is now the label source. Mitigated by the oracle's
  fail-closed design (CC-FUZZ-0006), reusing the scope/budget/auth seam for the
  authenticated sender, and tests: probe-sender adaptation (auth + full response)
  and an oracle→store→harness end-to-end (findings scored, confidence is the
  mechanism, not `timing-only`). Updated the store-adapter tests to attempts-only.
- Deliverables:
  - [x] Probe senders + `make_probe_sender` — done.
  - [x] Fuzzer `--store` confirms via the oracle; adapter attempts-only — done.
  - [x] Tests (probe senders; oracle→harness; adapter attempts-only) — done.
  - [ ] Same wiring in the generalized harness / automatic pipeline — todo (as the
    harness is generalized).
- Effectiveness (assessed 2026-09-21): effective in tests — the oracle's findings
  are read back and scored by the harness (confidence = mechanism, not
  timing-only); the adapter writes attempts only. Live confirmation pending a lab.
  Suite 84/84.

### CC-FUZZ-0006 — Deterministic oracle implemented (Phase 2 T2.1/T2.2/T2.4) (2026-09-21)
- Change: built the `fuzzlab/oracle/` package — a class-pluggable deterministic
  confirmer and sole finding-writer. `baseline.py` (median/MAD robust baselines,
  T2.2); `context.py` (sink-context typing + break-out signatures, T2.4);
  `strategies.py` (`ConfirmationStrategy` base + `SqliErrorStrategy` [M2],
  `SqliBooleanStrategy` [M3], `SqliTimingStrategy` [M1 rising-delay], and
  `ReflectedXssStrategy` [M5]); `oracle.py` (`Oracle.confirm` runs applicable
  strategies cheapest/strongest first and writes a `finding` row on a positive,
  reproducible verdict — fail-closed otherwise). Senders are injected, so the whole
  thing is unit-tested without a network. Realizes T2.1 (framework + current-lab
  mechanisms), T2.2, and T2.4.
- Impact (other components / project): gives the project its deterministic
  confirmation layer; will supersede the fuzzer's provisional `timing-only`
  findings (CC-FUZZ-0003) once the harness/fuzzer route confirmation through the
  oracle (next chunk). Consumes the auditor's sink-context typing (candidate
  `sink_context`) when present, else types reflection itself. Writes `finding` rows
  (existing schema). Browser execution (M6, stored/DOM XSS), OOB (M8), and grey-box
  (M10) are later per `architecture/oracle-confirmation.md`.
- Risk (level; mitigation): high — the oracle is the label trust anchor. Mitigated
  by fail-closed labeling (confirm only on a positive reproducible signal),
  differential/rising-delay timing on median/MAD baselines (resists outliers),
  boolean confirmation requiring true≈benign and true≠false (avoids FP on secure
  int-cast params), error signatures cross-checked, escaped reflection rejected,
  and 10 unit tests incl. fail-closed cases for each mechanism.
- Deliverables:
  - [x] median/MAD baseline (T2.2) — done.
  - [x] sink-context typing + break-out (T2.4) — done.
  - [x] Strategy interface + M1/M2/M3/M5 + registry — done.
  - [x] Oracle orchestration + sole finding-writer + 10 tests — done.
  - [ ] Route the fuzzer/harness confirmation through the oracle (replace
    timing-only findings) — todo (next Phase 2 chunk).
  - [ ] M6 browser execution (stored/DOM XSS); new-class strategies as the lab grows — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests — each mechanism
  confirms its positive fixture and fails closed on the secure fixture; the oracle
  writes exactly one finding on confirmation and none when unconfirmed. Suite 81/81.

### CC-FUZZ-0005 — Oracle scoped as class-pluggable across attack vectors (spec) (2026-09-21)
- Change: per direction to expand the project to as many attack vectors as
  possible, re-scoped the oracle from "differential timing + error signatures"
  (SQLi-leaning) to a **class-pluggable deterministic confirmer**. Reviewed the
  `references/` catalogs (63 categories) and defined a small set of confirmation
  **mechanisms** (M1–M10: differential timing, error signature, boolean differential,
  evaluation marker, reflected-canary-in-context, browser execution, file-content
  marker, out-of-band callback, redirect-target control, grey-box) with a
  `ConfirmationStrategy` per class selecting mechanisms by `(vuln_class,
  sink_context)`. Added the secondary architecture doc
  `docs/architecture/oracle-confirmation.md` (mechanisms + full injection-class →
  mechanism mapping + sequencing tiers + out-of-scope non-injection categories).
  Updated FR-FUZZ-3/3a/4/5 and the scope; Phase 2 T2.1 + exit criterion reframed.
  Spec/plan only — no code.
- Impact (other components / project): broadens the oracle's remit to the whole
  injection surface, sequenced by tier (Tier 1 black-box in Phase 2; Tier 2 browser
  execution via Playwright; Tier 3 out-of-band with a lab loopback listener; Tier 4
  grey-box in Phase 3). Ties to the auditor's sink-context typing (AUD Phase 2), the
  Lab track's class-breadth order, and the plugin system's `register_oracle` hook
  (#13). First secondary architecture doc created under the splitting rule;
  `ARCHITECTURE.md` #7 + splitting-rule index updated.
- Risk (level; mitigation): medium — a much larger confirmation surface risks
  false labels across classes. Mitigated by fail-closed labeling (confirm only on a
  positive reproducible signal), preferring stronger mechanisms over timing,
  per-class strategies validated against lab ground truth, the default-off
  destructive gate, and OOB restricted to a loopback canary. Breadth is sequenced
  by tier so each confirmer is validated as its lab class is added.
- Deliverables:
  - [x] Review `references/`; define mechanisms + class mapping (secondary doc) — done.
  - [x] Re-scope FR-FUZZ-3/4/5, scope, Phase 2 T2.1 + exit — done.
  - [ ] Implement the pluggable oracle + current-lab confirmers (Phase 2 T2.1) — todo.
  - [ ] Add confirmers per new class as the Lab track generates them — todo (ongoing).
- Effectiveness (assessed or pending): pending — spec/design. Judged in Phase 2 by
  confirming the lab's 8 cases via their per-class mechanisms and by a new class
  being addable as one `ConfirmationStrategy`.

### CC-FUZZ-0004 — Fuzzer HTTP migrated onto the auth seam (2026-09-21)
- Change: the fuzzer's HTTP now goes through a sender abstraction — `RequestsSender`
  (standalone, unchanged raw-requests behavior) or `SeamSender` (routes through the
  `core/` HTTP seam with the session manager, timing-serialized per host). Added a
  `--identity` flag: with it, the fuzzer authenticates as that identity (per-host
  credentials, detection-only login) via a shared `fuzzlab/tools/authhttp.py`
  helper; without it, behavior is exactly as before. Realizes the requests-tool
  half of Phase 1 T1.10 for the fuzzer.
- Impact (other components / project): the fuzzer can now fuzz authenticated
  endpoints as a given identity; depends on the session manager (#3) and credential
  store. Timing goes through the seam's per-host mutex. No output-format change.
- Risk (level; mitigation): medium — must not perturb standalone timing. Mitigated
  by keeping `RequestsSender` byte-identical to the old `measure_once`, routing
  timing through the seam only on the authenticated path (`timing=True`), and
  fail-loud auth (a `SessionAuthError` aborts the run rather than fuzzing
  unauthenticated). Covered by 3 tests (URL building, standalone unchanged,
  authenticated send attaches the session cookie).
- Deliverables:
  - [x] Sender abstraction; `--identity`; `authhttp` helper — done.
  - [x] Tests (standalone + authenticated) — done.
  - [ ] Live authenticated fuzz run against the lab (T1.10) — todo (needs a lab).
- Effectiveness (assessed 2026-09-21): effective in tests — the authenticated
  sender attaches the session and reaches the fuzzed URL; standalone path
  unchanged. Live run pending.

### CC-FUZZ-0003 — Writes attempts/findings to the unified store (2026-09-21)
- Change: added `--store PATH` to the fuzzer; after a run it consolidates its CSV
  into the unified store via `store_adapter.import_fuzz_csv`, writing `attempt`
  rows (behavioral features JSON + reward) and, for confirmed timing hits, a
  `finding` row (vuln_class `sqli`, label 1, confidence `timing-only`, self-
  describing url/method/param). Native CSV unchanged without `--store`. Phase 0 T0.8.
- Impact (other components / project): closes the Phase 0 loop — the harness (T0.7)
  reads these findings to score against ground truth. Note the confidence is
  `timing-only`: the deterministic oracle that will own finding labels is Phase 2,
  so these are provisional confirmations flagged as such, not oracle verdicts.
- Risk (level; mitigation): medium — writing findings from a timing-only signal
  risks false positives before the real oracle exists. Mitigated by flagging them
  `timing-only`, keeping the differential/median timing logic from the baseline,
  and requiring `--authorized`; the Phase 2 oracle will supersede this path.
- Deliverables:
  - [x] `--store` + `import_fuzz_csv` (attempt + finding rows) (T0.8) — done.
  - [ ] Replace timing-only findings with the deterministic oracle (Phase 2) — todo.
- Effectiveness (assessed 2026-09-21): effective for Phase 0 — synthetic fuzz
  output yields 3 attempts and 2 timing findings that the harness scores as true
  positives on the lab's known GET SQLi cases (test green).

### CC-FUZZ-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `blind_sqli_fuzzer.py` moved to `fuzzlab/tools/blind_sqli_fuzzer.py`;
  imports `core/` (`get_logger`, structured startup line after the `--authorized`
  gate). Behavior unchanged; still writes a labeled CSV (T0.8 moves it onto the
  store). Phase 0 T0.1.
- Impact (other components / project): the fuzzer is now a package module; the
  `--authorized` safety gate and detection logic are unchanged.
- Risk (level; mitigation): low — move + one import placed after the authorization
  check so the gate still fires first; verified the module imports and `--help` runs.
- Deliverables:
  - [x] Move into package; import `core/` (T0.1) — done.
  - [ ] Read candidates / write attempts+findings to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — runs as a package module with
  the authorization gate intact.

### CC-FUZZ-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `blind_sqli_fuzzer.py`
  performs time-based blind SQLi detection (median of repeats), requires `--url`
  and `--authorized`, and emits a labeled CSV. Detection is decoupled from the
  payload label. The generalized harness and the standalone deterministic oracle
  are specified but not yet built.
- Impact (other components / project): the oracle is the only writer of `finding`
  labels, so it is the trust anchor for the scheduler's reward, the classifier's
  training data, and all reports (D10). Generalizing the harness lets one engine
  serve multiple vulnerability classes; until then only blind SQLi is covered.
- Risk (level; mitigation): high — a wrong oracle silently corrupts every label
  and every learned model downstream. Mitigated by: differential (not absolute)
  timing, median-of-repeats, decoupling detection from the payload label (removes
  the earlier circular-labeling bug), grey-box confirmation when available,
  measured oracle precision, and state reset between iterations. Safety mitigated
  by the required `--authorized` flag, default-off destructive classes, and
  auth-endpoint exclusion.
- Deliverables:
  - [x] Time-based blind SQLi detection, median of repeats — done.
  - [x] `--authorized` gate; missing-`requests` import guard — done.
  - [x] Detection decoupled from payload label (circular-labeling fix) — done.
  - [x] Labeled CSV output — done.
  - [ ] Generalize to `template + injection_point + payload_source + oracle` — todo (Phase 2).
  - [ ] Standalone deterministic oracle (differential timing + error signatures) — todo (Phase 2).
  - [ ] Grey-box coverage / DB-fault confirmation — todo (Phase 3).
  - [ ] Write `attempt`/`finding` to the shared store — todo (Phase 0 T0.8).
- Effectiveness (assessed or pending): effective for time-based blind SQLi on the
  lab (confirms known points; circular-labeling defect removed). Multi-class
  harness, standalone oracle, and grey-box confirmation pending.
