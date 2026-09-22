# Fuzzing Harness and Oracle — Change Control Log

Component code: **FUZZ**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-FUZZ-0020 — Oracle-probes-per-finding metric_series (CC-FUZZ-0016 follow-up) (2026-09-22)
- Change: `Oracle.confirm()` now counts every probe sent across the *whole* call —
  every confirmation mechanism it tries, not only the one that ultimately confirms
  — via a call-scoped `_CostCounter` (`total_probe`) that wraps `sender`; when a
  scheduler is attached, each mechanism's existing per-arm cost counter (`probe`)
  now wraps `total_probe` instead of `sender` directly, so both totals stay
  accurate from the same `sender.send()` calls (no double-counting, no separate
  instrumentation pass). On a confirmed finding, when both `store` and `run_id`
  are attached, emits one `metric_series` point (source `oracle`, key
  `probes_per_finding`, step = a per-oracle-instance running finding count,
  value = `total_probe.count`) via `log_scalar` (CC-CORE-0018). Emitted **with or
  without a scheduler** — deliberately, since the metric's purpose is a
  before/after comparison ("the bandit's request savings" CC-FUZZ-0016 named as a
  follow-up) that only exists as a delta between the two conditions, not a
  standalone number from either one.
- Impact (other components / project): read-only-shaped instrumentation — no
  change to `confirm()`'s control flow, return value, or the bandit's existing
  per-arm reward/cost update (`probe.count` is unchanged; only what it wraps
  changed). No schema change (consumes `metric_series`/`log_scalar`, CC-CORE-0018).
  A future diagnostics-tab or runbook script can now plot/compare
  `probes_per_finding` across a bandit-off and bandit-on run of the same
  workload — the concrete ask this follow-up closes.
- Risk (level; mitigation): low — purely additive; the only behavior change
  visible to existing callers is one more `metric_series` row per finding when a
  store is attached (an existing test asserting the exact prior `source` set had
  to be updated to include `oracle` — expected, not a regression). Mitigated by
  4 new tests (`tests/test_oracle_scheduler.py`): the recorded value matches the
  sender's own independent probe count with and without a scheduler, the step
  counter increments across multiple findings in one `Oracle` instance, and a
  store-less `Oracle` still confirms without error (nothing to record into).
- Deliverables:
  - [x] Call-scoped total probe counter across every tried mechanism — done.
  - [x] `probes_per_finding` metric_series emission (with/without scheduler) —
    done.
  - [x] Tests + existing bandit-metric test updated for the new source — done.
- Effectiveness (assessed 2026-09-22): effective — the recorded value equals the
  sender's own ground-truth probe count in both the scheduler and no-scheduler
  cases, and increments correctly across repeated findings.

### CC-FUZZ-0019 — Emit bandit posterior/regret + coverage-frontier metric_series (2026-09-22)
- Change: `Oracle.confirm()` emits `posterior/<arm>/mean` and `regret/cumulative`
  metric_series points (source `bandit`) after each `scheduler.update()` call, only when
  both `store` and `run_id` are attached to the Oracle (optional — absent either, behavior
  is unchanged). `run_greybox` (`fuzzlab/greybox/run.py`) emits `coverage/lines`
  metric_series points (source `coverage`, the running `CoverageFrontier.size`) per probe
  via a buffered `core.store.MetricLogger`, flushed at the end of the run. Both go through
  the new `CC-CORE-0018` write API; no other write path touches `metric_series`.
- Impact (other components / project): read-only consumer of the CORE `metric_series`
  table/API (CC-CORE-0018); a future UI diagnostics tab (Phase 4b) can chart these series.
  No change to `Oracle.confirm`'s finding-writing contract (FR-FUZZ-5) or to
  `run_greybox`'s existing per-point differential-coverage reward logic (BUG-0016,
  CC-FUZZ-0017) — the metric emission is additive instrumentation alongside it, not a
  change to the reward/novelty computation.
- Risk (level; mitigation): low — purely additive, optional-by-default (no store/run_id
  → no-op) instrumentation. Mitigated by the unchanged full suite (1395 passed / 23
  skipped, same 6 pre-existing unrelated failures) plus new unit/integration tests
  asserting the emitted rows.
- Deliverables:
  - [x] `Oracle.confirm()` bandit posterior/regret emission — done.
  - [x] `run_greybox` coverage-frontier growth emission — done.
- Effectiveness (assessed 2026-09-22): effective — `tests/test_greybox_live.py::test_run_greybox_emits_coverage_frontier_growth_series`
  and the oracle-side bandit emission tests confirm monotonically-sensible series are
  recorded with no change to existing confirm/reward behavior.

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
