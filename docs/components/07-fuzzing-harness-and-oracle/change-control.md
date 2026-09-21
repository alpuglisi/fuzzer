# Fuzzing Harness and Oracle — Change Control Log

Component code: **FUZZ**. Entry format and required fields: see `../README.md`.
Newest first.

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
