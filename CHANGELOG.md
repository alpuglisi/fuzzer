# Changelog

A running record of notable changes to this project and **why** each was made.
Newest entries at the top. When you make a change, add a dated bullet: what
changed, and the reason. Reference the commit hash where useful.

Format per entry: `- <area>: <what changed> — <why>` (commit `<hash>`).

**Every change updates both logs:** this high-level CHANGELOG *and* the
change-control log of each affected component under `docs/components/`. This file
is the project-level history; the component logs are the lower-level controlled
records (see `docs/components/README.md`).

## 2026-09-21

- Phase 5 groundwork (T5.1): added `fuzzlab/ml/` — a dependency-light (pure-Python)
  detection-classifier + honest-evaluation core, strictly **advisory** (scores/triage,
  never `finding` labels). `metrics` (`pr_auc`, leakage-free `group_kfold`), `baselines`
  (prevalence, mean+kσ), `logistic` (standardized/L2/class-balanced), and `conformal`
  (flag/abstain/drop at a target error rate). A test proves the exit in miniature: the
  model beats **both** baselines on held-out GroupKFold PR-AUC and the conformal gate's
  error rates are bounded. Wrote `docs/PHASE_5_PLAN.md`; roadmap points to it.
  Store-training + persistence + optional GBT remain. +5 tests (188 passed / 2 skipped).
  Change-control: CC-ML-0002.
- Phase 4 (T4.4 + T4.5): **cost-normalized selection** and **hierarchical backoff** for
  the bandit. Each observation records a cost (the oracle passes the mechanism's probe
  count); with `cost_normalized`, ordering divides sampled reward by mean cost so a cheap
  informative mechanism beats an expensive one of equal reward (costs persist via
  migration 5). With `backoff`, a fresh (context, arm) is seeded from the first coarser
  context that has data (`context_parents`), so cold buckets borrow strength. Both are
  enabled on `fuzzlab auto --bandit`; defaults off elsewhere. +5 tests (183 passed / 2
  skipped). Change-control: CC-SCHED-0004, CC-CORE-0011.
- Phase 4 (T4.2 + T4.3): context buckets, priors, and the bandit wired into the confirm
  loop. Added `context_for` (bucket = `category:sink|location`), `arm_priors` (cost/
  reliability warm starts for oracle mechanisms), and a `references/`-derived
  `catalog_families`/`catalog_priors` reader (for the future payload-family bandit).
  `Oracle.confirm` now orders its applicable mechanisms via an optional scheduler and
  updates it per outcome, so the productive mechanism is front-loaded and its
  confirmation skips the expensive probes; threaded through `run_pipeline`/`run_auto`
  and `fuzzlab auto --bandit` (posteriors load/save around the run). A test shows a
  trained bandit reaches the confirming mechanism with fewer probes than a fresh one.
  Default (no scheduler) unchanged. +10 tests (179 passed / 2 skipped). Change-control:
  CC-SCHED-0003, CC-FUZZ-0015.
- Phase 4 groundwork: added `fuzzlab/scheduler/` — a `ThompsonBandit` (Beta-Bernoulli
  Thompson sampling per (context, arm), catalog priors, posteriors persisted in the
  reserved `bandit_posteriors` table) and a `UniformScheduler` control. Consumes the
  Phase 3 shaped reward; the RNG is injected so the method is stochastic but tests are
  deterministic — incl. a beat-uniform simulation (the bandit finds the paying arm and
  beats the control on hits). Wrote `docs/PHASE_4_PLAN.md`; roadmap points to it.
  Loop-wiring + cost-normalization + backoff + the on-lab exit remain. +7 tests (169
  passed / 2 skipped). Change-control: CC-SCHED-0002.
- Stored-XSS auto-wiring: `auto` now emits the stored-XSS observe point from the
  ground-truth *cases* (the enumerated points file lacks `source_url`), carrying the
  store endpoint via `InjectionPoint.store_url`/`store_param` (new) into the candidate;
  `StoredXssStrategy` plants at the store endpoint and observes the render page. With
  `--browser`, `profile.php` stored XSS (via `edit_profile.php`) is confirmed as
  `xss-stored` — closing the last DOM/stored detection gap. +2 tests (162 passed / 2
  skipped). Change-control: CC-FUZZ-0014, CC-AUD-0013.
- Web control panel (D11): built out `fuzzlab web` into a real dashboard. Added
  `fuzzlab/web/results.py` (store-backed `list_runs`/`run_detail`) and expanded the
  app with a **runs table**, **run-detail** views (`/runs/{id}` HTML + `/api/runs[/{id}]`)
  showing the score (TP/FP/FN/TN), target fingerprint, dataset counts (findings,
  negatives, candidates, attempts, pages), the findings table, and run metrics. Manual
  mode surfaces the selectable categories (D14). The panel is **read-only** over the
  store (never creates it, never sends traffic — no-auto-run and loopback-only
  preserved). +6 tests (160 passed / 2 skipped). Change-control: CC-UI-0007.
- Oracle vectors (M6): **browser execution for stored + DOM XSS**. Added an injected
  `BrowserExecutor` seam (`fuzzlab/oracle/browser.py`) with a `FakeBrowserExecutor` for
  offline tests and a live `PlaywrightBrowserExecutor` (`fuzzlab/tools/browserexec.py`,
  on-host). New `DomXssStrategy`/`StoredXssStrategy` confirm only when a tokened payload
  actually *fires* in the browser (execution, not reflection; fail-closed). Strategies
  are now scoped by `Candidate.category`, so the `xss` category fans out to reflected +
  DOM + stored. Threaded the browser through `Oracle`/`run_pipeline`/`run_auto` and
  `fuzzlab auto --browser`; `R-XSS-REFLECT` also nominates on `fragment`. With
  `--browser`, `auto` confirms `reviews.php#author` and `feedback.php?ref`; without it
  nothing changes. Stored-XSS auto-wiring (source_url) is a follow-up. +9 tests (154
  passed / 2 skipped). Change-control: CC-FUZZ-0013, CC-AUD-0012.
- Oracle vectors: added four more deterministic confirmers — **open redirect** (M9
  redirect-target-control), **SSTI** (M4 evaluation marker), **path traversal/LFI** (M7
  `/etc/passwd` content marker), and **command injection** (M1 differential timing) —
  taking the oracle from 2 classes to 6. Each is a fail-closed `ConfirmationStrategy`
  scoped to its vuln_class; the rising-delay timing logic is now shared by SQLi and
  command injection. Categories are scoped by the run plan (D14), so these cost nothing
  on the SQLi/XSS lab benchmark and run only when selected or present in a target's
  ground truth. `R-SSTI` now nominates on location (like XSS). +10 tests (145 passed /
  2 skipped). Change-control: CC-FUZZ-0012, CC-AUD-0011.
- Phase 2 build: **POST-body injection**. The oracle can now test POST body params, not
  just GET query — a backward-compatible `_send` helper threads `method`/`location`
  through, and `RequestsProbeSender`/`SeamProbeSender` issue a POST with a form-encoded
  body. The pipeline builds POST candidates from the evaluation evidence (now carrying
  method/location), and `auto`'s ground-truth benchmark audits the 16 POST points too
  (only client-only/DOM points remain, pending M6). Unlocks `login.php` auth-bypass
  SQLi and turns the POST controls into real negatives. POST probing is state-changing
  — reset the lab between runs. Change-control: CC-FUZZ-0011, CC-AUD-0010. Suite 135
  passed / 2 skipped.
- Bug fix (BUG-0006): automatic mode never nominated XSS — `R-XSS-REFLECT` required
  `sink_context`, a post-detection label the pipeline's discovery never sets, so no XSS
  candidate reached the oracle (the `test_pipeline` fixture masked it by hand-setting
  the label). Changed the rule to nominate on location (query/body); the oracle's M5
  types the context itself and confirms (fail-closed → no FP on escaped params).
  Preventive rule PA-0006. Change-control: CC-AUD-0009.
- Phase 2 build (T2.8): `fuzzlab auto` now runs a real **detection benchmark** — with
  `--ground-truth` it audits the enumerated contract points (not just crawl-discovered
  ones), decoupling detection from crawl coverage, and lists the points it can't yet
  test (POST-body injection, stored/DOM XSS needing M6) instead of silently missing
  them. `--points auto|crawl|ground-truth` selects the source. `run_pipeline` now
  counts oracle-rejected candidates as negatives too. Change-control: CC-FUZZ-0010.
- Phase 2 build (T2.8 live wiring): added **`fuzzlab auto`** — the automatic-mode
  entry point (`fuzzlab/harness/auto.py` + `auto_cli.py`). It builds injection points
  from a crawl consolidated into the store, resolves the run plan (D14 categories from
  ground truth + scored, or D15 fail-safe), wraps the real probe sender in a request
  counter, and runs `run_pipeline` — writing the `target` fingerprint, `evaluation`
  negatives, and oracle `finding` rows, and scoring TP/FP vs ground truth. Requires
  `--authorized`; runs authenticated with `--identity`. This is the runnable automatic
  path the manual tool chain lacked. +4 tests (130 passed / 2 skipped). Runbook Part D
  updated with the command; on-host step is the run + fewer-requests measurement.
  Change-control: CC-FUZZ-0009.
- Bug fix (BUG-0005): the headless encrypted-credential backend used `keyrings.alt`'s
  `EncryptedKeyring`, which needs PyCrypto/pycryptodome (undeclared, uninstalled) — so
  `fuzzlab session set-credential` crashed with `No module named 'Crypto'` on a fresh
  host, blocking every authenticated run. Reimplemented it on `cryptography` (Fernet +
  PBKDF2, `0600`, atomic, loud on wrong passphrase), declared `cryptography` as a
  dependency, and added real round-trip tests (skippable when the native lib is
  broken). The store's fake-backed tests never exercised the real path — preventive
  rule PA-0005. Change-control: CC-CORE-0010. Suite 126 passed / 2 skipped.
- Lab tooling: `labctl.sh` now probes for a *working* Compose provider
  (`docker compose` / `podman compose` / `docker-compose` / `podman-compose`) instead
  of assuming a `docker`/`podman` CLI implies one, and prints an install hint if none
  is found — fixes a "looking up compose provider failed" dump on a Fedora host with
  podman-docker but no compose package. Documented the prerequisite in the lab README
  and on-host runbook. Change-control: CC-LAB-0005.
- Docs: added `docs/ON_HOST_RUNBOOK.md` — step-by-step for running the toolkit on a
  host with a container daemon: bring up the lab and verify the DB fix, install the
  toolkit, Phase 1 authenticated per-identity crawl→audit→fuzz (+ two-lab), Phase 2
  automatic run + request-reduction measurement, and the Phase 3 grey-box live wiring.
  Delivers the parked Phase 1 runbook TODO; linked from `ON_HOST_TASKS.md`.
- Bug fix (BUG-0004): the lab app's `config.php` defaulted the DB user to `root`
  (empty password), which modern MariaDB authenticates over the unix socket and
  refuses over TCP — so any run without the PFF_DB_* env failed with "Access denied
  for user 'root'". Defaulted to the dedicated least-privilege `pff` user instead
  (matching `lab/.env.example`/compose); updated the app README manual setup to
  create `pff` and stop using root, and aligned the `schema.sql` import note to
  `sudo mysql`. Preventive rule PA-0004. Change-control: CC-LAB-0004.
- Phase 3 build (offline scaffolding): added `fuzzlab/greybox/` — the grey-box
  **consumer** layer behind injected-source seams, fully testable without a lab:
  `CoverageSource`/frontier + `app_lines` filtering, `DbFaultSource`, a multi-tier
  `shaped_reward` (screening / coverage-novelty / db_fault), a `LabControl` reset
  seam, the pure M10 confirmation decision, and `record_attempt_signals` filling the
  schema's already-reserved `attempt.coverage`/`attempt.db_fault`. +17 tests
  (125/125 green), including the "new code scores higher" exit property end-to-end.
  Remaining Phase 3 work is the live pcov/DB-fault/reset sources + M10 oracle wiring
  + exit measurement (on-host, `docs/ON_HOST_TASKS.md`). Change-control: CC-CORE-0009.
- Docs: added `docs/PHASE_3_PLAN.md` — the Phase 3 (grey-box instrumentation) plan:
  per-request pcov line coverage (app-filtered), a DB-fault signal, deterministic
  lab reset between iterations, coverage-novelty folded into `attempt.reward`, and
  the grey-box M10 mechanism into the oracle — all behind injected-source seams
  (offline-testable) with live capture on the host. Fills the schema's reserved
  `attempt.coverage`/`attempt.db_fault`; no ML this phase. Roadmap points to it.
- Docs: added `docs/ON_HOST_TASKS.md` — one place tracking the deferred **on-host**
  work that needs a real lab/browser/container daemon (Phase 1 live two-lab run +
  runbook; Phase 2 T2.8 live crawler/auditor wiring + request-reduction
  measurement). Phase 1/2 plans point to it — so the last-mile items are not lost.
- Phase 2 build (T2.8): **automatic-mode pipeline wired end-to-end** (library
  composition). Added `fuzzlab/harness/pipeline.py::run_pipeline` — one entry point
  that runs an automatic run: dedup by template cluster (T2.6) → fingerprint the
  target and record the `target` row (T2.5) → evaluate the rules engine scoped to the
  run's categories, logging negatives (T2.3/D14/D15) → confirm each candidate with the
  deterministic oracle (sole finding-writer) → score against ground truth only when
  the plan is scored (D15) → record request-efficiency metrics. Fully testable with an
  injected sender; the live crawler/auditor browser-fetch wiring is the remaining
  on-host last mile. +3 tests (108/108 green). Change-control: CC-FUZZ-0008.
- Bug fix (BUG-0003): the oracle stored `finding` URLs verbatim (full URLs) while
  ground truth and every other stored URL use **path form**, so a scored pipeline run
  counted every true finding as a false alarm (`tp=0, fp=3`). Centralized URL
  normalization in `fuzzlab/core/urls.py::to_path` (the single home of the convention)
  and call it at every finding writer; removed `store_adapter`'s duplicate helper.
  Preventive rule PA-0003. Change-control: CC-CORE-0008.
- Phase 2 build (T2.9/T2.10): **category selection + no-ground-truth fail-safe**
  decision logic. `core/runmode.py` `resolve_run` implements D14 (automatic against
  our lab auto-derives categories from ground truth and is scored; manual selects,
  defaulting to all) and D15 (automatic against a no-ground-truth target requires an
  explicit selection or fails loudly, and is unscored); it normalizes ground-truth
  vuln classes to categories and fails closed on unknown categories/modes.
  `audit.known_categories()` supplies the selectable set. +7 tests (105/105 green).
  Wiring into the launcher/harness rides with T2.8. Change-control: CC-CORE-0007,
  CC-AUD-0008.
- Phase 2 build (T2.3): **rules-as-data + full evaluation logging**. Added
  `fuzzlab/audit/` — an editable JSON rule set with a declarative `when` predicate,
  a loader, and an engine that records **every** rule evaluation (fired and
  not-fired → negatives) in a new `evaluation` table (migration 4), emitting
  candidates for fired ones; a `categories` filter is the D14/T2.9 hook. This gives
  the trainable-dataset-with-negatives half of the Phase 2 exit. Resolved the
  negatives to-confirm toward a dedicated `evaluation` table. +4 tests (98/98
  green). Change-control: CC-CORE-0006, CC-AUD-0007.
- Phase 2 build (T2.5/T2.6/T2.7 algorithms): added the fewer-requests building
  blocks as pure, tested `core/` modules — `fingerprint.py` (server/framework/DBMS/
  WAF from headers/cookies/errors), `dedup.py` (DOM-skeleton MinHash +
  `TemplateClusterer` so near-duplicate pages are audited once), and `hybrid.py`
  (`needs_browser` — static-first, browser-on-demand). +10 tests (94/94 green).
  Loop-wiring into the crawler/auditor and the live request-reduction measurement
  ride with T2.8. Change-control: CC-CRAWL-0005, CC-AUD-0006.
- Phase 2 build (T2.1 wiring): the **oracle is now the sole finding-writer**. Added
  `fuzzlab/tools/probesender.py` (authenticated + standalone probe senders adapting
  tool HTTP to the oracle's `Sender`); the fuzzer's `--store` path confirms its
  target via the oracle, which writes the `finding`. `store_adapter.import_fuzz_csv`
  writes attempts only — the provisional timing-only finding path is removed. Added
  an oracle→store→harness end-to-end test (findings scored; confidence is the
  mechanism, not `timing-only`). Suite 84/84 green. Change-control: CC-FUZZ-0007.
- Phase 2 build (T2.1/T2.2/T2.4): implemented the **deterministic oracle** —
  `fuzzlab/oracle/`: a class-pluggable `Oracle` + `ConfirmationStrategy` registry
  (sole finding-writer, fail-closed) with the current lab's mechanisms — M1
  differential timing (rising-delay on median/MAD baselines), M2 error signature,
  M3 boolean/response differential (SQLi), and M5 reflected-canary-in-context
  (reflected XSS); plus median/MAD robust baselines (T2.2) and sink-context typing
  (T2.4). Senders are injected, so it is unit-tested without a network; +10 tests
  (81/81 green), each mechanism with a fail-closed case. Next: route the
  fuzzer/harness through the oracle to replace the provisional timing-only findings.
  Change-control: CC-FUZZ-0006.
- Planning: added a **no-ground-truth fail-safe** for automatic runs (D15) — an
  automatic test against a validation lab / target whose vulnerabilities we don't
  know must not auto-select or test everything: it requires an explicit category
  selection, fails loudly if none is given, runs unscored (findings but no
  TP/FP/FN), and keeps all safety gates on (destructive off, scope-enforced,
  authorized). Recorded as D15 + a cross-cutting safety principle in
  `DECISIONS_AND_ROADMAP.md` and `ARCHITECTURE.md`, the UI spec (FR-UI-nogt), the
  oracle doc, and `PHASE_2_PLAN.md` (T2.10). Change-control: CC-UI-0006.
- Planning: added **injection-category selection by run mode** (D14) — automatic
  runs (against our lab) auto-select the categories from the lab's ground truth;
  manual runs let the user select which vulnerabilities/categories to test (launcher
  selector + a `--categories` flag). The selection scopes the auditor's rules,
  payload sources, and which oracle strategies run. Recorded in
  `DECISIONS_AND_ROADMAP.md` (D14), `architecture/oracle-confirmation.md`, the UI
  spec (FR-UI-categories), and `PHASE_2_PLAN.md` (T2.9). Change-control: CC-UI-0005.
- Planning: scoped the deterministic oracle as a **class-pluggable confirmer across
  attack vectors** (not time-based only), per direction to expand coverage. Reviewed
  the `references/` catalogs (63 categories) and wrote a secondary architecture doc
  `docs/architecture/oracle-confirmation.md` — a small set of confirmation
  mechanisms (M1–M10) and the full injection-class → mechanism mapping, sequenced by
  tier (black-box → browser → out-of-band → grey-box), with non-injection
  categories marked out of scope for the oracle. Updated the FUZZ spec (FR-FUZZ-3/4/5),
  `ARCHITECTURE.md` #7 + the splitting-rule index (first secondary doc), and
  `PHASE_2_PLAN.md` (T2.1 + exit criterion). Change-control: CC-FUZZ-0005.
- Planning: added `docs/PHASE_2_PLAN.md` — the deterministic-hardening (no-ML) task
  breakdown (T2.1–T2.8): a standalone deterministic oracle (differential timing +
  error signatures) as the sole finding-writer, median/MAD baselines, rules-as-data
  with full evaluation logging (negatives), canary reflection + sink-context typing,
  fingerprint-before-fuzz, template-cluster (MinHash) dedup, hybrid crawl, and a
  request-efficiency exit measurement. Referenced from the roadmap.
- Phase 1 build (T1.7): **non-secret session-state persistence**. Added migration 3
  (`session_state` table) + Store methods; the session manager persists non-secret
  metadata (host/identity/kind/validity/endpoints/token-exp) on login and logout,
  resumes it in a fresh manager, and the tools pass `--store` so runs persist.
  Secrets are never stored — a resume re-authenticates. +4 tests. Recorded a runbook
  TODO for the live two-lab validation in `PHASE_1_PLAN.md`. Change-control:
  CC-CORE-0005, CC-SESS-0006.
- Bug: BUG-0002 — a harness test still hardcoded the schema head (`== 2`),
  broken by migration 3 (recurrence of BUG-0001's class). Fixed to derive from the
  migration registry; added PA-0002 (sweep the codebase for a bug class when adding
  its preventive action, don't fix only the triggering instance). Suite 71/71 green.
- Phase 1 build (T1.10, part): **authenticated the Playwright/browser path** for
  the crawler and auditor. Added `fuzzlab/tools/browserauth.py`, which shapes a
  session into Playwright cookies / an extra bearer header and applies it to the
  browser context. The crawler gained `--identity` (injects at browser start); the
  auditor's browser path injects too (built via `make_auth`). With this, every tool
  code path (requests + browser) authenticates via the session manager; only the
  live two-lab run remains. +2 tests (67/67 green). Change-control: CC-CRAWL-0004,
  CC-AUD-0005.
- Phase 1 build (T1.10, part): migrated the **requests-based tools onto the auth
  seam** so they authenticate via the session manager. Added
  `fuzzlab/tools/authhttp.py` (build an authenticated `HttpClient` for a target +
  identity). The fuzzer gained `--identity` and a sender abstraction
  (`RequestsSender` standalone / `SeamSender` authenticated, timing-serialized);
  the auditor's static fetch gained `--identity`/`--base-url` and routes through the
  seam. Standalone behavior preserved; +5 tests (65/65 green). Remaining: the
  crawler/Playwright browser path (cookie injection) and the live two-lab run.
  Change-control: CC-FUZZ-0004, CC-AUD-0004.
- Phase 1 build: implemented the **session manager** (detection-only auth,
  per-host credentials) and the **per-host credential store**. `core/credentials.py`
  (T1.1) stores credentials keyed by `(host, identity)` in the OS keyring with an
  encrypted-file headless fallback and a gated lab-only env fallback; JWT `exp` is
  read without a crypto dependency. `fuzzlab/session/` (T1.2–T1.9) detects a host's
  login form (with fresh CSRF carry-through), detects the session credential
  (cookie / JSON-token+JWT / Basic), verifies success differentially, detects
  logout, re-authenticates single-flight, fails loudly on unparseable logins,
  excludes auth endpoints from fuzzing, and is a drop-in `core/` HTTP-seam addon;
  added a `fuzzlab session` CLI. Tests: session package 17, suite 60/60 green.
  Remaining (T1.10): route tool HTTP through the seam + live two-lab validation
  (needs a runnable lab). Change-control: CC-CORE-0004, CC-SESS-0005.
- Planning: recorded a **manual-login session capture** capability (post-Phase 6):
  once the proxy exists, a human logs in through it in a real browser, the proxy
  captures the established session (FR-PROXY-9), and the session manager adopts it
  (FR-SESS-11) — the escape hatch for logins detection can't crack (MFA, CAPTCHA,
  multi-step), still with no per-host config. Reflected in D13, the Phase 6
  roadmap, `ARCHITECTURE.md` (#3, #11), and both component specs. Change-control:
  CC-SESS-0004, CC-PROXY-0002.
- Planning: refined the session manager to **detection-only** auth with
  **per-host credentials** (revised D12/D13, per user direction), superseding the
  profile-first framing. The manager now detects each host's login/session
  mechanism dynamically (login form incl. fresh CSRF carry-through; cookie vs
  JSON-token/JWT vs Basic/Bearer; differential success; dynamic expiry) and passes
  credentials saved per host; there are no hand-written per-host profiles, and an
  unparseable login fails loudly (accepted trade-off for zero per-host config).
  Rewrote FR-SESS-1…10, D12/D13, `ARCHITECTURE.md` #3, and `PHASE_1_PLAN.md`.
  Change-control: CC-SESS-0003 (supersedes the profile/strategy-authoring parts of
  CC-SESS-0002; its credential-store backend resolution stands, now per-host).
- Planning: settled the session manager's **credential store** (D12 — OS keyring
  with an encrypted-file headless/CI fallback and a gated lab-only env fallback)
  and re-architected it for **multi-target auth** (D13 — pluggable `AuthStrategy`
  strategies: form+cookie, JSON+JWT, Basic, header key, scripted; per-target
  profiles as data) so it can log in and hold sessions across the external
  validation labs (D10), not just the Puppy Fort Factory. Expanded the
  session-manager spec (FR-SESS-6/9/10, NFR-portable/extensible), updated
  `ARCHITECTURE.md` (#3 + `core/` credential store) and `docs/PHASE_1_PLAN.md`
  (now T1.1–T1.10), and added the `keyring`/`keyrings.alt`/`pyjwt` dependencies.
  Change-control: CC-SESS-0002.
- Planning: added `docs/PHASE_1_PLAN.md` — the session-manager task breakdown
  (T1.1–T1.8) with acceptance checks, grounded in the lab's actual auth (PHP
  session cookies; no CSRF/JWT). Scope decision recorded: CSRF/JWT built to spec
  and fixture-tested now, live-validated later. Referenced from the roadmap.
- Process: adopted a **bug-investigation** requirement — every bug discovered in
  the code gets a root-cause-analysis document under `docs/bugs/` (description,
  where, what failed, what it was, RCA, corrective action, preventive action), and
  every preventive action is maintained in `docs/PREVENTIVE_ACTIONS.md`, a single
  context-free rule list to follow while working. Added `docs/bugs/README.md`, the
  first investigation `BUG-0001` (schema version hardcoded in tests, fixed in
  `30ea97d`/CC-CORE-0003), and `PREVENTIVE_ACTIONS.md` with PA-0001. Recorded as a
  cross-cutting principle in `docs/DECISIONS_AND_ROADMAP.md`.
- Process: added a **splitting rule** to `docs/ARCHITECTURE.md` — if it grows too
  complex, detailed material moves into secondary architecture documents under
  `docs/architecture/` referenced from the primary map. Recorded as a cross-cutting
  principle too.
- Docs: rewrote the root `README.md` to reflect the `fuzzlab` package layout, the
  CLI, the containerized lab, the launcher, and the lab-only/no-auto-run posture —
  the old README described only the standalone fuzzer.
- Phase 0 build (cont.): migrated the tools onto the unified store (T0.8) via a
  `store_adapter` and an opt-in `--store` flag on each tool. The crawler writes
  `page`/`endpoint`/`parameter`, the auditor writes `candidate`, and the fuzzer
  writes `attempt` rows plus `finding` rows for confirmed timing hits (flagged
  `timing-only` until the Phase 2 oracle). A synthetic end-to-end test shows a full
  run populating all six tables and the harness scoring the consolidated findings.
  Change-control: CC-CRAWL-0003, CC-AUD-0003, CC-FUZZ-0003.
- Phase 0 build (cont.): containerized the target lab (T0.2, D7) under `lab/` —
  `compose.yaml` (PHP/Apache + MariaDB), `web.Dockerfile`, `.env.example`,
  `labctl.sh` (up/down/reset), and a README. Web tier published on loopback only,
  DB not published; app bind-mounted, DB seeded from `schema.sql`. `docker compose
  config` validates; actual bring-up runs in an environment with a container
  daemon. Change-control: CC-LAB-0003.
- Phase 0 build (cont.): added the ground-truth label contract (T0.6) —
  `lab/ground-truth/{labels.json,injection-points.json,expectedresults.csv}` with
  JSON Schemas and a validating loader that cross-checks the files; the integration
  harness (T0.7) — a scorer (TP/FP/TN/FN, precision/recall/F1/MCC) and an
  assert-known-vulns run that reads oracle findings and records `run_metrics`; the
  minimal local web launcher (T0.9, D11) — loopback-only, offering automatic vs
  manual with no auto-run and an authorization gate; a `fuzzlab` CLI entry point;
  and migration 2 (self-describing findings). Tests: 28/28 green.
  Change-control: CC-LAB-0002, CC-CORE-0003, CC-UI-0004.
- Phase 0 build: created the `fuzzlab` Python package with a `core/` shared
  library and implemented the foundations — the SQLite project store with a
  numbered, idempotent migration runner and the core-contract tables (T0.3);
  layered config with a run hash + redaction, structured JSON logging, the request
  budget + per-host timing mutex, and a scope-enforcing session-aware HTTP seam
  (T0.4); and a versioned feature extractor with golden tests (T0.5). Moved the
  existing tools (spider/fetcher/fuzzer/build_sql_db) into `fuzzlab/tools/` so each
  imports `core/` and runs as a package module, with the indicator DB relocated to
  packaged data (T0.1). Added `pyproject.toml`. Foundation test suite: 12/12 green.
- Process: made explicit in `docs/components/README.md` that change-control logs
  are **append-only** — every change adds a new entry, all historical entries are
  kept, and a superseding change references the entry it supersedes rather than
  rewriting it (the living `requirements.md` specs are what get updated in place).
- Planning: decided the primary UI is a **local web application** (control panel +
  dashboard on localhost), not a `textual` TUI (new decision D11) — results and
  output are far easier to review in a browser and it composes with the planned
  Datasette. The no-auto-run launcher now lives on the web page; a plain CLI entry
  point per tool is kept for headless use; the web app binds to loopback only and
  is served separately from the vulnerable target. Reflected in
  `docs/DECISIONS_AND_ROADMAP.md` (D11, Phase 6 UI, deferred list),
  `docs/ARCHITECTURE.md` (component map + component #12), `docs/PHASE_0_PLAN.md`
  (T0.9), and the component #12 spec + change-control log (CC-UI-0003).
- Planning: added a **no-auto-run** requirement — bring-up presents a launcher
  offering automatic vs manual operation and never starts tools against the
  container on its own. Recorded in `docs/PHASE_0_PLAN.md` (Goal, T0.7, new T0.9,
  exit criterion), `docs/DECISIONS_AND_ROADMAP.md` (cross-cutting principle),
  `docs/ARCHITECTURE.md` (integration model, component #12, Security-and-safety),
  and the component #12 spec + change-control log (CC-UI-0002) — to keep the user
  in control of when the tools touch the target.
- Process: made it explicit that **both** logs are updated on every change — this
  high-level CHANGELOG and each affected component's change-control log — noted in
  this file's header and in `docs/components/README.md`.
- Planning: updated `docs/ARCHITECTURE.md` to reflect the settled decisions — a
  standing maintenance rule (keep the doc in sync whenever the architecture
  changes; each component now also has its own spec and change-control log),
  containerization/env-pinning of the lab (D7), and the manifest-driven generator
  (D8) — so the architecture document matches the decisions we made.
- Planning: added `docs/components/` — a requirement specification and a
  per-component change-control log for each of the 13 primary components, plus a
  `README.md` defining the change-control entry format (change, impact, risk +
  mitigation, deliverables with status, effectiveness). The component
  change-control logs are lower-level and per-component; the root CHANGELOG stays
  the high-level project history.
- Planning: added `docs/DECISIONS_AND_ROADMAP.md` (settled design decisions
  D1–D7, cross-cutting principles, and the phased build plan) and
  `docs/ARCHITECTURE.md` (component map, subcomponents, interactions, and
  dependencies) — to lock the project direction before building the next phase
  (lean foundations, then the session manager).
- Planning: committed the two research prompts under `docs/` and stripped their
  human-facing preambles so each `.md` is a raw prompt fed directly to an agent.
- Planning: after reviewing the lab-scaling research, recorded decisions D8–D10
  (manifest-driven lab generator as a track sequenced after the toolkit; a
  machine-readable out-of-band label contract now; the lab serving both detection
  and ML with cell/transform splits and a blind holdout), added env pinning to
  D7, added a parallel Lab track to the roadmap, and updated the ground-truth
  component and evaluation principle in the architecture and roadmap docs.
- Planning: added `docs/PHASE_0_PLAN.md` (foundations task breakdown) and chose a
  containerized lab environment for reproducibility and easy resets.

## 2026-09-20

- Project docs: added `CHANGELOG.md` (this file) and `ERROR_LOG.md` — to keep a
  durable record of why changes were made and how identified errors were fixed,
  so the project's history is legible as it grows.
- Planning: added `docs/ml-tooling-research-prompt.md` — a self-contained prompt
  to drive external research into ML techniques and the proxy/session-manager
  design before building the next phase.

## 2026-09-18

- `build_sql_db.py` / `php_indicators.db`: defined all 28 indicator types that
  the auditor implements (was 7) and added a `reference` column mapping each to a
  `references/` payload folder — to activate 21 rules that were dormant and let
  the audit summary point findings at the right payload catalog (commit `bc096b4`).
- `fetcher.py`: rewrote the auditor into a rule registry of 28 rules covering the
  `references/` taxonomy, parsed each page once via a `PageContext`, deduplicated
  findings with an occurrence count, and added a static-request fallback — to
  broaden coverage, cut duplicate rows, and stay robust when the browser refuses
  a response (commit `dabcf55`).
- `spider.py` / `fetcher.py`: reset the results table by default (with `--resume`
  to keep it), captured fetch/XHR endpoints, added a `source` column, and fixed
  discovery bugs — to make re-runs rebuild the map, reach JSON APIs that are
  never linked, and record how each URL was found (commit `1d18ce6`).
- `fetcher.py`: added an optional headless-browser engine — so the auditor
  inspects the rendered DOM and sees JavaScript-built forms and inputs
  (commit `7727ab8`).
- `spider.py`: added a headless-browser (Playwright) engine plus a `--engine`
  flag and richer storage — so the crawler can discover and parse
  JavaScript-rendered pages, not just static HTML (commit `36951eb`).
- Target app: expanded to 30 pages, 10 JavaScript-rendered — to give the crawler
  and auditor a realistic mix of server-rendered and client-rendered targets, and
  to exercise crawler-evasion handling (commit `8f121a9`).
- Target app: added the first JavaScript-rendered pages — to create content
  invisible to a static-HTML spider as a discovery test (commit `508d291`).
- `deploy.sh`: made the web root the default deploy destination — so the app is
  served at `http://localhost/` instead of a subdirectory (commit `5f87d80`).
- `deploy.sh`: added a deploy script that copies the app into the Apache web root
  with correct ownership/permissions and preserves an existing DB config — to
  make redeploying to the local lab repeatable and safe (commit `566c9f3`).

## 2026-09-17

- `tools/` and `references/`: added the crawler, auditor, indicator-DB builder,
  and payload-catalog taxonomy — to begin the discovery-and-audit pipeline that
  feeds the fuzzer (commit `25e512b`).
- `REFERENCES.md`: recorded the SQL injection and XSS payload catalogs the
  project draws on — to keep source references in one place (commit `40f404c`).
- Target app: added "Ryder's Puppy Fort Factory," a deliberately vulnerable
  PHP/MySQL app with a documented mix of vulnerable and secure pages — to serve
  as a local, authorized test target for the fuzzer (commit `b409603`).
- `blind_sqli_fuzzer.py`: added a time-based blind SQL injection detector and
  labeled-dataset builder — the project's starting tool, hardened from an initial
  draft (see `ERROR_LOG.md` for the fixes applied) (commit `814cdd7`).
