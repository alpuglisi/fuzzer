# On-host tasks (deferred: need a real lab / browser / container daemon)

Work that is **built and unit-tested here** but whose final step must run on a host
with a container daemon, network, and a real browser — i.e. the user's Fedora host
running the containerized lab. This is the single place these live so none is lost;
the phase plans point here. When one is done, tick it, move the detail into the
relevant change-control entry, and update the owning phase plan's exit criterion.

Why deferred: this sandbox has the Docker/Podman CLI but **no daemon**, so the
containerized lab (D7) cannot run; Playwright is present but there is no live target
to drive. Everything below is offline-complete (code + tests green); only the live
measurement/validation remains.

## Phase 1 — live session validation

- [ ] **Two-lab per-identity run.** Save per-host credentials
  (`fuzzlab session set-credential`), bring up the lab, and run per-identity
  crawl→audit→fuzz against (a) the containerized cookie lab and (b) an external
  JWT lab. Confirms dynamic login detection, per-host credentials, session hold,
  and single-flight re-auth on expiry with no per-host auth config.
  (Phase 1 plan T1.10; closes Phase 1 end-to-end.)
- [ ] **Write the two-lab validation runbook.** Short runbook: saving credentials,
  bringing up each lab, running per-identity crawl→audit→fuzz, and the expected
  checks. (Phase 1 plan "TODO (revisit)".)

## Phase 2 — live wiring + exit measurement (T2.8)

- [x] **Automatic-mode entry point wired.** `fuzzlab auto`
  (`fuzzlab/harness/auto.py` + `auto_cli.py`, CC-FUZZ-0009) builds injection points
  from a crawl, resolves the plan (D14/D15), runs the pipeline with the real probe
  sender + a request counter, and writes `target`/`evaluation`/`finding` rows + scores.
  Offline-tested (`tests/test_auto.py`).
- [ ] **Run it against the lab + measure the request reduction (Phase 2 exit).** Run
  `fuzzlab auto` against the running lab (see runbook Part D) and show **measurably
  fewer requests** for the same findings than the Phase-1 baseline (`fuzz` request
  count); confirm `run_metrics` has `pipeline_requests` /
  `pipeline_requests_per_finding` and the `evaluation` table holds negatives (fired=0).
- [ ] **(Optional) DOM-skeleton dedup for distinct-URL same-template pages.** Needs the
  crawler to store rendered HTML so `pages_html` can feed the pipeline's T2.6 dedup.
  Not needed for this lab (endpoint-keying already collapses `?id=1..10` to one point).

### Detection-capability gaps the benchmark will show as false negatives (next build)

The `fuzzlab auto --ground-truth` benchmark tests all enumerated points and lists what
it can't yet confirm. These are scoped capabilities, not bugs:
- [x] **POST-body injection** in the probe sender/oracle (CC-FUZZ-0011) — the benchmark
  now audits the 16 POST points; the oracle probes them over POST with a form body.
- [x] **Browser-execution (M6)** built (CC-FUZZ-0013): DOM + stored XSS strategies
  behind an injected `BrowserExecutor`, offline-tested. Live pieces remain:
  - [ ] Run `fuzzlab auto --browser` on the host (drives the live
    `PlaywrightBrowserExecutor`) to confirm `reviews.php#author` + `feedback.php?ref`.
  - [x] **Stored-XSS auto-wiring:** done (CC-FUZZ-0014) — `auto` emits the stored
    observe point from the ground-truth cases with `store_url` from `source_url`.
    Live remainder: pass the authenticated session to the browser executor so the
    (auth-gated) store step at `edit_profile.php` succeeds under `--identity`.

## Phase 3 — grey-box live sources + validation

The consumer layer (`fuzzlab/greybox/`) is **built and unit-tested offline** behind
injected-source seams (17 tests). What remains needs the instrumented lab:

- [ ] **Instrument the image (T3.1).** Add pcov to `web.Dockerfile` + a request-scoped
  coverage shim writing app-filtered covered lines to a loopback side channel keyed by
  a per-request correlation id.
- [ ] **Live coverage reader** backing `CoverageSource` (reads the T3.1 side channel).
- [ ] **Live DB-fault reader** backing `DbFaultSource` (tails MariaDB error/general log
  or a DB-proxy error hook).
- [ ] **`labctl.sh` snapshot/restore (T3.5)** backing `LabControl`, and the harness
  reset sequencing between iterations.
- [ ] **Wire M10 into `Oracle.confirm` + the pipeline (T3.6/T3.7)** with the sources
  injected and the sink's file/line known.
- [ ] **Exit measurement:** on the running lab, a request reaching new application code
  produces a distinguishable (higher) reward; error-based SQLi separates from benign
  traffic via `db_fault`.

## Phase 4 — bandit scheduler exit measurement

The scheduler core, context/priors, and the oracle-mechanism ordering are built and
offline-tested; `fuzzlab auto --bandit` wires it in and persists posteriors. On the
lab:
- [ ] **T4.6 exit:** run `fuzzlab auto --bandit` repeatedly (posteriors accumulate) and
  compare against a uniform control on **hits-per-1000-requests** / requests-per-finding
  over held-out pages — the bandit must beat uniform. Also wire cost-normalization
  (T4.4) and hierarchical backoff (T4.5) if the live numbers call for them.

## Phase 6 — intercepting proxy: live TLS serving + the exit

The full offline proxy stack is built and unit-tested (`fuzzlab/proxy/`): the
byte-exact dual-path core, scope, match-and-replace, flow history (FTS5), repeater,
interception (awaited future), manual-login session capture, the sans-I/O
`ProxyEngine`, the `AsyncProxyServer` plain-HTTP path, and the `LocalCA` leaf-cert
cache. The **live last mile** needs a real browser + TLS (the sandbox has no working
`cryptography`/TLS):
- [ ] **Wire live upstream + CONNECT/TLS serving:** implement the real socket `Sender`
  (upstream connect/send/recv) and TLS-terminate CONNECT with `LocalCA` leaf certs
  (mint on first CONNECT, cache per host). `AsyncProxyServer` currently returns 501 for
  CONNECT offline.
- [ ] **Browser trust:** install the generated `fuzzlab-ca.crt` in the browser/OS trust
  store used to browse the lab (never distribute the CA key; it stays 0600 on the host).
- [ ] **Verify the real `cryptography` minting** on the host: `test_proxy_server.py::
  test_real_ca_mints_signed_leaf` currently skips in the sandbox — it must pass on-host.
- [ ] **Exit criterion:** browse the lab through the proxy, intercept a request, hand-edit
  it to carry a **duplicate `Content-Length`**, forward it, and confirm the **exact
  bytes** go on the wire (the raw path) while the parsed path would have rejected it.
- [ ] **Manual-login session capture live:** log in to the lab through the proxy, capture
  the session (`SessionCapture`), `adopt_into` the `SessionManager`, and confirm a
  subsequent authenticated tool run reuses it — no per-host config.

## Phase 7 — candidate ranker + active-learning exit

The ranker (NDCG@k/Precision@k vs random, `fuzzlab auto --rank`) and the active learner
(uncertainty sampling + query-by-committee) are built and offline-tested. On the lab's
real dataset:
- [ ] **T7.4 ranker exit:** on a **uniformly-sampled held-out** set of endpoints, show the
  ranker's NDCG@k and Precision@k beat the random-order baseline (GroupKFold by
  endpoint) — run `fuzzlab auto --rank` on a real crawl and read `rank_ndcg` vs
  `rank_ndcg_random` in `run_metrics`.
- [ ] **T7.4 active-learning exit:** show a fixed uncertainty/committee budget of *b*
  candidates (`active.propose_queries`) captures **more positives per confirmation** than
  a random budget of the same size, over held-out pages.

## Phase 8 — mutation engine: live filter-bypass + coverage exit

The mutation engine is built and offline-tested (`fuzzlab/mutation/`): operators +
semantics validator, context-typed XSS, the filter model + bypass learner, the
bandit/coverage-guided search, variant write-back behind the destructive gate, and the
gated LLM scaffold. On the lab, with the D16 WAF enabled (`PFF_WAF=on`):
- [ ] **T8.7 exit:** show the engine produces variants that **bypass the live WAF** where
  the base payload is blocked (`PFF_WAF_MODE=block`) or sanitized (`=sanitize`), **and**
  reach application code the static catalog did not — measured by live grey-box coverage
  (Phase 3 live sources). The semantics validator must reject meaning-changing transforms;
  generated payloads respect the destructive gate.
- [ ] **Live filter learning:** point `FilterLearner` at the running WAF via real canary
  round-trips (not the offline `FilterModel`) and confirm it learns the same
  block/strip behavior and finds working bypasses.
- [ ] **Wire variants into the fuzzer's attempt path** so bypasses are actually sent and
  confirmed by the oracle, and recorded in `payload_variant`.

## How to pick these up

Step-by-step commands for all of the above are in **`docs/ON_HOST_RUNBOOK.md`**.

1. Bring up the containerized lab on the host (see `docs/components/01-target-lab/`).
2. Save credentials per host with `fuzzlab session set-credential`.
3. Run the tools with `--identity` (and `--authorized` for the fuzzer); for
   automatic mode, category selection follows the ground truth (D14) and the run is
   scored, else it fails safe (D15).
4. Record results in the owning change-control entry and update the phase plan.
