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

- [ ] **Wire `run_pipeline` into the live crawler/auditor loops.**
  `fuzzlab/harness/pipeline.py::run_pipeline` composes the automatic run and is
  tested with an injected sender; feed it **real pages/HTML** from the crawler and
  the auditor's browser-fetch paths (cluster-id from live HTML, engine switch,
  fingerprint→`target` row from a live baseline probe).
- [ ] **Measure the request reduction (Phase 2 exit).** Run a full pipeline against
  the running lab and show **measurably fewer requests** for the same findings than
  the Phase-1 baseline; confirm `run_metrics` records
  `pipeline_requests` / `pipeline_requests_per_finding` and the
  `evaluation`/`candidate`/`attempt` tables hold negatives.
  (Phase 2 plan T2.8 exit criterion.)

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

## How to pick these up

1. Bring up the containerized lab on the host (see `docs/components/01-target-lab/`).
2. Save credentials per host with `fuzzlab session set-credential`.
3. Run the tools with `--identity` (and `--authorized` for the fuzzer); for
   automatic mode, category selection follows the ground truth (D14) and the run is
   scored, else it fails safe (D15).
4. Record results in the owning change-control entry and update the phase plan.
