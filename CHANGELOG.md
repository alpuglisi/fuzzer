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
