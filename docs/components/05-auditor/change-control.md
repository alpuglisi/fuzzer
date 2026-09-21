# Auditor / Fetcher — Change Control Log

Component code: **AUD**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-AUD-0006 — Target fingerprinting (algorithm) (2026-09-21)
- Change: built `core/fingerprint.py` (T2.5) — a pure, accumulative fingerprinter
  that identifies server / framework / DBMS / WAF from response headers, cookies,
  and error text (`Fingerprint.merge` accumulates over responses). Fingerprint-
  before-fuzz lets the scheduler/oracle scope payloads to the target.
- Impact (other components / project): the auditor will accumulate a fingerprint
  over its fetches and write the `target` row (dbms/framework/waf), which the
  scheduler (#8) and oracle (#7) read. The module is in `core/` (shared). Wiring it
  into the auditor's fetch loop + `target` write is the next step (needs live
  responses to validate end-to-end).
- Risk (level; mitigation): low (pure function, tested). Mis-fingerprint is
  non-fatal (payloads just aren't scoped); mitigated by first-observation-wins merge
  and signature specificity. 3 unit tests (PHP/MySQL from headers+error; framework
  from cookie; WAF + merge).
- Deliverables:
  - [x] `fingerprint.py` + tests (T2.5) — done.
  - [ ] Accumulate in the auditor loop and write the `target` row — todo (with T2.8).
- Effectiveness (assessed 2026-09-21): effective in unit tests — server/framework/
  DBMS/WAF identified from representative responses. Live wiring pending.

### CC-AUD-0005 — Authenticated Playwright audit (cookie injection) (2026-09-21)
- Change: the auditor's Playwright engine now authenticates too — `ContentFetcher`
  gained `session_manager`/`auth_base_url`, and `__enter__` injects the session
  (cookies / bearer header) into the browser context via `browserauth`. `main`
  builds the manager + seam client together (`make_auth`) and passes both. With
  this, both auditor paths (static via the seam, browser via injection) audit
  authenticated. Completes the auditor side of Option A.
- Impact (other components / project): JS-rendered pages are audited as an identity;
  depends on the session manager (#3) and credential store. No rule/output change.
- Risk (level; mitigation): low–medium — injection runs once at browser start;
  failed login fails loud. Covered by the `browserauth` unit tests; live browser
  wiring validated on a host with a browser + lab.
- Deliverables:
  - [x] `session_manager`/`auth_base_url` on ContentFetcher; `__enter__` injection — done.
  - [x] `main` builds manager + client via `make_auth` — done.
  - [ ] Live authenticated audit (browser) against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests (shared with the
  crawler's browser-auth path); live browser audit pending.

### CC-AUD-0004 — Auditor static fetch migrated onto the auth seam (2026-09-21)
- Change: `ContentFetcher` gained `identity`/`seam_client`; its static
  (non-browser) fetch now routes through the `core/` HTTP seam + session manager
  when an identity is given (via `fuzzlab/tools/authhttp.py`), so pages are audited
  authenticated. Added `--identity` and `--base-url` flags. The Playwright (browser)
  path is unchanged — cookie injection into the browser context is the separate,
  later sub-step. Standalone behavior is unchanged when no identity is given.
  Realizes the requests-tool half of Phase 1 T1.10 for the auditor.
- Impact (other components / project): the auditor can now reach and audit
  authenticated pages as an identity; depends on the session manager (#3) and
  credential store. No rule or output-format change; browser-rendered auditing is
  still unauthenticated until the Playwright sub-step.
- Risk (level; mitigation): low–medium — only the static path changed; standalone
  raw-requests path preserved. Mitigated by isolating the change to `_static_fetch`
  and 2 tests (authenticated static fetch attaches the cookie; standalone uses raw
  requests). Note the mixed state: static = authenticated, browser = not yet.
- Deliverables:
  - [x] `identity`/`seam_client` on ContentFetcher; `_static_fetch`; flags — done.
  - [x] Tests (authenticated static + standalone) — done.
  - [ ] Playwright path cookie injection (browser auth) — todo (next A sub-step).
  - [ ] Live authenticated audit run against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — the static fetch is
  authenticated and returns the protected page; standalone unchanged. Browser-path
  auth and the live run pending.

### CC-AUD-0003 — Consolidates candidates into the unified store (2026-09-21)
- Change: added `--store PATH` to the auditor; after an audit it consolidates its
  native `findings` into the unified store via `store_adapter.import_audit`,
  writing `candidate` rows (rule = transaction type, evidence JSON incl. category/
  reference/occurrences, sink_context from the HTML context) and linking to a
  discovered `parameter` when one matches. It first imports the spider DB so
  candidates can link to parameters. Native output unchanged without `--store`.
  Phase 0 T0.8.
- Impact (other components / project): candidates now land on the integration bus
  for the scheduler/fuzzer/ranker; depends on the crawler having populated
  parameters (CC-CRAWL-0003) for linkage.
- Risk (level; mitigation): low — opt-in, additive; covered by the consolidation
  test (synthetic audit DB → candidate rows).
- Deliverables:
  - [x] `--store` + `import_audit` (candidate rows, param linkage) (T0.8) — done.
  - [ ] Full per-rule evaluation evidence + versioned features (Phase 2) — todo.
- Effectiveness (assessed 2026-09-21): effective — synthetic findings become
  candidate rows in the unified store (test green).

### CC-AUD-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `fetcher.py` moved to `fuzzlab/tools/fetcher.py`; imports `core/`
  (`get_logger`, structured startup line) and now defaults `--indicator-db` to the
  packaged `php_indicators.db` (via `fuzzlab.tools.paths`) so it runs from
  anywhere. Still writes its own SQLite file (T0.8 migrates it). Phase 0 T0.1.
- Impact (other components / project): the auditor is now a package module and
  resolves its indicator DB from the package rather than the working directory;
  depends on the IND component's packaged data path (CC-IND-0002). No rule or
  output-format change.
- Risk (level; mitigation): low — move + path default + one import; verified the
  module imports, `--help` shows the packaged default, and the indicator DB loads.
- Deliverables:
  - [x] Move into package; import `core/`; packaged indicator-db default (T0.1) — done.
  - [ ] Write candidates to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — runs as a package module with
  the packaged indicator DB resolved automatically.

### CC-AUD-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `fetcher.py` renders dynamic
  content, evaluates 28 injection-point rules against discovered parameters, probes
  canary reflection, and emits candidates. Standalone; not yet on the shared store,
  session manager, or ranker.
- Impact (other components / project): produces the candidate queue the scheduler
  and fuzzer consume; depends on the indicator DB for its rule/indicator data.
  Currently writes its own output rather than the shared `candidate` table, and
  rules are in code rather than data.
- Risk (level; mitigation): low–medium. Rules-in-code and no shared store limit
  reuse and explainability; mitigated by the Phase 0 store migration and the
  Phase 2 move to rules-as-data with full per-rule evaluation logging. No current
  risk to other components beyond output format.
- Deliverables:
  - [x] 28-rule evaluation over dynamic + static content — done.
  - [x] Canary reflection probing — done.
  - [ ] Full per-rule evaluation logging (fired + not-fired) — todo (Phase 2).
  - [ ] Rules-as-data registry — todo (Phase 2).
  - [ ] Sink-context typing of reflections — todo (Phase 2).
  - [ ] Target fingerprinting (DBMS/framework/WAF) — todo (Phase 2).
  - [ ] Migrate to the shared store + versioned features — todo (Phase 0 T0.8).
  - [ ] Session-manager integration — todo (Phase 1).
- Effectiveness (assessed or pending): effective at emitting candidates from the
  lab's injection points with the 28 rules active; explainability and store
  integration pending.
