# Phase 2 — Deterministic hardening (no ML) (plan)

Sharpen the toolkit deterministically: confirm findings with a real oracle, spend
fewer requests for the same results, and produce a trainable dataset that contains
**negatives** — all without any machine learning (that starts in Phase 5, and
grey-box signals in Phase 3).

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (Phase 2, D1),
`docs/components/{04-crawler,05-auditor,07-fuzzing-harness-and-oracle}/`, and
`docs/PREVENTIVE_ACTIONS.md` (rules to follow).*

## Goal

Measurably fewer requests for the same findings; a deterministic oracle that is the
sole writer of `finding` labels (replacing the fuzzer's provisional timing-only
findings); and a `candidate`/`attempt` dataset that records negatives, not just
hits, so later ML has something to learn from.

## Status (2026-09-21)

Build started. Done so far:
- **T2.1** (core) — the `fuzzlab/oracle/` package: class-pluggable `Oracle` +
  `ConfirmationStrategy` registry, sole finding-writer, fail-closed. Mechanisms for
  the current lab: M1 differential timing, M2 error signature, M3 boolean, M5
  reflected-XSS context. (M6 browser XSS, M8 OOB, M10 grey-box: later.)
- **T2.2** — median/MAD robust baselines.
- **T2.4** — sink-context typing + break-out signatures.

- **T2.1** (wiring) — the oracle is now the **sole finding-writer**: the fuzzer's
  `--store` path confirms its target via the oracle (probe senders in
  `fuzzlab/tools/probesender.py`); `store_adapter.import_fuzz_csv` writes attempts
  only; the provisional timing-only finding path is removed. An oracle→harness test
  scores oracle findings.

- **T2.5/T2.6/T2.7** (algorithms) — `core/fingerprint.py` (server/framework/DBMS/WAF),
  `core/dedup.py` (DOM-skeleton MinHash + `TemplateClusterer`), and `core/hybrid.py`
  (`needs_browser`) built and unit-tested. Loop-wiring into the crawler/auditor
  (cluster-id from HTML, engine switch, fingerprint→`target` row) rides with T2.8.

Next: T2.3 rules-as-data + negatives, T2.9 category selection, T2.10 fail-safe, then
T2.8 wire the fewer-requests trio into the loops + measure request reduction (live).
94/94 tests green.

## Principles (this phase)

- **Deterministic only.** No ML. Every confirmation is a reproducible rule/measurement.
- **Differential, not absolute.** Confirm time-based findings by probing several
  requested delays and requiring latency to rise with the delay — never one slow
  response. Robust baselines (median/MAD, not mean/σ).
- **Record everything.** Log every rule evaluation (fired and not), so negatives
  exist in the store.
- **Fewer requests.** Deduplicate near-duplicate pages; fetch statically first and
  escalate to a browser only when needed; fingerprint before fuzzing so payloads
  are scoped.

## Tasks

Ordered; each lists a deliverable and an acceptance check. Follow
`PREVENTIVE_ACTIONS.md` throughout (PA-0001: derive test expectations from
source-of-truth constants; PA-0002: when a bug adds a preventive action, sweep the
whole class).

### T2.1 — Class-pluggable deterministic oracle (sole finding-writer)
Build the oracle as a **class-pluggable** confirmer — the **only** writer of
`finding` rows — not a time-based-only check. It is a small set of confirmation
**mechanisms** with a `ConfirmationStrategy` per vulnerability class selecting the
mechanism(s) that prove it; the auditor's `(vuln_class, sink_context)` picks the
strategy. Full mechanism set and the injection-class → mechanism mapping across the
`references/` attack-vector catalogs live in
`architecture/oracle-confirmation.md`. This phase builds the framework plus the
mechanisms the **current lab's 8 cases** need:
- **M1 differential timing** (rising-delay, median/MAD), **M2 error signature**,
  **M3 boolean/response differential** — SQLi (blind/error/boolean).
- **M5 reflected-canary-in-executable-context** — reflected XSS (uses T2.4 typing).
- **M6 browser execution** (Playwright) — stored + DOM XSS.

Replaces the fuzzer's provisional `timing-only` findings (CC-FUZZ-0003). New
classes (SSTI, LFI/traversal, SSRF, command injection, XXE, …) plug in as the Lab
track adds them (their mechanisms — M4/M7/M8 — are specified in the secondary doc);
grey-box (M10) is layered in Phase 3.
- **Accept:** each of the lab's 8 known vulns is confirmed via its appropriate
  mechanism (SQLi ×4 by M1/M2/M3; reflected XSS by M5; stored + DOM XSS by M6),
  with evidence and no false positives on the secure controls; re-running
  reproduces every verdict; a new class can be added as one `ConfirmationStrategy`.

### T2.2 — Median/MAD rolling baselines
Replace the fuzzer's mean/σ jitter band with a **median / MAD** rolling baseline
(robust to outliers), shared by the fuzzer and the oracle.
- **Accept:** the baseline is median/MAD; benign controls are not flagged under
  jitter; a single outlier does not shift the band materially (unit test).

### T2.3 — Rules-as-data + full evaluation logging (auditor)
Move the 28 rules from code toward data (an editable, versioned rule set) and record
**every** per-rule evaluation per injection point — fired and not-fired — so the
`candidate` table (or an `evaluation` table) contains negatives with rule evidence.
- **Accept:** auditing the lab writes candidates including negatives, each traceable
  to the rule and outcome; the rule set is editable as data without code changes.

### T2.4 — Canary reflection probing with sink-context typing (auditor)
Probe reflection with a unique canary and classify the **sink context** of each
reflection (HTML body, HTML attribute, JS string, URL/attribute-URL).
- **Accept:** on the lab's reflected-input page(s), each reflection's context is
  typed correctly (unit-tested against fixtures for each context).

### T2.5 — Fingerprint-before-fuzz (auditor)
Fingerprint the target (DBMS, framework, WAF) and record it on the `target` row;
the scheduler/fuzzer/oracle condition payload choice on it.
- **Accept:** the lab's DBMS/framework are fingerprinted and recorded; payload
  scoping reads the fingerprint (unit test with signature fixtures).

### T2.6 — Template-cluster dedup (crawler)
Compute a DOM-skeleton **MinHash** per page, assign a `template_cluster_id`, and
deduplicate near-duplicate pages so they are audited once.
- **Accept:** near-duplicate pages (same skeleton, different data) collapse to one
  cluster; distinct templates stay distinct (unit test on fixture DOMs).

### T2.7 — Hybrid crawl (crawler)
Fetch cheaply over HTTP first and escalate to the headless browser **only** when a
page is client-rendered (empty/JS-shell), instead of rendering everything.
- **Accept:** static pages are fetched without launching the browser; only
  client-rendered pages escalate — fewer browser navigations (decision logic
  unit-tested; request count measured live in T2.8).

### T2.8 — Request-efficiency + negatives (exit measurement)
Record request-efficiency metrics in `run_metrics` (requests total, requests per
confirmed finding) and confirm the dataset now holds negatives. Compare against a
Phase-1 baseline run.
- **Accept:** a full run records requests-per-finding and shows **measurably fewer
  requests** than the Phase-1 baseline for the same findings, and the `candidate`/
  `attempt` tables contain negatives.

### T2.9 — Injection-category selection by run mode (D14)
Scope which categories run by launcher mode: **automatic** (against our lab)
auto-derives the category set from the ground-truth contract; **manual** exposes a
category selector and a `--categories` flag on the tools. The selection scopes the
auditor's active rules, the payload sources, and which oracle `ConfirmationStrategy`
classes run.
- **Accept:** an automatic lab run tests exactly the ground-truth categories; a
  manual run with `--categories` tests only the chosen categories and nothing else.

### T2.10 — No-ground-truth fail-safe (D15)
An automatic run against a target with no ground-truth contract must fail safe: no
auto-derivation and no test-everything default; require an explicit category
selection; **fail loudly** if none is given; run **unscored** (harness reports
findings but no TP/FP/FN); keep destructive off, scope enforced, `--authorized`
required.
- **Accept:** pointing an automatic run at a no-ground-truth target without
  `--categories` fails loudly (no traffic); with `--categories` it runs unscored,
  tests only those categories, and destructive stays off.

## Exit criterion

The class-pluggable deterministic oracle confirms **all** the lab's known
vulnerabilities — SQLi (timing/error/boolean), reflected XSS (context), and
stored/DOM XSS (browser execution) — via the appropriate per-class mechanism, as
the sole finding-writer, with no false positives on the secure controls; a new
attack class can be added as one `ConfirmationStrategy` (mapping in
`architecture/oracle-confirmation.md`); a full run uses **measurably fewer
requests** than Phase 1 for the same findings; and the store holds a trainable
dataset **with negatives**. No ML.

## Out of scope for Phase 2 (deferred)

Grey-box coverage / DB-fault signals and snapshot/restore (Phase 3); the bandit
scheduler (Phase 4); any ML — classifier/ranker/anomaly/active-learning (Phases 5,
7); the mutation engine (Phase 8). The oracle here is black-box (timing + error
signatures); grey-box confirmation is layered on in Phase 3.

## To confirm during the build

- Whether negatives live as extra `candidate` rows (a `fired`/`outcome` column, a
  new migration) or a dedicated `evaluation` table.
- MinHash parameters (shingle size, permutations) and the cluster-distance threshold.
- The "is this page client-rendered?" heuristic for hybrid-crawl escalation
  (empty-body / script-density / known-shell signals).
- Differential-timing delay set and the rising-delay acceptance test (how many
  delays, monotonicity tolerance).

## Known risks

- **Oracle false positives/negatives corrupt every label.** Mitigated by
  differential (rising-delay) confirmation, median/MAD baselines, error-signature
  cross-checks, measured oracle precision, and reproducibility tests — the same
  trust anchor discipline as CC-FUZZ-0001.
- **Dedup hides a real, distinct page.** Mitigated by clustering on DOM skeleton
  (not content), capping per-cluster instances, and keeping a manifest of what was
  collapsed.
- **Hybrid-crawl mis-classifies a JS page as static** and misses dynamic surface.
  Mitigated by conservative escalation (escalate on any doubt) and validating
  against the known 10 JS pages.
- **Request-reduction claims need the live lab.** Unit tests cover the logic; the
  fewer-requests measurement is validated on a running lab (with the two-lab runbook,
  still TODO).
