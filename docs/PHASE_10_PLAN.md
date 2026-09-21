# Phase 10 — Polish and generalization (plan, for review)

Make the toolkit **extensible** (a plugin system on `core/` hooks), add the last ML
piece (an **anomaly-detection tripwire**), prove **reproducibility** (evaluation reports),
and test **transfer** to a second target. This is the "make it a platform, and show it
generalizes" phase.

*Draft for review — nothing built yet. Components **PLUG** (#13), **ML** (#10), **CORE**
(#2), **LAB** (#1), **UI/docs** (#12). See `DECISIONS_AND_ROADMAP.md` (D6, D10, Phase 10)
and the plugin requirements (FR-PLUG-1..5).*

## Goal

A third party can extend the toolkit — ML model, extra rules, custom oracle, payload
source — **without editing core**, via entry-point plugins on a hook registry; an
anomaly tripwire flags weird flows/attempts (advisory); a reproducible report captures a
run's inputs, versions, seeds, and metrics; and the whole pipeline runs against a
**second target** to show the findings transfer.

## Exit criterion

A sample plugin registers on each hook and runs at the right point (a failing plugin is
contained and logged, not fatal); active plugins/versions are recorded on the run and
running with **zero** plugins works unchanged (D6); the anomaly detector beats a naive
baseline on held-out outliers, advisory-only; an evaluation report reproduces a run's
metrics deterministically; and the toolkit produces results on a second lab target.

## Principles (this phase)

- **Optional by construction (D6/NFR-PLUG-optional).** The toolkit runs fully with no
  plugins; ML and extra rules attach as plugins, never core edits. Zero-plugin behavior is
  byte-for-byte the current behavior.
- **Contained plugins (NFR-PLUG-safe).** In-process but isolated: one plugin's exception
  is caught, logged, and that plugin disabled — it never aborts a run or corrupts the
  store. Deterministic order via per-plugin priority.
- **Oracle/advisory split holds through plugins (FR-PLUG-5).** A plugin may
  `register_oracle`, but ML-style plugins write scores/uncertainty, never `finding` labels
  — enforced at the hook boundary, not by trust.
- **Advisory-only ML.** The anomaly detector produces scores/flags and a hybrid feature;
  it never writes labels (same split as Phases 5/7).
- **Offline-testable seams.** The registry, hook dispatch/isolation/priority, the
  entry-point discovery (with injected fakes), the ECOD detector, and the report generator
  are unit-tested here. The live second-target transfer run is **on-host**.
- **Reproducibility (NFR-PLUG-reproducible).** The active plugin set + versions, feature/
  model versions, seeds, and config hash are recorded onto the run and into the report.

## Design decisions (confirmed)

1. **Hook set + isolation. `[confirmed]`** Implement the FR-PLUG-2 hooks — `on_request`,
   `on_response`, `on_candidate`, `on_finding`, `register_rules`, `register_payload_source`,
   `register_oracle` — with per-plugin **priority** ordering and **contain-log-disable**
   isolation. Entry-point discovery via `importlib.metadata`, tested with an injected
   entry-point set (no real installed package needed).
2. **Anomaly detector. `[confirmed]`** Pure-Python **ECOD** (empirical-CDF tail outlier
   score; no numpy/sklearn), **advisory-only**, over the attempt/flow feature vectors; the
   **XGBOD-style hybrid** = feed the anomaly score in as an extra feature to the existing
   classifier.
3. **Recording active plugins. `[confirmed]`** Add a small **`run_plugin`** table
   (migration 10: run_id, name, version, priority) so a run records exactly which
   plugins/versions were active (NFR-PLUG-reproducible).
4. **Second target / transfer. `[confirmed — A now, C later]`** Build the **multi-target
   evaluation harness** (run the toolkit against any base-url + ground-truth contract) and
   the docs now, and use an **external validation lab** (e.g. OWASP Juice Shop / WAVSEP,
   per D10) as the transfer target **on-host** (option A). The **eventual** direction is
   option C — the manifest-driven lab generator ("lab as a compiler") producing a second
   target with its own labels — tracked on the **Lab track**, not built this phase. A
   bespoke hand-written second app (option B) is not pursued.

## Tasks

- **T10.1 — Plugin registry + hooks `[done, offline]` (FR-PLUG-1..5).** `fuzzlab/plugins/`:
  entry-point discovery (`importlib.metadata`), a `HookRegistry` with the seven hooks,
  per-plugin priority, contain-log-disable isolation, and the oracle/advisory-split guard
  on `register_oracle`/finding writes. Migration 10's `run_plugin` records the active set.
- **T10.2 — Hook attachment points `[done, offline]`.** Wire the hooks into the pipeline —
  `on_request`/`on_response` at the HTTP seam, `on_candidate`/`register_rules` in the
  auditor, `on_finding`/`register_oracle` in the oracle, `register_payload_source` in the
  scheduler — all no-ops with zero plugins (D6). Offline-tested with a sample plugin.
- **T10.3 — Anomaly detector (A.5) `[planned]`.** `fuzzlab/ml/anomaly.py` — pure-Python
  ECOD tripwire (advisory scores/flags) + the XGBOD-style hybrid (anomaly score as a
  classifier feature). A test shows it flags synthetic outliers and beats a naive
  baseline; it never writes labels.
- **T10.4 — Reproducible evaluation report `[planned]`.** `fuzzlab/report/` + a
  `fuzzlab report` CLI: a deterministic report over a stored run (config hash, feature/
  model versions, seeds, metrics, findings, active plugins) — the reproducibility artifact.
- **T10.5 — Multi-target harness + transfer `[planned; live on-host]`.** A thin
  multi-target eval harness (base-url + ground-truth contract per target) + docs; the live
  transfer run against an external lab is on-host; a bespoke second app is deferred to the
  Lab track.
- **T10.6 — Exit `[on-host]`.** A sample plugin extends the toolkit with no core change; a
  failing plugin is contained; the anomaly detector tags a weird flow; the report
  reproduces a run; results transfer to a second target.

## Component mapping

- **PLUG (13)** — `fuzzlab/plugins/` (registry, hooks, discovery, isolation).
- **CORE (2)** — migration 10 (`run_plugin`) + the hook attachment points on the seam.
- **ML (10)** — `fuzzlab/ml/anomaly.py` (ECOD + hybrid feature).
- **UI/docs (12)** — the reproducible report + `fuzzlab report`; the panel may surface it.
- **LAB (1)** — the multi-target harness; a second/external target (on-host / Lab track).

## Out of scope for Phase 10 (deferred)

- Heavy process/sandbox isolation of plugins (they run in-process, contained — this is a
  lab tool; the open trust-model question stays deferred).
- An async hook variant for the proxy data path (open question; defer).
- Building a bespoke second vulnerable app from scratch (Lab track / manifest generator).
- Writing labels from any ML plugin (never — oracle-only).
