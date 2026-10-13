# BUG-0069 — The report's `reproducibility.feature_versions` was always empty

- Date: 2026-10-13
- Status: fixed (CC-UI-0047, CC-ML-0022, CC-FUZZ-0055)
- Severity: medium. Reproducibility metadata was wrong on every real run. No score,
  label or finding was affected, but the report claimed that no feature version was
  involved in runs whose models and stages read version-1 candidate features.

## Description
`report.build_report` filled `reproducibility.feature_versions` with `SELECT DISTINCT
feature_version FROM candidate WHERE run_id=?`. No production code ever writes
`candidate.feature_version`: candidate features are recomputed on read (FR-ML-5). So
every real run's report said `feature_versions: []`. `tests/test_report.py` passed only
because its fixture wrote that column by hand.

## Where encountered
Reviewing FR-ML-5 while moving the candidate extractor into `core/` (CC-CORE-0031). It
was flagged there and fixed in this error-review phase, as batch 4's review required.

## What it caused to fail
Every `fuzzlab report` (text and JSON) for a run whose classifier, ranker, anomaly
tripwire or budget prioritizer read candidate features. A reader comparing two runs
could not tell which feature schema produced their numbers.

## What the bug was identified to be
The reader depended on a contract column with **no production writer**. The test
supplied the value itself, which hid that.

## Root cause analysis
Five Whys:
1. *Why was the list empty?* The column it read is never written.
2. *Why was it never written?* Features are recomputed on read. The column was
   reserved in the schema but no writer was ever built.
3. *Why did the reader still use it?* The reader was written against the schema, not
   against what production writes.
4. *Why did the test pass?* Its fixture inserted `feature_version = 1` by hand, a value
   production never produces.
5. *Why did no rule catch this?* No rule required a reader's input column to have a
   production writer, and none forbade fixtures from supplying values production never
   writes.

**Root cause:** a reader depended on a contract column that no production code writes,
and the test's hand-seeded fixture masked it.

## Corrective action
- **The report** (CC-UI-0047) now builds `reproducibility.feature_versions =
  {"candidate": [...], "flow": [...]}`. **This is a JSON contract change:** the field
  was a list. Each counter is reported separately:
  - **candidate:** stored `candidate.feature_version` values (legacy/future), the run's
    pinned models' `feature_version`, and every stage that read candidate features
    without saving a model;
  - **flow:** the flow tripwire's version.

  The text format prints `feature versions: candidate [1], flow —`. The response
  extractor's counter is not listed, since nothing records it on a run yet.
- **Stages record what they read** (CC-ML-0022, CC-FUZZ-0055):
  - `detect_anomalies` records `anomaly_feature_version` when it persists. The
    read-only refit records nothing. The stage runs under the advisory write guard,
    which denies DELETE, so a rerun appends an identical value.
  - `Prioritized.feature_version` is recorded by the pipeline as
    `pipeline_budget_feature_version`; `random` reads no features and records none.
  - `detect_flow_anomalies` records `flow_anomaly_feature_version`, replacing it on
    rerun (it is not under the guard).
- **Tests** seed only through production writers. They cover:
  - a run with no ML stage: `[]`;
  - a trained run: `[1]`;
  - an anomaly-only run: `[1]`;
  - a read-only refit records nothing;
  - the flow version, written once across reruns;
  - the prioritizer's version (none for `random`);
  - the pipeline metric per budget method.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0066 / PA-0067** (the report pinned store-wide newest models): the same reader,
  a different field. Its root cause was query scope, not a missing writer. It is related
  but not the same.
- **PA-0029 / PA-0064(3)** (a branch needs a test that enters it): this is not a
  branch-coverage gap. The reader was entered, with fabricated input.
- No prior bug had a fixture supplying a value production never writes.

**Result:** a new root cause, with no prior PA to analyse for failure.

## Preventive action
**PA-0071** (in `docs/PREVENTIVE_ACTIONS.md`):
1. **A contract column or key that a reader depends on must have a production writer.**
   A test must not supply, by hand, a value production never writes. If a reader needs
   such a column, the writer is built or the reader stops presenting it as a recorded
   fact.
2. **Enforced mechanically.** `tests/test_contract_writers.py` takes the contract
   tables' columns from the migrated schema and asserts each one has an INSERT/UPDATE
   writer in `fuzzlab/`, or an allowlist entry with its reason. It is proven on a
   synthetic writer-less column, and a stale allowlist entry fails too.
3. **The PA-0002 sweep for this class covers every column with no writer.**

**Sweep (PA-0002):**
- **`candidate.features_json` / `feature_version`:** recomputed on read, allowlisted.
  The report no longer relies on them alone.
- **`attempt.features_json` without `feature_version`:** written by `greybox/run.py`
  and `tools/store_adapter.py`. These dicts are writer-specific telemetry, not the core
  extractor's vector, so stamping the extractor's version would itself be false
  provenance. Each writer now names its own schema inside the dict (`"_schema":
  "greybox/1"` / `"fuzz-csv/1"`), and `feature_version` stays NULL, allowlisted.
- **`attempt.candidate_id`, `score`, `uncertainty`:** reserved for the blocked
  attempt-screening classifier (FR-ML-1). Allowlisted; no reader presents them.
- **`finding.attempt_id`, `case_id`:** findings are not yet linked to attempts or to
  ground-truth cases. The finding view shows no attempt when the value is NULL.
  Allowlisted.
- **Every other column of `candidate`, `attempt`, `flow`, `finding`, `model`,
  `run_metrics`, `run_plugin`, `holdout_*`, `target` and `run`** has a production writer,
  asserted by the guard.
