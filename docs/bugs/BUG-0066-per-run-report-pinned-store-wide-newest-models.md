# BUG-0066 — The per-run report pinned the store's newest models, not the run's own

- Date: 2026-10-13
- Status: fixed
- Severity: low–medium (a reproducibility record, `fuzzlab report`, named the wrong
  model versions for every run except the latest. No result, finding or score was
  affected.)

## Description
`fuzzlab/report/report.py::build_report(store, run_id)` builds a deterministic report
for **one run**. Its "Reproducibility" block (`model_versions`, and the `models` list)
lists "the deployed models". It read them with `SELECT name, MAX(version),
feature_version FROM model GROUP BY name`, i.e. the newest version of each model name
**anywhere in the store**. Once a later run trained its own classifier or ranker, an
earlier run's report cited the later run's models as the ones that produced it.

## Where encountered
Found on 2026-10-13 by both reviewer agents, independently, in the pre-change review
gate for CC-ML-0015 / CC-UI-0038 (saving trained models). That change was about to add
each model's params sha to the same block. Pinning a sha to the wrong model would have
made a false reproducibility claim *more* convincing.

## What it caused to fail
- A store with two runs that each trained a classifier and a ranker: run 1's report
  said `model_versions: {logistic: 2, ranker: 2}`, which are run 2's models. Anyone
  reproducing run 1 from its report would have used the wrong model versions.
- The report is the project's reproducibility artefact (Phase 10 T10.4, "names the
  versions/plugins that produced" a run). That is exactly the claim this broke.

## What the bug was identified to be
A per-run reader used a store-wide selection. `MAX(version) … GROUP BY name` is
correct for "the newest model of each family", but not for "the models this run used".

## Root cause analysis
Five Whys:
1. Why did run 1's report cite version 2? It read `MAX(version)` per name across every
   run.
2. Why was that query used? It was written (`CC-UI-0009`, Phase 10 T10.4) when the
   `model` table had no run scope at all, so "newest per name" was the only selection
   available.
3. Why wasn't it fixed when run scope arrived? `CC-ML-0011` (BUG-0061) added the run
   scope (`calibration.run_id` + `select_latest`). Its PA-0002 sweep examined this exact
   query and recorded "`report.py:65` (`GROUP BY name`, per-family correct) — not an
   instance".
4. Why did the sweep clear it? It judged the query against the *table's* producers
   (one row per family, which is correct) and not against the *reader's* own scope,
   which is per run. The query was right for a store-wide view and wrong for this
   function.
5. Why did PA-0066 (BUG-0065, later the same day) not reopen it? PA-0066 extended the
   rule to joins and told sweeps to grep by mechanism. It still said nothing about
   checking each reader against its own scope. The report's query was a selection,
   not a join, and had already been cleared.

**Root cause:** each sweep for this scope-bug class asked whether a query was right for
the *data* it reads (which producer and which run wrote the row). None asked whether it
was right for the *reader's* contract. A per-run function can be "correct per family"
and still wrong for its run.

## Corrective action
Delivered in `CC-UI-0039` (`docs/components/12-diagnostics-and-ui/change-control.md`),
after a 3/3-agreed pre-change review, in the same commit as CC-CORE-0027, CC-ML-0015
and CC-UI-0038:
- `build_report` now builds `models` / `model_versions` from `latest_classifier(store,
  run_id)` and `latest_ranker(store, run_id)`: the models whose scope covers this run
  (FR-ML-10). Legacy rows without a run scope still cover every run, as before.
- The new `model_params_sha256` block is built from the same pins.
- `tests/test_ml_persist.py::test_report_pins_the_runs_own_models_not_the_newest`: two
  runs each train, and run 1's report pins `{logistic: 1, ranker: 1}` and run 1's sha.
  It fails with the old store-wide selection (mutation-checked).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0061 / PA-0063**: "newest row of any family, any run" on the run page and ML
  tab. **The same bug**, in a third reader. Worse, BUG-0061's own sweep inspected this
  line and explicitly cleared it.
- **BUG-0065 / PA-0066**: a store-wide join keyed without the run. Same root-cause
  family (a scope missing from a store read); PA-0066 strengthened PA-0063 for joins.

**Result: a recurrence of BUG-0061 / PA-0063**, in a site that the prior sweep wrongly
cleared, after PA-0066 had already strengthened the rule once.

## Prior-preventive-action failure analysis
- **PA-0063 itself was applied.** Its sweep found this query and reached a verdict, so
  the rule was not ignored. The verdict was wrong because the sweep's question was
  incomplete. It checked the query against the *rows' scope* (family, run) and not
  against the *reader's scope*. A sweep that records "correct" without naming the
  reader's contract cannot tell "correct for a store-wide view" from "correct for this
  per-run function".
- **PA-0066 widened what counts as an instance** (joins) and **how to find candidates**
  (by mechanism). It did not change **how to judge** one, so a previously cleared site
  stayed cleared.
- Neither is mechanically enforced at the report. The `model`-table guard
  (`test_no_module_reads_model_as_newest_row_of_any_family`) only catches `DESC` /
  `LIMIT 1` "newest row" shapes, and `MAX(version) … GROUP BY` is a different shape of
  the same mistake.

## Preventive action
**PA-0067** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0063 and PA-0066 in how a
sweep judges a site:
1. **A sweep verdict names the reader's scope.** For each site, record what the reader
   is *for* (one run's page or report, one run's training, a store-wide view) and
   whether the query's scope matches that. "Correct per family" or "correct per name"
   is not a verdict for a per-run reader. A site cleared without naming its reader's
   scope counts as unswept.
2. **Per-run readers of `model` go through the run-scoped readers.** Every function
   that takes a `run_id` and reads `model` uses `select_latest` /
   `latest_classifier` / `latest_ranker` with that `run_id`. The guard is extended:
   no `fuzzlab/` module may read `model` with `MAX(version)` either, except a
   store-wide registry view that says so in its own docstring.
3. **A recurrence in a site the prior sweep cleared triggers a re-sweep** of every site
   that sweep cleared, judged with rule 1. The re-sweep is recorded below.

**Re-sweep of BUG-0061's "not an instance" verdicts, judged by reader scope (PA-0067
rule 3):**
- `report.py:65` was a per-run report: **an instance**, fixed here.
- `web/diagnostics.py::model_registry_timeline` is a store-wide registry view listing
  every row by design: not an instance. The extended guard exempts it by name.
- `train.py` / `rank_train.py::_next_version` take "newest version of *this* name" to
  number a new row, a store-wide counter by design: not an instance.
- BUG-0061's other cleared reads (`results.py:79/388`, `diagnostics.py:86`,
  `findingsview.py:81`, `proxycontrol.py:307`, `mlview.py` `payload_variant`,
  `report.py:26/40`) are list views or run-filtered single-producer reads whose scope
  matches their reader: not instances.
