# BUG-0061 — Readers of the shared `model` table picked "the newest row of any family, any run", losing the classifier's conformal decisions

- Date: 2026-10-13
- Status: fixed
- Severity: medium (advisory triage silently disappears or is computed with the wrong
  run's thresholds; no `finding` label is affected — ML never writes labels)

## Description
The run page's "Model scores (advisory)" card and the ML tab's conformal panel read
the classifier's conformal calibration (`t_lo`/`t_hi`) from "the newest `model` row".
That table is also written by the candidate ranker, and by every run's own training,
so "newest row" is frequently not the classifier that scored the run being viewed.

## Where encountered
Found in a code review of the ML components on `main` @ `0800e42` (2026-10-13), then
reproduced offline with `tests/test_ml_train.py::_seed_rich`, and independently
re-reproduced by the two reviewer agents of this change's pre-change review gate.
Code: `fuzzlab/web/results.py::_scored_candidates` (formerly line 47) and
`fuzzlab/web/mlview.py::conformal_panel` (formerly line 181), both
`SELECT name, version, calibration FROM model ORDER BY id DESC LIMIT 1`.

## What it caused to fail
1. **Ranker after classifier** — `fuzzlab auto --score --rank` runs the classifier, then
   the ranker (`harness/auto_cli.py:153-162`). The ranker's row
   (`calibration={"at_k": 10}`, no thresholds) became the newest, so the run page showed
   decision `n/a` for **every** candidate under model name "ranker" (reproduced: `flag`
   before ranking, `n/a` after), and the ML tab reported "latest model has no
   conformal calibration". The flag/abstain/drop triage the classifier exists to give
   vanished whenever both flags were used.
2. **Another run trained later** — run 1's page gated run 1's scores with run 2's
   thresholds, calibrated on a different model's out-of-fold scores (reproduced by a
   reviewer: run 1's page showed `logistic v2`).

## What the bug was identified to be
Two read sites each inlined an unfiltered "newest row" query over a table that two
model families and many runs write, with no family or run column to distinguish them.
The family is derivable only from `model.name`; the run was not recorded at all.

## Root cause analysis
Five Whys:
1. Why did the decision show `n/a`? The reader built no `ConformalGate`, because the row
   it read had no `t_lo`/`t_hi`.
2. Why did it read a row without thresholds? It read the newest `model` row, which was
   the ranker's.
3. Why did "newest row" stop meaning "the classifier"? The query was written in
   `CC-UI-0008` (Phase 5) when only the classifier wrote `model`. `CC-ML-0006` (Phase 7)
   then made the ranker write the same table, and nothing required checking the
   existing readers of that table when a new writer of a different kind was added.
4. Why were there two broken readers, not one? `CC-UI-0031` (the ML tab) re-derived the
   same selection inline, copying `results.py`'s query, instead of calling one shared
   reader. "Which `model` row is the deployed classifier" was never recognized as a
   convention needing one home.
5. Why did no test catch it? Every reader test seeded a single classifier row. No test
   trained a classifier and then a ranker, or two runs, against the same store.

**Root cause:** a selection convention over a table written by more than one producer
(which row is "the deployed model of family F for run R") lived inline at each read site
as an unfiltered "newest row" query, rather than in one shared, family- and run-scoped
reader. And adding a new producer to that table did not trigger a sweep of its existing
readers.

## Corrective action
Delivered in `CC-ML-0011` (`docs/components/10-ml-components/change-control.md`) and
`CC-UI-0034` (`docs/components/12-diagnostics-and-ui/change-control.md`), after a
3/3-agreed pre-change review:
- New `fuzzlab/ml/model_registry.py::select_latest(store, names, run_id)`: the one
  `FROM model … ORDER BY id DESC` query in `fuzzlab/`. It returns the newest row of the
  named family whose recorded scope covers the run: same `run_id`, null (store-wide
  train), or absent (legacy row).
- `train.py`: `PREVALENCE_FALLBACK_NAME`, `CLASSIFIER_MODEL_NAMES` (derived from
  `_MODELS`), `ClassifierModel` and `latest_classifier`. `rank_train.py`:
  `RANKER_MODEL_NAMES` and `latest_ranker`. Both trainers record `run_id` (and their
  out-of-fold numbers, see BUG-0062) in the row's calibration JSON. No schema change.
- `_scored_candidates` and `conformal_panel` call `latest_classifier(store, run_id)`.
- `tests/test_ml_model_selection.py` (14 tests): scope rules, family disjointness,
  classifier-then-ranker and two-run regressions through the real trainers and the
  real web readers, and a source-scan guard (below). With the old query restored in
  `results.py`, the two regression tests and the guard fail.

Known limitation, kept and documented (FR-UI-11): the ML tab's all-runs view
(`conformal_panel(store, None)`) applies the newest classifier's single set of
thresholds to every run's scores. One panel can show only one set; per-run views are
exact.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or the same root
cause:
- **BUG-0003 / PA-0003**: result URLs normalized per writer instead of in one shared
  function. Same root-cause class: a convention spanning several participants of one
  table, implemented per site.
- **BUG-0007 / PA-0021**: credential host key canonicalized inline at the read site.
  PA-0021 generalized PA-0003 to every such convention: "before adding a second,
  independent derivation of a value another path already stores or parses … check
  whether a shared normalization function already exists".

**Result: a recurrence of the BUG-0003/BUG-0007 root-cause class** (one convention,
several sites, no shared function), on a new axis: *row selection* rather than value
normalization.

## Prior-preventive-action failure analysis
PA-0003 and PA-0021 did not prevent this, for three reasons:
1. **Too narrow in framing.** Both are worded around normalizing a *value*: URL path
   form, host keys, "cache keys, identifiers, normalized hosts/URLs/paths". "Which row of
   a shared table is current for a given producer and run" is a selection convention,
   not a value normalization. Neither the `CC-UI-0008` author nor the `CC-UI-0031`
   author recognized it as an instance, so the rule was never consulted. This is the
   same scoping-by-example failure PA-0021 itself diagnosed in PA-0003.
2. **Wrong trigger.** Both rules fire when someone *adds a derivation*. Here the reader
   was correct when written. It broke when a *new writer* (`CC-ML-0006`, the ranker)
   began writing a second kind of row into the same table, and neither rule asks a new
   writer to audit existing readers.
3. **Not enforced.** Both are prose. Nothing mechanical detects a second inline
   derivation, so the copy in `CC-UI-0031` passed review and tests.

## Preventive action
**PA-0063** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0003/PA-0021 on each of
the three failure modes:
1. It names the missing axis. Selecting "the current row" of a table that more than one
   producer (model family, tool, run) writes is a convention like any other. It lives
   in one shared reader, scoped by the producer and by whatever the row is "current
   for" (here, the run). It is never an inline `ORDER BY id DESC LIMIT 1` at a read
   site.
2. It adds the writer-side trigger. A change that makes a new producer write rows into
   an existing table must, in the same change, grep every reader of that table
   (`FROM <table>`) and check it for single-producer assumptions.
3. It is mechanically enforced for `model` by
   `tests/test_ml_model_selection.py::test_no_module_reads_model_as_newest_row_of_any_family`.
   This is an `ast` scan of every string under `fuzzlab/`, exempting only
   `select_latest`. Its regex was proven against synthetic buggy and benign fixtures
   first (PA-0034(2), PA-0022).

**PA-0002 sweep.**
- *Other readers of `model`:* `report/report.py:65` (`MAX(version) … GROUP BY name`,
  correct per family) and `web/diagnostics.py::model_registry_timeline` (lists every
  row by design) are not instances. `_next_version` filters `WHERE name=?`.
- *Every other "latest row" read in `fuzzlab/`* (`grep -rn "DESC LIMIT 1\|MAX(id)\|ORDER
  BY id DESC"`): `report.py:26/40` (`run`; `target` filtered by `run_id`),
  `results.py:79/388` and `diagnostics.py:86` (list runs), `findingsview.py:81`,
  `mlview.py` `payload_variant` and `proxycontrol.py:307` are all list views or
  single-producer, run-filtered reads, so none is an instance.
- *The other half of the class:* the ML tab also showed *metrics* that did not belong to
  the model whose scores it displayed. That case is fixed under BUG-0062 /
  `CC-UI-0035`, which reads them from the same run-scoped row.
