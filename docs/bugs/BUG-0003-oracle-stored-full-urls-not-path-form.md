# BUG-0003 — Oracle stored findings with full URLs, not path form

- Date: 2026-09-21
- Status: fixed
- Severity: medium

## Description
The deterministic oracle — the sole writer of `finding` labels (T2.1) — recorded
each finding's URL verbatim from the candidate (`http://localhost/product.php`).
Every other result URL in the store (pages, endpoints, parameters, and the
adapter-imported findings) is written in **path form** (`/product.php`) so it
lines up with the ground-truth contract, which is authored in paths. Findings the
oracle wrote therefore did not match ground truth, so the harness scored them all
as false alarms.

## Where encountered
Wiring the automatic-mode pipeline (T2.8, `fuzzlab/harness/pipeline.py`), verified
by `tests/test_pipeline.py::test_run_pipeline_scored_end_to_end`. The pipeline is
the first path that runs the oracle and the harness scorer against ground truth in
one flow, so it is the first place the mismatch could surface.

## What it caused to fail
`ScoreReport(tp=0, fp=3, tn=8, fn=8)`: three genuine, oracle-confirmed
vulnerabilities (product SQLi, blog_post SQLi, search XSS) were all counted as
false alarms, and the same three as false negatives, because
`http://localhost/product.php` never equals the ground-truth key `/product.php`.
Every true finding was double-penalized (an FP and an FN). On a live scored run
this would have reported 0% precision and 0% recall despite the oracle working
correctly.

## What the bug was identified to be
`Oracle._write_finding` inserted `candidate.url` directly into the `finding.url`
column instead of normalizing it to path form first. The path-normalization
convention existed and was documented (`store_adapter` normalized every URL it
imported, and the module docstring stated the rule), but it lived as a private
`_path` helper inside one tool. The oracle — a newer writer of the same column —
did not know about or follow the convention, because it was not enforced in a
single shared place every writer must go through.

## Root cause analysis
Five Whys:
1. Why did scoring fail? Oracle findings carried full URLs; ground truth is keyed
   on paths, so no finding matched.
2. Why did the oracle write full URLs? `_write_finding` stored `candidate.url`
   verbatim, skipping normalization.
3. Why was normalization skipped? The oracle author did not apply the path
   convention — it was not visible or required at the point of writing.
4. Why was it not visible/required? The convention was implemented as a private
   helper (`store_adapter._path`) and stated only in that module's docstring, not
   exposed as a shared utility that every finding/URL writer imports.
5. Why does that matter? A convention that lives inside one writer is invisible to
   the next writer of the same data. Each new writer must independently rediscover
   and re-implement it, and one that does not silently violates it.

**Root cause:** a cross-cutting storage convention (URLs stored in path form for
ground-truth cross-referencing) was implemented per-writer rather than in one
shared function applied at every write site, so a later writer bypassed it.

## Corrective action
- Added `fuzzlab/core/urls.py` with `to_path(url)` — the single home of the
  path-normalization convention, with a docstring stating that result URLs are
  stored in path form and writers must not normalize ad hoc.
- `Oracle._write_finding` now stores `to_path(candidate.url)`. The candidate's
  full URL still flows through the confirmation strategies unchanged (they need
  the sendable absolute URL to issue probes); only the stored finding is
  normalized.
- Swept the codebase for the bug class (PA-0002): `store_adapter` had its own
  local `_path` doing the same job — replaced it with the shared `to_path` so
  there is exactly one implementation. Confirmed the candidate-evidence URL is
  intentionally the full sendable URL (the oracle re-sends from it) and only the
  scored `finding` column is normalized, so no other writer needed changing.
- Suite green (108/108), including the previously-failing scored pipeline test.

## Preventive action
PA-0003 (see `docs/PREVENTIVE_ACTIONS.md`): a storage/serialization convention
that must hold across multiple writers lives in exactly one shared function that
every writer calls at the write site — never as a per-writer private helper or a
convention stated only in prose. New writers of the same column/field go through
the shared function.
