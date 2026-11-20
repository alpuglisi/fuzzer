# Held-out labs — the black-box benchmark (FR-LAB-420..423)

Every lab used before this list was also used to tune detection, which flatters its
numbers. The labs below are **held out**: nobody tunes against them, and they are scored
only by **crawl (discovery) runs** — never by ground-truth-point runs. Their score is the
honest measure of real-world detection.

## The rule

1. **No lane may run, measure, read the answer key of, or tune detection against a
   held-out lab.** Detection code (audit rules and engine, oracle and strategies,
   session detection and login discovery, crawler/probe heuristics, run-mode plans)
   is never changed because of anything a held-out lab did or contains.
2. **Only the orchestrator's benchmark runs them:** `scripts/holdout_score.py`, which
   brings each lab up, crawls it (`fuzzlab crawl`, with the lab's identity when it has
   one), runs `fuzzlab auto --points crawl` and scores the run against the lab's answer
   key. It never runs ground-truth points.
3. **Findings that would require tuning are recorded, not fixed.** A miss (fn) or a
   false alarm (fp) a benchmark run shows is written into the benchmark table
   (`docs/components/01-target-lab/holdout-scores.json`) and, where it names a general
   defect, into a ledger item for the owner — never fixed by a change aimed at that lab.
   A fix for a *general* defect is made, measured and verified on non-held-out labs;
   the next benchmark run then shows whether it generalises.
4. **Tests name no held-out lab** except the benchmark's own test file,
   `tests/test_holdout_benchmark.py` (its fixture unit tests and this rule's guard).
   The guard, `tests/test_holdout_benchmark.py::test_no_other_test_file_names_a_held_out_lab`,
   reads the names from the table below. Structural checks that discover every answer
   key from the layout (`tests/test_external_labs_static.py`: the key loads, its
   classes are scoreable, its points pass the destructive rule) are allowed: they name
   no lab and feed nothing to detection.
5. **The black-box guard sees them.** Each held-out answer key lives at
   `lab/ground-truth-<lab>/` like every other key, so PA-0660's guard
   (`tests/test_blackbox_detection.py`, which reads `lab/ground-truth*/`) adds its
   directory name, target id, paths and parameters to the lab-only vocabulary that
   detection code must never contain.
6. **Onboarding is the one exception.** The lane that onboards a held-out lab builds its
   fixture and its answer key by hand from upstream's own docs, solutions and source,
   checked live — and changes no detection code. After onboarding, the lab is held out.
   Adding a lab to this list, or removing one (which ends its holdout for good), is an
   owner decision recorded in `CHANGELOG.md`.

## Held-out labs

The guard and the benchmark read this table: the first column is the lab's directory
(`lab/external/<lab>/`, `lab/ground-truth-<lab>/`); the last column lists, comma
separated, every name a test file may not contain (case-insensitive).

| Lab | Upstream | Stack | Names the guard looks for |
| --- | --- | --- | --- |
| vampi | erev0s/VAmPI | Python / Flask REST API, JWT, OpenAPI | vampi |
| dvws-node | snoopysecurity/dvws-node | Node / Express REST, SOAP/XML, GraphQL, WebSocket | dvws |
| railsgoat | OWASP/railsgoat | Ruby on Rails | railsgoat |
