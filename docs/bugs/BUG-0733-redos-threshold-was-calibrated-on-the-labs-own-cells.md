# BUG-0733 — The ReDoS timing threshold was calibrated on the lab's own cells, with no control of the probe's shape

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
`RegexDosStrategy` confirmed when two evil-regex templates each took longer than
`max(median + 4 sigma, median + 0.02 s)` of three benign samples, one sample per
template. The 20 ms floor and `k = 4` were "calibrated" on this project's own
`node_express` ReDoS cells (CC-FUZZ-0025 / CC-LAB-0076: ~55-70 ms vulnerable, <1 ms secure),
and no control sent a regex of the same shape without the catastrophic part.

## Where encountered
Lane HEUR's review of lab-fitted heuristics in component 07 (2026-11-20), sub-task
HEUR-CD (D1).

## What it caused to fail
- A non-vulnerable endpoint with ordinary jitter could confirm: with every answer
  uniformly 0-40 ms, the former rule (3 samples, 1 sample per template, 2 templates)
  confirmed 0.63 % of candidates in a Monte-Carlo of the rule (CC-FUZZ-0711 "Measured").
- A target slow for any regex-shaped input (a compile cost, a validation or error path)
  confirmed: nothing separated "a pattern" from "an ambiguous pattern".
- A target slower or noisier than the lab cells had a threshold set by the lab's figures,
  not its own.

## What the bug was identified to be
A detection threshold fitted to one generator's cells, and a differential whose control
did not have the probe's type (PA-0117(1)): the benign term is not a regex of the
template's shape.

## Root cause analysis
Five whys:
1. Why 20 ms / k = 4 / 3 samples? They were chosen so the labgen cell's ~60 ms blowup
   cleared and its <1 ms secure twin did not.
2. Why tune to the cell? The acceptance test was the cell (`tests/test_labgen_redos.py`),
   and the class docstring cited "this project's own calibration" as the jitter figure.
3. Why no structural control? The strategy was modelled on `_confirm_timing`, whose
   requested delay plays the control's role; ReDoS has no requested delay, and nothing
   replaced it.
4. Why one sample per template? "Two templates" was taken as the replication, but two
   templates are two probes, not a repeat of one.
5. Why did PA-0117 not catch it? Its discovery guard runs every strategy against
   payload-independent noise (constant, periodic, signature-always); a random-jitter
   source and a "slow for any pattern" source were not in its set.

**Root cause:** the threshold came from the lab rather than the target's own answers,
and the differential lacked a control with the probe's type minus what it tests.

## Corrective action
CC-FUZZ-0711 (FR-FUZZ-711): `_REDOS_CONTROLS` (each template minus its nested/ambiguous
quantifier); every evil sample must exceed the slowest benign-or-control answer by the
pool's own spread (or 4 robust sigmas), at least a 5 ms measured client resolution; 3
alternating rounds per template; 5 baseline samples. Measured on real Node: the vulnerable
cell confirms 5/5, the secure cell 0/5; a 0-40 ms jittery fake never confirms (300 seeds).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`: BUG-0117 / PA-0117 (control is the
probe minus what it tests; differentials replicate), BUG-0630 / PA-0630 (the mutation side
of the same rule, timing), BUG-0529 / PA-0529 (a baseline that is not the application's),
BUG-0660 / BUG-0661 / PA-0660 (lab-fitted detection). This is a recurrence of the
PA-0117(1)/(2) class (no same-type control, no replication) and of the PA-0660 class (a
figure taken from a lab).

## Prior-preventive-action failure analysis
- PA-0117 (BUG-0117): its rule covered this case, but its **enforcement** (point 3) is a
  discovery over three noise shapes, none of which separates a regex-shape cost from the
  ambiguity or injects random jitter at the threshold's scale; ReDoS passed it. The rule
  was not followed for this strategy because nothing checked that each timing strategy
  has a same-type control.
- PA-0630 (BUG-0630) applied the rule only to strategies running the shared timing engine
  (`_confirm_timing`); `RegexDosStrategy` has its own loop, so the guard never saw it --
  **too narrow** (by engine, not by mechanism).
- PA-0660 (BUG-0660/0661) names numbers taken from a lab ("value") but its guard reads
  string tokens, never numeric thresholds -- **not enforced** for constants.

## Preventive action
PA-0730 (written by the lane). Proposed content: every timing differential, whatever
engine it runs, has a control of the probe's own type minus the tested part, re-sends the
probe, and derives its margin from its own measured samples; any fixed time constant is
an instrument floor with a cited measurement, never a target calibration. Enforcement
proposal: extend PA-0117's discovery set with a random-jitter source (uniform 0-40 ms) and
a "slow for any value of the probe's shape" source, run over every `differential-timing`
strategy; the new tests `tests/test_oracle_redos.py::test_a_jittery_endpoint_that_is_not_vulnerable_never_confirms`
and `::test_redos_not_confirmed_when_any_regex_shaped_term_is_slow` are the ReDoS
instances.
