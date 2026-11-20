# BUG-0630 — Command-injection timing payloads dropped the value their baseline sent

- Date: 2026-11-20
- Status: fixed (CC-FUZZ-0631)
- Severity: medium. False negatives only: a shell command injection behind a filter that
  refuses `;` and `&` was never confirmed when the command the app runs on the baseline
  value itself takes time. Nothing false was confirmed and nothing extra was sent.

## Description
`CommandInjectionStrategy.confirm` (`fuzzlab/oracle/strategies.py`) on a point with no
base value of its own timed three baseline samples of the value `1` and then sent the
bare templates of `_CMDI_TIMING_TEMPLATES` (`; sleep 2`, `| sleep 2`, `$(sleep 2)`,
...). The baseline value made the application run its command on a host (`ping -c 2 1`,
about 1 s); a bare payload left the command no host, so it failed at once and only the
sleep was timed. The added latency the engine saw was the sleep minus the baseline's own
work: about 1 s for a 2 s request, under the 1.5 s floor, so no template confirmed.

## Where encountered
The JAVA lane's baseline run of SasanLabs OWASP VulnerableApp 2.2.115 (CC-LAB-0350,
`fuzzlab auto --points ground-truth --browser --oob`, 2026-11-20): CommandInjection
LEVEL_1 and LEVEL_2 confirmed (their filters let `; sleep` through, which runs after the
ping), LEVEL_3..5 never did. The run's trace showed baseline samples of 1.02 s and
mutations of 2.01 s (`| sleep 2`, `$(sleep 2)`) or 3 ms (`; sleep 2`, refused by the
level's raw-URL check for `%3B`).

## What it caused to fail
Three positives missed (VAPP-0045..0047). Measured with curl at the same time:
`127.0.0.1$(sleep 2)` took 3.02 s at LEVEL_3 and LEVEL_5, `127.0.0.1|sleep 4` 4.0 s at
LEVEL_3: the levels were injectable through separators the strategy already sends.

## What the bug was identified to be
A timing differential whose two sides did not differ only by the part under test: the
baseline carried a value (`1`) that the payloads replaced instead of extending. The
base-value branch of the same method already prefixed every template with the base
value; the no-base branch did not prefix the baseline's own value.

## Root cause analysis (Five Whys)
1. Why did LEVEL_3..5 not confirm? The measured added latency (~1.0 s) stayed under the
   floor (1.5 s) for every template that passed the level's filter.
2. Why only ~1 s for a 2 s sleep? The baseline's 1 s (ping on host `1`) was not in the
   payload: `ping -c 2 $(sleep 2)` runs the sleep, then ping fails at once with no host.
3. Why was the host missing from the payload? With no base value the strategy sent the
   bare templates, while its baseline sent `1`.
4. Why was that never seen? Every test's fake application took the same time for any
   value that does not sleep, so dropping the baseline's value cost nothing there; and
   LEVEL_1/2-shaped sinks (`; sleep` runs after the command) hide it, since the
   baseline's work happens on both sides anyway.
5. Why did no rule catch it? PA-0117(1) states the symmetry of a differential only from
   the control side ("the control has the probe's type, minus what the probe tests") and
   is enforced by noise discovery, which finds false confirmations, never a missed one.

**Root cause:** the timing engine's callers chose the mutation's value with no rule that
a mutation is the baseline's value plus the tested part, and no guard compared the two.

## Corrective action
CC-FUZZ-0631: `cmdi_timing_payloads(base)` builds every payload as the baseline's own
value followed by a template (`_CMDI_BASELINE = "1"` when the point has none; a template
already starting with it is not prefixed twice), and `CommandInjectionStrategy.confirm`
uses it on both branches. Live on VulnerableApp: LEVEL_3 and LEVEL_4 confirm through
`1|| sleep {d}` (3.03 s / 5.04 s against a 1.02 s baseline), LEVEL_5 through
`1$(sleep {d})`; LEVEL_6..8 (SECURE) stay unconfirmed.

## Recurrence review
Checked `docs/bugs/` (the timing, baseline and differential reports: BUG-0072, BUG-0117,
BUG-0127, BUG-0135, BUG-0529) and `docs/PREVENTIVE_ACTIONS.md` (every PA naming a
baseline, a control or a differential: PA-0017, PA-0117, PA-0529, PA-0528). No earlier
bug where a mutation dropped the baseline's value. Same root-cause family: **BUG-0117 /
PA-0117** -- an asymmetric differential (there, a control that was not the probe minus
the tested part, giving false confirmations).

## Prior-preventive-action failure analysis
PA-0117 (from BUG-0117) did not prevent this because it was **too narrow and enforced at
the wrong layer for this failure mode**: (1) its rule (1) constrains the *control* given
the probe, not the *mutation* given the baseline; (2) its enforcement
(`test_payload_independent_noise_never_confirms_any_sqli_strategy` and the discovery
guards) runs every strategy against payload-independent noise and fails only when
something confirms, so an engine that can never confirm on a real sink passes it; (3) it
was written for marker and response differentials, and the timing engine's callers were
reviewed only for a stable baseline (rule 2), which this one had.

## Preventive action
PA-0630 (strengthens PA-0117(1)): in a timing differential every mutation is the
baseline's own value plus the part under test, never a replacement of it; enforced by
discovery over every default strategy running `_confirm_timing`, with and without a base
value, proven on a synthetic offender (`tests/test_timing_payloads_carry_the_baseline.py`).
PA-0002 sweep: the two callers of `_confirm_timing` (SQLi timing: every template already
starts with `1`, its baseline; command injection: fixed) and the timing strategies
outside it (`RegexDosStrategy`: its payloads are escalating shapes timed against its own
benign sample, not a value extended, so the rule does not apply; the OOB command
injection templates are not timed).
