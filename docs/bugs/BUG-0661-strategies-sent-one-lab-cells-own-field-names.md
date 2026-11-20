# BUG-0661 — Seven confirmation strategies sent one lab cell's own field names

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
Seven strategies in `fuzzlab/oracle/strategies.py` were written for one labgen cell each
and hardcoded that cell's names -- a convention their own docstrings stated ("hardcode the
sink's own known field name in the strategy"):
- `JwtAlgNoneConfusionStrategy`: the `channel_id` / `role: owner` claims (CC-LAB-0180).
- `PredictableTokenSourceStrategy`: the response key `session_token` (CC-LAB-0181).
- `MassAssignmentPrivilegedFieldStrategy`: `is_partner`, `display_name`, `bio` (CC-LAB-0182).
- `PriceTrustDifferentialStrategy`: `monthly_charge`, `plan_tier: standard` (CC-LAB-0188).
- `PriceIntegrityBypassStrategy`: booking-clone's `data-charged-amount` attribute and its
  rate table `89.00/149.00/249.00` (CC-FUZZ-0047).
- `GoTemplateSstiStrategy`: the JSON key `template` (CC-LAB-0196).
- The XXE wrapper `<r><title>&xxe;</title></r>`: the labgen XXE sink's extracted element.

## Where encountered
Lane BBOX's sweep of `strategies.py` (2026-11-20); `channel_id` also reported by the new
guard `tests/test_blackbox_detection.py` (`strategies.py:2075`, `:2082`).

## What it caused to fail
On a black-box target these strategies could confirm only an app that happened to use the
lab's names; the labs' recall (twitch-clone 14/15, netflix-clone 11/11) overstated real
detection.

## What the bug was identified to be
Lab knowledge (the generated sink's field, claim, element and attribute names, and its
price table) in confirmation logic rather than in the fixtures and answer keys.

## Root cause analysis
Five whys:
1. Why did the strategies send `channel_id`, `monthly_charge`, `is_partner`? Each was built
   to confirm one generated cell, and the cell's template reads only those names.
2. Why build to the template? The acceptance check was a live boot of that cell; a generic
   draft (a `{"marker": ...}` claim) failed it and was "corrected" to the template's names
   (FR-FUZZ-23's own record).
3. Why was that read as a correction? The labgen apps were treated as real targets, so
   matching their template counted as matching reality.
4. Why was it repeated six times? The first strategy's docstring named the practice a
   project convention, and later strategies cited it as precedent.
5. Why did nothing stop it? No rule or guard separated lab knowledge from detection code.

**Root cause:** the same as BUG-0660: no rule and no guard kept lab knowledge out of
detection logic; here a docstring "convention" turned it into precedent.

## Corrective action
CC-FUZZ-0660 (lane BBOX): each strategy now takes its names from the target (the captured
body's leaves, the response's own properties) or from a public standard (RFC 7519, OIDC
Core, W3C XML 1.0), and gives no verdict when the target offers none. Measured on real
labgen boots (oracle diagnostic): twitch-clone 14 -> 11, netflix-clone 11 -> 9; the weak
token, mass assignment and XXE (out-of-band) cases still confirm generically.

## Recurrence review
Same review as BUG-0660 (same lane, same day): BUG-0124 / PA-0124 and F-011, F-013, F-014,
F-049, F-284 are the prior occurrences of detection fitted to the labs at hand; BUG-0660 is
this lane's sibling (rules).

## Prior-preventive-action failure analysis
As in BUG-0660: PA-0124 was too narrow (classifier mapping only) and nothing enforced the
class. In addition, these strategies passed their own reviews because the review question
was "does it confirm the real boot", which a lab-fitted strategy answers best.

## Preventive action
PA-0660 (the black-box rule and its guard) covers string literals in every strategy; its
point 3 forbids a strategy confirming against a lab's names, and a strategy docstring may
not set a convention that does. The guard's token set includes every answer key's
parameter names; names that appear only inside a generated template (not in a key) are
caught by the rule and review, not the guard (stated in PA-0660(5)).
