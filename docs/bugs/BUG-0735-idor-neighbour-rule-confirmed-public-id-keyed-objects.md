# BUG-0735 — The IDOR neighbour rule confirmed public id-keyed objects (a catalogue page was an access-control finding)

- Date: 2026-11-20
- Status: fixed (before merge)
- Severity: high (a false-positive class on every crawl run)

## Description
CC-FUZZ-0712 (BUG-0734's fix) changed `AccessControlIdorStrategy` to send the point's
captured id and its numeric neighbour, and to confirm when the captured id answered 200
twice with the same body and the neighbour answered 200 with a different, non-empty body
and no denial phrase. Every public page keyed by a numeric id satisfies that: a product
`?id=41` and `?id=42`, a public profile, a blog post. Since CC-AUD-0660, `R-ACCESS-CONTROL`
nominates every id-shaped GET parameter, so every such page of a crawl run would have
become an `access_control` finding.

## Where encountered
Lane HEUR's review of the HEUR-CD sub-agent's diff, before merging it (2026-11-20). The
sub-agent's own docstring named the limitation ("can also false-positive on a
legitimately public object keyed by id"); the old echo requirement with an arbitrary
large id had masked the class on real apps (such an id names no object), and removing it
unmasked it.

## What it caused to fail
Nothing shipped: the defect existed only on the sub-agent's branch. Had it merged, the
external-lab crawl runs would have reported public id pages (catalogues, posts, product
reviews) as broken access control; a ground-truth negative on such a page would have
scored fp > 0.

## What the bug was identified to be
The verdict lacked the premise of the vulnerability: an IDOR is access to an object the
caller must not reach (OWASP WSTG-ATHZ-04; OWASP API1:2023), which presupposes the object
is protected at all. Nothing in the probe set tested that premise.

## Root cause analysis
Five whys:
1. Why did a catalogue confirm? Two neighbouring public objects are two distinct,
   stable, 200 answers -- exactly the rule.
2. Why was there no control for "public"? The strategy had never needed one: the fixed
   ids of CC-FUZZ-0033 named no real object, so a real catalogue answered them 404.
3. Why was that not noticed when the ids changed? The documented false-positive class
   ("a public echo endpoint does confirm") had been pinned by a test as accepted, so a
   wider version of it read as the same accepted limitation.
4. Why was it accepted in the first place? The strategy was validated only on labgen
   cells that have no authentication, where no protected/public control is possible.
5. Why did the rewrite keep the acceptance? The brief asked to keep the fp=0 safeguards
   that existed; it did not ask which safeguard the removed echo check had been doing
   implicitly.

**Root cause:** a confirmation rule's precision rested on an implicit control (a
non-existent id) that was neither named nor tested; replacing the probe values removed
the control without anyone seeing it, because the strategy had no explicit control for
the vulnerability's premise (the object is protected).

## Corrective action
CC-FUZZ-0714 (FR-FUZZ-714): the neighbour must also be refused to the same request sent
with no session (the run's unauthenticated sender, `PeerAccounts.anonymous`, which
`fuzzlab auto` now builds for every logged-in run); no such sender -> no verdict.
Tests: a public echo endpoint and a public catalogue give no verdict; a protected one
confirms; the three IDOR live boots now give no verdict (their cells serve objects with
no session at all -- an honest, stated miss).

## Recurrence review
- **BUG-0734** (this lane, same strategy): the fixed ids were the lab-fitted part; this bug
  is the precision its removal exposed. Same item, first bug spawned by its fix (PA-0144
  counts one).
- **BUG-0117 / PA-0117** ("the control is the probe minus what it tests") and **BUG-0630 /
  PA-0630** (the control side and the mutation side): the same root -- a differential
  without the control that isolates what it claims. PA-0117 governs controls a strategy
  *has*; it did not require a strategy to have a control for its vulnerability's premise.
- **BUG-0660 / BUG-0661 / PA-0660**: the black-box rule demanded target-derived values,
  which BUG-0734's fix delivered; it says nothing about keeping a rule's precision when its
  values change.

## Prior-preventive-action failure analysis
PA-0117 and PA-0630 were **too narrow**: they define what a control must be, not that a
confirmation must test the premise that makes the observed difference a vulnerability.
PA-0660 was **not designed** for this: replacing lab values with target values is
necessary, but a change of probe values can silently remove an implicit control, and no
rule asked for the controls a value change removes to be named.

## Preventive action
PA-0730 (point 4: a strategy names the control for its vulnerability's premise, and a
change of its probe values lists the implicit controls it removes, each replaced or the
loss stated), enforced by
`tests/test_oracle_strategies_access_control.py::test_a_public_catalogue_neighbour_gives_no_verdict`
and `::test_no_verdict_without_an_unauthenticated_sender`.
