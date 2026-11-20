# BUG-0734 — The IDOR strategy sent two fixed synthetic ids and required each echoed, fitted to lab cells that echo any id

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
`AccessControlIdorStrategy` sent `_ID_A = "50172"` and `_ID_B = "88190475"` to every
access-control candidate and confirmed when both answered 200, each body echoed its id,
no denial phrase appeared and the bodies differed. The ids are not the target's, and the
echo requirement is the shape of the labgen `no_ownership_check` cells, which render any
requested id.

## Where encountered
Lane HEUR's review of lab-fitted heuristics in component 07 (2026-11-20), sub-task
HEUR-CD (D2).

## What it caused to fail
- On a real application the fixed ids name no object: a real IDOR answers 404 or an
  empty record for them, so the strategy could not confirm the class it targets; it
  confirmed only apps that echo arbitrary input (the labgen cells and the documented
  public-echo false-positive class).
- The echo check is trivially satisfied for a short id and says nothing about whether
  the answer is keyed by the id.
- Every confirmation recorded in its tests and change control (twitch-clone
  TWCH-0003/0007, netflix-clone NFLX-0004, the Laravel photo-view shape) was a labgen
  cell.

## What the bug was identified to be
The probe values were invented rather than taken from the target (PA-0660(1)), and the
keyed-ness proof (an echo) was the lab template's behaviour, not a property of IDOR.

## Root cause analysis
Five whys:
1. Why `50172` / `88190475`? CC-FUZZ-0033 needed two "unrelated" ids and the lab cell
   accepted any.
2. Why not the target's own id? Ground-truth-point runs -- the acceptance path -- carry
   no captured value, so a strategy that needed one would have shown no recall there.
3. Why require an echo? The adequacy review asked for precision on the cell's own
   false-positive class, and the cell echoes the id, so echo became the check.
4. Why was a lab-shaped check accepted as generic? It was called "a generic
   differential", and the only targets it was tried on were labgen cells (Go, Spring,
   Laravel templates of one generator -- one source, PA-0660(2)).
5. Why did nothing flag it before? PA-0660's guard reads tokens in answer keys; `50172`
   is in no key, and the rule's "value taken from a lab" covers values a lab supplied, not
   values invented to suit one.

**Root cause:** the acceptance path (ground-truth points with no captured value) pushed
the strategy to invent its probe values and to prove keyed-ness by the lab template's
echo, instead of starting from what the target gave.

## Corrective action
CC-FUZZ-0712 (FR-FUZZ-712): the id is the point's captured value
(`Candidate.base_entries[param]`), the probe its numeric neighbour (+1, else -1; OWASP
WSTG-ATHZ-04, API1:2023 BOLA); the captured id is sent twice and must replicate; fp=0
safeguards kept (both 200, non-empty, distinct bodies, no denial phrase); no captured
value or no numeric neighbour is `UnplaceableLocation` (no verdict). Crawl runs supply
the value (query links, forms, path segments); ground-truth runs do not, and lose these
points as stated misses (twitch-clone 11 -> 9, netflix-clone multi-cell 9/11 -> 8/11 on
the oracle diagnostic).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`: BUG-0661 / PA-0660 (seven strategies
sent one cell's own field names -- the same root cause: a strategy shaped to a lab cell),
BUG-0660 (rules), BUG-0124 / PA-0124, and BUG-0117 / PA-0117(2) (differentials replicate).
Recurrence of the BUG-0661 class.

## Prior-preventive-action failure analysis
PA-0660 (BUG-0660/0661) forbids names and values "taken from a lab" and its guard reads
answer-key and manifest tokens. This strategy's values were invented, not taken -- they
appear in no key -- so the guard could not see them, and BUG-0661's sweep looked for the
cells' field names, not for synthetic probe values or lab-shaped checks. PA-0660 was
**too narrow in its enforcement** (lexical, key-derived) and its sweep was by symptom
(names) rather than by mechanism (where does each probe value come from).

## Preventive action
PA-0730 (written by the lane). Proposed content: every probe value a strategy sends
either comes from the target (the captured request, the response), from a cited public
corpus, or is a fresh random token whose only role is a marker; an invented "realistic"
constant (an id, an amount, a username) is lab-fitted. A strategy's acceptance runs
include a crawl run, so a mechanism is never shaped to the ground-truth path's missing
data. Enforcement proposal: an AST guard over strategy modules flagging a class-level
numeric-string constant sent through `_send`, proven on a synthetic offender (the former
`_ID_A`), plus `tests/test_oracle_strategies_access_control.py::test_sends_only_the_targets_id_and_its_neighbour`.
