# BUG-0519 — The finding filter lost the flows it did not derive from the finding's event

- Date: 2026-10-19
- Status: fixed (CC-UI-0063)
- Severity: medium. A finding's filtered data flow, the view FR-UI-510 offers as that
  finding's evidence, showed its interface without the flows into it, or nothing at all.

## Description
`report.diagram.dataflow(..., finding=F)` decided what finding F cites by itself, apart
from `finding_links` and the finding's sequence, and got two things wrong:
1. **The actor list (since 9b17d0d).** It kept only flows whose source was in
   `cited | parents | {APP, TOOL, BROWSER}`. BUG-0515's fix (9b17d0d) moved the
   spider's own page loads from `actor:browser` to `actor:spider`. The list was not
   updated, so the spider's flow into the finding's interface was dropped.
2. **The attribute cap (since ede72b9).** It found the cited interface through the
   entity attribute `attrs.finding`. The reducer caps every attribute at
   `MAX_ATTR_VALUES` (40) values, keeping the smallest plus `finding_more`. From the
   41st finding on an interface onward, no entity cited the finding, and the filter
   kept no interface and no flow.

## Where encountered
DG-FINDLINK. Measurement before designing the Findings → Diagrams link (CLAUDE.md #8):
- Half 1: a real `run_auto` with the spider import recorded. `finding_links` listed
  `flow:app:actor:spider->…` and the tool's flow. `dataflow(finding=F)` returned 0
  flows, and 1 flow (the tool's) with the overlay.
- Half 2: found by both gate reviewers of CC-UI-0063's draft, and reproduced: 45 findings
  on one interface. For findings 41–45, `dataflow(finding=F, overlay=True)` returned
  0 flows while `finding_links(F)` listed 2.

## What it caused to fail
The Diagrams page's finding filter (and anything linking to it, such as the planned
deep link). It showed an interface with none of the traffic that reached it, or an
empty diagram for a finding the sequence draws fully. The JSON and Mermaid exports pass
no finding filter and were not affected.

## What the bug was identified to be
A second implementation of the relation "finding F → its interface and that
interface's flows". It was read from a capped display attribute and an enumerated actor
list, instead of from the finding's own trace event, which `finding_links` and
`_finding_sequence` read.

## Root cause analysis
Five whys:
1. Why did the filter drop the spider's flow? Its keep-set enumerated the actors whose
   flows it kept, and `actor:spider` was not among them.
2. Why was the list not updated when the spider actor was added? BUG-0515's sweep
   (PA-0515) went through *drawn elements and counts*, view by view. A filter's
   keep-set is neither, and nothing tied the list to the reducer's actors.
3. Why did findings past the 40th vanish? The filter took "cited by F" from
   `attrs.finding`, a capped summary written for display. The reducer caps it on
   purpose (PA-0516).
4. Why did the filter read a summary and a list at all? It was written as its own
   derivation of the relation. `finding_links` already derives the same relation from
   the producer's record (the `finding:<id>` event) and was never compared with it.
5. Why was the disagreement not caught? No test compared the two implementations. The
   filter was tested on one finding of one fixture: under the cap, and before the
   spider actor existed.

**Root cause:** a view re-derived a relation the model already records once, from data
that is not the relation (a capped display attribute, a hand-kept list of ids). No test
held the two derivations equal on every record.

## Corrective action
CC-UI-0063:
- `dataflow(finding=F)` now takes F's interface from `finding_links` (F's own event).
  It keeps that interface, its parent chain (origin, application) and the source of
  every returned flow into it, intersected with the run's entities. There is no actor
  list and no read of `attrs.finding`.
- Tests:
  - `tests/test_diagram_e2e.py::test_the_finding_filter_draws_exactly_the_flows_finding_links_names`.
    For every finding of the real pipeline's run and of a 45-finding interface, the
    drawn flows equal `finding_links(F)["flows"]` (with a box), and equal their app-view
    part without the overlay. The boxes are exactly the interface, its origin, the
    application and the flows' sources.
  - `::test_a_finding_past_the_attribute_cap_keeps_its_interface_and_flows` (PA-0516(1),
    plus a run with no `run.start`).
- Both fail on the old filter: "assert 'actor:spider' in set()", and the 41st finding
  keeping no interface.

## Recurrence review
Checked `docs/bugs/` BUG-0509..0518 and PA-0510..0518, the diagrams series:
- **BUG-0512 / PA-0512.** A consumer composed a correlation id instead of copying the
  producer's. Same family: a consumer re-derived what the producer records.
- **BUG-0510 / PA-0510(1).** Evidence was reconstructed from a field that summarises
  another consumer's result. Same root cause, on the producer side.
- **BUG-0515 / PA-0515.** Its fix introduced half 1, as described above.
- **BUG-0516 / PA-0516.** Made the cap order-independent and tested it. Its consumers
  were not reviewed.

So this is a recurrence of the PA-0510(1) / PA-0512 root cause, one layer out: at a view
reading the model, instead of at an evidence producer or an importer.

## Prior-preventive-action failure analysis
- **PA-0510(1)** is worded for the producer ("evidence of an action is recorded where
  the action happens"). It was enforced only by producer tests, so it never reached a
  view reading the model. Too narrow, and the wrong layer.
- **PA-0512** ("a correlation id is copied from what the producer wrote, never
  composed") covers ids. A relation read from a capped summary attribute is not an id,
  so it did not apply. Too narrow.
- **PA-0515(1)** asked every drawn element to name its supporting event field. The
  filter's keep-set was not a drawn element, so BUG-0515's sweep never looked at it.
  Its sweep was keyed on *output*, not on *every place that enumerates the changed
  set*.
- **PA-0516** proved the cap itself, but not what reads the capped value as if it were
  complete. Not followed through to the consumers.

## Preventive action
PA-0519 (in `docs/PREVENTIVE_ACTIONS.md`). It strengthens PA-0510(1) and PA-0512 from
producers and ids to every view reading the model, and widens PA-0515's sweep:
1. A view or filter takes a relation from the record that defines it: the producer's
   event, or the model's links. It never takes it from a capped or summary attribute,
   or from an enumerated list of kinds or ids.
2. Where two functions derive one relation, a test holds them equal on every record of
   a real run, and on a fixture past every cap.
3. A change that adds or splits an entity kind or actor sweeps every enumeration of
   kinds or ids in `report/diagram.py` and `static/js/diagrams.js`, filters included.

**PA-0002 sweep:**
- No other keep-set or filter in `report/diagram.py` enumerates actor ids. The two
  `boundaries` lists are descriptions, and they list all three client actors.
- The origin filter selects by kind, not by id.
- One reader of a capped attribute **as a count** remains, and is not remediated here:
  - `static/js/diagrams.js` labels an interface `⚑<n>` with `(k.attrs.finding).length`,
    so 45 findings show as ⚑40. The same interface's coverage `finding` count, from
    events, is correct.
  - It is left to the item owner. It is outside DG-FINDLINK's agreed scope (PA-0143),
    and it needs its own browser test.
- The tooltips that list `attrs.status`, `data` and `auth` show capped *listings* that
  have no "more" marker. They are not counts or relations, and are recorded here only
  as a limit.
