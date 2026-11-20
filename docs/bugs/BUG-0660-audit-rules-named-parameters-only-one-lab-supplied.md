# BUG-0660 — Audit rules nominated candidates by parameter names only one lab supplied

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
Several rules in `fuzzlab/audit/rules_data/default_rules.json` chose their candidates by
words copied from one lab's answer key: `R-ACCESS-CONTROL` by `channel_id` (twitch-clone)
and `account_id` (netflix-clone, added after that lab's miss); `R-SPEL-INJECTION` by
`sort|sortby|filter|order|expr|expression`, grounded only in expedia-clone's `sortBy`;
`R-SSRF` by `thumbnail` (twitch-clone's `/api/clips/thumbnail`); `R-CSV-FORMULA-INJECTION`
by `label` (booking-clone's export parameter); `R-JWT-ALG-NONE` by a header named `jwt`
(no source); and `value_shape.FILE_EXTENSIONS` held `lang` (bWAPP's `lang_en.php`).

## Where encountered
Lane BBOX's black-box audit (2026-11-20), after the owner's directive that all detection
logic work against a black-box target (F-284). Found by the per-module sweep and by the
new guard `tests/test_blackbox_detection.py`, which reported
`default_rules.json:71: lab identifier 'channel_id'`.

## What it caused to fail
Recall measured on these labs counted as detection evidence for words a black-box target
need not use. A real app whose object id is `invoice_id`, or whose SpEL sink is a
parameter called `q`, was never a candidate; the labs' recall rose by construction.

## What the bug was identified to be
Rule predicates holding lab vocabulary, each justified in its CC entry only by "the lab
uses this name" and verified only by that lab's recall going up (CC-AUD-0016, 0017,
0024; FR-FUZZ-15, 16, 17).

## Root cause analysis
Five whys:
1. Why did the rules name `channel_id`, `sortBy`, `label`? A lane added each rule to close
   one lab case and grounded the predicate in that case's parameter name.
2. Why was that accepted? The acceptance test was the lab's own recall, and each CC entry
   argued "no other ground truth uses X, so no other target's scoring changes" -- which
   checks lab impact, not real-world grounding.
3. Why was real-world grounding not asked for? No rule required a rule's words to come
   from a public source or a second independent target; the labgen apps (one generator)
   were treated as independent targets.
4. Why did review not catch it? Reviews checked correctness and safety, not where the
   evidence came from (F-284's own cause).
5. Why was there no mechanical check? Nothing compared detection code with the answer
   keys: lab vocabulary could enter detection code silently.

**Root cause:** no rule and no guard separated lab knowledge (answer keys, fixtures) from
detection logic, so a predicate fitted to one lab passed every check.

## Corrective action
CC-AUD-0660 (lane BBOX): `R-ACCESS-CONTROL` matches by the object-identifier shape
(OWASP API1:2023, WSTG-ATHZ-04); `R-SPEL-INJECTION` nominates by location only;
`thumbnail`, `label`, `jwt` and `lang` removed. Measured on the labgen live boots:
booking-clone 3/3 -> 2/3 (BKNG-0002, an honest miss); the other lab names still match by
shape. `tests/test_audit_rule_words_generic.py` pins the generic behaviour on non-lab names.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for detection fitted to one lab, and
`docs/claude_juicelab_failures.md`:
- **BUG-0124 / PA-0124**: Juice Shop's open redirect (`to`) was missed by a name-only rule;
  PA-0124 made a classifier map every output in one table -- same class (a name list built
  from the labs at hand).
- **F-011, F-013, F-014, F-049, F-284** (agent failure record): Juice Shop route names as
  CLI flags, login discovery keyed to the word "login", Angular Material icon rules, tools
  built from lab source, and the DVGA-derived GraphQL words. F-014's "general pattern" is
  recorded as open.
- **BUG-0148** (login discovery by word list) has no bug file in this tree; F-013 tracks it.
Result: a recurrence of the class "detection fitted to the labs at hand" (BUG-0124 /
PA-0124; F-013, F-014, F-049, F-284).

## Prior-preventive-action failure analysis
PA-0124 targeted one form of the class: a value-shape classifier's outputs must each map
to categories in one table, and a sweep over a classifier goes by output, not by the
lane's own categories. It was **too narrow**: it governs how a classifier is mapped, not
where a rule's words come from; a name list like `channel_id|account_id` satisfies it.
It was **not enforced against the class**: its guards test the shape table, not the
vocabulary. F-014 recorded the general pattern as open and no PA was ever written for it;
F-284's correction ("every lane given the black-box rule") was an instruction in dispatch
prompts, not a rule in this repository or a check.

## Preventive action
**PA-0660** (supersedes PA-0124's scope for the vocabulary question, strengthening it from
classifier mapping to every detection literal): the black-box rule, enforced by
`tests/test_blackbox_detection.py`, which builds the lab-identifier set from every answer
key and manifest, subtracts SecLists' common web vocabulary and a cited allow-list, and
fails on any remaining token in rules data or a detection module's string literals
(proven on a synthetic offender). PA-0002 sweep: done by lane BBOX across `audit/`,
`oracle/`, `session/`, `core/runmode.py` and `tools/` (five sub-agent sweeps); the items
fixed here are BUG-0660 and BUG-0661; the items not fixed are listed in the lane report and
in CC-AUD-0660 / CC-FUZZ-0660.
