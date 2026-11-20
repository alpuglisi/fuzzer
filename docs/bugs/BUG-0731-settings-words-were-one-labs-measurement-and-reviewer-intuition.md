# BUG-0731 — The settings words were one lab's measurement and reviewers' intuition, uncited

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
`fuzzlab/tools/formnav.py::SETTINGS_WORDS` / `SETTINGS_PAIRS` -- the vocabulary that
decides whether a form "configures something" -- were chosen without a cited source.
Fourteen words came from forms phase 1 (CC-CRAWL-0013) and were checked live on bWAPP
alone; thirteen words and the pair `per page` were added in forms phase 2
(CC-CRAWL-0014, "reviewer B-R4") and measured offline over bWAPP's 159 picker options,
where they refused nothing new: no target evidence at all. The same list gates five
decisions: selector-form navigation (`refusal`, `option_refusal`), the importer's
POST-selector rule (`store_adapter.form_skip_reason`, FR-FUZZ-43), captured-body import
(`store_adapter.body_refusal`, FR-AUD-22) and the SPA form and label gates
(`spa.form_refusal`, `spa.label_refusal`).

## Where encountered
Lane HEUR's audit of heuristics fitted to one lab (item HEUR-B), following the open item
in `docs/claude_juicelab_failures.md` (BUG-0660's entry: "bWAPP-measured settings words"
listed as remaining).

## What it caused to fail
- Over-refusal of injection surface: `sort` and `per_page` are read-only list modifiers
  in every public API reviewed (JSON:API 1.1, GitHub REST, WordPress REST), and ORDER BY
  is a classic injection point (OWASP WSTG-INPV-05); a POST `sort` picker or a captured
  JSON body with a `sort` key was never fuzzed. `view` is a navigation parameter
  (Joomla `view=article`); as an SPA label it refused every "View ..." menu item, so
  pages behind them were never reached.
- Under-refusal of real settings: `locale` (Spring `LocaleChangeInterceptor`, Rails
  I18n), `timezone` (Django) and `time_zone` (Rails `time_zone_select`) -- the names the
  major frameworks actually use -- were absent, so such a picker was submitted and
  fuzzed. A settings picker whose name says nothing (`<select name=hl>` of locale tags)
  was invisible.
- The bWAPP measurement was the only evidence, which is lab-fitting by PA-0660(3).

## What the bug was identified to be
A detection word list (safety-direction) whose entries were justified only by one lab's
picker and by review intuition, with no per-entry source, and whose guard
(`tests/test_blackbox_detection.py`) could not see it: every word is common web
vocabulary (all appear in SecLists' `burp-parameter-names.txt`), which the guard
subtracts.

## Root cause analysis
Five whys:
1. Why did the list hold `view`, `sort`, `mode` but not `locale`? Its words were picked
   by reviewers thinking of bWAPP's `security_level` picker and of generic "settings"
   vocabulary, then accepted because bWAPP's 159 options were unchanged.
2. Why was "bWAPP unchanged" accepted as evidence? The phase-2 review's acceptance test
   was "refuses more, never less" on the lab at hand; no rule asked where each word came
   from.
3. Why did PA-0660, written for exactly this class, not catch it? Its guard detects
   lab-specific tokens by subtracting common vocabulary; a lab-fitted *selection of
   common words* passes. Its point 2 (cite every relied-on behaviour) has no mechanical
   check for word lists.
4. Why was no per-entry citation check written? PA-0660's sweep went module by module
   for lab identifiers; the settings words were listed as an open item (failure record)
   rather than fixed, and no guard asserted "every entry of a gating word list carries a
   source".
5. Why does that matter more here? The list is a shared primitive by use (five
   consumers, two components) with no registered owner check, so a word added for one
   consumer changes all five silently.

**Root cause:** detection word lists made of common words are outside PA-0660's guard,
and nothing required each entry to cite an independent source, so a list fitted to one
lab and to review intuition passed every check.

## Corrective action
CC-CRAWL-0680 / CC-FUZZ-0713 (FR-CRAWL-680, FR-FUZZ-713): every remaining word carries
its public source in a comment next to it; `sort`, `per page`, `view`, `display`,
`layout`, `skin`, `region`, `mode` removed (no independent source names them a stored
setting; sources name `sort` / `per_page` read-only and `view` navigation); `locale`,
`timezone` and the pair `time zone` added (Spring, Rails, Django docs); new
`formnav.option_set_setting` reads the target's own option values against public code
lists (IANA tz areas, the platform's ISO 639/3166 locale table) so a picker is refused
by what it picks, not only by its name. Tests on shapes from Django, Rails, Spring,
Shopify, GitHub/GitLab and Joomla (`tests/test_formnav_settings_evidence.py`), plus a
citation guard proven on a synthetic offender.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0660 / PA-0660**: audit rules named parameters only one lab supplied; PA-0660 is
  the black-box rule. Same class (detection vocabulary fitted to a lab).
- **BUG-0661**: strategies sent one labgen cell's own names. Same class.
- **BUG-0124 / PA-0124**: a name-only classifier fitted to Juice Shop. Same class,
  earlier.
- `docs/claude_juicelab_failures.md` (BUG-0660's entry) recorded "bWAPP-measured settings
  words" as remaining -- the class was known and left open.
Result: a recurrence of BUG-0660's root cause (detection words fitted to the labs at
hand), in a form PA-0660 did not enforce.

## Prior-preventive-action failure analysis
PA-0660 (from BUG-0660, BUG-0661) states the right rule -- point 1 (no name taken from a
lab) and point 2 (any relied-on behaviour cited to two independent targets or a public
corpus) -- but enforces only point 1, and only for tokens that are not common web
vocabulary: `tests/test_blackbox_detection.py` subtracts SecLists'
`burp-parameter-names.txt` and `common.txt` before looking for lab identifiers. A list of
common words selected *because of* one lab (`level`, `security`, `mode`) is invisible to
it. So PA-0660 was **not enforced** for this form of the class (point 2 has no guard),
and its guard is at the **wrong layer** for it (token identity, not the evidence for
each entry). BUG-0660's lane recorded the settings words as remaining in the failure
record instead of fixing or guarding them (**not followed**, PA-0002's sweep stopped at
the guard's reach).

## Preventive action
PA-0730 (written by the lane). Proposed content: strengthen PA-0660(2) from a stated
rule to an enforced one for word lists -- every gating word list in a detection module
(a frozenset/tuple of words or token pairs that decides refuse/allow/nominate) carries a
source comment per entry group naming a public specification, vendor documentation or
two independent targets, and a whole-package guard fails on an uncited entry (the
per-list form is `tests/test_formnav_settings_evidence.py::test_every_settings_word_sits_under_a_cited_comment`,
proven on a synthetic offender); a word list shared by more than one consumer is
recorded in `docs/SHARED_PRIMITIVES.md` with its consumers, and a change to it sweeps
them all.
