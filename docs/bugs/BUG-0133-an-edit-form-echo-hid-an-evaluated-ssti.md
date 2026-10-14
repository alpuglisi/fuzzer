# BUG-0133 — An edit form's echo of the input hid an evaluated SSTI

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0079)
- Severity: medium. A false negative on a real, confirmed-by-hand vulnerability (Juice
  Shop's `/profile` username SSTI), on the shape every profile/settings page has.

## Description
Juice Shop's `/profile` renders the evaluated username in `<p …>647192</p>` and echoes
the raw stored value in its edit field, `<input id="username" name="username"
value="#{728*889}">`. `SstiStrategy` refused: its rule
`if not _contains_number(text, a * b) or expr in text: continue` read the literal
`728*889` in the input's `value` as a reflection.

## Where encountered
The coordinator's live check of FR-FUZZ-49 (post/redirect/get observation, CC-FUZZ-0078)
on the operator's loopback Juice Shop lab, with a diagnostic wrapper tracing every SSTI
probe on `/profile`: `POST /profile username=#{728*889}` → `302 /profile`; the follow-up
returned 200 with `647192`; `SstiStrategy.confirm` returned None.

## What it caused to fail
M4 (SSTI evaluation marker) and its kin on any page that shows the stored input back in
an edit form and renders the evaluated value elsewhere — the usual profile, settings and
"edit item" page. The PRG work (FR-FUZZ-49) made the evaluated page observable and so
exposed it; the defect is in M4 itself (the non-PRG edit-form variant fails the same way).

## What the bug was identified to be
The "evaluated, not just reflected" rule judged the probe's literal as a **substring
anywhere in the raw response**, not by where the page shows it. A literal inside a form
control's value is the app displaying the stored input for editing; it says nothing about
whether the number elsewhere came from evaluation.

**Why the rule exists (the rationale kept).** `git log -S` shows the check in the
first version of the oracle in history (12ce859, 2026-09-25):
`if product in text and expr not in text:  # evaluated, not just reflected`, with the
docstring "M4: a template expression is evaluated server-side (product appears, not the
literal)". BUG-0117 (c368b26) kept it ("its literal ``a*b`` must not [appear]") and added
the second-sample causality check, and the same rule was copied to
`SqliEvaluationMarkerStrategy` ("a bound or escaped sink stores the literal text"),
`SpelInjectionStrategy` (`payload in text`) and `GoTemplateSstiStrategy` ("rules out
reflection"). Its purpose: a page that **reflects** the probe is a sink echoing input, so a
number beside the echo is no evidence the sink evaluated anything (a coincidence, or a
number the page derives from the echoed text). For SpEL it is essential: the literal
`T(java.lang.Math).abs(-123)` contains its own canary `123`, so a plain reflection would
otherwise "confirm".

## Root cause analysis
Five Whys:
1. *Why no confirmation?* `expr in text` was true: the literal was in the input's `value`.
2. *Why did that disqualify?* The rule tests the literal as a raw substring anywhere,
   standing in for "the sink reflects the probe".
3. *Why a substring stand-in?* The rule predates the structural judgements (BUG-0083's
   parsed contexts); it was written against reflection fixtures, where every echo is in
   text content, and was copied unchanged into three later strategies.
4. *Why did no test catch it?* Every M4 true-positive fixture renders only the evaluated
   value; no fixture shows the input back in an edit field, the way real apps do. The
   BUG-0117 work added false-positive fixtures (number-rich pages, payload-independent
   noise), never a realistic true positive around the disqualifier.
5. *Why was the true-positive side not required?* The preventive actions for confirmers
   (PA-0084, PA-0090, PA-0094, PA-0117, PA-0127) are written against false positives:
   they require every **positive** signal to be structural and noise-proof, but say
   nothing about a **disqualifier**, so a negative rule could stay a raw substring.

**Root cause:** a confirmer's disqualifying rule judged its evidence by raw substring
instead of by the structure the rule is about (a sink's reflection), and the fixture rules
covered only the false-positive side, so no realistic true positive ever crossed it.

## Corrective action
CC-FUZZ-0079:
- `oracle/context.split_form_control_values(html)`: the parsed page (BeautifulSoup, the
  oracle's existing parser) split into form-control values (an `<input>`'s `value`, a
  `<textarea>`'s content, a selected `<option>`'s text and `value`) and everything else
  (text, comments, script, every other attribute).
- `oracle/strategies._echo` / `_echoed_outside_form_controls` / `_evaluated`: the literal
  disqualifies when it appears anywhere but a form control's value — in the parsed page
  (so an entity-encoded echo counts) or as a raw occurrence no control accounts for. When
  the literal is only in form controls, the number must appear outside every form control
  (hence outside every literal occurrence: SpEL's literal holds its canary). With no
  literal in the page the rule is exactly the old one. The second-sample causality check
  (BUG-0117) and the P5 attribution (FR-FUZZ-49) are unchanged.
- Applied to `SstiStrategy`, `SpelInjectionStrategy`, `SqliEvaluationMarkerStrategy` (both
  samples) and `GoTemplateSstiStrategy` (its literal check and its own-number check).
- Tests (`tests/test_evaluation_marker_echo.py`): each of the four strategies over ten page
  shapes — confirms with the literal in an input value, a textarea, a selected option;
  refuses the literal echoed in text, an attribute, a comment, an unselected option (with
  the number beside it), the number only inside the control, and an echo with no
  evaluation; the PRG edit form (Juice Shop's captured shape, 302) confirms; a stale page
  still fails the second sample; the split by role; the old answer where no literal is
  shown; the PA-0133 guard and its synthetic offenders.

## Recurrence review
Checked `docs/bugs/` (BUG-0083, BUG-0090's PA-0090, BUG-0093, BUG-0102, BUG-0117,
BUG-0124, BUG-0127, BUG-0129) and `docs/PREVENTIVE_ACTIONS.md` (PA-0084, PA-0090,
PA-0094, PA-0103, PA-0117, PA-0124, PA-0127, PA-0129).
- **BUG-0083 / PA-0084 — the same root cause, other direction.** BUG-0083 confirmed
  reflected XSS when a break-out *substring appeared anywhere*; PA-0084(1) made
  confirmation structural ("never a substring appearing somewhere"). BUG-0133 is the
  same substring stand-in for a structural fact, in a rule that *refuses*.
- **BUG-0117 / PA-0117 — related.** It made the evaluation markers' positive signal
  causal (second sample) and noise-proof; it kept the literal rule as written.
- **BUG-0093 / PA-0094, BUG-0127 / PA-0127 — related.** Both made a confirmation state and
  check the structure of where its signal sits (container executability, response type).
  PA-0127(1) "a confirmer states every precondition of its signal and checks each on the
  observed response" is the closest rule.
- **BUG-0124 / PA-0124(2) — related.** A confirmer must state the filters it cannot pass;
  that was about probe forms, not page shapes.
- No earlier bug was a false negative caused by a disqualifier.

## Prior-preventive-action failure analysis
- **PA-0084(1) (BUG-0083) did not prevent this: wrong scope.** It was written for M5 and
  for the confirming signal; the evaluation markers' *refusing* rule was never read as a
  "structural effect" to judge. PA-0084(2)'s fixture rule (a true positive and an escaped
  false positive per context) was M5-only, so M4 had no realistic true-positive page.
- **PA-0117 (BUG-0117): one-directional.** Its discovery guard runs every strategy against
  payload-independent noise, which only proves no false positive; nothing ran the
  strategies against true positives in realistic pages, and its sweep reviewed the literal
  rule only as a false-positive defence.
- **PA-0127(1): not applied to disqualifiers.** "Every precondition of its signal" was read
  as the signal's preconditions (HTML rendering), not the conditions under which the
  strategy refuses.

## Preventive action
**PA-0133** (strengthens PA-0084(1) and PA-0127(1); extends PA-0117 to the
true-positive side):
1. A confirmer's **disqualifying** rule is judged by the same structural standard as its
   positive signal: by the parsed role of what it sees (where a literal is echoed), never
   by a raw substring anywhere. Enforced by an AST guard
   (`tests/test_evaluation_marker_echo.py::test_no_strategy_judges_its_literal_by_a_raw_substring`)
   proven on BUG-0133's own line.
2. Every confirmer has a **true-positive fixture in a realistic page**: the input echoed
   where real apps echo it (an edit form's control, around the evaluated value), at least
   one a captured third-party shape (Juice Shop's `/profile`), next to its
   false-positive fixtures for each place a reflection disqualifies.
3. A disqualifier change is mutation-checked in both directions (dropping it lets a
   reflection confirm; widening it refuses the edit form).

## PA-0002 sweep
| Site | Same literal rule? | Disposition |
|---|---|---|
| `SstiStrategy` (M4), both samples | yes (`expr in text`) | fixed |
| `SpelInjectionStrategy`, both samples | yes (`payload in text`; the literal holds the canary) | fixed |
| `SqliEvaluationMarkerStrategy`, both samples | yes (`f"{a}*{b}" in text`) | fixed |
| `GoTemplateSstiStrategy` | yes (`expr in text`), and blind to an HTML-escaped echo (`&quot;`): a text echo of `{{ len "AAA" }}` with the number beside it confirmed | fixed (judged on the parsed page; escaped text echoes now refuse) |
| `PriceIntegrityBypassStrategy`, `CsvFormulaInjectionStrategy` | no: the echo *is* the signal (anchored) | cleared |
| `XxeInBandMarker`, `SsrfInBandMarker` | no: an HMAC proof, never the probe's literal (PA-0090) | cleared |
| Access-control, upload, mass-assignment, deserialization markers | no: presence of the strategy's own token required, nothing disqualified by it | cleared |
| `SqliErrorStrategy`, path-traversal markers | no literal rule; controls (PA-0117) | cleared |
| `ReflectedXssStrategy` (M5) | no: structural since BUG-0083 | cleared |
| `labgen/oracle_wrapper.py` (SSTImap), greybox M10 | external tool / coverage signal | cleared |

## Residuals
- An app that echoes the input in an edit field and shows, outside it, a number it
  computes from the input by other means confirms only if that number tracks the second,
  fresh sample (BUG-0117) — computing it from the input is evaluation in effect; accepted.
- A `<select>` that lists earlier values as unselected options disqualifies (it is outside
  the edit control): a stated false negative.
- A non-HTML page (JSON) is parsed as one text: an echo in it disqualifies as before.
