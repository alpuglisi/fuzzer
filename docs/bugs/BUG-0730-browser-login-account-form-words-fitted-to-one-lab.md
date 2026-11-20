# BUG-0730 — The browser login's account-form refusal was fitted to one lab's field names and missed a single-password sign-up

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
`fuzzlab/session/browserlogin.py::login_form_refusal` decides which rendered form the
browser login may fill with the operator's credential. Its account-form words
(`ACCOUNT_WORDS`, `ACCOUNT_PAIRS`) held `repeat`, `retype`, `security question` and
`security answer`, chosen from one lab's registration, forgot-password and
change-password controls (`repeatPassword`, `newPasswordRepeat`, `securityQuestion`,
`securityAnswer`), with no source for any word. The words that were fitted decided
nothing (the password count already refused every such form), while the gate had no
signal for the account form the words cannot see: a sign-up with one password control,
which the target itself marks `autocomplete="new-password"` (WHATWG).

## Where encountered
Lane HEUR's black-box audit (2026-11-20, item HEUR-A), applying PA-0660 to the session
manager's detection vocabulary: `browserlogin.py:81-87` flagged as lab-fitted.

## What it caused to fail
- A single-password sign-up form (web.dev's recommended shape: email, one password with
  `autocomplete="new-password"`, a "Continue" button, a route with no account word) was
  accepted as the login form (measured, CC-SESS-0660 table): the browser login would type
  the operator's credential into it and click once. Only the request-side gate
  (`account_endpoint_reason`) stood between that click and an account created on the
  target, and only when the sign-up endpoint's path names an account token.
- The words' evidence was one lab's recall, against PA-0660(3); FR-SESS-19 stated the
  list as the specification.

## What the bug was identified to be
A refusal gate whose vocabulary was taken from one lab's control names (CC-SESS-0021,
"reviewers A4/B3", no measurement or citation) instead of from signals the target supplies
and public sources define; and so a gate with no rule for the account-form shape that
lab does not have.

## Root cause analysis
Five Whys:
1. Why did the gate accept a single-password sign-up? Its only account signals were the
   password count and words on the route, button, action and control names; that form has
   one password and no such word.
2. Why were words the only non-structural signal? The words were written by reading the
   lab's forms (its fixture is "a loopback fake of Juice Shop's login", whose register
   form is `email`, `password`, `repeat`), so each word answered a control that lab
   renders, and the lab's forms all carry a repeat field.
3. Why was that not caught as fitting? CC-SESS-0021's review judged the list by whether
   it refused the lab's account forms (it did, redundantly) and recorded no source; the
   later black-box guard (PA-0660(5)) subtracts SecLists vocabulary, and `repeat`,
   `security`, `question`, `answer` are all in `burp-parameter-names.txt` /
   `common.txt`, so the guard could not see them.
4. Why was a target-supplied standard signal not used? The form reader already returned
   each control's `autocomplete` attribute (`spa.FORMS_JS`, used by `spa.form_refusal`
   for `one-time-code`), but the login gate was designed from the lab's names, not from
   what the HTML standard says a form declares about itself.
5. Why did no rule require that? PA-0660 requires a cited source for a word a rule
   relies on, but its enforcement checks lab identifiers, not that each word of a
   detection word table carries a citation; a word that is also common vocabulary passes
   by construction.

**Root cause:** detection word tables (here a safety refusal list) were accepted without
a per-word independent source, and the only automated check (the lab-identifier guard)
is blind to a lab-fitted word that is also common web vocabulary; so the gate was built
from one lab's names and never asked what the target itself declares (WHATWG autofill).

## Corrective action
CC-SESS-0660 (FR-SESS-660; this commit):
- `repeat` and `retype` removed from `ACCOUNT_WORDS` (every repeat/confirmation form in
  the sources renders two password controls, refused by the count; a lone password
  control so named is refused by `credential_change_reason`).
- `new_password_reason`: a control with the WHATWG autofill token `new-password` refuses
  the form (HTML Living Standard §4.10.18.7; Chromium's password-form guide; MDN; web.dev).
- Every remaining word and pair cited in the module comment to at least two independent
  public sources (framework docs, OWASP, RFCs, WHATWG, NIST); a test fails on a word
  without a citation line.
- Tests on five framework account forms, two single-password sign-ups, four framework
  login forms; mutation checks recorded in CC-SESS-0660.

## Recurrence review
Checked `docs/bugs/` (BUG-0660, BUG-0661, BUG-0121, BUG-0301, BUG-0124) and
`docs/PREVENTIVE_ACTIONS.md` (PA-0124, PA-0660, PA-0002, PA-0003):
- **BUG-0660** (audit rules named parameters only one lab supplied) and **BUG-0661**
  (strategies sent one lab cell's own names): the same root cause, lab vocabulary in a
  detection decision. This is a recurrence.
- **PA-0660** (the black-box rule) and **PA-0124** (its narrower predecessor) are the
  prior preventive actions.
- BUG-0301 (the destructive rule missed one lab's password-change URL) is the opposite
  direction (a missing word) on a different gate; not the same root cause.

## Prior-preventive-action failure analysis
PA-0660 (from BUG-0660 / BUG-0661) states the right rule in points 1-3 (no lab names; a
relied-on behaviour cited on two independent targets; recall is not evidence), but:
- **Not enforced for this shape.** Its guard (point 5, `tests/test_blackbox_detection.py`)
  builds lab identifiers and subtracts SecLists vocabulary; a lab-fitted word that is
  also a common English / parameter word (`repeat`, `security`, `question`, `answer`)
  is subtracted, so the guard is blind by construction. Point 5 names this limit only
  for template-only names.
- **Wrong layer for a word table.** The guard checks string literals one by one; it
  never asks whether each entry of a word table has a source, which is what points 1-3
  require.
- **Sweep scope.** BUG-0660's sweep audited audit rules and fuzz strategies; refusal
  gates in the session manager (whose words decide where the credential is typed) were
  in the guard's globs but not in the per-module sweep.
PA-0124 was too narrow (one classifier's output table), as PA-0660 already records.

## Preventive action
PA-0730 (written by the lane). Proposed content (strengthens PA-0660(2) and (5)): every
word table in a detection or refusal module carries, per entry, a citation line naming at
least two independent public sources, and a test fails on an entry without one (here
`tests/test_session_browser_login.py::test_every_account_word_names_its_independent_source`;
to generalise to the other tables, e.g. `store_adapter._CHANGE_SUBSTRINGS` /
`_CHANGE_TOKENS`); and where the target declares the property in a standard attribute
(WHATWG autofill tokens, input types, ARIA), the gate reads that first and the word list
is a fallback, never the only signal.
