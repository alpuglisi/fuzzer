# BUG-0110 — The login detector did not submit a form the way a browser does

- Date: 2026-10-13
- Status: fixed (CC-CORE-0037, CC-SESS-0014, CC-AUD-0028)
- Severity: medium. Authenticated testing was impossible against any target whose login
  form needs its submit button's `name=value` or a `<select>`'s default. The run fails
  loudly ("login … was rejected"), so it is not a silent unauthenticated run.

## Description
`find_login_form` built the POST from each control's `value` attribute:
- `<button>` elements were never collected, and named `<input type=submit>` controls were
  skipped, so the submitter's `name=value` was never sent;
- a `<select>` sent `""` (it has no `value` attribute), not its selected/first option;
- a `<textarea>` sent `""`, not its text;
- unchecked checkboxes and radios were sent, and disabled controls were sent;
- a `type=file` input was sent as an empty text field;
- duplicate names collapsed to the last one (a `dict`).

## Where encountered
Live, against a self-hosted, loopback-only bWAPP (`127.0.0.1:8090`, the operator's own
sandbox, `--authorized`). `fuzzlab session print --host 127.0.0.1 --identity user
--base-url http://127.0.0.1:8090/bWAPP/` failed with "login for user@127.0.0.1 was
rejected … (status 200)" with the right credentials. bWAPP's `login.php` runs only when
`isset($_POST["form"])`. `form` is the name of its `<button type="submit" value="submit">`,
and it reads `security_level` from a `<select>` with options 0/1/2.

## What it caused to fail
- FR-SESS-3 (login detection): no session, so no authenticated crawl or fuzz.
- Auditor field values (`PageContext._field`, same bug class): selects and textareas
  reported `""`, so value-based indicator rules (serialised tokens, NoSQL operators, the
  privileged-field value) could not see what the control held.

## What the bug was identified to be
A hand-rolled, partial form serialisation that read the `value` attribute for every
control, instead of implementing the HTML entry-list algorithm (§4.10.21.4).

## Root cause analysis
1. *Why was the login rejected?* The POST lacked `form=submit`, and `security_level` was
   `""`.
2. *Why were they missing?* The detector skips buttons and reads `value` for a select.
3. *Why did it read attributes?* The serialisation was written to fit our own lab's login
   form (hidden CSRF token, text, password, an unnamed submit button). It was never
   written against the browser algorithm it emulates.
4. *Why didn't a test catch it?* The only fixtures were our own lab's forms. No test had
   a named button, a select, a checkbox or a disabled control.
5. *Why only our own forms?* Nothing required emulated browser behaviour to be tested
   against the rules it emulates, or against a third-party target's shape.

**Root cause:** browser behaviour was emulated by approximation, checked only against
the lab we wrote. Divergence from a real browser stays invisible until a third-party
target exercises it.

## Corrective action
- **`fuzzlab/core/forms.py` (new, CC-CORE-0037):**
  - `form_entries(form)` returns an ordered `FormEntries` list of `(name, value)` pairs,
    following §4.10.21.4;
  - every rule implemented is listed in `RULES` with its spec step:
    - form ownership (`form=`);
    - the disabled control, disabled-fieldset and optgroup rules; readonly is sent;
    - only the submitter is sent. The submitter is the first enabled submit control in
      tree order, where a `<button>` with a missing or invalid type is a submit button.
      An image submitter sends `name.x` / `name.y`, or `x` / `y` when unnamed;
    - checkboxes and radios only when checked, defaulting to `on`, while an empty
      `value` stays `""`;
    - every selected option, or a drop-down's first enabled option; a listbox
      (`size>1`) sends nothing. Selectedness is decided over all options, so a
      disabled, pre-selected "Choose…" placeholder sends nothing;
    - an option's value is its attribute if present, else its collapsed text;
    - a textarea sends its text, minus one leading newline;
    - file inputs are skipped;
    - duplicates are kept in order;
  - `submitter_overrides(form)` reports `formaction` / `formmethod` / `formenctype`;
  - `default_value(el)` is used for reporting.
- **`session/detect.py` (CC-SESS-0014):**
  - `LoginForm.fields` is the entry list;
  - `fill()` replaces the username and password entries in place;
  - field detection uses the controls the form owns, skipping disabled ones.
- **`session/manager.py`:** a form whose submitter carries an override is refused before
  any credential request (it would go where the button says, which is not emulated).
- **`tools/fetcher.py` (CC-AUD-0028):** `_field`'s `value` is `default_value(el)`.
- **Tests:** `tests/test_form_entries.py`:
  - one fixture per `RULES` id, and a guard that fails on a rule with no fixture;
  - the captured bWAPP form;
  - `fill` order and duplicates;
  - a disabled password field;
  - overrides refused with no request made;
  - auditor default values, and a value rule that now sees a textarea;
  - a bWAPP-shaped end-to-end `SessionManager` login.

  The eight non-fixture tests fail on `eb9a949`. The mutation check killed 26/26 (one
  fixture was strengthened after a survivor).
- **Review:** both reviewers, in the implementation round, found a disabled `selected`
  placeholder sent as the first enabled option. It is fixed, with its own rule and
  fixture.
- **Verified live:** `session print` against the loopback bWAPP now returns
  `PHPSESSID=…; security_level=0`.

## Known limitations (recorded, not changed here)
- **The credential request is always a urlencoded POST.** A login form with
  `method=GET` or `enctype=multipart/form-data` is not served the way a browser serves
  it (FR-SESS-14 states this).
- **The first form with a password input is taken.** On a page with a signup form before
  the login form, the credentials go to the signup action (a reviewer's note; a
  follow-up).
- **Fuzzing points send one parameter with no sibling fields.** Pages gated on a submit
  button's field (bWAPP's `isset($_POST["form"])`) will not process a probe. That is a
  fuzzer design limitation (single-parameter points), not this defect.

## Recurrence review
- **BUG-0059 and BUG-0060** (PA-0061, PA-0062): emulated browser *request headers* were
  incomplete (a UA only, then a UA with `requests`' own `Accept`). A real third-party
  target's WAF exposed it each time, and the lab never did. **Same root cause:**
  approximate browser emulation checked only against our own lab.
- **BUG-0008 and BUG-0097**: login detection and redirects were tested only with the
  lab's own login shape.

## Prior-preventive-action failure analysis
- **PA-0062 was too narrow (wrong layer).** It said to check every header a real client
  would set, "not just the one header the original symptom pointed at". It was scoped to
  request headers, so its sweep never looked at the other browser behaviour the tool
  emulates: form serialisation, redirects and cookies.
- **PA-0061 was too narrow.** It was a `User-Agent` rule only.
- **Neither was enforced mechanically.** Neither asked for one fixture per emulated rule,
  or for a third-party target's shape, so the lab-only fixture gap persisted.

## Preventive action
- **PA-0111** (strengthens PA-0061 and PA-0062):
  - code that emulates a browser or protocol behaviour implements the named algorithm
    rule by rule, with each rule listed and spec-cited in a rule table;
  - a guard test fails if any listed rule has no fixture;
  - at least one fixture is a captured third-party target's shape, not only our own
    lab's.

**Sweep (PA-0002), extended to all emulated browser behaviour:**
- **Form serialisation:** the only other instance was `tools/fetcher.py::_field`, which
  was fixed. There are no other form serialisers in `fuzzlab/`.
- **Redirects:**
  - the session manager walks hops by hand (BUG-0097) and was reviewed;
  - the auditor's static fetch uses `requests`' redirect handling, which matches a
    browser for GET.
- **Cookies:**
  - the login fetcher and the auditor use the `requests` jar;
  - `detect.parse_set_cookie` reads one cookie, but only as the fallback when a fetcher
    exposes no jar (documented "best-effort");
  - the crawler's browser mode is a real browser.

  No further instance needed remediation.
