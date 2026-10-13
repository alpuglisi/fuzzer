# BUG-0083 — The reflected-XSS oracle confirmed non-exploitable reflections

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0057; FR-FUZZ-39 new)
- Severity: high. The oracle is the sole writer of findings (`finding` labels, which the
  ML trains on), so a false confirmation is a false finding and a false positive label.

## Description
`ReflectedXssStrategy` typed the context of a marker, sent a context break-out, and
confirmed when a signature substring appeared "unescaped" anywhere in the response.
This produced confirmed findings for:
- `<a href="/search?q=<html-escaped>&page=2">`: `javascript:TOK` mid-URL, never at the
  scheme position;
- `<script>var q = <json_encode(value)>;</script>`: `';TOK;//` sits inside a
  double-quoted string;
- by the same logic: single-quoted attributes, where `"><TOK>` stays inside the value,
  and RCDATA (`<textarea>`, `<title>`), where `<TOK>` is text.

The strategy also preferred `candidate.sink_context` (the auditor's coarse label) over
the observed context, so a declared `html` on an attribute reflection picked the wrong
break-out.

## Where encountered
The error-review phase (`scratchpad/review7/r7_xss_fp.py`). Reviewer A found that a
naïve fix would also break two lab sink shapes: unquoted attributes and
`javascript:` URLs.

## What it caused to fail
FR-FUZZ-5 (the oracle's verdicts are ground truth for the store) and the ML labels
trained on them.

## What the bug was identified to be
Confirmation by substring presence, not by the break-out's structural effect.

## Root cause analysis
1. *Why confirm?* `is_unescaped` checked substring presence.
2. *Why is presence insufficient?* Where the substring lands decides whether it
   executes: inside a string, comment, RCDATA, mid-URL, or an attribute value.
3. *Why not caught?* Tests had one true-positive fixture (raw HTML) and one escaped
   negative, and no context-specific false-positive fixtures.
4. *Why one break-out per context?* The JS break-out assumed a single-quoted string,
   and the attribute break-out assumed double quotes.
5. *Why the declared context?* A shortcut for the browser path that was never
   re-examined once the pipeline stopped passing it.

**Root cause:** a confirmation criterion weaker than the vulnerability it claims to
prove, and tested on too few contexts.

## Corrective action
In CC-FUZZ-0057 (`oracle/context.py`, `ReflectedXssStrategy`):
- **`locate_reflection`** types the first reflection (script, then attribute, then
  text) and records:
  - the JS lexer state at the marker;
  - whether the attribute executes `javascript:` (`a`/`area` `href`, `form` `action`,
    `button`/`input` `formaction`, `iframe`/`frame`/`embed` `src`, `object` `data`);
  - whether the marker starts the value;
  - the raw-text quote;
  - an inert parent.
- **`xss_breakouts`** offers at most 3 tries, most specific first; each is judged
  structurally:
  - script → close the lexer's state (`;T;//`, `';T;//`, `";T;//`, `` `;T;// ``) →
    T in **code state**;
  - attribute → js-url (lex the decoded `javascript:` remainder), then scheme position
    (`javascript:T`), then **attribute injection** (`q T=1 x=q`, or `x T=1` unquoted) →
    an injected attribute named T;
  - text → `<T>`, or `</inert><T>` inside RCDATA → an element T with no inert ancestor.
- **The JS lexer fails closed.** An unterminated string, regex or block comment →
  `UNSURE` → no verdict. Regex versus division is decided by the previous token.
- **The observed context always decides.** No strategy reads `candidate.sink_context`
  (an AST guard, proven on a synthetic offender). `_candidate_of` documents the
  omission (item 11).
- **Dead substring helpers removed:** `is_unescaped`, `breakout_for`.
- **Tests** (`tests/test_oracle_xss_structural.py`):
  - **the 4 lab sink templates**, vulnerable and secure: body, quoted and unquoted
    attributes (an entity-escaped unquoted value is still vulnerable), `javascript:`
    URL (entity-escaped is still vulnerable);
  - two secure twins;
  - 8 false-positive fixtures (both repros, single-quoted, textarea, title, template,
    JS comment, `img src`);
  - 7 true positives (JS `'` `"` `` ` `` and code, single-quoted raw, scheme position,
    textarea close);
  - lexer fail-closed cases;
  - at most 4 requests per candidate;
  - the existing oracle tests and the auto goldens are unchanged (the lab's
    reflected-XSS cases are html-body shapes).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **PA-0025** (a status conclusion verified against the real thing, fail closed):
  related. That covered tool-output classification.
- **BUG-0040 / BUG-0045** (strategy vuln_class spelling): same strategy file, different
  defect.
- No prior bug in the XSS confirmation criterion.

**Result:** a new root cause. The fail-closed lexer applies PA-0025.

## Preventive action
**PA-0084:**
1. An oracle confirms by the **structural** effect a break-out would have (an element
   exists outside inert content; an attribute was injected; a token is in code state;
   a scheme is in scheme position), never by a substring appearing somewhere.
2. Each confirmation strategy has a true-positive **and** an escaped-reflection
   false-positive fixture per context it handles, derived from the lab's own sink
   templates where they exist.

**Sweep (PA-0002):** strategies confirming on a substring of the response:
- **Open redirect:** `Location.startswith(canary)`, already positional.
- **SSTI:** an arithmetic result. The product of two random tokens must appear; a
  reflection of the expression cannot produce it, so it is structural by construction.
- **Header injection:** checks the parsed response headers.
- **CSV formula:** checks a downloaded cell's leading character.
- **Stored / DOM XSS:** executed in the real browser (M6), the strongest evidence.

No other substring-presence confirmer was found.
