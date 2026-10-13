# BUG-0102 — Regex literals after `return` / `)` were lexed as code, giving false confirmed XSS

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0059)
- Severity: high. These were false CONFIRMED findings, which feed the ML training labels.

## Description
`js_states` decided regex versus division from the single previous non-space
character. After `return` that character is `n`, and after `if (…)` it is `)`, so
`/TOK/` in `function f(){ return /TOK/; }` was lexed as code. `ReflectedXssStrategy`
confirmed a reflection that stayed inside a regex literal, with every slash escaped.

## Where encountered
A third-party audit (finding #6), reproduced with `scratchpad/ext2/f06_regex.py`: it
returned `Verdict(confirmed=True, breakout='js')`.

## What it caused to fail
FR-FUZZ-39 and PA-0084(1) (structural evidence, and no verdict when unsure).

## What the bug was identified to be
A lexer that claimed to resolve the regex/division ambiguity, using a one-character
look-behind that cannot.

## Root cause analysis
1. *Why code?* `n` and `)` are not in `_REGEX_PREV`.
2. *Why one character?* It was a simplification in BUG-0083's lexer.
3. *Why not caught?* Fixtures varied reflection escaping (PA-0084) and container
   executability (PA-0094), never the grammar context inside the code.

**Root cause:** an untested grammar ambiguity in a hand-written lexer.

## Corrective action
Token-aware context in `oracle/context.py`:
- **Regex** after a punctuator or operator, after a `REGEX_KEYWORDS` keyword (`return`,
  `typeof`, `case`, `default`, …), or after the `)` that closes an `if` / `while` /
  `for` / `with` head. A paren stack records the token before each `(`.
- **Division** after an identifier (`this` / `null` / `true` … included), a number, a
  string or regex, `]`, any other `)`, or a postfix `++` / `--`.
- **`}` followed by `/`** is ambiguous (a block or an object literal), so the whole
  source is UNSURE (fail closed).

**Stated limit:** structural state is not proof. Browser-sentinel confirmation (M6) or a
real ECMAScript parser is the stronger path (FR-FUZZ-39).

**Tests** (`tests/test_oracle_xss_structural.py`):
- 10 regex contexts;
- 8 division contexts, `a\n/b/g` and `this / 2` included;
- `}` is UNSURE;
- the audit's fixture → no confirmation;
- all existing XSS fixtures unchanged.

## Recurrence review
- **BUG-0083 / PA-0084 and BUG-0093 / PA-0094:** the same oracle. A recurrence.

## Prior-preventive-action failure analysis
**Too narrow.** PA-0084 and PA-0094 required fixtures for escaping and for container
executability. Neither required testing the lexer on the grammar ambiguities it
resolves.

## Preventive action
- **PA-0103:** a hand-written lexer is tested on every grammar ambiguity it resolves.
  Where the grammar alone cannot decide, the result is UNSURE, never "code".

**Sweep:**
- `_js_url_body` (lexed by `js_states` as well, so fixed with it);
- `hybrid.needs_browser` (no lexing);
- no other hand-written lexers in `fuzzlab/oracle`.
