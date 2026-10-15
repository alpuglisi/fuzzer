# BUG-0155 — An attribute's quote was read from the nearest `=`, so a quoted query link got the unquoted break-out

- Date: 2026-10-15
- Status: fixed (CC-FUZZ-0091)
- ERROR_LOG: the 2026-10-15 entry "an attribute's quote was read from the nearest `=`".
  Rule: PA-0161.
- Severity: medium. A false negative on a raw reflection in any quoted attribute whose
  value holds an `=` before the reflection: every query-string link, form action and
  `src`.

## Description
`context._raw_attr_quote(html, marker)` decided the quoting of the attribute that holds
a reflected marker. It found the first raw occurrence of the marker that sat after a
`<` with no `>` between them, then looked back for the nearest `=` and read the
character after it. In `<a href="/find?term=MARK">` the nearest `=` is the query's, the
character after it is the marker, and the value was typed **unquoted**. M5 then sent
`x TOKEN=1`, which stays inside the double-quoted value, and never sent `" TOKEN=1 x="`,
which breaks out.

## Where encountered
Building BUG-0154's per-attribute contexts: each attribute needed its own quote, and the
helper could give only one per page. Reproduced offline: `_raw_attr_quote('<a
href="/s?q=zqxm1&p=2">x</a>', 'zqxm1') == ''`, and `ReflectedXssStrategy` sent
`['zqxm…', 'x zqxb…=1']` and returned None for a raw reflection there.

## What it caused to fail
M5 on a raw reflection in a quoted attribute value with an `=` before the marker
(`href`, `action`, `src`, `data-*` holding a query or a `key=value` text). It also gave
every attribute on a page the quote of the first tag-like occurrence. That could be
another attribute, a comment such as `<!-- <a title='MARK'> -->`, or a script with
`a<b` before the marker.

## What the bug was identified to be
A markup position decided by scanning back from an occurrence for the nearest delimiter,
instead of by lexing the element's start tag by the HTML tokenizer's rules. The parser
(BeautifulSoup over `html.parser`) does not keep quoting, but it does keep each tag's
source position (`sourceline`, `sourcepos`), which the helper never used.

## Root cause analysis
Five Whys:
1. *Why the unquoted break-out?* The helper returned `""` for a double-quoted value.
2. *Why?* It read the character after the nearest `=` to the left of the marker, and
   that `=` was inside the value.
3. *Why a backward scan?* The parser drops quoting. BUG-0083 needed the quote and took the
   shortest path through the raw text, with no lexer.
4. *Why did no test catch it?* The attribute fixtures put the marker at the start of
   the value (`value="MARK"`, `data-q=MARK`) or HTML-escaped mid-URL (a negative). No
   true positive had a raw marker after an `=` in a quoted value.
5. *Why was that shape not required?* PA-0103 requires a hand-written lexer to be tested
   on every grammar ambiguity it resolves. This was not seen as a lexer, so the rule was
   never applied to it.

**Root cause:** a hand-rolled, delimiter-scanning reading of markup grammar (attribute
quoting), not lexed by the grammar's rules and not tested on the grammar's own
ambiguities (an `=` or `>` inside a value, a tag-like comment, `<` in a script).

## Corrective action
CC-FUZZ-0091:
- `context._start_tag_attrs(html, pos)` lexes a start tag's attributes by the HTML
  tokenizer's attribute states: name, optional `=`, then a double-quoted,
  single-quoted or unquoted value. It returns each attribute's quote.
- `context._attr_quote` locates the attribute's own start tag through the parser's
  `sourceline` / `sourcepos`. It returns the quote of the same-named attribute holding
  the marker (the last duplicate, as the parser keeps it). `_raw_attr_quote` remains
  only as the fallback for a tag with no source position, and says so.
- Tests (`tests/test_oracle_xss_multicontext.py`):
  - a raw query-link reflection confirms with the `"` break-out over a loopback server,
    and an encoded one does not;
  - a mutation check: the old reading misses;
  - per-attribute quotes beside a tag-like comment and a script with `a<b`;
  - the lexer on CRLF, non-ASCII text, `>` inside a value, spaces round `=` and a
    duplicate attribute;
  - an AST guard: no `rfind` / `rindex` in `fuzzlab/oracle/` but the listed fallback,
    proven on a synthetic offender.

## Recurrence review
Checked `docs/bugs/` (BUG-0083, BUG-0093, BUG-0102, BUG-0122, BUG-0131, BUG-0133,
BUG-0456) and `docs/PREVENTIVE_ACTIONS.md` (PA-0022, PA-0084, PA-0103, PA-0122,
PA-0131, PA-0456).
- **BUG-0102 / PA-0103: the same root cause, another grammar.** A hand-written JS lexer
  resolved an ambiguity (regex or division) by a one-character look-back. PA-0103 asks
  that a hand-written lexer be tested on every ambiguity it resolves, and that an
  undecidable case be UNSURE.
- **BUG-0131 / PA-0131: related.** A gate judged a text through another grammar's
  container; PA-0131(1) asks that an input be judged in its own grammar.
- **BUG-0122 / PA-0122: related.** A substring rule decided a URL-structured fact.
- BUG-0083 introduced the helper.

## Prior-preventive-action failure analysis
- **PA-0103 (BUG-0102): too narrow in what it names.** It applies to "a hand-written
  lexer". `_raw_attr_quote` was a backward scan, not a lexer, so the rule was never read
  as applying, and its ambiguities (an `=` or `>` inside a value) were never listed or
  tested.
- **PA-0131(1): another case.** It covers judging an input in its own grammar at a
  safety gate, not reading a position in a response.

## Preventive action
**PA-0161** (strengthens PA-0103 and PA-0131(1)):
1. **A confirmer reads a structural fact about markup (quoting, the context of a
   position) by lexing from the element's own start, located through the parser's
   source position.** It never scans back from an occurrence for the nearest
   delimiter. Enforced by an AST guard: no `rfind` / `rindex` in `fuzzlab/oracle/` but
   the listed fallback, proven on a synthetic offender.
2. **Such a reader is tested on its grammar's ambiguities:** the delimiter inside a
   value, a tag-like comment, `<` in a script, line endings and duplicates. A mutation
   check (the old reading) must fail a true positive.

**PA-0002 sweep:**
| Site | Disposition |
|---|---|
| `context._raw_attr_quote` | fixed: fallback only, documented |
| `oracle/strategies._META_REFRESH` (a regex over raw markup for a meta refresh) | not a backward scan, but a raw-markup regex that needs `http-equiv` before `url=` in the tag and no `>` between them. Stated limits: a `content` written before `http-equiv`, or a `>` inside a quoted value, is a false negative, never a false positive. Left as is in this change and flagged |
| `tools/spa.py` `rfind("<Route", …)`, `rfind("push(", …)` | JS-source discovery heuristics, not a confirmer; owned by another lane: flagged, not changed |
| `session/manager.py` `rfind("]")`, `rfind("/")` | URL authority and path splitting, not markup: cleared |
