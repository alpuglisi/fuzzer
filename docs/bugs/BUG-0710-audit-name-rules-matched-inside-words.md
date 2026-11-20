# BUG-0710 — Audit name rules matched a word inside another word

## Description
Every `name_regex` audit rule was evaluated with `re.search`, unanchored, so a rule
word matched anywhere inside a parameter name: `ip` in `description`, `zip`, `shipping`
(command injection), `load` in `payload` (file inclusion), `next` in `nextid`. This is
the audit-rule part of the long-open BUG-0121 (named in BUG-0122 and BUG-0124, never
written up): "BUG-0121 owns the name rules: ... the audit rules' name patterns".

## Where encountered
`fuzzlab/audit/rules.py::matches` (`re.search(when["name_regex"], n, re.I)`), on every
rule of `fuzzlab/audit/rules_data/default_rules.json` with a `name_regex`. Named again as
gap (3) of lane RULESEL's brief (2026-11-20).

## What it caused to fail
False nominations, so requests spent on strategies that cannot apply, and (on the other
side) rule words written short so the substring would catch compounds. Measured on
SecLists' `burp-parameter-names.txt` (6453 names, `tests/data/common_web_vocabulary/`):
the six substring rules matched 97/399/207/150/27/299 names (open redirect / file
inclusion / command injection / SSRF / price / CSV); token-anchored, 71/293/62/80/21/269.
On the answer keys, the substring rules nominated `description` (an XSS case) for
command injection and `payload`/`yaml_payload` (deserialization cases) for file
inclusion. No answer-key positive of a rule's own category was lost by the fix
(`test_no_same_category_answer_key_positive_lost_its_name_rule`).

## What the bug was identified to be
A matching primitive that did not anchor its words: the rule data could not say "this
word as a whole token" and the engine never anchored for it.

## Root cause analysis
1. Why did `ip` match `description`? `matches` used `re.search` with the rule's
   alternation.
2. Why `re.search`? The first rules (T2.3) were written as short substrings to catch
   compounds (`returnurl`, `filename`) without a tokeniser.
3. Why was it never changed after BUG-0121 was named? BUG-0121 had no owner document and
   no PA; BUG-0122's PA-0122 covered URL and session rules, and it listed the audit
   rules as "owned by BUG-0121 (open)".
4. Why did PA-0022 (anchor on `\b`) not cover it? It names mechanical heuristics (hooks,
   lint, gates); `\b` would not split camelCase or `_`, and no guard checked the engine.
5. **Root cause:** the rule engine owned no token-anchored matching primitive, and no
   guard forbade unanchored matching in it, so every rule inherited substring semantics.

## Corrective action
CC-AUD-0700 (lane RULESEL): `name_token_regex`, matched with `re.fullmatch` against each
whole token of the name (`core.redaction.name_tokens`: `_ - . [ ]`, camelCase,
letter/digit), and `name_regex` now a fullmatch of the whole name. The six substring
rules moved to `name_token_regex` with their compounds spelled out (`\w*ur[il]`,
`dest\w*`, `\w*(file|path|folder|dir|page)`, ...); the access-control regexes rewritten
as whole-name patterns. The owner is SP-137 (`audit/rules.py::_token_match`).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for substring/anchoring rules:
BUG-0020 → PA-0022 (keyword heuristics anchor on `\b`), BUG-0122 → PA-0122 (auth/URL
rules compare canonical keys and whole tokens), BUG-0124 (named BUG-0121 as the same
class from the other side), BUG-0660 → PA-0660 (rule words must be cited, not lab
names). Same root cause as BUG-0122 for a different layer.

## Prior-preventive-action failure analysis
- **PA-0022** (BUG-0020) was **too narrow and not enforced**: it named hooks, lint rules
  and build gates, its remedy (`\b`) does not split camelCase or `_`, and no test read
  the audit engine.
- **PA-0122** (BUG-0122) was **scoped to another layer**: session and auth decisions. Its
  own sweep table left the audit rules to BUG-0121, which never got a document, a PA or
  an owner, so the class stayed open for months.

## Preventive action
PA-0710 (strengthens PA-0022 and PA-0122 for the audit layer): the rule engine matches
every rule regex with `re.fullmatch` on a whole name or a whole token, never
`re.search`/`re.match`; a compound a rule means is written in the rule; a change to a
name rule shows, on the answer keys, that no positive of the rule's own category is lost.
Enforced by an AST guard proven on a synthetic offender and by the recall test. The
`_USERNAME_HINT` regex in `session/detect.py` (also listed under BUG-0121) is outside this
lane's files and stays open under BUG-0121.
