# BUG-0032 — bookkeeping Stop hook's keyword regex misses plain plural nouns ("failures", "regressions")

- Date: 2026-09-22
- Status: fixed
- Severity: low (a narrower detection miss in an already-heuristic keyword
  check; the hook has other trigger paths, e.g. `docs/bugs/`/`docs/spikes/`
  path changes, that are unaffected)

## Description
`.claude/hooks/check-error-log-bookkeeping.sh`'s incident-keyword regex
(`PA-0020`/`BUG-0019`) matches singular/verb forms of "fail" and "regress"
but not their plain plural noun forms ("failures", "regressions"), due to a
word-boundary interaction with the optional-suffix alternation groups.

## Where encountered
Same script review as BUG-0029/BUG-0030/BUG-0031, formalized in
`docs/change-requests/CR-LAB-0002-*.md` (§3.4) and independently reviewed by
two agents before this fix landed.

## What it caused to fail
A diff adding ordinary incident-shaped prose like "three known failures" or
"a list of regressions" — with no `ERROR_LOG.md` touch — would not trigger
the hook's keyword heuristic (though it could still be caught by the
separate `docs/bugs/`/`docs/spikes/` path heuristic, if applicable). Verified
directly against the *unfixed* regex:
```sh
$ echo "three known failures" | grep -qE '\bfail(s|ed|ing|ure)?\b' ; echo $?
1
$ echo "a list of regressions" | grep -qE '\bregress(es|ed|ion)?\b' ; echo $?
1
```
Both ordinary ways this project's own `docs/bugs/README.md` describes
incidents ("a failing test, a wrong result, a crash, a regression") — the
plural form of the same two nouns is exactly as likely in prose and was
invisible to the hook.

## What the bug was identified to be
```sh
keyword_regex='\bfail(s|ed|ing|ure)?\b|\bhang(s|ing)?\b|\bworkaround(s|ed)?\b|\bkilled\b|\btimed out\b|\btimeout(s|ed)?\b|\bcrash(es|ed|ing)?\b|\bbroken\b|\bregress(es|ed|ion)?\b'
```
`fail(s|ed|ing|ure)?` and `regress(es|ed|ion)?` each end their nominalized
form (`ure`, `ion`) with no branch admitting a trailing plural `s` before the
`\b` word boundary — so "failures" (`fail` + `ures`) and "regressions"
(`regress` + `ions`) each have a trailing `s` left over after the longest
matching alternative, which breaks the `\b` boundary. Every *other*
alternative in the same regex (`hang(s|...)`, `workaround(s|...)`,
`timeout(s|...)`, `crash(es|...)`) already handles its own plural — only
these two nominalized forms were missed.

## Root cause analysis
Five Whys:
1. Why do "failures"/"regressions" not match? The `ure`/`ion` alternatives
   have no plural branch, so a trailing `s` after either breaks the `\b`
   boundary the regex requires.
2. Why did the regex admit plurals everywhere else but not here? The other
   keywords in the list (`hang`, `workaround`, `timeout`, `crash`) were
   authored with an explicit `s` alternative alongside their `-ed`/`-ing`
   forms; `fail` and `regress` additionally have a *nominalized* form
   (`failure`, `regression`) that isn't just "verb + s", and that nominalized
   form's own plural was the one case not mirrored when the list was
   assembled.
3. Why wasn't this caught when the hook was built (`BUG-0019`)? The keyword
   list was authored by enumerating incident-shaped words directly, not by
   testing each alternative against a corpus of the project's own incident
   prose (e.g. `docs/bugs/README.md`'s own wording) — had it been, the
   mismatch between "regression" (singular, matches) and "regressions"
   (plural, doesn't) in that exact sentence would have been visible
   immediately.
4. Why is this worth fixing given the hook is already a heuristic (never
   claims completeness)? Because the gap isn't a deliberate scope boundary
   (like "we don't run an NLP classifier") — it's an accidental asymmetry
   within the *same* two keywords' own alternation, catching the singular but
   not the ordinary plural of the same noun, which is not the kind of gap the
   heuristic's design intends to leave open.
5. Why generalize the fix as a preventive action rather than treat it as a
   one-off regex edit? Because the same authoring-without-corpus-testing
   process could reintroduce an equivalent asymmetry the next time a keyword
   is added or edited, and nothing currently checks the regex's own coverage
   against real incident prose.

**Root cause:** the keyword regex's nominalized-form alternatives (`ure`,
`ion`) were authored without a plural branch, an asymmetry with the rest of
the list's alternatives (which all admit `s`), because the list was built by
enumerating keywords directly rather than testing each alternative against
this project's own incident-prose conventions.

## Corrective action
Extended the two affected alternatives to admit a trailing plural, matching
how every other alternative in the same regex already handles `s`:
```sh
keyword_regex='\bfail(s|ed|ing|ures?)?\b|\bhang(s|ing)?\b|\bworkaround(s|ed)?\b|\bkilled\b|\btimed out\b|\btimeout(s|ed)?\b|\bcrash(es|ed|ing)?\b|\bbroken\b|\bregress(es|ed|ions?)?\b'
```
Verified by construction:
```sh
$ echo "three known failures and a list of regressions" | \
  grep -oE '\bfail(s|ed|ing|ures?)?\b|\bregress(es|ed|ions?)?\b'
failures
regressions
```
and confirmed the change only *adds* alternation branches (`ures?`, `ions?`
in place of `ure`, `ion`) — it cannot narrow or remove a previously-matching
case, since every string the old branch matched (the singular form) is still
matched by the new one (the `s?` is optional). Reviewed and approved via
`docs/change-requests/CR-LAB-0002-*.md`.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. Same originating
mechanism as **BUG-0031** (the hook from `BUG-0019`/`PA-0020`), but a
different, independent defect within it (a regex authoring gap, not a
data-source/fallback gap) — not a recurrence of BUG-0031's root cause, and no
other prior bug audited this hook's regex coverage. No stronger match found.

## Preventive action
**PA-0034** (see `docs/PREVENTIVE_ACTIONS.md`): when a keyword-matching
heuristic includes a **nominalized noun form** derived from a verb (e.g.
`fail` → `failure`, `regress` → `regression` — as opposed to a plain
`-s`/`-ed`/`-ing` inflection), that nominalized alternative must itself admit
its own plural (`ures?`/`ions?`, not `ure`/`ion`) — nominalization changes
the word's part of speech, and a noun pluralizes independently of whatever
inflections its parent verb takes. Before adding or editing such a regex,
test every alternative against this project's own incident-prose
conventions (e.g. `docs/bugs/README.md`'s and other `docs/bugs/*.md` files'
actual wording) as a concrete corpus, not just by enumerating keywords from
memory — the exact asymmetry here (singular "regression" matches, plural
"regressions" doesn't, in a sentence taken directly from this project's own
`docs/bugs/README.md`) would have been caught immediately by that check.
