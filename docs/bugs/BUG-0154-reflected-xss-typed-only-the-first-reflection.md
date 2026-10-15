# BUG-0154 — Reflected XSS typed only the first place a value reflected in

- Date: 2026-10-15
- Status: fixed (CC-FUZZ-0091)
- ERROR_LOG: the 2026-10-15 entry "reflected XSS typed only the first place a value
  reflected in". Rule: PA-0160.
- Severity: medium. A false negative on a common server-rendering shape. The edit page
  of any stored field and the search page of any term show the value in two places.

## Description
`ReflectedXssStrategy.confirm` (M5) sent a marker, typed where it landed with
`context.locate_reflection`, and then sent only that context's break-outs
(`xss_breakouts`). `locate_reflection` returned the **first** match in a fixed
priority: an executing script, then an attribute value, then text. A value escaped in
its first place and raw in a later one was never tried in the raw place.

## Where encountered
The JUICE-0008 investigation on the operator's dev lab, with the reproduction
script `invest-juice/scripts/repro_profile.py` in the session scratchpad: a stored value
is shown on its page escaped in an `<input value="…">` and raw in a `<p>`.
`locate_reflection` typed `attribute` (quote `"`). The attribute break-out came back
escaped, and it was the only one tried. The untried text break-out `<TOKEN>` landed raw,
and `element_injected` was true on that response. Reproduced offline on synthetic pages
(an edit form in both orders, a search box beside a heading, a script beside text).

## What it caused to fail
M5, for stored (post/redirect/get, FR-FUZZ-49) and reflected values alike, on any page
that echoes one value in more than one context when the first context is safe:
- an edit form showing the stored value in its control and in a read-only view;
- a search page echoing the term in its box and in a heading;
- a page carrying the value in a properly escaped script string and raw in text.

The browser mechanism (M6) can still find these, but only with a browser attached, which
a plain run does not have.

## What the bug was identified to be
The typing returned one context per page. Every distinct context is a separate
opportunity, but only the first was tried. The confirmation of each try is page-wide
and structural (an element, attribute or code-state token anywhere), so the defect was
only in which break-outs were sent, not in how they were judged.

## Root cause analysis
Five Whys:
1. *Why no confirmation?* Only the attribute context's break-out was sent, and the page
   escaped it.
2. *Why only that one?* `locate_reflection` returns the first reflection it finds, and
   the strategy tries only `xss_breakouts(ref)` for that one reflection.
3. *Why one reflection?* BUG-0083 (CC-FUZZ-0057) designed the typing as "the first
   reflection (script, then attribute, then text)". The priority answered "which
   context is most specific", not "which contexts exist". Its bug report lists the
   choice without stating it as a limit.
4. *Why did no test catch it?* Every M5 fixture, the four lab sink templates and the
   structural true and false positives, reflects the value in exactly one place.
   PA-0084(2) asks for a true positive and an escaped false positive **per context**,
   which a one-place page per context satisfies.
5. *Why was the two-place page not required?* BUG-0133 (PA-0133(2)) required a
   realistic true-positive page, the input echoed where real apps echo it (an edit form),
   for every confirmer. Its enforcement and its fixtures covered the evaluation markers
   only, and its sweep cleared M5 as "structural since BUG-0083". That judged M5's
   signal, not which places M5 types.

**Root cause:** the reflected-XSS typing collapsed a one-to-many fact (where a value is
output) to its first element, and the fixture rules asked for one fixture per context,
never for a page with several contexts, so the collapse was never exercised.

## Corrective action
CC-FUZZ-0091:
- `oracle/context.locate_reflections(html, marker)` returns every distinct context, in
  a fixed order:
  - executing scripts, one entry per distinct lexer state at an occurrence;
  - attribute values, with their executability, position and own quote (BUG-0155);
  - text, with its innermost inert parent;
  - each group in document order; equal contexts appear once. The text of an executing
    script is its script context only, which keeps a script page at its old cost.

  `locate_reflection` is now `locate_reflections(...)[0]` (None when nothing reflects),
  so its contract is unchanged.
- `ReflectedXssStrategy` tries the break-outs of every context, in rounds: each
  context's most specific try comes before any context's second try, and a fragment
  already listed is not sent again. It sends at most `MAX_BREAKOUTS = 6` break-outs
  after the typing probe, and confirms on any one. The evidence records the context that
  confirmed (`context`, `reflection`: its typing) and how many were typed (`contexts`).
  PRG observation and the `prg` / `prg-redirect` attribution are unchanged.
- **The cap and why.** One context offers at most 3 tries (`xss_breakouts`), so a
  single-context page costs what it did (1 + at most 3). A cap of 6 tries any two
  contexts in full. The common multi-context pages (edit form, search box and heading,
  script and text) need 2. The cap bounds a page that types many distinct contexts.
- Tests: `tests/test_oracle_xss_multicontext.py` (loopback servers):
  - the PRG edit page, escaped in its control and raw in a paragraph, in both document
    orders, gives an `xss-stored` finding with `observation: prg`;
  - both places escaped gives no finding (one try per context);
  - a search box and heading; script plus text in both directions;
  - the cap binds and is respected; a single-context page costs 2 requests;
  - the round order and the fragment dedupe;
  - a mutation check (first context only) fails the fixtures;
  - an AST guard, no `locate_reflection` call in `fuzzlab/oracle/`, proven on a
    synthetic offender.

## Recurrence review
Checked `docs/bugs/` (grep for "reflection", "context", "xss": BUG-0006, BUG-0041,
BUG-0046, BUG-0072, BUG-0083, BUG-0093, BUG-0102, BUG-0115, BUG-0117, BUG-0127,
BUG-0129, BUG-0133, BUG-0139, BUG-0311) and `docs/PREVENTIVE_ACTIONS.md` (PA-0048,
PA-0084, PA-0094, PA-0103, PA-0117, PA-0127, PA-0133, PA-0139, PA-0311).
- **BUG-0133 / PA-0133: the same page shape, another confirmer.** An edit form's echo
  of the input hid an evaluated SSTI. Its sweep cleared M5. This is a recurrence of
  "a realistic multi-place page hides a true positive", in a site that sweep cleared.
- **BUG-0311 / PA-0311(1): the same root cause at the label layer.** A ground-truth
  negative was proven from one output path of several.
- **BUG-0046 / PA-0048: the same shape at point building.** A one-to-many lookup
  collapsed to one value per key.
- **BUG-0083 / PA-0084: the origin.** It introduced the one-context typing.
- **BUG-0139 / PA-0139: related.** A confirmer's probe set narrower than the
  vulnerability (one quoting shape).
- BUG-0093, BUG-0102, BUG-0127: the same strategy, different defects (what a context
  is, how JS is lexed, which responses render).

## Prior-preventive-action failure analysis
- **PA-0084(2) (BUG-0083): too narrow.** "A true positive and an escaped false positive
  per context" is satisfied by one-place pages. It never asks for a page combining
  contexts, so the typing's collapse to the first was never exercised.
- **PA-0133(2) (BUG-0133): not enforced for M5.** It already required "every confirmer"
  to have a realistic edit-form true positive, but its guard and fixtures covered the
  evaluation markers only. Its PA-0002 sweep judged M5 by the bug's class (a
  substring disqualifier) and cleared it without asking whether M5 sees every place the
  input is echoed (PA-0067(1): a verdict must name what the site is judged for).
- **PA-0311(1) (BUG-0311): wrong layer.** "A negative is proven on every path the input
  reaches output by" was scoped to ground-truth labels. The same rule was never
  applied to a confirmer's own view of a response.
- **PA-0048 (BUG-0046): wrong layer.** It covers point building, not a response's
  contexts.

**Re-sweep of the sites BUG-0133's sweep cleared (PA-0067(3), PA-0300(3)),** judged by
this class, "judges only the first of several places its input is output":
| Site | Judges every place? | Disposition |
|---|---|---|
| `ReflectedXssStrategy` (M5) | no: first context only | fixed (this bug) |
| `PriceIntegrityBypassStrategy` | yes: an anchored `in` over the whole body | cleared |
| `CsvFormulaInjectionStrategy` | yes: anchored cell match anywhere in the export | cleared |
| `XxeInBandMarker`, `SsrfInBandMarker` | yes: the HMAC proof anywhere in the body | cleared |
| access-control, upload, mass-assignment, deserialization markers | yes: the strategy's own token anywhere | cleared |
| `SqliErrorStrategy` | yes: any signature, in the probe and in every control | cleared |
| path-traversal markers | yes: `re.search` over the whole body | cleared |
| `labgen/oracle_wrapper.py` (SSTImap), greybox M10 | external tool / coverage signal | cleared |
| evaluation markers (M4 and kin) | yes: `_echo` judges every part of the page (BUG-0133) | cleared |

## Preventive action
**PA-0160** (strengthens PA-0084(2) and PA-0133(2), and carries PA-0311(1) from labels
to confirmers):
1. **A confirmer judges every place its input is output.** A typing step returns every
   distinct context (`context.locate_reflections`), never the first. A single-place
   helper exists only as a wrapper for non-confirming callers. Enforced by an AST guard:
   no `locate_reflection` call in `fuzzlab/oracle/`, proven on a synthetic offender.
2. **Its fixtures include a page that outputs the value in two places, escaped in one
   and raw in the other, in both orders,** beside the both-escaped negative. At least one
   is a post/redirect/get page. A mutation check (the first place only) must fail them.
3. **A per-place cost has a stated total cap that keeps the single-place cost**, and tries
   go in rounds so the cap never starves a later place.

**PA-0002 sweep (this class in the codebase):**
| Site | Disposition |
|---|---|
| `ReflectedXssStrategy` | fixed |
| `context.locate_reflection` | now the first of `locate_reflections`; no caller in `fuzzlab/` (tests only) |
| `context.type_reflection` | first context only, by contract (the coarse vocabulary `mutation/xss` shares). No caller in `fuzzlab/`; tests only. Not a confirmer: kept, documented here |
| one script's lexer state | was the first occurrence's; now one entry per distinct state |
| `OpenRedirectStrategy` meta refresh (`_META_REFRESH.search`, the first only) | cleared, left unchanged: under the HTML standard's "will declaratively refresh" flag a document honours only its first meta refresh, so the first is the one a browser follows (from the standard; not measured in a browser here) |
| `_header` (first header of a name) | cleared: `requests` joins repeated headers into one value, and a response has one `Location` |
| `mutation/xss.xss_payloads(sink_context)` | one context per call, chosen by its caller; not a confirmer, and it has no production caller. Not owned by this lane: flagged |
| `DomXssStrategy`, `StoredXssStrategy` (M6), greybox XSS | cleared: execution or canary evidence, no context typing |
