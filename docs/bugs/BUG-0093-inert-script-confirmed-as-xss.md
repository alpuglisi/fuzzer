# BUG-0093 — A reflection in a script that never runs was confirmed as XSS

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0058)
- Severity: high. False CONFIRMED findings. The oracle is the project's ground truth,
  and its confirmations train the ML.

## Description
`ReflectedXssStrategy` returned CONFIRMED for a reflection inside each of these:
- `<script type="application/json">`
- `<script type="application/ld+json">`
- a `<script>` inside `<template>`
- the inline body of `<script src=…>`

None of these execute. `oracle/context.py`'s `locate_reflection` typed any marker
inside any `<script>` as JavaScript, and `js_executes` accepted a token in code state
in any `<script>`.

## Where encountered
A third-party review of head `5eb4be9` (finding #4). Reproduced with
`scratchpad/ext/f4_inert_script.py`.

## What it caused to fail
FR-FUZZ-39 (confirmation by structural effect) and PA-0084(1).

## What the bug was identified to be
The structural model assumed "inside `<script>`" means "JavaScript". The HTML standard
runs a script's inline body only for a JavaScript MIME type (or `module`), with no
`src`, not `nomodule` on a classic script, and not inside an inert subtree.

## Root cause analysis
1. *Why confirmed?* The JS break-out landed in code state of the block's text.
2. *Why was that text treated as code?* `locate_reflection` and `js_executes` never
   asked whether the script element executes.
3. *Why not?* BUG-0083's fix modelled the lexical state *inside* a container, not the
   container's own executability.
4. *Why not caught?* PA-0084(2)'s false-positive fixtures cover escaped reflections per
   context, not a matching structure inside an inert container.

**Root cause:** executability of the container was missing from the structural model.

## Corrective action
- **CC-FUZZ-0058.** `oracle/context.script_executes(tag)` follows the standard's
  "prepare the script element" type rules exactly:
  - the type string is `type` when present (empty → JavaScript; otherwise ASCII
    whitespace stripped), else `"text/" + language` when `language` is non-empty, else
    JavaScript;
  - it is matched case-insensitively and **exactly** against the JavaScript MIME type
    essence list (`x-ecmascript` included), so a type with parameters is a data block;
  - `module` runs;
  - anything else (JSON, `importmap`, `text/template`) never runs;
  - `nomodule` on a classic script, any `src` (even empty), and an inert ancestor
    (`template`, `noscript`, …) mean the inline body never runs.
- **`locate_reflection`** types a marker in an executing script as `script`. A marker in
  a non-executing script falls through to text inside a raw-text element (`html`,
  `inert_parent="script"`). Its only try is `</script><TOK>` with element evidence, and
  element evidence still excludes inert ancestors, so a real break-out of a JSON block
  is real XSS while one inside `<template>` is not.
- **`js_executes`** accepts only executing scripts, and `javascript:` URLs only on an
  element with no inert ancestor.
- **`type_reflection`** (the legacy classifier) uses the same predicate.
- **Stated limit:** structural lexical state is still not proof of execution, and
  client-rendered `text/template` blocks are a false negative here. Browser-backed
  confirmation (M6) is the stronger path (FR-FUZZ-39).
- **Tests** (`tests/test_oracle_xss_structural.py`):
  - 13 inert script shapes: the finding's 4, empty `src`, `importmap`,
    `text/template`, `text/plain`, a type with parameters, a whitespace-only type,
    `language="vbscript"`, `nomodule` and `noscript`;
  - 10 executing shapes: no type, `text/javascript`, padded upper-case, `module`, an
    empty type, `x-ecmascript`, `language` javascript / `JavaScript1.2` / empty, and a
    module with `nomodule`;
  - a raw `</script>` break-out of a JSON block → confirmed;
  - a `<\/script>`-escaped JSON block → not confirmed;
  - a break-out under `<template>` → not confirmed;
  - a `javascript:` URL under `<template>` → not confirmed;
  - the one-predicate check.

  17 of the new cases fail on `5eb4be9`. The lab's four sink templates are unchanged
  (existing tests).

Also corrected: this test file's docstring still cited FR-FUZZ-15 (now FR-FUZZ-39), a
remnant missed by `5eb4be9`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0083 / PA-0084:** this oracle's structural confirmation. A **recurrence**: my
  own fix left this gap.
- **BUG-0089 / PA-0090:** another oracle false positive with a different root cause (a
  proof derivable from the probe). Related, not the same.

## Prior-preventive-action failure analysis
**PA-0084 was too narrow.**
- Rule 1 required structural evidence, but my structure assumed "inside `<script>` ⇒
  JavaScript".
- Rule 2's false-positive fixtures varied the **reflection's escaping** per context,
  never the **container**. A matching structure inside an inert container is exactly
  the case the rules did not name.

## Preventive action
- **PA-0094** (strengthens PA-0084):
  1. **Structural evidence includes the container's executability under the platform's
     own rules** (script type, `src`, `nomodule`, inert ancestors), implemented as one
     predicate.
  2. **Each structural check has a fixture where the structure matches but the
     container is inert.**

**Sweep (PA-0002):** other code that reads `<script>` content:
- **`core/hybrid.needs_browser`:** a heuristic for client-rendered pages. Data blocks
  counting as scripts only biases it toward using the browser. Not a confirmation; left
  as is.
- **`tools/fetcher._extract_scripts`:** collects script text for parameter discovery.
  Over-collecting from data blocks finds more candidate names, never a finding; left as
  is.
- **The M6 `BrowserExecutor` seam:** when an executor is injected, execution is
  judged in a real browser, which applies these rules itself. Not affected.
