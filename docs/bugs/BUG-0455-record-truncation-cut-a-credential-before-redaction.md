# BUG-0455 — the record redactor cut a value before stripping its userinfo, and kept part of a password

- Date: 2026-10-15
- Status: fixed
- Severity: high (a credential could be written into a project file's `launch.argv` /
  `project.targets`, against NFR-UI-project-provenance-redacted)

## Description
`core.redaction.redact_for_record` capped a value at `MAX_RECORD_CHARS` (4096) **before**
running the userinfo patterns. When a URL's `user:password@` straddled the cut — a long
password (`http://admin:` + 4 KB + `@lab.local/`), or a short one after 4 KB of other text —
the `@` that ends the userinfo fell past the cut, neither `_URL_USERINFO` nor
`_BARE_USERINFO` matched, and the password (or its prefix) was stored.

## Where encountered
Code review round 3 of the project-files change, found independently by both reviewers on
8569187. Never merged.

## What it caused to fail
A target or argument carrying URL credentials longer than about 4 KB from the value's start
was recorded with the credential in the project file — a file the operator may share.

## What the bug was identified to be
The size cap (added in round 2 to bound work) ran before the redaction it was meant to
protect, so redaction saw a value whose structure the cut had broken.

## Root cause analysis
Five Whys:
1. Why kept? The userinfo pattern needs the terminating `@`, which the cut removed.
2. Why cut first? Round 2 capped values to bound the redactor's work, at the function's
   entry.
3. Why at the entry? The bound was placed where it was simplest, without asking which
   transformations need the whole value.
4. Why not caught? The round-2 test checked the output *length* for an oversized value, not
   that a secret straddling the cut was removed.
5. Why that test? PA-0101(2) asks for oversized inputs *carrying secrets* — the test used
   an oversized value with no secret.

**Root cause:** a lossy transformation (truncation) was applied before redaction, and the
oversize test did not place a secret across the boundary it introduced.

## Corrective action
`redact_for_record` strips userinfo (both patterns are linear, round 2) from the **whole**
value, then cuts, then redacts per piece. Test:
`tests/test_core_project.py::test_a_credential_straddling_the_record_cut_is_still_removed`
(a long password, a straddling URL, a straddling scheme-less userinfo). CC-CORE-0450 (code
review round 3).

## Recurrence review
- **BUG-0100 / PA-0101** (a redactor failed open at its parser's limits): **same root-cause
  family** — redaction losing at a size limit.
- **BUG-0099 / PA-0100** (one storage boundary) — related, not the same: the boundary was
  right; its internal order was wrong.

## Prior-preventive-action failure analysis
**PA-0101(2) was not followed in full**: it requires oversized inputs *carrying secrets*,
and the round-2 test carried none. It was also **too implicit**: it does not say that a
size bound itself is a transformation whose boundary needs a secret placed across it.

## Preventive action
**PA-0455** (strengthens PA-0101): a redactor never applies a lossy transformation
(truncation, decoding, splitting) before the redaction that depends on the whole value;
size is bounded with linear-time redaction first and the cut last. Every bound a redactor
introduces is tested with a secret straddling it. PA-0002 sweep: `core.redaction` has no
other cut-before-redact (the 1 KB JSON sniff in the body redactor only classifies);
`web.mlview._truncate` shortens displayed payload variants and is not a storage path.
