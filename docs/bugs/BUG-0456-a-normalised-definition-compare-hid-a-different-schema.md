# BUG-0456 — the definition check compared whitespace-normalised text, and a definition SQLite reads differently compared equal

- Date: 2026-10-15
- Status: fixed
- Severity: medium (a crafted project file could drop a column or a constraint from an
  allowed table and still pass the untrusted-file check; no new SQL could run, but the
  project pages 500ed and integrity constraints were silently gone)

## Description
BUG-0453's fix compared every `sqlite_master` definition with the reference schema after
`_norm_sql`, which collapsed whitespace with Python's `str.split()`. That normalisation is
not SQLite's grammar:
- Python treats U+00A0 (and other non-ASCII spaces) as whitespace; SQLite treats every
  byte ≥ 0x80 as an identifier character. `TEXT NOT NULL` normalised equal to
  `TEXT NOT NULL`, while SQLite read the type name `TEXT NOT` — the `NOT NULL` was gone;
  ` argv` replaced the `argv` column.
- Normalising erased newlines, and a newline is where a `--` comment ends: moving the
  newline after `-- 'link' | 'xhr' | ...` in `page` commented out `template_cluster_id`.

## Where encountered
Code review round 4 of the project-files change (security reviewer, on bffa9c1),
confirmed with repros (`launch` with ` argv`: `inspect` and `summary` accepted the file,
then `run_history` raised `no such column: argv` and `/project` was a 500). Never merged.

## What it caused to fail
A file from someone else could pass the gate FR-UI-457 / FR-CORE-450 describe as exact
while its schema differed: columns renamed or removed, `NOT NULL` dropped. The reviewer
found no way to add executable SQL (only tokens already in the reference are available,
and it holds no generated column, `CHECK` or expensive `DEFAULT`).

## What the bug was identified to be
An equality check over untrusted text applied a normalisation from a different grammar
(Python's whitespace) before comparing, so the check's notion of "same" was not the
consumer's (SQLite's).

## Root cause analysis
Five Whys:
1. Why accepted? `_norm_sql(file) == _norm_sql(reference)`.
2. Why equal? The normaliser removed differences that are significant to SQLite.
3. Why normalise at all? It was inherited from BUG-0451's index comparison, written to
   tolerate whitespace rewording assumed (never checked) to come from `ALTER`.
4. Why was the assumption never checked? Round 3 checked migration *history* against
   normalised text, and nobody compared raw stored text with the reference's.
5. Why did no test catch it? The attack fixtures added new tokens (generated columns,
   `CHECK`); none rearranged existing tokens in ways only SQLite's tokenizer distinguishes.

**Root cause:** a safety comparison judged untrusted input after a lossy transformation
written in another grammar than the input's consumer, so "equal" did not mean "same to
SQLite".

## Corrective action
`core.project._exact_sql` returns the stored text unchanged: definitions are compared
**byte for byte**. Checked safe: a fresh store, an `ANALYZE`d store and stores downgraded to
v21/v22 (including `DROP COLUMN` rewrites) match exactly; every past version of
`migrations.py` (15 commits) builds byte-identical text at every version; the reference is
pure ASCII. Test:
`tests/test_core_project.py::test_a_definition_that_only_normalises_equal_is_refused`
(`non-ascii-space`, `comment-shift`; each asserts the rewrite is equal once normalised,
that SQLite no longer has the column — non-vacuity — and that `inspect` and `summary`
refuse it). CC-CORE-0450 (code review round 4).

## Recurrence review
- **BUG-0131 / PA-0131** ("a gate judges its whole input in the input's own grammar"):
  **same root cause** — a lossy step from another grammar before the rule.
- **BUG-0451 / PA-0451** and **BUG-0453 / PA-0453** (same gate): the third defect in the
  untrusted-schema check. BUG-0451 enumerated spellings; BUG-0453 exempted a kind; this one
  normalised away meaning. **A recurrence of the gate, with a new root cause each time**,
  all three PA-0131's family.

## Prior-preventive-action failure analysis
- **PA-0131 was not applied**: it was written for destructive-word gates over labels and
  URLs and was not read as covering a schema comparison; nothing linked it to PA-0451.
- **PA-0451/PA-0453 were too weak**: "an exact definition" did not say what *exact* means;
  the implementation kept a normaliser, and PA-0453's attack-fixture rule covered exempted
  kinds, not the comparison's own equivalence.

## Preventive action
**PA-0456** (strengthens PA-0131 and PA-0453): an equality or allowlist check over
untrusted input compares the raw form, byte for byte, unless a normalisation is the
consumer's own (its tokenizer, its parser) — never a convenience transform from another
grammar; and its tests include inputs that differ only in what the consumer treats as
significant and the normaliser does not (non-ASCII spaces, comment boundaries, quoting),
each with a non-vacuity step proving the consumer reads them differently. PA-0002 sweep:
the other comparisons over untrusted structure on this branch are `_version_table_trusted`
(now exact, same helper), the `sqlite_stat*` definitions (exact) and `_parse_recent` /
`_parse_metadata` (typed parsers, no text normalisation); `fuzzlab/` has no other
`" ".join(….split())` comparison guarding a safety decision (`grep` recorded in
CC-CORE-0450).
