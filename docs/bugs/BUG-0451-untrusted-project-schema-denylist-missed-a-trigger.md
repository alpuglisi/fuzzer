# BUG-0451 — the untrusted-project check was a denylist, and a trigger got past it twice

- Date: 2026-10-15
- Status: fixed
- Severity: high (a project file from someone else ran its own SQL when opened)

## Description
`core.project.inspect` refuses a project file holding schema objects fuzzlab never
creates, because a project file can come from someone else. It did so with a **denylist**
over `sqlite_master`: first `name -> type` folded into one dict (a trigger named
`schema_version` hid behind the table of that name), then — after that was fixed —
`type IN ('trigger','view')`, which is case-sensitive while SQLite's schema loader is
not: a row typed `TRIGGER` (written with `PRAGMA writable_schema`) passed, and the trigger
fired during the UI's own open (`ensure_metadata` updates `project`).

## Where encountered
Code review of the project-files change (CC-UI-0450 / CC-CORE-0450), reviewer B: round 1
on 9f1536e (same-name trigger) and round 2 on 1e81639 (`TRIGGER` / `Trigger` rows). Never
merged.

## What it caused to fail
A crafted `.fuzzlab` file opened in the UI could delete or forge findings and runs on open
(reviewer B: "fired on open: 1"), the exact untrusted-input case FR-UI-457 / FR-CORE-450
say is refused.

## What the bug was identified to be
The gate enumerated what to refuse (trigger, view, foreign virtual table) by one textual
field, so every spelling of a refused kind that differed from the enumeration — a shared
name, a different case, a comment before `VIRTUAL` — was admitted.

## Root cause analysis
Five Whys:
1. Why did the trigger run? `inspect` returned `ok`, so the file was opened.
2. Why `ok`? Its row's type was `TRIGGER`, not in the denylist `('trigger','view')`.
3. Why did the round-1 fix not stop it? It fixed one spelling (the name namespace) of the
   same denylist, not the denylist.
4. Why a denylist? It is the obvious way to say "refuse what we never create"; but the set
   of spellings SQLite accepts for a schema object is open-ended (case, comments, schema
   writes), while the set of objects fuzzlab creates is closed and known.
5. Why was nothing failing? The tests planted only the spellings the denylist named.

**Root cause:** a safety gate over untrusted structured input was a default-accept
denylist keyed on one field, when an exact allowlist of what this code itself creates was
available.

## Corrective action
`core.project` builds the **reference schema** by running fuzzlab's migrations in memory up
to the file's version (`reference_schema`, cached), and `_foreign_objects` refuses any
`sqlite_master` row whose exact `(type, name, tbl_name)` — type compared as written — is
not in it, and any index or virtual table whose definition differs (normalised
whitespace); tables are matched by identity (their stored text is reworded by
`ALTER`/`DROP COLUMN`, and `trusted_schema=OFF` keeps a function in a table definition
from running). `ANALYZE`'s `sqlite_stat*` are allowed by name. The same check guards the
listing `summary`. Tests: `tests/test_core_project.py::test_inspect_refuses_what_is_not_a_fuzzlab_store`
(`TRIGGER-row`, `Trigger-row`, `same-name-trigger`, `commented-virtual-table`,
`extra-table`, `changed-index`, …), `::test_a_case_variant_trigger_never_fires_on_open`,
and the non-vacuity `::test_the_allowlist_accepts_every_real_store_shape` (fresh, legacy
v21, `ANALYZE`d). CC-CORE-0450 (code review round 2).

## Recurrence review
- Within this change: round 1's same-name trigger (reviewer B) — same root cause; its fix
  patched one spelling. **Recurrence.**
- `PA-0028` / `PA-0029` (a validator that accepts by default must refuse what it is
  structurally blind to; a gated-off branch needs a positive fixture) — same family: a
  default-accept check.
- `PA-0083(3)` (a gate on an obfuscatable signature matches the normalised form too) and
  `PA-0131` (a gate judges its whole input in the input's own grammar) — related: both are
  about a gate missing an equivalent spelling.
Result: a recurrence of PA-0028's root cause, at a new layer (untrusted file structure).

## Prior-preventive-action failure analysis
- `PA-0028` was **too narrow**: written for semantics validators of payload mutations; its
  remedy ("enumerate the shapes you are blind to and refuse them") is itself a denylist
  and does not say to prefer an allowlist when one exists.
- `PA-0083(3)` was **the wrong layer**: it adds normalised forms of a *signature* to match,
  and normalising `type` would have closed `TRIGGER` but not a comment, a namespace or the
  next spelling — still enumerating what to refuse.
- The round-1 fix here **was not a rule at all**, only an instance fix, so the class was
  unguarded.

## Preventive action
**PA-0451** (strengthens PA-0028 and PA-0083(3)): a safety gate over untrusted structured
input admits only an **allowlist derived from what this code itself creates or accepts**
— exact identity, and an exact definition wherever the object can execute — never a
denylist keyed on one field; and its tests include the platform's own equivalent
spellings (case, comments, namespaces, direct schema writes) plus a non-vacuity fixture of
every legitimate shape. PA-0002 sweep: the only other untrusted-structure gates on this
branch are `summary` (now the same allowlist) and `_parse_recent` / `_parse_metadata`
(already allowlists of keys and shapes, PA-0108).

## Correction — code review round 3 (2026-10-15)
The corrective action above says tables are matched by identity because "`trusted_schema=OFF`
keeps a function in a table definition from running". That is false for SQLite's built-in
functions, and the carve-out let an executable table definition through: **BUG-0453**
(PA-0453) — every definition, tables included, is now compared. This report is otherwise
unchanged (append-only).
