# BUG-0453 — an allowed table kept a crafted definition, and SQLite's own functions ran on open

- Date: 2026-10-15
- Status: fixed
- Severity: high (a project file from someone else could hang the UI's start screen and
  every project transition; denial of service on open, listing and migration)

## Description
BUG-0451's allowlist (`core.project._foreign_objects`) matched ordinary **tables** by
identity only — `(type, name, tbl_name)` — and compared definitions only for indexes and
virtual tables, on the stated reasoning that "`trusted_schema=OFF` keeps any function in a
table definition from running". That reasoning was false: `trusted_schema=OFF` stops
application-defined functions, not SQLite's built-ins. A file whose `project` table row (in
`sqlite_master`, rewritten with `writable_schema`) gained a generated column, `CHECK` or
`DEFAULT` built from `printf('%.*c', N, 'x')` / `replace` / `length` passed `inspect`, and
the expression ran — unbounded in depth and size — every time a row was read or written.
Separately, `schema_version` was **read** (`typeof(version)`, `MAX(version)`) before any
definition was checked, so a generated `version` column ran before the allowlist; and a
file claiming a version above this build's skipped the allowlist yet still had `run` and
`project` read.

## Where encountered
Code review round 3 of the project-files change (CC-UI-0450 / CC-CORE-0450), security
reviewer, on 8569187 — confirmed by the reviewer with a 266 KB file that held `inspect` for
38 s at 20 nesting levels (cost linear in depth and string size). Never merged.

## What it caused to fail
- `ProjectManager.open` runs `inspect` under the manager lock: every transition and every
  launch blocked until the UI was restarted.
- `summary()` runs on every `GET /projects` (and `/` redirects there when nothing is open):
  a file merely dropped into the projects directory hung the start screen, one threadpool
  worker per reload; the VM-step budget never tripped (one heavy call is one opcode).
- `migrate_with_backup` ran the same expressions in its migrations and post-steps.

## What the bug was identified to be
The gate exempted one object kind (tables) from definition matching on an unverified
claim about a platform safety setting, and read rows of a table before its definition had
been checked.

## Root cause analysis
Five Whys:
1. Why did the expression run? `inspect` accepted the file and then read `project`.
2. Why accepted? Its `project` table matched the allowlist by name; its definition was not
   compared.
3. Why not compared? The allowlist assumed a table definition cannot execute because of
   `trusted_schema=OFF`, and that `ALTER`/`DROP COLUMN` might reword legitimate table text.
4. Why was that assumption never caught? No test planted an executable table definition;
   PA-0451's non-vacuity fixtures covered legitimate shapes only, and its attack fixtures
   covered triggers, views, indexes and virtual tables — the kinds the assumption named as
   executable.
5. Why did the assumption stand? It was a claim about what a platform setting protects,
   accepted from reading rather than shown by an attack, and the "rewording" worry was
   never checked against history (every past migration set builds the identical schema).

**Root cause:** a safety gate trusted a platform setting's protection without an attack
fixture proving it, and so exempted the largest object class from the exact-definition
rule; and it read untrusted rows before validating the structure that computes them.

## Corrective action
- `_foreign_objects` now compares the normalised definition of **every** `sqlite_master`
  row with the reference schema, tables included; `sqlite_stat1`/`sqlite_stat4` must carry
  SQLite's own definitions. Verified safe for legitimate stores: all 15 historical versions
  of `fuzzlab/core/migrations.py` build a schema identical to today's at every version
  (scratch check recorded in CC-CORE-0450's round-3 note); migrations only `CREATE` and
  `ALTER … ADD COLUMN`.
- `_version_table_trusted` checks `schema_version`'s definition from `sqlite_master` alone
  **before** any of its rows is read, in `inspect` and in `summary`.
- A file newer than this build is returned as `newer` right after its version is read;
  nothing else of it is read.
- Defence in depth: `SQLITE_LIMIT_LENGTH` of 4 MiB on the inspecting connection and 1 MiB on
  the summarising one.
- The false docstring and BUG-0451's corrective-action sentence are corrected (BUG-0451 is
  append-only history; this report supersedes that sentence).
- Tests: `tests/test_core_project.py::test_an_allowed_table_with_a_changed_definition_is_refused_before_any_row_is_read`
  (generated column, `CHECK`, `DEFAULT`, generated `version`; each with a non-vacuity step
  showing the expression really costs time on a plain connection, and a time bound on the
  refusal), `::test_a_newer_file_is_refused_without_reading_its_tables`,
  `::test_sqlite_statistics_tables_must_have_sqlites_own_definition`,
  `::test_the_allowlist_accepts_a_v22_store_migrated_to_head_and_one_with_flows`.
  CC-CORE-0450 (code review round 3).

## Recurrence review
- **BUG-0451 / PA-0451** (same change, same gate): an untrusted-file check let executable
  schema through. **Same root-cause family, a recurrence**: BUG-0451 was a denylist; this
  is the allowlist that replaced it, with a carve-out.
- `PA-0028` / `PA-0029` (a default-accept validator; a gated-off branch needs a positive
  fixture) — related: the tables carve-out was a gated-off branch with no positive
  (attack) fixture.

## Prior-preventive-action failure analysis
**PA-0451** said "exact identity, and an exact definition **wherever the object can
execute**". It was followed — but the qualifier left the judgment of *which* objects can
execute to the author, and that judgment was wrong. The PA was **too weak at exactly the
point that failed**: it required a non-vacuity fixture of legitimate shapes, but no attack
fixture per exempted kind, so a wrong exemption could pass every test it required.

## Preventive action
**PA-0453** (strengthens PA-0451): an allowlist over untrusted structure compares the full
definition of **every** object — no kind is exempted because a platform setting is believed
to make it inert; any claim that a setting protects something is backed by an attack
fixture that shows the protected case blocked (and the unprotected case running). Nothing
of an untrusted structure is read (no row, no computed value) before the definition that
computes it is validated, and a version this build cannot validate is refused before any
other read. PA-0002 sweep: the gates over untrusted SQLite on this branch are `inspect`,
`summary` (both fixed here) and the migrations' entry (`migrate_with_backup` calls
`inspect` first); `Store`/`open_store` elsewhere open only stores the operator configured
or that passed `inspect`, so no other site reads an unvalidated file.
