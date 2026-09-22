# BUG-0027 — `SemanticsValidator.preserves()`: AST verdict overrode canonicalize in both directions

## 1. Description
`fuzzlab/mutation/semantics.py::SemanticsValidator.preserves()` let a decisive
`sqlglot` AST-equivalence verdict override the canonicalize-based check in either
direction. This produced two opposite defects: (a) it **rejected** a case-toggle
surface variant that canonicalize (correctly) accepted, and (b) it **accepted** an
unvetted `--` line-comment injection that canonicalize (correctly) rejected — a
fail-*open* result, since sqlglot discards every comment style as lexer trivia and
so cannot distinguish the one vetted `/* */` insertion this validator is meant to
recognize from an arbitrary trailing comment that, in a real query, would truncate
everything after it.

## 2. Where encountered
First observed and recorded (without a fix) in `ERROR_LOG.md`'s
2026-09-21 entry "MUT: two `tests/test_mutation_operators.py` failures pre-existing
on the branch tip (found, not fixed)", surfaced by lane L-P3.4's full-suite run and
explicitly deferred to whoever owns the MUT component. Reproduced directly in this
session via `pytest tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics
tests/test_mutation_operators.py::test_sql_equivalent_needs_trusted_provenance`.

## 3. What it caused to fail
- `test_every_surface_variant_preserves_semantics`: `preserves(SQLI, "1 UNION SELECT
  PASSWORD FROM USERS", "sql-injection", trusted=False)` returned `False` for a
  same-meaning, case-toggled surface variant of the `case-toggle` operator.
- `test_sql_equivalent_needs_trusted_provenance`: `preserves("1 or 1=1", "1 or 1=1 --
  x", "sql-injection")` (untrusted, hand-crafted, not produced by any vetted
  operator) returned `True` — the more serious failure, since it is a validator
  designed to *refuse* unproven mutations silently approving one that changes what a
  real query would execute.

## 4. What the bug was identified to be
`preserves()` called `self._ast_equiv(original, mutated)` first and, whenever it
returned a decisive `True`/`False` (not `None`), used that as the final answer,
falling back to `canonicalize()` equality only when AST was inconclusive. AST
equivalence and canonical equivalence do not define the same equivalence class for
this validator's actual surface-operator envelope:
- `canonicalize()` lowercases everything, so it is case-insensitive; `sqlglot`'s
  parsed-tree equality (`pa == pb`) is not — it treats a case-toggled identifier/
  keyword string as a different tree, decisively `False`, even though it is
  semantically identical for SQL's case-insensitive keywords/unquoted identifiers.
- `canonicalize()` only strips `/* */` block comments (the one comment style the
  `sql-comment` operator actually inserts); `sqlglot`'s tokenizer discards **both**
  `/* */` and `--` comments as trivia before building the tree, so AST equality
  cannot tell a vetted block-comment insertion from an arbitrary `--` comment append
  — it decisively says `True` for both.

## 5. Root cause analysis (Five Whys)
1. Why did an untrusted `--` comment injection get accepted? Because `_ast_equiv`
   returned a decisive `True` and `preserves()` trusted that verdict over
   canonicalize's (correct) `False`.
2. Why did `_ast_equiv` return `True` for a semantically-relevant `--` insertion?
   Because `sqlglot`'s parser discards `--`-style comments as lexer trivia, the same
   as `/* */`, before constructing the AST it compares.
3. Why does discarding `--` as trivia matter here specifically? Because this
   validator's only recognized-safe comment insertion is `/* */` (what
   `canonicalize()` — and the `sql-comment` operator — actually implement); AST
   equivalence silently answers a *broader* question ("are these the same parsed
   statement, comments ignored entirely") than the one the validator needs answered
   ("did this mutation only apply a recognized-safe surface transform").
4. Why wasn't this mismatch caught when AST equivalence was added? Because every
   test written for the AST path used a `/* */` insertion, where canonicalize and
   AST equivalence happen to agree — so the design never exercised a case where the
   two checks *disagree*, and the code was written with an implicit, never-verified
   assumption that a decisive AST verdict is strictly more trustworthy than
   canonicalize's.
5. Why is that assumption wrong? Because canonicalize is *itself* the validator's
   authoritative, exhaustive definition of "safe surface variation" (per its own
   docstring: "This proves the surface operators ... preserve meaning and rejects
   anything that drifted") — AST equivalence is a different, broader notion of
   syntactic equality that happens to overlap with canonicalize's definition in the
   common case but is neither a subset nor a superset of it, so letting it override
   canonicalize's verdict was never sound in either direction.

**Root cause:** `preserves()` treated a decisive `sqlglot` AST-equality verdict as
strictly more authoritative than `canonicalize()`'s verdict, without the two checks
ever having been shown to agree on the full equivalence class the validator is
responsible for — they disagree exactly on case-folding (AST too strict) and on
`--` comments (AST too permissive), and the more permissive disagreement is a real,
security-relevant fail-open.

## 6. Corrective action
`fuzzlab/mutation/semantics.py`:
- `preserves()` now checks `canonicalize()` equality **first** (it is authoritative
  for the recognized surface-operator envelope) and returns `True` immediately on a
  match — this alone fixes the case-toggle false-rejection, since canonicalize's
  lowering already treats it as equal.
- Only when canonicalize disagrees does the method consult `_ast_equiv`, and only
  after a new guard, `_comment_provenance_differs(original, mutated)`, confirms the
  difference does not turn on `--` comment presence in one string but not the
  other — since AST equivalence is provably blind to that distinction and must never
  be allowed to launder it into an accept.
- Added `_comment_provenance_differs()` (a `--`-presence XOR check) and its
  docstring explaining exactly why AST cannot be trusted for this.
Delivered in `CC-MUT-0010` (see that component's change-control log for the full
change/impact/risk/deliverables record).

Regression tests added to `tests/test_mutation_operators.py`:
`test_ast_never_approves_an_unvetted_line_comment_injection` and
`test_ast_never_rejects_a_case_toggle_canonicalize_already_accepts`. Full targeted
suite (`test_mutation_operators.py` + every other `test_mutation_*.py` file): 48
passed (was 46 passed / 2 failed before the fix). Full project suite: see
`CC-MUT-0010`'s effectiveness note.

## 7. Recurrence review
Checked every existing `docs/bugs/BUG-NNNN-*.md` (title/summary) and the full
`docs/PREVENTIVE_ACTIONS.md` rule list (PA-0001…PA-0028) for a prior occurrence of
"two validation/decision paths disagree and one silently overrides the other" or
anything specific to `SemanticsValidator`/`canonicalize`/AST equivalence/`sqlglot`.
No prior bug or preventive action addresses this pattern — the closest adjacent
rules (PA-0025, tool-oracle output inference; PA-0026, allowlist-adapter
preconditions) are about a *single* fallible signal being trusted uncritically, not
about two computable, disagreeing verdicts where one is wrongly given priority over
the other. **No prior occurrence found — this is a new bug class.**

## 8. Prior-preventive-action failure analysis
Not applicable — no prior occurrence found (step 7).

## 9. Preventive action
See `PA-0029` in `docs/PREVENTIVE_ACTIONS.md`.

## 10. Status
Fixed. Closes the `ERROR_LOG.md` 2026-09-21 "found, not fixed" entry for this
symptom (cross-referenced there).
