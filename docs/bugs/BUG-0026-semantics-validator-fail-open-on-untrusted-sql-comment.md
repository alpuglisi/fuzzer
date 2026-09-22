# BUG-0026 — `SemanticsValidator` accepts an untrusted `--` comment-append as
semantics-preserving (fail-open), and is case-sensitive where SQL is not

- Date: 2026-09-22
- Status: fixed
- Severity: high

## Description

`fuzzlab/mutation/semantics.py::SemanticsValidator.preserves()` had two independent
defects:

1. **Fail-open (security-relevant).** An untrusted mutation that appends a SQL `--`
   line comment (e.g. `"1 or 1=1"` → `"1 or 1=1 -- x"`) was accepted as
   semantics-preserving with `trusted=False` — i.e. without any vetted provenance —
   although a `--` comment is exactly the kind of transform (it truncates everything
   that follows once the fragment is concatenated into the real query) that
   `NFR-MUT-semantics`/`NFR-MUT-safe` require the validator to refuse or flag absent
   provenance.
2. **Fail-closed on a case toggle it should have accepted.** The `case-toggle`
   *surface* operator (provably meaning-preserving for SQL, since unquoted keywords
   and identifiers are case-insensitive) was rejected by the AST-equivalence path,
   which compared `sqlglot` AST nodes with `==` — an equality that is sensitive to the
   literal source case `sqlglot` preserves, even though the two payloads are the same
   query.

## Where encountered

`tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics`
and `tests/test_mutation_operators.py::test_sql_equivalent_needs_trusted_provenance`
— both chronically failing (re-confirmed by many lanes' `pytest` runs this session,
per `ERROR_LOG.md`'s 2026-09-21 "found, not fixed" entry from lane L-P3.4).

## What it caused to fail

- `test_every_surface_variant_preserves_semantics` failed on the `case-toggle`
  variant of `SQLI`: `v.preserves(SQLI, "1 UNION SELECT PASSWORD FROM USERS", ...)`
  returned `False` even though the mutation genuinely preserves meaning.
- `test_sql_equivalent_needs_trusted_provenance` failed on its final assertion:
  `v.preserves("1 or 1=1", "1 or 1=1 -- x", "sql-injection")` (untrusted) returned
  `True`, when it must return `False`.
- Beyond the two tests: every consumer of `SemanticsValidator.preserves()` —
  `fuzzlab/mutation/learn.py` (filter-bypass learning) and
  `fuzzlab/mutation/search.py` (coverage-guided `MutationSearch`) — inherits this
  fail-open behavior. A learned or searched variant that merely appends a `--`
  comment to an otherwise-unrelated payload would have been recorded as a genuine,
  semantics-preserving filter bypass, when its real effect on a live target depends
  entirely on what it truncates in the concatenated query — something the isolated
  fragment cannot prove and the validator was not verifying.

## What the bug was identified to be

Two independent code defects in `SemanticsValidator`:

1. `preserves()` treats a decisive AST-equivalence verdict, and canonical-form
   equality, as unconditionally sufficient to accept an *untrusted* mutation. Both
   checks are blind to `--` comments in the sense that matters here:
   `sqlglot.parse_one()` discards comments as non-semantic trivia (so
   `"1 or 1=1"` and `"1 or 1=1 -- x"` parse to identical ASTs — the AST path
   returned `True`), and `canonicalize()`'s `_SQL_COMMENT` regex only strips bounded
   `/* */` block comments (the shape the `sql-comment`/`ws-alt` surface operators
   actually emit), never `--` line comments, so the canonical path was never even
   reached before the AST path short-circuited it.
2. `_ast_equiv()` compared parsed `sqlglot` expression trees with Python `==`, which
   is case-sensitive on captured source text (identifiers/keywords), while SQL's own
   equivalence rule for unquoted tokens is case-insensitive.

## Root cause analysis

Five whys (for the fail-open defect, the security-relevant one):

1. **Why did the validator accept an untrusted `--` comment-append as
   semantics-preserving?** Because the AST-equivalence check returned `True` for the
   pair, and a decisive AST verdict was returned immediately without any other gate.
2. **Why did the AST check return `True` for a payload that added a `--` comment?**
   Because `sqlglot`'s SQL grammar (like virtually every SQL parser) discards
   comments when building the AST — comments are lexical trivia with no semantic
   node, so parsing `"1 or 1=1"` and `"1 or 1=1 -- x"` in isolation yields
   structurally identical trees.
3. **Why is "structurally identical trees for the isolated fragment" treated as
   proof the mutation preserves meaning?** Because the validator's contract
   (`preserves()`'s docstring, `canonicalize()`'s design) was written around the
   surface operators the mutation engine actually emits — `/* */` block-comment
   insertion, whitespace alternation, URL-encoding, case toggling — all of which
   *are* provably safe from the fragment alone. Nothing in the validator's design
   anticipated that a `--` marker is a structurally different case: unlike a bounded
   `/* */` block comment, an unbounded `--` comment's safety cannot be judged from
   the fragment at all, because its effect (truncating everything after it) depends
   on what the fragment gets concatenated into at the real injection point — the one
   thing the validator, working only on `(original, mutated)` strings, cannot see.
4. **Why wasn't that gap noticed before it produced a fail-open result?** Because no
   default operator in `fuzzlab/mutation/operators.py` currently emits a `--` line
   comment (only `/**/`), so the gap was invisible to the operator-driven test suite
   until a test was written that probed the validator directly with a `--`-bearing
   string not sourced from an operator — `test_sql_equivalent_needs_trusted_provenance`
   asserts precisely this: `assert not v.preserves(base, "1 or 1=1 -- x", ...)`.
5. **Root cause:** `preserves()` conflated "the two isolated fragments are
   syntactically/canonically equivalent" with "safe to accept without provenance."
   For most surface transforms those coincide, but `--` comment injection is a case
   where fragment-level equivalence is not evidence of safety at all — the risk is
   in what the comment hides *outside* the fragment, which no per-fragment check
   (AST or canonical) can observe. The validator had no explicit rule saying "an
   `--`-introducing transform is only ever acceptable as `trusted=True`, never
   inferred," so it silently defaulted to fail-open for that one case, which is
   exactly the class of input `NFR-MUT-safe`'s fail-closed posture is meant to catch.

(For the case-sensitivity defect: root cause is that `sqlglot`'s node `__eq__`
preserves source case for identifiers/keywords, while the validator's own
`canonicalize()` a few lines away already documents "lowercase" as one of the
surface variations it must treat as equivalent — the AST path was never brought
into agreement with that documented invariant.)

## Corrective action

`fuzzlab/mutation/semantics.py`:

- Added `introduces_line_comment(original, mutated)`: `True` when `mutated` contains
  more `--` occurrences than `original`.
- `SemanticsValidator.preserves()`: for a SQL-like `vuln_class`
  (`_SQL_LIKE_CLASSES`), an untrusted mutation that `introduces_line_comment(...)`
  now returns `False` immediately — before the AST or canonical checks run — so
  neither can fail-open on it. `trusted=True` still accepts it (vetted provenance is
  unaffected).
- `SemanticsValidator._ast_equiv()`: now compares `pa.sql().lower() == pb.sql().lower()`
  (the re-rendered SQL text, lowercased) instead of node `==`, so a pure case toggle
  of unquoted SQL is correctly recognized as equivalent, consistent with
  `canonicalize()`'s existing lowercasing.
- Added `tests/test_mutation_operators.py::test_untrusted_line_comment_introduction_is_rejected`
  (direct regression for the fail-open case, including the `trusted=True` escape
  hatch) and
  `tests/test_mutation_operators.py::test_no_default_surface_operator_introduces_a_line_comment`
  (a PA-0027-style regression, derived from `default_operators()` itself rather than
  a hardcoded operator-id list, asserting the invariant holds for every current and
  future surface operator, across all three vuln-class sample payloads used
  elsewhere in the file).
- Delivered in change control `CC-MUT-0008`.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of the
same bug, or a different bug with the same root cause.

- **`ERROR_LOG.md` (2026-09-21, lane L-P3.4)** recorded these same two test failures
  as "found, not fixed" — a lightweight log line, not a `BUG-NNNN`/`PA-NNNN` pair, so
  per the task instructions this is not treated as a formal recurrence of an existing
  `BUG-NNNN`. Noted here for context: this is the first time the defect gets the full
  RCA/PA treatment, several `pytest` runs after it was first spotted and left
  unfixed.
- **PA-0007** ("never infer authentication/authorization success from an *ambient*
  signal; require a positive differential signal") and **PA-0025** ("a tool-oracle
  wrapper must not infer 'secure' purely from the absence of a positive match")
  are both instances of the same general shape — inferring a safe/positive verdict
  from a check that is blind to the actual risk — but neither is about mutation
  semantics or SQL comments specifically; this is a new instance of that general
  fail-open shape in a different subsystem, not a recurrence of either.
- No existing `BUG-NNNN`/`PA-NNNN` addresses `SemanticsValidator`, `sqlglot` AST
  comparison, or SQL comment semantics. No prior-preventive-action failure analysis
  applies; this is a new preventive action, not a strengthening of an existing one.

## Preventive action

**PA-0028** (new) — recorded in `docs/PREVENTIVE_ACTIONS.md`:

A semantics/equivalence validator that accepts a mutation *by default* (any check
that returns "equivalent" from comparing two isolated fragments — AST, canonicalized
string, or otherwise) must enumerate the transform shapes its fragment-level checks
are structurally blind to — specifically, any construct whose safety depends on
context *outside* the compared fragment (e.g. a SQL `--`/unterminated-comment marker,
whose effect is on whatever follows it in the real, concatenated statement) — and
refuse those **unconditionally** absent explicit trusted provenance, before running
the fragment-level checks at all, rather than trusting the fragment-level checks to
happen to catch them. This is the "unprovable from the compared unit" special case
of PA-0025's fail-closed doctrine, applied to semantics validators rather than tool
oracles: a validator's default posture for an unproven case must be reject, not
accept. The PA-0002 sweep for this class covered every call site of
`SemanticsValidator.preserves()` in `fuzzlab/mutation/` (`learn.py`, `search.py`) —
both call the shared method directly, so the fix applies to them automatically; no
other equivalence/validator function in `fuzzlab/mutation/` independently re-derives
an accept/reject verdict (checked: `operators.py`, `xss.py`, `catalog.py`,
`filtermodel.py`, `livefilter.py`, `llm.py`, `payloads.py`, `run.py`, `cli.py` — none
define a second `preserves`-shaped predicate).
