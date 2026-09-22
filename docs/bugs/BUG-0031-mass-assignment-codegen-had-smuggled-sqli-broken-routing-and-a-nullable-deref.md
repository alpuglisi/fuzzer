# BUG-0031 — Mass-assignment code generation (CC-LAB-0064/FR-LAB-59) shipped a smuggled SQLi, broken POST routing, and a nullable dereference

## Description

The `orm_entity_bulk_assign` code-generation increment (mass-assignment sink
family, `CC-LAB-0064`/`FR-LAB-59`), merged via PR #1 after passing its own
21-test suite and a 4-round adversarial change-control review, had three
independent real defects that surfaced only once a *different* reviewer (the
PR's own external review, not this session) exercised the generated code and
the routing machinery directly instead of trusting the authoring session's
own tests:

1. `fuzzlab/labgen/modules/sinks/orm_entity_bulk_assign.php.j2` (php_current):
   the SET-clause **column name** (`$__col`) was spliced into `$sql` straight
   from an unvalidated `$_POST` array key, with no identifier-charset check.
   A request like `postFields[updated_at=NOW() WHERE 1=1;--]=x` turns `$__col`
   into that raw string, giving a real SQL injection (CWE-89) smuggled into a
   cell `lab/safety_matrix.yaml`/`static_precheck.py` both classify as
   mass-assignment (CWE-915) only.
2. `fuzzlab/labgen/emitters/php_laravel/__init__.py`'s `_served_route_for()`
   hardcoded `"GET"` for every illustrative page regardless of the manifest
   cell's declared `method`. The new mass-assignment manifest cells are the
   first illustrative **POST** cells this emitter ever rendered, so their
   generated route was `Route::get(...)` — a POST to the declared endpoint
   received a method mismatch and could never exercise either twin's logic.
3. `fuzzlab/labgen/emitters/php_laravel/templates/sinks/
   orm_entity_bulk_assign.php.j2` unconditionally dereferenced
   `$request->user()->id`. The generated skeleton sets up no session/auth
   middleware for an illustrative cell, so an ordinary unauthenticated
   request has a null `$request->user()`, and `null->id` is a fatal PHP
   error, not the graceful null-degrade `php_current`'s `$currentUser['id']`
   array-access convention has.

## Where encountered

External code review on `alpuglisi/fuzzer#1` (the PR merging this branch's
work into `main`), on the freshly-merged `orm_entity_bulk_assign` codegen
commit. All three findings were inline review comments on the generated PHP
templates and the Laravel routing helper.

## What it caused to fail

Nothing failed loudly in this session's own build/test pass — that is the
point of this bug. `tests/test_labgen_mass_assignment.py` (21 tests, all
green) and the full `labgen`-marked suite (928 passed) never exercised any of
these three paths adversarially:
- No test fed a non-identifier-shaped key through the php_current sink to
  check the resulting SQL text for injected syntax.
- No test checked the *emitted HTTP verb* in a rendered route fragment
  against the manifest cell's own declared method for an illustrative page —
  every existing assertion checked the URL/controller wiring, never the verb.
- No test rendered the Laravel sink against a request with no authenticated
  user to see whether it would actually execute.

Had this landed unreviewed, a real fuzzing/oracle run against this cell would
have mis-scored a live SQL-injection vulnerability as mass-assignment-only
ground truth (a false negative on the SQLi class), and the Laravel twin pair
would have been entirely unexercisable (wrong HTTP verb, fatal on an
unauthenticated request) — silently absent from the corpus despite appearing
present and tested.

## What the bug was identified to be

Three independent code defects in the same code-generation increment,
described above (1: unvalidated SQL identifier from array keys; 2: hardcoded
HTTP method for illustrative pages; 3: unguarded nullable-object dereference).

## Root cause analysis (Five Whys)

1. **Why did the SQLi/routing/null-deref defects ship?** Because the
   authoring session's own tests all passed and the pre-change review gate
   (`docs/components/README.md`) approved the *design*, not the generated
   code's own adversarial edge cases.
2. **Why didn't the tests catch them?** Because every test asserted the
   *happy path* the feature was built to demonstrate (mass-assignment via a
   valid key, a GET-style render, a populated `$request`) — none fed an
   adversarial input shaped to break a *different* invariant (SQL syntax,
   HTTP verb correctness, null safety) than the one the cell was built to
   illustrate.
3. **Why didn't the 4-round change-control review catch them?** Because that
   review (per its own record, `CC-LAB-0064`'s change-control entry) verified
   the *design*'s claims against the *existing* codebase's conventions
   (registry structure, safety-matrix rows, Eloquent semantics) — it never
   rendered the actual generated PHP and tried to break it adversarially, nor
   checked the routing layer's HTTP-verb handling for an illustrative POST
   cell (the first one ever authored, so no prior test coverage existed to
   extend).
4. **Why was there no prior test coverage to extend for illustrative POST
   cells or column-name-from-array-key SQL construction?** Because both
   shapes are genuinely new to this codebase (every prior illustrative cell
   is GET; every prior SQL sink parameterizes a *scalar value*, never builds
   an identifier from a runtime-computed key) — this increment was the first
   to combine "illustrative + non-GET" and "identifier position sourced from
   attacker-controlled array keys" at once.
5. **Root cause:** the authoring session's own verification (tests +
   change-control review) checked the code against the *design it was
   written to satisfy*, never against *adversarial inputs orthogonal to that
   design's own concern* — the same class of gap PA-0006 already names
   generally ("a rule or step keys only on what is available at its stage")
   applied here to a code-generation feature rather than a detection rule: a
   feature whose own tests only exercise its intended demonstration will not
   catch a different vulnerability class it accidentally also introduces.

## Corrective action

All three fixed in the same commit as this report:
1. `orm_entity_bulk_assign.php.j2` (php_current): reject any `$__col` that
   does not match `^[A-Za-z0-9_]+$` before splicing it into `$sql`,
   mirroring this codebase's own `identifier_charset_filter` pattern —
   closes the SQLi while leaving the mass-assignment vulnerability itself
   (any *validly-shaped*, endpoint-unintended column name) fully intact on
   the unfiltered twin.
2. `_served_route_for()`: illustrative pages now serve at the cell's own
   declared `method` instead of a hardcoded `"GET"` — verified backward
   compatible (every pre-existing illustrative cell across every manifest is
   already `GET`, confirmed via `load_manifest` over `lab/manifests/*.yaml`
   before the fix landed).
3. `orm_entity_bulk_assign.php.j2` (php_laravel): `$request->user()?->id`
   (PHP 8's nullsafe operator) instead of `$request->user()->id`, matching
   php_current's own non-fatal degrade-to-null convention for this same
   illustrative-cell shape.

New/updated tests: `test_orm_entity_bulk_assign_sink_rejects_a_syntax_
injection_shaped_key` (renders the malicious key, proves it is dropped, not
merely absent from template text); `test_the_routes_file_carries_one_sorted_
line_per_cell` updated to check every cell's *actual* HTTP verb, not just
count `Route::get(` lines (its prior form would have hidden this exact bug
by construction, only ever counting the one verb it assumed).

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of "own tests pass, but did not exercise an adversarial input orthogonal to
the feature's own intended demonstration." `BUG-0022` (a `supports()`/
`render()` shape/page-profile lockstep gap) and `BUG-0024`
(emitter/safety-matrix lockstep gap, → `PA-0024`) are the closest prior
matches, but both are about **structural lockstep between two registries**
(a shape claimed supported that cannot actually render), not about
**adversarial input against a rendered code path's own runtime behavior**.
No prior bug in this class (a code-generation feature's tests all pass while
the *generated code itself* is adversarially unsafe in a way orthogonal to
what it was built to demonstrate) was found — this is a new root cause, not
a recurrence of an existing one, so no prior-preventive-action failure
analysis is required (per `docs/bugs/README.md` step 8's own gating on step
7 finding a match).

## Preventive action

See `docs/PREVENTIVE_ACTIONS.md` **PA-0034**: for any new code-generation
sink/template that constructs a SQL statement (or other executable text)
from a runtime-computed *identifier* (not just a bound value), or that
combines a request-derived value with a request-derived HTTP verb/route/
auth-context assumption for the first time in a given code path, add at
least one test that renders the actual code and executes it against an
adversarial input orthogonal to the feature's own intended demonstration
(a malformed identifier, a mismatched verb, an absent auth context) — not
only the assertions that prove the feature's own happy path.
