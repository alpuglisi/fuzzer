# BUG-0034 — `ruby_rails` generated controller looked up the wrong view directory for a cell ID containing a digit run

- Date: 2026-09-22
- Status: fixed
- Severity: medium

## Description

The first real live-boot test of the new `ruby_rails` emitter
(`tests/test_labgen_ruby_rails_live_boot.py`) failed with a real HTTP `500`:
`ActionView::MissingTemplate` for `cell_labgen_rr0001/show` — note the
missing underscore before `0001` — even though the emitter had written the
view file to `app/views/cell_labgen_rr_0001/show.html.erb` (with the
underscore) and the controller class was named
`CellLabgenRr0001Controller`.

## Where encountered

`fuzzlab/labgen/emitters/ruby_rails/__init__.py`'s `RailsEmitter.render()`,
surfaced by the real, executed live-boot test
`tests/test_labgen_ruby_rails_live_boot.py::
test_live_boot_illustrative_reflected_cell_serves_real_page` against a real
booted Rails 8.1.3.1 app (`fuzzlab/labgen/conformance/rails_live_boot.py`).

## What it caused to fail

Every generated controller whose controller-name slug contains a digit run
immediately preceded by an uppercase-letter-then-lowercase-letter pair in
its camelized form (e.g. `..._rr_0001` -> `...Rr0001Controller`) would 500
on every real HTTP request, because Rails' bare `render :show` resolves the
view directory from `self.class.controller_path`, which Rails derives from
the class name via `ActiveSupport::Inflector#underscore` at runtime — not
from the string this emitter itself used to name the file/directory. Every
cell ID this generator's own `LABGEN-...-NNNN` convention produces hits
this case (a numeric suffix directly after a letter), so this was not a
narrow edge case — it was the *default* shape, and the illustrative test
cell (`LABGEN-RR-0001`) caught it on the very first real boot.

## What the bug was identified to be

`RailsEmitter` computed the controller's file/directory name
(`controller_name_for`) and its Ruby class name (`_controller_class_for`)
from the same slug, then relied on Rails' bare `render :{{ view_name }}`
symbol form to reconstruct that same file path *back out of the class name*
via Rails' own inflector at request time. That reconstruction is not a
faithful round trip: `ActiveSupport::Inflector#underscore` only inserts an
underscore before a capital letter when it follows a lowercase letter or
another capital-then-lowercase run — it does not insert one before a digit
run that directly follows a letter. `"Rr0001".underscore` produces
`"rr0001"`, not `"rr_0001"`. The emitted file lived at the correctly
underscore-separated path this emitter itself chose; the *runtime* lookup
Rails performed used a different, inflector-derived path the emitter never
verified matched.

## Root cause analysis

**Five Whys:**

1. Why did the request 500? Because `ActionView::MissingTemplate` could not
   find `cell_labgen_rr0001/show`.
2. Why did Rails look in `cell_labgen_rr0001/` when the file was at
   `cell_labgen_rr_0001/`? Because `render :show` (the bare symbol form)
   derives the view directory from `self.class.controller_path`, which Rails
   computes from the controller's *class name*, not from any path string the
   emitter itself wrote.
3. Why does that computation disagree with the emitter's own path string?
   Because `ActiveSupport::Inflector#underscore` (which
   `controller_path` is built from) is not the exact inverse of the
   `capitalize`-per-underscore-segment camelization
   `_controller_class_for` used to build the class name — digits abutting a
   letter collapse the boundary in one direction (underscore -> camelize)
   but do not reappear on the way back (camelize -> underscore).
4. Why was this mismatch not caught before the class name and the file path
   were both derived from the same slug? Because the emitter's own
   `controller_name_for`/`_controller_class_for` functions were written and
   reviewed as a matched pair by inspection — "the class name is this slug,
   capitalized" reads correct — without ever exercising Rails' *own*,
   real `underscore` implementation against the result to confirm the round
   trip actually holds for the format of slug this generator produces
   (a letter run immediately followed by a zero-padded numeric cell-ID
   suffix).
5. Why wasn't that checked? Because the code was authored and unit-checked
   only in Python (rendering the two file contents and inspecting them
   looked correct), and the first time any of it ran against Rails' *real*
   inflector was inside the live-boot test itself — which is exactly what
   caught it, but only because that test happened to render and request the
   actual page rather than merely asserting on the rendered source text.

**Root cause:** the emitter derived a Ruby class name from a slug and then
relied on Rails' own runtime naming convention (`ActiveSupport::Inflector`)
to reconstruct a matching file path from that class name, without ever
verifying that reconstruction was a faithful inverse of the forward mapping
the emitter itself used — for exactly the slug shape (letters immediately
followed by digits) this generator's own `LABGEN-...-NNNN` cell-ID
convention always produces.

## Corrective action

Removed the dependency on Rails' inflector-derived `controller_path`
entirely, rather than trying to make the camelization scheme
round-trip-safe (a real fix that would still be fragile against some future
slug shape). `templates/complexities/render_only.rb.j2` now renders
`render template: "<controller_name>/<view_name>"` — an explicit path
literal, computed directly from the same `controller_name` the emitter used
to write the view file — instead of Rails' bare `render :show` symbol form,
which is the one call that went through the inflector. `RailsEmitter.render()`
passes `view_template = f"{controller_name}/{view_name}"` into the
complexity module's context for this. Verified for real: the same live-boot
test now returns a real HTTP `200` with the expected unescaped payload in
the response body (see `tests/test_labgen_ruby_rails_live_boot.py`, and
`docs/components/01-target-lab/change-control.md`'s `CC-LAB-0071` entry).

## Recurrence review

Checked `docs/bugs/` (all entries, via `grep -il` for `underscore|inflect|
camelize|controller_path`) and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of this bug or a bug with the same root cause. One textual match
(`BUG-0020`) was a regex false-positive in a keyword-matching hook, an
unrelated root cause (string matching, not a framework naming-convention
round trip). No prior bug in this project's history involves a
framework's own name-inflection convention at all — this is the first
Rails-idiom code this project has generated, and no other stack's emitter
(`php_current`/`php_laravel`/`node_express`/`python_fastapi`) has an
equivalent implicit class-name -> path derivation to have hit this earlier
(Laravel's `route()`/Blade `view()` calls the Laravel emitter renders
always take an explicit path string, never a bare symbol resolved through
an inflector). **No prior occurrence found** — this is a new bug class for
this project, not a recurrence, so no prior-preventive-action failure
analysis applies (step 8 is not required).

## Preventive action

See `docs/PREVENTIVE_ACTIONS.md` **PA-0036**: when generated code names an
entity by one convention (a file path, a route string) and separately
derives a *related* name for it via a target framework's own naming/
inflection convention (a class name, a symbol Rails/another framework
expands into a path at runtime), the code performing that derivation must
not assume the two are inverses of each other without checking — either by
computing the framework-facing value from the *same* single source of
truth (an explicit path/string, never re-derived through the framework's
own inflector, which is the fix applied here), or, where the inflected form
must be relied upon, by executing the target framework's real
name-conversion function once against representative "hard" inputs
(a run of digits abutting a letter, for this app-framework class of bug)
before trusting the round trip generatively. Distinct from PA-0035 (a
capability probe's fidelity to a real operation path) and PA-0034 (executed
adversarial tests for sinks that construct executable text) — this is
about **generated code's own naming consistency with a target framework's
implicit conventions**, a failure mode neither prior rule covers.
