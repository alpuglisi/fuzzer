# BUG-0400 — The launcher's argv builder mis-serialises four argparse shapes

- Date: 2026-10-15
- Status: open. Pinned by strict xfails. The fix belongs to the UI lane, because this
  lane may not edit `fuzzlab/web/`.
- Severity: medium

## Description

`fuzzlab.web.runner.build_flags(spec, values)` turns a values dict, keyed by argparse
dest, back into command-line flags. It handles three action shapes: bool, `append`, and
single value. It mis-serialises the others that this project's parsers use:

1. **`nargs='*'`/`'+'` lists.** A list value is emitted as one argument, its Python
   repr. A bare `--submit-spa-forms` becomes `--submit-spa-forms []`, an SPA route
   literally named `[]`. `--submit-spa-forms login search` becomes one argument,
   `['login', 'search']`. The discovery test found the second case; the design review
   found the first.
2. **An optional value whose `const` is `""`.** For example, a bare
   `--follow-selector-forms` is dropped, because an empty value counts as "unset".
3. **A value starting with `-`.** For example, `--identity=-bob` is emitted as
   `--identity -bob`, which argparse then rejects ("expected one argument").

## Where encountered

During the design gate of the CLI-simplification lane
(`docs/CLI_WORKING_VS_TRAINING_DESIGN.md`). Reviewer B reproduced the problem through
`cli_dryrun.report`. Reviewer A traced the same function into the web launcher's launch
path. I reproduced both with `python -c` against the real parsers.

## What it caused to fail

- **The web launcher's real child argv** (`web/app.py` → `runner.build_argv`):
  - a UI user cannot enable the bare `--follow-selector-forms` (GET menu forms);
  - `--submit-spa-forms` submits a route called `[]` (bare) or `['login', 'search']` (with routes), never the routes named;
  - a dash-leading value produces a child that exits 2.
- **Every CLI's `--dry-run`** (through `cli_dryrun.report`) shows a "command that would
  run" that is not the command that would run. That breaks NFR-*-dry-run's promise of an
  exact plan.

## What the bug was identified to be

`build_flags` classifies each option only by the `OptionSpec` fields `type` and
`multiple`. `OptionSpec` (`web/commandspec.introspect`) records neither `nargs` nor
`const`. So the serializer cannot tell these apart:

- a list-valued `nargs='*'` option from a scalar one;
- "flag given with no value" from "flag absent";
- a value that needs the `--flag=value` form from one that does not.

## Root cause analysis

Five Whys:

1. *Why is `--submit-spa-forms` emitted as `[]`?* `build_flags` prints `str(value)` for
   every non-bool, non-append option.
2. *Why does it not know the value is a list?* `introspect` reduces each action to
   `type`/`multiple`; `nargs` and `const` are lost.
3. *Why was that reduction accepted?* The serializer was written for the shapes the
   tools had when it was built (Phase 0.3). Later flags (`nargs='*'`, `nargs='?'` with a
   `const`) arrived through other lanes' parsers and were picked up by introspection
   automatically. Nothing checked that they also serialised back.
4. *Why did no test catch it?* `tests/test_web_runner.py` checks `build_flags` against
   hand-written spec fixtures (bool, append, str). No test parses a built argv back with
   the real parser. The introspection tests (`test_web_commandspec.py`) check the forward
   mapping only.
5. *Why is there no round-trip check?* The adapter was treated as a formatting helper,
   not as an inverse of argparse whose correctness depends on enumerating every input
   shape the wrapped API accepts.

**Root cause:** an adapter that inverts a third-party parser (argparse) was written for
the action shapes present at the time. Its contract was never stated as
"`parse(build(parse(argv))) == parse(argv)` for every action of every registered
parser", so new shapes entered through introspection with no failing test.

## Corrective action

This lane cannot edit `fuzzlab/web/` (it belongs to the UI session). It did two things:

- **Pinned each broken shape** with a strict xfail in `tests/test_cli_argv_roundtrip.py`:
  - `test_nargs_star_with_no_items_round_trips`;
  - `test_optional_value_with_empty_const_round_trips`;
  - `test_dash_leading_value_round_trips`.

  It also asserts the three working shapes there
  (`test_bool_append_and_single_value_shapes_round_trip`). This follows PA-0054(3) and
  PA-0115(3): a known instance not fixed is pinned in the same change. The UI lane's fix
  turns each xfail into an XPASS(strict) failure, which that lane converts into a plain
  test (`docs/MULTI_AGENT_ORCHESTRATION.md` §6).
- **Avoided the defect in this lane's own code.** `fuzzlab train run` forwards the
  user's argv verbatim and never re-serialises it (design §6.2), so this lane adds no
  second instance. CC-FUZZ-0400.

Recommended fix for the UI lane:

- carry `nargs` and `const` into `OptionSpec`;
- emit `--flag=value` for single values;
- emit the bare flag for `nargs='*'` with `[]` and for a value equal to `const`;
- refuse (raise) a list item that starts with `-`;
- make the round-trip test cover every action of every registered spec.

## Recurrence review

**What I checked.**

- `docs/bugs/` for argv, `build_flags`, `nargs` or serialisation defects. Hits: BUG-0023,
  BUG-0080, BUG-0125 and BUG-0130 mention argv, but only for process launch and
  bind-flag argv. None is a serialiser.
- `docs/PREVENTIVE_ACTIONS.md` for adapters over third-party APIs:
  - **PA-0026** (an allowlist adapter must enumerate the value-shape preconditions of
    every parameter it wraps, with a test reproducing the library's silent failure);
  - **PA-0065(5)** (adapters pass vendored-library options in the exact shape the
    vendored source handles);
  - PA-0036 (a derived name and its inverse are never assumed to round-trip without
    checking).

**Result.** This is not a recurrence of the same instance. It is the **same root cause
class as BUG-0024/PA-0026**: an adapter around a third-party API that did not enumerate
the input shapes the API accepts. So a prior-preventive-action failure analysis follows.

## Prior-preventive-action failure analysis

PA-0026 (from BUG-0024) failed to prevent this for three reasons:

- **Too narrow, by its trigger wording.** PA-0026 is scoped to "an explicit-allowlist
  adapter built *because* the wrapped function silently mishandles some input class". An
  argv serializer was not seen as such an adapter: it does not wrap a function that
  mishandles input; it *inverts* one. So nobody applied PA-0026's per-parameter
  enumeration to it.
- **Not enforced mechanically.** PA-0026 and PA-0065(5) are written rules with no
  discovery-based guard. Nothing enumerates "every adapter over argparse" or "every
  action of every registered parser".
- **The wrong layer.** The shapes that broke arrived through *other* lanes' parsers via
  automatic introspection. A rule applied when the adapter was written cannot cover
  shapes added to its inputs later. Only a standing test over the live set of parsers
  can.

## Preventive action

**PA-0400** strengthens PA-0026 and PA-0036.

1. Code that maps between argv and argparse values for the project's own parsers
   (introspection, serialisation, copying, forwarding) states its contract as a **round
   trip**. A test parses with the real parser, builds, parses again, and compares
   values. The test runs over **every action of every registered parser** (discovery,
   not a list), so a shape added later by another lane fails it.
2. A shape the code cannot express **fails closed** (raises). It never emits a different
   argv.
3. Prefer **forwarding the user's own argv verbatim** over re-serialising a parsed
   namespace, wherever the original argv is available.

The PA-0002 sweep for this class covered every argv builder in `fuzzlab/`. The grep
`build_flags|build_argv|argv.append|args +=` (excluding `labgen/`, whose argv lists
launch toolchains, not fuzzlab parsers) found one serializer: `web/runner.build_flags`
(with `build_argv`/`display_command` on top of it, and `cli_dryrun.report`).
`fuzzlab/train_cli.py` (this lane) forwards verbatim. No other instance exists. This
lane's own argparse copying (`cli_taxonomy.copy_parser`) is proven by a
parity-and-identity test over every action of `auto`'s parser (CC-FUZZ-0400).
