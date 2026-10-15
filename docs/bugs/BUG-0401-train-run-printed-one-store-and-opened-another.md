# BUG-0401 — `train run` printed and checked one store, while the engine opened another

- Date: 2026-10-15
- Status: fixed
- Severity: medium

## Description

`fuzzlab train run` resolved `--store` itself through `core.storepath.resolve`, which
expands `~` and makes the path absolute. It used that resolved path for its writable
check and its `store: …` line. When the user had given `--store`, though, it forwarded
the user's **raw** argv to the engine (`auto_cli.main`). The engine opens
`Store(args.store)` and does not expand `~`.

## Where encountered

Code review B of the CLI-simplification Phase 1 (`git diff cdde39f 31b5013`), before
merge. The reviewer reproduced it with `run_main([URL, '--store=~/x.db', '--score',
'--authorized'])`.

## What it caused to fail

- The command printed `store: <HOME>/x.db (--store)` and checked that path.
- The engine then opened `./~/x.db`: either a SQLite "unable to open database file" or a
  store inside a directory literally named `~`.
- The printed store line, which exists so the user knows where results went, was
  therefore wrong.
- The writable check validated a path that was never opened.

## What the bug was identified to be

Two derivations of one value:
- `train_cli` derived the store path with `storepath.resolve`;
- the engine derived it with `Path(args.store)`.

The two disagree on `~` (and would on any normalisation the resolver adds later).
`forward()` appended the resolved path only when the user gave no `--store`.

## Root cause analysis

Five Whys:

1. *Why did the engine open another file?* The engine received the raw `--store=~/x.db`.
2. *Why raw?* `train run` forwards the user's argv verbatim, and added `--store` only
   when the flag was absent.
3. *Why verbatim?* PA-0400(3), written the same day, says to prefer forwarding the
   user's own argv over re-serialising a parsed namespace. That avoids BUG-0400's
   serialisation defects.
4. *Why did verbatim forwarding break this value?* The wrapper does not merely pass
   `--store` through. It *resolves* it, and acts on the resolved form: it checks it and
   prints it. The engine resolves it differently, with no expansion. A value the wrapper
   resolves is no longer the user's text.
5. *Why was the split not seen?* The forwarding tests compared the forwarded argv with
   the input argv (verbatim), not the engine's parsed value with the value the wrapper
   printed.

**Root cause:** a wrapper that resolves a value, and reports or checks that resolution,
forwarded the unresolved form to a downstream that derives the value its own way. That
left two derivations of one convention (PA-0003/PA-0021). PA-0400(3)'s "forward
verbatim" did not distinguish values the wrapper itself resolves.

## Corrective action

`train_cli.forward()` now always appends `--store <resolved path>` last. argparse keeps
the last occurrence, so the engine opens exactly the store the wrapper resolved, checked
and printed, whatever spelling the user gave: `~`, `..`, an abbreviation such as
`--sto`, or `--store=`. All other values are still forwarded verbatim.

The test is `tests/test_train_cli.py::test_the_engine_opens_exactly_the_store_resolved_and_printed`
(3 spellings × 3 forms), which parses the forwarded argv with the engine's own parser.
A discovered forwarding round trip over every engine action was also added
(`::test_forwarding_round_trips_every_action_of_the_engine`). Delivered by CC-FUZZ-0401.

## Recurrence review

- **`docs/bugs/`.** BUG-0400 (the same lane, the same day): argv serialisation by the
  launcher. A different root cause; it was the *reason* for PA-0400(3). No earlier bug
  is about a wrapper forwarding raw text that it also resolves.
- **`docs/PREVENTIVE_ACTIONS.md`.**
  - **PA-0003/PA-0021:** one shared function per convention. That is the same class:
    two derivations of the store path.
  - **PA-0400(3):** "prefer forwarding verbatim". This is the rule followed here.
- **Result:** a recurrence of the PA-0003/PA-0021 class, and a direct gap in PA-0400(3).

## Prior-preventive-action failure analysis

- **PA-0003/PA-0021 did not apply in the author's view.** They target code that "adds a
  second derivation". Forwarding text was not seen as deriving anything; the engine's
  `Path(args.store)` *is* a derivation, but it lives in a locked file nobody was
  editing. The rule is worded around writing a derivation, not around *handing a value
  to* one.
- **PA-0400(3) was too broad.** It said to forward verbatim without carving out values
  the wrapper itself interprets. It was followed exactly, and that is what produced
  this bug.

## Preventive action

**PA-0401** strengthens PA-0400(3) and PA-0021. When a wrapper resolves a value and acts
on the resolution (checks it, prints it, records it), it forwards the **resolved** value,
in a position the downstream parser lets win. Its test parses the forwarded argv with the
downstream's own parser and compares that value with the one the wrapper reported. Every
other value is still forwarded verbatim.

PA-0002 sweep:
- **Wrappers that forward argv in `fuzzlab/`.** `train_cli.forward` is the only one that
  resolves anything. `train reveal-holdout`, `train flow-anomaly` and `train mutate` pass
  argv to CLIs that resolve the store themselves (one derivation each).
- **`cli.py`.** Its `runpy` dispatch to `crawl`, `audit` and `fuzz` passes argv
  untouched and resolves nothing.

No other instance.
