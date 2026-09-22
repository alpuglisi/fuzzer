# BUG-0029 — `blind_sqli_fuzzer.py` discarded every completed observation on Ctrl-C

## 1. Description
`run_fuzzing_cycle()` in `fuzzlab/tools/blind_sqli_fuzzer.py` collected timing
observations into a local `rows` list, returned only when the payload loop
finished normally. `main()`'s `except KeyboardInterrupt: print(...)` handler wraps
the whole `establish_baseline` → `run_fuzzing_cycle` → `save_dataset` sequence, but
because the interrupt is raised **inside** `run_fuzzing_cycle` and that function
never returns on that path, `save_dataset(rows, args.output)` is never reached —
every already-completed, real observation the run had already paid the request
cost for was silently thrown away instead of saved.

## 2. Where encountered
Found during a requested robustness review of fuzzlab's primary CLI driver
scripts (`fuzzlab/cli.py`, `fuzzlab/tools/spider.py`, `fuzzlab/tools/fetcher.py`,
`fuzzlab/tools/blind_sqli_fuzzer.py`, `fuzzlab/harness/auto_cli.py`,
`fuzzlab/mutation/cli.py`, `fuzzlab/session/cli.py`), not from a user report.
Verified directly by reading `run_fuzzing_cycle`/`main()` and reproduced with a
fake sender that raises `KeyboardInterrupt` on a scripted call.

## 3. What it caused to fail
No test previously covered `run_fuzzing_cycle`/`main()`'s interrupt path at all
(zero coverage on this module before this change). Reproducing the documented
symptom: a fake sender that raises `KeyboardInterrupt` after N calls, fed into
`run_fuzzing_cycle` with the real `PAYLOADS` catalog, returns from the *function
call itself* via the propagating exception — before this fix, that exception
reached `main()`'s handler directly, and the `rows` list (with every payload
result gathered before the interrupt) was never passed to `save_dataset`, so
`args.output` (the CSV) was never written and, when `--store` was also given, the
unified-store consolidation step never ran either. A long fuzz run (each payload
measured `--repeats` times with a `--pause` between measurements, against a real
timing-sensitive target) interrupted anywhere after its first payload lost 100% of
its real, already-obtained results.

## 4. What the bug was identified to be
`rows` is a value local to `run_fuzzing_cycle`; the function has a single `return`
statement at the very end of its loop. There is no `try/except KeyboardInterrupt`
*inside* the function to intercept the exception before it unwinds the whole call,
so the caller's `save_dataset(rows, ...)` call — three lines below the
`run_fuzzing_cycle(...)` call in `main()` — is provably unreachable on that path.

## 5. Root cause analysis (Five Whys)
1. Why were completed observations lost on Ctrl-C? Because `run_fuzzing_cycle`
   never returned the `rows` it had already collected — the function exits via an
   unhandled exception, not a `return`, on that path.
2. Why does the function exit via an unhandled exception instead of returning?
   Because nothing inside `run_fuzzing_cycle`'s loop catches `KeyboardInterrupt`;
   only a `requests.RequestException` around a single HTTP call is caught, for an
   unrelated purpose (skip one bad payload, not stop the run).
3. Why wasn't this caught earlier? `main()`'s own `except KeyboardInterrupt` gives
   the *appearance* of handling the interrupt (it prints a clean "[-] Interrupted
   by user." message, no raw traceback) — so superficially the script "handles
   Ctrl-C fine." The data loss is invisible unless you inspect what actually
   happened to the in-progress `rows`, which nothing — no test, no manual
   inspection during development — previously did.
4. Why did the outer handler's clean message mask the real problem? Because a
   clean message with no crash looks like correct, graceful handling; the
   defect isn't a crash at all, it's silent data loss disguised as graceful
   shutdown — the worst kind of failure to spot by just running the tool and
   watching it not crash.
5. Why was there no test to catch this? This module had zero test coverage of
   `run_fuzzing_cycle`/`establish_baseline`/`main()` before this review (only the
   HTTP-seam sender classes were tested, in `tests/test_fuzzer_seam.py`) — nothing
   ever exercised the interrupt path to observe what `rows` actually contained
   afterward.

**Root cause:** the interrupt handler was placed at the wrong layer (around the
whole `main()` sequence) to actually recover the partial work already done by the
layer it wraps (`run_fuzzing_cycle`'s internal loop) — a clean top-level message on
`KeyboardInterrupt` was mistaken for "handling the interrupt," when the actual
requirement (per the surrounding code's own intent — collecting `rows` precisely
so `save_dataset` can persist them) was to salvage in-progress work, not just avoid
a raw traceback.

## 6. Corrective action
`fuzzlab/tools/blind_sqli_fuzzer.py::run_fuzzing_cycle()`: wrapped the per-payload
loop in `try/except KeyboardInterrupt`, returning the `rows` collected so far (with
a message naming how many observations were salvaged) instead of letting the
exception propagate past the function. `main()`'s existing
`save_dataset(rows, args.output)` call then naturally persists the partial results,
unchanged — no caller-side code needed to change. Delivered in `CC-FUZZ-0024`.

New tests in `tests/test_blind_sqli_fuzzer_robustness.py` (this module had zero
prior coverage): a clean run returns every row; an interrupt partway through
returns a non-empty, strictly-partial row set; an interrupt on the very first call
returns an empty list without crashing; a per-request `RequestException` still
only skips that one payload (regression guard, unchanged prior behavior);
`establish_baseline` raises a clear `ConnectionError` when the target is
unreachable.

## 7. Recurrence review
Checked every `docs/bugs/BUG-NNNN-*.md` title/body and the full
`docs/PREVENTIVE_ACTIONS.md` rule list for a prior "interrupt/exception silently
discards already-completed work" pattern. No match — the closest adjacent bug is
BUG-0028 (a *different* silent-data-loss shape: a migration step overwriting
already-correct persisted state on every `--append` run, not an interrupt
discarding in-memory work). **No prior occurrence found — this is a new bug
class**, though it shares the general "graceful-looking handling that actually
discards good data" theme with BUG-0028's recompute-on-every-run bug — see
`PA-0031` for how the new preventive action generalizes across both.

## 8. Prior-preventive-action failure analysis
Not applicable — no prior occurrence found (step 7).

## 9. Preventive action
See `PA-0031` in `docs/PREVENTIVE_ACTIONS.md`.

## 10. Status
Fixed.
