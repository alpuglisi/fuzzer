# BUG-0145 — lab scripts piped into readers that can stop early, under `pipefail`

- Date: 2026-10-15
- Status: fixed
- Severity: medium.
  - `labctl.sh down` could skip force-clearing leftover containers in exactly the case
    where some were left.
  - `extctl.sh up` could exit 141 with no message.

## Description
Four `set -o pipefail` scripts piped a producer into a reader that may exit before
reading everything:
- `podman ps | grep -q` (labctl.sh);
- `php -m | grep -qi` (greybox_e2e.sh);
- `sed | head -n 1` (labctl.sh, extctl.sh);
- `printf "$rendered" | _py check-config` (extctl.sh).

When the reader exits first, the producer dies of SIGPIPE, and `pipefail` makes the
pipeline fail with status 141. A `grep -q` that *found* its match then reads as "not
found".

## Where encountered
The merged full suite of the 2026-10-15 integration:
`tests/test_external_labs_extctl.py::test_up_preflights_starts_checks_exposure_and_bootstraps_only_when_authorized[False]`
returned 141 with empty output, once, under parallel load.

## What it caused to fail
- That test, intermittently.
- In production, latent but real:
  - `labctl.sh down`'s leftover check read a match as "no leftovers" when `podman`
    printed more after the match;
  - `up` would mask a checker error behind a bare 141.

## What the bug was identified to be
The test's stand-in checker never reads its input, so `printf` raced its exit. It was
not reproduced in 20 runs under CPU load (a narrow window). It **was reproduced
deterministically** with a config larger than a pipe buffer (300 KB): `printf` then
blocks and must take SIGPIPE, giving exit 141 every time.

## Root cause analysis
**Method: barrier analysis** of the shell-safety convention.
- **`set -euo pipefail` was adopted to fail loudly** (PA-0059(1): an engine error never
  reads as "nothing").
- **Nothing banned the one pipeline shape that `pipefail` turns into a false
  failure:** a reader that may exit before EOF.
- **No guard scans the shell scripts for it.** The Python side has `procutil` guards;
  the shell side has none.

**Root cause:** `pipefail` was applied without the matching rule that a pipeline's reader
must consume all of its input. Readers that exit early (`grep -q`, `head`, a checker
that may error) were piped into.

## Corrective action
Commit in the 2026-10-15 integration (CC-LAB-0258):
- the checker takes its config as a here-string;
- `sed` quits at the first `name:`;
- `podman ps` and `php -m` output is captured first, then searched with a here-string;
- regression test:
  `tests/test_external_labs_extctl.py::test_the_preflight_never_dies_of_sigpipe_when_its_checker_stops_reading`,
  which fails with 141 before the fix and passes after.

## Recurrence review
- **BUG-0059 / PA-0059:** engine errors must not read as "nothing". Related: `pipefail`
  was the tool chosen for that, without this caveat. Not the same defect.
- **BUG-0143 / BUG-0144:** the same day's lesson, that a failure seen only under load
  is a defect to reproduce. That is how this one was found instead of re-run.

## Prior-preventive-action failure analysis
PA-0059(1) was too narrow in the other direction: it asked scripts to never mistake an
error for "nothing", and `pipefail` delivered that. But it also made an early-exiting
reader's normal exit look like an error. No rule covered that interaction.

## Preventive action
PA-0151:
1. Under `pipefail`, never pipe into a reader that may exit before EOF (`grep -q`,
   `grep -m`, `head`, `sed …q`, a checker that may refuse early).
2. Capture the output, or use a here-string, a single tool that quits itself, or a
   file.
3. A test of any such script uses an input larger than a pipe buffer.

**PA-0002 sweep:** all eight `pipefail` scripts in `lab/` and `scripts/` were searched.
Four sites were fixed. `scripts/on_host_full_run.sh:171` is a quoted command string run
elsewhere, not a pipeline of this script.
