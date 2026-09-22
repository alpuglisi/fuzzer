# BUG-0029 — `labctl.sh down` reports success without verifying the fallback teardown worked

- Date: 2026-09-22
- Status: fixed
- Severity: low (masks a real teardown failure as success; no automated caller
  currently depends on the exit code — see corrective action)

## Description
`lab/labctl.sh`'s `down` subcommand, on a failed `compose down`, calls the
shared `_force_clean` self-heal helper and then always exits the `case` arm
with status 0 — regardless of whether the stack was actually torn down.

## Where encountered
Script review of `lab/labctl.sh` requested against the repo's shell scripts
(2026-09-22), then formalized in `docs/change-requests/CR-LAB-0002-labctl-and-bookkeeping-hook-bugfixes.md`
(§3.1) and reviewed by two independent agents before this fix landed.

## What it caused to fail
`./labctl.sh down` can print nothing wrong and exit 0 while the compose stack
is still up (or in an even worse state than before the call), if the original
`compose down` failure wasn't the "wedged podman stack" case `_force_clean`
actually fixes — e.g. `podman` isn't installed at all (`_force_clean`'s first
line, `command -v podman >/dev/null 2>&1 || return 0`, makes it an immediate
no-op) or the daemon/permissions error is unrelated to a wedged pod. Nothing
downstream can distinguish "down succeeded" from "down failed, then a no-op
ran, then we lied about it."

## What the bug was identified to be
```sh
down)
  if ! "${COMPOSE[@]}" down; then
    echo "down failed; force-clearing wedged stack (DB volume kept)..." >&2
    _force_clean keep-volume
  fi
  ;;
```
`_force_clean`'s body is entirely `cmd || true`, ending in an explicit
`return 0`. Once the `if` branch runs at all, the `case` arm's exit status is
unconditionally 0. `up` and `reset` don't have this defect: both re-attempt
the real compose operation after `_force_clean` and let *that* attempt's exit
status propagate under `set -euo pipefail`.

## Root cause analysis
Five Whys:
1. Why can `down` report success on a stack that's still up? Because the
   `case` arm's last executed command in the failure branch is `_force_clean`,
   which always returns 0, not a re-check of whether teardown succeeded.
2. Why does `_force_clean` always return 0? By design (`return 0` at the end)
   — it's meant to be a best-effort cleanup helper safe to call unconditionally
   from every container-lifecycle path (`up`, `reset`, `down`), including when
   `podman` isn't installed at all (a legitimate no-op).
3. Why wasn't that a problem for `up`/`reset`? Because both of those paths
   were written to *retry the real operation* after calling `_force_clean`,
   and let that retry's own exit code decide success — `_force_clean`'s
   always-0 return was never the thing determining their final exit status.
4. Why didn't `down` get the same retry? BUG-0017's fix (`CC-LAB-0013`) added
   `_force_clean keep-volume` to `down`'s failure branch as part of routing
   every container-lifecycle path through the shared helper (PA-0018), but
   that fix's own corrective-action note explicitly frames the goal as "even
   a wedged teardown succeeds" — i.e. it assumed calling `_force_clean` *was*
   the fix, and never added the retry-and-propagate step `up`/`reset` already
   had, because `down` has no "recreate" step afterward to naturally serve
   as that retry.
5. Why wasn't this caught at the time? BUG-0017's own test plan
   (`docs/bugs/BUG-0017-*.md`) is a Five-Whys/code-reading verification, not
   an execution-traced check of `down`'s exit code on a non-podman or
   non-wedged failure path — the fix was verified against the wedged-stack
   scenario it targeted, not against the "force_clean legitimately no-ops"
   scenario this bug is about.

**Root cause:** `down`'s failure branch was given the shared self-heal call
(`_force_clean`) as part of BUG-0017's cross-path convention (PA-0018), but
unlike `up`/`reset` it was never given a **retry of the real operation** to
determine its own exit status — so it inherited `_force_clean`'s
by-design-unconditional `return 0` as its own result instead.

## Corrective action
`lab/labctl.sh`'s `down` case now retries `"${COMPOSE[@]}" down` after
`_force_clean keep-volume` and lets that retry's exit status propagate under
`set -euo pipefail`, matching `up`'s and `reset`'s existing retry-then-propagate
shape:
```sh
if ! "${COMPOSE[@]}" down; then
  echo "down failed; force-clearing wedged stack (DB volume kept)..." >&2
  _force_clean keep-volume
  "${COMPOSE[@]}" down
fi
```
Verified: `bash -n lab/labctl.sh` (syntax); a standalone `set -euo pipefail`
harness confirming a failing final command in an `if` branch propagates its
exit status as the branch's own status. No automated script currently
executes `./labctl.sh down` on a live path (the two textual references,
`scripts/greybox_e2e.sh:81` and `scripts/h2_desync_e2e.sh:94`, are both
printed human-facing recovery hints inside `die`/`echo`, never executed —
confirmed by direct grep of every `scripts/*.sh` caller during this CR's
review), so this fix's present-day effect is limited to a human operator
running `down` interactively now getting an honest result. Reviewed and
approved via `docs/change-requests/CR-LAB-0002-*.md` (`CC-LAB-0057`).

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **No exact match** —
this is not a second instance of BUG-0013/BUG-0017's "podman-compose cannot
remove/recreate a running/wedged stack" class (PA-0014/PA-0018): the
underlying podman limitation isn't in question here, and `down` *does*
already route through the shared `_force_clean` helper per PA-0018's
requirement. The defect is one layer up — assuming that calling the shared
helper *is* the fix, without also re-verifying the operation it was supposed
to enable. That is the same general shape as **PA-0007/PA-0025** (a checker
must not infer success/"secure" from the absence of a proven failure signal —
there, a tool-oracle's exit code without confirming the tool actually ran;
here, a `case` arm's exit code without confirming the retried operation
actually succeeded), but in an entirely different component (an operational
shell script's control flow, not a fuzzing tool-oracle wrapper) and a
different kind of check (shell exit-status propagation, not tool-diagnostic
parsing) — so it is **related in spirit, not the same bug or the same
component's failure mode**, and does not trigger a prior-preventive-action
failure analysis under `docs/bugs/README.md`'s "same bug or same root cause"
test. No stronger match found.

## Preventive action
**PA-0031** (see `docs/PREVENTIVE_ACTIONS.md`): when a shared best-effort
helper is added to a code path specifically to make a previously-failing
operation succeed (a self-heal, a retry, a fallback), the calling path's exit
status must come from **re-attempting and checking the actual operation the
helper was meant to unblock** — never from the helper's own return value,
if that helper is designed to return success unconditionally (as a "safe to
call anywhere, including as a no-op" cleanup helper legitimately is). This
generalizes PA-0018's "every container-lifecycle path must route through the
shared helper" to also require: routing through the helper is necessary but
not sufficient — the path must still verify the operation succeeded
afterward, the same way its sibling paths already do, rather than treating
"we called the self-heal helper" as itself the success condition.
