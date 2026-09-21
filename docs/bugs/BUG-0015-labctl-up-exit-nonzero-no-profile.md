# BUG-0015 — `labctl.sh up` exits non-zero on success (no profile), aborting `set -e` callers

- Date: 2026-09-21
- Status: fixed
- Severity: medium (Part J could not run; a self-testing script exited before its self-test)

## Description
The `up)` case in `lab/labctl.sh` ended with
`[ -n "${PFF_PROFILE:-}" ] && echo "profile '${PFF_PROFILE}' enabled"`. When `PFF_PROFILE`
is empty (the common path — `scripts/waf_evasion_e2e.sh` sets no profile), `[ -n "" ]`
returns 1 and, being the **last command executed**, makes `labctl.sh up` exit **1 despite
bringing the lab up successfully**. A caller under `set -e`
(`( cd lab && PFF_WAF=on ./labctl.sh up )`) then aborts immediately after "lab up", before
reaching its next step — and `waf_evasion_e2e.sh`'s silent EXIT trap turned the WAF back
off, so the run ended with no output past step 1.

## Where encountered
On the host: `scripts/waf_evasion_e2e.sh` printed step 1's "lab up" then exited silently
with no step 2–5. `scripts/h2_desync_e2e.sh` worked because it sets `PFF_PROFILE=desync`,
so the `&& echo` fired and returned 0 — the with-profile path was fine, the no-profile path
was not.

## What it caused to fail
Part J (WAF evasion) never ran past enabling the WAF; the evasion/record/verify steps were
skipped and the script gave no error, just a silent early exit.

## What the bug was identified to be
A shell `set -e` exit-status pitfall: a `A && B` compound as the **last command** of a
function/case/script returns non-zero when `A` is false (`B` never runs), so the whole
script's exit status is non-zero on an otherwise-successful path. Introduced with the
`PFF_PROFILE` support (CC-LAB-0010).

## Root cause analysis
Five Whys:
1. Why did waf_evasion_e2e.sh stop after step 1? `( ... ./labctl.sh up )` returned non-zero
   and `set -e` aborted the script.
2. Why did `labctl.sh up` return non-zero? Its last command, `[ -n "" ] && echo ...`,
   returned 1 (empty profile → test false → echo skipped).
3. Why is that the exit status? A trailing `A && B` yields `A`'s status when `A` fails, and
   it was the last command in the case/script.
4. Why wasn't it caught? The change (CC-LAB-0010) was never executed on a no-profile `up`
   path in the build environment (no lab there), so the exit code was never observed.
5. Why does the self-test not catch it? The script aborted *before* reaching its self-test;
   a fail-loud self-test cannot catch a harness bug that exits earlier in the script.

**Root cause:** a `set -e` exit-status pitfall (trailing `A && B` as the last command)
returned failure on success; and, per the recurrence below, the script was labelled `[run]`
on offline verification without an actual on-host execution that would have exposed it.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. The immediate cause (a `set -e`
trailing-`&&` exit status) has no prior bug. But **the reason it shipped is a recurrence of
BUG-0014's root cause** — an on-host script presented as verified/runnable (`[run]`) without
an executed run against the real host (the build sandbox has no lab), so a real-path runtime
defect slipped through. PA-0002 sweep: checked the other `&&`-as-conditional sites
(`labctl.sh:42` standalone; `greybox_e2e.sh:128` last-in-if-body) — both are exempt from
`set -e` (verified with `bash -c`), because only a trailing `A && B` that is the last command
of the whole execution path sets the script's exit status. No other instance needs fixing.

## Prior-preventive-action failure analysis
PA-0015 (created immediately before this) requires runbook steps to be written from an
executed, verified run and to ship a fail-loud self-test before being tagged `[run]`. It did
not prevent this because: (a) the scripts were tagged `[run]` on the strength of **offline
unit tests + the presence of a self-test**, not an actual on-host execution the sandbox
cannot perform; and (b) a fail-loud self-test **cannot catch a harness/exit-code bug that
aborts the script before the self-test runs**. So PA-0015 covered "the exit is proven" but
not "the script's own control flow / exit status is correct on every path."

## Corrective action
`lab/labctl.sh` `up` now uses an `if` for the profile notice
(`if [ -n "${PFF_PROFILE:-}" ]; then echo ...; fi`), which returns 0 whether or not a
profile is set, so `up` exits 0 on success. Verified with `bash -c 'set -e; ...'` that the
no-profile tail now returns 0. (CC-LAB-0012)

## Preventive action
PA-0016 (see `docs/PREVENTIVE_ACTIONS.md`): shell scripts under `set -e` must not end a
function/case/script with a bare `A && B` (it returns non-zero when `A` is false); use an
`if` or append `|| true`. Because the build environment cannot run the on-host scripts,
statically check them — `shellcheck` and a targeted `bash -c` exit-code check on **both**
branches (e.g. profile set and unset) — and assert the success path exits 0. This
strengthens PA-0015: a `[run]` script's own harness (control flow, exit codes on all paths)
must be verified, not just its exit assertion, since a self-test cannot catch an abort that
precedes it.
