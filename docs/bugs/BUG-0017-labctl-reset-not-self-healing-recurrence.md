# BUG-0017 — `labctl.sh reset` not self-healing under podman-compose (recurrence of BUG-0013)

- Date: 2026-09-21
- Status: fixed
- Severity: medium (blocks on-host Part E grey-box runs; leaves the stack wedged)

## Description
`scripts/greybox_e2e.sh` step 1 runs `( cd lab && ./labctl.sh reset )` to get a clean,
freshly-seeded lab before the grey-box coverage run. On an already-running (or
previously-wedged) podman stack this failed: `podman-compose down -v` cannot remove
containers it considers "improper" or that are still running (`cannot remove container
… as it is running`, `container state improper`), so the volume drop and the subsequent
recreate errored with `executing /usr/bin/podman-compose up -d --build: exit status 125`,
leaving the stack wedged and Part E unable to start.

## Where encountered
On the host (podman-compose): after `git pull` (to `a32e250`), `scripts/greybox_e2e.sh`
failed at step 1 (`labctl.sh reset`) with podman container-recreate / "cannot remove …
as it is running" errors and `exit status 125`.

## What it caused to fail
Part E (Phase 3 grey-box instrumentation) could not start — `reset` never produced a
clean stack, and the leftover running/wedged containers blocked the re-seed and every
subsequent `up`/`reset`.

## What the bug was identified to be
The `reset` subcommand of `lab/labctl.sh` recreated containers with a bare
`compose down -v` → `compose up -d --build` and **no force-clean fallback**. That is the
exact podman-compose limitation fixed in BUG-0013 — podman-compose cannot tear down /
recreate a running or wedged stack cleanly — but the BUG-0013 fix (CC-LAB-0011) was
applied **only to the `up` subcommand**. `reset` recreates containers too, so it hit the
same wall with no recovery.

## Root cause analysis
Five Whys:
1. Why did step 1 fail? `labctl.sh reset` → `podman-compose down -v` / `up -d --build`
   errored (`exit status 125`) because the stack was running/wedged.
2. Why did that error? podman-compose cannot remove "improper"/running containers with
   `down`, nor recreate them in place — the same limitation as BUG-0013.
3. Why was there no recovery? `reset` ran a bare `down -v` + `up` with no force-clean
   fallback; only the `up` subcommand had been made self-healing.
4. Why was only `up` self-healing? The BUG-0013 fix inlined the self-heal logic in the
   `up` case and its remediation/sweep were framed around the *env/profile change on a
   running stack* trigger — `reset` (which recreates to drop the volume, not to change
   env) was not recognized as the same class.
5. Why wasn't the class caught by the PA-0002 sweep? The sweep was performed against that
   narrow framing ("paths that change env/profile") rather than the actual mechanism
   ("any podman-compose operation that must remove/recreate running containers"), and the
   self-heal was never factored into a shared helper, so there was no single call site to
   reuse and no obvious second call site to notice.

**Root cause:** the container-lifecycle self-heal (force-clear a wedged podman stack) is
a convention that must hold across every labctl path that removes/recreates containers,
but BUG-0013 implemented it inline in one path (`up`) and its sweep enumerated by the
*trigger* (env/profile change) instead of the *operation* (container recreate/remove),
so the sibling recreate path (`reset`) was left unguarded and recurred.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Match found (same root-cause
class):** **BUG-0013** — "Orchestration assumed `compose up` recreates a running stack
(podman can't)", remediated by CC-LAB-0011 and PA-0014. This is a direct recurrence: the
same podman-compose limitation (cannot remove/recreate a running/wedged stack) striking a
different labctl subcommand (`reset` here, `up` there). Also relevant: the earlier
un-investigated ERROR_LOG "no Compose provider" incident that BUG-0013 first identified as
this class's origin.

## Prior-preventive-action failure analysis
BUG-0013 produced two preventive actions whose intent covers this case, yet it still
recurred. Why each did not hold:

- **PA-0014** ("orchestration that changes env/profile on a running stack must be
  self-healing…") was **scoped to the trigger, not the mechanism**. Its wording keys on
  *env/profile change*; `reset` does not change env/profile (it drops the volume), so it
  read as out of scope even though it hits the identical podman limitation. The rule
  named a symptom (env/profile changes fail) instead of the cause (podman-compose can't
  remove/recreate running containers), so a sibling path with the same cause but a
  different trigger slipped through.
- **PA-0002** (sweep the whole codebase for the bug class when a PA is added) **was
  applied against that same narrow framing**. Sweeping for "paths that change env/profile
  on a running stack" found only `up`; sweeping for "paths that remove or recreate
  containers" would have found `reset` (and `down`) immediately. The sweep inherited
  PA-0014's mis-scoping.
- **PA-0003** (a convention that must hold across more than one writer lives in exactly
  one shared function every writer calls) **was not applied** to the self-heal logic:
  CC-LAB-0011 inlined the force-clean sequence inside the `up` case rather than a shared
  helper. Had it been a shared function, `reset` would have been an obvious call site and
  the omission would have been visible at the call, not hidden in duplicated prose.

**Why prevention did not hold (summary):** the previous fix guarded the *instance and its
trigger* rather than the *mechanism and all its call sites* — it named the rule after the
symptom (PA-0014), swept for the symptom (PA-0002 under that framing), and did not
centralize the fix (PA-0003), so the second recreate path stayed unguarded.

## Corrective action
- `lab/labctl.sh`: factored the force-clean sequence into a single shared helper
  `_force_clean()` (`podman rm -f pff-lab_{frontend,web,db}_1` — `-f` removes even
  running/wedged containers — then `podman pod prune -f`, `podman network rm`, and an
  optional `podman volume rm` when passed `drop-volume`; no-op when `podman` is absent).
  Every container lifecycle path now routes through it: `up` calls `_force_clean keep-volume`
  on failure (data preserved); `reset` force-cleans with `drop-volume` before the recreate
  and again (then retries `up`) if the recreate fails; and — from the PA-0018 sweep below —
  `down` force-cleans `keep-volume` on failure so even a wedged teardown succeeds. The happy
  path is unchanged; force-clean runs only when needed and only under podman. (CC-LAB-0013)

## Sweep (PA-0002 / PA-0018)
Enumerated `lab/labctl.sh` subcommands by the *operation* (not the trigger): `up`
(create/recreate), `reset` (remove + recreate), and `down` (remove) all touch container
lifecycle and now route through `_force_clean`; `status`, `logs`, `exec`, `snapshot`,
`restore`, `pin` do not create/remove/recreate containers (read-only, in-container, or
image-only) and are correctly out of scope. Swept `scripts/` for direct compose/podman
calls that bypass labctl: the only one is `greybox_e2e.sh`'s pcov-repair hint
(`labctl.sh down && podman-compose build --no-cache web && labctl.sh up`) — a *build*
(image) op, not a container-recreate path, and it is bracketed by the now-self-healing
`down`/`up`, so no change is needed there.

## Preventive action
PA-0018 (see `docs/PREVENTIVE_ACTIONS.md`): container-lifecycle self-heal is a
cross-path convention — every orchestration path that creates, removes, or recreates
containers on a possibly-running/wedged podman stack must route through the **one shared
force-clean helper** (PA-0003), not reimplement or omit it per subcommand. When a
container-lifecycle fix is added, the PA-0002 sweep must enumerate call sites by the
**operation** (recreate/remove/tear-down) — every relevant subcommand (`up`, `reset`,
`down`, and any future one) — not by the **trigger** that first surfaced it (env/profile
change). This strengthens PA-0014 (which named the trigger) by re-keying it to the
mechanism, and closes the sweep gap that let BUG-0013 recur.
