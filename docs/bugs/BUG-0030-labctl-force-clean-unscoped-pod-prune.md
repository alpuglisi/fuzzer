# BUG-0030 — `labctl.sh`'s `_force_clean` prunes every podman-managed project's pods, not just this one's

- Date: 2026-09-22
- Status: fixed
- Severity: low (host-side blast radius on multi-project podman hosts; never
  touches the lab target's own exposure/authorization posture)

## Description
`lab/labctl.sh`'s shared `_force_clean` self-heal helper called
`podman pod prune -f`, which removes every stopped/empty pod on the host —
not scoped to this project (`pff-lab`) at all.

## Where encountered
Same script review as BUG-0029/BUG-0031/BUG-0032, formalized in
`docs/change-requests/CR-LAB-0002-*.md` (§3.2) and independently reviewed by
two agents before this fix landed.

## What it caused to fail
On a host that also runs other podman-managed projects, any fuzzlab
`up`/`down`/`reset` self-heal (triggered by a wedged stack, per BUG-0013/
BUG-0017) would remove those other projects' stopped/empty pods too, as an
unintended side effect of a fuzzlab-only operation.

## What the bug was identified to be
```sh
podman pod prune -f >/dev/null 2>&1 || true        # drop the emptied pod(s)
```
`podman pod prune` has no project or name filter; it operates host-wide by
design (it's a generic "clean up my whole podman install" command), not a
per-project operation.

## Root cause analysis
Five Whys:
1. Why did the self-heal remove pods belonging to other projects? Because
   `podman pod prune -f` is host-wide by design.
2. Why was a host-wide command used for a project-scoped cleanup? The other
   lines in `_force_clean` are already project-scoped by construction
   (`podman rm -f pff-lab_{frontend,web,db}_1` names the exact containers;
   `podman network rm pff-lab_default` names the exact network), but no
   equivalent project-scoped removal command was reached for at the pod step
   — `pod prune` was the first thing that "dropped the emptied pod(s)"
   (per the code's own comment), and, since the *effect* looked right in
   testing (no other podman project was running alongside it), the scoping
   gap wasn't visible.
3. Why wasn't the scoping gap visible in review? BUG-0013's original fix
   (`CC-LAB-0011`) and BUG-0017's generalization (`CC-LAB-0013`) both verified
   this function against the wedged-single-project-stack scenario it was
   built for; neither exercised (nor could easily exercise, without a second
   podman project actually present) the multi-tenant-host case where the
   blast radius becomes observable.
4. Why does a project-scoped alternative exist that wasn't used? `podman pod
   ps`/`pod rm` support name filters (`--filter name=...`), the same
   filtering primitive `_force_clean`'s sibling lines rely on implicitly via
   exact container/network names — `prune` was reached for because it's the
   more commonly-reached-for verb for "clean up leftover pods," not because
   no scoped alternative existed.
5. Why does this matter enough to fix now (low severity, no incident so far)?
   Because `PA-0002`'s sweep obligation applies to a bug *class*, not just the
   instance that happened to be observed — the review that found this asked
   explicitly to catch bugs before they recur in the field, and an unscoped
   host-wide side effect in a "self-heal helper that runs automatically on
   failure" is exactly the kind of quiet blast-radius bug that goes unnoticed
   until it destroys someone else's work on a shared host.

**Root cause:** `_force_clean`'s pod-cleanup step used a host-wide
convenience command (`podman pod prune -f`) instead of the same
name-scoping discipline already used for its container- and network-removal
steps in the same function, because the scoping gap has no observable effect
on a single-project host and was never exercised against a multi-tenant one.

## Corrective action
Replaced the unscoped prune with a name-filtered removal, matching the
scoping discipline already used elsewhere in `_force_clean`:
```sh
mapfile -t _pods < <(podman pod ps -q --filter "name=pff-lab" 2>/dev/null) || true
if [ "${#_pods[@]}" -gt 0 ]; then
  podman pod rm -f "${_pods[@]}" >/dev/null 2>&1 || true
fi
```
Verified: `bash -n lab/labctl.sh` (syntax); a standalone `set -euo pipefail`
harness confirming `mapfile` against an empty process substitution safely
yields a zero-length array (no unbound-variable trap under `set -u`) and the
`[ "${#_pods[@]}" -gt 0 ]` guard correctly skips the removal call. Two
residual risks accepted and documented (not silently absorbed) in
`docs/change-requests/CR-LAB-0002-*.md` §3.2:
1. `--filter name=...` is substring/regex matching, not exact-name — a
   hypothetical second project literally named e.g. `pff-lab-ci` on the same
   host would still match. Narrower than the prior fully host-wide prune
   (an improvement), not a perfect per-checkout guarantee.
2. `podman pod rm -f` (unlike `podman pod prune -f`) will force-remove a
   matched pod even if it still holds live containers. This is judged a
   desirable strengthening for the wedged-stack case this function exists
   for (BUG-0013/BUG-0017) — a live-container pod being left behind on a
   wedged stack is the exact failure mode those bugs are about — but it is a
   real behavior change beyond pure scoping and is recorded as such rather
   than folded silently into "this is just narrowing."

Reviewed and approved via `docs/change-requests/CR-LAB-0002-*.md`
(`CC-LAB-0057`).

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **No prior bug or PA
addresses unscoped/host-wide side effects from a project-local self-heal
helper.** BUG-0013/BUG-0017/PA-0014/PA-0018 are about the same function but a
different concern entirely (whether the self-heal *runs at all* on every
container-lifecycle path, not whether an individual step inside it is
correctly scoped to this project). None found addressing this specific
failure mode (a project-scoped helper using a host-wide primitive for one of
its steps while its sibling steps are correctly scoped).

## Preventive action
**PA-0032** (see `docs/PREVENTIVE_ACTIONS.md`): a project-scoped cleanup
helper (self-heal, teardown, cache-clear, etc.) must scope **every** step to
the project, not just the steps whose scoping was easy to reach for by
naming an exact resource. When adding a step to such a helper, check whether
the CLI/tool being called has a host-wide "clean everything of this kind"
verb (`prune`, `clean`, `gc`, etc.) as well as a filtered/scoped one
(`--filter`, `--name`, a label selector); if a host-wide verb is used, that
is a deliberate, documented exception (with a stated reason it cannot be
scoped), never the unexamined default. This closes a gap PA-0018's
container-lifecycle sweep did not cover: PA-0018 asks "does every relevant
*path* route through the shared helper", not "is every *step inside* the
shared helper itself scoped to the project" — both questions must be asked
when auditing or extending such a helper.
