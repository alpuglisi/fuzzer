# BUG-0013 — Orchestration assumed `compose up` recreates a running stack (podman can't)

- Date: 2026-09-21
- Status: fixed
- Severity: medium (blocks on-host Part J/K runs; leaves the stack wedged)

## Description
`scripts/waf_evasion_e2e.sh` (enable the WAF via `PFF_WAF=on ./labctl.sh up`) and
`scripts/h2_desync_e2e.sh` (`PFF_PROFILE=desync ./labctl.sh up`) rely on `compose up -d`
to apply an env/profile change to an already-running stack. **podman-compose cannot
recreate containers in place**: it errors with `the container name "pff-lab_web_1" is
already in use ... use --replace` and `has dependent containers which must be removed
before it`, and can leave the pod half-torn-down and wedged so even a subsequent `up`
keeps failing.

## Where encountered
On the host (podman-compose): `scripts/waf_evasion_e2e.sh` step 1 and
`scripts/h2_desync_e2e.sh` step 1 both failed with `exit status 125` and container
name-in-use / dependent-container errors; re-running kept failing because the stack was
wedged.

## What it caused to fail
Parts J and K could not start — the env/profile change never applied, and the leftover
containers blocked further `up`s.

## What the bug was identified to be
The orchestration assumed `up` performs an in-place recreate when configuration changes
(as `docker compose` does). podman-compose does not; it neither `--replace`s nor cleanly
tears down dependents first, so changing `PFF_WAF`/profile on a running stack fails and
wedges it. `labctl.sh up` ran a bare `up -d --build` with no recovery.

## Root cause analysis
Five Whys:
1. Why did step 1 fail? `podman-compose up -d` errored: container names already in use.
2. Why in use? The stack was already running and the env/profile changed, so `up` had to
   recreate the containers.
3. Why did recreate fail? podman-compose cannot recreate in place (no `--replace`, no
   ordered teardown of dependents) — unlike docker compose.
4. Why did the toolkit rely on that? `labctl.sh up` assumed `compose up` applies config
   changes to a running stack, a docker-compose behavior podman-compose lacks.
5. Why wasn't it guarded? The one prior incident of this class was treated as a one-off
   (see below), so no rule prevented the next "assumed compose capability" gap.

**Root cause:** the toolkit relied on a compose behavior (in-place recreate on config
change) that podman-compose does not implement, with no fallback — the same *class* as a
prior "assumed a compose capability podman lacks" incident that was never captured as a
preventive rule.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Match found (same root-cause
class):** the ERROR_LOG entry "`labctl.sh up` failed: no Compose provider" (root cause:
"`labctl.sh` assumed `docker` existing implied `docker compose` worked"). Both are the same
class — *the toolkit assumed a compose capability that is absent/different under
podman-compose*. That incident had no `docs/bugs/` investigation and no PA (its ERROR_LOG
remediation line even mis-referenced "PA-0004", which is actually about committed external
defaults — an unrelated rule).

## Prior-preventive-action failure analysis
Why prevention did not hold: the earlier incident was fixed **in place** (probe candidate
providers) and its lesson was **never distilled into a preventive action** — it was
mislabeled to an unrelated PA and effectively treated as an environment quirk. So the
general class ("don't rely on compose behaviors that differ between docker compose and
podman-compose") was never guarded, and it recurred here as a different capability gap
(in-place recreate). The failure of prevention was the **absence of a rule**, caused by
closing the earlier incident without a PA.

## Corrective action
- `lab/labctl.sh` `up` is now self-healing: if `up` fails, it runs `down` (keeping the DB
  volume), force-clears any wedged podman containers/pod/network
  (`podman rm -f pff-lab_{frontend,web,db}_1`, `podman pod rm -f`, `podman network rm`),
  and retries `up` — so env/profile changes and a wedged stack recover automatically. The
  happy path is unchanged; the fallback only runs on failure and only force-cleans when
  `podman` is present. (CC-LAB-0011)

## Preventive action
PA-0014 (see `docs/PREVENTIVE_ACTIONS.md`): do not rely on compose behaviors that differ
between `docker compose` and `podman-compose` — chiefly in-place recreate on a config/env
change (podman-compose cannot). Orchestration that changes env/profile on a running stack
must be self-healing: on failure, tear the stack down (keep data volumes), force-clear
wedged containers/pod/network under podman, and retry. Also (process, from the recurrence
review): when a provider/environment incident is fixed in place, still record a PA for the
*class* — do not close it as a one-off, or the class recurs unguarded.
