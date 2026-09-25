# BUG-0057 — `labctl.sh down` silently leaves an `apps`-profile stack running (second recurrence of BUG-0013/BUG-0017)

- Date: 2026-09-25
- Status: fixed
- Severity: medium (Gate F's own required teardown step left 11 containers and 10 networks running; would strand every future `apps`-profile session the same way)

## Description

`PFF_PROFILE=apps ./labctl.sh down`, run right after `PFF_PROFILE=apps ./labctl.sh up`
during Lane 7 Gate F's required full-profile boot (`CC-LAB-0247`), printed a wall of
podman-compose errors (`container state improper`, `"<net>" has associated containers
with it`) but reported nothing wrong and left every one of the 10 new app containers —
and all 10 of their dedicated networks — running.

## Where encountered

On-host (podman-compose, no docker daemon), running Lane 7 Gate F's own required manual
verification step (`docs/LAB_LANE7_GATES_D_TO_G_HANDOFF.md` §F1) after the full
`apps`-profile boot.

## What it caused to fail

`labctl.sh down`'s one documented job — stop and remove containers — silently did not
happen for the `apps` profile. A caller trusting the command's success (no error surfaced
to the script's own exit code or stdout beyond the raw podman-compose error text) would
believe the stack was down while 11 containers kept running and consuming resources
indefinitely.

## What the bug was identified to be

Two independent defects, both in `lab/labctl.sh`:

1. `_force_clean()` — the one shared self-heal helper `up`/`reset`/`down` all route
   through (per `BUG-0017`'s own `PA-0018` fix) — only ever listed the 3 pre-Lane-7
   containers (`pff-lab_frontend_1`/`pff-lab_web_1`/`pff-lab_db_1`) and one network
   (`pff-lab_default`). The 10 new Lane 7 app containers and their 10 dedicated networks
   (added in this same lane's Gate E) were never added to these hand-maintained lists, so
   `_force_clean` could not have cleared them even if it had run.
2. `podman compose down` itself **returns exit code 0** even when it fails to remove
   containers and prints per-container/per-network errors. `down`'s case block was
   `if ! "${COMPOSE[@]}" down; then _force_clean keep-volume; fi` — trusting that exit
   code — so the failure was never detected and `_force_clean` never ran at all, making
   defect 1 moot for this call path (it would have failed the same way even with an
   up-to-date list).

## Root cause analysis

Five Whys:
1. Why did `down` leave the stack running? `_force_clean` was never invoked.
2. Why was it never invoked? The `if ! "${COMPOSE[@]}" down; then ...` check saw exit
   code 0 and treated the `down` as successful.
3. Why did `podman compose down` exit 0 despite failing? podman-compose's own exit-code
   contract does not propagate per-container/per-network removal failures to the overall
   command's exit status for this failure shape (multiple services on per-service
   dedicated networks, some still "improper"/running) — confirmed by running
   `podman compose down` directly and observing `exit=0` alongside a page of `Error:`
   lines.
4. Why was this never caught before? Every prior labctl.sh path that calls
   `_force_clean` unconditionally after a `|| true` (`reset`) rather than gating on the
   inner command's exit code — only `down`'s case trusted the exit code as the failure
   signal, and `down` had never been exercised against the new, larger `apps`-profile
   topology (11 containers across 10 dedicated networks) until Gate F's own boot.
5. Why did `_force_clean`'s own container/network lists go stale independently? They are
   hand-maintained literal lists in the shell script, not derived from `compose.yaml`
   (unlike, e.g., `docker compose down` itself, which reads the compose file); Gate E
   added 10 new services to `compose.yaml` without a corresponding update to this
   separate, unrelated file's hand-kept lists — nothing connects the two, so nothing
   forced the update or flagged the omission.

**Root cause:** the container-lifecycle self-heal convention (`BUG-0013`/`BUG-0017`'s
`PA-0018`, "every operation that removes/recreates containers must route through the one
shared force-clean helper") holds structurally in this codebase (`down` does call
`_force_clean` on failure), but two things PA-0018 did not anticipate both broke it at
once: (a) the failure-detection signal it relies on (the wrapped command's own exit code)
is not reliable for every podman-compose failure shape, and (b) the shared helper's own
data (which containers/networks to clean) is a hand-maintained literal list with no
mechanism forcing it to stay in sync with `compose.yaml`'s actual service set as that set
grows.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Match found (same root-cause
class, second recurrence):** `BUG-0013` (podman-compose cannot recreate/remove a
running/wedged stack; fixed by centralizing self-heal into `_force_clean`, `PA-0014`) and
its own direct recurrence `BUG-0017` (`reset` was left unguarded because the fix and its
sweep were scoped to the *trigger*, not the *mechanism*; `PA-0018` re-keyed the rule to
the mechanism — "every path that creates/removes/recreates containers must route through
the shared helper" — and swept `up`/`reset`/`down` by that mechanism). This is a *third*
occurrence of the same underlying class (a podman-compose container-lifecycle operation
silently fails to converge), now via two mechanisms `PA-0018` did not cover: an
unreliable exit code, and a self-heal helper whose own data went stale as the compose
topology grew.

## Prior-preventive-action failure analysis

`PA-0018` already got the *structural* rule right — `down` does route through
`_force_clean` on failure, exactly as `PA-0018` requires — yet the bug still occurred, for
two reasons `PA-0018` did not address:

- `PA-0018` names the mechanism as "every operation that creates/removes/recreates
  containers," which correctly identified `down` as in scope, but it says nothing about
  **how a caller detects that the operation failed**. It implicitly assumed the wrapped
  command's own exit code is that signal — true for `up`/`reset`'s failure modes at the
  time, but not true for `down`'s failure mode against this larger topology. The rule
  targeted *routing* self-heal to the right subcommands, not *triggering* it reliably.
- `PA-0018` also says nothing about keeping the shared helper's own container/network
  *data* current. Centralizing the self-heal logic into one function (as `PA-0003`/
  `PA-0018` require) prevents the logic itself from drifting across call sites, but the
  literal name lists inside that one function are exactly the kind of hand-maintained
  duplication `PA-0027` warns about elsewhere (independently-hand-maintained copies of a
  single source of truth) — and `PA-0018`'s own sweep never named `compose.yaml`'s service
  list as that source of truth to check the helper against.

**Why prevention did not hold (summary):** `PA-0018` fixed *where* self-heal must run but
not *how its own trigger is detected* or *how its own data stays in sync with the compose
file it exists to clean up after* — both gaps are new failure modes of the same
"self-heal must actually happen" class, not restatements of `PA-0018`'s own scope.

## Corrective action

`lab/labctl.sh` (Lane 7 Gate F commit):
1. `_force_clean()`'s container list now includes all 13 `pff-lab_*_1` containers
   (the 3 pre-existing plus the 10 Lane 7 app containers) and its network-removal loop
   now includes all 10 Lane 7 dedicated networks alongside `pff-lab_default`.
2. `down`'s case block no longer trusts `podman compose down`'s exit code: it runs
   `"${COMPOSE[@]}" down || true` unconditionally, then checks real post-state
   (`podman ps -a --format '{{.Names}}' | grep -q '^pff-lab_'`) and only then calls
   `_force_clean keep-volume` if anything is actually still present.

Verified live: `PFF_PROFILE=apps ./labctl.sh down` on the wedged stack this bug produced
now force-clears every container and network (`podman ps -a` / `podman network ls` show
nothing `pff-lab_*` left afterward); a `down` run against an already-clean stack stays a
no-op (no spurious force-clean).

## Sweep (PA-0002)

Enumerated every `_force_clean`/exit-code-trusting call site in `lab/labctl.sh` (the same
three subcommands `BUG-0017`'s own sweep enumerated: `up`, `reset`, `down`):
- `up`: already checks `_force_clean`'s own trigger via `if ! ... up -d --build`, whose
  failure mode (a real build/start failure) does propagate through Compose's exit code
  reliably (confirmed: unlike `down`'s dependent-removal-ordering failure, a build or
  boot failure is a hard, unambiguous non-zero exit in every case exercised in Gates
  D–F) — left unchanged, not a case of this same defect.
- `reset`: already ignores `down -v`'s exit code entirely (`|| true`) and unconditionally
  force-cleans before recreating — never trusted the exit code in the first place, so it
  was not exposed to this specific failure mode. Its own `_force_clean` calls now benefit
  from the completed container/network lists above.
- `down`: fixed, as above.
No other script in this repo wraps `podman compose down`/`up`/`reset` independently of
`labctl.sh` (confirmed by grepping `scripts/` and `docs/ON_HOST_RUNBOOK.md`, matching
`BUG-0017`'s own sweep finding for `greybox_e2e.sh`, unchanged since).

## Preventive action

`PA-0059` (see `docs/PREVENTIVE_ACTIONS.md`) — supersedes/strengthens `PA-0018` on the two
gaps above: (1) a container-lifecycle operation's self-heal trigger must check real
post-state, never trust the wrapped compose command's own exit code alone; (2) a shared
self-heal helper's own resource-name data must be swept and updated in the same change
that adds/removes a compose service, and is flagged as a candidate to derive from
`compose.yaml` directly rather than hand-list, the next time this file is touched for that
reason.
