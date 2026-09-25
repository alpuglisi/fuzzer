# BUG-0058 — Unqualified base-image names hang `podman-compose ... --build` (Gate D Dockerfiles)

- Date: 2026-09-25
- Status: fixed
- Severity: medium (blocks the whole `apps`-profile build non-interactively; the process
  never errors, it just hangs forever)

## Description

`PFF_PROFILE=apps ./labctl.sh up` (a non-interactive `podman-compose ... --build`) hung
indefinitely partway through the build, after printing `Please select an image:` for
several base images (`composer:2`, `maven:3.9-eclipse-temurin-21`,
`ruby:3.3.6-bookworm`, and others pulled by the Lane 7 Gate D Dockerfiles).

## Where encountered

On-host (podman-compose, no docker daemon), live-running the full `apps`-profile build
after Lane 7 Gates D-G were reported complete.

## What it caused to fail

The build never completed and never failed either — no error, no non-zero exit, just an
indefinite hang, because the process was blocked waiting on stdin for an interactive
answer to a prompt that a non-interactive `--build` run can never provide.

## What the bug was identified to be

Every Lane 7 Gate D Dockerfile (`lab/web*.Dockerfile`) and the pre-existing
`fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile`, plus `lab/compose.yaml`'s
own `mariadb`/`nginx` `image:` entries, referenced base images by short name only
(`ruby:3.3.6-bookworm`, `maven:3.9-eclipse-temurin-21`, `composer:2`, `php:8.3-apache-bookworm`,
`python:3.12-slim`, `golang:1.22-bookworm`, `debian:bookworm-slim`, `eclipse-temurin:21-jre`,
`node@sha256:...`, `mariadb:11.4`, `nginx:1.27`) with no registry component. Podman's
short-name resolution (`containers-registries.conf(5)`) prompts interactively
(`Please select an image:`) to disambiguate a short name whenever more than one
unqualified-search registry is configured on the host — a configuration this host has,
which docker (with its single implicit `docker.io` default) never exercises. That prompt
is why these Dockerfiles built fine under `docker build` in prior testing but hung under
`podman-compose ... --build` here.

## Root cause analysis

Five Whys:
1. Why did the build hang? A `podman pull` triggered by an unqualified `FROM`/
   `COPY --from=`/`image:` reference blocked on an interactive prompt.
2. Why did it prompt? More than one unqualified-search registry is configured for
   Podman on this host, so short-name resolution is ambiguous and Podman asks rather
   than guessing.
3. Why weren't these images qualified already? Gate D's Dockerfiles were authored and
   validated primarily against `docker build` semantics (per the handoff document this
   lane worked from), where short names resolve silently against the single implicit
   `docker.io` registry — the ambiguity Podman's multi-registry config exposes simply
   does not exist under Docker, so the gap was invisible until a real multi-registry
   Podman host ran the build.
4. Why did prior Gate D/E verification not catch this? Verification in the cloud sandbox
   (Gates A-C) had no working Docker daemon at all (a different, already-flagged
   limitation), and the handoff document itself was authored without ever running an
   actual Podman build — the first real build against this exact host's registry
   configuration was this live `apps`-profile boot.
5. Why is this a systemic gap, not a one-off? None of the 8 base images pulled across
   the 7 `lab/web*.Dockerfile` files (plus the pre-existing node_express scaffold and
   compose.yaml's `mariadb`/`nginx`) were fully qualified — this was the default
   authoring style throughout the lab's Dockerfiles, not an isolated typo.

**Root cause:** the Dockerfiles were written and validated under Docker-build
assumptions (implicit single-registry short-name resolution) without accounting for
Podman's multi-registry short-name-resolution behavior, which this project's own README
explicitly treats as a supported, tested runtime (`docker compose`/`podman compose`/
`podman-compose` are all documented as interchangeable in `lab/labctl.sh`'s own header
comment).

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. No prior bug in this class
(Docker-vs-Podman image-name-resolution divergence) was found; the closest related
entries (`BUG-0013`/`BUG-0017`/`BUG-0057`) are all about podman-compose container
lifecycle/self-heal, a different mechanism, not image resolution. This is a new bug
class, not a recurrence.

## Corrective action

Fully qualified every base-image reference with an explicit `docker.io/library/`
registry prefix, removing the ambiguity Podman's short-name resolution needs a human to
resolve:
- `lab/web.Dockerfile`, `lab/web-django.Dockerfile`, `lab/web-go.Dockerfile`,
  `lab/web-node.Dockerfile`, `lab/web-rails.Dockerfile`, `lab/web-spring.Dockerfile`,
  `lab/web-fastapi.Dockerfile`: every `FROM`/`COPY --from=<image>` short name qualified
  (`python:3.12-slim` -> `docker.io/library/python:3.12-slim`, `composer:2` ->
  `docker.io/library/composer:2`, etc.; `COPY --from=gen`/`--from=build` build-stage
  references are untouched, since those name build stages, not images).
- `fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile`: its own pinned
  `node@sha256:...` reference qualified the same way.
- `lab/compose.yaml`: `db`'s `mariadb:11.4` and `frontend`'s `nginx:1.27` `image:`
  entries qualified the same way (same short-name-prompt exposure on `up`/`pull`).

Verified offline: `grep -nE '^\s*FROM |COPY --from=' lab/web*.Dockerfile` shows every
entry now carries a `docker.io/` prefix (except build-stage `--from=gen`/`--from=build`
references, which are correctly left alone). Live re-verification of the previously-hung
`PFF_PROFILE=apps ./labctl.sh up` against this exact host's Podman config is the
caller's own follow-up (this fix was made and offline-verified in a sandbox with no
working Podman/Docker daemon, matching this lane's own established split between
sandbox-buildable and real-host-verified work).

## Sweep (PA-0002)

Grepped every `FROM`/`COPY --from=<image>`/compose `image:` line in the repository
(`lab/*.Dockerfile`, `fuzzlab/**/scaffold/Dockerfile`, `lab/compose.yaml`) for a short
name lacking a registry component. All instances found are listed under Corrective
Action above and fixed in the same change; none were left unqualified except deliberate
build-stage references (`--from=gen`, `--from=build`), which are not image pulls.
`.claude/worktrees/*` copies (stale agent worktree checkouts, not part of the tracked
source tree this bug's sweep covers) were not touched.

## Preventive action

`PA-0060` (see `docs/PREVENTIVE_ACTIONS.md`).
