# Lane 7 handoff: Gates D–G (needs real Docker/Podman)

**Read this whole document before starting. It is self-contained, but the
full design rationale lives in `docs/LAB_LANE7_INTEGRATION_PLAN.md` (the
reviewed, 3/3-converged plan) — read that too, especially §2 (Design), §3
(risk register S1–S17), §5 (this same Gate A–G sequence), and §6
(Deliverables). This document tells you what to *do*; the plan tells you
*why*. If anything here conflicts with the plan, the plan wins — fix this
document to match and mention the discrepancy in your final report.**

## Why this handoff exists

Lane 7 ("Browsable Labs" integration — `CC-LAB-0247`, `FR-LAB-170`-`171`)
is being built gate by gate (§5 of the plan). Gates A–C are done, committed,
and pushed:

- **Gate A**: the `go_net_http` S7 digit-check blind-spot decision (deferred,
  tracked follow-up — see plan §3.S13) and the shared-strict-xfail-sentinel
  rule added to `docs/MULTI_AGENT_ORCHESTRATION.md` §6.
- **Gate B**: `assemble_django_app`/`assemble_go_net_http_app`/
  `assemble_ruby_rails_app` (mirroring `assemble_spring_boot_app`), each
  with a dual-path proof test in `tests/test_lab_lane7_assemble_functions.py`.
- **Gate C**: the absent-input vocabulary reconciliation
  (`fuzzlab/labgen/absent_input.py`, `go_net_http`'s route table renamed
  onto the shared core), plus the S15 cross-emitter check now validating
  real membership.

Gates D, E, and F need a **real, running Docker (or Podman) daemon** to
build and boot containers — something the cloud sandbox that built Gates
A–C does not have (`docker` CLI is present there but the daemon cannot
start: `ulimit -Hn 524288` fails with "Operation not permitted", a sandbox
restriction with no workaround found). That is why this document exists —
you're running on a real machine with real Docker/Podman, so you can finish
what that environment could not.

**Do not re-do Gates A–C.** Confirm they're present (see "Before you start"
below) and move straight to Gate D.

## Before you start

1. `git status` — should be clean. `git log --oneline -5` on
   `claude/trusting-noether-heon0n` should show, newest first: a commit
   titled "Lane 7 Gate C: absent-input vocabulary reconciliation...", then
   "Lane 7 Gate B: assemble_django_app...", then "Lane 7 Gate A: shared
   strict-xfail sentinel rule...". If you're on a different branch or these
   commits aren't there, `git fetch origin && git checkout claude/trusting-noether-heon0n && git pull` first.
2. Confirm Docker or Podman actually works here: `docker compose version`
   or `podman compose version` (or `docker-compose`/`podman-compose`) —
   whichever responds is your compose provider for the rest of this
   document. If none work, stop and fix that first; nothing below is
   possible without one.
3. Run the full non-slow suite once before touching anything, so you have a
   clean baseline: `python3 -m pytest tests/ -m "not slow" -q`. Expect
   **2584 passed, 8 skipped, 5 xfailed, 0 failed** (this is the Gate-C
   baseline; if your numbers differ, figure out why before proceeding —
   don't build on top of an unexplained baseline drift).
4. Read `docs/LAB_LANE7_INTEGRATION_PLAN.md` §2b/§2c/§2d/§2f/§2h/§2g and
   §3's S1–S17 now, if you haven't already. This document assumes you have.

## Verification discipline (do not skip)

This project's `CLAUDE.md` and `docs/MULTI_AGENT_ORCHESTRATION.md` are
non-negotiable. In particular:

- **Never bind a container port to `0.0.0.0`.** Always `127.0.0.1:<port>:<container-port>`.
  This is the single most important rule in this whole document.
- **Never commit a secret.** `SECRET_KEY_BASE` (Rails) and any other
  generated credential must be generated at container start, never baked
  into an image layer or written to any file this repo tracks.
- Every new offline test you add must actually run and pass before you
  commit. Every claim you make in a commit message or in your final report
  must be something you personally ran and observed, not something you
  assume will work.
- Run the full non-slow suite (`python3 -m pytest tests/ -m "not slow" -q`)
  after each gate and paste the real pass/fail counts into your commit
  message, the same way Gates A–C's own commits did (`git log` them for the
  exact style to match).
- Commit at the end of each gate (D, then E, then F, then G) — don't batch
  everything into one giant commit. This matches the established pattern
  for this whole Lane 7 effort and makes review/bisection possible.
- Push after each gate's commit: `git push origin claude/trusting-noether-heon0n`.
  **Also keep the other two branches in lockstep** (this has been done
  after every commit so far in this effort):
  `git push origin HEAD:refs/heads/main HEAD:refs/heads/claude/second-target-cat1-ecommerce`.
  Confirm before you start that `main` and `claude/second-target-cat1-ecommerce`
  are at the same commit as `claude/trusting-noether-heon0n` — they should
  be, from Gates A–C. If they've drifted, stop and figure out why before
  pushing more onto them blindly.

---

## Gate D — Dockerfiles

Goal: every stack gets a real, working, individually-built-and-booted
Dockerfile. Reference: plan §2b, risk S10.

### D1. `lab/web.Dockerfile` — add `ARG APP` passthrough

Today this file always builds the merged PFF app
(`python3 -m fuzzlab.labgen.assemble --out /app`, no app selection). Add an
`ARG APP` (default empty string) to the `gen` stage and pass it through to
`assemble.py`'s existing `--app` flag when set:

```dockerfile
FROM python:3.12-slim AS gen
ARG APP=""
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -m fuzzlab.labgen.assemble --out /app $( [ -n "$APP" ] && echo "--app $APP" )
```

(Adjust the shell conditional to whatever's cleanest — the point is: `APP`
unset or empty ⇒ today's exact behavior, unchanged; `APP=circlefeed` (or
`huddlehub`/`booking`) ⇒ that split app.) Verify: build the image twice,
once with no `--build-arg APP` (must produce the same PFF app as today —
diff a couple of key files or just boot it and hit `/` for a 200) and once
with `--build-arg APP=circlefeed` (must produce CircleFeed's app instead —
boot it and confirm `/` shows CircleFeed's homepage, not PFF's).

### D2. Four new Dockerfiles

One per remaining stack, each a two-stage build (a `gen` stage running that
stack's `assemble_<stack>_app` function, then a real-runtime stage),
following `lab/web.Dockerfile`'s own shape. Concrete details for each,
gathered from this repo's own live-boot harnesses (`fuzzlab/labgen/conformance/*_live_boot.py`)
so you don't have to re-derive them:

**`lab/web-django.Dockerfile`** (PicTrail):
- `gen` stage: `python:3.12-slim`, `pip install -e .`, then call
  `assemble_django_app` (write a tiny inline `python3 -c "..."` invocation,
  or a small script under `lab/` — your call) to produce `/app`.
- Real stage: `python:3.12-slim` (or reuse the same base), `pip install django==5.2.17`
  (the pinned version — see `fuzzlab/labgen/conformance/django_live_boot.py`'s
  `DJANGO_PIN`), copy `/app` in, `python manage.py migrate`, then
  `CMD ["python", "manage.py", "runserver", "127.0.0.1:8000"]` — **bind to
  127.0.0.1 explicitly inside the container too**, not `0.0.0.0` (the
  skeleton's own `entrypoint_cmd` may default to `0.0.0.0`; force it, the
  same way `DjangoLiveBootHarness.build()`'s own docstring says it does).
  `EXPOSE 8000`.
- The database is SQLite (a file, `db.sqlite3`) — no separate DB service
  needed. Seed data the same way `DjangoLiveBootHarness._seed_db()` does if
  you want the app to have realistic content, or leave it empty (a browsable
  app doesn't strictly need seed data to prove it boots and serves pages —
  your call, but note which you picked in your final report).

**`lab/web-go.Dockerfile`** (LoopCast):
- `gen` stage: `golang:1.22-bookworm` (matching `go.mod`'s `go 1.22`), call
  `assemble_go_net_http_app` (via a small Python invocation — this needs
  Python too, so either a multi-stage `python:3.12-slim` step feeding into
  the Go build stage, or install Python in the Go image; simplest is
  probably: a `python:3.12-slim` stage runs `assemble_go_net_http_app` to
  produce the Go source tree, then `COPY --from=that-stage /app /app` into
  a `golang:1.22-bookworm` stage that runs `go build -o server .`).
- Real stage: a minimal runtime (e.g. `debian:bookworm-slim`), copy the
  compiled `server` binary in, `EXPOSE 8080` (or whatever port env var the
  binary reads — check `go_live_boot.py`'s `proc_env["PORT"]` usage), run it
  bound to `127.0.0.1`.
- No database.

**`lab/web-spring.Dockerfile`** (TrackerNest/ReelQueue/WanderFare):
- Also takes an `ARG APP` (one of `trackernest`/`reelqueue`/`wanderfare`,
  no default — this one should probably require it, since there's no
  single "default" spring_boot app the way PFF is php_laravel's default).
- `gen` stage: `python:3.12-slim` runs `assemble_spring_boot_app(app_key, "/app")`
  to produce the Java source tree.
- Build stage: `maven:3.9-eclipse-temurin-21` (Java 21, per the skeleton's
  `pom.xml` `<java.version>21</java.version>`), `COPY --from=gen /app /app`,
  `mvn -B package -DskipTests` inside `/app`.
- Real stage: `eclipse-temurin:21-jre` (or `-jre-jammy`/similar slim JRE
  image), copy the built jar in, `CMD ["java", "-jar", "app.jar", "--server.port=8080"]`
  bound to loopback via Spring's own `server.address=127.0.0.1` property
  (add it to the jar's run command or an `application.properties` override
  — check how `live_boot_spring_boot.py`'s `build()` forces this, if it
  does, and mirror it exactly). `EXPOSE 8080`.
- No database.

**`lab/web-rails.Dockerfile`** (ForgeCart):
- `gen` stage: `python:3.12-slim` runs `assemble_ruby_rails_app` to produce
  the Rails app tree.
- Real stage: `ruby:3.3.6-bookworm` (or `-slim`) — matches the skeleton's
  `.ruby-version`. `COPY --from=gen /app /app`, `WORKDIR /app`,
  `bundle install`, then an **entrypoint script** (not baked-in
  `CMD`/`ENV`) that:
  1. Generates `SECRET_KEY_BASE` fresh every container start if not already
     set: `export SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(bin/rails secret)}"`
     — **never write this to a file the image or the repo persists, never
     hardcode a literal value** (plan §2h, D12). A `docker-entrypoint.sh`
     that does this and then `exec`s `bin/rails server -b 127.0.0.1` is the
     right shape.
  2. Sets `RAILS_ENV=production`.
  3. Runs `bin/rails db:prepare` (creates/migrates the per-container SQLite
     DB) before serving.
  - Verify ForgeCart genuinely needs no `assets:precompile` step before
    committing to skip it (plan §2f says it shouldn't, since the skeleton
    uses Propshaft with an almost-empty manifest — confirm this live by
    booting once and checking for asset-related errors in the server log,
    don't just trust the plan's own note without a live check).
  `EXPOSE 3000` (Rails' default) or whatever port you pick — just be
  consistent with the port table below.

### D3. Wire in the two existing scaffold Dockerfiles

`fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile` and
`fuzzlab/labgen/emitters/python_fastapi/templates/scaffold/Dockerfile.j2`
already exist but were **never built or booted** (plan risk S10 — written
speculatively). Copy (or symlink, your call) them into `lab/` as
`lab/web-node.Dockerfile` and `lab/web-fastapi.Dockerfile` (the FastAPI one
needs its Jinja placeholders (`{{ base_image }}`, `{{ workdir }}`,
`{{ entrypoint_cmd_json }}`) resolved to real values first — check
`fuzzlab/labgen/emitters/python_fastapi/__init__.py` for how the emitter
itself renders this template, and reuse that rendering rather than
hand-filling the placeholders). `node_express`'s Dockerfile already sets
`NODE_ENV=production` and binds nothing itself (the app code binds
`127.0.0.1` per `app.js`'s own `app.listen(port, '127.0.0.1')`) — no
changes needed there beyond verifying it actually builds and boots.

**The `python_fastapi` generic sample has no app identity and no reserved
port** (plan §1, confirmed in `docs/LAB_BROWSABLE_APPS_PLAN.md`'s own port
table). Build and boot its Dockerfile to prove it works (S10 still applies),
but **do not add it to `lab/compose.yaml` in Gate E** — it stays
un-containerized-by-default until it has a real identity, per the plan.

### D4. Verify every Dockerfile individually (S10 — do not skip)

For each of the 6 Dockerfiles (the amended `web.Dockerfile`, plus
`web-django`/`web-go`/`web-spring`/`web-rails`/`web-node`; `web-fastapi`
gets built-and-booted too per D3 but isn't wired into compose):

```
docker build -f lab/web-<stack>.Dockerfile -t fuzzlab-lab-<stack>-test .
docker run --rm -p 127.0.0.1:<some-free-port>:<container-port> fuzzlab-lab-<stack>-test
# in another shell: curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<some-free-port>/
# expect 200 (or the app's own correct anonymous-visitor status for `/`)
docker stop <container>
```

Record each stack's result (pass/fail, and the exact command you ran) —
this becomes part of Gate G's change-control entry. If a build or boot
fails, **fix it now, in Gate D** — don't carry a broken Dockerfile into
Gate E's compose wiring.

Commit Gate D:
```
git add lab/web.Dockerfile lab/web-django.Dockerfile lab/web-go.Dockerfile \
        lab/web-spring.Dockerfile lab/web-rails.Dockerfile lab/web-node.Dockerfile \
        lab/web-fastapi.Dockerfile <any entrypoint scripts you added>
git commit -m "Lane 7 Gate D: Dockerfiles for django/go_net_http/spring_boot/ruby_rails + wire node_express/python_fastapi scaffolds

<your own summary of what you verified live, with real build/boot results per stack>

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin claude/trusting-noether-heon0n
git push origin HEAD:refs/heads/main HEAD:refs/heads/claude/second-target-cat1-ecommerce
```

---

## Gate E — compose.yaml + labctl + SECRET_KEY_BASE

Reference: plan §2c, §2h, risks S3/S5/S15/S17.

### E1. Port table (already decided, do not invent new numbers)

| App | Stack | Port | Compose service name (suggested) |
|---|---|---|---|
| CircleFeed | php_laravel | 8082 | `circlefeed` |
| Huddle Hub | php_laravel | 8083 | `huddlehub` |
| Booking clone | php_laravel | 8084 | `booking` |
| PicTrail | django | 8085 | `pictrail` |
| LoopCast | go_net_http | 8086 | `loopcast` |
| TrackerNest | spring_boot | 8087 | `trackernest` |
| ReelQueue | spring_boot | 8088 | `reelqueue` |
| WanderFare | spring_boot | 8089 | `wanderfare` |
| ForgeCart | ruby_rails | 8090 | `forgecart` |
| MeadowMart | node_express | 8091 | `meadowmart` |

(8080 = PFF, unchanged; 8081 = the existing `desync` frontend, unchanged.
`python_fastapi`'s sample gets **no** compose service, per D3 above.)

### E2. Add the 10 services to `lab/compose.yaml`

Each new service:
- `profiles: ["apps"]` (matches the already-decided convention stated in
  `docs/LAB_BROWSABLE_APPS_PLAN.md`'s "Apps and serving" section).
- `build:` pointing at the repo root context and the right Dockerfile
  (`lab/web.Dockerfile` with `build.args.APP` set for CircleFeed/Huddle
  Hub/Booking; `lab/web-spring.Dockerfile` with `build.args.APP` for the 3
  spring_boot apps; the stack-specific Dockerfile for the other 4).
- `ports: ["127.0.0.1:${<APPNAME>_WEB_PORT:-<port>}:<container-port>"]` —
  **loopback only**, one env var per app following `PFF_WEB_PORT`'s naming
  (e.g. `CIRCLEFEED_WEB_PORT`, `PICTRAIL_WEB_PORT`, ...).
- `networks:` — **its own dedicated network, one per service, not the
  project's implicit default network** (plan §2c/S17: a real SSRF exists in
  this lab, ReelQueue's `/api/content/thumbnail-import`, so apps must not be
  able to reach each other by service-name DNS even though every host port
  is loopback-only). Something like:
  ```yaml
  services:
    circlefeed:
      # ...
      networks: [circlefeed-net]
    # ... one networks: [<name>-net] per new service, each a distinct name
  networks:
    circlefeed-net: {}
    huddlehub-net: {}
    booking-net: {}
    pictrail-net: {}
    loopcast-net: {}
    trackernest-net: {}
    reelqueue-net: {}
    wanderfare-net: {}
    forgecart-net: {}
    meadowmart-net: {}
  ```
  **Do not add a `networks:` key to the existing `db`/`web`/`frontend`
  services** — they have none today and must keep using the implicit
  default network unchanged (a compose service with an explicit `networks:`
  key stops auto-joining the default network rather than joining both, so
  this is sufficient by itself — no other change needed to isolate them).
- `environment:` — `RAILS_ENV=production` for `forgecart`,
  `NODE_ENV=production` for `meadowmart` (already baked into its
  Dockerfile per D3, but setting it here too is harmless and explicit);
  ForgeCart's `SECRET_KEY_BASE` should come from the entrypoint script you
  wrote in D2, not from a compose `environment:` literal — do not put a
  secret value in `compose.yaml` itself.
- No `depends_on: db` on any of the 10 (none needs PFF's MariaDB).

Verify with `docker compose config` (or your compose provider's equivalent)
that the file parses and the rendered config shows each new service on its
own network, never the default one, and every port bound to `127.0.0.1`.
Write a small offline test for this if one doesn't already exist —
`tests/test_lab_compose_network_isolation.py` or similar: parse
`lab/compose.yaml` as YAML, assert every service (existing and new) either
has no `networks:` key (the 3 original ones) or has exactly one, distinct,
per-service network (the 10 new ones), and assert every `ports:` entry
starts with `127.0.0.1:`.

### E3. `lab/labctl.sh` — multi-profile support

Today `PROFILE_ARGS=(--profile "${PFF_PROFILE}")` supports exactly one
value. Change it to split `PFF_PROFILE` on commas and emit one `--profile`
flag per entry:

```bash
PROFILE_ARGS=()
if [ -n "${PFF_PROFILE:-}" ]; then
  IFS=',' read -ra _profiles <<< "$PFF_PROFILE"
  for p in "${_profiles[@]}"; do
    PROFILE_ARGS+=(--profile "$p")
  done
fi
```

Verify both forms still work: `PFF_PROFILE=desync ./labctl.sh up` (today's
existing single-value case, must be unchanged) and
`PFF_PROFILE=apps,desync ./labctl.sh up` (the new combined case). A quick
offline test of just the splitting logic (extract it to a testable function,
or test the rendered `COMPOSE` invocation via a dry-run flag) is better than
only a live check — plan risk S5.

Commit Gate E:
```
git add lab/compose.yaml lab/labctl.sh <your new offline test(s)>
git commit -m "Lane 7 Gate E: compose services for all 10 apps + labctl multi-profile + per-app network isolation

<real docker compose config verification results, real offline test results>

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin claude/trusting-noether-heon0n
git push origin HEAD:refs/heads/main HEAD:refs/heads/claude/second-target-cat1-ecommerce
```

---

## Gate F — the manual full-profile boot + the cross-app navigability run

Reference: plan §2d, §4, risks S4/S16/S17.

### F1. The one required manual full-profile boot

```
PFF_PROFILE=apps ./labctl.sh up
docker compose ps    # or your provider's equivalent — confirm all 11 services (PFF + 10 new) are up and healthy/running
```

For each of the 10 new apps, `curl` its `/` and confirm the expected
anonymous-visitor status (200 for all of them — none of these apps gate `/`
behind auth). Then:

- **S16 (resource contention)**: measure the combined memory/CPU footprint
  while all 11 are running (`docker stats --no-stream`, or your provider's
  equivalent). Record the numbers. If anything is clearly starved or
  crash-looping, that's a real finding — decide whether a per-service
  `mem_limit`/`deploy.resources.limits` is needed based on what you
  actually measure, not a guess.
- **S17 (network isolation)**: from inside one app's container (e.g.
  `docker compose exec circlefeed sh` or equivalent), try to reach another
  app's container by its compose service name and port (e.g.
  `curl http://pictrail:8000/` from inside `circlefeed`'s container) —
  **this must fail** (name resolution failure or connection refused,
  since they're on disjoint networks). If it succeeds, Gate E's network
  isolation didn't actually take effect — go back and fix it before
  proceeding.
- Confirm ForgeCart's `SECRET_KEY_BASE` is actually different across two
  separate `up`/`down` cycles (proving it's genuinely ephemeral, not
  accidentally cached/persisted): `docker compose exec forgecart env | grep SECRET_KEY_BASE`,
  then `docker compose restart forgecart` and check again — the two values
  should differ.

Once verified, `PFF_PROFILE=apps ./labctl.sh down` (or leave it running if
you want to keep testing — your call, just don't leave it running
unattended past your session).

### F2. The automated cross-app navigability run

Per the plan's own R2 recommendation (already decided, not open): this
does **not** need a real compose boot — it reuses each stack's own
in-process/subprocess live-boot harness (the same ones each stack's own
navigability live-boot test already uses), orchestrated into one combined
run. Write `tests/test_lab_cross_app_navigability.py`:

- For each of the 6 stacks with a real app identity (php_laravel's 4 apps,
  django, go_net_http, spring_boot's 3 apps, ruby_rails, node_express — 10
  apps total, same list as the port table minus the fastapi sample), boot
  it via that stack's own harness (`LiveBootHarness`/`DjangoLiveBootHarness`/
  `GoLiveBootHarness`/`SpringBootLiveBootHarness`/`RailsLiveBootHarness`;
  `node_express` — check whether it has a harness under
  `fuzzlab/labgen/conformance/`; if not, mirror how
  `tests/test_labgen_node_meadowmart_navigability_live_boot.py` boots it
  and reuse that).
- Run each app's own already-existing navigability test's own crawl logic
  against it (import and call the same fixture/helper each stack's own
  `test_labgen_<stack>_navigability_live_boot.py` uses — do not re-derive
  crawl logic, PA-0002's "derive, never hand-maintain a second mechanism").
- Report one combined pass/fail plus a per-app summary table (print it,
  or write it to a file — your call).
- Mark it `@pytest.mark.slow` and skip-guard each stack's own row the same
  way that stack's own live-boot suite already does (a host missing e.g.
  `java`+`mvn` skips only that row, not the whole run).

Run it for real: `python3 -m pytest tests/test_lab_cross_app_navigability.py -v`.
Every non-skipped row must pass. Record the real output in your commit
message.

Commit Gate F:
```
git add tests/test_lab_cross_app_navigability.py
git commit -m "Lane 7 Gate F: full-profile boot verified live (resource/network isolation confirmed) + cross-app navigability run

<real docker stats numbers, real network-isolation probe result, real
SECRET_KEY_BASE rotation confirmation, real pytest output for the new
cross-app navigability test>

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin claude/trusting-noether-heon0n
git push origin HEAD:refs/heads/main HEAD:refs/heads/claude/second-target-cat1-ecommerce
```

---

## Gate G — docs and bookkeeping

Reference: plan §2g, §6 (Deliverables), and **`CLAUDE.md`'s "Definition of
done" checklist — read it now if you haven't, this gate is where it all
gets paid off.**

1. **Runbook.** Add a section to `docs/ON_HOST_RUNBOOK.md` (or a new
   `docs/LAB_MULTI_APP_RUNBOOK.md`, your call — the plan left this open)
   covering: `PFF_PROFILE=apps ./labctl.sh up`, the port table (copied from
   `docs/LAB_BROWSABLE_APPS_PLAN.md`, kept in sync — one source of truth),
   the expected resource footprint (your real F1 measurements), the
   per-app network-isolation posture, and how to run the cross-app
   navigability check both ways (the in-process pytest module, and
   manually against a real running stack via `curl`).

2. **`docs/ARCHITECTURE.md`.** One new paragraph (matching every earlier
   lane's own precedent — read a couple of the existing ones, e.g. the
   PicTrail/LoopCast/TrackerNest paragraphs, for the expected tone and
   level of detail) naming: the 10 new compose services + per-app network
   isolation, the vocabulary reconciliation (Gate C, already committed —
   confirm your ARCHITECTURE.md paragraph mentions it even though the code
   landed earlier), and the cross-app navigability run.

3. **`docs/components/01-target-lab/requirements.md`.** Add `FR-LAB-170`
   (the compose/labctl/runbook integration — cite every Dockerfile, the
   network-isolation design, the resource findings) and `FR-LAB-171` (the
   absent-input vocabulary contract — cite `fuzzlab/labgen/absent_input.py`,
   the `go_net_http` rename, and the S15 membership check). Follow the
   exact format of the existing `FR-LAB-164`/`165` entries (Lane 4's own,
   right above where these should go) as your template.

4. **`docs/LAB_BROWSABLE_APPS_PLAN.md`.** Update Lane 7's own row (currently
   just "Integration: compose services + ports + `labctl` profile, runbook,
   cross-app navigability run, ARCHITECTURE/requirements | 0247 | 170–171 |
   — | 0057 / 0059") to the completed, detailed style every other lane's row
   uses (see Lane 4's or Lane 5's row for the template — done date, what was
   built, what was found, bug numbers if any). Also fix the stale "Netflix
   clone"/"Expedia clone" naming in the "Apps and serving" port table to
   "ReelQueue"/"WanderFare" (plan S12 — a one-line fix, unrelated to
   everything else in this bullet, don't skip it just because it's small).

5. **`docs/components/01-target-lab/change-control.md`.** A full
   `CC-LAB-0247` entry, following the exact template every other lane's
   entry in this same file uses (Lane 4's `CC-LAB-0244` entry is the
   longest/most-recent full example — copy its section structure: Change,
   Impact, Risk register with every S-item, Deliverables checklist with
   every box ticked and what you actually did, Effectiveness section with
   your **real** measured numbers — suite counts, the F1 resource/network
   findings, the S9 before/after evidence note pointing back at Gate C's
   own commit since that already happened, the numbering check-back
   confirming `CC-LAB-0247`/`FR-LAB-170`-`171` sufficed and no other lane
   needed a bump).

6. **`CHANGELOG.md`.** One dated entry (newest on top, matching the format
   every existing entry uses) summarizing the whole Lane 7 effort — Gates
   A through G, referencing `CC-LAB-0247`.

7. **`docs/PREVENTIVE_ACTIONS.md` / `ERROR_LOG.md` / a `docs/bugs/BUG-0057-*.md`
   file** — **only if Gates D–F actually found a real code defect** (e.g. a
   Dockerfile that needed a real fix beyond "the first attempt didn't work
   syntactically", a genuine resource-starvation bug, a network-isolation
   bug). If nothing rose to the level of a real bug, say so explicitly in
   the change-control entry's Effectiveness section ("no defect found;
   `BUG-0057`/`PA-0059` unused") — do not force a bug report into existence
   to fill a slot, and do not silently skip mentioning that the numbers
   went unused either.

8. **Final full-suite run.** `python3 -m pytest tests/ -m "not slow" -q`
   one more time, plus every stack's own `slow` suite you touched, and
   record the final counts.

9. Final commit:
```
git add docs/ON_HOST_RUNBOOK.md docs/ARCHITECTURE.md \
        docs/components/01-target-lab/requirements.md \
        docs/components/01-target-lab/change-control.md \
        docs/LAB_BROWSABLE_APPS_PLAN.md CHANGELOG.md \
        <ERROR_LOG.md/docs/bugs/*/PREVENTIVE_ACTIONS.md if used>
git commit -m "Lane 7 Gate G: bookkeeping (CC-LAB-0247, FR-LAB-170/171, runbook, ARCHITECTURE)

Lane 7 (Browsable Labs integration) complete. <your own one-paragraph
summary + final suite counts>

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin claude/trusting-noether-heon0n
git push origin HEAD:refs/heads/main HEAD:refs/heads/claude/second-target-cat1-ecommerce
```

## When you're done

Report back (to whoever is reading your session's output) with:
- Confirmation all 4 gates (D, E, F, G) are committed and pushed to all 3
  branches, with their commit hashes.
- The real, final full-suite pass/fail counts.
- Anything from the plan's own open questions (§7: R1 test-file-vs-script
  placement — already decided as a `tests/` module above; R3/S13's
  go_net_http S7 decision — already decided as defer, done in Gate A) that
  you had to re-decide differently, and why.
- Any real defect found along the way, whether or not it rose to a formal
  `BUG-0057`.
- Anything in this document that turned out to be wrong once you had real
  Docker to check against — fix the document and say so, don't just
  silently do something different.
