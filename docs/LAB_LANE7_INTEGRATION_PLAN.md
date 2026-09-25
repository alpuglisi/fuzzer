# Lane 7 — Browsable Labs integration plan

Reserved bookkeeping (`docs/LAB_BROWSABLE_APPS_PLAN.md` row 7, PA-0031): `CC-LAB-0247`,
`FR-LAB-170`-`171`, `BUG-0057`/`PA-0059` (if a defect is found). No `CC-FUZZ`/`FR-FUZZ`
number is reserved and none is expected to be needed (this lane touches serving/packaging,
not detection).

Status: **converged 3/3, implementation authorized (2026-09-25)**. Round 1: ACCURATE WITH
CORRECTIONS (2 fixes) / ADEQUATE CONTINGENT ON 8 items -- all applied. Round 2: ACCURATE /
ADEQUATE CONTINGENT ON 3 items -- all applied. Round 3: ACCURATE / ADEQUATE, both reviewers
confirmed ready for implementation, no further items. See §8.

## §0. What Lanes 1-6 taught us, applied here from the start

- **Pre-assigned bookkeeping avoids merge friction** (PA-0031, every lane's own precedent):
  `CC-LAB-0247`/`FR-LAB-170`-`171`/`BUG-0057`/`PA-0059` are reserved above, not claimed
  ad hoc.
- **A cross-cutting fix that touches an already-merged lane needs before/after evidence,
  not just "still green"** (Lane 4's own S9-equivalent discipline for `BUG-0054`): the
  `go_net_http` vocabulary rename (2e) inherits this directly (S9).
- **"Flag, never silently build or skip"** (the multi-agent orchestration policy, applied
  by Lane 5 to ForgeCart's stale citations and by this lane to S13's `go_net_http` S7 gap
  and to the process-doc suggestion, §1 item 7): a lane's own reviewers, not the lane
  itself, get the final call on deferring something it notices but doesn't strictly own.
- **A strict-xfail marker shared across concurrent lanes' own cross-emitter checks
  resolves itself at merge time** (observed twice already: Lane 3/Lane 6 landing their own
  mechanisms concurrently with Lane 4, XPASSing Lane 4's own markers) -- worth codifying
  once rather than rediscovering a third time (§1 item 7, 2i).
- **A living port/identity table needs one source of truth** (Lane 4's own post-convergence
  ReelQueue/WanderFare rename left a stale table entry elsewhere, S12): this lane's own
  runbook explicitly copies from, and stays in sync with, `docs/LAB_BROWSABLE_APPS_PLAN.md`'s
  table rather than forking a second copy (2g).
- **A lab whose purpose is hosting real, exploitable sinks must reason about those sinks
  when changing its own network topology**, not just about the host-level loopback rule
  every earlier lane's own compose work already honored -- new for this lane specifically,
  since no earlier lane put multiple vulnerable apps on the same Docker network (S17).

## §1. Scope (live pre-scan, 2026-09-25)

Lanes 1-6 are merged into `claude/trusting-noether-heon0n`. Every app identity is now
browsable *as a live-boot-harness-managed test process*, but:

- Only Puppy Fort Factory is a real, standing container (`lab/compose.yaml`, port 8080).
- No other app has a Dockerfile, a compose service, a port, or a public "assemble the
  whole app to a real directory" function:
  - `php_laravel` already has one, at module level: `fuzzlab/labgen/assemble.py`'s
    `assemble_lab(out_dir, *, manifest_paths=None, emitter=None, app=None)`, with an
    `app=` key from `emitters.php_laravel.app_site.APP_REGISTRY`
    (`circlefeed`/`huddlehub`/`booking`, or `None` for the merged PFF build). Its CLI
    (`python -m fuzzlab.labgen.assemble --out DEST [--app ...]`) already supports app
    selection, but **`lab/web.Dockerfile`'s `gen` stage does not pass `--app` through
    today** -- verified directly (round-1 accuracy correction): the file contains no
    `ARG` and no `--app` flag anywhere; it always builds the merged PFF app. There is
    also no Dockerfile yet, of any shape, for CircleFeed/Huddle Hub/Booking. This is
    real, uncredited scope this lane must add (§2b), not an existing precedent to mirror.
  - `spring_boot` already has one, at emitter level (Lane 4, `CC-LAB-0244`):
    `assemble_spring_boot_app(app_key, dest)` in `fuzzlab/labgen/emitters/spring_boot/__init__.py`,
    built specifically for this lane. It writes a source tree only (`mvn package`/`java -jar`
    still needed at container-build time).
  - `django`, `go_net_http`, `ruby_rails` have **no such function**. Each stack's own
    live-boot harness (`fuzzlab/labgen/conformance/{django,go,rails}_live_boot.py`) has a
    private `_assemble()`-equivalent that writes a real app tree into a temp dir before
    booting it for a test -- this lane lifts each into a public function, the same move
    Lane 4 made for `spring_boot`, never duplicating the logic.
  - `node_express` and `python_fastapi` already carry checked-in scaffold Dockerfiles
    (`fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile`,
    `fuzzlab/labgen/emitters/python_fastapi/templates/scaffold/Dockerfile.j2`), neither
    wired into any compose file yet. Neither needs a new "assemble" function: `app.js`
    already honors a `PORT` env var and binds `127.0.0.1` (per
    `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md`).
- Each stack's live-boot harness proves what a real server process for that stack needs:

  | Stack | Runtime | Boot | Datastore |
  |---|---|---|---|
  | php_laravel | PHP 8.3 + Composer | `php artisan serve` | MariaDB (compose already has it) |
  | django | Python | dev-server-style | SQLite (`db.sqlite3`) |
  | go_net_http | Go | plain binary | none |
  | spring_boot | Java + Maven | `java -jar` | none |
  | ruby_rails | Ruby + Bundler + Rails | `bin/rails server` | per-run SQLite |
  | node_express | Node 22 | `node app.js` | none |
  | python_fastapi | Python + uvicorn | templated `CMD` | none |

  None of the five non-PFF, non-`python_fastapi` app identities needs a *shared* database
  server the way PFF does; SQLite is a file, so it needs no separate compose service.
- The port table and the `PFF_PROFILE=apps` compose-profile convention are already decided
  (`docs/LAB_BROWSABLE_APPS_PLAN.md`, "Apps and serving"): every real app identity except
  the `python_fastapi` sample (explicitly "no identity ... no port") gets 8082-8091.
  **Naming note:** that table still says "Netflix clone"/"Expedia clone"; this lane's own
  compose/doc text uses the current names, ReelQueue/WanderFare (post-convergence rename,
  `CC-LAB-0244`), and the table itself gets a one-line fix (S12, below).
- Seven things are explicitly flagged to this lane, because no earlier lane owns them
  (each citation verified directly against its source file, not from memory; two
  corrected from round-1's original misattribution):
  1. **Absent-input vocabulary reconciliation** (`docs/bugs/BUG-0056-*.md`, "the
     vocabulary is fragmented... different value spellings," and its own "flagged to
     Lane 7" line; `PA-0058` rule 2 -- **not** `PA-0056`, which is about enforcement
     precision (own-method sweep, every input channel), never vocabulary; round-1
     accuracy correction applied): Lane 3 (`go_net_http`) and Lane 4 (`spring_boot`)
     independently spelled their `absent_input` values (`required_400` vs.
     `required_param`, etc.). Unify into one closed, cross-emitter value set.
  2. **Lane 4's own S15 cross-emitter check must validate membership**, not merely
     presence, against that unified set (`PA-0058` rule 2's own unmet half).
  3. **`node_express`'s production-mode serving decision** (`docs/bugs/BUG-0055-*.md`:
     "left to Lane 7, which PA-0057's check keeps honest") -- its 3 test-time
     `node app.js` launches don't set `NODE_ENV=production` (pinned by a strict xfail,
     `test_every_test_time_node_launch_sets_production`); a real compose service must
     actually run production mode.
  4. **`ruby_rails`'s production-mode serving decision** (`docs/LAB_LANE5_RUBY_RAILS_FORGECART_PLAN.md`:
     "Both [compose/port wiring and the `RAILS_ENV=production` choice] are Lane 7, which
     must keep `PA-0057`'s check green").
  5. **F1/F2/F4** (`docs/LAB_BROWSABLE_APPS_PLAN.md` row 6): `/api/profile`'s `currentUser`
     undefined (MeadowMart); async handlers exit the process on a rejected DB call
     (`node_express`/`python_fastapi`); the generated FastAPI `requirements.txt` lacks
     `python-multipart`. F1/F2 are **already pinned** by strict xfails (a different defect
     class from this lane's own scope, per the same discipline every earlier lane used for
     its own flagged, not-fixed follow-ups) -- this lane does not have to fix them, only
     decide, and record, whether either blocks compose/production serving (it does not:
     neither is exercised by a bare boot).
  6. **Lane 3's own go_net_http S7 digit-check blind spot** (identified during Lane 4's own
     work, never reported or fixed, and confirmed live in round-1 review -- not merely
     hypothetical: `site.go:18-29`'s CSS is a Go backtick raw string literal containing a
     genuine, currently-undetected `max-width:100%` 3-digit run; both Lane 3's and Lane
     4's own S7 tests use a double-quote-only regex that never matches it) -- flagged
     here for a decision, not silently fixed or silently skipped (per the multi-agent
     orchestration policy's "flag, never silently build or skip" rule). See S13 below.
  7. **A process-doc suggestion from Lane 4's own round-2 adequacy review** (non-blocking
     there, deferred to this lane): codify in `docs/MULTI_AGENT_ORCHESTRATION.md` the
     rule this project has already applied ad hoc at least twice (Lane 3/Lane 6's own
     shared strict-xfail sentinels) -- "a shared strict-xfail sentinel file: the lane
     that lands the fix deletes its own marker." **Decision:** do it. It is a single,
     low-risk paragraph in an existing process doc, cheap enough that deferring it again
     would just repeat the same "flag instead of fixing something trivial" pattern this
     plan itself criticizes at S13. See 2h below.

**Not** flagged to this lane, and explicitly out of scope here: ForgeCart's 5 stale
`CC-LAB-0077`/`FR-LAB-81` comment citations (Lane 5's own plan recommends "the next free
CC-LAB after 0248" -- i.e. a lane after this one); any new detection/oracle work
(`CC-FUZZ`/`FR-FUZZ`, none reserved); building a login system for any split app (R8's own
accepted-risk decision stands).

## §2. Design

### 2a. Per-stack assemble functions (django, go_net_http, ruby_rails)

One function per emitter, named and shaped like `assemble_spring_boot_app` (a precedent,
not a coincidence -- Lane 4 built it exactly so this lane could copy the pattern):

```python
def assemble_<stack>_app(dest: str) -> None
```

No `app_key` parameter for these three (each stack has exactly one app identity today,
unlike `spring_boot`'s three or `php_laravel`'s four) -- `app_cells_for`-style filtering
is not needed. Each function:

1. Copies that stack's skeleton directory to `dest` (mirroring `assemble_spring_boot_app`'s
   `shutil.copytree`).
2. Loads every real cell for that stack from `lab/manifests/*.yaml` (PA-0027: derived, never
   hand-kept), renders each with the stack's own emitter, and writes the site layer
   (homepage/nav/catalog/client pages) already built by Lanes 2/3/5.
3. Is exercised by a new offline test asserting the written tree contains the expected
   file set (mirroring `test_site_layer_renders_deterministically`'s existing pattern),
   **and** by re-running that stack's own existing live-boot harness against the output of
   the new function (not just the harness's own private path) at least once, so the two
   code paths are proven to produce the same live-bootable result -- never assumed from
   the harness's own already-passing tests alone.

`node_express`/`python_fastapi` need no new function (§1); `php_laravel`/`spring_boot`
already have one.

### 2b. Dockerfiles

One Dockerfile per stack, each following `lab/web.Dockerfile`'s existing two-stage shape
(a `gen` stage, then a real-runtime stage) -- **this lane builds app selection into
`lab/web.Dockerfile` itself for the first time** (round-1 correction: no `--app`
passthrough exists there today):

- `lab/web.Dockerfile`: add an `ARG APP` (default empty, the current merged-PFF
  behavior unchanged when unset) passed through to `assemble.py`'s `--app` flag, so this
  one Dockerfile can build PFF, CircleFeed, Huddle Hub, or Booking depending on a
  compose-level `build.args.APP`. This is new work, credited honestly as such.
- `lab/web-django.Dockerfile`, `lab/web-go.Dockerfile`, `lab/web-spring.Dockerfile`,
  `lab/web-rails.Dockerfile`: new, one two-stage build each (a `gen` stage running the new
  `assemble_<stack>_app`/`assemble_spring_boot_app` function, then a stage with that
  stack's real runtime). `web-spring.Dockerfile` takes the same `ARG APP` treatment as
  `web.Dockerfile` (`trackernest`/`reelqueue`/`wanderfare`).
- `lab/web-node.Dockerfile` / `lab/web-fastapi.Dockerfile`: the two scaffold Dockerfiles
  already checked into each emitter (§1) are **the** Dockerfiles for these stacks --
  copied into `lab/`, not rewritten, unless a live-boot run shows they need a fix (S10
  below covers verifying this rather than assuming it).
- Every Dockerfile pins its base image the same way `lab/web.Dockerfile` does (a tagged,
  not `latest`, image), and every production stage sets that stack's own
  production-mode env var (`APP_ENV`/`RAILS_ENV=production`/`NODE_ENV=production`/
  Spring's default -- `no_debug_pages` already required repo-wide by `PA-0057`).

### 2c. compose.yaml + ports + labctl profile

- Add one service per real app identity to `lab/compose.yaml` (10 new services: CircleFeed,
  Huddle Hub, Booking, PicTrail, LoopCast, TrackerNest, ReelQueue, WanderFare, ForgeCart,
  MeadowMart), each:
  - `profiles: ["apps"]` (the already-decided convention, "Apps and serving");
  - loopback-only (`127.0.0.1:<port>:<container-port>`, never `0.0.0.0` -- CLAUDE.md's own
    non-negotiable safety rule);
  - its own env-var-overridable port, following `PFF_WEB_PORT`'s naming
    (`CIRCLEFEED_WEB_PORT`, `PICTRAIL_WEB_PORT`, ... defaulting to the reserved port table);
  - no `depends_on: db` (none of the 10 needs PFF's MariaDB; SQLite/no-DB stacks manage
    their own file-backed or no state);
  - **its own dedicated compose network, not the project's shared default network** (S17
    below) -- each app is otherwise fully self-contained, so no cross-app network path is
    needed, and one exists is a real risk in a lab whose whole purpose is hosting
    exploitable sinks (ReelQueue's `/api/content/thumbnail-import` is a real,
    live-verified SSRF: an `unchecked_url_fetch` on a caller-supplied URL). Compose's
    default same-project network would otherwise let that sink's fetch reach e.g.
    `http://picktrail:8000/` by service-name DNS even though every host port stays
    loopback-only -- host-level isolation alone does not close this. Mechanically: a
    compose service that declares its own `networks:` key stops auto-joining the
    project's implicit default network (it does not additionally join both), so PFF's
    own `db`/`web` services -- which declare no `networks:` key today -- keep using the
    implicit default network completely unchanged; only the 10 new services gain an
    explicit, per-app `networks:` key, which removes each one from the default network
    rather than adding a second network alongside it (round-2 clarification).
- `lab/labctl.sh`: `PROFILE_ARGS` currently supports exactly one `--profile` value
  (`PFF_PROFILE`). Compose supports multiple `--profile` flags simultaneously; this lane
  extends `PFF_PROFILE` to accept a comma-separated list (e.g. `PFF_PROFILE=apps,desync`),
  splitting it into one `--profile` flag per entry, so `apps` and the existing `desync`
  profile can be combined without a breaking change to the single-value case.
- `status`/`logs`/`snapshot`/`restore` need no change (they already operate compose-wide or
  are PFF-DB-specific by design).

### 2d. Cross-app navigability run

A new top-level script/test, `tests/test_lab_cross_app_navigability.py` (or a `scripts/`
entry, decided during review -- R1 below), that:

1. Boots every real app identity's compose service (or, for a faster/CI-friendly path,
   every stack's own `assemble_<stack>_app`/`assemble_lab`/`assemble_spring_boot_app`
   output via that stack's own live-boot harness, avoiding a real `docker compose up` in
   the test suite -- decided during review, R2 below, since every stack already has this
   proven, in-process live-boot path and a real container boot in CI is a much bigger
   dependency);
2. Runs each app's **own, already-existing** navigability test in one combined pass
   (this lane does not re-derive per-app crawl logic -- it orchestrates what Lanes 1-6
   already built and proved, per PA-0002's "derive, never hand-maintain a second
   mechanism" discipline) and reports one combined pass/fail plus a per-app summary table;
3. Is marked `slow` (every real app boot is real, per stack's own live-boot module) and
   skip-guarded per stack the same way each stack's own live-boot suite already is (a host
   missing e.g. `java`+`mvn` skips only that stack's row, not the whole run).

This automated run is separate from, and does not replace, the one required manual
full-profile boot in §4/§5 (a real `docker compose --profile apps up` of all 10 services
together at least once) -- an in-process/subprocess re-run of each stack's own harness
proves each app still works, but not that the 10 real containers coexist without a
container-name, network-alias, or resource collision (S16/S17).

### 2e. Absent-input vocabulary reconciliation (§1 item 1-2)

- One closed, cross-emitter `ABSENT_INPUT_VALUES` set (or equivalently-named), defined once
  (a shared module, not duplicated per emitter -- PA-0027's discipline applied to a value
  set instead of a cell list), covering every value every emitter currently uses:
  `default_value` / `required_param` / `required_header` / `required_multipart` /
  `empty_body_400` / `no_input` / `form_when_absent` (`spring_boot`) plus `go_net_http`'s
  own spellings (`required_400`, `default_caller_else_401`, `auth_reject_401`,
  `form_on_get`) -- reconciled by **renaming `go_net_http`'s values to the shared set
  where the underlying behavior is identical**, and keeping a distinct value only where
  the behavior is genuinely different (`go_net_http`'s caller-header-based auth shapes,
  which no other emitter's vocabulary currently models). Renaming an existing emitter's
  values is a **behavior-preserving rename**, verified by re-running that emitter's full
  offline+live suite unchanged in outcome (S9 below).
- `tests/test_absent_input_declarations_cross_emitter.py` (Lane 4's own S15 module) is
  extended so each emitter's positive-confirmation test validates every declared value is
  a member of the shared set, not merely that "some declaration-shaped dict exists" (its
  current, deliberately coarse existence check, per that module's own docstring).

### 2f. Production-mode serving decisions (§1 items 3-4)

- `node_express`'s compose service runs with `NODE_ENV=production` (already supported by
  `app.js`, per Lane 6's own plan). `tests/test_every_test_time_node_launch_sets_production`'s
  strict xfail is revisited: if this lane's own new test-time launches (the assemble-
  function test, the cross-app run) also set it, that test's scope is the *existing*
  3 launches Lane 5's sweep found, which are unchanged by this lane (a different code
  path) -- the xfail is not touched unless a future change fixes those 3 call sites too
  (out of scope here, named so explicitly rather than silently left ambiguous).
- `ruby_rails`'s compose service runs with `RAILS_ENV=production` (a real production
  Rails boot needs `SECRET_KEY_BASE` and a precompiled-assets step in general; ForgeCart
  serves no assets needing compilation today, verified directly rather than assumed, so
  this lane only needs to confirm that live before deciding whether the Dockerfile needs
  an `assets:precompile` step).

### 2h. `SECRET_KEY_BASE` (D12 compliance)

A real `RAILS_ENV=production` boot requires `SECRET_KEY_BASE` to be set (Rails refuses to
boot in production without it). CLAUDE.md's D12 ("credentials live in the OS keyring /
credential store — never commit secrets") forbids hardcoding one in `lab/compose.yaml` or
`lab/web-rails.Dockerfile`. **Decision:** generate an ephemeral value at container start
(e.g. `SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(bin/rails secret)}"` in the container's own
entrypoint, or an equivalent one-liner), never persisted, never committed, and not derived
from anything sensitive -- ForgeCart has no real user data or real secrets to protect (it
is a lab-only app whose whole ground truth is deliberately public), so an ephemeral,
container-lifetime-only value is a complete, correct resolution, not a placeholder for
later real-secret handling. This is recorded here explicitly rather than left as an
unstated implementation detail (S15 below).

### 2i. Process-doc addition (§1 item 7)

`docs/MULTI_AGENT_ORCHESTRATION.md` gains a short paragraph naming the pattern this
project has already used at least twice (a strict-xfail marker shared across concurrent
lanes' own cross-emitter checks, e.g. Lane 4's `test_absent_input_declarations_cross_emitter.py`,
resolved independently by whichever lane lands the underlying fix first): the lane that
lands the fix deletes its own marker at merge; a concurrent lane must never delete another
lane's still-relevant marker, and a marker that unexpectedly XPASSes after an unrelated
merge (as happened during this branch's own Lane 4 merge, §3.S9's own sibling case) is
converted to a positive confirmation, not silently deleted without comment.

### 2g. Runbook and docs

- `docs/ON_HOST_RUNBOOK.md` (or a new `docs/LAB_MULTI_APP_RUNBOOK.md`, decided during
  review) gains a section: bringing up every app (`PFF_PROFILE=apps ./labctl.sh up`),
  the port table (copied from `docs/LAB_BROWSABLE_APPS_PLAN.md`, kept in sync -- a single
  source-of-truth decision made explicit in the entry, not left implicit), the expected
  resource footprint (S16), the per-app network-isolation posture (S17), and how to run
  the cross-app navigability check against a real running stack vs. the in-process path.
- `docs/ARCHITECTURE.md`: one new paragraph (matching every earlier lane's own precedent)
  naming the compose services, the vocabulary reconciliation, and the cross-app run.
- `docs/components/01-target-lab/requirements.md`: `FR-LAB-170` (the compose/labctl/runbook
  integration) and `FR-LAB-171` (the absent-input vocabulary contract).
- `docs/LAB_BROWSABLE_APPS_PLAN.md`: Lane 7's own row updated on completion; the stale
  "Netflix clone"/"Expedia clone" port-table names fixed to ReelQueue/WanderFare (S12).
- `docs/MULTI_AGENT_ORCHESTRATION.md`: the 2i paragraph.

## §3. Risk register

1. **S1** -- *A per-stack assemble function might not produce a live-bootable tree*, since
   it is new code, not merely lifted verbatim. Mitigation: 2a's own dual-path test
   (re-boot the new function's output through the stack's existing harness).
2. **S2** -- *Renaming `go_net_http`'s absent-input values is a behavior-preserving
   refactor, not a new feature*, so it carries real regression risk on an already-shipped,
   merged lane. Mitigation: `go_net_http`'s full offline+live suite re-run unchanged in
   outcome (S9), and the rename touches only the value string, never the guard logic.
3. **S3** -- *Loopback-only discipline across 10 new compose services* (CLAUDE.md
   non-negotiable). Mitigation: an offline test asserting every service in
   `lab/compose.yaml` binds `127.0.0.1`, never `0.0.0.0`, extended from any such check
   Lane 1's own compose work may already have (verified during implementation, not
   assumed).
4. **S4** -- *A real production-mode Rails/Node boot may behave differently from the
   development-mode boot every existing live-boot/navigability test already proved
   correct* (assets, session secrets, error pages). Mitigation: the cross-app run (2d)
   boots the *real* compose-configured mode at least once, not only each stack's existing
   development-mode live-boot harness.
5. **S5** -- *`PFF_PROFILE`'s comma-split change could silently break the existing
   single-value `desync` case.* Mitigation: an offline test of `labctl.sh`'s profile-arg
   parsing (or a direct shell-level check) for both the single-value and comma-list forms.
6. **S6** -- *Port collisions with anything else already listening on 8082-8091 on a given
   host* are a real, if unlikely, operational risk on shared dev machines -- out of this
   lane's control beyond following the existing reserved-port table exactly (no new
   numbers invented).
7. **S7** -- *A `docker compose up` of all 10 new services in CI/this environment may not
   actually be exercisable* (no Docker/Podman compose provider, or a build needing
   network access this sandbox lacks) -- confirmed empirically before committing to that
   path for 2d/§4's test design, not assumed either way.
8. **S8** -- *`assemble_<stack>_app`'s manifest-scan-and-filter logic could silently drift
   from each stack's own existing `app_cells_for`-equivalent/harness logic* over time.
   Mitigation: each new function reuses that stack's own existing cell-selection code
   path (e.g. the same manifest-glob + `emitter.supports()` predicate already used by that
   stack's live-boot harness), never a second, hand-written copy (PA-0027).
9. **S9** -- *Behavior-preserving-rename verification for `go_net_http`* (§3.S2): full
   non-slow suite plus `go_net_http`'s own `slow` live-boot/navigability suites, before
   and after the rename, with identical pass/fail outcomes **captured as an explicit
   before/after evidence artifact** (counts + which tests exercise which behavior),
   recorded in the change-control entry's own Effectiveness section as a named,
   separately-reviewable item -- not folded into a generic "vocabulary reconciliation
   done" bullet (round-1 adequacy fix; mirrors how Lane 4's own `CC-LAB-0244` entry
   treated equivalent before/after evidence for `BUG-0054`).
10. **S10** -- *The two checked-in scaffold Dockerfiles (`node_express`/`python_fastapi`)
    were written speculatively and never actually built or booted.* Mitigation: a real
    `docker build`/`podman build` of each, verified live, before wiring either into
    compose -- never assumed correct from having compiled cleanly as a template.
11. **S11** -- *This lane could balloon into a de facto Lane 8* if implementation reveals
    the 3-app-per-Dockerfile / one-function-per-stack shape doesn't fit cleanly (mirroring
    every earlier lane's own numbering-collision contingency clause). Mitigation: the same
    contingency rule every Lane 1-6 entry used -- a split bumps no other lane (none exists
    past this one yet), flagged in this entry's own Impact section the moment it's found,
    not deferred.
12. **S12** -- *Stale "Netflix clone"/"Expedia clone" naming* in the existing port table
    (predates the `CC-LAB-0244` rename). Low risk (documentation only); fixed as a one-line
    edit alongside this lane's own doc updates (2g).
13. **S13** -- *`go_net_http`'s own S7 digit-check blind spot* (§1 item 6): `site.go`'s CSS
    is a Go backtick raw string literal, never matched by the double-quote-only regex both
    Lane 3's and Lane 4's own S7 offline tests use, and round-1 review confirmed a real,
    currently-undetected `max-width:100%` 3-digit run already sits there in already-merged,
    already-pushed code. **Decision needed at review**: fix it now (touches an
    already-merged lane's file, `site.go`, outside this lane's own stated scope) or
    flag-and-defer with a tracked follow-up (matching how Lane 5 deferred ForgeCart's
    stale-citation cleanup). Recommendation: defer with a tracked, precisely-worded
    follow-up rather than silently expand scope, per the multi-agent orchestration
    policy's own "flag, never silently build or skip" rule -- this lane's own reviewers
    should confirm or override that recommendation.
14. **S14** -- *F1/F2's pinned-xfail status must not be silently disturbed* by this lane's
    own new production-mode boots. Mitigation: re-run `tests/test_labgen_node_express_browsable.py`/
    `tests/test_labgen_python_fastapi_browsable.py`'s existing strict-xfail tests
    unchanged, confirmed still `xfail` (not `xpass`), **as its own explicit deliverable
    line** (round-1 adequacy fix; previously only implied by "full suite green").
15. **S15** -- *A real `RAILS_ENV=production` boot needs `SECRET_KEY_BASE`, and hardcoding
    one anywhere in the repo would violate D12* (round-1 adequacy finding, previously an
    unstated implementation detail). Mitigation: 2h's ephemeral, container-lifetime-only,
    never-committed generation -- recorded as its own deliverable line.
16. **S16** -- *Resource contention across up to 11 real containers on one host*
    (4 PHP/Laravel, 1 Django, 1 Go, 3 Spring/JVM, 1 Rails, 1 Node -- the JVM apps
    especially are not lightweight) is a real operational risk this plan's earlier draft
    did not name (round-1 adequacy finding). Mitigation: the runbook (2g) states the
    expected combined memory/CPU footprint, measured live during the manual full-profile
    boot (§4); a per-service compose `deploy.resources.limits`/`mem_limit` is added if
    that measurement shows it is needed, not preemptively guessed.
17. **S17** -- *Compose's default same-project network would let one app's container
    reach another's by service-name DNS even though every host port stays loopback-only*
    (round-1 adequacy finding) -- a real concern specifically because this lab hosts
    genuine exploitable sinks, including a live SSRF (`unchecked_url_fetch` on
    ReelQueue's `/api/content/thumbnail-import`, a caller-supplied URL fetched
    server-side) that could otherwise pivot to another app's internal container port.
    Mitigation: 2c's per-app dedicated compose network (no shared default network across
    app services), verified by an offline/live check that no two app containers can reach
    each other (e.g. `docker network inspect` showing disjoint networks, or a live
    connectivity probe from inside one app container to another's internal port failing).

## §4. Test design

- Offline: one new module per new assemble function (tree-shape assertions), the extended
  `test_absent_input_declarations_cross_emitter.py` (membership, not just existence), a
  loopback-only compose-service check (S3), a per-app network-isolation check (S17), and a
  `labctl.sh` profile-arg parsing check (S5).
- Live (`slow`, skip-guarded per stack): each new Dockerfile built and booted individually
  at least once (S10); the cross-app navigability run (2d, in-process per R2); `go_net_http`'s
  full existing live-boot suite re-run after the vocabulary rename (S9), with the
  before/after outcome recorded; F1/F2's xfails re-confirmed still `xfail` (S14).
- **One manual, recorded full-profile boot**: a real `docker compose --profile apps up`
  (or `PFF_PROFILE=apps ./labctl.sh up`) of all 10 new services together plus PFF, at
  least once, with its resource footprint measured (S16) and its network isolation
  verified (S17) -- this is the one check that an individually-passing per-Dockerfile
  build (S10) and an in-process cross-app run (2d/R2) cannot substitute for, since neither
  proves the 10 real containers coexist without a name/network/resource collision.
- Full non-slow suite green throughout, counts recorded (PA-0038), the same discipline
  every earlier lane's own Deliverables checklist required.

## §5. Sequencing (named gates)

Ordered so a later gate never depends on an earlier one's *unresolved* risk (round-1
adequacy fix: this section did not exist in the previous draft):

1. **Gate A** -- S13/R3 decision recorded (fix now or flag-and-defer), and 2i's process-doc
   paragraph landed. Both are cheap, independent of everything else, and settle two open
   scope questions before any code is written.
2. **Gate B** -- Per-stack assemble functions (2a) green, including each one's dual-path
   test (S1, S8).
3. **Gate C** -- Absent-input vocabulary rename (2e) landed, with S9's before/after
   evidence captured, **before** Gate F touches `go_net_http` again (round-2 correction:
   the dependency is on Gate F, the cross-app navigability run, not Gate E's
   compose/labctl wiring, which never touches the absent-input vocabulary at all -- the
   cross-app run must run against the renamed, already-verified vocabulary, not the old
   one).
4. **Gate D** -- Every Dockerfile (2b) built and booted individually (S10), including the
   `web.Dockerfile`/`web-spring.Dockerfile` `ARG APP` addition.
5. **Gate E** -- compose.yaml + labctl (2c) wired: per-app networks (S17), loopback-only
   (S3), profile-arg parsing (S5), `SECRET_KEY_BASE` handling (S15).
6. **Gate F** -- The one manual full-profile boot (§4), with S16/S17 measured/verified
   live, plus the automated cross-app navigability run (2d).
7. **Gate G** -- Docs/bookkeeping (2g): runbook, `ARCHITECTURE.md`, `FR-LAB-170`/`171`,
   the plan-table row and naming fix (S12), the change-control entry's Effectiveness
   section (S9's explicit evidence, S14's explicit re-confirmation).

## §6. Deliverables (draft -- finalized after review)

- [ ] `assemble_django_app`/`assemble_go_net_http_app`/`assemble_ruby_rails_app`, each with
      its dual-path test (2a, Gate B).
- [ ] `lab/web.Dockerfile`/`lab/web-spring.Dockerfile`'s new `ARG APP` passthrough, plus
      3 further new Dockerfiles (`web-django`/`web-go`/`web-rails`), plus the 2 existing
      scaffold Dockerfiles verified live and copied into `lab/` (2b, S10, Gate D).
- [ ] `lab/compose.yaml`: 10 new services, loopback-only, `profiles: ["apps"]`, ports from
      the existing reserved table, each on its own dedicated network (2c, S17, Gate E).
- [ ] `lab/labctl.sh`: multi-profile `PFF_PROFILE` support (2c, S5, Gate E).
- [ ] `SECRET_KEY_BASE` ephemeral generation for `ruby_rails`'s compose service, D12-compliant
      (2h, S15, Gate E).
- [ ] Absent-input vocabulary reconciliation, with `go_net_http`'s explicit before/after
      suite-outcome evidence recorded (2e, S9, Gate C) + Lane 4's S15 module extended to
      validate membership (2e item 2).
- [ ] `node_express`/`ruby_rails` production-mode compose serving decisions recorded and
      verified (2f, Gate E); F1/F2's xfails re-confirmed still `xfail`, not silently
      disturbed (S14, Gate F).
- [ ] One manual, recorded full-profile `docker compose --profile apps up` of all 10
      services together, with resource footprint (S16) and network isolation (S17)
      measured/verified live (§4, Gate F).
- [ ] Cross-app navigability run (2d, Gate F).
- [ ] `docs/MULTI_AGENT_ORCHESTRATION.md`'s shared-strict-xfail-sentinel paragraph (2i,
      Gate A).
- [ ] Runbook update + `docs/ARCHITECTURE.md` paragraph + `FR-LAB-170`/`171` +
      `docs/LAB_BROWSABLE_APPS_PLAN.md` row 7 + naming fix (2g, S12, Gate G).
- [ ] S13's decision recorded either way (fixed, or flagged with a tracked follow-up)
      (Gate A).
- [ ] Full non-slow suite green, counts recorded; every affected stack's own `slow` suite
      re-run green.
- [ ] Bug protocol if S1/S4/S10 (or any other item) surfaces a real defect (`BUG-0057`/`PA-0059`,
      pre-reserved).

## §7. Open questions for review (not yet decided)

- R1: cross-app navigability run as a `tests/` module vs. a `scripts/` entry point.
- R2: whether the cross-app run boots real compose containers or reuses each stack's
  in-process/subprocess live-boot harness (recommended: the latter, for CI practicality;
  a real compose boot stays the one required manual step, §4/§6).
- R3 (= S13): fix `go_net_http`'s S7 blind spot now, or flag-and-defer.

## §8. Review history

- **Round 1** (2026-09-25): ACCURATE WITH CORRECTIONS (2 fixes: §1 item 1's vocabulary
  citation was wrongly attributed to `PA-0056` instead of `BUG-0056`/`PA-0058`; §2b's
  claimed `--app` build-arg precedent in `lab/web.Dockerfile` did not exist) /
  ADEQUATE CONTINGENT ON 8 items (a missing 7th flagged-item + 2i, a missing §5
  Sequencing section, S9/S14 needing explicit deliverable lines, S15 `SECRET_KEY_BASE`/D12,
  a required full-profile compose-up deliverable, S16 resource contention, S17 network
  leakage). All 10 items applied in the round-1 revision.
- **Round 2** (2026-09-25): ACCURATE, no further corrections / ADEQUATE CONTINGENT ON 3
  items (Gate C's dependency wrongly named Gate E instead of Gate F; missing §0/§8
  sections against the established template; 2c's network-isolation mitigation needed one
  clarifying sentence on the underlying compose mechanic and on PFF's own services being
  unaffected). All 3 applied in this revision.
- **Round 3** (2026-09-25): ACCURATE (a full re-verification of §0's cited sources, the
  compose-networking mechanic claim against real Compose semantics, and the Gate C fix,
  with no further errors found) / ADEQUATE (a full cross-check of every S1-S17 risk item
  against §4/§5/§6 confirmed no missing test/deliverable/gate coverage, and one trivial,
  non-blocking cosmetic nit -- §2's subsections run 2a-2f, 2h, 2i, 2g, out of alphabetical
  order -- noted as not worth a fourth round). **Converged 3/3; implementation
  authorized.**

---

*Converged 3/3 after 3 review rounds. Implementation begins at Gate A, per this project's
process (`CLAUDE.md`).*
