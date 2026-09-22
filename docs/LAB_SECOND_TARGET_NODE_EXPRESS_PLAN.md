# Second lab target — `node_express`, implementation plan

**Status: planning only — nothing in this document has been executed.** This
plan exists to size and sequence the work before any of it is dispatched,
per this project's own standing discipline of not building through an open
question speculatively (see `docs/LAB_IMPLEMENTATION_PLAN.md`'s own framing).

## 0. Why this exists, and what's already decided

`docs/DECISIONS_AND_ROADMAP.md`'s "Deferred decisions" list has carried
**"Second target app — decide when generalization becomes a goal, after the
core toolkit works"** since early in the project. All ten toolkit phases
are now code-complete offline (only live-infra exit measurements remain,
tracked in `docs/ON_HOST_TASKS.md`), and the reconciliation of this
session's parallel lines of work is done — the project owner judged this
the right point to make that deferred call.

**Decided (this session, by the project owner, in order):**

1. The second target is **a second manifest-generated app**, not an
   external independently-built lab (Juice Shop/WAVSEP were the
   alternative, per D10's own naming of them for the "realism"/
   "scanner-benchmark" validation tiers respectively) — cheaper, reuses the
   existing generator/module/conformance machinery, and is what the
   already-built-but-unused `fuzzlab/harness/multitarget.py`/`TargetSpec`
   plumbing was built to consume.
2. The stack is **`node_express`**, chosen over `python_fastapi` (the other
   existing shallow "Tier-A" stack) specifically for generalization value:
   Node/Express has a much larger real-world security-research footprint
   (most of this session's own corpus examples under
   `docs/research/corpus-examples/` drawing on real Node CVEs are Express
   apps), and fewer built-in framework guardrails than FastAPI+Pydantic's
   default type coercion, which tends to map vulnerability shapes more
   directly/idiomatically rather than requiring the shape to route around
   the framework's own validation first.

**Not yet decided (flagged, not resolved here — see §4):** whether the new
app's pages are original content or deliberately drawn from the
site-architecture corpus research. This gates Phase C and should be decided
before Phase C is dispatched, not during it.

## 1. Current state of `node_express` (verified against the code, not assumed)

- `fuzzlab/labgen/emitters/node_express/__init__.py` (242 lines),
  `modules.py` (267 lines), `stack_env.py` (88 lines) — comparable in size
  to `python_fastapi`'s equivalents, both meaningfully shallower than
  `php_laravel`'s full-depth build.
- One manifest currently targets it (`grep -l node_express lab/manifests/
  *.yaml` — 1 hit), vs. 11 for `php_laravel`.
- **No checked-in bootable skeleton.** `php_laravel/stack/skeleton/` (a
  real, trimmed `composer create-project laravel/laravel` output) has no
  Node equivalent. `node_express/stack_env.py` exists (88 lines) but this
  has not been read in detail as part of this plan — Phase A's first task
  is to determine exactly how much of the "real assembled app" mechanism
  it already provides before writing anything new.
- **No live-boot conformance harness.** `LiveBootHarness`
  (`fuzzlab/labgen/conformance/live_boot.py`) is `php_laravel`-specific;
  there is no `NodeLiveBootHarness` or equivalent. Tier 1/2 conformance for
  `node_express` is `[design]`-only, per the last full architecture audit.
- **Environment check (this sandbox, done for this plan):** `node` v22.22.2
  and `npm` v10.9.7 are both on `PATH`. A local Node boot-and-serve
  conformance harness is buildable and testable in this sandbox today —
  no container/Docker daemon needed for this part, exactly the same
  situation `php_laravel`'s `LiveBootHarness` was in with `composer`/`php`.

## 2. Phase A — real bootable skeleton + boot harness

**Goal:** the Node equivalent of `php_laravel`'s
`LiveBootHarness`/`SKELETON_DIR` — a real, checked-in, trimmed Express app
skeleton, and a harness that assembles a manifest's rendered output onto
it, runs a real `npm install`, boots the app for real, and lets a caller
make real HTTP requests against it.

Tasks:

1. Read `node_express/stack_env.py` in full first — do not assume it's
   empty or equivalent to what's needed; it may already provide part of
   this.
2. Produce a real, minimal Express skeleton (analogous to `php_laravel`'s
   trimmed `composer create-project` output) — a real `npm init`/`express-
   generator` output with dev-only tooling stripped, checked in under
   `fuzzlab/labgen/emitters/node_express/stack/skeleton/` (mirroring
   `php_laravel`'s own directory shape) with a README recording exact
   provenance and the trim list, per that directory's own convention.
3. Build `NodeLiveBootHarness` (or fold into a renamed shared module if the
   overlap with `LiveBootHarness` turns out large enough to warrant a
   shared base — a judgment call to make once both are visible side by
   side, not decided here) with:
   - A real capability probe, `node_boot_available()` — built correctly
     the first time per `PA-0035`'s rule (a probe must exercise the actual
     operation path: a real, bounded `npm` operation against the actual
     registry a real `npm install` would use, respecting any configured
     proxy — never a bare socket/DNS check standing in for it). This is
     the exact class of mistake `BUG-0033` was; do not repeat it for a new
     package manager.
   - Real assembly: copy the skeleton, overlay a manifest's rendered
     `EmittedFiles`, accumulate routes (whatever `node_express`'s own
     route-registration convention is — read `route_fragment_for` in the
     existing emitter before assuming Express's own `Router` shape maps
     directly onto `php_laravel`'s route-accumulator design).
   - Real `npm install`, real process boot (`node server.js` or
     equivalent), real HTTP requests via the same `urllib.request`-based
     client pattern `LiveBootHarness` already uses (no new HTTP client
     abstraction needed).
   - A real per-run database. SQLite via a Node driver (`better-sqlite3` or
     `node:sqlite` if the pinned Node version ships it — v22 does carry an
     experimental `node:sqlite` built in, worth checking before adding a
     dependency) to mirror `LiveBootHarness`'s own SQLite-for-testing /
     MariaDB-for-production split, rather than inventing a different
     persistence story for this stack.
   - Bounded timeouts on every real subprocess step (install, boot,
     request), enforced at the shared runner, not left to each call site —
     `PA-0035`'s second half, applied from day one instead of retrofitted.
4. One minimal, real, executed test: assemble+boot+serve a single
   illustrative cell, prove a real payload differential end to end (the
   same bar `php_laravel`'s very first live-boot test set).

**Bookkeeping owed:** `CC-LAB-NNNN`/`FR-LAB-N` (verify next-free at dispatch
time), a `CHANGELOG.md` line, and the full bug protocol for any genuine
defect surfaced building this (a new capability probe and a new
package-manager integration are exactly the kind of code most likely to
hide one, per this project's own recent history with `BUG-0029`/`0033`).

## 3. Phase B — deepen the module inventory to full depth

**Goal:** bring `node_express`'s op/sink/source registry up to parity with
the shared vocabulary already accumulated in `lab/safety_matrix.yaml` —
redoing, for Node, what `L-P3.3b` did for `php_laravel`.

Tasks:

1. Diff `node_express`'s current `_MODULE_SET_BY_SHAPE` (or equivalent)
   against the full `lab/safety_matrix.yaml` vocabulary to get an exact
   gap list — do not estimate this, compute it.
2. For each missing `(vuln_class, sink_family)` shape already proven on
   `php_current`/`php_laravel`, write the Node/Express-idiomatic module
   (source/transform/sink) — reusing the shared minimal-pair vocabulary
   convention (register in the shared registry even where only one stack
   renders a given shape, exactly as `L-P3.3c-DOM`'s `dom_url_source` was
   registered in `php_current`'s registry despite being render-only there).
3. Cover, at minimum, the shape classes every other full-depth stack has:
   SQLi (value and identifier position), XSS (body, attribute, DOM), and
   the two newest classes this session added (mass-assignment,
   `orm_entity_bulk_assign`'s ORM-equivalent for whatever Node ORM/query
   builder the skeleton uses — Sequelize/Knex/raw `pg`/`sqlite3`, a choice
   Phase A's skeleton decision determines).
4. Tier 0 (lint — Node's own syntax-check equivalent, e.g. `node --check`)
   and Tier 3 (whole-manifest regenerate-and-diff, byte-deterministic) for
   every new cell, exactly like every other emitter's own build gate.

**Sequencing note:** this phase can start once Phase A's skeleton/harness
shape is settled (module templates need to target real file paths/route
conventions Phase A defines), but the module-writing work itself doesn't
need Phase A's harness *running* — Tier 0/3 conformance doesn't require a
real boot. Phase A's live-boot proof and Phase B's module breadth can
proceed as two concurrent lanes once Phase A's skeleton structure (not its
full harness) is fixed, mirroring this project's own multi-lane
parallelization discipline (`docs/MULTI_AGENT_ORCHESTRATION.md`) — flagged
here rather than assumed serial, but not committed to a lane map until
Phase A's skeleton decisions actually land (a lane map drawn now would be
speculating on an interface that hasn't been designed yet).

## 4. Phase C — its own identity and ground truth (has an open design question)

**Goal:** a genuinely separate app — its own name, its own coherent page
set, its own `labels.json`/`injection-points.json` ground truth, never
reusing `puppy-fort-factory`'s (or its successor generated lab's) case IDs
or identity. Generalization evidence means nothing if the "second" target
is secretly the first one's cases relabeled.

**Open question, not resolved here — decide before dispatching this
phase:** should the new app's pages be original content authored for this
purpose, or deliberately drawn from the site-architecture corpus research
(`docs/research/corpus-examples/`, the six original categories plus the
six `claude/vuln-corpus-expansion-zjl1iw` added — access-control,
auth-session, ugc-xss, file-handling, search-export, ecommerce-logic,
mass-assignment, ssrf, ssti, header-injection, insecure-deserialization,
webhook-signature).

Considerations for that decision, laid out rather than resolved:

- **Corpus-grounded** gives the new app the same "modeled on real code
  shapes, not invented from memory" grounding this project's whole
  generator philosophy already rests on (see `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s
  own "Why" section) — and reuses research already done and reviewed this
  session, rather than inventing a second, parallel justification story.
- **Corpus-grounded** also means this second target can exercise
  vulnerability classes the current `php_laravel` lab doesn't have at all
  yet (SSRF, SSTI, header injection, insecure deserialization, webhook
  signature bypass) — a genuinely different attack-surface profile, which
  is exactly what makes a transfer-generalization measurement meaningful
  rather than a repeat of the same classes on a different templating
  syntax.
- **Original content** is faster to design (no corpus-fidelity bar to
  clear) but weaker generalization evidence — it would only be testing
  "does the toolkit work on syntactically different Node code," not "does
  it work on a different, independently-grounded set of vulnerability
  shapes."

**Recommendation (not a decision — the project owner's call):** corpus-
grounded, specifically using the newer classes the current lab doesn't yet
model (SSRF/SSTI/header-injection/insecure-deserialization/webhook-
signature) rather than re-doing SQLi/XSS a second time, so the second
target's value is additive to the toolkit's real coverage, not merely
duplicative.

Once decided:

1. Pick a coherent page/route set spanning the chosen vulnerability classes
   (a small, self-consistent app identity — e.g. a webhook-integration
   dashboard, matching whichever classes are in scope — not a loose bag of
   unrelated illustrative cells).
2. Author `labels.json`/`injection-points.json` for this app from scratch,
   with its own opaque case-ID scheme (never `PFF-*`), following
   `docs/DECISIONS_AND_ROADMAP.md` D9's existing out-of-band ground-truth
   contract.
3. Author the manifest(s) (vulnerable/secure twin pairs, one per chosen
   class) using Phase B's module inventory.

## 5. Phase D — Tier 1/2 conformance

Same standard `php_laravel` was held to: real boot, real HTTP, a real
payload differential proven for every cell in the new app's manifest(s),
using Phase A's harness. This phase is mostly mechanical once Phases A-C
land — it is "run the proof," not "design the proof."

## 6. Phase E — wire it into `multitarget.py`

1. Construct the new app's `TargetSpec` (`name`, `base_url` pointing at a
   locally-booted instance via Phase A's harness, `ground_truth` from
   Phase C's labels).
2. Run `fuzzlab/harness/multitarget.py` against **both** targets (the
   `php_laravel` lab and this new one) and confirm it actually produces
   per-target + macro metrics and a `generalizes` verdict — this is
   genuinely testable in this sandbox (both targets can be locally booted;
   no live/external infra needed for this proof).
3. This closes the *toolkit-side* half of Phase 10's `T10.6` exit
   criterion. The *other* half — the real, on-host measurement against a
   live production deployment — stays exactly as blocked as before; this
   plan does not change that.

## 7. What this plan does not do

- Does not build an external target (Juice Shop/WAVSEP) — that option was
  explicitly not chosen (§0).
- Does not resolve Phase C's corpus-vs-original design question — flagged,
  not decided, per §4.
- Does not attempt the live/on-host `T10.6` measurement itself — only the
  toolkit-side proof that a second target can be run and compared, which
  is the part actually blocked on nothing but being built.

## 8. Bookkeeping conventions for whoever executes this plan

Every phase above owes this repository's standard checklist per `CLAUDE.md`
— a `CHANGELOG.md` line, a `CC-LAB-NNNN` change-control entry (verify
next-free at dispatch time, not from this document, since other work may
land between now and execution), a `requirements.md` update, and the full
bug protocol for any genuine code defect surfaced along the way. If this
plan is executed via concurrent build lanes, pre-assign each lane's
bookkeeping numbers before dispatch per `docs/MULTI_AGENT_ORCHESTRATION.md`
§3/`PA-0031`, rather than letting each lane claim "the next free" one.
