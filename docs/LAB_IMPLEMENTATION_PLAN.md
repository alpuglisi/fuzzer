# Lab generator — implementation plan for the remaining work

**Status: draft, for review.** This is a task-level plan, in the style of
`docs/LAB_PHASE_0_PLAN.md`, covering everything **after** the point Phase 0
has actually reached (as of `CC-LAB-0028`) through the rest of `CR-LAB-0001`
§8's phase list. It does not re-litigate anything already decided (D20,
Addenda A-E) — it sequences what is left, names what each task actually
requires, and marks every point that needs a decision or more research
before it can be built, rather than building through it speculatively. Per
this project's own convention, items marked **[research needed]** or
**[decision needed]** are not blocking the rest of the plan unless a
dependency arrow below says so — most of them gate one phase, not all of
them.

Companion documents this plan assumes you have open: `CR-LAB-0001` (the
approved change request, including Addenda A-E), `docs/DECISIONS_AND_ROADMAP.md`
D20, `docs/LAB_PHASE_0_PLAN.md` (Phase 0's own task breakdown, T-LAB0.1-11),
`docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` (T-LAB0.8 methodology),
`docs/LAB_SEED_AUTHORING_PLAYBOOK.md` (oracle validation status), and
`docs/components/01-target-lab/{requirements,change-control}.md`.

## 0. Where things actually stand (verified against the code, not just the docs)

Phase 0 is **9 of 11 tasks done** (T-LAB0.1-7, T-LAB0.11, plus two items
pulled forward from Phase 1: the minimal-pair checker and the
fingerprint-independence gate). Two Phase 0 tasks remain open and are this
plan's first section:

| Task | State | Why it's open |
|---|---|---|
| T-LAB0.8 | Partial | Mechanical pull/index/scope/rank/cluster pipeline is built (`fuzzlab/tools/pattern_corpus_sourcing.py`, `CC-LAB-0020`). Only 3 of the ~25-30 target cards exist — card *authoring* (step 6/7 of the sourcing plan) is explicitly human-only by design, not an agent task. |
| T-LAB0.9 | Not started | Flagged, not built: it changes `expectedresults.csv`'s schema, a contract `fuzzlab/labels/contract.py` and the FUZZ harness already consume. |
| T-LAB0.10 | Not started | Low risk, blocked only on confirming the CLI subcommand shape (§7 decision 5 of the plan doc, never explicitly confirmed in this conversation). |

Everything in Phase 1-4 below is **not started** — CR-LAB-0001 §8 records
them at phase granularity only ("task-level detail deferred to the
implementation plan"). This document is that detail, one level down from §8,
for Phase 1 (most of it) and at milestone granularity for Phases 2-4 (full
task breakdowns for those are better written closer to when Phase 1 actually
finishes, since Phase 1's own results — the leakage-probe threshold, the
authoring-hours actuals — feed directly into how Phase 2-4 get scoped).

---

## 1. Finish Phase 0

### 1.1 T-LAB0.9 — Regression/additive-only gate **[decision needed before starting]**

**What it is.** A permanent test that diffs the generator's emitted
`labels.json`/`expectedresults.csv`/`injection-points.json` against the
current hand-authored ground truth and fails if any existing case ID, page,
or verdict is missing or changed. Per Addendum B, this also requires adding
`primary_endpoint`/`primary_role`/`related_endpoints`/`flow_variant` columns
to `expectedresults.csv` (the multi-artifact ground-truth shape), even though
Phase 0 has no multi-location cells yet.

**Why it's flagged rather than built speculatively.** `CR-LAB-0001` §4 names
this a real FUZZ-component contract change, not merely a LAB-internal one:
"the harness and oracle... need their schema validators and consumers
extended." A code check (this session) found the actual blast radius is
smaller than that language suggests — `fuzzlab.labels.contract._load_expected_csv`
uses `csv.DictReader` and only reads the `case_id`/`expected_vulnerable`
columns today, so *unknown extra columns are already tolerated* at the
parser level. Adding the four new columns would not break
`fuzzlab.labels.contract.load()` as it stands. What is **not** yet verified:
whether anything downstream of `GroundTruth` (the harness, the oracle, any
report code under `fuzzlab/harness/`, `fuzzlab/report/`) assumes a 1:1
case-to-endpoint mapping in a way the new `related_endpoints` shape would
violate — that requires reading those consumers, which is FUZZ-component
territory this session was not asked to touch.

**Decision needed:** whether to (a) have a LAB-side agent add the four new
CSV columns and the regression gate now, on the verified basis that the
*parser* tolerates them, deferring a FUZZ-consumer sweep to whoever next
touches the harness; or (b) do the FUZZ-consumer sweep first (a `Case`
dataclass extension in `fuzzlab/labels/contract.py` plus a read of every
consumer of `GroundTruth.cases`) as part of this same task, so the schema and
its consumers land together. **Recommendation: (b)** — CR-LAB-0001 itself
calls this a FUZZ-touching change, and Addendum B's whole point (the SARIF/
Juliet one-row-per-finding shape) is only correctly honored if a consumer
that currently assumes one row = one location doesn't silently mis-score a
multi-location case once one exists. This is the one item in this plan
closest to a genuine cross-component review, not just a LAB-internal build.

**Task breakdown once decided:**
1. Read every consumer of `fuzzlab.labels.contract.Case`/`GroundTruth` (grep
   for `.cases`, `.positives()`, `.negatives()`, `case_by_id`) and confirm
   none assumes exactly one location per case.
2. Extend `Case` with `primary_endpoint: str | None`, `primary_role: str |
   None`, `related_endpoints: tuple[dict, ...]`, `flow_variant: str` (default
   `"direct"` for every existing single-location case, per Addendum B's
   naming: `direct | same_file_helper | cross_file | stored_second_order |
   cross_service`).
3. Extend `lab/schemas/*.schema.json` (labels + expectedresults, if a JSON
   Schema governs the CSV shape — check `fuzzlab/labels/schemas/`) and
   `expectedresults.csv`'s four new columns, all optional/defaulted so every
   existing row still validates unchanged.
4. Write the regression gate itself: load the generator's emitted ground
   truth and the current hand-authored one (today, that's
   `lab/ground-truth/`), diff by case ID, fail loud on any missing ID, page,
   or changed verdict. This is a `fuzzlab/labgen/` build-gate module,
   following the existing `gates.py`/`secret_scanner.py`/`fingerprint_gate.py`
   convention (typed error, no silent pass).
5. Tests: the gate must fail on a deliberately shrunk/altered ground-truth
   fixture, and pass on an unchanged one — mirroring `test_labgen_gates.py`'s
   own convention.

**Depends on:** nothing else in this plan. Can start immediately once the
decision above is made.

### 1.2 T-LAB0.10 — `fuzzlab lab-generate` CLI

**Status of the blocking decision:** `fuzzlab/cli.py` already dispatches
`web`/`session`/`crawl`/`audit`/`fuzz`/`auto`/`greybox-run`/`proxy`/
`mutate-run`/`report`/`build-db`/`version` as `fuzzlab <command>`
subcommands, each a thin `if command == "..."` branch importing a
`<component>.cli.main(rest)` module. **This confirms decision 5's proposed
answer is correct and consistent with existing convention** — a
`lab-generate` branch fits the same pattern exactly. No further research
needed here; this was previously listed as blocked on a decision, but
reading the actual CLI file resolves it as a non-decision (the alternative,
a standalone `lab/` script, would be the inconsistent choice, not the
default one).

**Task breakdown:**
1. `fuzzlab/labgen/cli.py`: `main(argv) -> int` parsing `--manifest
   <path> --out <dir> [--check]`.
2. Wire `--manifest`/`--out` to load a manifest (`schema.py`), resolve it
   (`resolver.py`, once T-LAB0.3's covering-array expansion is actually
   plugged into manifest loading — confirm it is; the plan doc calls
   `resolver.py` "dormant" as of Phase 0), and render every cell via the
   selected emitter (`emitters/php_current` today; the CLI should take an
   emitter name/registry lookup, not hardcode `php_current`, so Phase 3's
   additional emitters don't require a CLI rewrite).
3. Wire `--check` to run, in order: the name-leak scanner (`gates.py`), the
   secret scanner (`secret_scanner.py`), the regenerate-and-diff determinism
   check (`gates.py`), the minimal-pair checker (`minimal_pair.py`), and (once
   T-LAB0.9 lands) the regression/additive-only gate. `fingerprint_gate.py`
   is *not* wired here yet — it needs a real multi-stack corpus (Phase 3) to
   mean anything; wiring it against a single-stack corpus would either
   vacuously pass or need `expected_stacks`/`expected_classes` overrides
   with no real signal behind them.
4. Register `fuzzlab.labgen.conformance`'s Tier 0/Tier 3 checks as part of
   `--check` too — they're already real and offline; Tier 1/2 stay
   unregistered until their on-host dependencies exist.
5. Tests: an end-to-end CLI test using the existing example manifest
   (`lab/manifests/example_phase0_scaffold.yaml`), asserting `--check` passes
   on a clean tree and fails loud on each individual gate's own known-bad
   fixture (reuse the fixtures each gate's own test module already has,
   don't re-author them).

**Depends on:** T-LAB0.9's regression gate existing, if you want `--check`
to be complete at first landing; can otherwise land now and add the
regression-gate line to `--check` in the same small follow-up that lands
T-LAB0.9.

### 1.3 T-LAB0.8 remainder — pattern-card authoring

**Not a build task.** The mechanical half (pull/index/scope/rank/cluster,
`fuzzlab/tools/pattern_corpus_sourcing.py`) is done and does not touch card
content. What remains is steps 6-7 of `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md`
§3: reading cluster-representative advisory prose and hand-writing
`root_cause` text for ~22-27 more cards across the ten first-wave classes.
This is explicitly, by the sourcing plan's own design (§3 step 6), work an
LLM may assist with a `triage_hint` label/rationale but **may never perform
end to end** — "every cluster representative still reaches me [the human],
and the schema has no field a model can populate as the final card text."

**What an agent *can* do to prepare this, offline:** run
`pattern_corpus_sourcing.py` against the current `github/advisory-database`
clone and produce the candidate/cluster report the sourcing plan describes,
so the human triage step (whenever it happens) starts from a ready report
rather than a cold pull. This is a legitimate, low-risk, offline task and
can be dispatched as its own lane whenever the corpus is due a refresh check
— it produces no cards, per the pipeline's own separation.

**[decision/scheduling needed]:** when the card-authoring pass itself
happens is yours to schedule; it is not gated on anything else in this
plan, and nothing else in this plan is gated on it reaching 25-30 cards
(Phase 1's `patterns/` consumption is citation-only, never a `verdict()`
input, so a smaller corpus doesn't block Phase 1's other work — it just
means fewer cells carry a card citation until more are written).

---

## 2. Phase 1 — Variation on the existing stack

Per `CR-LAB-0001` §8: covering-array expansion, the minimal-pair invariant
(already built, pulled forward), χ² balance + leakage probe as build gates
(fingerprint-gate and leakage-probe already built, pulled forward — but
**not yet wired into a required build gate**, since neither has real
multi-cell variation to check yet), rebuilding the current PHP SQLi/XSS cells
around identifier/alias/connector-position and escaping-context-mismatch
shapes, and stratified splits + de-duplication + diversity reporting. No new
containers — this phase's entire value is realism gains on the stack already
built.

Task breakdown:

### 2.1 Wire the covering-array resolver into manifest loading
`resolver.py`'s real `covertable`-backed expansion exists (T-LAB0.3) but is
"dormant" — Phase 0 manifests list cells explicitly, one axis level each.
This task makes a manifest able to declare axis *ranges* (e.g. "every
`vuln_class` × every `sink_context.family`, pairwise") and have the resolver
expand that into concrete `Cell`s before the emitter ever sees them.
- Extend `lab/schemas/manifest.schema.json` to allow an axis-range block
  alongside (not replacing) explicit cell lists.
- `schema.py`'s manifest loader calls `resolver.py` when axis ranges are
  present, producing the same `Cell` IR the emitter already consumes — no
  emitter-side change needed.
- Tests: a manifest with axis ranges expands to the expected cell count and
  covering-array strength; an explicit-cell-list manifest (today's format)
  still loads identically (regression).

### 2.2 Rebuild the current PHP SQLi/XSS cells around harder shapes
Per the report's "highest value-per-hour" finding: move from textbook
`? id=1` shapes to identifier/alias/connector-position SQLi (injection into
a column/table identifier or JOIN alias, not just a literal value) and
escaping-context-mismatch XSS (correct escaping for the wrong context — e.g.
HTML-escaping a value placed in a `javascript:` URL or an unquoted HTML
attribute).
- New `sink_context.family` values and matching `lab/safety_matrix.yaml`
  rows for each new shape (extends the existing versioned, snapshot-tested
  matrix — no change to `verdict()`'s derivation logic itself).
- New `modules/{sources,transforms,sinks}` fragments for `php_current`
  covering the new shapes, following the module-composition convention
  already established (Addendum C).
- **[research needed, small]:** identifier/alias/connector-position SQLi
  needs its own tool-oracle validation — `oracle_wrapper.py`'s existing
  sqlmap wrapper was validated (Spike 001) against value-context injection;
  confirm sqlmap's `-p`/technique flags actually detect identifier-context
  injection before assuming the existing oracle wrapper "just works" for
  the new shape. If it doesn't, this needs either a sqlmap technique-flag
  change (additive to `oracle_wrapper.py`) or a fallback plan before the new
  cells can be confirmed at all — worth a short spike before authoring more
  than one or two seed cells of this shape.

### 2.3 Wire χ² balance + leakage probe as required build gates
Both `fingerprint_gate.py` and `leakage_probe.py` exist as reference
implementations, deliberately not build-gating yet (no real variation to
check). Once 2.1/2.2 produce a manifest with real cell-count variation
across classes/transforms:
- Add both to `--check` (from T-LAB0.10) as required, not optional, steps.
- **[decision needed]:** the leakage-probe AUC threshold is currently a
  fixed 0.55-0.60 band per the report's recommendation, accepted as
  "revisable per class once real corpus data exists" (`CR-LAB-0001` §5,
  accepted risk). This is the first point real corpus data exists — decide
  per-class thresholds now, or keep one global threshold until Phase 2. No
  default is stated in this plan; it is one of the CR's seven originally
  deferred open questions.

### 2.4 Stratified splits + de-duplication + diversity reporting
- A split function grouping by generating-rule ID (same grouping
  `leakage_probe.py` already uses for its own cross-validation — reuse the
  grouping logic, don't re-derive it) so near-duplicate cells never land on
  both sides of a train/holdout split.
- De-duplication: define "near-duplicate" for this corpus (candidate:
  identical `(vuln_class, sink_context, transform-shape)` tuple regardless of
  cell ID) and a report of duplicate/near-duplicate rate.
- A diversity report (class × transform × verdict counts) as a build
  artifact, not a gate — informative alongside the χ² gate, not redundant
  with it.

**Depends on:** 2.1 before 2.2 can produce more than a handful of cells by
hand; 2.2 before 2.3 has real data to check; 2.4 can proceed in parallel
with 2.2 once 2.1 exists.

---

## 3. Phase 2 — Identity and depth

Per `CR-LAB-0001` §8: identity/ownership model + `authz_expectations`
(unlocks IDOR/BOLA *mechanically* — the cells themselves stay deferred
indefinitely per Addendum E, so this is groundwork Phase 2 needs for other
things, not IDOR/BOLA authoring); `sink_endpoint` distinct from
`injection_endpoint` (unlocks stored/second-order cases — this is exactly
T-LAB0.9's `primary_endpoint`/`related_endpoints` shape, extended from the
ground-truth contract into the manifest/`Cell` IR itself); a parameter
location/encoding axis; the `context_depth` axis (0-4, already named via
Addendum B's `flow_variant` values).

This phase's task-level breakdown is deliberately not written out to the
same depth as Phase 1 above — **[research needed before detailed
planning]:** Phase 2 is the first phase where the manifest schema itself
grows new top-level concepts (`identities`, `authz_expectations`), not just
new axis values within the existing `Cell`/`SinkContext` shape. Before
writing a task breakdown, confirm:
- How `identities` interacts with the existing single-target,
  no-session-manager-yet lab (the toolkit's own Session manager is Phase 1
  of the *toolkit* roadmap, a different track — check whether Phase 2 of the
  Lab track can proceed independently of that landing, or needs it).
- Whether `authz_expectations` belongs in the manifest (verdict-adjacent) or
  in a separate identity-graph file analogous to `provenance.yaml`'s
  separation principle (Addendum A) — an authz expectation is arguably
  closer to ground truth than to provenance, which would put it in the
  manifest/labels contract rather than a side file. This is a real design
  question, not a research gap, but it should be answered before schema
  work starts, the same way Addendum A caught the provenance-direction
  mistake before it shipped.

Once those are answered, write `docs/LAB_PHASE_2_PLAN.md` at the same
granularity as Phase 0/1 above, before starting implementation.

---

## 4. Phase 3 — Multi-stack

Per `CR-LAB-0001` §8 and Addenda C/D: the IR + emitter interface + conformance
suite are **already built** (T-LAB0.4, T-LAB0.7) and were deliberately built
multi-stack-ready even though only `php_current` exists today (module-schema
extensions for multi-file routing, `StackEnv`, cardinality classes — Addendum
D). What's left: Node/Express emitter, fingerprint-independence build gates
actually gating (they exist; Phase 3 is when they have real cross-stack data
to check, same dependency shape as Phase 1's leakage probe), Python/FastAPI
emitter, digest-pinned bases + lockfiles + SBOM recording, PHP/Laravel
emitter (**migrating the existing hand-built app**, per D20 §7.2 — the app
is retired once this lands, not kept alongside it).

**[decision needed before scheduling this phase — carried over from
Addendum C, unresolved]:** Addendum C's calibrated effort estimate is
~330h for the first new stack, ~180h/stack after, i.e. ~450-520h disciplined/
~650-750h unassisted for all three stacks. Three options were given, none
adopted:
- (a) all three stacks to full depth (~8 months solo at 15h/week);
- (b) stack 1 to full depth, stacks 2-3 to Tier-A-only depth (well-documented
  classes only, deferring identifier/alias/connector-position cases on those
  stacks), roughly halving stacks 2-3's cost;
- (c) treat the optional fourth stack (Spring Boot) as explicitly out of
  near-term scope.

This plan does not pick one — it is exactly the kind of scope/pace call the
CR itself reserved for you, and it changes how much of Phase 3's task list
below is worth writing out now versus after Phase 1's actual authoring-hours
data comes in (Addendum C's own recommendation: "time three real seed
authoring sessions before trusting the schedule" — Phase 1's cell-rebuild
work, §2.2 above, is exactly that timing opportunity, and should inform this
decision before it's made, not after).

**[research needed, per Addendum D, ~10 minutes, low cost]:** confirm whether
FastAPI's `APIRouter` auto-inclusion means the Python/FastAPI emitter can
avoid a `route`-category accumulator module entirely, or whether it needs
one like Laravel/Express will. Addendum D flags this explicitly as
"unconfirmed, worth ten minutes to check before Phase 3 starts" — do this
check first, since it affects whether the `route` accumulator module
(already designed, Addendum D) needs to be built for two stacks or just one.

**[research needed]:** Addendum D also flags the `complexity`-as-file-count-
multiplier interaction with the accumulator and covering array as
"the first place to expect an implementation surprise, not asserted as
settled" — this should get a small design spike (a few cells rendered by
hand against the design, not a full stack) before it's built into the second
emitter for real, the same way T-LAB0.4's module-composition schema itself
was validated against NISTIR 8493 before implementation rather than after.

Once the pacing decision above is made, the task breakdown is, per stack (in
whatever order the decision picks):
1. `StackEnv` + scaffold files for the new stack (Addendum D's schema).
2. Port/author the module inventory for that stack's shapes (per the pacing
   decision: full class coverage, or Tier-A-only).
3. A conformance-suite pass against the new emitter (T-LAB0.7's suite is
   already stack-agnostic by design — this is the first real test of that
   claim).
4. Digest-pinned base image + lockfile + SBOM for that stack's container.
5. Wire the fingerprint-independence gate as required once ≥2 stacks exist
   (its own minimum precondition, `min_stacks_per_class >= 2`).
6. For the PHP/Laravel emitter specifically: the migration step (D20 §7.2)
   — reproduce every remaining real `puppy-fort-factory/` page (T-LAB0.7's
   own whole-manifest Tier-3 regression pattern, `PA-0024`, is the exact
   tool for proving this byte-for-byte before retiring the hand-built app),
   then retire `puppy-fort-factory/` as a separate fixture.

---

## 5. Phase 4 — Realism tier and beyond

Per `CR-LAB-0001` §8: the shop tier (6 business objects, ownership graph,
4-step checkout), webhook/callback + seeded internal SSRF target + no-egress
network policy, limit-overrun/race-condition counters, OpenAPI + GraphQL
surfaces, hand-written Next.js fixture cells, optional Spring Boot emitter.

**[decision needed]:** whether Spring Boot proceeds at all is folded into
the Phase 3 pacing decision above (option (c)) — don't schedule Phase 4's
Spring Boot line independently of that call.

**[research needed, deferred appropriately]:** the seeded internal SSRF
target and the GraphQL surface (introspection/aliasing/depth-limit/
resolver-BOLA, per CR-LAB-0001 §3's renaming of the old
`references/graphql-injection` framing) both need their own short design
passes analogous to Addendum C/D's — this plan does not attempt them now,
since Phase 4 is far enough out that anything decided today would likely be
stale by the time it matters. Flagging this explicitly so it isn't
mistaken for "already researched" the way Phase 3's items above are.

This phase is intentionally left at CR-LAB-0001 §8's own bullet granularity
— writing a task breakdown this far out, before Phases 1-3 land and before
the race-condition/business-logic gap-class decision (Addendum E item 2,
deferred indefinitely but revisitable) is revisited, would mostly be
guessing.

---

## 6. Consolidated list of open decisions and research items

For quick reference — everything marked **[decision needed]** or **[research
needed]** above, in the order it first becomes load-bearing:

1. **T-LAB0.9 scope** (§1.1) — sweep FUZZ consumers before or alongside the
   schema change? *Recommended: alongside, before landing.*
2. **Leakage-probe threshold** (§2.3) — per-class or one global 0.55-0.60
   band, now that Phase 1 will produce the first real data to decide it against.
3. **Identifier/alias/connector-position SQLi oracle coverage** (§2.2) — does
   sqlmap's existing wrapper detect this shape, or does `oracle_wrapper.py`
   need a technique-flag addition? Short spike, one or two cells, before
   authoring more.
4. **`authz_expectations` placement** (§3) — manifest/labels-contract vs. a
   separate identity file, before Phase 2 schema work starts.
5. **Toolkit Session-manager dependency** (§3) — does Lab-track Phase 2 need
   it, or can identity groundwork proceed independently?
6. **Phase 3 pacing** (§4) — (a) all three stacks full depth, (b) stack 1
   full + stacks 2-3 Tier-A, or (c) drop Spring Boot from near-term scope.
   Inform with Phase 1's actual authoring-hours data before deciding.
7. **FastAPI route-accumulator need** (§4) — ~10-minute check, before Phase 3
   starts.
8. **Complexity-as-file-count-multiplier interaction** (§4) — small design
   spike before building the second emitter's complexity modules for real.
9. **`patterns/` card-authoring schedule** (§1.3) — not gating, purely a
   "when do you want to do this" scheduling call.
10. Everything in `CR-LAB-0001` §7's remaining deferred list not already
    resolved by an addendum (stack in `labels.json` vs. a separate file;
    the all-secure-profile false-positive contract around framework debug
    pages; whether the pattern corpus versions with the manifest or
    independently; DOM XSS frontend-code generation) — none of these gate
    Phase 1, but each should be resolved before the phase that first needs
    it, per the CR's own original framing.
