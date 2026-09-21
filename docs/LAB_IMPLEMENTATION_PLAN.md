# Lab generator — implementation plan for the remaining work

**Status: draft, for review — eight flagged research items resolved across
two passes, 2026-09-21.** This is a task-level plan, in the style of
`docs/LAB_PHASE_0_PLAN.md`, covering everything **after** the point Phase 0
has actually reached (as of `CC-LAB-0028`) through the rest of `CR-LAB-0001`
§8's phase list. It does not re-litigate anything already decided (D20,
Addenda A-E) — it sequences what is left, names what each task actually
requires, and marks every point that needs a decision or more research
before it can be built, rather than building through it speculatively. Per
this project's own convention, items marked **[research needed]** or
**[decision needed]** are not blocking the rest of the plan unless a
dependency arrow below says so — most of them gate one phase, not all of
them. Eight **[research needed]** items — the original four (identifier-
context SQLi oracle coverage, `authz_expectations` placement, the FastAPI
route-accumulator question, the complexity-as-file-count-multiplier
interaction) plus four more surfaced on a follow-up review pass (SBOM/
digest-pinning tooling, the framework-debug-page false-positive contract,
`stack` field placement in the label contract, DOM XSS fixture authoring) —
were each dispatched to a web-enabled research agent with its own
purpose-built prompt and are now marked **[research complete]** with
findings folded into the relevant sections and summarized in §6. One item
(Phase 4's SSRF/GraphQL design passes) was deliberately left undispatched
both times, since the plan itself judges that research premature this far
out — see §6 item 15. Every remaining **[decision needed]** item is a
judgment/scope call research cannot resolve and is still yours to make.

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
- **[research complete, 2026-09-21]:** identifier/alias/connector-position
  SQLi needs its own tool-oracle validation, and the research confirms it
  cannot reuse the existing sqlmap wrapper as-is.
  **Verdict: sqlmap does not reliably detect identifier/alias/connector-
  context injection, and this is a long-documented, unresolved limitation,
  not a flag/configuration gap.** sqlmap's `--technique=` option (current
  stable ~1.10) only exposes the six classic value-context techniques
  (`B`/`E`/`U`/`S`/`T`/`Q` — boolean-blind, error-based, UNION, stacked,
  time-based, inline) and has no identifier-aware technique; `-p` and the
  `*` custom-injection-point marker both still assume the marked position
  holds a mutable *value* sqlmap can wrap with a prefix/suffix boundary, not
  a bare identifier token. Documented evidence of this gap: sqlmap GitHub
  issue #97 (2012, still open — a user's working manual `CASE WHEN` ORDER-BY
  payload was not found automatically at `--level 3`), issue #2459 (ORDER BY
  column-count heuristic is fragile), and issue #490 (an ORDER BY case was
  only caught because the vulnerable parameter happened to be a numeric
  column index — i.e. it degenerated to value-context, not true identifier
  substitution).
  **Recommended fallback, to build as a small addition alongside
  `oracle_wrapper.py`, not inside it:** a custom differential-response
  prober using the boolean-differential CASE-WHEN technique already
  referenced above — fire two requests (or two direct DB calls if testing
  offline), one with a TRUE-condition substitution
  (`ORDER BY (CASE WHEN <condition> THEN <col_a> ELSE <col_b> END)`) and one
  FALSE, and diff the observable output (row order/count, HTTP status, or a
  `SLEEP()`/`pg_sleep()`/`BENCHMARK()` timing signal for a blind variant).
  This is DBMS-dialect-specific (MySQL/Postgres/SQLite phrase it
  differently) and needs at least one known real column-name pair per
  dialect to construct the probe. Map to the existing fail-closed contract:
  both responses differ as expected and consistently →
  `confirmed_vulnerable`; both identical (parameterization/allowlisting
  holds) → `confirmed_secure`; ambiguous/inconsistent → `inconclusive`,
  matching `oracle_wrapper.py`'s existing three-outcome shape so this can be
  wired in the same way `nuclei_oracle.py` was — a sibling module reusing
  only the generic safety/lookup helpers, not a change to
  `oracle_wrapper.py`'s sqlmap/commix/SSTImap-specific code. **Residual
  uncertainty the research flagged:** the verdict rests partly on
  documentation/issues dating to 2012 with no evidence the core limitation
  was ever closed, and one source (a mailing-list thread) could not be
  fully fetched due to this environment's network proxy — worth a quick
  spot-check against the actual installed sqlmap binary before committing
  to the fallback design, per PA-0005's own "verify against the real tool"
  convention.

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
same depth as Phase 1 above. Phase 2 is the first phase where the manifest
schema itself grows new top-level concepts (`identities`,
`authz_expectations`), not just new axis values within the existing
`Cell`/`SinkContext` shape, so two questions needed resolving before a task
breakdown could be written responsibly:

- How `identities` interacts with the existing single-target,
  no-session-manager-yet lab (the toolkit's own Session manager is Phase 1
  of the *toolkit* roadmap, a different track).
- Whether `authz_expectations` belongs in the manifest (verdict-adjacent) or
  in a separate identity-graph file analogous to `provenance.yaml`'s
  separation principle (Addendum A).

**[research complete, 2026-09-21]** on the second question. No prior-art
project surveyed (crAPI, vAPI, or the closest academic tool found,
**AuthProbe**, arXiv:2607.20574, a 2026 spec-driven multi-identity BOLA
detector) declares "identity X owns resource Y" as a static, hand-authored
ground-truth artifact at all. crAPI and vAPI both leave ownership entirely
implicit in seeded database rows and exploit-script/Postman-collection
steps — there is no schema to adapt from either. AuthProbe comes closer
(it keeps identity credentials in an operator-supplied config, separate
from the OpenAPI spec it tests against — a config listing named identities
each with their own auth headers) but even AuthProbe **discovers ownership
dynamically at runtime** (querying each identity's own list endpoints, then
cross-testing) rather than declaring it as data — because it targets
already-running third-party APIs, not a synthetic corpus it controls, it
has no need to. **Conclusion: `identities`/`authz_expectations` is
genuinely novel schema ground for this project; there is no external schema
to adapt wholesale, only a directional precedent.** The one transferable
idea, present in both AuthProbe's identity-config split and this project's
own `provenance.yaml` precedent, is to keep identity/ownership data in a
**separate side file**, decoupled from the manifest cells the verdict
engine consumes — recommended for the same reason `provenance.yaml` is
decoupled: the verdict-deriving code path should not gain a dependency on
data that isn't part of the vulnerable/secure code-generation contract
itself, and ownership metadata is closer to "annotation feeding future test
classes and audit tooling" than to "input the generator or verdict engine
needs today." This reasoning is by analogy to this project's own
architecture, not an external citation — flagged as such, since no
external project could actually settle it.

The first question (Session-manager interaction) remains open and is not a
research question so much as a scheduling one: **[decision needed]** confirm
whether Lab-track Phase 2 can proceed independently of the toolkit's own
Session-manager phase landing, or whether identity groundwork should wait
for it — this needs a look at what Phase 2 actually requires operationally
(does confirming an authz expectation require staying authenticated as two
different identities across a run, which is exactly what the Session
manager provides?) rather than external research, so it's left as a
decision item, not dispatched to a research agent.

With the file-placement question now resolved, write
`docs/LAB_PHASE_2_PLAN.md` at the same granularity as Phase 0/1 above once
the Session-manager scheduling question above is settled, before starting
implementation.

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
is retired once this lands, not kept alongside it). Once a second stack
lands, `labels.json` also gains a `stack` (or `stack_profile`, per
`CR-LAB-0001` §4's naming) field, resolving one of the CR's originally
deferred §7 questions.

**[research complete, 2026-09-21]:** whether `stack` belongs inline in
`labels.json` or in a separate analysis-only file (`CR-LAB-0001` §7). Two
findings converge on the same answer. First, **prior art uniformly inlines
this kind of metadata**: OWASP Benchmark's own `expectedresults.csv` keeps
every per-case field (test name, category, real-vulnerability flag, CWE) in
one flat file, and the multi-language academic vulnerability-dataset
literature (CrossVul, CVEfixes, DiverseVul, ICVul) consistently stores
language/framework identity inline alongside the vulnerability label — no
example of a deliberate schema split for this reason was found. Second, and
more decisively, **the general ML shortcut-learning/spurious-correlation
literature actually favors inlining, not splitting**: it treats the
*statistical correlation a scorer or model actually consumes* as the
leakage vector, never *file co-location* as an independent risk — and the
closest established convention (group-robustness benchmarks like
Waterbirds/CelebA) deliberately stores the spurious/group attribute
**alongside** the class label specifically so group-conditioned audits (like
this project's own χ² fingerprint-independence gate) can be computed
directly, without a join. **Recommendation, adopted: keep `stack` inline in
`labels.json`.** The fingerprint-independence gate's correctness doesn't
depend on file layout either way (it operates on the underlying pairing
regardless), the tool under test sees neither file, and a schema split would
only make the gate's own implementation marginally more awkward (a join
instead of a flat read) for no compensating protection. If a "belt and
suspenders" instinct remains, the cheaper mitigation is a documentation/lint
rule ("no scoring script may branch on `stack`"), not a schema split — that
targets the actual risk (a human misusing the field) rather than file
layout, which the research found no evidence protects against it anyway.
One caveat the research flagged honestly: it could not fetch one
tangentially relevant paper (arXiv, blocked by this environment's egress
proxy) whose abstract mentions a "leakage-aware evaluation mode" for a
similar dataset — worth a follow-up read from an unblocked environment if
this needs to be closed out with full rigor, though the recommendation
above does not depend on it.

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

**[research complete, 2026-09-21]:** confirmed whether FastAPI's `APIRouter`
auto-inclusion means the Python/FastAPI emitter can avoid a `route`-category
accumulator module entirely. **Verdict: by default FastAPI needs the same
accumulator treatment as Laravel/Express, but a project-authored, one-time
discovery scaffold can avoid it.** FastAPI's own documented multi-file
pattern ("Bigger Applications - Multiple Files",
fastapi.tiangolo.com/tutorial/bigger-applications/) requires one new
`import` plus one new `include_router()` line in a central `main.py` per
router module — architecturally identical to Laravel's `routes/web.php` or
Express's `app.js`, confirmed via FastAPI's own GitHub discussion #6903
("Split router across multiple files"), where the community treats
directory-based auto-registration as something you build yourself, not a
first-party feature. **However**, it is straightforward to write a small
(~15-line), static "scaffold" `main.py` using `pkgutil.iter_modules()`/
`importlib` to walk a `routers/` package at import time and call
`include_router()` on everything found — this scaffold is rendered once per
build and never touched per generated cell, so it carries none of the
reshuffling/non-determinism risk an accumulator exists to guard against.
**Decision this research resolves:** treat the FastAPI case as "avoidable
via a one-time static discovery scaffold," not "no accumulator needed by
the framework itself" — i.e., the `route` accumulator module (Addendum D)
still needs to be built for Laravel and Express, but the FastAPI emitter can
skip it by using this static-scaffold approach instead, at the cost of
~15 lines of project-owned (unofficial, not FastAPI-supported) directory-
walking glue whose import-order/error-handling/route-collision behavior the
project itself must define and test.

**[research complete, 2026-09-21]:** Addendum D's `complexity`-as-file-
count-multiplier interaction, flagged as "the first place to expect an
implementation surprise." **No directly relevant prior art was found** —
this appears to be a genuinely novel combination, not a documented pattern,
and the research says so plainly rather than stretching tangential material.
The closest analogues: the **Juliet Test Suite**'s flow variants (01-22
control-flow wrappers, 31+ data-flow variants that do span a primary +
secondary file) use the same "wrapper as a difficulty knob" idea this
project's own module-composition design already generalizes from, but
Juliet never turns file-count into a combinable axis with an ordinal/
continuous dial. **SecCodePLT** and **BaxBench** were also checked and
confirmed off-point (SecCodePLT has no depth axis; BaxBench generates whole
multi-file apps per task via an LLM with no fragment composition, so it has
no complexity axis at all — consistent with this project's own prior
differentiation research). One independent, tangentially supporting data
point: an unrelated benchmark-analysis paper found real-world vulnerabilities
distribute roughly 35% zero-hop / 24% one-hop / 13% two-hop / 7% three-hop
in taint-path length — external validation that "hop count" is a natural
difficulty axis in principle, even though no generator builds it as a
compositional knob today.
**Pitfalls flagged from general multi-file code-generation literature**
(not vulnerability-generator-specific, since none exists on this exact
point): cross-file identifier/naming consistency degrades sharply as file
count grows (one cited study found multi-file edit success dropping from
~19% at one file to ~5% at three-plus); a per-cell explicit symbol/alias map
(the tainted variable's name or its mapping) should be generated once and
passed to every file template for that cell, not left to ad hoc per-file
naming; interface-contract mismatches across layer boundaries (a sanitizer
applied in one file but not visible to a check in another) are a documented
failure mode and argue for a post-generation, per-hop signature/contract
validation pass; accumulator ordering must be sorted by a stable key
(cell ID) at render time, never by append/iteration order.
**Recommendation, adopted into this plan:** do not launch straight into a
continuous file-count-multiplier axis under full covering-array treatment.
**Spike first with two fixed depth levels** (e.g. "shallow":
controller→model, "deep": controller→service→repository→model) for one
vulnerability class/sink/transform combination, specifically to validate
the riskiest new mechanism — a shared taint-plan/symbol-consistency
intermediate representation (materializing the intended file path and the
variable name carried at each hop *before* rendering any file template,
rather than generating files independently and reconciling after) and the
accumulator's deterministic ordering — before generalizing to an N-valued
combinable axis. If the two-level spike is clean, extending to more depth
levels is a parameter change, not a redesign.

**[research complete, 2026-09-21]:** the "all-secure-profile false-positive
contract around framework debug pages" (`CR-LAB-0001` §7, previously
deferred without a resolution date) is now researched, since it becomes
acute exactly when multiple frameworks exist. **Finding: no comparable
prior-art project (DVWA, Juice Shop, WebGoat, OWASP Benchmark) has actually
solved this — it is a genuinely open problem, not something this project
missed finding an existing answer to.** DVWA in fact runs the *opposite* of
a hardened default (`display_errors = On` required for the app to function
at all); Juice Shop folds verbose error output into one of its own graded
challenges rather than treating it as noise; OWASP Benchmark sidesteps the
whole class by not being a full framework app with a debug mode at all
(each test case is an isolated servlet). **What each of this project's
three target frameworks exposes by default, and how to close it:**

| Framework | Default exposure | Disable via | Residual exposure |
|---|---|---|---|
| Laravel | Full stack trace, all env vars (DB/API credentials), file paths, query logs via the Ignition debug page (`APP_DEBUG=true`) | `APP_DEBUG=false` + `APP_ENV=production` | None found beyond the generic 500 page |
| Express | `err.stack` written into the HTTP response by the built-in default error handler | `NODE_ENV=production` (suppresses the built-in handler's stack output) | Only covers Express's *built-in* handler — any custom error middleware the emitter generates must independently avoid leaking internals; `NODE_ENV` doesn't enforce that |
| FastAPI | No single "debug mode" flag; **`/docs`, `/redoc`, `/openapi.json` are enabled by default regardless of any debug setting** and expose the full API schema | `FastAPI(debug=False)` (default) for tracebacks; **separately**, `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` for the schema routes | None found once both are disabled |

The FastAPI row confirms the suspicion behind flagging this at all:
"production mode" alone is not sufficient for every framework — FastAPI
needs an explicit, separate step orthogonal to any debug flag.
**Recommendation, two-layered:** (1) build/run every generated container in
production-equivalent mode by default as a blanket rule, with the FastAPI
docs-routes disable treated as its own named checklist item, not assumed
covered by "production mode"; (2) as a second line of defense, `zap_oracle.py`'s
whole-app "safety net" mode should carry an explicit, reviewed allowlist of
known framework-debug alert IDs, using ZAP's own documented mechanisms for
this — a **rules file** (tab-separated, mapping plugin IDs to
`IGNORE`/`WARN`/`FAIL`, the same mechanism ZAP's baseline/full-scan
automation already uses) or **Alert Filters** (reclassifying alerts matching
a plugin ID/URL pattern as false-positive) — never a broad "ignore
everything unscoped" rule, so a genuine regression (debug mode left on by
mistake) still fails the oracle rather than being silently swallowed. The
exact ZAP alert/plugin IDs that fire on each framework's debug page were
not pinned down by this research (would need empirical confirmation against
real generated cells) — flagged as a small follow-up spike when Phase 3's
first non-PHP emitter is being validated, not before.

Once the pacing decision above is made, the task breakdown is, per stack (in
whatever order the decision picks):
1. `StackEnv` + scaffold files for the new stack (Addendum D's schema).
2. Port/author the module inventory for that stack's shapes (per the pacing
   decision: full class coverage, or Tier-A-only).
3. A conformance-suite pass against the new emitter (T-LAB0.7's suite is
   already stack-agnostic by design — this is the first real test of that
   claim).
4. Digest-pinned base image + lockfile + SBOM for that stack's container.
   **[research complete, 2026-09-21]:** tooling now settled rather than
   left open. **Generate SBOMs with Syft** (Anchore) — mature, CLI-first,
   non-interactive (clean JSON to stdout/file, standard exit codes), scans
   both images and lockfiles, and emits both CycloneDX and SPDX from one
   scan. `docker sbom`/`docker scout sbom` were checked and rejected: the
   old `docker sbom` plugin is deprecated (its repo archived), and
   `docker scout sbom` requires Docker Hub authentication — a real conflict
   with this project's no-cloud-dependency, loopback-only posture. `cdxgen`
   was also checked as an alternative (wider raw ecosystem coverage, newer
   reachability features) but is CycloneDX-only, foreclosing format
   flexibility for no offsetting benefit here. **Record as CycloneDX**
   (not SPDX) — more compact, application-security-oriented rather than
   license-compliance-oriented, and Syft can still emit SPDX later from the
   same scan if ever needed, so nothing is foreclosed by defaulting to
   CycloneDX now. **Digest-pin freshness**: skip Renovate/Dependabot (both
   are CI-service/bot-oriented — genuine overkill for a solo, low-frequency-
   rebuild project with no CI service); instead, use a small local script,
   run on the same quarterly cadence already established for the pattern
   corpus refresh (`docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` §3 step 8):
   `docker pull <image>:<tag>`, diff the resulting digest against the pinned
   one, and surface a manual-review reminder rather than auto-bumping —
   consistent with this project's existing "reviewed, not automated" refresh
   philosophy, and documented as a runbook step
   (`docs/ON_HOST_RUNBOOK.md`-style) rather than infrastructure. **One
   design gap surfaced, not yet resolved:** no existing tool distinguishes
   "this vulnerable dependency version is the deliberate point of a lab
   cell" from "this SBOM entry is a real, unintended supply-chain
   regression" — if a vulnerability scanner is ever pointed at these SBOMs
   as a build gate, the project will need its own allowlist/expected-
   findings file (keyed by CVE + component), designed from scratch; flagged
   here rather than assumed solved, since research found no comparable
   project's convention to borrow.
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

**[research complete, 2026-09-21]:** DOM-based XSS/frontend-code-generation
approach (`CR-LAB-0001` §7, "lean toward hand-written fixtures per the
report, final call later"). **Confirmed, with one refinement.** DVWA, Juice
Shop, and WebGoat were each checked directly: all three hand-author DOM XSS
as a single bespoke vulnerable snippet embedded in realistic app-routing/
component code (Juice Shop's Angular search component bypassing
`DomSanitizer`; DVWA's three difficulty-tier PHP files with independently
hand-written filter logic per tier; WebGoat's Backbone.js router reflecting
a URL parameter) — **no evidence of a templated or generated approach in any
of them**, a consistent pattern across three independently-built projects.
This confirms hand-authoring is the field norm, validating the tentative
call. **Refinement the research recommends:** "hand-written" should mean
"hand-written per sink-type template with an explicit vulnerable/safe swap
point," not "fully independent, twin-by-twin" — none of the three surveyed
projects need this refinement themselves (they're unpaired training apps
with no "secure twin" concept at all), but this project already relies on
the minimal-pair discipline elsewhere and can preserve it here at
negligible extra cost, since there are only ~5-8 sink-type cells total, not
a combinatorial set. **Sink taxonomy to cover** (OWASP's DOM-based XSS
Prevention Cheat Sheet — the single authoritative source found; no separate
academic taxonomy paper exists): `innerHTML`/`outerHTML` (incl. jQuery
`.html()`), `document.write()`/`document.writeln()`, `eval()`,
`setTimeout()`/`setInterval()` with a string argument, `new Function()`,
`location.href`/navigation assignment, and `element.setAttribute()` writing
an event-handler or `href`/`src` attribute — a well-cited core set of 5,
extendable to 7 for solid coverage; CSS sinks (`style.cssText`, CSS
`url()`/`expression()`) are largely legacy/IE-era and can reasonably be
skipped. Suggested concrete shape per cell: a fixed HTML+JS scaffold (fixed
DOM setup, fixed "read tainted value from `location.hash`/`search`"
boilerplate) with a single swapped line — e.g. `el.innerHTML = tainted`
(vulnerable) vs. `el.textContent = tainted` (safe) for the innerHTML cell.

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

Eight research items have now been dispatched to web-enabled research
agents across two passes (four on 2026-09-21's first pass, four more the
same day on a second review pass) and are resolved (marked below); their
findings are folded into the relevant sections above. Items still needing a
human decision (not resolvable by research — they are judgment/scope calls)
remain open, in the order they first become load-bearing:

1. **T-LAB0.9 scope** (§1.1) — **[decision needed]** sweep FUZZ consumers
   before or alongside the schema change? *Recommended: alongside, before
   landing.*
2. **Leakage-probe threshold** (§2.3) — **[decision needed]** per-class or
   one global 0.55-0.60 band, now that Phase 1 will produce the first real
   data to decide it against.
3. ~~Identifier/alias/connector-position SQLi oracle coverage~~ (§2.2) —
   **[research complete]** sqlmap does not reliably detect this shape; build
   a custom differential-response prober alongside `oracle_wrapper.py`
   instead. One residual **[decision needed]**: whether to spot-check the
   verdict against the real installed sqlmap binary before committing to the
   fallback design (recommended, low cost).
4. ~~`authz_expectations` placement~~ (§3) — **[research complete]** no
   external prior art declares ownership/authz as static data at all
   (crAPI/vAPI leave it fully implicit; AuthProbe, the closest academic
   tool, discovers it at runtime rather than declaring it) — this is
   genuinely novel schema ground. Recommendation, by analogy to this
   project's own `provenance.yaml` precedent (not an external citation):
   keep it in a **separate side file**, decoupled from the manifest cells
   the verdict engine consumes.
5. **Toolkit Session-manager dependency** (§3) — **[decision needed]** does
   Lab-track Phase 2 need the toolkit's own Session manager to land first
   (e.g. because confirming an authz expectation requires staying
   authenticated as two identities across a run), or can identity
   groundwork proceed independently? This is an operational question about
   what Phase 2 actually requires, not something further web research can
   resolve — left as a decision item.
6. **Phase 3 pacing** (§4) — **[decision needed]** (a) all three stacks full
   depth, (b) stack 1 full + stacks 2-3 Tier-A, or (c) drop Spring Boot from
   near-term scope. Inform with Phase 1's actual authoring-hours data before
   deciding.
7. ~~FastAPI route-accumulator need~~ (§4) — **[research complete]**
   avoidable via a one-time static discovery scaffold (~15 lines,
   project-owned, not a first-party FastAPI feature); the `route`
   accumulator module is still needed for Laravel/Express.
8. ~~Complexity-as-file-count-multiplier interaction~~ (§4) — **[research
   complete]** no direct prior art exists for this combination;
   recommendation adopted into the plan: spike with two fixed depth levels
   before generalizing to a combinable N-valued axis.
9. **`patterns/` card-authoring schedule** (§1.3) — **[decision needed]**
   not gating, purely a "when do you want to do this" scheduling call.
10. ~~SBOM/digest-pinning tooling~~ (§4) — **[research complete]** generate
    SBOMs with **Syft**, record as **CycloneDX**; pin base-image digests via
    a small local script on the same quarterly cadence as the pattern-corpus
    refresh, not a bot (Renovate/Dependabot are overkill for this project's
    scale). One residual **[decision needed, low priority]**: no comparable
    project's convention exists for distinguishing a deliberately-vulnerable
    pinned dependency from a real supply-chain regression in an SBOM-based
    scan — needs its own allowlist design if a vulnerability scanner is ever
    wired to these SBOMs as a build gate; not urgent, no such gate is
    currently planned.
11. ~~The all-secure-profile false-positive contract around framework debug
    pages~~ (§4) — **[research complete]** no comparable prior-art project
    has actually solved this (DVWA runs the opposite of hardened by design;
    Juice Shop folds it into a graded challenge; OWASP Benchmark sidesteps
    it structurally) — genuinely unsolved territory, not a known-answer gap.
    Recommendation adopted: production-mode-by-default for every generated
    container (with FastAPI's `/docs`/`/redoc`/`/openapi.json` disabled as
    an explicit separate step, since it's on by default regardless of any
    debug flag), plus a reviewed ZAP rules-file/Alert-Filter allowlist as a
    second line of defense. One residual **[decision/verification needed,
    small]**: the exact ZAP alert/plugin IDs that fire on each framework's
    debug page need empirical confirmation against real generated cells —
    a small follow-up spike when Phase 3's first non-PHP emitter is
    validated, not before.
12. ~~Whether `stack` belongs in `labels.json` directly vs. a separate
    file~~ (§4) — **[research complete]** prior art (OWASP Benchmark, the
    multi-language academic vulnerability-dataset literature) uniformly
    inlines this kind of metadata, and the general ML shortcut-learning
    literature actually favors inlining over splitting for this exact
    reason (group-robustness benchmarks deliberately co-locate a spurious
    attribute with its class label specifically to enable the kind of
    conditional audit this project's own χ² gate already performs).
    Recommendation adopted: keep `stack` inline in `labels.json`.
13. **Whether the pattern corpus versions with the manifest or
    independently** (§1.3) — **[decision needed]**, not dispatched for
    research in this pass (this is a pure project-versioning-policy
    question with no external prior art to inform it — a design choice,
    not a research gap). Still open, low priority, no phase currently
    depends on it.
14. ~~DOM XSS frontend-code generation~~ (§5) — **[research complete]**
    confirmed hand-authoring is the field norm (DVWA, Juice Shop, WebGoat
    all hand-author, no templated approach found in any), validating the
    plan's tentative call, with one refinement: use a per-sink-type template
    with an explicit vulnerable/safe swap point (preserving this project's
    existing minimal-pair discipline at negligible cost, since only ~5-8
    sink-type cells are needed) rather than fully independent authoring per
    cell. A concrete 5-8 item sink taxonomy (OWASP's DOM-based XSS
    Prevention Cheat Sheet) is now specified.
15. **Phase 4 SSRF target + GraphQL surface design** (§5) — **deliberately
    not dispatched for research in either pass.** The plan itself states
    this research would be premature ("Phase 4 is far enough out that
    anything decided today would likely be stale by the time it matters");
    spawning a research agent for it now would contradict that reasoning
    rather than honor it. Flagged here, not silently skipped — revisit when
    Phase 3 is close to landing.
