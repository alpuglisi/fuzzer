# CR-LAB-0001 — Manifest generator: real-world grounding, modern stacks, maximal variation

**Status: PROPOSED — pending your approval.** Nothing in this document has been
implemented. This is a change-control-format change request, not a change-control
log entry — it does not get appended to `docs/components/01-target-lab/change-control.md`
until approved and work actually lands (per component, per landed increment, as
`CC-LAB-0011` onward — see "On approval" at the end).

**Date:** 2026-09-21 · **Primary component:** LAB (`01-target-lab/`) · **Secondary
components touched:** FUZZ (`07-fuzzing-harness-and-oracle/`, label-contract
consumer), IND (`06-indicator-db-and-catalogs/`, catalog-boundary question only)

**Source:** `docs/lab-generator-realism-research-prompt.md` (the prompt) and the
research report it produced, *"Realism, Currency and Variation for a
Manifest-Driven Vulnerable-Lab Generator"* (2026-09-21), supplied by you.

---

## 1. What this CR asks you to approve

Adopt the research report's design as the concrete shape of the **already-settled**
manifest-driven lab generator (D8), and commit to a five-phase build order. This CR
governs *strategy and scope*, not line-level implementation — once approved, the
next step (per your instruction) is a separate implementation plan.

This does **not** re-litigate: the generator decision itself (D8), the two-tier
range/shop plan, the build profiles, or the out-of-band opaque-ID label contract
(D9). Those stay as they are.

## 2. Why now (the gap this closes)

The lab today is a single hand-authored PHP 8.3/MariaDB monolith with textbook-style
SQLi/XSS. Per the report's headline warning, generating *more of the same shape* would
just build a bigger version of the thing the SAST-benchmark literature already shows
fails to predict real-world detector performance (~12.7% real-world detection despite
strong synthetic-benchmark scores — EASE '25). The report's five load-bearing
recommendations, which this CR proposes to adopt as-is:

1. Ground new cells in **real, current disclosures** (OSV/GHSA-sourced "pattern
   cards" as provenance, never as a verdict input) instead of textbook payloads.
2. Target **three modern stacks** (Node/TS+Express, Python+FastAPI, PHP+Laravel),
   not eight — chosen for coverage-per-effort, with Spring Boot as an optional fourth.
3. Replace full cross-product cell enumeration with a **pairwise/mixed-strength
   covering array** (NIST ACTS-style) — the single highest-leverage change in the
   report for controlling combinatorial cost while maximizing variation.
4. Add a **leakage probe** as a build gate: a deliberately weak classifier trained on
   response *metadata only* must not exceed ~0.55–0.60 AUC, or the corpus has a
   shortcut and the build fails.
5. Split the determinism guarantee: **hard-guarantee byte-identical source
   emission** (CI-gated), **soft-guarantee digest-pinned + SBOM-recorded**
   containers (not bit-identical images across five language runtimes).

## 3. Change

- Adopt the report's generalized verdict model: `transform` becomes an ordered
  **pipeline** of ops, `sink_context` becomes **structured** (a family + required
  neutralizations), and the safety matrix becomes a table of `(op, context) →
  {neutralises | partial | no_effect | introduces}` effects. The verdict stays
  **derived**, never asserted — this generalizes D8/D9's existing derivation model,
  it does not weaken it.
- Adopt a **polyglot-core, per-stack-emitter** architecture: one resolver/IR/verdict
  engine, with Node/Express, Python/FastAPI, and PHP/Laravel as emitters (existing
  PHP app becomes the third emitter's target, migrated in Phase 3). Java/Spring Boot
  and one or two hand-written Next.js fixture cells are optional, Phase-4-or-later.
- Adopt the **identity/ownership model** (`identities`, `authz_expectations`) as a
  required addition — without it, IDOR/BOLA cells are unlabelable in principle.
- Adopt a **`patterns/` provenance corpus** fed by OSV.dev + GitHub Security
  Advisories, hand-triaged into abstract pattern cards (`id`, `class`, `stack`,
  `sink_family`, `root_cause` in our own words, `source_url`, `published_date`).
  Cards document *why* a cell exists; they are never read by the verdict function.
- Adopt the **combinatorial-variation controls**: covering-array expansion (t=2
  default, mixed t=3 on `(class, sink_context, transform)`), a minimal-pair
  invariant enforced mechanically (vulnerable/secure diff must touch only the
  transform region), χ² independence checks on nuisance axes, and fingerprint-
  independence constraints across stacks (every class in ≥2 stacks; every stack
  carries ≥3 classes) so the corpus can't teach "stack ⇒ class" as a shortcut.
- Adopt the phased build order in §5 below, gated in the order given — most
  importantly: **the verdict-pipeline model (0.1) must land before any second
  emitter (3.x)**, or the atomic model gets baked into three codebases.
- Retire the current-lab-as-endpoint approach to SQLi/XSS realism in favor of
  identifier/alias/connector-context SQLi and escaping-context-mismatch XSS — this
  is flagged in the report as the single highest value-per-hour item and requires
  no new stack (Phase 1.4).
- Rename the `references/graphql-injection` framing area (not the folder
  necessarily — a documentation/schema decision, not a deletion) toward
  introspection/aliasing/depth-limit/resolver-BOLA, matching what's actually
  disclosed in the wild.

## 4. Impact (other components / project)

- **LAB (primary):** `01-target-lab/requirements.md` gets new/superseded
  functional requirements for the pipeline verdict model, the stack-profile axis,
  the identity model, and the covering-array/leakage-probe build gates.
  `docs/ARCHITECTURE.md` §1 and the Lab-track phase list in
  `docs/DECISIONS_AND_ROADMAP.md` need updating to reflect this as the concrete
  shape of D8 (proposed as a new decision, D20 — see §6).
- **FUZZ (`07-fuzzing-harness-and-oracle/`):** the label-contract schema gains
  `stack_profile`, `sink_endpoint` (distinct from `injection_endpoint`), and the
  `identity_model`/`authz_expectations` blocks. The harness and oracle, which
  consume `labels.json`/`expectedresults.csv`/`injection-points.json`
  (`fuzzlab/labels/contract.py`, `fuzzlab/harness/*`), need their schema
  validators and consumers extended — additive fields, but `sink_endpoint` as a
  distinct concept from `injection_endpoint` is a real contract change for
  stored/second-order cases. Existing consumers must treat unknown/new fields
  as optional until this lands, so the current single-stack contract keeps
  validating unchanged in the interim.
- **IND (`06-indicator-db-and-catalogs/`):** boundary question, not yet decided —
  does the new `patterns/` provenance corpus live under LAB or under IND
  alongside `references/`? They serve different consumers (generator-design
  input vs. runtime payload catalogs for the scheduler/fuzzer). Recommend LAB
  ownership since patterns feed manifest authoring, not runtime tooling — open
  for your call in §7.
- **Project-wide:** container topology grows from one app + one DB to (at
  steady state) 3-4 app containers + 2-3 databases + a seeded internal-only SSRF
  target, all still loopback-only/no-egress. Build/regeneration time grows
  materially (multi-runtime image builds); Phase 0's source-only vs.
  container-rebuild split exists specifically to keep the fast local loop fast.
- **Safety invariants (D11, D7, no-leak):** unchanged in spirit, strengthened in
  enforcement — several conventions (loopback binding, no-egress app network,
  no vuln-class-name leakage) move from documented convention to **generator
  build-gate tests**, which the report treats as necessary once manual review
  stops scaling past ~100 cells.

## 5. Risk assessment

**Overall risk: medium**, concentrated in three places, each with its mitigation
already designed into the plan above:

1. **Scope creep into a "second project."** A 3-stack polyglot generator with
   covering arrays, identity graphs, and a pattern corpus is a substantially
   larger undertaking than the current lab. *Mitigation:* the phased plan is
   ordered so each phase is independently useful and stoppable — Phase 1 (variation
   on the existing PHP stack) delivers real value with zero new containers before
   any multi-stack work starts. The report's explicit "don't build" list (LLM
   injectors, all 64 reference categories, generated HTTP smuggling, deep XXE,
   bit-reproducible multi-runtime images, a 5th/6th stack) bounds the ceiling.
2. **Label-contract churn breaking existing FUZZ consumers.** *Mitigation:* additive
   schema fields, versioned safety matrix (`verdict(pipeline, sink_context,
   matrix_version)` as a pure, snapshot-tested function), and the existing
   `manifest_version`/`safety_matrix_version` fields already in the design keep
   old corpora re-derivable under old rules.
3. **New leakage risk introduced by going multi-stack** (framework fingerprinting —
   e.g. "every Flask cell is SSTI" teaches `Server: Werkzeug` ⇒ SSTI instead of the
   real signal). *Mitigation:* the fingerprint-independence build gates
   (`min_stacks_per_class`, `min_classes_per_stack`, χ² independence of `stack`
   from `class`/`verdict`) are adopted as mandatory, not optional, in §3.

**Accepted risk:** the leakage-probe threshold (0.60 AUC) and several of the
report's open questions (§7) are judgement calls without settled prior art. We
proceed on the report's recommendation and treat the threshold as revisable per
class once real corpus data exists, rather than blocking the whole CR on
resolving it perfectly up front.

## 6. Proposed new decision record

Recommend adding **D20** to `docs/DECISIONS_AND_ROADMAP.md` (only on approval),
stating: *the manifest-driven generator (D8) is realized as a polyglot core with
per-stack emitters (Node/TS+Express, Python+FastAPI, PHP+Laravel, +Spring Boot
optional), a pipeline-valued transform model with a structured sink-context safety
matrix, an OSV/GHSA-sourced provenance corpus, and mandatory covering-array,
minimal-pair, and leakage-probe build gates — order and scope per CR-LAB-0001.*
This keeps D8 itself intact (it's the "why"), while D20 pins down the "what,"
consistent with how D16/D17 already record specific built mechanisms (WAF, h2→h1
downgrade) under the same lab track.

## 7. Decisions I need from you before/at approval

The report flags ten open questions; most can be deferred to the implementation
plan or to whichever phase first needs an answer. Three are scope-gating and I'd
like your call now, since they change what Phase 0/1 actually build:

1. **Binary or three-valued verdict?** The report recommends treating `partial`
   neutralization as VULNERABLE-but-harder (feeding a `difficulty` tier) rather
   than introducing a third `hardened` verdict value. This is the most
   consequential open call in the report — it shapes the oracle, the CSV schema,
   and every metric downstream. **Recommend: accept the binary-verdict
   recommendation** (simpler, keeps existing binary-detector scoring intact);
   flag if you'd rather explore three-valued.
2. **Fate of the existing hand-built PHP app.** Migrate its content into the
   generator (Phase 3.6, loses its hand-authored character) vs. keep it
   permanently as a Tier-0 fixture alongside generated tiers (more honest, costs
   maintaining two things). **Recommend: migrate** — consistent with D8's original
   "stop hand-adding pages" consequence — but this is genuinely your call.
3. **Does `patterns/` live under LAB or IND?** See §4. **Recommend: LAB**, since
   it's generator-design provenance, not a runtime payload catalog.

The remaining seven (deferrable to the implementation-planning stage or to the
phase that first touches them): whether `stack` belongs in `labels.json` directly
vs. a separate analysis-only file; per-class leakage-probe thresholds vs. one
global threshold; whether `context_depth` should split into lexical-distance and
temporal-distance axes; how a cell vulnerable only in combination with another
cell (e.g. a signing-key write/read pair) gets its label attached; the
all-secure-profile false-positive contract around framework debug pages; whether
the pattern corpus versions with the manifest or independently; and whether/how
to generate frontend code for DOM XSS (lean toward hand-written fixtures per the
report, final call later).

## 8. Deliverables (phase-level; task-level detail deferred to the implementation plan)

All `todo`, pending approval. Phase order matters — see the dependency note under
Phase 3.

- [ ] **Phase 0 — Foundation.** Pipeline verdict model + structured sink contexts
      + versioned, snapshot-tested `verdict()`; sub-seed derivation + canonical
      serialization + regenerate-and-diff CI gate; name-leak scanner as a build
      gate; `patterns/` corpus seeded with 25-30 cards for the first-wave classes.
- [ ] **Phase 1 — Variation on the existing stack.** Covering-array expansion
      (constraints + mixed strength); minimal-pair invariant enforced
      mechanically; χ² balance assertions + leakage probe as build gates; rebuild
      the current PHP SQLi/XSS cells around identifier/alias/connector and
      escaping-context-mismatch shapes (no new containers — highest value/hour
      item in the report); stratified splits + de-duplication + diversity
      reporting.
- [ ] **Phase 2 — Identity and depth.** Identity/ownership model +
      `authz_expectations` (unlocks IDOR/BOLA); `sink_endpoint` distinct from
      `injection_endpoint` (unlocks stored/second-order); parameter
      location/encoding axis; `context_depth` axis (0-4).
- [ ] **Phase 3 — Multi-stack.** IR + emitter interface + conformance suite
      (written *before* the second emitter); Node/Express+Prisma/Knex+Nunjucks
      emitter; fingerprint-independence build gates; Python/FastAPI+SQLAlchemy+
      Jinja2 emitter; digest-pinned bases + lockfiles + SBOM recording;
      PHP/Laravel+Eloquent+Blade emitter (migrating the existing app, pending
      §7.2).
- [ ] **Phase 4 — Realism tier and beyond.** Shop tier (6 business objects,
      ownership graph, 4-step checkout); webhook/callback + seeded internal SSRF
      target + no-egress network policy; limit-overrun/race-condition counters
      with configurable windows; OpenAPI + GraphQL surfaces; hand-written Next.js
      fixture cells; optional Spring Boot emitter.

## 9. Explicitly out of scope (per the report's "hype and effort flags")

Not building, and not part of any phase above unless you override: an
LLM-based vulnerability injector; cells for all 64 `references/` categories
(target ~18 well-built classes against the CWE Top 25 / OWASP 2025
intersection instead); generated HTTP request smuggling as an app-level class
(it's a proxy-topology property, not an application one); deep XXE investment;
a bit-reproducible-images promise across runtimes; a 5th or 6th stack.

## 10. Effectiveness

Pending — not assessable until phases land. Per-phase effectiveness will be
recorded in the real `CC-LAB-00NN` entries created as each phase's deliverables
complete, per the standard change-control process.

---

## On approval

Once you approve (all of it, or a subset — tell me which phases/decisions to
adjust), I will, in order: (1) add D20 to `docs/DECISIONS_AND_ROADMAP.md` and
update the Lab-track phase list; (2) update `docs/ARCHITECTURE.md` §1 and
`01-target-lab/requirements.md` to reflect the new target shape; (3) add a
`CHANGELOG.md` line and the first real `CC-LAB-0011` change-control entry
recording this decision (status: decided, deliverables in progress); (4) then,
per your instruction, we move to discussing the actual implementation plan for
Phase 0.

---

## Addendum A (2026-09-21) — provenance architecture correction

This CR is append-only per this project's own change-control convention, so
this is a dated addition, not an edit to §6's original text above.

A follow-on research pass validating `LAB_PATTERN_CORPUS_SOURCING_PLAN.md`
(the T-LAB0.8 methodology) found that §6's manifest sketch is built the wrong
way round. §6's example has each cell carry `id_ref: pattern://ghsa-...`
— a reference **from** the functional manifest **to** the provenance corpus.
Provenance-separation prior art (the in-toto attestation model, SLSA
provenance) is explicit that an artifact must be unchanged by whether
provenance for it exists; a manifest cell that carries a card reference,
even one `verdict()` is written to ignore, means the verdict engine's input
type is not actually independent of the provenance corpus — a future
refactor could break that separation without any test noticing, since
nothing stops a later change from reading the field.

**Correction:** provenance moves to a separate, one-directional index,
`lab/patterns/provenance.yaml`, mapping `cell_id → [card_id, ...]`. The
manifest the verdict engine reads carries no card reference at all. A build
gate asserts no card ID or `pattern://`-style string appears anywhere in the
manifest or in the verdict module's source — the same shape as the existing
name-leak scanner (§3's other build gates are unaffected).

This changes §6's illustrative YAML only — it does not change §3's core
change (pipeline verdict model, structured sink contexts), §5's risk
assessment, or §8's phase-level deliverables, beyond T-LAB0.1's manifest
loader now needing to not expose a provenance field to the verdict path (a
detail-level addition to that deliverable, not a new one). See
`LAB_PATTERN_CORPUS_SOURCING_PLAN.md` §0 and §4 for the full reasoning and
the revised file layout.

---

## Addendum B (2026-09-21) — multi-artifact ground truth resolved

Resolves §7 item 2 ("how do you label a cell that is vulnerable only in
combination with another cell?"), left open at CR approval time. A Phase 0
tooling-research pass looked at how NIST/SARD's Juliet test suite and the
SARIF 2.1.0 standard both already solve this, rather than inventing a new
scheme.

**Finding.** Juliet's unit of ground truth is the **test case**, not a
single location: each case names `BadSource`/`GoodSource`/`BadSink`/
`GoodSink` roles plus an enumerated flow variant, and the higher variants are
explicitly cross-method/cross-file/cross-class. SARIF 2.1.0 serializes this
shape without breaking a one-row-per-finding contract: one primary
`locations` entry (conventionally the sink), any other locations in
`relatedLocations`, and an ordered `codeFlows` array when the path between
them matters.

**Decision:** adopt the same shape (**Option B** of three considered — see
`LAB_PATTERN_CORPUS_SOURCING_PLAN.md`'s companion tooling report for the
full comparison against a synthetic-pair-ID row type and a two-rows-linked-
by-case-ID scheme, both rejected). A cell whose ground truth spans two
artifacts stays **one row**: `expectedresults.csv` gains
`primary_endpoint`/`primary_role`/`related_endpoints` (a list of
`{endpoint, role}`, roles drawn from `source | propagator | sanitizer |
sink`) and `flow_variant` (the existing `context_depth` axis, named the way
Juliet names it: `direct`, `same_file_helper`, `cross_file`,
`stored_second_order`, `cross_service`). The tie-break rule for which
location is primary when it's ambiguous (the signing-key case: where the key
is set, or where it's trusted?): **primary is always the location where the
untrusted value reaches the dangerous operation** — for a signing-key pair,
that's where the key is *trusted*, not where it's set. This rule is written
down once here so it never needs re-deciding per cell.

**Consequence accepted, stated plainly:** a detector that finds only the
non-primary location of a pair (e.g. the stored-XSS write endpoint but not
the read/render endpoint) scores zero on that case under this scheme — that
is judged correct (finding an injection point without finding where it
executes isn't a detection of the stored vulnerability), not a scoring gap.
`related_endpoints` retains enough structure that partial credit could be
added later as a scorer change, without a schema migration, if this judgment
is ever revisited.

This is recorded here as a decision (§7 item 2 is no longer open) and in
`LAB_PHASE_0_PLAN.md` T-LAB0.9 as the concrete schema change, forward-
compatible starting in Phase 0 even though Phase 0 itself has no
multi-location cells yet.

---

## Addendum C (2026-09-21) — module composition, authoring workflow, and a realistic effort number

A research pass on vulnerable-code authoring feasibility (answering: can we
actually produce the code, at scale, from what we can legally source?) found
a public-domain/MIT reference architecture that changes how the emitter
should be built, and produced the first grounded effort estimate this
program has had. Recorded here because it changes real scope/timeline
inputs to §8's phased plan, not because it changes §3's core decisions.

**1. Architecture change: the emitter's internal model adopts NIST VTSG's
module-composition schema, not a monolithic per-cell template.** NIST's
Vulnerability Test Suite Generator (NISTIR 8493, MIT-licensed,
`usnistgov/VTSG`) is — measured, from a cloned copy — a manifest-driven
generator with the same shape as ours (inputs × filters × sinks ×
complexities, ACTS covering-array selection), and it demonstrates a ~122:1
leverage ratio: 65 hand-authored PHP modules compose into 7,920 combinations.
**The unit of authoring effort is the module (a source/transform/sink
fragment), not the "template pair."** T-LAB0.4's emitter interface should
internally decompose a cell's rendering into these composable pieces rather
than one template per `(class, sink_context, stack)` combination. VTSG's
own code is not reusable for us (its PHP is procedural, not Laravel/Eloquent/
Blade idiom, and its verdict model is *asserted* per module rather than
*derived* — ours stays derived, which is strictly better and already
correct). Its **schema, module inventory, and safety-declaration model are
the thing to study** (read NISTIR 8493 before implementing T-LAB0.4's
internals) — not its templates.

**2. A grounded effort estimate, replacing an unstated assumption.**
Calibrated against VTSG's measured module counts and published
benchmark-construction team sizes (SecCodePLT, CASTLE): roughly **~330 hours
for the first stack** (including one-time harness/emitter/oracle-runner
cost) and **~180 hours per additional ported stack**, i.e. **~450–520 hours
for three stacks with disciplined LLM-assisted porting** (~650–750
unassisted). A fourth stack is a further ~150–180 hours. These are
judgment-calibrated estimates with a stated ±40% band, not measurements —
see the report's own gap #1, which recommends timing three real seed
authoring sessions before trusting the schedule.

**Decision needed from you, not resolved by this addendum:** this doesn't
reduce anything already planned (CR-LAB-0001's additive-only mandate is
unaffected — nothing built is removed), but it does mean the **pace** at
which new stacks arrive in Phase 3/4 should be set with this number in view.
Options, none of which are default — your call: (a) proceed with three
stacks as planned, accepting an ~8-month solo timeline at 15h/week; (b)
build stack 1 (PHP/Laravel) to full depth and stacks 2–3 to Tier-A-only
depth (well-documented classes only, deferring the deliberately-hard
identifier/alias/connector-position cases on those stacks until later),
roughly halving stacks 2–3's cost; (c) treat the optional fourth stack
(Spring Boot) as explicitly out of near-term scope rather than "optional
Phase 4" per the original CR-LAB-0001 §4 wording. This does not need
resolving before Phase 0 starts — Phase 0 is single-stack — but should be
decided before Phase 3 is scheduled.

**3. Authoring workflow rule, mirroring the existing pattern-card rule.**
Per the report's reading of SecCodePLT's published methodology (expert
authors a seed plus its own oracle assertions; an LLM only mutates/ports
from there, filtered by the seed's oracle, with failures regenerated, never
accepted on faith): **a human authors every seed's oracle assertions and
safety-matrix entry; an LLM may only draft candidate modules and port them
between stacks, and never sees the pattern-card text while doing so** (the
card is provenance for the cell's existence, not a code specification — it's
underdetermined as one, and reading it while drafting code would blur the
licensing separation the pattern-corpus work deliberately maintains). This
is the code-authoring analogue of the already-established rule that an LLM
may label a pattern card but never author its `root_cause` text.

**4. Static pre-checks are reframed from "detect the vulnerability" to
"assert the module is shaped as intended."** A taint analyzer (Psalm+
`psalm/plugin-laravel` for PHP — CodeQL doesn't support PHP; Semgrep for
Python/Node) cannot validate the deliberately-hard cells this program cares
about (identifier/alias/connector-position injection looks identical to safe
code to a taint engine), so a clean scan is evidence for textbook cases only.
Each `(class, sink_context)` entry in the safety matrix gets a
`static_precheck: informative | uninformative` flag; the pipeline **skips**
uninformative checks rather than treating a clean-but-meaningless scan as
confirmation. The actually load-bearing use of a tool like Semgrep is
writing one bespoke "shape" rule per seed asserting the vulnerable module
contains the intended sink and the secure twin contains the intended
transform — a conformance check, not a vulnerability detector.

**5. Fast-feedback tiering for the emitter conformance suite (T-LAB0.7),
with one hard trap flagged.** A tiered check (lint/diff → in-process
functional+security test → full container oracle → whole-lab regeneration)
keeps authoring iteration fast without ever recording a fast-tier pass as
oracle confirmation — only the full container-based oracle confirms a label.
**The trap:** substituting in-memory SQLite for the real database in the
fast tier produces dialect-dependent false passes/fails for SQL-injection
cells specifically (identifier-position injection behaves differently across
SQL dialects) — the fix is app-in-process, database in a long-lived
container booted once per authoring session, never a full stack rebuild per
edit but never a different database engine either.

None of this changes Phase 0's scope (still single-stack, still reproducing
today's PHP lab) — it changes how T-LAB0.4's internals should be designed
now so Phase 1/3 authoring doesn't hit a module-vs-template rework later,
and it sets honest expectations for Phase 3's timeline per point 2 above.
