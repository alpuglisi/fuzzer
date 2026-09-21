# Lab generator — implementation plan for the remaining work

**Status: active, building — 15 of 16 flagged items decided, Phases 0-3
fully task-broken-down with a parallel lane map, 2026-09-21.** This is a
task-level plan, in the style of `docs/LAB_PHASE_0_PLAN.md`, covering
everything **after** the point Phase 0 has actually reached (as of
`CC-LAB-0028`) through the rest of `CR-LAB-0001` §8's phase list. It does
not re-litigate anything already decided (D20, Addenda A-E) — it sequences
what is left, names what each task actually requires, and records every
decision made along the way rather than building through an open question
speculatively. Eight research items were dispatched to web-enabled research
agents across two passes (four per pass, each with its own purpose-built
prompt); their findings, plus the project owner's decisions on every
resulting and originally-flagged judgment call, are recorded inline in the
relevant sections and summarized in §6. One item remains genuinely open
(Phase 4's SSRF/GraphQL design passes, deliberately left unresearched as
premature) — see §6's "Still open" list. §7 maps every Phase 0-3 task to a
build lane with real dependencies and a wave number, sized for maximum
concurrent agent dispatch under this project's standing multi-lane
orchestration policy — Phase 4 is excluded from that map, per §5's own
reasoning for staying at milestone granularity.

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

Everything in Phase 1-3 below is **not started** but now has an executable
task breakdown (§2-4) plus a lane/dependency map (§7) — CR-LAB-0001 §8
records these at phase granularity only ("task-level detail deferred to the
implementation plan"); this document is that detail. Phase 4 is deliberately
left at milestone granularity (§5) — writing it out further before Phases
1-3 land and the race-condition/business-logic gap-class decision is
revisited would mostly be guessing, per §5's own reasoning. Where a task's
exact design is still underdetermined (e.g. Phase 2's identity schema),
this document commits to a concrete first draft rather than leaving a
placeholder, flagged as revisable during implementation, not as blocking.

---

## 1. Finish Phase 0

### 1.1 T-LAB0.9 — Regression/additive-only gate **[decided: option (b)]**

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

**Decided (2026-09-21): option (b).** Do the FUZZ-consumer sweep first (a
`Case` dataclass extension in `fuzzlab/labels/contract.py` plus a read of
every consumer of `GroundTruth.cases`) as part of this same task, so the
schema and its consumers land together — not (a), which would add the four
CSV columns now and defer the consumer sweep to whoever next touches the
harness. Rationale: `CR-LAB-0001` itself calls this a FUZZ-touching change,
and Addendum B's whole point (the SARIF/Juliet one-row-per-finding shape) is
only correctly honored if a consumer that currently assumes one row = one
location doesn't silently mis-score a multi-location case once one exists.
This is the one item in this plan closest to a genuine cross-component
review, not just a LAB-internal build.

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

**Decided (2026-09-21): schedule the card-authoring pass after the rest of
the build is done.** It is not gated on anything else in this plan, and
nothing else in this plan is gated on it reaching 25-30 cards (Phase 1's
`patterns/` consumption is citation-only, never a `verdict()` input, so a
smaller corpus doesn't block Phase 1's other work — it just means fewer
cells carry a card citation until more are written).

**Versioning, decided (2026-09-21): the pattern corpus versions
independently of the manifest, never in lockstep.** This follows directly
from a principle already adopted in Addendum A (provenance separation): a
manifest cell carries zero reference to any pattern card, only a
one-directional `provenance.yaml` index the verdict engine never reads.
Coupling the corpus's own version number to the manifest's version number
would reintroduce a dependency between the two artifacts at the
version-number level, even though their content is deliberately decoupled
— and would force a pointless corpus version bump every time the manifest
schema changes for a reason that has nothing to do with the corpus (e.g.
Phase 2's identity-model addition). The mechanism for independent
versioning already exists and needs no new machinery: `REFRESH_LOG.md`
(commit SHA + date per quarterly pull), each card's own stable ID, and a
`superseded_by` pointer for corrections. No action item follows from this
beyond continuing to use what's already built.

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
  fully fetched due to this environment's network proxy. **Decided
  (2026-09-21): spot-check against the actual installed sqlmap binary
  before committing to the fallback design**, per PA-0005's own "verify
  against the real tool" convention — do this check first, as the very
  first step of this task, before writing `oracle_wrapper.py`'s
  identifier-context sibling module.

### 2.3 Wire χ² balance + leakage probe as required build gates
Both `fingerprint_gate.py` and `leakage_probe.py` exist as reference
implementations, deliberately not build-gating yet (no real variation to
check). Once 2.1/2.2 produce a manifest with real cell-count variation
across classes/transforms:
- Add both to `--check` (from T-LAB0.10) as required, not optional, steps.
- **Decided (2026-09-21): per-class thresholds**, not one global 0.55-0.60
  band. `leakage_probe.py`'s tests already group by generating-rule ID, so
  per-class thresholds extend the existing structure rather than adding new
  machinery. Concretely: implement `PER_CLASS_FEATURE_EXCLUSIONS`-style
  per-class threshold overrides now, but since this phase is the *first*
  point real corpus data exists to calibrate against, treat the initial
  per-class values as provisional — set from the report's 0.55-0.60 band as
  a starting point per class, then revisit each class's number once Phase 1
  produces enough real cells to compute the permutation-null distribution
  properly. Document the provisional-vs-calibrated status of each
  threshold in the gate's own report output so a future pass can tell which
  numbers still need revisiting.

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

**Decided (2026-09-21): Lab-track Phase 2 proceeds independently of the
toolkit's own Session-manager phase.** The two are easily conflated but
serve different consumers: the toolkit's Session manager is infrastructure
for *tools attacking the lab* (a crawler/fuzzer staying authenticated as
`anonymous`/`user`/`admin` across an adversarial run, with re-auth, JWT
handling, and auto-exclusion of auth endpoints) — Phase 2's actual need is
narrower: the *build-time oracle* confirming a cell's verdict (e.g. a
stored-XSS cell submitted as one identity and observed elsewhere) only ever
needs to hold two or three **known, generator-controlled** test-account
cookies at once, not defend against an unknown target. This is closer in
scope to `oracle_wrapper.py`'s existing `refresh_session` callback than to
the full toolkit Session manager. **Task addition for Phase 2:** build a
small, Lab-track-owned session helper (named test identities + a cookie
jar, nothing more) as part of Phase 2's own oracle-confirmation code, rather
than depending on the toolkit's Session-manager phase landing first. The
full toolkit Session manager remains relevant later, once the toolkit's own
tools are pointed at a multi-identity-aware lab for actual IDOR/BOLA
testing — but that class of cell stays deferred indefinitely (Addendum E)
regardless, so it is not on Phase 2's own critical path.

With both open questions now resolved, task breakdown follows, at the same
granularity as Phase 0/1 above.

### 3.1 Identity/ownership schema — `lab/identities/identities.yaml`

New file, new loader module. First-draft concrete schema (this is genuinely
novel ground per the research above — refine field names during
implementation if a cleaner shape emerges, but do not skip writing one down
before starting):

```yaml
schema_version: 1
identities:
  - id: user_a
    role: standard_user
  - id: user_b
    role: standard_user
  - id: admin_a
    role: admin
resources:
  - resource_id: profile_user_a
    owner: user_a
    cell_ids: [LABGEN-...]      # which generated cells this resource maps to
authz_expectations:
  - cell_id: LABGEN-...
    endpoint: /profile/{id}
    accessing_identity: user_b   # the identity making the request
    target_resource: profile_user_a
    expected_outcome: denied     # allowed | denied — binary, matches D20's
                                  # binary-verdict convention
```

- New module `fuzzlab/labgen/identity.py`: `Identity`, `Resource`,
  `AuthzExpectation` frozen dataclasses; `load_identities(path) ->
  IdentityGraph`; JSON-Schema-validated the same way `schema.py` validates
  manifests (`lab/schemas/identities.schema.json`). Deliberately reads
  nothing the manifest cells reference and is never imported by
  `verdict.py` — mirrors `provenance.yaml`'s separation, per the decision
  above.
- Tests: schema validation (missing/malformed fields raise
  `ManifestError`-style typed errors, not raw `KeyError`); a round-trip
  load of the example above; a duplicate-`id`/`resource_id` check (fail
  loud, matching `load_labels`'s duplicate-`case_id` convention).

### 3.2 LAB-owned session helper — `fuzzlab/labgen/identity_session.py`

- A small session-holder: named test identities from `identities.yaml` +
  one cookie jar per identity, with a `login(identity_id) -> Session`
  method the build-time oracle confirmation code calls. Mirrors
  `oracle_wrapper.py`'s `refresh_session` callback shape (a `Callable[[],
  Mapping[str, str]]`) rather than inventing a new session-management
  pattern.
- Explicitly out of scope: re-auth on expiry, JWT handling, auto-exclusion
  of auth endpoints — those are the toolkit's own Session-manager
  concerns, not this helper's, per the decision above.
- Tests: fake HTTP layer (no real server needed, same convention as
  `oracle_wrapper.py`'s injected-runner tests) proving two identities'
  cookies stay isolated from each other across sequential logins.

### 3.3 `sink_endpoint` distinct from `injection_endpoint`

- Extend `fuzzlab.labgen.schema.Cell` with an optional `sink_endpoint:
  Route | None` (reuses the existing `Route` type `schema.py` already
  defines for the injection-point route) — `None` for a same-endpoint
  cell (today's entire corpus), populated only for stored/second-order
  cells.
- No change to `verdict.py`'s derivation logic — `sink_endpoint` is
  render/tracking metadata, the same category as `identity.py`'s data,
  not a verdict input.
- `php_current`'s module registry gains a `read_stored_field`-style source
  already built (`CC-LAB-0022`) — confirm it composes with a `sink_endpoint`
  cell without new module categories; only add a new module if composing
  reveals a genuine gap, per this project's own "extend, don't rebuild"
  convention.
- Tests: a hand-built stored-XSS cell (write endpoint ≠ sink endpoint) round
  trips through `schema.py` and renders correctly with `php_current`.

### 3.4 Parameter location/encoding axis

- Extend `SinkContext` or add a new `Cell`-level field (decide during
  implementation which is the better fit — `SinkContext` if the encoding
  affects what neutralizes it, a separate `Cell` field if it's orthogonal)
  for parameter location (`query | body | header | cookie | json`) and
  encoding (`raw | url_encoded | double_url_encoded | base64`).
- Wire as a new resolver axis (reuses 2.1's axis-range mechanism directly
  — this task is much smaller if 2.1 has already landed, though it does
  not strictly require it: a small manifest can still list encoding
  variants explicitly, the way Phase 0 manifests list everything
  explicitly today).
- Tests: an encoded-parameter cell's oracle confirmation still succeeds
  (the oracle wrapper must decode/re-encode correctly — check
  `oracle_wrapper.py`'s existing header/cookie handling before assuming
  new code is needed here).

### 3.5 `context_depth` axis (0-4) wired into the manifest/`Cell` IR

- Addendum B already named the values (`direct`, `same_file_helper`,
  `cross_file`, `stored_second_order`, `cross_service`) and T-LAB0.9 (§1.1)
  already added `flow_variant` to the **ground-truth** `Case` — this task
  is the matching addition to the **generator-input** `Cell` IR, so a
  manifest can declare which depth a cell should be generated at, not just
  record it after the fact.
- On the single-stack PHP corpus, only `direct`/`same_file_helper`/
  `cross_file`/`stored_second_order` are reachable (`cross_service` needs
  ≥2 stacks — Phase 3). Scope this task to those four; a `cross_service`
  cell type is Phase 3's concern once a second stack exists.
- Tests: one cell per reachable depth value, each rendering and confirming
  correctly; a value outside the four reachable ones raises rather than
  silently rendering something meaningless for a single-stack corpus.

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

**Decided (2026-09-21): option (b).** Addendum C's calibrated effort
estimate is ~330h for the first new stack, ~180h/stack after, i.e.
~450-520h disciplined/~650-750h unassisted for all three stacks. Three
options were given:
- (a) all three stacks to full depth (~8 months solo at 15h/week);
- **(b) — adopted: stack 1 to full depth, stacks 2-3 to Tier-A-only depth**
  (well-documented classes only, deferring identifier/alias/connector-
  position cases on those stacks), roughly halving stacks 2-3's cost;
- (c) treat the optional fourth stack (Spring Boot) as explicitly out of
  near-term scope.

**(c) was not decided** — the choice of (b) is about how deep stacks 2-3 go,
not whether the optional fourth (Spring Boot) stack is in scope at all;
these are separable questions and only (b) was confirmed. Treat Spring
Boot's near-term status as still open until explicitly decided.

**Consequence of choosing (b), stated plainly per the earlier "does this
lock us in" question:** it does not — upgrading a Tier-A stack to full
depth later is additive (new modules/safety-matrix rows/cells layered onto
what already exists), not a rewrite, per this project's own established
module-composition convention and the whole-manifest regression tests
(T-LAB0.7 Tier 3, `PA-0024`) that exist specifically to catch a regression
when a stack's supported shapes widen. Choosing (b) defers the harder-shape
authoring and per-dialect oracle work for stacks 2-3, it does not eliminate
it — budget for that work to still land whenever/if those stacks are
later upgraded to full depth. Per Addendum C's own recommendation ("time
three real seed authoring sessions before trusting the schedule"), use
Phase 1's actual cell-rebuild hours (§2.2 above) to sanity-check this
pacing once that data exists, rather than treating (b) as unrevisable.

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

**Working assignment of "stack 1" (the one decision (b) leaves unnamed):
PHP/Laravel.** The pacing decision says "stack 1 to full depth, stacks 2-3
Tier-A-only" without naming which is which — resolved here as a working
default, not a new open decision: PHP/Laravel is already mandated to reach
full page coverage regardless (D20 §7.2's migration requirement means every
real `puppy-fort-factory/` page, hard shapes included, must eventually be
reproduced before the hand-built app can be retired), so assigning it "full
depth" costs nothing extra — the work was required either way. Node/Express
and Python/FastAPI take Tier-A-only depth. Override this assignment before
starting if a different stack should go first for some other reason (e.g.
wanting Node/Express's full depth sooner) — nothing below depends on this
particular choice except which stack's task list says "full" vs "Tier-A."

**Each stack below is a fully independent build lane.** All three share
only read-only inputs already built (the `Emitter` ABC, `EmittedFiles`,
`fuzzlab.labgen.schema`'s `Cell`/`SinkContext` IR, the conformance suite) —
no stack's emitter package imports another's, and each gets its own
`fuzzlab/labgen/emitters/<stack>/` directory, its own test files, and its
own manifest. They can be built in parallel, in any order, by separate
agents, with zero coordination needed between them beyond not editing
shared read-only files (`emitter.py`, `schema.py`, `conformance/`) at the
same time without checking for conflicts.

### 4.1 Node/Express emitter (Tier-A depth)

1. `StackEnv` for `node_express` (Addendum D's schema): `language="node"`,
   `framework="express"`, a pinned `framework_version`, a digest-pinned
   Node base image, `is_multi_file=True`, a `route` accumulator module
   (`app.js`'s route-registration lines, sorted by cell ID at render time
   per Addendum D's determinism rule).
2. Module inventory, **Tier-A scope only**: port the well-documented
   value-context shapes already proven on `php_current`
   (`sql_numeric_literal`, `sql_string_literal`, `html_body` XSS) —
   explicitly **not** identifier/alias/connector-position SQLi or
   escaping-context-mismatch XSS on this stack yet (those stay deferred
   per the pacing decision). Reuse `php_current`'s module *shapes*
   (source/transform/sink categories) as the porting template; the actual
   JS/Express code is new.
3. Conformance-suite pass: Tier 0 (lint — use `node --check` in place of
   `php -l`, same skip-guarded-when-absent convention) + Tier 3
   (whole-manifest regenerate-and-diff) against a new
   `lab/manifests/phase3_node_express_sample.yaml`.
4. Digest-pinned base image + lockfile (`package-lock.json`) + Syft-
   generated CycloneDX SBOM (per the tooling decision above).
5. Tests: per-module unit tests (mirroring `test_labgen_modules.py`'s
   convention) + an end-to-end test per cell (supports/determinism/
   verdict-cross-check/`node --check`), mirroring
   `test_labgen_php_current_real_pages.py`'s shape.

### 4.2 Python/FastAPI emitter (Tier-A depth)

1. `StackEnv` for `python_fastapi`: `language="python"`,
   `framework="fastapi"`, a pinned `framework_version`, a digest-pinned
   Python base image, `is_multi_file=True`. **Per the FastAPI research
   above, use the static-discovery-scaffold approach, not a `route`
   accumulator**: a one-time, static `main.py` using
   `pkgutil.iter_modules()`/`importlib` to walk a `routers/` package and
   call `include_router()` on every discovered module — written once as
   part of this `StackEnv`'s scaffold files, never touched per generated
   cell. Also disable `/docs`, `/redoc`, `/openapi.json`
   (`docs_url=None, redoc_url=None, openapi_url=None`) in that same
   scaffold, per the framework-debug-page research above — this is a
   correctness requirement for this task, not a follow-up.
2. Module inventory, **Tier-A scope only**: same three shapes as 4.1
   (`sql_numeric_literal`, `sql_string_literal`, `html_body` XSS), ported
   to FastAPI + SQLAlchemy + Jinja2 idiom.
3. Conformance-suite pass: Tier 0 (lint — `python -m py_compile`, same
   skip-guarded convention) + Tier 3, against a new
   `lab/manifests/phase3_python_fastapi_sample.yaml`.
4. Digest-pinned base image + lockfile (`requirements.txt`/`poetry.lock` —
   pick whichever this project's own Python tooling convention favors,
   check `pyproject.toml`) + Syft-generated CycloneDX SBOM.
5. Tests: same shape as 4.1's tests, adapted to pytest/FastAPI's
   `TestClient` for any in-process assertions Tier 0/3 need.

### 4.3 PHP/Laravel emitter (full depth + app migration)

This is the largest of the three lanes and the one most likely to benefit
from its own internal sub-lanes (see the lane map below) — the migration
step in particular (4.3.6) decomposes cleanly into independent per-page
groups once the base emitter exists.

1. `StackEnv` for `php_laravel`: `language="php"`, `framework="laravel"`,
   a pinned `framework_version`, a digest-pinned PHP base image,
   `is_multi_file=True`, a `route` accumulator module
   (`routes/web.php`'s route-registration lines, sorted by cell ID).
   Disable debug mode in the scaffold (`APP_DEBUG=false`,
   `APP_ENV=production`) per the framework-debug-page research — same
   correctness requirement as 4.2's `/docs` disable.
2. Module inventory, **full depth**: every shape `php_current` already
   supports (ported to Laravel/Eloquent/Blade idiom) **plus** the
   identifier/alias/connector-position SQLi and escaping-context-mismatch
   XSS shapes from Phase 1 (§2.2) — this is why "stack 1 = full depth"
   costs nothing extra assigned to Laravel: Phase 1's hard-shape work on
   `php_current` is directly portable here once it exists, whereas
   assigning full depth to Node/Express or FastAPI would mean re-deriving
   those shapes from scratch on an unrelated stack.
3. Conformance-suite pass: Tier 0 (`php -l`, already proven) + Tier 3,
   against a new `lab/manifests/phase3_php_laravel_sample.yaml`.
4. Digest-pinned base image + lockfile (`composer.lock`) + Syft-generated
   CycloneDX SBOM.
5. Tests: same shape as 4.1/4.2's tests.
6. **Migration** (D20 §7.2): reproduce every remaining real
   `puppy-fort-factory/` page not already covered by `php_current`'s
   existing real-pages sample (`CC-LAB-0022`'s four pages) through the new
   `php_laravel` emitter instead. Decompose into independent per-page (or
   small per-page-group) sub-lanes — each page's migration is a self-
   contained diff against a known real file, verified via the same
   whole-manifest Tier-3 regeneration pattern that caught `BUG-0022`
   (`PA-0024`'s own standing test). Once **every** real page is
   reproduced and its Tier-3 test passes, retire `puppy-fort-factory/` as
   a separate fixture (delete it, update `docs/ARCHITECTURE.md` and this
   project's README to point at the generator as the sole source of the
   PHP lab) — do not retire it page-by-page; the cutover is one atomic
   step once full coverage is proven, per D20's own framing ("the
   generator becomes the single source... not an additional target
   alongside a permanently-kept original").

### 4.4 Cross-cutting: `stack` field + fingerprint-independence gate

**Depends on:** at least one of 4.1/4.2/4.3 landing (needs a second stack
name to exist before "stack" is a meaningful axis at all); the
fingerprint-independence gate specifically needs **two** stacks landed
(`min_stacks_per_class >= 2`), so this task's second half depends on
whichever two of 4.1/4.2/4.3 land first, not all three.

1. Add `stack` (or `stack_profile`) to `Cell` and to `labels.json`'s
   per-case output — **inline**, per the research decision above, not a
   separate file.
2. Once two stacks exist: wire `fingerprint_gate.py` into `--check`
   (T-LAB0.10) as a required step, with `expected_classes`/
   `expected_stacks` populated from whichever stacks/classes actually
   exist at that point (not hand-waved placeholders).
3. Tests: a two-stack corpus fixture proving the gate both passes on a
   balanced sample and fails on a deliberately confounded one — reuse
   `fingerprint_gate.py`'s own existing test fixtures/patterns
   (`test_labgen_fingerprint_gate.py`), don't re-author them.

---

## 5. Phase 4 — Realism tier and beyond

Per `CR-LAB-0001` §8: the shop tier (6 business objects, ownership graph,
4-step checkout), webhook/callback + seeded internal SSRF target + no-egress
network policy, limit-overrun/race-condition counters, OpenAPI + GraphQL
surfaces, hand-written Next.js fixture cells, optional Spring Boot emitter.

**Decided (2026-09-21): explicitly left open, not dropped.** Given the
choice between formally dropping Spring Boot from near-term scope now
(previously option (c)) or leaving it as an undecided, optional line item
the way `CR-LAB-0001` originally framed it, the project owner chose to
leave it open — a deliberate deferral, not an oversight. Don't schedule
Phase 4's Spring Boot line without a fresh decision at that point; nothing
else in this plan depends on which way this eventually resolves.

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

Eight research items were dispatched to web-enabled research agents across
two passes on 2026-09-21, and every decision they informed has now been
made by the project owner (2026-09-21). This section is kept as a durable
record of what was decided and why, plus the few items still genuinely
open.

### Resolved

1. ~~**T-LAB0.9 scope**~~ (§1.1) — **decided: option (b)**, sweep every
   FUZZ consumer of the label contract alongside the schema change, not
   deferred.
2. ~~**Leakage-probe threshold**~~ (§2.3) — **decided: per-class
   thresholds**, seeded from the report's 0.55-0.60 band as a provisional
   starting point per class, recalibrated once Phase 1 produces real corpus
   data.
3. ~~**Identifier/alias/connector-position SQLi oracle coverage**~~ (§2.2)
   — **research complete**: sqlmap does not reliably detect this shape;
   build a custom differential-response prober alongside `oracle_wrapper.py`
   instead. **Decided: spot-check the real sqlmap binary first**, as the
   opening step of that task, before committing to the fallback design.
4. ~~**`authz_expectations` placement**~~ (§3) — **research complete**: no
   external prior art declares ownership/authz as static data at all;
   genuinely novel schema ground. **Decided: a separate side file**,
   decoupled from the manifest cells the verdict engine consumes, by
   analogy to this project's own `provenance.yaml` precedent.
5. ~~**Toolkit Session-manager dependency**~~ (§3) — **decided: Lab-track
   Phase 2 proceeds independently.** Build a small, Lab-track-owned session
   helper (named test identities + a cookie jar) as part of Phase 2's own
   oracle-confirmation code, rather than waiting on the toolkit's unrelated
   Session-manager phase, whose full re-auth/JWT/auto-exclusion feature set
   is built for a different job (adversarial tools attacking an unknown
   target) than Phase 2 actually needs (holding a couple of known
   test-account cookies during build-time confirmation).
6. ~~**Phase 3 pacing**~~ (§4) — **decided: option (b)** — stack 1 to full
   depth, stacks 2-3 to Tier-A-only depth. Confirmed this does not lock the
   project out of upgrading later: a Tier-A stack's later upgrade to full
   depth is additive (new modules/matrix rows/cells layered onto what
   exists), not a rewrite, per this project's own module-composition
   convention and its whole-manifest regression tests. Choosing (b) defers
   the harder-shape authoring/oracle cost for stacks 2-3, it does not
   eliminate it. **(c) — dropping Spring Boot from near-term scope — was
   decided separately: deliberately left open** (see item 15 below), not
   dropped; it is a separable question from the depth pacing that (b)
   answers.
7. ~~**FastAPI route-accumulator need**~~ (§4) — **research complete**:
   avoidable via a one-time static discovery scaffold (~15 lines,
   project-owned, not a first-party FastAPI feature); the `route`
   accumulator module is still needed for Laravel/Express. No decision
   needed beyond adopting the finding.
8. ~~**Complexity-as-file-count-multiplier interaction**~~ (§4) —
   **research complete**: no direct prior art exists for this combination;
   spike with two fixed depth levels before generalizing to a combinable
   N-valued axis, adopted into the plan.
9. ~~**`patterns/` card-authoring schedule**~~ (§1.3) — **decided:
   schedule it after the rest of the build is done.** Not gating anything
   else in this plan.
10. ~~**SBOM/digest-pinning tooling**~~ (§4) — **research complete**:
    generate SBOMs with **Syft**, record as **CycloneDX**; pin base-image
    digests via a small local script on the pattern-corpus's own quarterly
    cadence, not a bot. **Decided: defer the vulnerable-dependency-vs-
    regression allowlist question** — no scanning-based build gate is
    currently planned to consume these SBOMs, so no allowlist should be
    designed preemptively; revisit only if such a gate is ever proposed.
11. ~~**The all-secure-profile false-positive contract around framework
    debug pages**~~ (§4) — **research complete**: no comparable prior-art
    project has actually solved this. Adopted: production-mode-by-default
    for every generated container (with FastAPI's
    `/docs`/`/redoc`/`/openapi.json` disabled as an explicit separate step),
    plus a reviewed ZAP rules-file/Alert-Filter allowlist as a second line
    of defense. One small follow-up remains, not a decision: the exact ZAP
    alert/plugin IDs need empirical confirmation once Phase 3's first
    non-PHP emitter exists.
12. ~~**Whether `stack` belongs in `labels.json` directly vs. a separate
    file**~~ (§4) — **research complete**: prior art and the general ML
    shortcut-learning literature both favor inlining. Adopted: keep `stack`
    inline in `labels.json`.
13. ~~**Whether the pattern corpus versions with the manifest or
    independently**~~ (§1.3) — **decided: independently.** Follows directly
    from the provenance-separation principle already adopted in Addendum A;
    the mechanism (`REFRESH_LOG.md`, stable card IDs, `superseded_by`)
    already exists and needs no new machinery.
14. ~~**DOM XSS frontend-code generation**~~ (§5) — **research complete**:
    confirmed hand-authoring is the field norm, validating the plan's
    tentative call, refined to a per-sink-type template with an explicit
    vulnerable/safe swap point to preserve this project's minimal-pair
    discipline. A concrete 5-8 item sink taxonomy is now specified.
15. ~~**Spring Boot near-term scope**~~ (§4/§5) — **decided: left open,
    deliberately.** Given the choice between formally dropping the optional
    fourth stack from near-term planning now, or leaving it an undecided,
    optional line item the way `CR-LAB-0001` originally framed it, the
    project owner chose the latter — a conscious deferral, not an
    oversight. Revisit only if/when a fresh decision is actually needed
    (e.g. when Phase 3 is being scheduled in detail); nothing else in this
    plan depends on which way it eventually resolves.

### Still open

16. **Phase 4 SSRF target + GraphQL surface design** (§5) — deliberately
    not dispatched for research in either pass. The plan itself judges this
    research premature this far out ("anything decided today would likely
    be stale by the time it matters"); revisit when Phase 3 is close to
    landing, not before.

---

## 7. Lane map — parallel build assignment (Phases 0-3 only)

Every atomic task above, given a lane ID, its real dependencies (not phase
order — per this project's own standing policy, a lane builds as soon as
its actual prerequisites exist, regardless of which `CR-LAB-0001` phase
number it's filed under), and a wave number. **A lane in wave *N* becomes
eligible the moment every lane it depends on is merged and verified — not
when wave *N-1* as a whole finishes.** Waves are a planning aid for reading
this table, not a synchronization barrier: if three of wave 2's five
dependencies land early, that lane starts immediately, it does not wait for
the other four wave-1 lanes to finish. No lane should ever sit idle while
its dependencies are satisfied and an agent is free — reassign the moment
either condition changes.

| Lane | Task (§ ref) | Depends on | Wave | Notes |
|---|---|---|---|---|
| L-P0.9 | T-LAB0.9 regression gate (§1.1) | — | 1 | FUZZ-consumer sweep + `Case` extension + gate + tests |
| L-P0.10 | T-LAB0.10 CLI (§1.2) | — (soft: L-P0.9 for full `--check`) | 1 | Land now; add the regression-gate line to `--check` in a small follow-up once L-P0.9 merges |
| L-P1.1 | Wire covering-array resolver (§2.1) | — | 1 | |
| L-P1.2a | Sqlmap spot-check + identifier-context oracle prober (§2.2, oracle half) | — | 1 | Spot-check first, then build the prober module regardless of result (fallback needed either way per the research) |
| L-P1.2b | Harder SQLi/XSS shapes: matrix rows + `php_current` modules (§2.2, module half) | L-P1.2a | 2 | Soft-benefits from L-P1.1 for scale, not blocked by it |
| L-P1.3 | Wire χ²/leakage gates as required (§2.3) | L-P1.1, L-P1.2b | 3 | Needs real cell-count variation to check |
| L-P1.4 | Stratified splits + dedup + diversity report (§2.4) | L-P1.1 | 2 | Parallel with L-P1.2b |
| L-P2.1 | Identity/ownership schema + loader (§3.1) | — | 1 | |
| L-P2.2 | LAB-owned session helper (§3.2) | — | 1 | Independent of L-P2.1; may be built by the same agent as a sub-lane if one agent takes both |
| L-P2.3 | `sink_endpoint` distinct from `injection_endpoint` (§3.3) | — | 1 | |
| L-P2.4 | Parameter location/encoding axis (§3.4) | — | 1 | Soft-benefits from L-P1.1's axis mechanism, not blocked by it |
| L-P2.5 | `context_depth` axis wired into `Cell` IR (§3.5) | L-P0.9, L-P2.3 | 2 | Needs `flow_variant` (L-P0.9) and `sink_endpoint` (L-P2.3) both to exist first |
| L-P3.1 | Node/Express emitter, Tier-A (§4.1) | — | 1 | Fully independent stack; internally sub-lane-able (StackEnv vs. module authoring vs. tests) |
| L-P3.2 | Python/FastAPI emitter, Tier-A (§4.2) | — | 1 | Same as above |
| L-P3.3a | PHP/Laravel `StackEnv` + accumulator + conformance harness (§4.3, steps 1/3/4/5) | — | 1 | |
| L-P3.3b | PHP/Laravel full module inventory incl. hard shapes (§4.3, step 2) | L-P1.2b, L-P3.3a | 2 | This is *why* Laravel was assigned "full depth" — the hard-shape modules port directly from L-P1.2b's `php_current` work |
| L-P3.3c | PHP/Laravel app migration, per-page sub-lanes (§4.3, step 6) | L-P3.3b | 3 | Decompose into one sub-lane per remaining real page (or small page group) once the base emitter is validated — an ideal candidate for the migrating agent to spawn its own sub-agents, per the standing policy |
| L-P3.4 | `stack` field + fingerprint-gate wiring (§4.4) | any 2 of {L-P3.1, L-P3.2, L-P3.3a} | 2 | Needs a second stack name to exist; the gate half needs exactly two stacks landed, not all three |

**Wave 1 (12 lanes, zero dependencies — dispatch all of them now):** L-P0.9,
L-P0.10, L-P1.1, L-P1.2a, L-P2.1, L-P2.2, L-P2.3, L-P2.4, L-P3.1, L-P3.2,
L-P3.3a, plus the T-LAB0.8 mechanical refresh-report prep (§1.3) if you want
it running in the background too — it was deliberately scheduled last for
its own *authoring* step, but the mechanical prep has no such restriction
and needs no one waiting on it.

**Wave 2 (5 lanes, unlocked incrementally as wave 1 lanes land):** L-P1.2b
(needs L-P1.2a), L-P1.4 (needs L-P1.1), L-P2.5 (needs L-P0.9 + L-P2.3),
L-P3.3b (needs L-P1.2b + L-P3.3a — so effectively wave 3 in practice, listed
here for its nominal position), L-P3.4 (needs any two stack lanes).

**Wave 3+:** L-P1.3 (needs L-P1.1 + L-P1.2b), L-P3.3c (needs L-P3.3b,
itself sub-lane-able per-page once unlocked).

**Cross-lane coordination notes (the only real coupling in this table):**
- `fuzzlab/labgen/schema.py`'s `Cell`/`SinkContext` dataclasses are touched
  by L-P2.3, L-P2.4, and L-P2.5 (and indirectly by L-P1.1's manifest-schema
  work). These are field *additions*, not restructuring, so conflicts
  should be limited to merge-order bookkeeping (the renumbering pattern
  already used repeatedly this session for `CC-LAB-NNNN`/`FR-LAB-N`
  collisions applies here too) — not a reason to serialize these lanes.
- `fuzzlab/labgen/__init__.py` gets a new submodule import for every new
  top-level module (`identity.py`, `identity_session.py`, each new emitter
  package) — expect a merge-order collision here on nearly every lane and
  resolve it the same way (keep both additions, alphabetize).
- No lane in this table modifies `verdict.py`'s derivation logic — every
  new field across every lane is additive metadata, matching this
  project's own repeated convention. If any lane's implementation finds
  itself needing to change `verdict()`'s actual logic (not just its
  inputs), stop and flag it rather than proceeding — that would be a
  genuine cross-cutting change this map doesn't anticipate.
