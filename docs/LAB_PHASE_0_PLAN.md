# Lab Phase 0 — Generator foundation (plan, for review)

Build the foundation of the manifest-driven lab generator adopted in
**CR-LAB-0001** (`docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md`):
the pipeline verdict model, a versioned safety matrix, determinism/build gates,
and the provenance corpus — with a plugin-style emitter interface designed in
from day one, even though Phase 0 itself ships zero new stacks. Same posture as
the rest of the toolkit: lab-only, loopback-only, on infrastructure we own.

*Draft for review — nothing built yet. Component **LAB** (#1), with schema
touch-points in **FUZZ** (#7, label-contract consumer). See
`docs/DECISIONS_AND_ROADMAP.md` (D7–D10, proposed D18) and
`CR-LAB-0001` (§5, §6, §8 Phase 0).*

## Two decisions this document resolves (per your last message)

You asked for scalability and modularity to be **priorities**, and for this
program to **never reduce functionality or capability — additive only.**
Those aren't just principles below; they resolve two things CR-LAB-0001 left
open:

1. **The existing hand-built PHP app is never removed or replaced.** §7.2 of
   the CR asked whether to migrate it into the generator or keep it as a
   permanent fixture. Under an additive-only mandate, the answer is: it stays
   exactly as it is, indefinitely usable standalone, for as long as you want
   it. When the PHP/Laravel emitter is eventually built (Phase 3), it is a
   **new, additional** target — generated Laravel cells — not a replacement
   for `puppy-fort-factory/`. If you ever *do* want to fold the hand-built
   app's content into the generator later, that is a separate, explicit,
   future decision — not a side-effect of this plan.
2. **Architecture Option A (single core, per-stack emitter plugins)** — the
   report's own recommendation — is confirmed, specifically *because* it is
   the modular choice: adding a stack means writing one emitter against a
   fixed interface, never touching the verdict engine, the resolver, the
   existing stacks' emitters, or their generated output. Report's Option B
   (separate generators per stack) is rejected as higher drift risk and lower
   modularity.

## Goal

Stand up the generator's core — resolver, pipeline-valued verdict engine,
versioned safety matrix, determinism gates, name-leak gate, and the
`patterns/` provenance corpus — such that it **reproduces today's lab
byte-for-byte** (no cells change, no labels change, nothing currently working
regresses) while being structurally ready for Phase 1 (variation on the
existing PHP stack) and Phase 3 (additional stacks as plugins) without a
rewrite.

## Exit criterion

`fuzzlab lab-generate` (new) runs against a manifest that describes the
**current** PHP lab cells, emits source and labels **byte-identical** to
today's hand-authored `puppy-fort-factory/` + `lab/ground-truth/*` (a
regenerate-and-diff CI gate is green); the verdict function is pure,
versioned, and snapshot-tested; the name-leak scanner and secret scanner run
as build gates and pass; and a documented emitter interface exists with zero
implementations required beyond "reproduce the current PHP app," so Phase 1
and Phase 3 can build against it without touching this phase's code.

## Principles (this phase, and the program as a whole)

- **Additive-only, enforced, not just promised.** Every phase gate includes a
  regression check: existing labeled cells (today: the ~30 PHP pages) must
  keep validating, keep serving, and keep producing the same verdicts after
  any generator change. A phase that would remove, relabel, or reduce
  coverage of an existing cell does not ship — it becomes a new cell alongside
  the old one, or a documented exception you explicitly approve.
- **Modularity as the primary architectural driver.** Three concrete
  commitments, each a direct answer to "how do we add capability without
  touching what already works":
  - **Emitters are plugins against a fixed interface**, not branches in a
    shared codebase. Adding stack N+1 (Phase 3+) never requires editing an
    existing emitter. The interface contract is written and conformance-
    tested in Phase 0 (as the "reproduce today's PHP app" emitter), even
    though no second emitter exists yet.
  - **The safety matrix is an open registry of `(op, context) → effect`
    entries**, not a fixed enum. Adding a transform op, a sink context, or a
    vulnerability class is *appending* an entry and a version bump, never
    editing existing entries (append-only, like the change-control logs
    elsewhere in this project).
  - **Verdict derivation, the manifest schema, and the label contract are
    independently versioned** (`manifest_version`, `safety_matrix_version`).
    Old manifests keep generating exactly what they generated before, forever
    — a new version is additive, never a breaking rewrite of the old one.
- **Scalability as a build-time property, not just a cell-count property.**
  Two concrete commitments:
  - **Covering-array expansion, not hand enumeration**, from day one — even
    though Phase 0 has only one stack and reproduces today's small cell set,
    the expansion machinery is the thing that has to scale later, so it's
    built once, correctly, here. Hand-listing cells only for the "reproduce
    exactly what exists today" bootstrap set.
  - **Source regeneration and container rebuild are separate, independently
    fast paths.** Phase 0 ships the source-only regenerate-and-diff gate as
    the fast local loop; container rebuild cost is a Phase 3 concern (new
    runtimes) that must never slow down Phase 0/1 iteration.
- **Offline-testable seams.** The resolver, verdict engine, safety matrix, and
  name-leak scanner are unit-tested with fixed manifests and fakes, same
  pattern as `core/store.py`/`core/features.py`. No container or live lab
  needed to test the generator's logic itself; only the final regenerate-
  and-diff-against-the-real-lab check touches the container.
- **No auto-run, unchanged.** The generator writes files and labels; it never
  starts, stops, or sends traffic to anything. D11 is untouched by this work.

## Design decisions to confirm (review points)

1. **Emitter interface shape.** Proposed: an emitter is a Python object
   implementing `render(cell: Cell) -> EmittedFiles` plus a declared
   capability set (which `(class, sink_context)` pairs it supports — unsupported
   pairs are skipped by the resolver, not errored, per the report's
   "declare unsupported and skip" rule). Registered similarly in spirit to the
   existing plugin system (component **PLUG**, #13), though this is a
   generator-internal registry, not a `fuzzlab` runtime plugin — *confirm
   whether you want it literally wired through `fuzzlab/plugins/` for
   consistency, or kept as a LAB-internal registry since it has no runtime
   HTTP-facing behavior.*
2. **Where `patterns/` and the new manifest/schema files live.** Proposed:
   `lab/generator/` for the generator code, `lab/patterns/` for the provenance
   corpus (resolves CR-LAB-0001 §7.3 in favor of LAB ownership), manifests
   under `lab/manifests/`. *Confirm paths.*
3. **Phase-0 manifest scope.** Proposed: hand-write **one manifest** that
   describes the current ~30 PHP pages as cells (mechanical transcription, not
   a redesign — Phase 1 is where the sink-context taxonomy actually improves).
   This is intentionally boring: Phase 0's job is proving the pipe works, not
   improving realism yet. *Confirm you're fine deferring all realism gains to
   Phase 1, as CR-LAB-0001 already laid out.*
4. **Verdict semantics.** Per CR-LAB-0001 §7.1, binary verdict with `partial`
   neutralization feeding the `difficulty` tier (not a three-valued verdict).
   *Confirm — this is baked into the safety-matrix schema in Phase 0, so it's
   the one semantic decision that's expensive to reverse later.*
5. **`fuzzlab lab-generate` as a new CLI subcommand vs. a `lab/` script.**
   Proposed: a `fuzzlab` subcommand (consistent with `fuzzlab crawl` / `audit`
   / `fuzz`), since it's core tooling, not a one-off lab-ops script like
   `labctl.sh`. *Confirm.*

## Architecture (Phase 0 slice of the full design)

```
lab/manifests/*.yaml + lab/safety_matrix.yaml@vN + seed + env_profile
        │
        ▼
   [ resolver ]  — validates, expands (covering-array machinery present,
        │           degenerate to "one cell per manifest entry" while the
        │           Phase-0 manifest lists cells explicitly)
        ▼
   typed IR:  Cell{ id, class, sink_context, transform[], route, nuisance }
        │
        ▼
   [ pure verdict(pipeline, sink_context, matrix_version) ]  — snapshot-tested
        │
        ├──► emitter registry ──► emitter:php-current (Phase 0's only entry;
        │                          reproduces today's puppy-fort-factory/)
        │
        ├──► labels.json / expectedresults.csv / injection-points.json
        ├──► docs/ (generated VULNERABILITIES.md stays out of scope this phase —
        │           the hand-written one is untouched, additive-only)
        └──► build gates: regenerate-and-diff · name-leak scan · secret scan
```

Nothing here removes `puppy-fort-factory/` or `lab/ground-truth/*` as they
exist today; the exit criterion is that the generator can *reproduce* them,
as a proof the pipe is correct, sitting alongside the hand-authored originals
until you decide (a later, separate decision) to cut over.

## Tasks

- **T-LAB0.1 — Pipeline verdict engine + structured sink contexts `[planned]`.**
  `lab/generator/verdict.py`: `Pipeline` (ordered transform ops), structured
  `SinkContext` (family + required neutralizations), and the pure
  `verdict(pipeline, sink_context, matrix_version)` function per CR-LAB-0001
  §3/§6. Snapshot tests fix its behavior per matrix version.
- **T-LAB0.2 — Safety matrix as an open, versioned registry `[planned]**.**
  `lab/safety_matrix.yaml` (v1, seeded with today's PHP transforms/contexts
  only — `param_bind`/`html_entity_escape`/etc. against the sink contexts the
  current app actually uses); a loader that validates it against a JSON
  Schema and rejects unknown effect values. Append-only discipline documented
  at the top of the file, mirroring `docs/PREVENTIVE_ACTIONS.md`'s own
  append-only convention.
- **T-LAB0.3 — Resolver + IR + covering-array machinery (dormant) `[planned]`.**
  `lab/generator/resolver.py`: manifest → validated `Cell` IR. Covering-array
  expansion (NIST ACTS-style, or a small IPOG reimplementation) is built and
  unit-tested against synthetic axis sets, but the Phase-0 manifest itself
  lists cells explicitly (one axis level each) so the real corpus doesn't
  change yet — proves the machinery without touching today's labels.
- **T-LAB0.4 — Emitter interface + the first (reproduction) emitter
  `[planned]`.** `lab/generator/emitter.py` (the ABC/protocol: `render(cell) ->
  EmittedFiles`, `supports(class, sink_context) -> bool`) and
  `lab/generator/emitters/php_current/` implementing it to emit exactly
  today's `puppy-fort-factory/` pages from the Phase-0 manifest. This is the
  emitter conformance suite's first subject (T-LAB0.7).
- **T-LAB0.5 — Determinism: sub-seed derivation + canonical serialization +
  CI gate `[planned]`.** `H(root_seed || cell_id)` sub-seeds; sorted
  map/dict iteration; canonical JSON/CSV serialization (sorted keys, LF, fixed
  float formatting); `SOURCE_DATE_EPOCH` honored for any embedded date. A
  `scripts/lab_regenerate_check.sh` (or `fuzzlab lab-generate --check`) that
  regenerates and `git diff --exit-code`s, wired as a CI/test-suite gate.
- **T-LAB0.6 — Name-leak scanner + secret scanner as build gates
  `[planned]`.** Greps every emitted, *served* artifact (routes, filenames,
  params, cookies, headers, HTML comments, error strings) against a denylist
  of class names/synonyms/CWE IDs/`labels.json` vocabulary; fails the build on
  a hit. Wires a secret scanner (gitleaks or equivalent) over emitted config.
  Both run even in Phase 0's single-emitter, small-corpus state, so they're
  proven before volume makes manual review impossible.
- **T-LAB0.7 — Emitter conformance suite `[planned]`.** A stack-agnostic,
  HTTP-level test suite (per the report's §5.1/§5.6: "write the suite before
  the second emitter") that any future emitter must pass: for each
  `(class, sink_context)` it declares support for, the oracle can confirm the
  unsafe rendering is vulnerable and the paired secure rendering is not.
  Phase 0 runs it against `emitters/php_current/` only, but it is written
  generically now so Phase 3's Node/Python/PHP-Laravel emitters plug into it
  unchanged.
- **T-LAB0.8 — `patterns/` provenance corpus, first 25–30 cards `[planned]`.**
  `lab/patterns/`: an OSV.dev + GHSA pull script (per CR-LAB-0001 §3, report
  §1.1), hand-triaged into cards (`id`, `class`, `stack`, `sink_family`,
  `root_cause`, `source_url`, `published_date`). Referenced by `id_ref` from
  manifest cells as provenance only — never read by `verdict()`. Not required
  for the Phase-0 exit criterion (today's cells predate this corpus) but
  seeded now so Phase 1's realism rebuild has material to draw on.
- **T-LAB0.9 — Regression/additive-only gate `[planned]`.** A test that
  diffs the generator's emitted `labels.json`/`expectedresults.csv`/
  `injection-points.json` against the current hand-authored ground truth and
  fails if any existing case ID, page, or verdict is missing or changed —
  the mechanical enforcement of "never reduce functionality." This gate
  stays in the suite permanently, not just for Phase 0.
- **T-LAB0.10 — `fuzzlab lab-generate` CLI `[planned]`.** Thin CLI wiring
  (pending decision 5 above) over T-LAB0.1–T-LAB0.4: `fuzzlab lab-generate
  --manifest lab/manifests/phase0.yaml --out <dir> [--check]`.

## How this connects to the rest of CR-LAB-0001

This document covers Phase 0 only, in task-level detail, per your instruction
that we discuss implementation after CR approval. The remaining phases stay
at the work-package level already recorded in CR-LAB-0001 §8 until each is
ready to be planned the same way:

- **Phase 1** (variation on the existing PHP stack — covering arrays turned
  on for real, minimal-pair invariant, leakage probe, the identifier/alias/
  connector SQLi and escaping-context-mismatch XSS rebuild) becomes a
  `LAB_PHASE_1_PLAN.md` once Phase 0 is built and its exit criterion is met.
- **Phase 2** (identity/ownership model, `sink_endpoint`, context depth) is
  where the FUZZ-component label-contract impact from CR-LAB-0001 §4 actually
  lands, and will need FUZZ's own sign-off on the schema addition, not just
  LAB's.
- **Phase 3** (first new stacks: Node/Express, then Python/FastAPI, then
  PHP/Laravel) is where the modularity bet in this document gets tested for
  real — the emitter interface and conformance suite from T-LAB0.4/T-LAB0.7
  should need **zero changes** to admit the second emitter. If they do need
  changes, that's a signal Phase 0's interface design needs revisiting before
  Phase 3 continues, not a reason to special-case the second emitter.
- **Phase 4** (shop-tier realism, SSRF target, GraphQL/OpenAPI surfaces)
  unchanged from CR-LAB-0001 §8.

## What is explicitly not happening in Phase 0

No new stacks, no new containers, no change to `puppy-fort-factory/` or
`lab/ground-truth/*` as currently served, no change to the existing test
suite's expectations, no change to `docs/PREVENTIVE_ACTIONS.md`-mandated
processes. Phase 0 is infrastructure that sits *beside* the current lab and
proves itself by reproducing it exactly.
