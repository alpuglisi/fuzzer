# Target Lab and Ground Truth — Requirement Specification

Component code: **LAB** · Status: `[built app; planned instrumentation + generator]`
· Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #1; `DECISIONS_AND_ROADMAP.md` (D7, D8, D9, D10);
`./change-control.md`.

## 1. Purpose
Provide a deliberately vulnerable, locally hosted target with exact,
machine-readable ground truth, against which the toolkit's tools are exercised
and measured. Authorized, lab-only.

## 2. Scope
- **In:** the Puppy Fort Factory app; ground-truth labels; grey-box
  instrumentation; the containerized environment; later the manifest-driven
  generator, tiers, and build profiles.
- **Out:** the tools themselves; anything reachable from a non-loopback network.

## 3. Functional requirements
- **FR-LAB-1** Serve a deliberately vulnerable web app on localhost with a
  documented mix of vulnerable and secure pages.
- **FR-LAB-2** Emit machine-readable ground truth out-of-band (`labels.json`,
  `expectedresults.csv`, `injection-points.json`) with opaque case IDs, never
  served by the app. (D9)
- **FR-LAB-3** Provide grey-box signals: per-request line coverage, a DB
  error/fault signal, and state snapshot/restore for reset. (D7)
- **FR-LAB-4** Run in a container with pinned PHP/Apache/MySQL/libxml, with
  one-command up and reset. (D7)
- **FR-LAB-5** (Lab track) Generate app, labels, docs, and oracle tests from one
  manifest + safety matrix + seed + env-profile, with a **binary** verdict
  derived from `(transform, sink context)` — a partially neutralized case is
  VULNERABLE-but-harder (a `difficulty` tier), not a third verdict value. (D8, D20)
- **FR-LAB-6** (Lab track) Support build profiles: annotated, blind, all-secure.
- **FR-LAB-7** (Lab track) Support two tiers: dense range and realistic shop.
- **FR-LAB-8** (Lab track) Migrate the existing hand-built Puppy Fort Factory
  app's content into the generator (Phase 3) rather than keep it as a
  permanent separate fixture. (D20)
- **FR-LAB-9** (Lab track) Own the pattern-provenance corpus (`patterns/`,
  OSV/GHSA-sourced pattern cards informing scenario briefs in original words
  only, never inlined as code) as a LAB subcomponent, not an IND catalog. (D20)
- **FR-LAB-10** (Lab track) For every vulnerability class with a mature,
  independently-authored exploitation tool (sqlmap, commix, et al.), the
  generator's security assertion is that tool invoked headlessly, not
  hand-authored exploit code. IDOR/BOLA, business-logic flaws, and
  race-condition classes (no mature automated oracle) are out of scope until
  further decided. (D20, `CR-LAB-0001` Addendum E)

## 4. Non-functional requirements
- **NFR-LAB-reproducible** Byte-identical regeneration; pinned env asserted at
  runtime.
- **NFR-LAB-safety** Lab-only; bound to localhost; destructive classes off by
  default; no outbound route.
- **NFR-LAB-no-leak** No vulnerability class name in any URL, filename, or
  parameter a tool can see.
- **NFR-LAB-label-accuracy** Labels derived, not hand-asserted; env settings that
  affect labels (e.g. `display_errors`, libxml entity handling, `open_basedir`)
  pinned and asserted.

## 5. Interfaces and data contracts
Serves HTTP to the tools. Publishes ground truth as out-of-band files (above),
plus `sitemap.xml`/OpenAPI later. Exposes grey-box coverage and fault signals for
the fuzzer, scheduler, and oracle. Does not write the SQLite store directly.

## 6. Dependencies (components)
None (it is the system under test).

## 7. Acceptance criteria
- App serves on localhost from the container; reset restores clean state.
- Ground-truth files validate against schema and match the served app.
- Runtime env self-check passes against the env-profile.
- (Lab track) generate-twice-and-diff is empty; the contamination sweep finds
  nothing undeclared.

## 8. Open questions
- Database isolation strategy (per-run schema, dump reload, or rollback).
- Whether to expose source (annotated build only, if at all).
- Exact pinned versions and error-surfacing behavior, recorded in the
  env-profile.
