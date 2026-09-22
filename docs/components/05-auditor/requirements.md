# Auditor / Fetcher — Requirement Specification

Component code: **AUD** · Status: `[built; to harden]` · Last updated: 2026-09-22 · see CC-AUD-0016

Related: `ARCHITECTURE.md` #5; `DECISIONS_AND_ROADMAP.md` (D5, D6, D9, Phase 2);
`./change-control.md`.

## 1. Purpose
Turn discovered surface (pages, endpoints, parameters) into ranked **injection
candidates** with recorded rule evidence, so the fuzzer and oracle spend their
budget where a vulnerability is plausible.

## 2. Scope
- **In:** per-parameter rule evaluation, canary reflection probing with context
  typing, target fingerprinting, candidate emission with evidence and features.
- **Out:** confirming a vulnerability (fuzzer + oracle) and ordering candidates by
  a learned model (the ranker reads what the auditor writes).

## 3. Functional requirements
- **FR-AUD-1** Evaluate each injection point against the rule set and record a
  full per-rule evaluation log (which rules fired, which did not, and why), not
  only the rules that matched.
- **FR-AUD-2** Move rules from code toward data (rules-as-data) so the rule set is
  editable and versioned without code changes.
- **FR-AUD-3** Probe reflection with a unique canary and classify the **sink
  context** of each reflection (HTML body, attribute, JS string, URL, etc.).
- **FR-AUD-4** Fingerprint the target (DBMS, framework, WAF) and record it for
  the scheduler and fuzzer to condition on.
- **FR-AUD-5** Emit `candidate` rows carrying rule evidence and an extracted,
  versioned feature vector; never emit a vulnerability label.
- **FR-AUD-6** Read discovered surface from the shared store and write candidates
  back to it (no direct tool-to-tool calls). (D5)
- **FR-AUD-7** Web application/service **technology fingerprinting**: passively
  identify every matching technology (not only one per category) from a single
  already-fetched response — server software, language/framework, CMS, JS
  libraries/meta-frameworks, WAF/CDN, and DBMS error hints — each with an optional
  version, a deterministic confidence, human-readable evidence, and the source URL,
  written to `fingerprint_signal` (CORE migration 13). Sends no additional
  requests; deduped by (category, name), keeping the highest-confidence match.
  Additive to, and independent of, FR-AUD-4's narrow single-value fingerprint
  (`target` table) — the two detectors are deliberately not unified, to avoid
  changing the narrow one's established match-precedence behavior.
  *(Realized: `core.fingerprint.identify_technologies()`, CC-AUD-0016; wired into
  `run_pipeline`, CC-FUZZ-0022; surfaced in the web UI, CC-UI-0034.)* Bounded active
  marker-path probing to improve CMS-detection recall further is an open,
  deliberately deferred follow-up (needs its own scope/safety design), not part of
  this requirement's current realization.

## 4. Non-functional requirements
- **NFR-AUD-explainable** Every candidate is traceable to the rule evidence that
  produced it; a candidate with no evidence is a bug.
- **NFR-AUD-idempotent** Re-auditing the same surface produces stable candidate
  identities (no duplicate churn).
- **NFR-AUD-safe** Probing uses non-destructive canaries only; destructive checks
  are gated off by default.
- **NFR-AUD-no-leak** Candidate identifiers carry no vulnerability class name (D9).

## 5. Interfaces and data contracts
Reads `page`, `endpoint`, `parameter` from the store; writes `candidate` rows
(rule evidence, `features_json` + `feature_version`), `target` fingerprint data,
and `fingerprint_signal` rows (FR-AUD-7). Reads indicators/rules from the
indicator DB & catalogs. Authenticates via the session manager. Runs standalone or
in the discovery pipeline.

## 6. Dependencies (components)
`core/`, session manager, crawler, indicator DB & catalogs.

## 7. Acceptance criteria
- Produces candidates with complete per-rule evidence on the lab's known
  injection points.
- Correctly types reflection contexts on the lab's reflected-input pages.
- Fingerprints the lab's DBMS/framework; candidates carry a versioned feature
  vector consumable by the ranker.

## 8. Open questions
- Rules-as-data schema and how rule versions bind to a run.
- Confidence weighting of overlapping rules for the same parameter.
