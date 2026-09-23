# Auditor / Fetcher — Requirement Specification

Component code: **AUD** · Status: `[built; to harden]` · Last updated: 2026-09-23

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
- **FR-AUD-7** *(`CC-AUD-0016`, 2026-09-23).* A candidate is generated for the
  `ssrf` category: `R-SSRF` (`fuzzlab/audit/rules_data/default_rules.json`)
  matches a parameter name against a common SSRF-fetch vocabulary (`url`,
  `src`, `target`, `webhook`, `thumbnail`, etc.), the same bare
  `name_regex`-only shape `R-OPEN-REDIRECT`/`R-FILE-INCLUSION`/
  `R-COMMAND-INJECTION` already use. Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-14`).
- **FR-AUD-8** *(`CC-AUD-0017`, 2026-09-23).* A candidate is generated for the
  `access-control` category: `R-ACCESS-CONTROL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `GET`/`query`
  parameter whose name looks like an object identifier (`channel_id`,
  `resource_id`, `object_id`, `item_id`, `record_id`, `owner_id`) —
  narrower than `R-SSRF`'s bare-`name_regex` shape (adds `method_in`/
  `location_in`) to bound the false-positive risk a broader match would
  carry for this category (see `CC-AUD-0017`). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-16`).
- **FR-AUD-9** *(`CC-AUD-0018`, 2026-09-23).* A candidate is generated for
  the `insecure-deserialization` category: `R-INSECURE-DESERIALIZATION`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `body`-location
  point whose `sink_context` is `"deserialization"` — this project's first
  use of the `sink_context_in` predicate, since this class has no
  informative parameter name to key off (every whole-body point shares the
  literal `param="body"`). **Scope limit, stated explicitly**:
  `sink_context` is currently populated only from ground truth
  (`fuzzlab.harness.auto.points_from_ground_truth` looks it up from the
  matching scoring `Case`); the auditor does not yet infer `sink_context`
  generically for an arbitrary crawled target, so this rule is reachable
  only in the project's own ground-truth-scored detection-benchmark mode
  today, not yet a general crawl-driven capability. Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-17`).

## 4. Non-functional requirements
- **NFR-AUD-explainable** Every candidate is traceable to the rule evidence that
  produced it; a candidate with no evidence is a bug.
- **NFR-AUD-idempotent** Re-auditing the same surface produces stable candidate
  identities (no duplicate churn).
- **NFR-AUD-safe** Probing uses non-destructive canaries only; destructive checks
  are gated off by default.
- **NFR-AUD-no-leak** Candidate identifiers carry no vulnerability class name (D9).
- **NFR-AUD-dry-run** `fuzzlab audit` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no probe is made), for
  headless use outside the web UI. Reuses the web launcher's dry-run plan/report
  logic (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper.

## 5. Interfaces and data contracts
Reads `page`, `endpoint`, `parameter` from the store; writes `candidate` rows
(rule evidence, `features_json` + `feature_version`) and `target` fingerprint
data. Reads indicators/rules from the indicator DB & catalogs. Authenticates via
the session manager. Runs standalone or in the discovery pipeline.

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
