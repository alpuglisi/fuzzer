# Crawler / Spider — Requirement Specification

Component code: **CRAWL** · Status: `[built; to harden]` · Last updated: 2026-09-22 · see CC-CRAWL-0007

Related: `ARCHITECTURE.md` #4; `DECISIONS_AND_ROADMAP.md` (D5, D6, Phase 2);
`./change-control.md`.

## 1. Purpose
Discover the target's reachable surface — pages, endpoints, parameters, and
JavaScript-driven endpoints — and record it in the store for the auditor and
fuzzer.

## 2. Scope
- **In:** fetching and rendering, link and endpoint discovery, deduplication,
  scope and budget, per-identity crawling.
- **Out:** deciding whether a parameter is vulnerable (auditor/fuzzer).

## 3. Functional requirements
- **FR-CRAWL-1** Hybrid fetch: cheap HTTP first, escalate to a headless browser
  only when a page is client-rendered. *(Realized: `fuzzlab crawl --engine
  hybrid` fetches statically and escalates a page to a lazily-started
  Playwright browser only when `core.hybrid.needs_browser()` says the static
  HTML looks client-rendered; the existing `auto`/`playwright`/`requests`
  engines are unchanged. CC-CRAWL-0007.)*
- **FR-CRAWL-2** Capture fetch/XHR endpoints and JS-extracted endpoints, not just
  static anchors.
- **FR-CRAWL-3** Deduplicate by DOM-skeleton template cluster (MinHash), recording
  a `template_cluster_id`, and normalize URLs. *(Realized: every crawled page is
  assigned a `template_cluster_id` (via `core.dedup.TemplateClusterer`, one
  clusterer per crawl) and persisted in `discovered_pages.template_cluster_id`
  — added via the existing ALTER-TABLE upgrade path, so older result
  databases pick it up. A future auditor pass can use it to audit one
  representative per cluster; the crawler itself still records every page.
  CC-CRAWL-0007.)*
- **FR-CRAWL-4** Crawl as a state machine (state = DOM-skeleton hash + identity),
  reaching pages behind multi-step flows.
- **FR-CRAWL-5** Crawl per identity, using the session manager; detect logout and
  re-authenticate.
- **FR-CRAWL-6** Respect a crawl budget and deadline via the shared budget
  manager; never overlap headless work with timing-sensitive fuzzing.

## 4. Non-functional requirements
- **NFR-CRAWL-safe** Deny-list destructive actions (delete/logout/reset); default
  to not clicking them.
- **NFR-CRAWL-bounded** Cap per-template instance counts to avoid infinite crawl
  spaces.
- **NFR-CRAWL-reproducible** Record a crawl manifest (URL → template →
  discovered-from) so runs can be diffed.

## 5. Interfaces and data contracts
Writes `page`, `endpoint`, and `parameter` rows (with a `source` of link vs xhr).
Reads the session context and the request budget. Runs standalone or as part of a
pipeline.

## 6. Dependencies (components)
`core/`, session manager, target lab.

## 7. Acceptance criteria
- Discovers JavaScript-rendered pages and XHR endpoints a static crawler misses.
- Deduplicates near-duplicate pages by template.
- Stays authenticated for a full crawl and records results per identity.

## 8. Open questions
- Form-fill value generation (type-aware) for reaching post-submission code.
- State-machine crawl depth and caps.
