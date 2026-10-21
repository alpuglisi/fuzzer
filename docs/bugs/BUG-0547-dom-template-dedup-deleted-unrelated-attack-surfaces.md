# BUG-0547 — DOM-template deduplication deleted unrelated attack surfaces

- Date: 2026-10-21
- Status: fixed (lane DEDUP10, item AU-REQID78; CC-CORE-0074, CC-FUZZ-0112)
- Severity: high (audit defect 10, CRITICAL: a library caller supplying `pages_html` lost
  every injection point on all but the first page of each DOM template)

## Description
`harness/pipeline.py::run_pipeline(pages_html=...)` ran `_dedup` before the audit. It
clustered each point's URL by the DOM skeleton of its page (`core/dedup.py`,
`TemplateClusterer`: tag names only, no text, no attributes) and kept **only the points
on the first URL of each cluster**. The skeleton holds no form action, input name,
handler or authorisation rule, so two pages that look alike but post to different
endpoints, take different parameters, or carry different sibling fields were one
"template", and every point on the second page was dropped before it was ever evaluated.
A URL missing from `pages_html` was clustered as `""`: every page without HTML had the
same all-zero signature and collapsed into one cluster.

## Where encountered
The adversarial audit, defect 10 (`fuzzlab/harness/pipeline.py` lines 56-67 and 145-146,
`fuzzlab/core/dedup.py` lines 23-26 and 65-73 at 6552276). Reproduced on c483dc1 by
`tests/test_dom_dedup_folding.py`: equal skeletons at `/safe?q=1` and `/admin?cmd=ls`
leave only `q`; a page given as `""` and a page with no HTML at all are one template.

## What it caused to fail
- Points on a non-representative page were never audited, confirmed or recorded as
  negatives: another endpoint (`/admin?cmd=`), another parameter (`/safe?lang=`), another
  location (a POST body), another form action (`/cart/add` vs `/wishlist/add`), other
  siblings (`op=safe` vs `op=search`), another content type, sink or stored-XSS store
  step. A vulnerability reachable only there was missed with no trace in the run.
- With a partial `pages_html`, every unobserved page collapsed together, whatever its
  structure.
- Nothing was reported: no count of dropped points and no key; `points_audited` was the
  only sign.
- Conditional: no production caller passes `pages_html` (`auto_cli` and `multitarget`
  call `run_auto` without it); a library caller that does was affected.

## What the bug was identified to be
A fold that dropped units of work (injection points) keyed on a similarity of the page
they were found on (its DOM template), not on the identity of the work (the request the
point sends and what it observes). The template is not even a field of the request.

## Root cause analysis
Five Whys:
1. *Why did distinct attack surfaces disappear?* `_dedup` kept a point only when its URL
   was the first URL of its template cluster.
2. *Why was a page's template the identity of its points?* T2.6 was written as "near
   duplicate pages (product #1 vs #99) should be audited once" -- a page-level sampling
   goal applied, unchanged, to points. The only shape its author pictured was a page
   whose points are the same request with another value.
3. *Why did the key never grow with the point?* The point gained `base_entries` (forms
   phases 1-2), body, JSON and header locations, content types, stored-XSS store steps,
   value shapes and a deciding mechanism after CC-FUZZ-0008 wired the stage; each widened
   what a point is, and the fold's key stayed the page because nothing tied the two.
4. *Why was it not caught?* Its one test (`tests/test_pipeline.py::
   test_pipeline_dedup_collapses_same_template`) fed two points that **are** one request
   on one template, the case where the page key and the request key coincide. No test had
   two requests on one template, or a page without HTML, and no production path supplies
   `pages_html`, so it never ran live.
5. *Why did no rule catch it?* PA-0076 ("a join keys on every identity field both sides
   record") is worded for joins between tables; no rule covered a step that drops work as
   duplicates, nor an absent input defaulting to a shared value.

**Root cause:** a deduplication step decided that two units of work were the same by a
similarity of their context (the page's DOM skeleton) instead of by everything the work
sends and observes, defaulted an unknown context to one shared value, and was tested only
on inputs where context and work coincide.

## Corrective action
In CC-CORE-0074 and CC-FUZZ-0112 (lane DEDUP10):
- `core/dedup.py::wire_request_key(point)`: every field of the point's dataclass, by name,
  as given (a field added later joins the key on its own); only a **standalone query
  point**'s URL (`location == "query"`, no `base_entries`, no `store_url`) is taken as
  sent, its injected slot placed by the one query placement (SP-42,
  `place_query_param`), because every sender overwrites that value. Nothing else is
  normalised: a sibling's value, a form default (the oracle sends both), another query
  part, a fragment, the method's case.
- `core/dedup.py::fold_points(points, pages_html)`: a point is folded only when an earlier
  kept point is on a page of the same template **and** has the same `wire_request_key`;
  a page with no HTML, or HTML with no tag structure, is unknown
  (`TemplateClusterer.known_cluster_id` returns None) and folds only with an identical
  point on the same URL. It returns `Folded(points, folded, unknown_pages, key)`.
- `harness/pipeline.py::_dedup` calls it and reports, when the stage runs,
  `dedup_points_in`, `dedup_folded`, `dedup_unknown_pages` (also stored as
  `pipeline_dedup_*` run metrics) and `dedup_key` (`FOLD_KEY`,
  `"template+wire-request-v1"`, in `PipelineResult.metrics`).
- `wire_request_key` is a local stand-in for the request-context identity SP-57 that
  AU-REQID78 is building; at merge it is replaced by SP-57, which must keep its
  guarantees.

Tests (`tests/test_dom_dedup_folding.py`), each failing on c483dc1: one template with six
different requests keeps all six; a pair differing in any one request field (param,
method, location, siblings, content type, sink, store step) keeps both; true duplicates
fold with the count and key reported; absent or empty HTML is unknown; every dataclass
field is in the key; a standalone query URL is keyed as sent (first occurrence), and only
that slot is normalised.

## Recurrence review
Checked `docs/bugs/` for keys, joins, folds, dedup, collapse and similarity, and
`docs/PREVENTIVE_ACTIONS.md` for every rule on identity keys and normalisation:
- **BUG-0075 / PA-0076** -- a join keyed on a subset of the identity fields both sides
  record (the HTTP method), harmless while the dropped field was constant. **Same root
  cause** (a key on a subset of what makes the unit distinct), in a join.
- **BUG-0507 / PA-0507** -- path variation took sibling routes for one parameter: a
  structural similarity taken for identity. **Same class** (similarity decides identity).
- BUG-0046 / PA-0048 (a one-to-many lookup collapsed to one value per key), BUG-0072 /
  PA-0073 (duplicate points confirmed twice: the inverse direction), BUG-0456 / PA-0456
  (a lossy normalisation made unequal definitions equal): related, other mechanisms.

## Prior-preventive-action failure analysis
- **PA-0076 (BUG-0075) was too narrow and not enforced beyond its instance.** It speaks of
  "a join between two tables", and its sweep rule fires "when a new value of an identity
  field becomes possible" -- for joins. Forms phases 1-3 did add identity fields to the
  point (siblings, locations, store steps), but `_dedup` is not a join, so no sweep looked
  at it. Its guard tests are the ML dataset's own.
- **PA-0507 (BUG-0507) targeted another layer.** Its rule 1 (a classifier names the
  evidence separating its confusable alternative, and is measured where the alternative
  occurs) is worded for path and route classification; T2.6 predates it and no sweep
  applied it to other similarity-based decisions. Had it been applied, the confusable
  alternative (two different forms on one template) would have been the test.
- PA-0073(1) names the consumers of *emitted* duplicates; nothing named the consumers of
  *dropped* non-duplicates.

## Preventive action
**PA-0547** (strengthens PA-0076 and PA-0507(1), related PA-0073 and PA-0456):
1. A step that drops units of work as duplicates keys on everything the unit sends and
   observes: every field of the unit, taken generically so a new field joins the key on
   its own, normalised only where the one owner that builds the request overwrites it.
   A similarity (template, cluster, shape) may narrow a fold, never decide it alone.
2. An absent or empty input is unknown, never a shared default: it gets its own identity.
3. A fold reports how many it dropped and on what key; a drop that is not provably the
   same work is a coverage reduction, reported as one.
4. Its tests change one field at a time over the unit's fields (a guard over the
   dataclass, not a list) and include the confusable shape: one context, two works.

Sweep (PA-0002), by mechanism -- every step in `fuzzlab/` that drops attack-surface work
as a duplicate (`grep` for `seen`, `dedup`, `duplicate`, `fromkeys`, cluster):
- `harness/pipeline.py::_dedup` -- fixed here.
- `harness/auto.py` point builder `seen = (path, method, name)` and
  `harness/pipeline.py::_confirmation_key` -- audit defect 8, owned by AU-REQID78 (SP-57);
  not touched here.
- `tools/spider.py::record_request` (method, origin/path, top-level body keys) -- audit
  defect 9, its own lane.
- `harness/auto.py` header points, one set per stored page path (`seen` by path, ~line
  494): query variants of a path share one header point set; uncounted. AU-REQID78's
  file -- **reported to the orchestrator** as a residual.
- `tools/store_adapter.py::_import_forms` `seen_selectors`: a POST selector form with the
  same `formnav.signature` (method, select name, option values) and control names is
  fuzzed once "whatever the action"; it is counted (`form_duplicate_selector`) but its key
  omits the action URL. Outside this lane's files (AUD) -- **reported to the orchestrator**
  as a residual.
- The disco explorer's action dedup -- audit defect 2, its own lane.
- Not this class: `disco/synth.py::_mine_js` (merges observations of one endpoint, drops
  no work), `mutation/payloads.py` and `mutation/livefilter.py` (exact-value payload
  dedup), `labgen` duplicate-id checks (they refuse, never drop).
