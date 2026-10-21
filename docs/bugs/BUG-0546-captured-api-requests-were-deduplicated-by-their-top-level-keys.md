# BUG-0546 — Captured API requests were deduplicated by method, path and top-level keys: a dispatcher's operations and a request's nested inputs were dropped

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0057, FR-CRAWL-37), with two pinned instances of the class in
  other items' code (strict xfails, below)
- Severity: high. The audit rated defect 9 CRITICAL. Every GraphQL operation after the
  first on an endpoint, every JSON-RPC method after the first, every `action`/`op`/`cmd`
  value after the first, and every input a request carried below the top level of its
  body that an earlier request with the same top-level keys lacked, never reached the
  importer, so it was never tested.

## Description
`tools/spider.py::StorageManager.record_request` is the one writer of the spider table
`discovered_requests` (FR-CRAWL-13), the contract the importer reads (FR-AUD-22). It
identified a captured request by `json.dumps([method, url_key(url), sorted top-level
keys])`, a `UNIQUE` column, and returned `duplicate` for any later request with the same
signature. The first stored row won.

That key left out everything that routes a request to different code or gives it
different inputs:
- **operation selectors**: a GraphQL `operationName` and operation, a JSON-RPC
  `method`, an `action`/`op`/`cmd` field in the body or the query;
- **nested key paths and their types**: only the top level of the body was keyed;
- **the media type and the query's parameter names**.

## Where encountered
The external adversarial audit at 6552276, defect 9 (`fuzzlab/tools/spider.py` lines
220-255). Reproduced on the base c483dc1 by `tests/test_captured_operations.py`, written
before the fix: `POST /api {"data":{"q":"x"}}` is stored and `POST /api
{"data":{"cmd":"x"}}` returns `duplicate`; two GraphQL operations on `/graphql`, two
JSON-RPC methods, two `?action=` values, a JSON and a form body with the same names, and
a request that adds a query parameter, each return `duplicate` for the second request.

## What it caused to fail
- **Coverage.** A dispatcher endpoint (GraphQL, JSON-RPC, a PHP-style `?action=` router)
  contributed only its first captured operation to `auto`. The others' inputs were never
  points, so a vulnerability reachable only through them was never tested.
- **Nested inputs.** A request that differed from an earlier one only below the top
  level (`{"data":{"name":…}}` after `{"data":{"q":…}}`, a GraphQL `variables` object
  that gained a field) lost what it added.
- Nothing was wrongly reported: the loss was silent. No counter recorded it (the passive
  capture path counts a `duplicate` as nothing).

## What the bug was identified to be
A deduplication key coarser than what tells two requests apart. The key described the
request's address (method and path) and the top of its body, not the operation it
invokes or the inputs it carries. And deduplication dropped the later request whole,
rather than keeping what it added.

## Root cause analysis (Five Whys)
1. Why was `{"data":{"cmd":"x"}}` a duplicate? Its signature (`POST`, `/api`, `["data"]`)
   equalled the stored row's.
2. Why did the signature hold only the top-level keys? Forms phase 3 (CC-CRAWL-0017)
   designed it for the first targets it was built against: flat JSON login and contact
   bodies, one operation per path. The forms-phase-3 review checked redaction and the
   import contract, not what the key merges.
3. Why was the later request dropped rather than merged or kept? The table's
   `signature TEXT UNIQUE` made "seen" and "stored" the same decision: an insert that
   violates it is a duplicate, and nothing compared what the new body added.
4. Why did no later rule catch it? PA-0505(1) ("a discovery mechanism identifies what it
   has seen by its content, never by the address it was reached at") was written for
   disco's documents and states. Its PA-0002 sweep looked at disco's state fingerprint and
   harvest, not at the spider's request signature, and it has no mechanical guard: its
   tests are disco harvest tests.
5. Why was a dispatcher endpoint never tried? No fixture of either crawler's capture
   writer had a GraphQL, JSON-RPC or `action=` endpoint, or a nested body that varied.
   **Root cause:** a deduplication key was chosen from the shape of the first targets
   (address plus top-level keys), not from what can route a request to different code or
   give it different inputs; and deduplication discarded the later item whole instead of
   keeping what it added. The rule that names the first half (PA-0505(1)) was scoped to
   documents and not enforced.

## Corrective action (CC-CRAWL-0057, FR-CRAWL-37)
- **`fuzzlab/tools/apiop.py` (new).**
  - `operation_key`: the operation is the method, `url_key` (canonical origin and
    path), the media type and every operation selector (`operation_selectors`) in the
    body at any depth and in the query: a GraphQL operation (`graphql_operations`: type,
    name and root fields of the operation `operationName` selects; aliases resolved,
    fragments expanded; a linear scanner, never a backtracking pattern; a document over
    20000 tokens told by the digest of its folded text), and the value of an
    `action`/`act`/`op`/`operation`/`operationName`/`cmd`/`command`/`do`/`task`/`func`/
    `function`/`method`/`_method` field when it is a token or an integer.
  - `request_shape`: a request's typed key paths at every depth (array elements as one
    position) and its query parameter names. `operation_schema`: the merge (union) of an
    operation's stored rows' shapes. `row_signature`: the operation plus the digest of the
    row's shape.
- **`StorageManager.record_request`.** It looks up the operation's stored rows (by the
  signature's operation prefix). A request whose exact shape a row already has is a
  `duplicate`. One whose shape adds a key path or a type at any depth to the operation's
  merged schema is always stored, with its own body. One that only combines known inputs
  differently (another context) is stored while the operation has fewer than 32 rows,
  then refused as "operation over its context cap" (counted and logged by the caller as
  not recorded). The new duplicate test is strictly finer than the old one: equal
  shapes imply equal top-level keys. The redaction boundary is unchanged (both
  redactors, at the write).
- **Bodies are not merged into one row.** The task asked for nested schemas to be merged
  recursively. They are, as the comparison basis (`operation_schema`); the stored bodies
  stay the application's own. A merged body was measured against the importer on
  2026-10-21 (`store_adapter.captured_request`): `{"q":"shoes"}` imports, while
  `{"q":"shoes","sort":"price"}` is refused as a settings field, so merging those two
  would have refused the operation that imports today; two 40-leaf bodies merge into 80
  leaves, over `jsonbody.MAX_LEAVES` (64), and the merged row would not be imported at
  all. Keeping representatives loses no key path or type and changes no import decision.

## PA-0002 sweep (instances of the class)
Searched `fuzzlab/` for deduplication keys of requests, forms and endpoints
(`sorted(`…`keys`, `signature`, `sig =`, `seen`):
- `tools/spider.py::StorageManager.record_request`: fixed here.
- `tools/spider.py::StorageManager.record_form`: a crawled form is keyed by action URL,
  method and control names; two forms posting to one action, told apart by a hidden
  `action` value, keep only the first. Lane SPIDER owns that code (not this lane's lines):
  pinned by the strict xfail
  `tests/test_captured_operations.py::test_two_forms_told_apart_by_a_hidden_action_value_are_both_kept`
  (PA-0531(4)).
- `disco/synth.py::synthesize`: an endpoint is keyed by origin, method, path template
  and content family, so a GraphQL endpoint's operations are one inventory operation
  (their body schemas are merged by `SchemaNode`, so no key path is lost; the operations'
  separation is). The disco import imports every exchange and is unaffected. Pinned by
  the strict xfail
  `tests/test_captured_operations.py::test_the_disco_inventory_keeps_two_graphql_operations_apart`
  and recorded as a known gap in FR-CRAWL-37 (PA-0505(2)).
- `tools/store_adapter.py::_store_request`: a parameter is the first captured request's
  per endpoint and name. Two GraphQL operations on one endpoint that share a variable
  name give one point. That is audit defect 8 (the request-context identity), another
  lane's item; not pinned here.
- `formnav.signature`, `spa.form_signature`, `revealed_forms (route, signature)`: forms
  by their controls for submission caps, not request evidence. Not instances.
- `core/dedup.py` (DOM templates): audit defect 10, another lane's item.

## Recurrence review
Checked `docs/bugs/` for identity and deduplication keys (`dedup`, `signature`,
`identity`, `first … wins`) and `docs/PREVENTIVE_ACTIONS.md` for rules on identity:
- **BUG-0505 / PA-0505(1)**: disco identified a state by the address it was reached at
  (`/sitemap.xml#/` was a second app). Same root cause: an identity key that leaves out
  what tells two things apart (there the document's content, here the operation and the
  inputs). **A recurrence of the root cause.**
- BUG-0502 / PA-0502(3): element identity carried the route it was seen on (too fine, not
  too coarse). Same family, opposite failure; not a recurrence.
- BUG-0138 (SP-08 `document_key`): a same-path document with another query is another
  document. Same family (a path key dropping a discriminator), fixed for document reads
  by a new owner; no PA states it for requests.
- BUG-0072 / PA-0048, PA-0073: duplicate findings for one confirmation key (too fine).
  Not a recurrence.

## Prior-preventive-action failure analysis
**PA-0505(1)** (from BUG-0505) did not prevent this:
- **Too narrow.** It is worded for "what a discovery mechanism has seen" as documents
  and states, and contrasts address with content. A request signature is a different
  kind of identity, and its discriminators (selectors, nested shape) are neither "the
  address" nor obviously "the content".
- **Not swept by mechanism.** BUG-0505's sweep covered disco's fingerprint and harvest.
  The spider's capture signature, a dedupe key of the same kind in the sibling tool, was
  not on it (the PA-0002 sweep went by symptom, not by "every dedupe key").
- **Not enforced.** PA-0505(1)'s enforcement lines are disco harvest tests. Nothing fails
  when another deduplication key is too coarse.
- **And it says nothing about what a dedupe discards.** Even a correct key would still
  drop the later item whole; PA-0505 has no rule that a duplicate is one that adds
  nothing.

## Preventive action (PA-0546)
Strengthens PA-0505(1) from documents and states to every deduplication key:
1. A deduplication key holds everything that can route the item to different code or
   give it different inputs (for a request: method, canonical path, media type and every
   operation selector, in the body at any depth or in the query). An item is a duplicate
   only when what is kept for its key already holds it exactly; one that adds anything
   (a key path or a type, at any depth) is always kept, with its own evidence, and a cap
   on what is kept applies only to items that add nothing.
2. A rule that keeps or drops by such a key names the confusable alternative and what
   decides it (selector or data field: a token value; a GraphQL document or search text:
   an executable document), and errs towards keeping.
3. A merge or dedupe that feeds a consumer judging the whole item is checked against that
   consumer before it ships (here the importer's whole-body refusals and leaf limit).
4. Every writer of `discovered_requests` keys its rows through `tools.apiop`: an AST guard
   proven on synthetic offenders (BUG-0546's writer among them). Its limits: it checks
   that the four keying functions are called in the writing function, not how their
   results flow; it covers this table only.

Enforced by `tests/test_captured_operations.py`: the guard and its synthetic offenders,
and the GraphQL, nested-key and JSON-RPC tests.
