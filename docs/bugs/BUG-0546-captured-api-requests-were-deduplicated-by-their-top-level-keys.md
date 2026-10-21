# BUG-0546 — Captured API requests were deduplicated by method, path and top-level keys: a dispatcher's operations and a request's nested inputs were dropped

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0057, FR-CRAWL-37; review round 1 below), with four pinned
  instances of the class in other items' code (strict xfails, below)
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
    `function`/`method`/`_method` field when it is a non-empty string or an integer
    (never a boolean). A string is keyed with its whitespace runs folded to one space:
    by its text up to 64 characters, else by `sha256:` and the digest of its folded
    text. *(As first committed at 34d4fd1 the value had to be a token -- no whitespace,
    at most 64 characters -- and anything else was data; review round 1, B1, below.)*
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
  per endpoint and name (`_get_parameter(...) is not None: continue`), and the point
  builder (`harness/auto.py`) builds points only from `parameter` rows joined to their
  form. Two GraphQL operations on one endpoint are two form rows, but every name they
  share (`query`, `operationName`, a shared variable name) is bound to the first
  operation's form, so the second operation's shared inputs are never sent with its own
  document. That is audit defect 8 (the request-context identity), another lane's item
  (owner: the defect-8 lane, `_store_request`). *(Review round 1, B2: first written
  here as "not pinned here", a prose deferral PA-0531(4) forbids.)* Pinned by the strict
  xfail
  `tests/test_captured_operations.py::test_each_captured_graphql_operation_gets_its_own_points_on_import`,
  which captures GetUser and SearchPosts through `record_request`, imports them with
  `import_spider`, and asserts that SearchPosts' form has its own `variables.n`.
- `formnav.signature`, `spa.form_signature`, `revealed_forms (route, signature)`: forms
  by their controls for submission caps, not request evidence. Not instances.
- `core/dedup.py` with `harness/pipeline.py::_dedup` (DOM templates): an instance. The
  pipeline keeps only the points on the first page of each DOM-skeleton template, and
  the skeleton holds tag names only (no action, input name or handler), so another
  endpoint on a look-alike page is dropped before the audit: a deduplication key that
  leaves out what routes the work to different code (PA-0546(1)). Audit defect 10,
  owner lane DEDUP10 (BUG-0547). *(Review round 1, B2: first listed without a pin or a
  reason.)* Pinned by the strict xfail
  `tests/test_captured_operations.py::test_two_endpoints_on_pages_of_one_dom_template_are_both_audited`
  (`/safe?q=` and `/admin?cmd=` on pages of one template; `run_pipeline` audits one).

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
   decides it (selector or data field: the field's name, whatever its non-empty value;
   a GraphQL document or search text: an executable document), and errs towards
   keeping: a condition on the value may only add a selector, never turn one into data
   (strengthened in review round 1, B1).
3. A merge or dedupe that feeds a consumer judging the whole item is checked against that
   consumer before it ships (here the importer's whole-body refusals and leaf limit).
4. Every writer of `discovered_requests` keys its rows through `tools.apiop`: an AST guard
   proven on synthetic offenders (BUG-0546's writer among them). Its limits: it checks
   that the four keying functions are called in the writing function, not how their
   results flow; it covers this table only.

Enforced by `tests/test_captured_operations.py`: the guard and its synthetic offenders,
and the GraphQL, nested-key and JSON-RPC tests.

## Review round 1 (added in review, 2026-10-21)
The orchestrator's review of 34d4fd1 confirmed two findings, each reproduced on 34d4fd1
through the real write path (`StorageManager.record_request`, and for B2 the real
importer `store_adapter.import_spider`). Both are fixed on `lane/SPIDER9-r1`
(CC-CRAWL-0057, review round 1). This section supersedes the text above where they
disagree.

### What the first fix still let through
- **B1, a selector value with whitespace or over 64 characters was data.**
  `apiop._is_selector_value` accepted a `SELECTOR_NAMES` field's value only when it was
  a whitespace-free token of at most 64 characters (`_TOKEN`). Any other value was
  data, so it was in no key: `POST /cart action=Add+to+cart&item=1`, then
  `action=Remove+from+cart&item=1`, gave the same operation and the same shape, and the
  second returned `duplicate`. The same happened in JSON (`{"action":"Add to
  cart"}` then `{"action":"Delete item"}`), in the query (`?action=Add+to+cart` then
  `?action=Remove+item`), and for two values over 64 characters. A submit button's
  label (`name=action value="Add to cart"`, sent by a `FormData` built with its
  submitter) is a common dispatcher value, so every operation of such a dispatcher
  after the first was lost again, silently (`_observe` ignores `duplicate`). The first
  commit's test asserted the merge as intended (`{"command": "cat a.txt"}` was a
  `duplicate` of `{"command": "ls -la /tmp"}`).
- **B2, two instances in the sweep were left as prose.** The importer's first-wins
  parameters (`tools/store_adapter.py::_store_request`) were written up as "another
  lane's item; not pinned here", and `core/dedup.py` was listed with neither a pin nor
  a reason. PA-0531(4) and PA-0054(3) require an offline strict xfail naming the owner,
  never a prose deferral, and the same change pinned two other instances that way.
  The importer instance also limits this fix end to end: on 34d4fd1, GetUser and
  SearchPosts captured on one `/graphql` endpoint import as two forms, but all three
  parameters (`query`, `operationName`, `variables.n`) are bound to form 1, so
  SearchPosts' shared inputs are never sent with its own document. CC-CRAWL-0057's
  impact line ("gets the added operations and inputs as form rows and points") was
  wrong for shared names.

### Root cause (Five Whys, both findings)
1. Why did "Add to cart" and "Remove from cart" merge? The selector rule turned a
   value into data by its shape (whitespace, length), and a data value is in no key.
2. Why did the rule test the value's shape? It was written to keep free text (a
   `command` field holding a shell line) from splitting rows, which is a row-count
   concern, and the deciding condition was chosen against that concern.
3. Why did nobody see that this contradicted "errs towards keeping"? PA-0546(2), as
   first written, named "a token value" as what decides selector or data. The rule
   itself encoded the merging bias, and the test asserted the merge as intended, so
   the suite agreed with it.
4. Why were two sweep rows left as prose? The lane treated "another lane's item" as a
   disposition. PA-0531(4) says it is not one, but nothing checks a sweep's rows, and
   the rule was applied only where the lane thought the instance was its component's
   neighbour (`record_form`, `disco.synth`).
5. Why did the impact line overstate the importer? It was written from the importer's
   form path (one form row per captured row) without running an import of two
   operations that share names.

**Root cause:** a keep-or-drop rule decided by a property the kept item can also have
(the selector's own value shape), so the rule erred towards merging while stating the
opposite; and a sweep whose dispositions were prose, unchecked, so a deferral passed
as one.

### Corrective action (CC-CRAWL-0057 review round 1)
- `apiop._selector_value` replaces `_is_selector_value` and `_TOKEN`: every non-empty
  string value of a `SELECTOR_NAMES` field is a selector (an integer too; a boolean,
  an empty string, `null`, a float or a container is not). Whitespace runs are folded
  to one space; a folded value of at most `MAX_SELECTOR_CHARS` (64) is keyed by its
  text, a longer one by `sha256:` plus the digest of its folded UTF-8 (`surrogatepass`,
  so it is total). The `command` free-text case is now two rows: it costs a row
  (FR-CRAWL-37).
- Tests (`tests/test_captured_operations.py`):
  - `test_a_selector_value_with_whitespace_or_over_64_characters_keeps_operations_apart`
    covers the four reproductions, the folding and the digest. It fails on 34d4fd1.
  - `test_an_action_op_or_cmd_field_in_the_body_or_query_keeps_operations_apart` now
    asserts the `command` pair as two rows and a boolean flag as no selector.
  - Two new strict xfails pin the swept instances:
    `test_each_captured_graphql_operation_gets_its_own_points_on_import` (owner: the
    defect-8 lane, `_store_request`) and
    `test_two_endpoints_on_pages_of_one_dom_template_are_both_audited` (owner: DEDUP10,
    BUG-0547).
  - `test_the_bug_0546_sweep_pins_every_instance_it_does_not_fix` checks that every
    sweep row above is fixed, not an instance, or names a strict xfail of that module
    that exists. It fails on 34d4fd1's text.
  - `test_the_sweep_guard_catches_a_prose_deferral` is that guard's proof on synthetic
    offenders: 34d4fd1's two rows, a missing pin, and a pin that is not a strict xfail.

### Recurrence review (round 1)
- **BUG-0052 / PA-0054(3), BUG-0531 / PA-0531(4):** "a sweep that finds an instance it
  does not fix pins it with a strict xfail, never a prose deferral". B2 is a
  **recurrence** of the failure these rules name, in this bug's own sweep.
- **PA-0546(2) (this bug, as first written):** B1 is a defect of the preventive action
  itself. Its deciding condition was the one that merged.
- No other `docs/bugs/` report has a selector or dispatcher-value rule.

### Prior-preventive-action failure analysis (round 1)
- **PA-0531(4) / PA-0054(3) were not followed, and they were not enforced.** Neither
  names a test that reads a sweep. PA-0531's enforcement lines are query-placement
  guards and PA-0054's are emitter declarations, so a prose deferral fails nothing.
  The lane followed the rule for two rows and wrote "another lane's item" for two
  others. The rule was understood but not checked, and "another lane's item" read as
  an exemption the rule never grants.
- **PA-0546(2) was wrong at the decision.** It said "errs towards keeping" and in the
  same sentence named a test (a token value) that drops. A rule that names its
  decider must not let the decider remove what the key is for.

### Preventive action (PA-0546, amended in review round 1)
- **(2)** is reworded above: selector or data is decided by the field's name for every
  non-empty value. A condition on the value may only add a selector, never turn one
  into data.
- **(5), new:** every row of a bug's PA-0002 sweep states one of three dispositions:
  fixed (here, or by a named bug), not an instance (with why), or pinned by a strict
  xfail that exists and names its owner. "Another lane's item" is not a disposition.
  For this bug the rule is enforced by the sweep guard, proven on synthetic offenders.
  - Limit: the guard reads this bug's sweep only. Generalising it to every bug doc
    with a `## PA-0002 sweep` section (10 today) is left to a PA-0531(4) owner.

Enforced by `tests/test_captured_operations.py`:
- the round-1 tests: the selector-value test, the sweep guard and its synthetic
  offenders;
- the tests listed above.
