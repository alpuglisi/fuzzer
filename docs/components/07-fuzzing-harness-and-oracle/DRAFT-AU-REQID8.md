# DRAFT AU-REQID: request contexts never merge, and every sender places a query value at one exact occurrence

> **IMPLEMENTED (2026-10-21) by AU-REQID78** (CC-FUZZ-0111, CC-AUD-0056, CC-CORE-0073,
> CC-ML-0501; BUG-0530, with defect 7 as BUG-0544). The owner decided Q1: every distinct
> context is tested, with no cap. Differences from this draft: no migration of
> `parameter.occurrence` or `finding.context_id` (the context is computed from the
> evidence, on read for older rows, and the finding records it in its evidence);
> per-occurrence binding and raw link-set text stay residuals R1/R2 (pinned). The text
> below is the parked design, kept as history.

> **PARKED (2026-10-19).** The coordinator accepted the split. This file keeps the
> defect-8 material for the later item **AU-REQID8**, unchanged below this note.
> - **Superseded parts.** Defect 14 is now its own item, AU-REQID14
>   (`DRAFT-AU-REQID14.md`). That file supersedes, for defect 14, §1.2, §1.3, §4,
>   §5.1 and the defect-14 parts of §7–§10 below. Its M6 design differs: there is no
>   oracle-side executor wrapper.
> - **Reserved numbers.** BUG-0530, PA-0530, CC-AUD-0056, FR-AUD-31 and SP-57 stay
>   reserved for AU-REQID8. CC-FUZZ-0106, CC-CORE-0068, BUG-0531, PA-0531 and all of
>   FR-FUZZ-64 went to AU-REQID14, so AU-REQID8 needs its own FUZZ and CORE numbers and a
>   new FR ID (coordinator, revision 2 of AU-REQID14).
> - **Measurement tests.** The defect-8 tests (`tests/test_request_contexts.py`: 9 strict
>   xfails, 2 controls, 2 upstream crawler measurements) were removed from the AU-REQID14
>   branch and are parked at commit `9ac56f8`. AU-REQID8 restores them with
>   `git show 9ac56f8:tests/test_request_contexts.py`. Its pin reasons still name
>   CC-FUZZ-0106 and need their numbers updated on restore.
> - **Open measurement.** The typical-crawl count (§1.4) is to be put to the owner when
>   AU-REQID8 starts.
> - **Split item.** POST-action query points are a separate later item.

- Item: `AU-REQID` (audit defects 8 and 14, owner-supplied audit at 6552276; F-096)
- Status: **draft for the pre-change review gate** (`docs/components/README.md`). Nothing
  here is implemented. The two measurement test files are committed with strict xfails.
- Base: `8100959` (branch `worktree-agent-aef1371774d69f3f5`)
- Pre-assigned numbers: CC-FUZZ-0106, CC-AUD-0056, CC-CORE-0068; BUG-0530 / PA-0530
  (defect 8), BUG-0531 / PA-0531 (defect 14); FR-FUZZ-64, FR-AUD-31; SP-57.
- **Proposed split** (§11): AU-REQID-14 (defect 14, placement) first, then AU-REQID-8
  (defect 8, identity). It needs numbers this item was not given (§11.3).

## 0. Summary

Two defects, one root: no part of the tool has a definition of "the request this test
sends". Each layer keys what it has at hand, and each key drops a field the next layer
needed.

- **Defect 8.** Distinct requests collapse into one test at four layers:
  1. the importer (one `parameter` row per endpoint and name);
  2. the point builder (`seen` on `(path, method, name)`);
  3. the pipeline (`_confirmation_key`);
  4. the ML label join.

  The proposal adds a **versioned request-context identity** (SP-57) with one owner. It is
  computed once for every point by the audit engine and written into each candidate's
  evidence. The confirmation key is built from it, and so are the finding's attribution
  and the label join. Rows share a test only when they send the same wire request and
  make the same observations.
- **Defect 14.** Each sender builds a query its own way: three append a second pair,
  three rebuild the query through a `dict`, the oracle's binder replaces every
  occurrence, and the browser appends. The proposal adds **one ordered query-entry
  representation and one placement function** (SP-42 extended). Every sender and the M6
  browser call it, and the placement conformance check reads the raw request target.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

Every failure below was reproduced through the real code on `8100959`. The tests are
committed: `tests/test_request_contexts.py` (defect 8) and `tests/test_query_placement.py`
(defect 14). Each test that fails today is pinned with `xfail(strict=True)`. Run with
`--runxfail` to see the failures: 9 + 30 fail, and the controls pass. With the pins in
place, the two files give 10 passed and 39 xfailed (`FUZZLAB_REQUIRE_BROWSER=1`).

### 1.1 Defect 8: where contexts merge (`tests/test_request_contexts.py`)

| Test | Layer, file:line @8100959 | Measured |
|---|---|---|
| `test_a_name_in_the_query_and_the_body_of_one_request_is_two_points` | builder `seen` (path, method, name), `harness/auto.py:377-384` | the audit's case: points `['query']`, want `['body','query']` |
| `test_each_link_context_of_a_parameter_is_its_own_point` | importer `_get_parameter` by (endpoint, name) `store_adapter.py:47`; link set bound `WHERE form_id IS NULL` (first wins) `:364-370` | `op=safe&q=` and `op=search&q=`: one point, the `op=safe` one |
| `test_each_captured_body_of_an_endpoint_is_its_own_context` | `_store_request` "first one's leaf wins" `store_adapter.py:872` | two captured JSON bodies, `op` safe / search: one `q` point (`['safe']`) |
| `test_a_form_body_and_a_json_body_of_one_endpoint_are_two_points` | `_get_parameter` keys no location / form | form `q` (body) + JSON `q`: `['body']` only |
| `test_a_post_actions_query_parameter_is_a_point` | `_import_forms` keeps a POST action's query on the URL (`:633-635`), never as a point | `{('POST','body')}`: the query `q` is never tested (**split item**, §11) |
| `test_the_pipeline_tests_a_context_that_only_its_siblings_reach` | `_confirmation_key` `pipeline.py:127-131` | the target receives `op=safe` only; the `op=search` sink is never probed; 0 findings |
| `test_a_raw_body_and_a_form_field_of_one_url_are_two_tests` | key has no content type | oracle asked for `application/json` only |
| `test_two_stored_cases_shown_on_one_page_each_plant_their_own_store` | key has no setup | only `/sign-a` planted; `/sign-b` (the vulnerable store) never |
| `test_a_context_never_tested_is_never_labelled_by_anothers_finding` | rows marked checked without a test (`pipeline.py:310-321`) + label join `(run, path, param, category, method)` `ml/dataset.py:121-127` | `{'safe': 1, 'search': 1}`: a training positive for a request no probe made |

The two controls (`test_control_the_search_context_alone_confirms`,
`test_control_the_second_store_alone_confirms`) pass on 8100959. Their fake target and
oracle do confirm a context once it is reached.

**Upstream (the crawler, CRAWL; measured for the sweep; both pass on 8100959):**
- `StorageManager.record_form`'s signature (action, method, names; `spider.py:311`) keeps
  one of two forms that differ only in a hidden `op` value.
- `record_request`'s signature (method, `url_key`, body keys; `spider.py:240`) keeps one
  of `POST /api/run?op=safe` and `?op=search` with bodies of the same keys.

These contexts never reach the store, so the importer cannot recover them (§6).

### 1.2 Defect 14: what each sender put on the wire (`tests/test_query_placement.py`)

A loopback echo server (`require_loopback`) records the raw request target. In the table
below, `M` is the payload. The point is a standalone GET query point, so the first
occurrence is the addressed one.

| Query before / param | Contract | `RequestsProbeSender`, greybox, blind-sqli `RequestsSender` | `SeamProbeSender` (anonymous and with an identity), blind-sqli `SeamSender` |
|---|---|---|---|
| `id=1&tag=a&tag=b` / id | `id=M&tag=a&tag=b` | `id=1&tag=a&tag=b&id=M` | `id=M&tag=b` |
| `tag=a&id=1&tag=b` / tag | `tag=M&id=1&tag=b` | `…&tag=M` appended | `tag=M&id=1` |
| `a=%7E&flag&id=1&b=x+y` / id | `a=%7E&flag&id=M&b=x+y` | `a=~&flag&id=1&b=x+y&id=M` | `a=~&flag=&id=M&b=x+y` |
| `id=&x=1` / id | `id=M&x=1` | `id=&x=1&id=M` | `id=M&x=1` (holds) |
| `a%5B%5D=1&a%5B%5D=2` / `a[]` | `a%5B%5D=M&a%5B%5D=2` | `…&a%5B%5D=M` appended | `a%5B%5D=M` |

- **The seam with an identity** was measured through a real `HttpClient` and its real
  `requests` transport, with a session addon that applies nothing. A real
  `SessionManager` needs keyring credentials. Every session route of `SeamProbeSender`
  (main, isolated copy, anonymous) builds its URL in the same `_send_on`, so the
  measured URL is the one each route sends.
- **Bound path** (`_FormBoundSender` → `FormEntries.replace`, `core/forms.py:92`): the
  entries `id=1&tag=a&tag=b`, point `tag`, put `id=1&tag=M&tag=M` on the wire. Every
  occurrence was replaced.
- **M6 browser, real Chromium** (`browserexec._with_query`, `browserexec.py:25-29`): the
  wire carried `id=1&tag=a&tag=b&id=M`. The executor appends.
- `test_the_anonymous_and_authenticated_senders_send_the_same_query` fails.
- The existing placement check cannot see any of this.
  `test_sender_conformance._Wire` parses the query into a `dict`, and its probe URL has
  no query. The check's channel cannot carry the violation (PA-0311(2)).

### 1.3 Platform facts the placement contract rests on

These are pinned by `test_platform_clients_rewrite_only_escapes_without_query_meaning`,
a real-process and real-browser test. It fails rather than skips under
`FUZZLAB_REQUIRE_BROWSER=1`. Measured 2026-10-19 with requests 2.34.2 and Chromium 1194.

- **requests** decodes escapes of unreserved characters (`%7E` → `~`). It upper-cases
  other hex (`%2b` → `%2B`), escapes raw `|{}<>` and non-ASCII, and keeps raw `'`.
- **Chromium** keeps every escape as given. It escapes raw `'`, `<>` and non-ASCII, and
  keeps raw `|{}`.
- **Neither client** changes a pair boundary, an `=` (`flag` stays `flag`), an empty
  part (`&&`, a trailing `&`), `+` vs `%20`, or an escape of `& = + % #`.

So byte equality across clients is impossible, but this relation is preserved by both:
pairs in order, `=` presence, and every escape decoded except those of `& = + % #`. That
relation is `canonical_pairs` in the test file. A unit test shows it still tells apart
what a server reads apart: a duplicate, a lost sibling, `flag` vs `flag=`, `+` vs
`%2B`, `&` vs `%26`, and order (PA-0034(2)).

### 1.4 Effect on the number of tests

- **Committed ground truth** (all `lab/ground-truth*`, the real `points_from_ground_truth`
  with browser and writes on; script
  `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/aureqid/gt_measure.py`):
  - 178 points;
  - 156 old keys `(url, param, method, location)`;
  - 156 contexts under §3's identity: **no change**. The 22 duplicates differ only in
    `sink_context` (PA-0048), which is not on the wire, so they stay one test.
  - No ground-truth URL carries a query, and no observe page has two store requests.
  - Scored ground-truth runs therefore keep their test count and verdicts. The
    `tests/data/auto_summary` goldens are unaffected.
- **A typical crawl: NOT MEASURED. Blocked; flagged.** The available development-lab
  crawl stores are the Juice Shop spider DBs and stores in this session's scratchpad
  `juice/`. Reading them was **denied by the permission classifier** ("PII Data
  Handling"). I did not work around it.
  - The measurement is ready to run, read-only and counts only:
    `python3 -I /tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/aureqid/crawl_measure.py <repo> <spider.db> <tmp dir>`.
  - It imports the crawl with today's importer and builder, and models the draft's
    importer from the same spider rows, using the importer's own redaction, refusal and
    filler helpers.
  - It prints today's points and keys, the draft's contexts, the growth factor and the
    contexts-per-old-key histogram.
  - On a 4-URL synthetic spider DB (a smoke check, not a measurement) it gives 7 keys →
    10 contexts.
- **Bound on the growth.** Per old key, the new count is the number of distinct sibling
  sets carrying that name at that endpoint, times its occurrences. On a listing page
  whose links differ in a data sibling (`?cat=3&page=1..20`), `cat` becomes 20 contexts:
  they are genuinely different wire requests. Whether to cap that (§3.6) is an owner
  decision, made on the measured histogram (open question Q1).

## 2. Root causes

**Defect 8.** Five whys:
1. The `op=search` sink was never probed. → Its row shared `_confirmation_key` with the
   `op=safe` row.
2. Why did they share it? → The key lists five fields, and the request has more:
   siblings, occurrence, content type, setup and identity.
3. Why five? → BUG-0072 made the key "the identical confirmation" (PA-0073). The fields
   that make confirmations differ were added later: siblings (FR-FUZZ-42/43), JSON
   leaves (FR-FUZZ-47), content type (FR-FUZZ-19), store requests (FR-AUD-24). Each
   was added to the evidence and the `Candidate`, and none to the key.
4. Why was the key not updated? → No test relates the key to the fields a sender or
   strategy reads. The importer and the builder have the same kind of dedup with fewer
   fields (name only, then path, method and name). Those were stated as residuals
   (FR-FUZZ-42 "one confirmation per (url, param, method, location)", FR-FUZZ-43 "the
   first crawled link wins", FR-AUD-22 "the first one's leaf wins a name").
5. **Root cause:** "which rows are the same test" is decided at four places, each by a
   hand-written tuple. Nothing ties those tuples to what the request actually contains.

**Defect 14.** Five whys:
1. A first-value server never saw the anonymous payload. → `requests` appended a second
   `id`.
2. And the authenticated path lost `tag=a`? → `with_query_param` rebuilds the query
   through a `dict`.
3. Why do two senders differ? → Each sender, plus greybox, blind-sqli and the M6
   executor, builds the query itself. No owner places a query value.
4. Why did the conformance check (PA-0115) not catch it? → It checks placement per
   location, not per occurrence. Its wire collapses the query into a `dict`, and its
   probe URL has none.
5. **Root cause:** query placement is not a shared primitive, and the check meant to
   hold the senders together observes through a channel that cannot carry the violation.

## 3. Design A: the request-context identity (defect 8; SP-57)

### 3.1 The identity, version 1

There is one owner, a new module `fuzzlab/core/reqctx.py` (CORE): `request_context`,
`context_id`, `confirmation_key`, `CONTEXT_VERSION = 1`, `SEED_CATEGORIES`.

`request_context(point)` is total and deterministic; the identity comes from the point's
`identity_scope` (§3.2). It returns a canonical JSON-able dict with these fields:

| Field | Value | Why it is in |
|---|---|---|
| `v` | `1` | versioned: a reader compares only within one version |
| `origin` | `core.urls.canonical_origin(url)` (SP-05) | another origin is another app |
| `path` | the URL's path; a path point's template (`/ticket/{id}`); a fragment point's `to_route_path` | the handler |
| `method` | upper-cased | the handler |
| `location` | query, body, json, header, path or fragment | where the payload goes |
| `target` | query/body: `[name, occurrence]`; json: the leaf's path segments (its own address); header: lower-cased name; path: the template's name | the exact occurrence (§4) |
| `query` | the request URL's ordered query pairs as sent. For a query point, the target's slot is a placeholder | sibling bindings in the URL; a POST action's query |
| `body` | the ordered form entries, or the JSON leaves (path, typed value) as sent, with the target's slot as a placeholder; `null` when there is no body | sibling bindings in the body |
| `content_type` | the body's media type as sent: form-urlencoded, application/json for a JSON leaf, the declared type of a whole raw body; `null` otherwise | a raw JSON body and a form field named `body` are two requests |
| `setup` | ordered list of setup requests, each in the same shape (a stored case's store step: method, origin, path, query, location, target, content type, body) | stored XSS planted through `/sign-a` vs `/sign-b` |
| `identity` | the run's identity label (`"anonymous"` or the `--identity` name), set by `run_auto` | the session the request carries. Within a run it is constant; across runs it separates labels (§3.5) |

**Excluded, with the reason.** A guard enforces the list (§7, `test_every_candidate_field_*`).

| Field | Why it is not in the identity |
|---|---|
| `sink_context` | an audit label, never on the wire (PA-0048's duplicates stay one test) |
| `rule_id`, `transaction_type` | several rules on one point are one test (BUG-0072) |
| `origin` (crawl / ground-truth) | not on the wire |
| `value_shapes` | derived from the target's value (see `seed`) |
| `decided_by` | which mechanism decides. It is a function of `setup` and location, and is merged per key as today (FR-AUD-30) |

**The target's own original value** is recorded as `seed`, the SHA-256 of the canonical
value, never the value itself. It enters the confirmation key only for the categories
whose strategies read it (§3.3). Those categories are `SEED_CATEGORIES`:

- access-control (cross-account replays the owner's value from `base_entries`);
- open-redirect (`redirect_seed`);
- command-injection (`base_value`);
- nosql-injection (the leaf's original type, from `base_entries`).

The set is derived and checked by an AST guard over `oracle/strategies.py`: which
strategy classes read `candidate.base_entries`, `.redirect_seed` or `.base_value`, and
their `category`. That file is read, never edited (it is AU-OUTCOME's).

`context_id(ctx)` is `"rc1-" + sha256(canonical JSON of ctx without seed)[:32]`. Values
in the context are the stored values, already redacted (`redact_sibling`, `redact_leaf`)
and made neutral (`_send_value`). The candidate's evidence already holds those values,
so nothing new is exposed. The target's value appears only as its digest.

### 3.2 Where it is computed and stored

| Stage | Change | Component |
|---|---|---|
| Import | One `parameter` row per (endpoint, location, name, occurrence, sibling set). Details below. | AUD (CC-AUD-0056) |
| Store | Migration 25: `parameter.occurrence INTEGER` (NULL = legacy = 0) and `finding.context_id TEXT` (NULL = legacy). Both have production writers (PA-0071, `test_contract_writers`). | CORE (CC-CORE-0068) |
| Point | `InjectionPoint` gains `occurrence: int = 0` and `identity_scope: str \| None`. The builder sets `occurrence` from the row. `run_auto` sets `identity_scope` to the sender's identity before `run_pipeline`. | AUD / FUZZ |
| Evaluate | `audit.engine.evaluate` calls `reqctx.request_context(point)` once per point. It writes `evidence["request_context"]` (the dict) and `evidence["context_id"]` for every fired rule, and `context_id` into the `evaluation` row's evidence JSON. Every point source goes through it, so none can skip the identity. | AUD (CC-AUD-0056) |
| Confirm | `pipeline._confirmation_key` → `reqctx.confirmation_key(ev)`. `_candidate_of` carries `occurrence` and `context_id` onto the `Candidate`, which gains both fields. `test.start` carries `request_context` (the id). | FUZZ (CC-FUZZ-0106) |
| Finding | `Oracle._write_finding` writes `finding.context_id`, and the `finding` trace event carries `request_context`. A new body key, checked against existing keys (PA-0517): the verdict evidence's `context` means the XSS reflection context, a different thing. | FUZZ |
| Label join | `ml.dataset.build_dataset` joins on `(run, context_id, category[, seed])` when both rows have a context id, and on the legacy key per row otherwise. `fired` (the `rules_fired` feature) is counted per context. | **ML: no number assigned (§11.3)** |

**Importer details** (`tools/store_adapter.py`, SP-37's owner; every caller of
`_get_parameter` is swept):
- `_get_parameter(store, run, endpoint, name)` becomes a lookup on (endpoint, location,
  name, occurrence, form_id).
- A link set is a crawled URL's query (FR-CORE-32). One with **two or more entries**
  (entries, not names, so `tag=a&tag=b` counts) gets its own `form` row. Identical sets
  dedup, as today: (endpoint, entries) gives the same wire request. It also gets its own
  parameter rows, one per (name, occurrence). The "first crawled link wins" binding is
  removed. A one-entry set stays one lone point per (endpoint, name), as today. A refused
  set (destructive or credential) gives lone points, as today.
- `_import_forms`: each form's fields are rows of that form. "A link already gave this
  parameter: attach the form's siblings to it" is removed. A link context and a form
  context of one name are two points.
- `_store_request`: each captured request is its own context. Identical stored bodies
  (endpoint, enctype, entries) dedup. "The first one's leaf wins a name" is removed.
- `import_disco`: a form-encoded body is parsed to ordered pairs (`query_pairs`), not
  `dict(parse_qsl(...))` (`:274`), so a repeated name is kept in order.
  `_captured_leaves` accepts a pair list for a form body. (The spider's own captured form
  bodies are already a `dict` at the crawler's write, in `core/redaction.py`: §5.1, AU-REDACT.)

**The point builder** (`harness/auto.py`): `seen` is removed. Rows are unique per
context, and two rows of one (path, method, name) are two points (the audit's case).
`header_points_from_store` builds its representative query through the owner (§4),
never `"?" + urlencode(...)`.

### 3.3 The confirmation key and the dedup rule

```
confirmation_key(ev) =
    (ev["context_id"], category) + ((seed,) if category in SEED_CATEGORIES else ())   # v1
    (url, param, method, location, category)                                          # legacy row: no context
```

Rows share a test only when the key is equal. Equal means the same wire request for
every probe, and the same observation steps for every strategy of that category. A row
is marked `checked` only by its own key's test. The BUG-0072 / PA-0073 invariant still
holds, now over v1 keys: oracle calls equal distinct keys, and findings are at most
distinct keys, in all three modes. `decided_by` is merged per key as today. Under v1 a
stored observe point and a DOM point at one URL have different `setup`, so they are
separate keys, which is what BUG-0523 intended.

### 3.4 Effect on existing data

- **Old stores** keep their runs exactly. A row without `request_context` keeps the
  legacy key wherever it is read: the pipeline (not re-run on old runs) and the ML join
  (per row). A new run on an old store imports afresh into its own run, under v1.
  Migration 25 is additive, and NULL means legacy.
- **ML.**
  - The label join changes only for runs with context ids.
  - `rules_fired` per context changes the feature's distribution on crawl runs with
    several contexts per (path, param). This is a `FEATURE_VERSION` question for the ML
    item (Q4).
  - Mixed old and new training scopes are joined per row.
- **Scoring:** unchanged. The case key is (url, method, param, vuln_class), and detections
  are a set, so two findings of two contexts at one parameter count once.
- **UI:** the findings list can show two findings at one (url, param), one per context,
  without naming the context. That is a display follow-up (UI; §6).
- **Oracle budget:** tests equal Σ keys. On ground truth there is no change (measured).
  On a crawl the growth is unmeasured (§1.4). `confirm_budget` still caps keys and
  `skipped_budget` marks the rest, never a label. A run with no budget tests every
  context.

### 3.5 Identity scope

Within a run the identity label is constant. Isolated copies (FR-FUZZ-44) and
out-of-origin anonymous sends (FR-SESS-20) are decided per path and origin, which the
identity already contains. Recording it keeps labels from two runs with different
identities apart in a store-wide ML scope, and lets a cross-identity comparison
(FR-FUZZ-55's peer replays) cite the run's own context. The peer's sends are that
strategy's observations, not separate contexts.

### 3.6 Budget control (owner decision, Q1)

The default is exact: every distinct context is tested. Suppose the crawl measurement
shows pagination-like growth. Then the proposal is an opt-in per-family cap,
`fuzzlab auto --contexts-per-point N`, where a family is (origin, path, method,
location, target). Contexts are ordered by first crawl, with contexts whose sibling
*names* or non-data sibling values differ taken first. Contexts beyond N are marked
`skipped_budget` (unlabelled), counted in `metrics["contexts_capped"]`, and listed in
`skipped_points`, never `checked`. Limiting what the tool sends is the owner's call
(HANDOFF §7), so the draft does not impose a default.

## 4. Design B: one ordered query-entry representation and one placement (defect 14; SP-42 extended)

### 4.1 The owner

The owner is `fuzzlab/core/urls.py` (CORE), beside `place_path_param` (SP-42):

- **`QueryEntries(FormEntries)`.** An ordered list of decoded `(name, value)` 2-tuples, so
  every existing consumer (`dict(...)`, `for n, v in ...`, the access-control strategy's
  `dict(base_entries)`) keeps working. It carries a parallel tuple of raw pair texts:
  `None` for a pair built from decoded values, and for a pair that was replaced.
  - `QueryEntries.parse(raw_query)` keeps every part's raw text, order, duplicates, empty
    parts and `=` presence.
  - `.replace_at(name, occurrence, value)` replaces exactly that occurrence. When the name
    is absent: occurrence 0 appends `name=value`; any other occurrence raises
    `UnplaceableLocation`. It never relocates (PA-0115).
  - `.to_query()` emits raw text for untouched pairs and encodes the rest with the one
    encoder.
- **`encode_query_pair(name, value)`.** The one encoder: `quote_plus(…, safe="")`, what
  `urlencode` does today. So a query-less URL's wire bytes are unchanged, and so are
  scored results.
- **`place_query_param(url, name, value, occurrence=0) -> str`.** The URL with its own query
  parsed, that occurrence replaced in place, and every other part kept verbatim.
- **`with_query(url, entries) -> str`** (moved from `tools/authhttp.py`). The URL's query
  becomes `entries`. A `QueryEntries` uses its raw text; a plain list is encoded (a
  form's entries, which a browser serialises: PA-0111).
- **`FormEntries.replace_at`.** It addresses the occurrence for bodies too. `replace`
  (every occurrence) stays for `formnav`'s selector option, a crawler-side browser
  submission.
- `tools/authhttp.with_query_param` is removed. Its two callers go to
  `place_query_param`, and `test_shared_primitives`' defined-once check applies.

### 4.2 Placement contract (every sender, `FR-FUZZ-64(3)`)

A query payload goes to the **addressed occurrence** of its name: the point's
`occurrence`, 0 for a standalone point. It replaces that pair's value in place. Every
other pair keeps its position, its `=` (or its absence) and its raw text, up to the
client rewrites measured in §1.3. The payload is encoded by the one encoder.

- A missing occurrence 0 is appended once.
- A missing occurrence k > 0 is refused (`UnplaceableLocation`).
- A sender never adds a second pair for a name the query already has. That is a
  deliberate duplicate-parameter probe. **None exists today.** If one is added, it is its
  own mechanism, with its own context field (`target.duplicate`), never the default
  placement.

Bodies (form-urlencoded) follow the same rule over the form's entries, serialised as the
browser does.

| Sender | Required change |
|---|---|
| `probesender.RequestsProbeSender` | standalone query: `url = place_query_param(url, param, value)`, no `params=` (`:964`). Bound: `with_query` (owner) (`:946`) |
| `probesender.SeamProbeSender` (main session, isolated copy, anonymous; all go through `_send_on`) | standalone: `place_query_param` (`:822`). Bound: `with_query` (owner) (`:793`) |
| `greybox.RequestsCorrelatingSender` | standalone `place_query_param` (`:196`). Bound query: `with_query` (owner), never `params=list(entries)` (`:192`), which appends to a URL's own query |
| `blind_sqli_fuzzer.RequestsSender` / `SeamSender` | `place_query_param` (`:58`, `:82`) |
| `tools/browserexec` (M6) | `_with_query` (`:25`) → `place_query_param`, for the observe navigation and the GET store step (`:539`, `:552`) |
| oracle `_FormBoundSender` (also used by the access-control strategy, `strategies.py:1750`; name and signature kept) | `replace_at(param, candidate.occurrence, value)`. It also binds a standalone point whose URL has a query (its base is `QueryEntries.parse(url's query)`), so an occurrence > 0 reaches every sender as `entries` and the `Sender` protocol does not change |
| oracle M6 binding (new `_ContextBoundExecutor` in `oracle/oracle.py`; `ExecRequest` gains `entries` in `oracle/browser.py`) | The oracle wraps the executor it hands `default_strategies`, and sets the candidate per `confirm_outcome`. An `ExecRequest` for the candidate's own URL and query location gets the context's entries with `replace_at`. A crawled DOM query point is then loaded with its siblings; today the browser drops them. `strategies.py` is not edited |
| `pipeline._baseline` | `replace_at(point.param, point.occurrence, "1")` |
| `harness/auto.header_points_from_store` | its URL via `with_query(page_url, QueryEntries…)` (`:510`) |

### 4.3 How conformance is proven

- **`tests/test_sender_conformance.py`.**
  - `_Wire` stops collapsing. A requests-style send records the URL the session would
    send, `requests.Request(method, url, params=…).prepare().url`, which is requests' own
    merge (PA-0035). The seam transport records its URL as given.
  - New `test_every_sender_places_a_query_occurrence_in_place` runs the §1.2 table
    through every `PLACEMENT_FACTORIES` sender (discovered by AST; a new sender must
    register), plus greybox and both blind-sqli senders. It asserts **byte equality**
    between the two requests-based seams: same owner, same client.
  - New `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` is its
    synthetic offenders: an appender and a `dict` rebuilder (PA-0034(2)).
- **`tests/test_query_placement.py`** is the end-to-end proof on a loopback echo server.
  Every sender and real Chromium are compared with `canonical_pairs`, the measured
  equivalence (§1.3), and the platform facts are pinned in the same file.
- **The AST guard** (`test_every_query_builder_goes_through_the_one_owner`) applies to
  `fuzzlab/` outside `core/urls.py`. It flags:
  - `dict(parse_qsl(...))` on a URL or body that is then sent;
  - a `params=` keyword on a session or `requests` send in a sender module;
  - `"?"` or `"&"` concatenated with `urlencode(...)` or a `.query`;
  - `._replace(query=...)`.

  Exceptions are a reasoned allow-list (§5). It is proven on synthetic offenders
  (`test_the_query_builder_guard_catches_synthetic_offenders`).

## 5. The full sweep (PA-0002; by mechanism: every query builder and every dedup key, PA-0138(3))

### 5.1 Query builders: `dict(parse_qsl`, `params=`, `urlencode` + `?`/`&`, `_replace(query=`

| Site @8100959 | Pattern | Disposition |
|---|---|---|
| `tools/authhttp.py:17` `with_query_param` | `dict(parse_qsl)` rebuild | **fix**: removed; owner `place_query_param` |
| `tools/authhttp.py:25` `with_query` | `urlencode(list(entries))` replace | **fix**: moved to owner, raw-aware |
| `tools/probesender.py:793,822,946,964` | `with_query`, `with_query_param`, `params=` | **fix** (§4.2) |
| `greybox/run.py:192,196` | `params=list(entries)` / `params={…}` (appends) | **fix** |
| `tools/blind_sqli_fuzzer.py:58,82` | `params=` / `with_query_param` | **fix** |
| `tools/browserexec.py:25-29,539,552` | `query + "&" + urlencode(...)` | **fix** |
| `tools/browserexec.py:32-48` `_with_fragment` | appends the pair to a hash route's query | **fix** through `QueryEntries` over the route query (a ground-truth DOM URL may carry one); crawl fragment endpoints have none (`to_route_path`) |
| `tools/browserexec.py` store step `form={s.param: s.value}` | a form-body store sends no siblings | **residual** (§10): ground truth enumerates JSON store bodies only (`store_entries`) |
| `oracle/oracle.py:153` `_FormBoundSender` → `FormEntries.replace` | every occurrence | **fix**: `replace_at` |
| `harness/pipeline.py:107` `_baseline` | `FormEntries.replace` | **fix**: `replace_at` |
| `harness/auto.py:510` header-point query | `"?" + urlencode(...)` | **fix**: owner |
| `tools/store_adapter.py:274` (disco form body) | `dict(parse_qsl(body))`: a repeated name collapses | **fix**: ordered pairs |
| `tools/store_adapter.py:172,677` (link and route query import) | `parse_qsl` list; one row per name | **fix** in the importer (§3.2); route-query siblings stay a stated gap (FR-AUD-22) |
| `core/redaction.py:514-` `redact_captured_body` | a form body becomes an object, "the last value of a repeated name winning" | **flag to AU-REDACT** (their file): upstream collapse; the importer cannot recover it |
| `disco/runner.py:262` contract runner | `url += "&" + urlencode(query)` appends | **flag to AU-OUTCOME** (their file): pinned in their lane, or a strict xfail in a test we own if they cannot take it |
| `disco/synth.py:309,450,507` | `dict(parse_qsl)`; per-name schema merge | **defect 9's item** (captured API schemas), not a sender |
| `labgen/oracle_wrapper.py:457-489` `_mark_query_param` / `_mark_body_param` | replaces every occurrence; re-encodes untouched pairs | **LAB follow-up** (no CC-LAB number): call the owner; pinned with a strict xfail in the meantime (PA-0054(3)) |
| `labgen/identifier_sqli_oracle.py:409-417` | `dict(base_query_params)` | allow-listed: the request type is a mapping, so a duplicate cannot be expressed; generated cells declare none |
| `labgen/conformance/{live_boot,rails,django,spring}*.py`, `tier2.py:140` | `params=` on a query-less path | allow-listed: test-harness clients for generated cells; no existing query |
| `lab_fixtures/external.py:1089,1251` | `params=` constants | allow-listed: lab provisioning, not probing |
| `tools/spider.py:2842-2860` | GET form: action query replaced by the entries | allow-listed: HTML form submission semantics (a GET form replaces the action's query; PA-0111) |
| `session/detect.py:291,320` | `parse_qsl` set comparison | not a builder: login-URL detection (SP-16) |
| `web/app.py:625,1116`, `web/projectroutes.py:41` | `dict(parse_qsl(body))` | not a builder: the operator's own UI forms |
| `tools/observe.py:50,64`, `ml/flow_anomaly.py:43`, `tools/fetcher.py:517`, `tools/spa.py:226,267,908`, `core/urls.py:122,313`, `proxy/server.py:72`, `core/redaction.py:236,413` | read names or features, redact, or forward verbatim | not builders |
| `tests/test_sender_conformance.py::_Wire`, `tests/test_forms_phase2.py::_App`, `tests/test_json_points.py::_JsonWire` | test doubles that `dict` the query | **fix**: raw query (PA-0006: a double must carry what the real wire carries) |

### 5.2 Dedup and identity keys over requests

| Site | Key | Disposition |
|---|---|---|
| `store_adapter._get_parameter` (all 6 callers) | (endpoint, name) | **fix** (§3.2) |
| `store_adapter._import_link_sets` | `WHERE form_id IS NULL` (first wins); `len(names) < 2` | **fix** |
| `store_adapter._import_forms` | attach to an existing link parameter | **fix** |
| `harness/auto.injection_points_from_store` `seen` | (path, method, name) | **fix** (removed) |
| `harness/auto.header_points_from_store` `seen` | path (one header point per page) | kept: one per page and name, by design (FR-FUZZ-43) |
| `harness/pipeline._confirmation_key` | 5-tuple | **fix** (owner) |
| `harness/pipeline._dedup` (template clusters) | URL cluster | **defect 10's item**; untouched here |
| `ml/dataset.build_dataset` label and `fired` keys | (run, path, param, category, method) | **fix**: ML number needed (§11.3); PA-0076(3) obliges it once both sides record the id |
| `harness/scoring` | case key (url, method, param, vuln_class) | kept: the ground-truth case key; a set, so no double count |
| `harness/auto.points_from_ground_truth` `sink_contexts_by_point` | (url, method, param) | kept: PA-0048's one point per sink_context; those become one test under v1 |
| `tools/spider.StorageManager.record_form` / `record_request` signatures | names only / keys only, `url_key` | **flag** (CRAWL; measured §1.1): defect 9 and 10's items, or a CRAWL follow-up |
| `greybox/run.points_from_store` | drops `base_entries` (no siblings) | **residual** (§10); greybox runs stay sibling-less (FR-FUZZ-8 unchanged) |
| M10 `GreyboxStrategy` through `_FormBoundSender` (no `send_correlated`) | a bound candidate is unplaceable for M10 | **residual**; not this item (no verdict, never a negative) |

## 6. Shared primitives

- **SP-57 (new): the request-context identity.** "Which rows of a run are one test, and
  which finding a context gets."
  - Owner: `fuzzlab/core/reqctx.py::request_context` (with `context_id`,
    `confirmation_key`, `SEED_CATEGORIES`, `CONTEXT_VERSION`).
  - Readers: `audit.engine.evaluate` (the writer), `harness.pipeline`, `oracle._write_finding`,
    `ml.dataset`.
  - Guards: `test_every_candidate_field_a_sender_or_strategy_reads_is_in_the_identity_or_excluded`,
    `test_the_identity_field_guard_catches_a_synthetic_offender`,
    `test_the_seed_categories_are_the_strategies_that_read_the_original_value`,
    `test_shared_primitives::test_every_owner_is_defined_once`.
- **SP-42 (extended): placing a value in its URL**, a path segment or a query occurrence.
  - Owner: `core/urls.py::place_path_param`, now with `place_query_param`, `QueryEntries`,
    `with_query` and `encode_query_pair`.
  - Readers: every sender in §4.2, the oracle binder and the M6 executor.
  - New guards: the query-builder AST guard and its synthetic offenders, and the
    occurrence conformance check and its offenders.
- **SP-20** (the sender protocol) and **SP-37** (the importer) rows gain the new guard
  names and the per-context import.

`docs/SHARED_PRIMITIVES.md` is a shared doc, so this item does not edit it. The rows
above go in at merge (orchestrator).

## 7. Tests, each with the revert it must fail against (PA-0034(2))

**Measurement tests (committed).** Each becomes positive at implementation, and its strict
xfail is removed in the same change (MULTI_AGENT §6).

| Test | Must fail against |
|---|---|
| `test_request_contexts::test_a_name_in_the_query_and_the_body_of_one_request_is_two_points` | restoring `seen` (path, method, name) |
| `…::test_each_link_context_of_a_parameter_is_its_own_point` | `_get_parameter` by (endpoint, name), or first-wins binding |
| `…::test_each_captured_body_of_an_endpoint_is_its_own_context` | `_store_request`'s first-leaf-wins |
| `…::test_a_form_body_and_a_json_body_of_one_endpoint_are_two_points` | a parameter key without location or form |
| `…::test_the_pipeline_tests_a_context_that_only_its_siblings_reach` | `_confirmation_key` without siblings |
| `…::test_a_raw_body_and_a_form_field_of_one_url_are_two_tests` | an identity without `content_type` |
| `…::test_two_stored_cases_shown_on_one_page_each_plant_their_own_store` | an identity without `setup` |
| `…::test_a_context_never_tested_is_never_labelled_by_anothers_finding` | the ML join on (run, path, param, category, method), or no `finding.context_id` |
| `…::test_a_post_actions_query_parameter_is_a_point` | (split item) the importer never making a POST action's query a point |
| `test_query_placement::test_every_sender_replaces_the_addressed_occurrence_in_place[*]` (27 pinned, 3 hold) | any sender's `params=` append or `with_query_param` `dict` |
| `…::test_the_anonymous_and_authenticated_senders_send_the_same_query` | either sender family's old branch |
| `…::test_a_bound_duplicate_name_changes_one_occurrence_only` | `FormEntries.replace` in the binder |
| `…::test_the_browser_executor_replaces_the_addressed_occurrence_in_place` | `browserexec._with_query` appending |
| `…::test_platform_clients_rewrite_only_escapes_without_query_meaning` | a client upgrade that changes §1.3 (a platform pin) |
| `…::test_the_equivalence_still_tells_apart_what_a_server_reads_apart` | a weakened `canonical_pairs` (for example, one decoding `%2B`) |

**New at implementation.**

| Test | Must fail against |
|---|---|
| `test_request_contexts::test_every_candidate_field_a_sender_or_strategy_reads_is_in_the_identity_or_excluded` (AST over senders, oracle and strategies, reading `candidate.*` / `point.*`) | a new `Candidate` field read by a strategy and in neither list |
| `…::test_the_identity_field_guard_catches_a_synthetic_offender` | the guard ignoring a synthetic strategy reading a synthetic field |
| `…::test_the_seed_categories_are_the_strategies_that_read_the_original_value` | `SEED_CATEGORIES` disagreeing with the AST of `strategies.py` |
| `…::test_a_seeded_category_keys_on_the_original_value_and_others_do_not` | the seed always in the key (extra tests), or never (two owners' ids merge for access-control) |
| `…::test_sink_context_duplicates_stay_one_test` | `sink_context` in the identity (PA-0048's points confirmed twice) |
| `…::test_a_legacy_row_keeps_the_legacy_key_and_reads_unchanged` | dropping the v0 fallback |
| `…::test_two_runs_with_different_identities_never_share_a_label` | `identity` left out of the identity |
| `test_pipeline_invariants::test_one_confirmation_and_at_most_one_finding_per_key` (extended with v1 rows, three modes) | the budgeted path keyed differently from the unbudgeted one |
| `test_query_placement::test_an_absent_occurrence_is_refused_never_appended` | an append fallback for k > 0 |
| `…::test_a_dom_point_is_loaded_with_its_context_siblings` (real Chromium) | `ExecRequest` without the binder's entries |
| `…::test_every_query_builder_goes_through_the_one_owner` and `…::test_the_query_builder_guard_catches_synthetic_offenders` | a new `params=` / `dict(parse_qsl` builder in a sender |
| `test_sender_conformance::test_every_sender_places_a_query_occurrence_in_place` and `…::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` | `_Wire` reverted to a `dict`: the offender would pass |

**Existing tests that pin the old behaviour; each is amended in the same change, with
before and after stated (PA-0073(3)):**
- `test_forms_phase2::test_the_first_crawled_link_wins_for_a_shared_parameter`: each
  link context becomes a point.
- `test_forms_phase2::test_a_form_sibling_set_wins_over_a_link_query`: both contexts.
- `test_forms_phase2` `link_set_bound` counts (`:124`, `:235`): re-derived.
- `test_fuzzer_seam::test_with_query_param`: the owner's test.
- `test_fuzzer_seam::test_requests_sender_unchanged_standalone_behavior`: it pins the
  call shape `params={"id": "1"}`.
- Every crawl-point count assertion in the 21 test files that import crawls: re-derived
  per file (PA-0045: count each occurrence).

## 8. Requirement text (living specs, edited in place at implementation)

**FR-FUZZ-64** *(one test per request context; one query placement; `CC-FUZZ-0106`,
BUG-0530, BUG-0531)*. It supersedes FR-FUZZ-42's residual "one confirmation per (url,
param, method, location)" and, for parameters, FR-FUZZ-43's "the first crawled link
wins".

1. **One test per request context.** The pipeline confirms once per
   `core.reqctx.confirmation_key`: the request context's id and the category, plus the
   original value's digest for a category whose strategies read it (`SEED_CATEGORIES`).
   A candidate row is marked `checked` only by its own key's test. A row with no context
   (an older run) keeps the key `(url, param, method, location, category)`.
2. **The request context v1** (SP-57) holds:
   - origin, path, method and location;
   - the target occurrence (a name and occurrence, a JSON path, a header name or a
     path name);
   - the URL's ordered query pairs and the ordered body entries or JSON leaves, as
     sent, with the target's slot blanked;
   - the content type, the setup requests (a stored case's store request) and the run's
     identity.

   It never holds `sink_context`, the rule, the point's source or a value beyond its
   digest. It is written into each candidate's evidence (`request_context`,
   `context_id`) by the audit engine. It is carried on the `Candidate`, recorded on the
   finding (`finding.context_id`), and carried on the `test.start` and `finding` trace
   events (`request_context`).
3. **Query placement** (SP-42). Every sender places a query value at the addressed
   occurrence of its name (the point's `occurrence`, 0 for a standalone point), in
   place. Every other pair keeps its order, its `=` and its text, up to the clients' own
   escaping (pinned by a real-browser test). A missing occurrence 0 is appended once,
   and a missing occurrence k > 0 is refused (`UnplaceableLocation`). No sender adds a
   second pair for a name already present. These senders are covered:
   - `RequestsProbeSender` and `SeamProbeSender` (every session route);
   - greybox's `RequestsCorrelatingSender`;
   - both blind-sqli senders;
   - the oracle's binder;
   - the M6 browser executor, which now loads a query DOM point with its context's
     siblings.

   Form bodies address the occurrence the same way.
4. **Stated gaps:**
   - a stored link set's untouched siblings are re-encoded from the stored decoded
     values (`flag` is sent as `flag=`, `%20` as `+`);
   - a POST action's query parameters are not points (split item);
   - greybox points carry no siblings;
   - a form-body store request sends no siblings;
   - contexts the crawler's own signatures merged never reach the store.

**FR-AUD-31** *(the importer keeps every request context; `CC-AUD-0056`, BUG-0530)*. It
supersedes FR-AUD-22's "the first one's leaf wins a name" and FR-FUZZ-43's link binding.

- `import_spider` and `import_disco` write one `parameter` row per (endpoint, location,
  name, occurrence, sibling set) (`parameter.occurrence`, migration 25).
- Each crawled link query with two or more entries is its own sibling set, bound to its
  own rows. Identical sets after redaction are one.
- A form's fields are that form's rows, never merged into a link's.
- Each captured request body is its own context. Identical stored bodies are one.
- A disco form body keeps repeated names in order.
- `audit.engine.evaluate` writes each point's request context (FR-FUZZ-64(2)) into every
  fired candidate's evidence, and its id into the evaluation row's evidence.

**FR-CORE (number needed, §11.3).** Migration 25 adds `parameter.occurrence` and
`finding.context_id`. The `core.reqctx` and `core.urls` query owners are added (SP-57,
SP-42).

## 9. Draft change-control entries (pre-change gate; Effectiveness pending)

```
### CC-FUZZ-0106 — One test per request context; every sender places a query value at one exact occurrence (BUG-0530, BUG-0531) (2026-10-19)
- Change: the pipeline keys confirmation on `core.reqctx.confirmation_key` (FR-FUZZ-64(1));
  `_candidate_of`, `Candidate` and the `test.start` / `finding` events carry the context;
  `Oracle._write_finding` writes `finding.context_id`; `_FormBoundSender` addresses the
  candidate's occurrence (`replace_at`) and binds a standalone point whose URL has a
  query; a new `_ContextBoundExecutor` gives the M6 executor the context's entries
  (`ExecRequest.entries`); `_baseline` uses `replace_at`; `run_auto` stamps
  `identity_scope`; `injection_points_from_store` drops `seen`;
  `header_points_from_store`, both probe senders, greybox, both blind-sqli senders and
  `browserexec` place queries through `core.urls` (FR-FUZZ-64(3)). Files:
  harness/pipeline.py, harness/auto.py, oracle/oracle.py, oracle/probe.py,
  oracle/browser.py, tools/probesender.py, tools/browserexec.py, greybox/run.py,
  tools/blind_sqli_fuzzer.py, tools/authhttp.py (~260 LOC changed).
- Impact (other components / project): AUD (the engine writes the context; CC-AUD-0056),
  CORE (owners and migration 25; CC-CORE-0068), ML (the label join and `rules_fired`:
  number needed), UI (findings list shows several findings at one parameter: follow-up).
  Contract changes: candidate evidence gains `request_context`/`context_id`; `Candidate`
  gains `occurrence`/`context_id`; `ExecRequest` gains `entries`; the `Sender` protocol
  is unchanged. Consumers found by search (PA-0152): `_confirmation_key` (pipeline only),
  `with_query_param` (probesender, blind_sqli_fuzzer, tests/test_fuzzer_seam.py),
  `_FormBoundSender` (oracle, strategies.py:1750, tests), `FormEntries.replace`
  (pipeline, oracle, formnav — formnav keeps `replace`).
- Risk: medium-high. More tests on crawl runs (unmeasured, §1.4; mitigated by an opt-in
  cap the owner decides, `confirm_budget` unchanged); a changed query on any URL that
  already carries one (intended); duplicate-name forms now probe one occurrence per
  point (intended; measured in §1.2). Ground-truth runs: no change in tests or verdicts
  (measured, §1.4).
- Deliverables:
  - [ ] pipeline key, candidate/finding/trace carriage — todo
  - [ ] binder (occurrence, standalone query) and M6 executor binding — todo
  - [ ] every sender through the query owner — todo
  - [ ] tests of §7 (new, amended; strict xfails removed) — todo
  - [ ] BUG-0530, BUG-0531, PA-0530, PA-0531, ERROR_LOG, CHANGELOG (at merge) — todo
- Effectiveness (assessed after landing): pending.

### CC-AUD-0056 — The importer keeps every request context; the engine writes it (FR-AUD-31, BUG-0530) (2026-10-19)
- Change: `store_adapter._get_parameter` keyed on (endpoint, location, name, occurrence,
  form); `_import_link_sets` binds each set of two or more entries to its own rows (no
  first-wins); `_import_forms` stops attaching to link rows; `_store_request` keeps each
  body's leaves (identical bodies deduplicated); `import_disco` parses form bodies to
  ordered pairs; `audit.engine.InjectionPoint` gains `occurrence`/`identity_scope` and
  `evaluate` writes `request_context`/`context_id`. Files: tools/store_adapter.py,
  audit/engine.py (~140 LOC).
- Impact: FUZZ (more points on crawl runs), CORE (migration 25), CRAWL (none; its
  signatures are flagged), ML (more candidate rows per (path, param)).
- Risk: medium. Count assertions in 21 crawl-import test files move (re-derived,
  PA-0045); a refused link set still gives lone points (unchanged).
- Deliverables: importer [ ] todo; engine [ ] todo; tests [ ] todo.
- Effectiveness: pending.

### CC-CORE-0068 — Request-context identity and query placement owners; migration 25 (SP-57, SP-42) (2026-10-19)
- Change: new `core/reqctx.py` (`request_context`, `context_id`, `confirmation_key`,
  `SEED_CATEGORIES`, `CONTEXT_VERSION`); `core/urls.py` gains `QueryEntries`,
  `place_query_param`, `with_query` (moved), `encode_query_pair`; `core/forms.FormEntries`
  gains `replace_at`; migration 25 adds `parameter.occurrence INTEGER` and
  `finding.context_id TEXT` (additive; NULL = legacy). (~230 LOC.)
- Impact: every caller in §4.2 and §3.2; `test_contract_writers` (both columns have a
  writer); `SHARED_PRIMITIVES.md` rows (orchestrator, at merge).
- Risk: medium (a migration; additive, tested by injected failure per PA-0088(1)).
- Deliverables: owners [ ] todo; migration [ ] todo; guards [ ] todo.
- Effectiveness: pending.
```

## 10. Bug records and preventive actions (drafts)

**BUG-0530: distinct request contexts merged into one test** (defect 8).

The RCA is §2. The corrective action is CC-FUZZ-0106, CC-AUD-0056 and CC-CORE-0068.

*Recurrence review* (`docs/bugs/`, `PREVENTIVE_ACTIONS.md`):

- **The same root cause, an identity key omitting a field that distinguishes the unit:**
  - BUG-0046 / PA-0048: a (url, method, param) lookup collapsed `sink_context`.
  - BUG-0072 / PA-0073: `_confirmation_key` was introduced here.
  - BUG-0075 / PA-0076: a join omitted the method.
  - BUG-0138 (SP-08 `document_key`): a key omitted the query.
- **Prior-PA failure analysis.** Why didn't those rules prevent this?
  - PA-0076(1)/(3) are worded for *joins between two tables*. The merges here are
    *dedup keys inside one table or loop*: `seen`, `_get_parameter`,
    `_confirmation_key`. So PA-0076(3)'s sweep ("a new value of an identity field
    becomes possible") never ran when forms phases 1–3 added siblings, JSON leaves,
    content types and store requests. That is the wrong layer.
  - PA-0073 asserted "rows that would send the oracle the identical confirmation share
    one key". No test checks the claim against the fields that make confirmations
    differ: its invariant test varies only url and param. So it was not enforced.
  - PA-0048 called duplicates "safe" for scoring. It named consumers, but not the
    importer's own dedup. Too narrow.

*Preventive action.* **PA-0530** strengthens PA-0073 and PA-0076(3):

1. Whether two units are one request, test or label (a dedup set, a lookup key, a
   confirmation key, a join) is decided by one versioned identity owner (SP-57).
   Never by a hand-written tuple.
2. Every field a sender, strategy or executor reads from a point or candidate is either
   in that identity or in its exclusion table with a reason. An AST guard fails on an
   unclassified field, and it is proven on a synthetic offender.
3. A row is marked done only by its own unit's work.
4. A stated residual that merges distinct inputs ("first wins") is a defect to pin with
   a strict xfail, not a residual (PA-0054(3)).

- Enforced by: `tests/test_request_contexts.py::test_every_candidate_field_a_sender_or_strategy_reads_is_in_the_identity_or_excluded`,
  `tests/test_request_contexts.py::test_the_identity_field_guard_catches_a_synthetic_offender`,
  `tests/test_request_contexts.py::test_the_pipeline_tests_a_context_that_only_its_siblings_reach`

**BUG-0531: each sender placed a query value differently** (defect 14).

The RCA is §2. The corrective action is CC-FUZZ-0106 and CC-CORE-0068.

*Recurrence review:*

- **The same root cause, one seam's implementations not in step:**
  - BUG-0039 / PA-0041: transport settings.
  - BUG-0044 / PA-0046: redirects.
  - BUG-0071 / PA-0072: the signature.
  - BUG-0115 / PA-0115: placement by location.
- **A related rule:** BUG-0110 / PA-0111, form serialisation rule by rule. `RULES`
  already has "duplicates-kept-in-order", for forms only.
- **Prior-PA failure analysis.** Why didn't those rules prevent this?
  - PA-0115(2) made placement checked "by discovery", but at **location granularity**.
    Its wire (`_Wire`) parses the query into a `dict`, and its probe URL has no query.
    The check could not observe an occurrence, a duplicate or order. It was not
    enforced at the level the violation lives (cf. PA-0311(2)).
  - PA-0041 and PA-0072 synchronise settings and signatures, not the request a sender
    builds.
  - PA-0111's rule table covers `core.forms` serialisation. URL query mutation is a
    different code path with no rule. Too narrow.

*Preventive action.* **PA-0531** strengthens PA-0115(2) and PA-0111:

1. A value placed in a URL (query occurrence or path segment) is placed only through
   the one owner (SP-42). An AST guard rejects `dict(parse_qsl`, a send's `params=`,
   and `urlencode` concatenated onto a query outside it, with a reasoned allow-list.
   It is proven on synthetic offenders.
2. A placement check observes the raw request through the real client's own URL
   preparation, never a parsed `dict`. It is shown to fail on a sender that appends
   and on one that collapses.
3. Two senders of one seam are compared on the same request, under an equivalence
   measured on the real clients and pinned by a real-browser test.

- Enforced by: `tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner`,
  `tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders`,
  `tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`,
  `tests/test_query_placement.py::test_platform_clients_rewrite_only_escapes_without_query_meaning`

## 11. Residual limits, migration, split and open questions

### 11.1 Residual limits (stated in FR-FUZZ-64(4) / FR-AUD-31)

1. **Stored link-set siblings are sent from the stored decoded and redacted values.**
   `flag` is sent as `flag=` (Rack reads `nil` vs `""`), and `%20` as `+`.
   - Keeping the crawled raw text needs a `form.raw_query` column, written through the
     redaction boundary (PA-0100). That is deferred.
   - The URL's own query, the standalone path, keeps raw text.
2. **Contexts the crawler merged never reach the store.** Its form and request
   signatures (CRAWL, measured §1.1) and its form-body `dict` (`core/redaction.py`,
   AU-REDACT) merge them first. These are flagged to their owners and to defect 9.
3. **A POST action's query parameters are not points.** A query point on a request with
   a body needs a second entry list in the `Sender` protocol (SP-20). That is the
   proposed split item AU-REQID-POSTQ.
4. **Greybox has gaps.** Greybox points carry no siblings, and M10 cannot place a bound
   candidate (no verdict, never a negative).
5. **A form-body store step sends no siblings.** Ground truth enumerates JSON store
   bodies only.
6. **The identity scope is the run's identity label.** It does not distinguish an
   isolated copy's session (a function of the path, which is in the identity).
7. **The findings list can show two findings at one parameter** without naming the
   context (UI follow-up).
8. **The crawl test-count effect is unmeasured** (§1.4). The measurement is blocked by a
   permission denial, and the script is ready.

### 11.2 Migration

- Migration 25 is additive (`parameter.occurrence`, `finding.context_id`), and NULL
  means legacy. An injected mid-migration failure leaves nothing behind (PA-0088(1);
  the existing `test_migrations_atomic` pattern).
- Old runs are read with the legacy key per row.
- Nothing is backfilled. A legacy row has no recorded siblings or occurrence to derive
  a context from, and inventing one would fabricate data (PA-0108(2)).

### 11.3 Size, split and numbers

The whole design is about 630 LOC of production code and 600 LOC of tests. It touches
CORE, AUD, FUZZ, ML and test doubles in 21 files. That does not fit one 4 h item with
two reviewers and the bookkeeping. **Proposed split:**

- **AU-REQID-14 first (defect 14, BUG-0531 / PA-0531):** §4, the sweep of §5.1, the
  conformance and guard tests, and the M6 binding.
  - About 250 LOC. No schema change.
  - Uses CC-FUZZ-0106 and CC-CORE-0068, and FR-FUZZ-64 parts (3) and (4).
  - It provides `replace_at` and occurrence placement, which the identity needs.
- **AU-REQID-8 second (defect 8, BUG-0530 / PA-0530):** §3, the sweep of §5.2,
  migration 25 and the ML join.
  - It needs **new numbers**: CC-FUZZ (second), CC-CORE (second, for reqctx and
    migration 25), CC-ML (the join and `rules_fired`), an FR-CORE ID, and FR-FUZZ-64
    parts (1) and (2), unless FR-FUZZ-64 is split into two IDs.
  - It uses CC-AUD-0056, FR-AUD-31 and SP-57.
- **Hand-offs (flag, not this item):**
  - CRAWL signatures (§1.1), via defect 9 or 10's items or a CRAWL item;
  - `core/redaction.py` form-body `dict` → AU-REDACT;
  - `disco/runner.py:262` → AU-OUTCOME;
  - `labgen/oracle_wrapper.py` → a LAB number;
  - POST-action query points → AU-REQID-POSTQ;
  - findings-list context display → UI.

### 11.4 Open questions for the reviewers and the owner

- **Q1 (owner).** Default exact (every context tested), or an opt-in or default
  per-family cap (§3.6)? This should be decided on the crawl histogram. Running
  `crawl_measure.py` on a development-lab spider DB needs the read the classifier denied
  this lane.
- **Q2.** Should the `seed` set be derived by AST from `strategies.py` (proposed), or
  declared on each strategy? Declaring it needs an edit to AU-OUTCOME's file.
- **Q3.** Should the oracle-side M6 binding (`_ContextBoundExecutor`, set per
  `confirm_outcome`) be accepted, or should `strategies.py`'s `DomXssStrategy` pass
  entries once AU-OUTCOME merges?
- **Q4 (ML).** Should `rules_fired` per context bump `FEATURE_VERSION`?
- **Q5.** Should FR-FUZZ-64 stay one requirement (placement and identity) or be split
  across the two items?
