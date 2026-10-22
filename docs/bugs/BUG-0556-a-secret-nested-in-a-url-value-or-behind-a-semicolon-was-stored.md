# BUG-0556 — A secret nested in a URL value or behind a `;` was stored: the URL and sibling redactors judged a value as one flat token

- Date: 2026-10-22
- Status: fixed (lane REDACTURL, item GAP-VALUES; CC-CORE-0076, CC-AUD-0059)
- Severity: high (D12: a session id, an access token or a capability token reached the
  store, a replay recipe's page and, by name, proxy history)

## Description

The redaction owner (`fuzzlab/core/redaction.py`, SP-17/SP-18) judged a query value as
one flat token. `looks_like_identifier` splits a value on `. : @`, whitespace and (for a
URL) `/` only, so an identifier behind `?`, `=`, `&` or `;` sits in a piece that also
holds those characters, which are outside the identifier alphabet: the piece is never
identifier-like. The URL redactors split a query on `&` only and never looked inside a
value, and no redactor looked at a `;name=value` path parameter except the project-record
one. So a secret nested in a URL or a query string inside a query value, or behind a `;`,
was kept wherever the crawler or an importer stored it.

## Where encountered

The AU-REQID78 round-1 fix check (audit "Gap 5", item GAP-VALUES), measured on 7393c90
by `import_spider` over these page URLs (one each, with the page as its own
`found_from`):

| Spelling | Where the secret was stored |
|---|---|
| `?u=bob&next=%2Fview%3Fticket%3D<32 hex>` | `parameter.example`, `form.entries`, `form.source_page` |
| `?u=bob&next=/view?ticket=<32 hex>` | `parameter.example`, `form.entries`, `form.source_page` |
| `?u=bob&return=https%3A%2F%2Fhost%2Fcb%3Faccess_token%3D<jwt>` | `parameter.example` (the URL redactor blanked this one only because a JWT segment is identifier-shaped on its own; a short `access_token` was kept everywhere) |
| `?u=bob&a=1;token=<32 hex>` | `parameter.example`, `form.entries`, `form.source_page` |
| `/app/a;jsessionid=<32 hex>/b.php?u=bob&v=2` | `page.url`, `endpoint.url`, `form.source_page` |
| `/app/q.php?next=%2Fview%3Fticket%3D<32 hex>` (one name) | `parameter.example`, `form.entries`, `form.source_page` |

Probe: `scratchpad/lanes/REDACTURL/exp/repro.py` (before and after); the wider sweep of
writers, `exp/repro2.py`, found the same class in a crawled form's hidden values and its
POST action's query, a disco capture's POST URL query, and the path-template endpoint.

## What it caused to fail

- **D12 / PA-0100:** a session id, an OAuth/one-time token or a capability token was
  persisted in the project store (`page`, `endpoint`, `parameter`, `form`), in the replay
  recipe's `source_page`, and -- through the name-only redactor -- in proxy history, the
  core HTTP recorder's flows, the disco capture and the spider's form and landing URLs
  (`redact_url` never looked inside a value or behind a `;`).
- **BUG-0544 / FR-FUZZ-67:** `page_url_is_clean` called such a page clean, so it was
  stored as `source_page` and the binder would fetch it with the stored token on the wire,
  the exact path BUG-0544 review B1 closed for flat values.
- `parameter.example` stored every crawled value as crawled (the reserved BUG-0120, which
  `tests/test_forms_phase2.py` asserted as "still needed").

## What the bug was identified to be

1. `core.redaction.looks_like_identifier` is a flat-token predicate; every URL and
   sibling redactor (`redact_url_identifiers` via `_redact_query_identifiers`,
   `store_adapter.redact_sibling`, `page_url_is_clean`) used it on the whole value.
2. `redact_query` / `redact_url` split on `&` only and judged names at the top level only.
3. No redactor of a stored URL handled a `;name=value` path parameter; `core.urls.
   store_url` kept a middle segment's (`urlparse` drops only the last segment's).
4. The importer stored `parameter.example` raw for link sets, lone query points and SPA
   fragment parameters; a crawled form's entries passed the name rule only; a POST form's
   action query and a disco-captured request's URL query passed no identifier rule.

## Root cause analysis

Five Whys:

1. *Why was the token stored?* The sibling rule and the URL rule judged `"/view?ticket=
   <hex>"` and `"1;token=<hex>"` as one token; the token's piece held `?`/`;` and failed
   the identifier alphabet.
2. *Why was a structured value judged as one token?* The redactor modelled a URL as one
   level: a query of `&`-separated pairs whose values are opaque. Nothing in the owner
   modelled a value as possibly being a URL, a query string or a `;` list, nor decoded a
   percent-encoding layer before judging.
3. *Why did no test catch it?* Every redaction test planted secrets at the top level of
   a query (`?token=…`, `?t=<hex>`), varying name and shape (PA-0085(2), PA-0091(1)),
   never position: depth, encoding or separator. BUG-0514/0521 added embedded shapes, but
   to the trace's own redactor (`core.trace.safe_ref`) and its tests, not to the owner.
4. *Why did BUG-0544's `page_url_is_clean` inherit it?* It was defined as "the strongest
   redactor leaves it unchanged", which made the owner's coverage the predicate's; its
   proofs were a generated sweep of *loopback* bypass shapes (PA-0544(7)), not of where a
   secret can sit in a URL.
5. *Why were importer writers outside the owner's rule?* The sibling rule was applied
   to link-set entries only; `parameter.example` was a known leak deferred as "reserved"
   (BUG-0120) and asserted in a test, and the form and captured-URL writers took the
   name-only redactor by analogy with their source.

**Root cause:** the owner's value model was flat. A URL value was judged as one token and
a URL as one level of `&` pairs, and its tests enumerated secret *shapes* and *names* but
never secret *positions* (nesting depth, percent-encoding layers, `;` separators, path
parameters), so every consumer that relied on "the strongest redactor" inherited the
blind spot, and three importer writers did not reach even that.

## Corrective action

CC-CORE-0076 (owner) and CC-AUD-0059 (importer); FR-CORE-537 (new), FR-CORE-32 amended.

- `core/redaction.py`: `_UrlWalk`, one walk for both URL redactors. At every level, a
  sensitively named pair or path parameter gets `PLACEHOLDER`; with identifiers, an
  identifier-like value is blanked (`""` at a URL's own query or fragment, as before;
  `PLACEHOLDER` when nested or in a path parameter); a value with structure is walked (a
  nested URL: path parameters, query, fragment, and a token in its host or path redacts
  the outer value whole; a query string: its `&`/`;` pairs); a value with neither is
  percent-decoded one layer and walked again, and re-encoded (`quote(safe="")`) only when
  something changed. Past `MAX_VALUE_DEPTH` (12) levels or `MAX_VALUE_CHARS` (64 KiB),
  with a layer still undecoded, or on any failure, the top-level value is redacted whole.
  Clean text is byte-identical. `redact_url` (names) and `redact_url_identifiers`
  (names + identifiers) are the walk; `redact_spa_fragment` walks a route's query;
  `page_url_is_clean` checks `&` and `;` pairs. New `value_holds_secret`, `stored_value`
  (the one stored-value rule) and `strip_secret_path_params`.
  `looks_like_identifier` (SP-18) and the body redactors are unchanged.
- `core/urls.py::store_url`: a path parameter that holds a secret is dropped
  (`strip_secret_path_params`), as `to_path` drops the last segment's.
- `tools/store_adapter.py`: `redact_sibling` is `stored_value`; every
  `parameter.example` of a link set, a lone query point, an SPA fragment parameter and a
  path template passes it; a crawled form's entries pass it (a changed one is blanked
  and named in `fresh`); a POST form's action query and a captured request's URL query
  pass `redact_url_identifiers`; a path template's path passes `strip_secret_path_params`.
- Tests: new `tests/test_redaction_nested.py` (a generated sweep of 750 spellings: 3
  depths x 10 secrets x 3 separators x 4 encodings x 3 nested shapes, plus 20 path
  parameter cases; the store, proxy history, the HTTP recorder and `safe_ref` searched
  for every secret run in any decoding; a benign list left byte-identical; bounds and
  totality; one strict xfail pin). `tests/test_forms_phase2.py` now requires
  `parameter.example` clean too (BUG-0120 closed); `tests/test_query_placement.py` drops
  three allowances for code that no longer exists.
- Proof on the pre-fix code: one invocation of `tests/test_redaction_nested.py` and
  `tests/test_forms_phase2.py` with the three product files of 7393c90 swapped in
  (`scratchpad/lanes/REDACTURL/prefix_proof.sh`, `prefix.log`): 62 failed, 274 passed,
  2 xfailed. Every defect test failed on its assertion (the secret found); the benign,
  bound and totality tests failed only because the new API (`stored_value`,
  `value_holds_secret`, `MAX_VALUE_DEPTH`, `MAX_VALUE_CHARS`) did not exist.

### The PA-0002 sweep, by primitive (every caller of the owner and every writer of a URL or sibling value)

| Writer / caller | Through the owner after the fix | Disposition |
|---|---|---|
| `core.urls.store_url` (page.url, endpoint.url of every importer) | `strip_secret_path_params` | fixed here |
| `store_adapter._import_page_url` / `_import_link_set` (link set entries, lone and set examples) | `redact_sibling` = `stored_value` | fixed here (examples were raw: BUG-0120) |
| `store_adapter._source_page` (form.source_page) | `page_url_is_clean` (walk) | fixed by the owner |
| `store_adapter._import_route_query` (fragment examples) | `redact_sibling` | fixed here (were raw) |
| `store_adapter._import_path_templates` (endpoint path, path example) | `strip_secret_path_params`, `stored_value` | fixed here |
| `store_adapter._import_forms` (form.entries, examples, POST action query) | `stored_value` + `fresh`; `redact_url_identifiers` | fixed here (name rule only before) |
| `store_adapter._store_request` (captured request's endpoint URL query) | `redact_url_identifiers` | fixed here (a disco capture redacts names only) |
| `store_adapter._store_request` (captured body leaves -> form.entries, examples) | `core.redaction.redact_leaf` (flat) | **residual R1, pinned** (body redaction paused by the owner) |
| `tools/spider.py` capture writer (`discovered_requests.url`), `_queue_xhr`, `_spa_url` | `redact_url_identifiers` / `redact_spa_fragment` | fixed by the owner; its body (`redact_captured_body`) is R1 |
| `tools/spider.py` `record_form` (page/action URL), `mark_visited` landing and `found_from` | `redact_url` (names) | fixed by the owner (nested names, `;`, path parameters); identifier-shaped values there are re-judged by the importer |
| `proxy/history.py` (`redact_url`), `proxy/redact.py` (request target, Location/Content-Location/Refresh) | `redact_url` | fixed by the owner |
| `core/http.py` recorder | `redact_url` | fixed by the owner |
| `disco/capture.make_record`, `disco/runner`, `disco/explore` (actions.jsonl), `disco/ede` | `redact_url` | fixed by the owner |
| `core/trace.safe_ref` (finding and trace evidence, diagrams) | `redact_url_identifiers` then `redact_for_record` | fixed by the owner |
| `oracle._write_finding` (`finding.url`) | `to_path` of the candidate URL, which is a stored endpoint (above) | clean by its source |
| `core/redaction.redact_for_record` (project records) | `_redact_piece` -> `redact_url` | fixed by the owner |
| `core/redaction.redact_query` (form bodies, disco's execution route key) | unchanged | body redaction: not changed (the owner's instruction); the execution route is an in-memory comparison key, never stored as a URL |
| `audit/value_shape.redirect_seed`, `disco/fingerprint`, `session/manager`, `tools/spa`, `disco/synth`, `core/pathtemplate` | `looks_like_identifier` (unchanged) | not writers of a stored URL value; SP-18 is unchanged, so their behaviour is unchanged |

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for redaction misses and for
"judged as one token":

- **BUG-0084 / PA-0085, BUG-0090 / PA-0091, BUG-0099 / PA-0100, BUG-0100 / PA-0101:**
  the name predicate, whole subtrees under a sensitive key, one boundary for every
  producer, fail closed. Same family (a redactor's coverage), not the same root cause:
  each varied names, shapes and producers, never position inside a value.
- **BUG-0514 / PA-0514 and BUG-0521 / PA-0521: a match.** The trace's URL redactor
  judged values and path segments whole, so a token embedded in text, a matrix parameter
  or a query-shaped fragment was kept; PA-0521(1): "a redactor that judges whole segments
  also judges the identifier runs inside them".
- **BUG-0544 / PA-0544(7): a match in its consequence.** `page_url_is_clean` was made
  "the strongest existing redactor leaves it unchanged", so the predicate inherited this
  bug; PA-0544(7) required a generated sweep for the loopback predicate only.
- **BUG-0120 (reserved, no report):** `parameter.example` holds raw crawled values; it
  was deferred and asserted in a test as "still needed". Same root cause at the importer.

## Prior-preventive-action failure analysis

- **PA-0514 / PA-0521 (BUG-0514, BUG-0521): wrong layer, and enforced on one consumer.**
  Both bugs were fixed inside `core.trace` (`_blank_identifiers`, `_TOKEN_RUN`) on top of
  the owner's output, and their tests (`test_trace_model.py`) exercise `safe_ref` only. The
  rule "judge the identifier runs inside a whole value" was never carried to the owner
  that every other sink calls, so the crawler, the importer, proxy history and the replay
  recipe kept the flat model. PA-0514(1) says "use the strongest existing redactor"; it
  does not say that a gap found in a consumer is fixed in the owner, and SP-17's rule 1
  ("made in its owner only") was not applied because the trace fix was seen as a trace
  feature.
- **PA-0544(7) (BUG-0544): too narrow.** "What a recipe records passes the strongest
  existing redactor" delegates to that redactor's coverage without testing it; its
  generated sweep was over loopback bypass spellings, not over where a secret sits.
- **PA-0085(2) / PA-0091(1): too narrow.** They enumerate name forms and value shapes,
  and every planted secret sat at a query's top level.
- **BUG-0120 was not a PA at all:** a known leak kept as a test assertion is a deferral
  in prose with a guard that protects the leak (the failure mode PA-0531(4)/PA-0054(3)
  name: pin a residual as a strict xfail that fails when it is fixed, never assert it).

## Preventive action

**PA-0556** (strengthens PA-0514(2)/PA-0521(1), PA-0544(7) and PA-0085(2)/PA-0091(1);
added to `docs/PREVENTIVE_ACTIONS.md`):

1. **A redactor models a value as possibly structured.** Wherever a value can sit in a
   URL (a query pair, `&` or `;` separated, a path parameter, a query-shaped fragment),
   the owner walks it as a nested URL, a query string or a percent-encoded layer, to a
   stated bound, and redacts the whole top-level value past the bound or on failure.
2. **A redaction test is generated over position as well as name and shape:** nesting
   depth, encoding (raw, single and double percent, `+`), separator (`&`, `;`, mixed),
   path parameters; each case searched for every secret run in every stored copy and in
   every decoding; plus a benign list asserted byte-identical.
3. **A redaction gap found in one sink is fixed in the owner** (SP-17, rule 1) and its
   sweep lists every writer of the kind of value, with its disposition; a writer that
   stores a value outside the owner's rule is a defect, and a known one is pinned by a
   strict xfail, never asserted as "by design".

- Enforced by: `tests/test_redaction_nested.py::test_every_nested_spelling_of_a_secret_is_redacted_and_the_url_stays_a_url`,
  `tests/test_redaction_nested.py::test_no_generated_spelling_reaches_the_store_through_import_spider`,
  `tests/test_redaction_nested.py::test_no_generated_spelling_reaches_the_store_through_import_disco`,
  `tests/test_redaction_nested.py::test_proxy_history_and_the_http_recorder_store_no_nested_credential`,
  `tests/test_redaction_nested.py::test_ordinary_nested_values_are_left_byte_identical`

## Residuals (pinned or stated with reason)

- **R1 (pinned):** a captured request body's leaf holding a nested token
  (`next=%2Fview%3Fticket%3D<hex>` in a form or JSON body) is judged by the flat leaf rule
  (`core.redaction.redact_leaf`, also the spider capture's `_blank_tree`) and reaches
  `form.entries` and `parameter.example`. Body redaction is paused by the owner (audit
  defect 26, AU-REDACT); this lane may not change it. Pinned by
  `tests/test_redaction_nested.py::test_a_captured_body_leaf_holding_a_nested_token_is_never_stored`
  (strict xfail).
- **R2 (pre-existing, PA-0544 class, stated for LABAUTH):** a POST form's action query or
  a captured request's URL query that redaction changed is stored redacted on
  `endpoint.url` and sent so by its probes (a spider-captured URL already was, since
  FR-CRAWL-13). No fresh binding of an endpoint's own query exists; that is replay
  binding's scope (PA-0544(1)/(3)), not redaction's.
- **R3 (out of the class, by design):** an identifier-shaped *top-level path segment*
  (`/item/<uuid>/view`) is a page's identity and is stored (FR-AUD-26 templates it); a
  token glued to characters outside the identifier alphabet with no separator
  (`(<hex>)`) is SP-18's stated limit, unchanged here.
