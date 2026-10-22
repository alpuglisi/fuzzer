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
  *(Corrected in review round 1, RU-5: false for the headline test,
  `test_every_nested_spelling_of_a_secret_is_redacted_and_the_url_stays_a_url`, which
  stopped on `AttributeError: … value_holds_secret` (`prefix.log` lines 20-46). It now
  asserts its leak list first and fails there on 7393c90; see "Review round 1".)*
  *(Corrected in review round 2, N5: also false for
  `test_a_value_past_the_depth_bound_is_redacted_whole`, which stopped on `AttributeError:
  … MAX_VALUE_DEPTH` though the old code kept the hex (a defect test, not a bound
  test), for the size-bound test (`MAX_VALUE_CHARS`), and for
  `test_the_redactors_are_total[http://[::1/x?token=a;b=%2F%3F]`, where the old
  redactor raised `ValueError: Invalid IPv6 URL` (not total: `prefix.log` lines
  1192-1266). Every test of the file now asserts its behaviour before any new API; the
  sweep on 7393c90 is in "Review round 2".)*

### The PA-0002 sweep, by primitive (every caller of the owner and every writer of a URL or sibling value)

*(Superseded by the review-round-1 table below: this one was read from the callers' code,
and missed `import_audit` (no owner call), the proxy's `?` gate and the record redactor's
flat fragment.)*

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
- **R2 (pre-existing, PA-0544 class, stated for LABAUTH)** *(review round 1, RU-4: the
  label was wrong for an identifier in a form's action query or a disco capture's URL
  query, which this change began to blank and send; fixed there, narrowed to the spider
  capture and re-pinned: see "Review round 1: residuals")*: a POST form's action query or
  a captured request's URL query that redaction changed is stored redacted on
  `endpoint.url` and sent so by its probes (a spider-captured URL already was, since
  FR-CRAWL-13). No fresh binding of an endpoint's own query exists; that is replay
  binding's scope (PA-0544(1)/(3)), not redaction's.
- **R3 (out of the class, by design):** an identifier-shaped *top-level path segment*
  (`/item/<uuid>/view`) is a page's identity and is stored (FR-AUD-26 templates it); a
  token glued to characters outside the identifier alphabet with no separator
  (`(<hex>)`) is SP-18's stated limit, unchanged here.

## Review round 1 (c3a13f7): what the first fix missed

Two reviewers, with a skeptic per finding, reproduced ten findings on c3a13f7: eight
defects, since RU-1 = RU-6 and RU-3 = RU-8 (`scratchpad/lanes/REDACTURL/review_round1.md`).
Each is fixed on branch `lane/REDACTURL-r1` (2568927). The owner's and the importer's
parts are in the review-round sub-bullets of CC-CORE-0076 and CC-AUD-0059. The FUZZ and
PROXY callers' entry texts are in the lane's doc texts, numbered by the coordinator. Each
fix has a test in `tests/test_redaction_nested.py` that fails on its own assertion on
c3a13f7 (RU-5 on 7393c90, as that finding says):

1. **RU-1 / RU-6: a layer left encoded behind a raw `/` or `://`.**
   - **What failed.** Some encoders leave `/` (and `:`) raw and encode `?`, `=`, `&`,
     `;`, `#` and `@`: Python's `quote()` by default (`safe="/"`), `quote(safe="/:")`,
     and Django's `redirect_to_login` (`QueryDict.urlencode(safe="/")`). Such a value
     took `nested_url`, which partitions on raw delimiters only, so
     `next=/orders/view%3Fticket%3D<hex>` was kept by every redactor. `page_url_is_clean`
     held for it, so the page reached `form.source_page` and would have been fetched
     with the token.
   - **Fix.** A value with a percent-escape and no raw query structure (no raw `?`, `#`,
     `=`, `&` or `;`) is decoded one layer first, as a whole. In such a spelling `/` is
     raw at every layer, so a raw `/` can belong to a value nested inside. Decoding each
     path segment alone was tried first and missed the sweep's depth-3 userinfo case. In
     a value whose query structure is raw, each value is decoded at its own level, and a
     nested URL's path segment that is still encoded is decoded and walked.
   - **Design measured.** The review proposed walking every value again, decoded, after
     the raw walk. On the oracle's URL that took 34 steps and 8.3 identifier-predicate
     characters per URL character and 84 step calls per pair, where the fix takes 8.3,
     1.6 and 12. It doubles at every encoded level. So a value is decoded first or split
     first, never both (`scratchpad/lanes/REDACTURL/r1probe/lin.py`).
   - **Tests.** The sweep's `_ENCODINGS` gains `slash`, `slash2` and `colon`, and with
     RU-2's shape the sweep has 1710 cases. New:
     `test_a_layer_left_encoded_behind_a_raw_slash_is_decoded_wherever_it_is_read` (8
     spellings, Django's included) and
     `test_the_review_round_1_spellings_store_no_secret_through_import_spider`.
2. **RU-2: userinfo in a nested URL.**
   - **What failed.** `https://bob:<password>@host/` in a value was stored in
     `parameter.example`, `form.entries` and `form.source_page` whenever the password
     was not identifier-shaped. The record boundary and `safe_ref` already treated
     userinfo as a credential.
   - **Fix.** `_UrlWalk.userinfo` replaces `user[:password]@`, through the authority's
     last `@` or `%40`, by `PLACEHOLDER@`, in both redactors. `value_holds_secret` then
     holds, and `stored_value` blanks the value. `PLACEHOLDER` survives percent-encoding,
     so `page_url_is_clean` sees it in any spelling, where `***@` would be encoded to
     `%2A%2A%2A%40` and missed.
   - **Tests.** The sweep's new `userinfo` shape, with the password percent-encoded as a
     URL carries one; `test_a_nested_urls_userinfo_is_a_credential_in_both_redactors`;
     the round-1 store test.
3. **RU-3 / RU-8: `import_audit` bypassed the owner.**
   - **What failed.** `fuzzlab audit --store` runs `import_spider` and then
     `import_audit`. `import_audit` stored `to_path(page_url)`, which keeps a middle
     segment's `;ref=<uuid>`. That gave a second endpoint beside the spider's. It also
     stored the rules' `target_identifier` (`<path>?<name>`) and `html_context`
     (`example value: …`, `value '…' reflected`, `supplied 2x: …`, `called from <url>`)
     unredacted.
   - **Fix.** The endpoint is `store_url(page, main)`; the run's main origin is
     `base_url`'s, else the first finding page's, as in the other importers.
     `_audit_text` replaces in both texts the page URL (by
     `redact_url_identifiers`' form), the page path (by `strip_secret_path_params`'), and
     every query value the owner's rule would not store, whole or cut where a rule cuts
     it (80, 60, 40, 20). A target identifier also passes `strip_secret_path_params` and
     `redact_url_identifiers` itself.
   - **Test.** `test_import_audit_stores_the_spiders_endpoint_and_no_secret` runs the
     real chain: the spider's rows, `load_urls`, `audit_page` with every real rule and a
     fake fetcher, `import_spider`, then `import_audit`.
4. **RU-4: a regression mislabelled "pre-existing".** BUG-0556's change stored a POST
   form's action query and a disco-captured request's URL query through
   `redact_url_identifiers`. An identifier there (`?id=<uuid>`) was stored as `id=`, and
   every probe sent that blank as the request's own value, a new false negative.
   - **Disposition (PA-0544).** Recording the names as `fresh` would need a new binder
     capability: the binder binds sibling entries from the page's form, and an action
     URL's query is not an entry. So the test is made unbound (PA-0544(3)).
   - **How.** The importer records the redacted value as `PLACEHOLDER`, by name, never
     by value (`redact_url_identifiers(..., placeholder=True)`, PA-0544(1)).
     `harness.auto._redacted_url_refusal` gives a `replay_refusal` to every crawl point
     whose own URL holds a placeholder (`core.redaction.holds_placeholder`). The oracle
     then returns `UNBOUND` before any strategy runs, and nothing is sent.
   - **Also closed.** This closes the part of the old R2 pin that existed before this
     change: a sensitive name in a crawled action URL (`token=__REDACTED__`) was sent
     that way.
   - **Cost.** Such a form's tests are inconclusive where they sent the blank before.
   - **Test.** `test_an_endpoint_query_redaction_changed_is_never_sent` replaces the
     strict xfail. It uses the identifier-only action `?id=<uuid>`, `?token=abc&state=
     <hex>` and a disco `POST /api/x?id=<uuid>`, and runs the oracle with a sender that
     refuses any send. R2 is narrowed (Residuals below).
5. **RU-5: the headline test's pre-fix proof was masked.**
   - **What failed.** On 7393c90 the test stopped with `AttributeError: …
     value_holds_secret` before its assertion.
   - **Fix.** The leak, clean-page and shape failures are now asserted first, and
     `value_holds_secret` is looked up with `getattr` in a separate, later assertion.
   - **Proof.** The test was run on a `git archive` export of 7393c90, by a plain Python
     call with no pytest session (`scratchpad/lanes/REDACTURL/r1_ru5_7393c90.log`). It
     fails with an `AssertionError` at line 158, `assert failures == []`. The proof
     sentence under "Corrective action" was false for this test, and is corrected there.
6. **RU-7: the proxy's `?` gate.**
   - **What failed.** `proxy.redact.redact` passed the request target, `Location`,
     `Content-Location` and `Refresh` to `redact_url` only when they held a `?`. So a
     `;jsessionid=` path parameter in a URL with no query (Tomcat's URL rewriting) stayed
     in the stored raw messages and their full-text index.
   - **Fix.** Every one of these is passed to `redact_url`. It returns a URL that holds
     no value byte-identical, so a clean message is unchanged.
   - **Test.** `test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query`
     covers 6 names, each in a middle segment, a last segment and a second parameter, and
     in `Location`, `Content-Location` and `Refresh`.
7. **RU-9: the record redactor judged a route fragment flat.**
   - **What failed.** `redact_for_record`'s `_redact_piece` passed a fragment's query to
     `redact_query`, so a credential nested in `#/r?next=…` was kept in `launch.argv`,
     `launch.target` and `project.targets`.
   - **Fix.** After the matrix substitution, `_redact_piece` returns
     `redact_url(piece)`. The walk is total, so the `ValueError` fallback is gone.
   - **Tests.** `test_a_project_record_redacts_a_credential_nested_in_a_route_fragment`
     (342 generated cases) and
     `test_a_launch_record_holds_no_credential_nested_in_a_route_fragment` (through
     `project.insert_launch`).
8. **RU-10: the linearity oracle was never proven on a quadratic form.**
   - **What failed.** The oracle counted only the identifier predicate's reads (against
     PA-0135(2)), and it was never run on a deliberately quadratic variant (PA-0135(3)).
   - **Fix.** `core.redaction.WalkCounter` (`steps`, `calls`). Every walk step adds the
     length of its text, and `_walk_url(..., counter)` exposes the counts. The oracle
     requires steps at most 12 times the URL's length, at most 20 calls per pair, and
     identifier-predicate reads at most 3 times the URL's length, at 500 and at 4000
     pairs. Measured: 8.3, 12 and 1.6.
   - **Tests.** `test_the_linearity_oracle_flags_a_quadratic_walk` runs the same oracle
     on three variants at 100 pairs, and each is flagged:
     - (A) a pair step that decodes the whole list once per pair. The first oracle passed
       this one: 807 steps per character.
     - (B) the every-layer re-walk that this round rejected for RU-1.
     - (C) a pair step that judges the whole query per pair.

**Pre-fix proof (PA-0545(6)).** One pytest invocation ran `tests/test_redaction_nested.py`
with c3a13f7's four product files swapped in (`fuzzlab/core/redaction.py`,
`fuzzlab/tools/store_adapter.py`, `fuzzlab/harness/auto.py`, `fuzzlab/proxy/redact.py`),
then restored them (`scratchpad/lanes/REDACTURL/r1_prefix.log`, mapped per line in
`r1_prefix_map.txt`): 331 failed, 121 passed, 2 xfailed. Every failure is an
`AssertionError` on the test's own assertion; none is an import, attribute or type
error. The 16 failing tests:
- the headline sweep and the name-only sweep (`assert failures == []`);
- the layer test (8 of 8) and the userinfo test (7 of 7);
- the `import_spider` and `import_disco` sweeps and the round-1 store test (11 of 11);
- the existing proxy and recorder test, and the query-less proxy test (6 of 6);
- the record test (288 of 342; the depth-1 cases passed, caught by `_MATRIX_PARAM` or
  `redact_query`) and the launch-record test;
- `safe_ref`;
- `import_audit` (its leak assertion);
- the endpoint-query test (`assert blanks == []`);
- the linearity test and its oracle test (no `WalkCounter`).

The tests that passed are the axis, benign, bound and totality tests, the matrix tests
and the first round's reported spellings. The two strict xfails are R1 and the narrowed
R2.

**Why the first fix missed them.**
- **The sweep read each writer's code instead of measuring what it stored.** It missed
  `import_audit`, which called no owner. It missed the proxy, which called the owner
  behind a gate it did not read. It missed the record redactor, which called the owner
  for the base only (RU-3, RU-7, RU-9).
- **The sweep's encodings were the author's, not those real encoders produce.** It
  generated fully encoded values, never the measured defaults (`quote`'s `safe="/"`,
  Django's `redirect_to_login`). Its positions left out userinfo, which the owner's other
  redactor already called a credential (RU-1, RU-2).
- **A change to what a request sends was judged as a storage change only.** An
  endpoint's own query is replay material, not only a stored value (RU-4).
- **PA-0545(6) and PA-0135(2)/(3) were read but not applied** (RU-5, RU-10).

**Recurrence review (round 1).** These are BUG-0556's own review findings. PA-0556 is
strengthened with items 4 to 6, and its enforcement list is extended. No new PA number
is assigned, as the lane's numbers allow. The prior-PA failure analysis above still
holds; what this round adds is the way PA-0556(3)'s sweep was carried out: by reading
callers, not by measuring them.

### The PA-0002 sweep after review round 1, by caller (supersedes the table above)

Every caller of `redact_url`, `redact_url_identifiers`, `store_url` and `stored_value`
(with `redact_sibling`), every other caller of the owner's URL rules, and every writer of
a URL or URL-derived text to the store. Measured by the tests named, not read.

| Caller (file:function) | Calls | What it stores or sends | Disposition |
|---|---|---|---|
| `core/http.py` `HttpClient` recorder | `redact_url` | `flow.url` of the core client's flows | fixed by the owner (RU-1, RU-2 included); `test_proxy_history_and_the_http_recorder_store_no_nested_credential` |
| `proxy/history.py` `HistoryWriter._prepare` | `redact_url` | `flow.url` | fixed by the owner; same test |
| `proxy/redact.py` `redact` (request target; `Location`, `Content-Location`, `Refresh`) | `redact_url` | stored raw messages, `flow_fts` | **fixed in round 1** (RU-7: the `?` gate removed); `test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query` |
| `disco/capture.py` `make_record`; `disco/runner.py`; `disco/explore.py` (actions.jsonl); `disco/ede.py` (page, route key) | `redact_url` | the disco capture files the importer reads; ede's key is in memory | fixed by the owner (names; identifiers are re-judged by the importer); `test_no_generated_spelling_reaches_the_store_through_import_disco` |
| `tools/spider.py` `record_form` (page and action URL); `mark_visited` landing and `found_from` | `redact_url` | spider DB (names only); the importer re-judges | fixed by the owner; the importer's tests |
| `tools/spider.py` `record_request` (both URLs), `record_revealed_form` (page URL), `_queue_xhr` (an XHR page URL) | `redact_url_identifiers` | spider DB `discovered_requests`, revealed forms, XHR pages | fixed by the owner; an identifier in a captured request URL's own query is stored **blank** by `record_request`: residual R2 (narrowed, pinned) |
| `tools/spider.py` `_spa_url` | `redact_spa_fragment` | spider DB page URLs | fixed by the owner |
| `core/trace.py` `safe_ref` (finding and trace evidence, diagrams) | `redact_url_identifiers`, then `redact_for_record` | evidence references | fixed by the owner; `test_a_diagram_reference_holds_no_nested_secret` |
| `core/redaction.py` `redact_for_record` / `_redact_piece` (`project.py`: `_clean_target`, `add_target`, `set_meta`, `insert_launch`) | `redact_url` | `project.targets`, `launch.argv`, `launch.target` | **fixed in round 1** (RU-9); the two record tests |
| `core/redaction.py` `page_url_is_clean` (`store_adapter._source_page`; the oracle binder `_FormBoundSender`) | `redact_url_identifiers`, `holds_placeholder` | `form.source_page`; the page the binder fetches | fixed by the owner (RU-1, RU-2); the sweep's clean-page check |
| `core/redaction.py` `value_holds_secret` / `stored_value` / `strip_secret_path_params` | the walk | (the rules below) | owner |
| `core/urls.py` `store_url` (`strip_secret_path_params`) | owner | `page.url`, `endpoint.url` | fixed (BUG-0556) |
| `store_adapter._import_page_url` | `store_url` | `page.url`, `endpoint.url` | fixed; import_spider and import_disco sweeps |
| `store_adapter._import_link_set` | `redact_sibling` = `stored_value` | `form.entries`, `parameter.example` | fixed (BUG-0556) |
| `store_adapter._source_page` | `page_url_is_clean`, `store_url(keep_query)` | `form.source_page` | fixed by the owner |
| `store_adapter._import_path_templates` | `strip_secret_path_params`, `stored_value` | `endpoint.url`, path `parameter.example` | fixed (BUG-0556) |
| `store_adapter._import_forms` | `stored_value`, `store_url`, `redact_url_identifiers(placeholder=True)` | `form.entries`, `fresh`, examples, a POST action's query on `endpoint.url` | **fixed in round 1** (RU-4: a redacted query value is a placeholder and its points are refused); `test_an_endpoint_query_redaction_changed_is_never_sent` |
| `store_adapter._import_route_query` | `store_url(route=True)`, `redact_sibling` | `endpoint.url`, fragment examples | fixed (BUG-0556) |
| `store_adapter._store_request` | `store_url`, `redact_url_identifiers(placeholder=True)`; `redact_leaf` for the body | a captured request's endpoint query; its body leaves | **fixed in round 1** (RU-4) for the query; the body leaf is residual R1 (pinned) |
| `store_adapter.import_audit` / `_audit_text` | `store_url`, `redact_url_identifiers`, `strip_secret_path_params`, `stored_value` | `endpoint.url`, `candidate.evidence.target_identifier`, `candidate.sink_context` | **fixed in round 1** (RU-3/RU-8); `test_import_audit_stores_the_spiders_endpoint_and_no_secret`. The rest of a quoted HTML snippet is body redaction (audit defect 26, out of scope) |
| `harness/auto.py` `injection_points_from_store` | `holds_placeholder` | what a crawl point sends | **fixed in round 1** (RU-4: refused, `UNBOUND`, never sent) |
| `audit/engine.py` `evaluate` (`candidate` rows) | none | the point's stored URL and entries (`point_evidence`) | clean by its source (stored endpoint and entries, above); a placeholder is by name |
| `oracle/oracle.py` `_write_finding` (`finding.url`) | none (`to_path` of a stored endpoint) | `finding.url` | clean by its source |
| `tools/fetcher.py` `log_finding` (audit DB) | none | the auditor's own DB (`findings`), raw | not the project store; re-judged by `import_audit` (above). The auditor's DB is the auditor's working file, as the spider DB is the spider's |

### PA-0556, strengthened (review round 1)

Items 1-3 stand. These are added, and the coordinator's text in the lane's doc texts is
amended to match:

4. **A sweep of an owner's callers is measured, not read.** Each caller's disposition
   cites a test that drives a secret through that caller and searches what it stored or
   sent. Some callers decide *whether* the owner runs: a gate on `"?" in target`, a
   branch that handles part of the value itself, a writer of the same kind of value that
   calls no owner. Such a caller is part of the owner's coverage. The sweep therefore
   lists every writer of that kind of value, not only every call of the owner (RU-3,
   RU-7, RU-9).
5. **A generated redaction sweep includes what real encoders produce, measured:**
   Python's `quote()` with its default `safe="/"`, `quote(safe="/:")`, and a framework's
   redirect helper. Its positions include every place the owner's other boundaries
   already treat as a credential, such as a URL's userinfo (RU-1, RU-2).
6. **A redaction that changes what a request sends is a replay change.** The sweep
   records, for each writer, whether its stored value is sent as the request's own. Where
   it is, a value that redaction replaces is recorded as a placeholder, by name, and its
   test is refused (`UNBOUND`): it is never sent blank (PA-0544(1)/(3)). Before a round
   is reported, each test's pre-fix proof is on its own assertion (PA-0545(6)), and a
   complexity oracle is proven on a deliberately quadratic variant (PA-0135(3)) (RU-4,
   RU-5, RU-10).

- Enforced by (added): `tests/test_redaction_nested.py::test_a_layer_left_encoded_behind_a_raw_slash_is_decoded_wherever_it_is_read`,
  `tests/test_redaction_nested.py::test_a_nested_urls_userinfo_is_a_credential_in_both_redactors`,
  `tests/test_redaction_nested.py::test_import_audit_stores_the_spiders_endpoint_and_no_secret`,
  `tests/test_redaction_nested.py::test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query`,
  `tests/test_redaction_nested.py::test_a_project_record_redacts_a_credential_nested_in_a_route_fragment`,
  `tests/test_redaction_nested.py::test_an_endpoint_query_redaction_changed_is_never_sent`,
  `tests/test_redaction_nested.py::test_the_linearity_oracle_flags_a_quadratic_walk`

## Review round 1: residuals (updated)

- **R1 (pinned, unchanged):** a captured request body's leaf holding a nested token
  keeps the flat leaf rule. Body redaction is paused by the owner (audit defect 26).
- **R2 (narrowed and re-pinned; owner CRAWL).** The round-1 label "pre-existing" was
  wrong for a form's action query and a disco capture's URL query: there BUG-0556's
  change introduced the blank, and it is now fixed (RU-4). What remains is the spider's
  own capture writer (`record_request`). It stores an identifier-like
  query value of a captured request URL as a blank, which the importer cannot tell from
  an empty value, so that request's points send `id=`. This predates BUG-0556 (since
  FR-CRAWL-13). The fix belongs to the writer, which should record a placeholder
  (PA-0544(1)). `tools/spider.py` is held by lane BROWSERALIAS this round. Pinned by
  `tests/test_redaction_nested.py::test_a_spider_captured_request_query_redaction_is_never_sent`
  (strict xfail).
- **R3 (out of the class, by design, extended):**
  - Unchanged from the first round: an identifier-shaped top-level path segment, and a
    token glued on with no separator (SP-18's limit).
  - The URL's own top-level path segments and its own non-query fragment route are not
    decoded and walked. They are the page's identity, not values.
  - A pair's *name* is judged by the name rule only, never decoded and walked as a value.
  - A top-level URL's userinfo is kept by `redact_url`. The project store keeps none of
    it (`to_path` and `canonical_origin` drop it), and a browser never sends userinfo in
    a request line.

## Review round 2 (f939778, final): the fix check's neighbouring paths

The owner approved one final round (2026-10-22): each round-1 finding's fix check
(`scratchpad/lanes/REDACTURL/review_round2.md`, items N1..N8, each with a repro, a
proposed fix and a skeptic's confirmation) found the round-1 repro fixed and the same
mechanism still open on neighbouring paths. Each neighbouring path is fixed by class on
branch `lane/REDACTURL-r2` from f939778; anything a later check finds is pinned by a
strict xfail, never a further fix. The owner's and the importer's parts are in the
review-round-2 sub-bullets of CC-CORE-0076 and CC-AUD-0059; the callers' are CC-FUZZ-0116
(greybox) and CC-PROXY-0031 (proxy), which also carry the round-1 FUZZ and PROXY texts.

1. **N1 (RU-1/RU-6's neighbours): a layer left encoded in any piece; a pair list holding
   a URL.**
   - **What failed.** `next=https://host%2Fcb%3Faccess_token%3D<word>?y=1`: the raw `?`
     sent the value to `nested_url`, whose head's authority holds the encoded layer, and
     `path(nested=True)` returned the head when no raw `/` followed the authority, so
     both redactors, `page_url_is_clean`, `safe_ref`, the proxy and `form.source_page`
     kept the token. Werkzeug's `url_for` applied twice (measured by the check on
     werkzeug 3.1.9: `/login?next=/login?next%3Dhttps://bob:<pw>@host/x`) decoded to
     `next=https://bob:<pw>@host/x`, which `"://" in text` sent to `nested_url` as one
     URL, so no pair was split and no userinfo found; `?state=next=https://bob:<pw>@…`
     raw, and `a=1&token=<word>&next=https://h/x` encoded, the same. The top-level
     fragment's route was never walked: `#/r%3Ftoken%3D<word>` (Python's `quote()` of a
     route), `#!/…`, `#%2Fr%3F…`, `#token%3D…` and `#/r;jsessionid=<word>?x=1` were kept
     (N7's second neighbour; the same class).
   - **Fix.** `_UrlWalk.path` decodes a nested authority holding an escape (a host's own
     escapes decode to host characters and come back unchanged); `_UrlWalk.route` walks a
     fragment's route for its `;` path parameters and its encoded segments, the top
     level's included (its raw segments stay the page's identity, R3); `_url_shaped`
     takes a value for a URL only when it starts with a scheme's `://`, `/` or `\`, or
     its first raw `?`/`#` comes before any `=`, `&` or `;`, else it is split into pairs.
   - **Tests.** `test_a_review_round_2_spelling_is_redacted_by_every_url_redactor`
     (`_ROUND2`, 19 spellings: both redactors, `page_url_is_clean`, `safe_ref`,
     `redact_for_record`) and
     `test_the_review_round_2_spellings_store_no_secret_through_import_spider`.
2. **N2 (RU-2's neighbours): a URL's userinfo wherever a URL starts.**
   - **What failed.** `_UrlWalk.userinfo` judged an authority only at the very start of a
     nested head, so `next=/go/https%3A%2F%2Fbob%3A<pw>%40host%2Fx` (decoded whole, then
     a path whose segments held no escape), raw `/go/https://bob:<pw>@host/x`,
     `https://proxy.example/go/https://bob:<pw>@…`, a leading space (`+https://…`,
     `%20https://…`), a nested fragment route (`/a%23https://bob:<pw>@…?y=1`),
     `https:///bob:<pw>@…` and the backslash spellings were stored by `import_spider`,
     called clean, and kept by proxy history, though `redact_for_record`'s
     `_URL_USERINFO` and `safe_ref` treated them as credentials.
   - **Fix, measured.** The WHATWG URL parser (Node 22's `URL`,
     `scratchpad/lanes/REDACTURL/r2/whatwg.js`) gives userinfo for `https:///bob:pw@`,
     `https:\\bob:pw@`, `/\bob:pw@` and `\\bob:pw@` against a base, a leading space or tab,
     and `http:/bob:pw@` and `http:bob:pw@` parsed absolute; not for `/go/https://…` (a
     path), which `_URL_USERINFO` and `safe_ref` still call a credential, so the walk
     agrees with them there. `_AUTHORITY_AT` finds every authority start in a value (a
     special scheme and any run of `/` or `\`, or two or more of them anywhere) and
     `_UrlWalk.userinfo` replaces each `user[:password]@` (last `@` or `%40`) by
     `PLACEHOLDER@`; it runs in `value`, at every nested level and layer.
   - **Tests.** The N2 spellings in `_ROUND2` and the proxy test's target and `Location`.
3. **N3 (RU-3/RU-8's neighbours): `import_audit`'s quoted substrings and its main
   origin.**
   - **What failed.** `_audit_text` replaced a secret value's prefixes at the rules' cut
     lengths (80/60/40/20); `rule_serialized_tokens` quotes `match.group(0)[:60]`, a
     substring (a JWT behind `Bearer `, `x.`, a short JWT before `~tail`, base64 up to a
     form-decoded `+`, a pickle behind `v1:`), stored in `candidate.sink_context` though
     `stored_value` held for each value. The round-1 test's fetcher echoed the query, so
     the body's row won the auditor's dedupe and hid it. And `import_audit` took the
     run's main origin from its first finding's page while `import_spider` took the
     seed's (`fetcher.py` passes neither a `base_url`): with an off-origin first finding,
     the main origin's pages were stored absolute beside the spider's paths -- partly
     round 1's own regression (before it, `to_path` kept the main origin's pages shared).
   - **Fix.** Each value the owner would not store is judged whole and replaced wherever
     the text repeats it whole or any run of 8 or more of its characters
     (`_secret_spans`), never by cut lengths; the endpoint is the form this run's spider
     rows hold the page in (`_audit_endpoint`), else `store_url(page, main)` as before.
     `tools/fetcher.py` (held by lane BROWSERALIAS) is unchanged.
   - **Tests.** `test_import_audit_redacts_a_quoted_substring_of_a_secret_value` (a
     fetcher echoing nothing) and
     `test_import_audit_stores_a_page_as_the_spider_does_when_the_first_finding_is_off_origin`,
     each through the real chain (spider rows, `load_urls`, `audit_page` with every rule,
     `import_spider`, `import_audit`).
4. **N4 (RU-4's neighbours): every caller of the point builder keeps its refusal.**
   - **What failed.** Round 1 made `injection_points_from_store` carry a
     `replay_refusal` but swept only the oracle path. `greybox.run.points_from_store`, its
     other caller (PA-0530(5): grep the producer's name), rebuilt `GreyboxPoint`s without
     it, and `RequestsCorrelatingSender` had no placeholder gate, so greybox sent `POST
     /app/edit.php?id=__REDACTED__` (it sent `id=` before round 1).
   - **Fix.** `points_from_store` reports a refused point in `skipped` and never returns
     it; `send_correlated` raises `ReplayRefused` for a URL holding a placeholder before
     anything is sent (CC-FUZZ-0116).
   - **The spider's own capture blank (R2).** `tools/spider.py` is still held by lane
     BROWSERALIAS; the blank `id=` is sent by both callers. R2's strict xfail now asserts
     both (`harness.auto` and greybox), so it fails until the writer records a
     placeholder.
   - **Test.** `test_greybox_never_sends_a_point_the_builder_refused_or_a_placeholder`.
5. **N5 (RU-5's neighbours): every test's pre-fix path reaches its behaviour.**
   - **What failed.** Round 1 re-proved only the test the review named.
     `test_a_value_past_the_depth_bound_is_redacted_whole` stopped on 7393c90 at
     `R.MAX_VALUE_DEPTH` though the old code kept the hex; the size-bound test stopped on
     `monkeypatch.setattr(R, "MAX_VALUE_CHARS", 64)`; the benign, layer, userinfo and
     totality tests called the new API directly.
   - **Fix.** `_api(name)` looks a new function up and asserts it present, called only
     after a test's behaviour assertions; the depth bound falls back to 12 and the leak
     is asserted first (in up to depth + 3 decodings); the size bound is set with
     `raising=False`.
   - **Proof, every test of the file.** A plain-Python runner (no pytest session:
     parametrize expanded, `tmp_path` and `monkeypatch` supplied;
     `scratchpad/lanes/REDACTURL/r2/run_plain.py`) ran all 35 test functions then in the
     file (R4's strict xfail was added after) on a `git archive` of 7393c90's `fuzzlab/`
     (`r2_n5_7393c90.log`): 425 cases failed, 57 passed (the 57: the two axis checks, an
     ordinary-link store test and the 54 depth-1 record cases, caught by `_MATRIX_PARAM`
     or `redact_query`). Every failure is an `AssertionError` on the test's own claim, except
     `test_the_redactors_are_total[http://[::1/x?token=a;b=%2F%3F]`, where the old
     redactor raised `ValueError: Invalid IPv6 URL` -- the totality failure that test
     names. The benign test's 18 cases and the other 16 totality cases fail on `_api`'s
     assertion after their behaviour held (the old code was byte-identical and total
     there). The depth test fails on its leak assertion (`redact_url_identifiers` keeps
     the hex), the size test on the over-long value kept. The proof sentence under
     "Corrective action" is corrected there.
6. **N6 (RU-7's neighbours): every URL-bearing header value and any request line.**
   - **What failed** (all older than BUG-0556): `redact()` read each URL header's first
     value only and `with_header` replaced every duplicate by a changed one; `Referer`,
     `Origin`, `Link` and custom URL headers were never read; `Refresh` only as `url=`;
     the target as `split(b" ")[1]` (empty for a doubled space or a tab).
   - **Fix.** Every header line is read and a changed value rewritten in place; the
     URL-bearing set, `Link`'s `<URI>`s, `Refresh` per the HTML declarative-refresh steps
     and a whitespace-tolerant target (CC-PROXY-0031). A URL inside another structured
     header's grammar is residual R4 (pinned).
   - **Test.** `test_proxy_history_redacts_every_url_bearing_header_and_any_request_line`.
7. **N7 (RU-9's neighbours): a URL holding a raw space in a project record.**
   - **What failed.** `redact_for_record` split the value on whitespace before the walk,
     so `#/r?next=/v?q=a b&token=<word>` kept its token (`b&token=…` walked alone), in
     `launch.argv` too.
   - **Fix.** `redact_url` runs on the whole value first, then each piece as before.
   - **Test.** `test_a_project_record_walks_a_url_holding_a_raw_space_whole` (the
     function, `insert_launch` and `add_target`).
8. **N8 (RU-10's neighbours): the linearity oracle counts the C-level work.**
   - **What failed.** The oracle counted the walk's own steps and the identifier
     predicate's reads; a pair step that unquotes, splits or quotes the whole list once
     per pair (with the real single `tick`) passed it at n=100 and n=500 (about 24 times
     the CPU time for 5 times the input), and round 1's variant A was flagged only
     because it ticked its own extra work. Its URL had no path parameter, nested path
     or fragment, and it ran with identifiers only.
   - **Fix.** `_counted_walk` wraps `unquote`, `unquote_plus`, `quote`,
     `looks_like_identifier`, `is_sensitive_name` and every compiled pattern of the
     module (`_PAIR_SEP`'s split, the escape, raw-structure and authority searches) and
     counts the characters each call is given; `_oracle_urls` has one URL per part of the
     walk (path parameters, query pairs, a nested path, a fragment route); both modes;
     per-character bounds measured with about 50% headroom (worst part: 10.3 steps, 0.79
     step calls, 15.4 C-level characters, 1.9 C-level calls per URL character, at 100,
     500 and 4000 items).
   - **Proof.** `test_the_linearity_oracle_flags_a_quadratic_walk` flags seven
     variants, none ticking its own work: the check's three (whole-list unquote, split,
     quote per pair: 615 C-level characters per character), the every-layer re-walk
     (52), a per-pair whole-query judgement (1815), a path step decoding its whole head
     per segment (105) and a fragment step re-encoding the whole fragment per pair (113).
     On f939778's product code f939778's own oracle returns `[]` for the check's three
     variants and the new oracle flags each in six places
     (`scratchpad/lanes/REDACTURL/r2/n8_proof.py`, `r2_n8_proof.log`).

**Pre-fix proof (PA-0545(6)).** One pytest invocation ran the whole of
`tests/test_redaction_nested.py` with f939778's four product files swapped in
(`fuzzlab/core/redaction.py`, `fuzzlab/tools/store_adapter.py`,
`fuzzlab/proxy/redact.py`, `fuzzlab/greybox/run.py`), then restored them
(`scratchpad/lanes/REDACTURL/r2_prefix_proof.sh`, `r2_prefix.log`): 28 failed, 452
passed, 3 xfailed. The 28 failures are exactly the round-2 tests (19 `_ROUND2` cases,
the `import_spider` store test, the proxy test, 4 record cases, the two `import_audit`
tests and the greybox test), each an `AssertionError` on its own assertion (the secret
found, the placeholder sent, the endpoint added); none is an import, attribute or type
error. The rounds-0/1 tests pass there, as does the N5- and N8-edited tests' behaviour
on f939778's product (their proofs are on 7393c90 and against f939778's oracle, above).
The 3 xfails are R1, R2 (both callers) and R4.

**The round's targeted run** (one pytest invocation of the 66 test files that import a
changed module, or `core.project`, `core.trace`, `proxy.history` or `greybox`, plus the
lint, wall-clock, traceability, PA and SP guards; `scratchpad/lanes/REDACTURL/r2_targeted.sh`,
`r2_targeted.log`): 3537 passed, 51 xfailed, 2 failed. Both were root-caused:
- `tests/test_base_url_subpath_registry.py::test_every_base_url_function_is_registered`:
  `import_audit`'s `base_url` keyword, added by round 1 (CC-AUD-0059), had no PA-0300
  registry entry, and round 2's `_audit_endpoint` took the same parameter; round 1's
  targeted run did not include the whole-package guard. Fixed: `_audit_endpoint` takes
  `spider_form` (a flag, not a base), and `import_audit` is registered with
  `test_import_audit_under_a_subpath_base_stores_the_spiders_paths` (the app under
  `http://h/app/`: pages stored by their whole path as `import_spider` stores them, no
  endpoint added). Verified after the run without a pytest session (the guard's
  functions called directly: no unregistered, stale or bad pointer; the new test and
  the three other `import_audit` tests pass).
- `tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age`: a race in the
  test, outside this lane. The writer thread commits a batch (`HistoryWriter._write`),
  runs `_trace`, and only then adds to `stats["written"]` (`proxy/history.py`); the test
  polls for the committed rows and reads the counter at once. A 0.3 s delay inserted in
  `_trace` makes it fail 5 times in 5, none without it
  (`scratchpad/lanes/REDACTURL/r2/age_race.py`, `r2_age_race.log`); no redaction code
  runs in that window (`redact` runs before the batch is written). Flagged to the
  coordinator with its fix (poll the counter: `_until(lambda: h.stats["written"] ==
  2)`); not changed here (owner PROXY's history lane, no bug number assigned to this
  lane for it).

R5's strict xfail was added after the targeted run and confirmed failing on the
revision by the plain runner.

**Why round 1 missed them.** Each round-1 fix was made at the path its repro took and
proven on that repro: the authority beside the path segment, the userinfo after a path
segment or a space beside the one at a value's start, the substring beside the prefixes
the rules' code showed, the greybox caller beside the oracle's, the other tests beside
the named one, the duplicate and the other URL headers beside the three named, the
whitespace split beside the walk it fed, and the oracle's own self-reporting variant.
None enumerated the mechanism's other paths before reporting. Two of the rules that
would have caught them already existed: PA-0530(5) (sweep every caller of a producer by
grep) and PA-0545(6) (the pre-fix proof of every test in the file).

**Recurrence review (round 2).** The same lane's third pass at the same class.
Prior-preventive-action failure analysis:
- **PA-0556(4) (a sweep measured per caller): too narrow.** It measured each caller of
  the owner, not each caller of a producer whose output round 1 changed (the point
  builder's `replay_refusal`), and not each *path inside* a caller (a header loop, a
  whitespace split).
- **PA-0530(5) and PA-0545(6): not followed.** Both name the exact step that was skipped.
- **PA-0135(3): followed in name only.** The offender reported its own work, so the
  oracle's blindness to C-level work was never tested.

PA-0556 gains item 7 (in the lane's doc texts): a fix is made to the mechanism, not
the spelling -- before a round is reported its neighbouring paths are enumerated by
mechanism (every piece the walk reads, every place a URL can start, every caller of a
producer whose output changed, every value of a repeated field, every split before the
owner sees a value) and each gets a test that fails on the pre-fix code.

### The PA-0002 sweep after review round 2 (rows that changed; the round-1 table stands otherwise)

| Caller (file:function) | Calls | What it stores or sends | Disposition |
|---|---|---|---|
| `proxy/redact.py` `redact` | `redact_url` | stored raw messages, `flow_fts` | **fixed in round 2** (N6): every value of every URL-bearing header, `Link`, `Refresh`, any request line; a URL inside another structured header is R4 (pinned); `test_proxy_history_redacts_every_url_bearing_header_and_any_request_line` |
| `core/redaction.py` `redact_for_record` | `redact_url` (whole value, then pieces) | `project.targets`, `launch.argv`, `launch.target` | **fixed in round 2** (N7); `test_a_project_record_walks_a_url_holding_a_raw_space_whole` |
| `store_adapter.import_audit` / `_audit_text` / `_audit_endpoint` | `store_url`, `redact_url_identifiers`, `strip_secret_path_params`, `stored_value` | `endpoint.url`, `candidate.evidence.target_identifier`, `candidate.sink_context` | **fixed in round 2** (N3); the two round-2 importer tests |
| `harness/auto.py` `run_auto` (a caller of `injection_points_from_store`) | the oracle (`replay_refusal` -> `UNBOUND`), `_fingerprint_point` (skips a refused point) | what an auto run sends | clean since round 1; `test_an_endpoint_query_redaction_changed_is_never_sent` |
| `greybox/run.py` `points_from_store` (the other caller) and `RequestsCorrelatingSender.send_correlated` | `replay_refusal`; `holds_placeholder` | what a greybox run sends | **fixed in round 2** (N4); `test_greybox_never_sends_a_point_the_builder_refused_or_a_placeholder`; the spider capture's blank (R2) pinned for both callers |
| every URL redactor's walk (`_UrlWalk`) | itself | every caller above | **fixed in round 2** (N1, N2); `_ROUND2` through every redactor and `import_spider` |

## Review round 2: residuals (final)

- **R1 (pinned, unchanged).**
- **R2 (pinned, both callers).** The spider capture writer's blank (`record_request`) is
  sent `id=` by `harness.auto` and greybox alike; the strict xfail asserts both. The fix
  is the writer recording a placeholder in `tools/spider.py` (lane BROWSERALIAS).
- **R3 (by design, narrowed).** Unchanged: an identifier-shaped top-level path segment;
  a token glued on with no separator (SP-18); a pair's name judged by the name rule
  only; a top-level URL's own userinfo kept by `redact_url`; the URL's own top-level
  path segments, raw or encoded (`/app/redirect/https%3A%2F%2Fbob%3Apw%40host%2Fx` is
  stored in `page` and `endpoint`), and a top-level path parameter's value cut by a raw
  `/` (`p.php;next=/cb%3Faccess_token%3D…`). Narrowed: the top-level fragment's route
  is now walked for its path parameters and its encoded segments (N1); its raw segments
  remain the page's identity.
- **R4 (new, pinned; owner PROXY).** A URL inside another structured header's grammar (a
  CSP `report-uri`, `Reporting-Endpoints`, `Report-To`'s JSON) is not parsed, so a
  sensitively named value there is kept in proxy history. Pinned by
  `tests/test_redaction_nested.py::test_proxy_history_redacts_a_url_inside_a_structured_header`
  (strict xfail).
- **R5 (new, pinned; owners CORE and AUD).** The check's N3 note: a finding page's own
  userinfo is kept by both URL redactors (R3), so `import_audit`'s `called from <url>`
  text keeps it in `candidate.sink_context`. R3's reason -- the store keeps no top-level
  userinfo -- holds for `page` and `endpoint` (`to_path`, `canonical_origin`) but not for
  this writer. It is outside N3's class (a query value judged by `stored_value`) and was
  found after the round's proof, so it is pinned, not fixed:
  `tests/test_redaction_nested.py::test_import_audit_stores_no_userinfo_of_the_finding_page`
  (strict xfail; confirmed failing on the revision by the plain runner, added after the
  targeted run).
