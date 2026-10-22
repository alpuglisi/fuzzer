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

## Residuals after the owner's final round (111b6fb; branch `lane/REDACTURL-r3`)

The fix check of review round 2 (`scratchpad/lanes/REDACTURL/final_check_findings.md`)
found each N1..N8 repro fixed on 111b6fb and neighbouring paths still open. The owner's
rule for the final round: anything found after it is pinned by a strict xfail, never
fixed in another round -- **except a regression the batch itself introduced, which is
fixed in the batch** (PA-0549(3c)). The check named one such regression; a differential
sweep of the fix against f939778 and 111b6fb found three more beside it, each fixed here
under the same rule. Everything else is pinned in a new file,
`tests/test_redaction_residual_pins.py` (strict, `raises=AssertionError`, each reason
naming BUG-0556 and its owner). The owner's changes are CC-CORE-0076's "after the final
round" sub-bullet; FR-CORE-537 is amended in place and names the pins.

### The in-batch regressions, fixed

1. **A userinfo holding whitespace (the check's N2 item 1 = N7 neighbour 2).**
   - **What failed.** Round 2's `_AUTHORITY_AT` took the authority as `([^/\\?#\s]*)`,
     stopping at whitespace, where round 1's `userinfo` ran to the next `/`. A passphrase
     was kept that f939778 redacted: `next=https%3A%2F%2Fbob%3Acorrect%20<pw>%40host%2Fx`
     (encodeURIComponent of `https://bob:correct <pw>@host/x`) by both redactors,
     `page_url_is_clean`, `safe_ref`, `redact_for_record` and the proxy's request line,
     `Referer` and `Location`; the raw `next=https://bob:correct%20<pw>@host/x`, a `%09`,
     an NBSP and the `/go/…` nested-path forms by `value_holds_secret`, so `import_spider`
     stored the password in `parameter.example`, `form.entries` and (encoded)
     `form.source_page`; `?next=https://bob:pw <word>@host/x` and the same in
     `#/r?next=` by every consumer.
   - **Measured.** Node 22's `URL` (`scratchpad/lanes/REDACTURL/r3/whatwg_ws.js`):
     `https://bob:correct horse@host/x` has password `correct%20horse`; a VT, FF, NBSP or
     U+3000 is kept and encoded, a tab or newline removed; `http://bob:Canary Word@h/` (a
     top-level URL) has password `Canary%20Word`.
   - **Fix.** `_AUTHORITY_AT`'s authority runs to `/`, `\`, `?` or `#` only.
2. **A userinfo that is also a pair list (found by the r3 sweep).**
   - **What failed.** Round 2 runs `userinfo` on a value before the walk splits it or
     decodes its layer, so in `next=a%3D%2F%2Fx%26password%3DHunter%40<word>` (and with
     `;`, `quote(safe="/")`, a route fragment, double encoding) the span `x&password=
     Hunter` became `PLACEHOLDER@` and the pair's name went with it:
     `a=//__REDACTED__@<word>` kept the password's tail in both redactors, `safe_ref`,
     `redact_for_record` and the proxy. f939778 split the pairs first and redacted it.
     Item 1's wider authority would have widened this to `a=//x b&password=…`, clean on
     111b6fb.
   - **Fix.** `_UrlWalk.userinfo` raises `_Whole` when a userinfo holds a pair separator
     raw or percent-encoded at any depth (`_USERINFO_PAIR`: `&`, `;`, `%26`, `%3B`,
     `%2526`, ...): the value is redacted whole, under both readings (fail closed).
3. **A nested authority holding raw pair structure (found by the r3 sweep; N1 (B)).**
   - **What failed.** Round 2's `_url_shaped` (N1) sends `a=https://x%26password%3D
     <word>` to the pair walk, whose value `https://x%26password%3D<word>` is decoded
     whole to `https://x&password=<word>`; `_UrlWalk.path` walked a nested authority only
     when it held an escape, so the decoded one was never read (f939778 had walked
     `a=https://…` as one URL and decoded its segment). The check's N1 (B) -- a `;` pair
     in a nested authority never walked once decoded (`next=https%3A%2F%2Fhost%3B
     jsessionid%3D<hex>`, Tomcat's encodeURL of a bare origin, encoded) -- is the same
     mechanism (it leaked on f939778 too), so it is fixed with it, not pinned.
   - **Fix.** `_UrlWalk.path` walks a nested authority holding a raw `=`, `&` or `;` as a
     value (`_AUTHORITY_PAIRS`); one holding an escape is decoded as before.
4. **A value led by one backslash (found by the r3 sweep).**
   - **What failed.** Round 2's `_url_shaped` took any leading `\` for a URL, so the
     layer `\host&token=<word>` of `next=/\host%26token%3D<word>?y=1` was walked as a
     URL whose path is never split: every URL consumer kept the token f939778 redacted.
   - **Fix.** Only an authority's `\\` or `\/` makes a value a URL; a single `\` leaves
     it a pair list.

Not a regression, changed with item 1 as the task asked (the same measurement holds for a
top-level URL): `redact_for_record`'s `_URL_USERINFO` stops at whitespace, so `http://bob:
pw <pw>@127.0.0.1:3000/app/` kept its password in `launch.argv`, `launch.target` and
`project.targets` (on f939778 too). A second pattern, `_URL_USERINFO_SPACED`, strips a
userinfo whose span crosses whitespace and holds no pair separator (raw or encoded once);
every span `_URL_USERINFO` matches is matched as before, and a space never lets a span
reach a later pair (`?next=//x q&password=…@…` stays a pair; widening `_URL_USERINFO`
itself would have deleted that name, clean on 111b6fb).

**Tests** (`tests/test_redaction_nested.py`, "after the owner's final round"):
`test_an_in_batch_regression_spelling_is_redacted_by_every_url_consumer` (21 spellings:
both redactors, `safe_ref`, `redact_for_record`, the proxy's request line, `Referer` and
`Location`, `page_url_is_clean`, `value_holds_secret`, collected before one assertion),
`test_an_in_batch_regression_spelling_stores_no_secret_through_import_spider` (16: the
spellings `import_spider` stored on 111b6fb; item 2's it stored clean there),
`test_a_raw_single_backslash_pair_list_is_redacted_by_every_url_redactor`,
`test_a_project_record_strips_a_top_level_userinfo_holding_a_space` (3, through
`insert_launch` and `add_target`) and the guard
`test_a_records_spaced_userinfo_never_reaches_a_later_pair`; three benign spellings
(a nested authority's clean `;v=2`, a backslash-led clean pair list, a `%20` in a nested
path) stay byte-identical.

**Proof.** A plain runner (no pytest session: parametrize expanded, `tmp_path` and the real
`MonkeyPatch` supplied, xfail honoured; `scratchpad/lanes/REDACTURL/r3/run_plain.py`) ran
the new tests against a `git archive` of 111b6fb's `fuzzlab/`: all 41 fail there, each an
`AssertionError` on its own assertion (the guard passes, as a guard must), and pass on the
revision. The differential sweeps (`r3/sweep.py`, 12 600 URLs; `r3/sweep2.py`, 90 720:
every authority shape the walk reads, six encodings, six positions, through both
redactors, `safe_ref`, `redact_for_record`, `page_url_is_clean` and `value_holds_secret`)
count, per URL, the consumers that keep the secret: 111b6fb regressed 6 313 of the 90 720
against f939778; the revision regresses none against either, and improves 39 051 against
f939778 and 22 169 against 111b6fb. A benign differential (`r3/benign.py`, 20 160 URLs
holding no secret) is identical between 111b6fb and the revision. The linearity oracle
passes the revision at 500 and 4000 items (the new branches are one linear pass each).

### N5: the tests' own pre-fix paths, fixed (no pin)

The check found the round's file failing on old code for the wrong reason again:
`_audit_store` passed `base_url=None` to `import_audit`, which has had the keyword only
since round 1, so three tests stopped on 7393c90 and c3a13f7 with a `TypeError` before any
assertion; and R5's strict xfail "held" there on an `ImportError` of `_audit_text`. Now the
fixture passes `base_url` only when given and to `import_audit` only where its signature
takes it; R5 looks `_audit_text` up with a fallback (the pre-round-1 writer stored the
text as it was); R1, R2, R4 and R5 are `raises=AssertionError`. Swept with the plain runner
over the whole file on four trees (`r3/plain_<rev>.log`): 7393c90 469 failed, c3a13f7 401,
f939778 60, 111b6fb 41, each an `AssertionError` on the test's own assertion except, on
7393c90, `test_the_redactors_are_total[http://[::1/x?token=a;b=%2F%3F]` (the old redactor
raised `ValueError: Invalid IPv6 URL`, the totality failure the test names); every xfail
fails on its `AssertionError` on every tree. The revision: 526 passed, 4 strict xfails.

### Pinned (`tests/test_redaction_residual_pins.py`; each proven failing on its stated assertion on the revision by the plain runner, `r3/pins_plain.log`)

- **N1 (A)** (owner CORE): `::test_an_encoded_authoritys_userinfo_is_redacted` (4 cases:
  `next=https://bob%253A<pw>%2540host%252Fx?y=1`, `#https://bob%3A<pw>%40host%2Fx?y=1`,
  `#//bob%3A…`, `#https://bob%3A<pw>%40host`): both redactors return the URL unchanged.
- **N2 item 2** (owner CORE):
  `::test_a_userinfo_the_whatwg_parser_reads_after_a_space_or_a_stripped_tab_is_redacted`
  (6: `+https:bob:<pw>@`, `+http:/bob:<pw>@`, `+https%3Abob%3A<pw>%40host%2Fx`,
  `https:/%0A/`, `https:/%09/`, `https:%2F/…?y=1`): both redactors keep the password.
- **N2 item 3, R3** (owners CORE and AUD):
  `::test_a_userinfo_in_the_top_level_fragment_route_is_redacted` (2: `#/go/https://bob:
  <pw>@host/x`, `#https://bob:<pw>@host/x`; both redactors keep it),
  `::test_a_userinfo_in_a_top_level_pair_name_is_never_stored` (2: `out.php?https://bob:
  <pw>@host/x?a=1` and the nameless form; `parameter.name` holds it) and
  `::test_a_userinfo_in_a_top_level_path_segment_is_never_stored`
  (`/app/redirect/https%3A%2F%2Fbob%3A<pw>%40host%2Fx`; `page` and `endpoint` hold it).
- **r3's sweep, item 4's raw spelling decoded once** (owner CORE):
  `::test_a_backslash_led_pair_list_decoded_once_is_held_secret` (`value_holds_secret(
  "/\host&token=<word>?y=1")` is False: `_authority_start` reads `/\` as a path, the
  WHATWG parser as an authority; `import_spider` stores the token; on f939778 too).
- **N3 neighbour 2, `fuzzlab audit --append --store`** (owner AUD):
  `::test_import_audit_after_an_appended_audit_stores_each_page_as_the_spider_does`: the
  audit adds `['/v1/q.php', 'http://h:80/app/old.php']` (the API page on the wrong host,
  a main-origin page absolute) where `['/app/old.php', 'http://api.h:8081/v1/q.php']` is
  the spider's form.
- **N6** (owner PROXY):
  `::test_proxy_history_redacts_a_url_in_a_malformed_or_folded_message` (9: an empty line
  or a leading space before the request line, `;jsessionid` and `?token`; folded
  `Referer` and `Location`; `Link`'s `anchor`; `X-Redirect` holding `?token=`,
  `app/;jsessionid=` and a quoted URL): `redact` returns the secret.
- **N7 neighbour 1 and `_URL_USERINFO` across a separator** (owner CORE):
  `::test_a_record_never_deletes_a_pair_name_with_a_userinfo_pattern` (5: `q=is:open
  label:bug&password=Hunter@<word>` -> `?q=is:open ***@<word>`; the route form;
  `q=a b:c&token=@<word>`; `?next=//x&password=Hunter@<word>` -> `?next=//__REDACTED__@
  <word>`; the same across `%26`, found by r3's sweep) and
  `::test_a_record_strips_a_top_level_userinfo_holding_a_space_and_a_pair_separator`
  (`http://bob:pw x&<word>@…`, kept: the spaced pattern stops at `&` by design).
- **N8** (owner CORE, the oracle):
  `::test_the_linearity_oracle_flags_c_level_work_outside_the_counted_names` (3: a
  per-pair `re.split` with an uncompiled pattern, `urllib.parse.unquote` called directly,
  `str.split`), `::test_the_linearity_oracle_runs_the_userinfo_loop` (a per-authority
  rescan never runs: no oracle URL holds `@`) and
  `::test_the_linearity_oracle_runs_the_redaction_path` (a per-redacted-pair re-split never
  runs: every oracle URL is clean); `_linearity_violations(100)` returns `[]` for each.

**The round's run** (one pytest invocation, `FUZZLAB_PYTEST_LOCK_WAIT=7000`, `-n 3 --dist
loadfile`, of `tests/test_redaction_nested.py`, `tests/test_redaction_residual_pins.py`,
`tests/test_proxy_redaction.py`, `tests/test_store_adapter.py` and every test file
importing `fuzzlab.core.redaction`; `scratchpad/lanes/REDACTURL/r3_run.sh`,
`r3_run.log`), 17 files: `1502 passed, 42 xfailed, 3 warnings in 505.69s` (exit 0; the
42 xfails are the 37 pin cases, R1, R2, R4, R5 and BUG-0554's
`test_capture_surrogates.py` pin; no skip, no failure; the warnings are a starlette
deprecation and a `fork()` notice in other files' tests).

**Why the final round introduced regressions.** Round 2 followed PA-0556(7): it
enumerated each finding's neighbouring paths and gave each a test failing on f939778.
Every such test asserts that something *more* is redacted; none compared what the changed
walk returns with what f939778 returned on the same inputs, so the places round 2
narrowed a reading -- a class that stopped at whitespace, a replacement moved before the
split, a value shape (`a=`, `\`) routed elsewhere -- were seen by no test. The check found
one by reading the regex; a generated differential (clean on the pre-fix code, kept after)
found 6 313 cases in four classes in minutes.

**Recurrence review.** The same lane's fourth pass at the class. Prior-preventive-action
failure analysis: **PA-0556(7) (fix the mechanism; neighbouring paths each with a test
failing on the pre-fix code): too narrow.** It is forward-only: it proves the fix adds
what it claims and never that it removes nothing. PA-0549(3c) was followed (the batch's
regressions are fixed here). PA-0556 gains item 8 (in the lane's doc texts): before a
round is reported, the change is diffed against the pre-fix code by a generated
differential over every consumer of the changed owner -- a case clean before and kept
after is a regression of the batch, fixed in it -- and each regression class found gets a
test that fails on the round's own pre-fix revision.

### The PA-0002 sweep after the final round (rows that changed)

| Caller (file:function) | Calls | What it stores or sends | Disposition |
|---|---|---|---|
| every URL redactor's walk (`_UrlWalk`) | itself | every caller of `redact_url`, `redact_url_identifiers`, `page_url_is_clean`, `value_holds_secret`, `stored_value` | **fixed after the final round** (the four in-batch regressions and N1 (B)); the rest pinned (N1 (A), N2 items 2-3, the backslash value) |
| `core/redaction.py` `redact_for_record` | `_URL_USERINFO`, `_URL_USERINFO_SPACED`, `_BARE_USERINFO`, `redact_url` | `launch.argv`, `launch.target`, `project.targets` | a spaced top-level userinfo **fixed**; the pre-pass deleting a pair name (N7 neighbour 1, across `&` and `%26`) and a spaced userinfo holding `&` **pinned** |
| `store_adapter.import_audit` / `_audit_endpoint` | `store_url` | `endpoint.url` | the `--append` fallback **pinned** (N3) |
| `proxy/redact.py` `redact` | `redact_url` | stored raw messages, `flow_fts` | malformed and folded messages, `Link`'s `anchor`, relative custom URL headers **pinned** (N6) |

### r4: the skeptic's regression after r3, fixed in the batch (branch `lane/REDACTURL-r4` from 20cd466)

A skeptic's check of the batch found one more regression the batch itself introduced
(fixed here under PA-0549(3c)) and one residual (pinned). Proof files are under
`scratchpad/lanes/REDACTURL/r4/`.

- **What failed.** `http://h/app/p.php?u=bob&next=%5C%5Cx%26password%3D<word>` (the value
  decodes once to `\\x&password=<word>`) kept the password in `redact_url`,
  `redact_url_identifiers`, `safe_ref`, `redact_for_record`, the proxy's request line,
  `Referer` and `Location`; `page_url_is_clean` called the page clean and
  `value_holds_secret` was False, so `import_spider` stored it. So did
  `%5C%5Chost%26token%3D<word>`, a `%5C%2F` (`\/`) lead, a triple backslash, the leads
  `\\/` and `\//`, the double-encoded spelling, a raw or encoded `/x` after the value,
  the lead left raw (`next=\\x%26password%3D…`) and the same in a route's query
  (`#/r?next=…`). Measured per consumer (`probe_r4_cases.py`, `probe_r4_cases.log`): on
  20cd466 every one of the eleven spellings is kept by all eight consumers; on f939778
  only the proxy's request line and `Referer` (round 2's N6, not this mechanism) keep
  it; on the revision none. 2955f16 and 111b6fb kept them too (`probe.py`).
- **What the defect was.** r3's class-(4) fix narrowed `_url_shaped` to an authority's
  `\\` or `\/` but kept a value so led URL-shaped, and `_authority_start` read an
  authority only after `scheme://` or a leading `//`. The walk (`_UrlWalk.path`) took
  such a head for a path whose first segment `\\x&password=<word>` holds no `;` and no
  escape, so it was returned unchanged; `_AUTHORITY_PAIRS`, which walks a nested
  authority's raw pairs as a value, sits in the authority branch and was never reached.
  f939778 had no backslash rule: it split the value into pairs and redacted it.
- **Five whys.** The password was kept because the pair list was never split. It was
  never split because the walk read the value as a path segment. It read a path because
  `_authority_start` and `_url_shaped` disagreed about which leads start an authority:
  r3 changed one and not the other. That went unseen because r3's differential
  (`r3/sweep2.py`) had no value led by `\\` or `\/` -- the very leads r3's change kept
  URL-shaped (its prefixes had `https:\\` and `/\` only). **Root cause:** the
  differential PA-0556(8) requires was generated from the author's list of shapes, not
  from the conditions the change itself added, so the branch the change created was the
  one case it never drove.
- **Measured.** Node 22's `URL` (`r4/whatwg_bs.js`, `whatwg_bs.log`): relative to a
  special base, `\\x&…`, `\/x&…`, `\\\x&…`, `\\/x&…`, `\//x&…`, `/\x&…`, `//x&…` and
  `///x&…` all have host `x&password=…`: the authority starts after the whole run of
  `/` and `\`; a single `\x&…` is a path (`/x&…` on the base's host).
- **Fix** (`fuzzlab/core/redaction.py`; CC-CORE-0076's r4 sub-bullet; FR-CORE-537 in
  place). `_authority_start(head, nested)`: in a nested value a head led by `\\` or `\/`
  -- the leads `_url_shaped` takes for an authority -- has its authority after the rest
  of its run of `/` and `\` (`_SLASH_RUN`), so `_UrlWalk.path` reaches the authority
  branch and walks `x&password=<word>` as a value (pairs split, name redacted). A
  top-level URL's head is unchanged (its authority is its identity and never walked: a
  backslash read there would stop its `;` parameters being walked).
- **Tests** (`tests/test_redaction_nested.py`, "r4"): `_BACKSLASH_AUTHORITY_PAIRS` (the
  eleven spellings) through
  `test_a_backslash_led_authoritys_pair_list_is_redacted_by_every_url_consumer` (both
  redactors, `safe_ref`, `redact_for_record`, the proxy's request line, `Referer` and
  `Location`, `page_url_is_clean`, `value_holds_secret`, collected by the shared helper
  `_url_consumers_keeping` before one assertion) and
  `test_a_backslash_led_authoritys_pair_list_stores_no_secret_through_import_spider`;
  the guard `test_a_clean_backslash_led_value_is_left_byte_identical` (4 clean
  spellings, a top-level path parameter's included). The plain runner on a `git archive`
  of 20cd466's `fuzzlab/` (`r4/plain_20cd466.log`): all 22 new cases fail, each an
  `AssertionError` on its own assertion (the helper's `== []`, the store's leak check),
  while the guard's 4 cases and r3's 37 in-batch-regression cases pass there; on the
  revision the whole file passes (`r4/plain_new.log`: 556 ok, its four strict xfails
  among them).
- **The differential, extended** (`r4/sweep3.py`: r3's `sweep2.py` with the leads `\\`,
  `\/`, `\\\`, `\\/`, `\//`, `\/\`, `\\\\` and `///`, which its encodings spell encoded,
  and a seventh encoding keeping the lead raw; 152 880 URLs through both redactors,
  `safe_ref`, `redact_for_record`, `page_url_is_clean` and `value_holds_secret`;
  `r4/sweep_diff.py`): **the revision leaks in 0 cases f939778 redacted and in 0 cases
  20cd466 redacted**; it improves 68 083 against f939778 and 10 008 against 20cd466.
  20cd466 against f939778 on the same sweep: 5 607 regressed cases (this class, unseen by
  `sweep2.py`). A benign differential with the same leads (`r4/benign2.py`, 25 536 URLs
  holding no secret) is identical between 20cd466 and the revision.
- **Residual pinned (not a regression: f939778 kept it too).**
  `tests/test_redaction_residual_pins.py::test_a_slash_led_authoritys_pair_list_encoded_once_is_redacted_by_redact_url`
  (strict, `raises=AssertionError`, owner CORE `_authority_start`): `next=%2F%5Cx%26
  password%3D<word>` decodes once to `/\x&password=<word>`, whose `/\` Node 22 reads as
  an authority start and the walk as a path, so `redact_url` keeps the password. r4's
  measurement (`probe_slash.py`) found the other `/`-led runs that are not exactly `//`
  the same on f939778, 20cd466 and the revision (`///`, `/\\`, `/\/`, `////`), so the
  pin has five cases, each failing on its stated assertion on the revision
  (`r4/pins_plain_new.log`) and on 20cd466 (`r4/pins_plain_20cd466.log`). It is the
  encoded sibling of `::test_a_backslash_led_pair_list_decoded_once_is_held_secret`
  (whose first assertion, `value_holds_secret`, stops before any redactor is judged, so
  a sibling, not an extension, covers `redact_url`).
- **Correction to r3's claim.** r3 listed `_AFTER_FINAL` (21 spellings) as spellings
  f939778's URL redactors redacted and 111b6fb kept. The skeptic measured three that
  f939778 kept too, and `r4/probe_after_final.py` confirms it: cases 5 and 6 (0-based;
  group 1's `/go/` spellings, a spaced userinfo in a nested path segment) and case 12
  (group 2's `#/r?next=a%3Dhttps…`, a pair-list userinfo in a route's query) are kept on
  f939778 by both URL redactors, the proxy's `Location`, `page_url_is_clean` and
  `value_holds_secret`, and cases 5 and 12 by `safe_ref` and `redact_for_record` too
  (case 6's raw `https://bob:…@` matched those two's own userinfo patterns). They are
  **not regressions against f939778**: they are fixed by the same r3 change as their
  group's regression (class 1's authority through whitespace; class 2's `_Whole` for a
  pair-list userinfo), as N1 (B) is by class 3's. The probe also shows case 14's
  `value_holds_secret` False on f939778 (its URL redactors redacted it). The test
  file's comment is corrected; r3's "41 new cases fail on 111b6fb" stands.
- **The round's run** (one pytest invocation, `FUZZLAB_PYTEST_LOCK_WAIT=7000`, `-n 3
  --dist loadfile`, of r3's 17 files -- every test file importing
  `fuzzlab.core.redaction`, the pins file and `tests/test_store_adapter.py`;
  `scratchpad/lanes/REDACTURL/r4_run.sh`, `r4_run.log`): `1528 passed, 47 xfailed, 3
  warnings in 496.76s` (exit 0; the 47 xfails are r3's 42 and the 5 new pin cases; no
  skip, no failure; the warnings are a starlette deprecation and a `fork()` notice in
  other files' tests; two comment-only edits to the `_AFTER_FINAL` comment of
  `tests/test_redaction_nested.py` landed about 80 s into the run, after collection, and
  change no code).
- **Recurrence review.** The lane's fifth pass at the class, and a recurrence of r3's own
  defect (a regression the batch introduced, unseen by its tests). **Prior-preventive-
  action failure analysis: PA-0556(8) (a generated differential against the pre-fix
  revision before a round is reported) was followed but too narrow.** r3 ran it
  (90 720 + 12 600 URLs, "regresses none") over prefixes its author chose; it did not
  require the generator to drive the conditions the change itself adds, and the change's
  new branch (a `\\` or `\/` lead kept URL-shaped) was the one shape absent. PA-0556
  gains item 9 (in the lane's doc texts): the differential's inputs are derived from the
  diff -- for every condition the change adds or alters (each literal a changed
  predicate tests: a prefix, a character class, a separator) at least one input on each
  side of it, in every encoding the sweep has, listed in the round's report -- and a
  claim that a listed spelling was redacted before is measured on the pre-fix revision
  per spelling, never inferred from its group.

### r5: the pushed tree's readings, against the owner's shipping criterion (branch `lane/REDACTURL-r4` from 290fcfb)

**The shipping criterion (the owner's rule).** The redactor must leak nothing the
**pushed** tree, 7393c90, redacted: a regression against the pushed code is fixed in this
batch (PA-0549(3c)), and every leak the pushed code also had is pinned by a strict xfail,
never fixed in another round. Every earlier round measured "no regression" against
f939778 (the unpushed review-round-1 revision) or its own pre-fix revision; neither is the
criterion, and both already held the walk that replaced the pushed tree's readings.
Proof files are under `scratchpad/lanes/REDACTURL/r5b/`.

- **The differential** (`r5b/gen_corpus.py`, `run_corpus.py`, `diff_corpus.py`; run on
  `git archive` exports of 7393c90 and 290fcfb and on the revision's package): one corpus
  of 234 112 distinct URLs -- r4's `sweep3.py` (152 880 cases, 116 466 distinct URLs; r3's
  `sweep2.py` is a subset of it), r4's `benign2.py` (25 536 cases, 19 760 distinct URLs,
  no secret), the r4 skeptic's two classes generated over leads, payloads, every
  encoding and positions (class (a): a value led by `\\`, `\/`, `\\\`, `\\/`, `\//`,
  `\/\` or `\\\\`, and neighbouring leads, whose pair list sits in a later path segment,
  `next=%5C%5Cx%2Fp%26password%3D<w>`, raw and in thirteen encodings, in twelve
  positions, routes included: 67 108 URLs; class (b): a top-level fragment holding a
  backslash-led userinfo, `#\\user%3A<w>%40x%2Fp` and its spellings: 20 194), and three
  classes derived from the pushed tree's own parsing (below: names split by a tab, CR or
  LF and identifiers so split, 3 708 + 792; a `;` inside an `&`-only pair, 6 084). Each
  URL goes through `redact_url`, `redact_url_identifiers`, `safe_ref`,
  `redact_for_record`, `page_url_is_clean` (True keeps it), `value_holds_secret` of the
  nested value decoded once (False keeps it; absent at 7393c90 and counted as kept
  there), the proxy's `redact()` of a request line, a `Referer` and a `Location`, and
  `import_spider` (batched, each URL its own secret variant and path). Oracle: the secret
  in the output or in any of its 1-7 percent-decodings.
- **Counts, 290fcfb against 7393c90** (`r5b/diff_290fcfb_vs_7393c90.txt`): **leaks at
  290fcfb and redacted at 7393c90: 4 366 URLs** (19 255 case-consumer pairs: 600 in the
  tab/CR/LF names, 3 288 in the `;` class, 478 in the tab combinations; none in sweep3,
  class (a) or class (b), which 7393c90 kept too: it never looked inside a value);
  **leaks at both: 83 209 URLs**; fixed: 150 996. Consumers that regressed: `safe_ref`
  4 366, `redact_url_identifiers` 3 616, `redact_for_record` 2 700, `page_url_is_clean`
  2 544, `redact_url` 2 289, the proxy's `Location` 2 038 and request line 1 702.
- **What the defect was: two readings of the pushed tree the walk dropped.** (1) 7393c90's
  `redact_query` split a query on `&` only, so a pair's name ran to its first `=` across a
  `;` (`?u=bob&password;x=<w>`, `a;token;b=<w>`) and a sensitive pair's value ran to the
  next `&` across one (`password=pw;<w>`); its record redactor read a fragment's pairs the
  same way. The walk split on `;` first, judged `x`, and kept `<w>` as a bare piece.
  (2) 7393c90 read the query through `urlsplit`, which removes every ASCII tab, CR and LF
  (bpo-43882; the WHATWG parser does the same), so `p<TAB>assword=<w>` and
  `%7<TAB>0assword=<w>` were `password=…` to it, a 16-hex token split by a tab was one
  token, and the URL it returned (`urlunsplit`) was so cleaned whenever it redacted --
  `safe_ref`'s record pass and identifier blanking then read a fragment's pairs, a path
  parameter (`p.php;passwor<TAB>d=<w>?token=a`) and a matrix value with them removed too.
  The walk judged each name and value as written: `p`, `assword`.
- **Five whys.** The secrets were kept because the walk read names with `;` and tabs
  where 7393c90 read them without. The walk replaced `redact_query` and `urlsplit` in the
  batch's first commit (b6db14a), so every later revision -- f939778 included -- had
  already dropped both readings. Every round's differential compared the round with
  f939778 or its own pre-fix revision, so a regression the first commit introduced was on
  both sides of every comparison and never showed. **Root cause:** the differential's
  baseline was the batch's own history, not the pushed tree the users have, and its
  inputs were derived from the walk's conditions (PA-0556(9)), not from the pushed code's
  own parsing (each library parse it called and each separator it split on).
- **Fix** (`fuzzlab/core/redaction.py`; CC-CORE-0076's r5 sub-bullet; FR-CORE-537 in
  place). Fail closed on either reading. `_UrlWalk.pairs`: an `&` part holding a `;` is
  also read as one pair, its name running to its first `=` (`amp_secret`); every `;`
  pair is walked first, then, when that name is sensitive, the part's value to the next
  `&` is replaced. `_secret_name` judges a pair's or path parameter's name as written and
  with its tabs, CRs and LFs removed (before the form-decode, so `%7<TAB>0` is `%70`);
  `_identifier_like` judges a value both ways too. `_walk_url`: a URL holding a tab, CR
  or LF that either reading redacts (the stripped URL is walked as well) is returned with
  them removed and walked again, as `urlunsplit` returned it, so `safe_ref` reads it as
  7393c90's did. A clean URL is returned byte-identical.
- **The first draft regressed against 290fcfb, caught by the differential before
  commit.** It replaced the `;` reading of such a part by the `&` one: when the `&`
  reading's name held a sensitive token only because a secret sat inside it
  (`next=host%253Btoken%253D<w>%2Fx%3Ba%3D1`, decoded `host%3Btoken%3D<w>/x;a=1`), it
  redacted the value after `=` and skipped the walk of the name's own pieces: 450 URLs
  (3 150 pairs) of sweep3 that 290fcfb redacted (7393c90 kept them too). Both readings
  now always apply; the guard
  `test_the_amp_reading_never_replaces_the_semicolon_reading` holds it.
- **Counts after the fix** (`r5b/diff_fix_vs_7393c90.txt`, `diff_fix_vs_290fcfb.txt`):
  **leaks at the revision and redacted at 7393c90: 0 URLs** (0 pairs); **leaks at both:
  78 135 URLs** (665 654 pairs; 73 251 with a consumer 7393c90 had, the other 4 884 kept
  only by `value_holds_secret`); **fixed against 7393c90: 153 720 URLs**. Against 290fcfb:
  0 regressed, 6 225 fixed, and the 19 760 benign URLs' outputs are identical in every
  consumer. Against 7393c90, 7 benign outputs differ, as they did on 290fcfb (unchanged by
  r5): `next=a=//host=1/x;a=1` and its spellings are blanked, because after the `;` split
  the unchanged identifier rule judges `a=//host=1/x` an identifier (12 characters, a
  digit, 36 bits); over-redaction of evidence, not a leak.
- **Tests** (`tests/test_redaction_nested.py`, "r5"): `_PUSHED_TREE_READINGS` (23
  spellings: the `&`-only reading in a query, a fragment and both route forms; a tab, CR
  or LF in a name and inside its escape; after a query 7393c90 redacted, in a fragment's
  pair, a route's query, a path parameter) through
  `test_a_secret_the_pushed_tree_redacted_is_redacted_by_every_url_consumer` (both
  redactors, `safe_ref`, `redact_for_record`, `page_url_is_clean`, and the proxy's
  request line and `Location` for a URL an HTTP line can carry), and
  `_PUSHED_TREE_IDENTIFIERS` (5) through
  `test_an_identifier_the_pushed_tree_read_whole_is_redacted_by_every_identifier_consumer`;
  the guards `test_the_amp_reading_never_replaces_the_semicolon_reading` (3) and
  `test_a_clean_semicolon_part_or_tab_is_left_byte_identical` (5). The plain runner on
  290fcfb's `fuzzlab/` (`r5b/r5_tests_plain_290fcfb.log`): all 28 new cases fail, each an
  `AssertionError` on its own assertion, and the 8 guard cases pass; on the revision all
  36 pass (`r5_tests_plain_fix.log`) and the whole file passes (`nested_plain_fix.log`:
  592 ok, its strict xfails among them).
- **Every leak present at both, assigned** (`r5b/assign.py`, `assign_fix.txt`: each of the
  78 135 URLs to a family by the generator's coordinates; none unassigned). Pinned now in
  `tests/test_redaction_residual_pins.py` (strict, `raises=AssertionError`, each reason
  naming BUG-0556 and its owner; 11 tests, 43 cases, each failing on its stated assertion
  on the revision, on 290fcfb and on 7393c90: `r5b/pins_plain_{fix,290fcfb,7393c90}.log`):
  - class (a), `test_a_pair_list_in_a_nested_urls_later_path_segment_is_redacted` (CORE
    `_UrlWalk.path`: a nested URL's later path segment is never split into pairs; a URL
    nested in a segment, `/go/https://x&…`, too): 40 503 URLs;
  - `test_a_path_parameter_value_holding_a_raw_slash_is_redacted` (CORE `_UrlWalk.path`:
    a top-level path parameter's value is cut at its first raw `/`): 13 298;
  - class (b), `test_a_backslash_led_userinfo_in_the_top_level_fragment_is_redacted`
    (CORE `_authority_start` / `route`; 20cd466 redacted the encoded spellings): 6 580;
  - `test_a_scheme_less_userinfo_in_a_value_is_redacted` (CORE `_AUTHORITY_AT`:
    `next=bob:<pw>@host`): 2 365;
  - `test_proxy_history_redacts_a_url_holding_a_raw_lf` (PROXY: a raw LF ends the
    request line or URL header): 948;
  - `test_a_top_level_userinfo_holding_a_raw_amp_is_redacted` (CORE `_UrlWalk.pairs`:
    `next=//bob:p&w<pw>@host` cut by the query split): 910;
  - `test_a_top_level_fragments_pairs_before_a_question_mark_are_redacted` (CORE
    `_UrlWalk.fragment`: `#token=<w>?y=1` is a route): 864;
  - `test_a_slash_run_after_a_scheme_before_a_pair_list_is_redacted` (CORE
    `_authority_start`: `https:///x&password=<w>`, the r4 pin's sibling behind a scheme):
    688;
  - `test_the_amp_reading_of_a_nested_value_is_redacted` (CORE `_UrlWalk.pairs`: the `&`
    reading's value across `;` is never walked whole, `next=/v?password;x=<w>`): 384;
  - `test_an_identifier_as_a_top_level_path_segment_or_route_is_redacted` (CORE and AUD:
    the page's identity, R3): 36;
  - `test_a_top_level_urls_own_userinfo_is_redacted_by_the_url_redactors` (CORE
    `_UrlWalk.url`: the URL's own authority is its identity): 4.
  Pinned before: R3's `test_a_userinfo_in_the_top_level_fragment_route_is_redacted` and
  N1 (A)'s `test_an_encoded_authoritys_userinfo_is_redacted` (the `//`, `///`,
  `https://`, `https:\\` and `/\` leads of class (b)'s generator, raw and encoded: 3 022),
  r4's `test_a_slash_led_authoritys_pair_list_encoded_once_is_redacted_by_redact_url`
  (1 305) and N7's `test_a_record_never_deletes_a_pair_name_with_a_userinfo_pattern`
  (732). **Stated, not pinned** (no reading of the pushed tree or of a URL parser makes
  them a kept secret of a consumer that judges them; for the owner to overrule): 4 884
  URLs kept only by `value_holds_secret`, which 7393c90 did not have (the stored consumer
  it feeds, `import_spider`, is measured directly and stores none of them); 1 152 `;`
  controls, in which no reading names the word's pair sensitive (`?u=bob;password;x=<w>`:
  the word is `x`'s under `;` and `u`'s under `&`; `/a;password;x=<w>/` a path
  parameter's); 460 identifiers kept only by the name-only consumers (`redact_url`,
  `redact_for_record`, the proxy), which judge names only by specification (FR-CORE-537),
  on 7393c90 too.
- **The round's run** (one pytest invocation, `FUZZLAB_PYTEST_LOCK_WAIT=7000`, `-n 3
  --dist loadfile`, of the same 17 files as r3 and r4 -- every test file importing
  `fuzzlab.core.redaction` and `tests/test_store_adapter.py`;
  `scratchpad/lanes/REDACTURL/r5_run.sh`, `r5_run.log`): `1564 passed, 90 xfailed, 3
  warnings in 533.42s` (exit 0; no skip, no failure; +36 passed and +43 xfailed against
  r4's run, the round's new cases and pins).
- **Recurrence review.** The lane's sixth pass at the class and a recurrence of r3's and
  r4's defect (a regression of the batch unseen by its tests), now against the pushed
  tree. **Prior-preventive-action failure analysis: PA-0556(8) and (9) were followed and
  were the wrong layer.** Item 8 asks for a differential "against the pre-fix revision"
  and item 9 derives its inputs from the change's own conditions; r3 and r4 read the
  baseline as the round's own pre-fix revision (f939778, 20cd466), so a reading the
  batch's first commit dropped was absent on both sides of every comparison, and the
  inputs came from the walk's branches, never from the parsing of the code it replaced.
  PA-0556 gains item 10 (in the lane's doc texts): every round's differential also runs
  against the pushed tree (the last revision users have), and its corpus drives the
  pushed code's own parsing -- each library parse it called (`urlsplit`'s removal of
  tabs, CRs and LFs) and each separator it split on (`&` only) -- on both sides.

### r6 (layered on the pushed redactor; branch `lane/REDACTURL-r6` from 144d234)

**Why a sixth fix round.** An independent check of 144d234 (journal `wf_9a1e5879-609`;
its corpus regenerated in `scratchpad/lanes/REDACTURL/r6/checkwork/`: 101 005 URLs,
100 504 holding a secret, through every URL consumer) found **2 104 URLs that 144d234
kept and the pushed tree 7393c90 redacted** (`diff.144d234_vs_7393c90.txt`: 1 253
case-consumer pairs where 7393c90 redacted, 6 256 where it raised and its caller withheld
the value), in five classes r5's differential never drove:

- **R1** `core.trace.safe_ref` ran the walk first and the record rule's userinfo
  regexes after it; where a userinfo password held a `;` or `&` before a piece the walk
  redacted, the walk cut the `@` the regex needed and `bob:<password>;` was kept
  (7393c90 ran its URL redactor, then the record rule, which removed the whole userinfo);
  775 URLs, 146 stored by `import_spider` through `fuzzlab auto`'s trace recorder.
- **R2** `redact_for_record` (and `safe_ref`) walked the whole value with a tab, CR or
  LF removed, merging the pieces 7393c90 split on that whitespace
  (`n<TAB>ext=/cb?password=v;<w>`: 7393c90 read `ext=/cb?password=v;<w>` as a URL of its
  own, its value running past the `;`); 450 of the check's 2 268 tab/CR/LF variants.
- **R3** the proxy read a quoted `Refresh` URL only inside its quotes and only the first
  `url=`; 7393c90 passed every `url=` run, quotes and tail included, to its redactor; 384
  of 1 410.
- **A1** 7393c90's URL redactors raised `ValueError` on a URL `urlsplit` rejects
  (`http://[h/…`, a bad bracketed host, a netloc that NFKC-normalises to a delimiter),
  and every caller withheld the value (`safe_ref`'s `(unparseable URL withheld)`, the
  history writer's `_prepare_contained`); the walk never raised and kept the secrets it
  keeps; 1 329 URLs.
- **A2** when 7393c90 rewrote a `Location` or `Content-Location` it replaced every
  duplicate by the one rewritten value (`RawMessage.with_header`); 144d234 kept every
  duplicate and walked each, keeping a secret its walk keeps.

**The design (the owner's, for audit gap 5).** Never replace the pushed redactor: layer
on it. `fuzzlab/core/redaction_floor.py` holds 7393c90's own redaction code verbatim
(73 definitions from `core/redaction.py`, `core/urls.py::is_spa_route_fragment`,
`core/trace.py::safe_ref` and its blanking, `tools/store_adapter.py::redact_sibling`,
`proxy/message.py::RawMessage` and `proxy/redact.py::redact`; the only edits point four
function-local imports at the floor itself, and it imports nothing of `fuzzlab` at
module level). Every URL redaction consumer runs its floor first on its input as
received and the batch's walk (144d234's code, unchanged) on the floor's output only, so
nothing the pushed tree redacted reaches the walk and the walk can only remove more.
Per consumer (`core.redaction.LAYERED`):

| Consumer | Floor (frozen 7393c90) | Then |
| --- | --- | --- |
| `redact_url` | `redact_url` | `_walk_names` (the walk, names) |
| `redact_url_identifiers` | `redact_url_identifiers`; with `placeholder=True`, `redact_url` (the floor's identifier rule blanks a value, and a blank in a sent query is what PA-0544(3) forbids) | `_walk_url(identifiers=True)` |
| `redact_spa_fragment` | `redact_spa_fragment` | `_walk_spa_fragment` |
| `page_url_is_clean` | its verdict must be True first | the walk's verdict (`_walk_url` unchanged, no placeholder, no blank) |
| `redact_for_record` | `redact_for_record` | `_walk_record` |
| `stored_value` | `redact_sibling` (7393c90's sibling rule) | `""` too when the walk's `value_holds_secret` holds |
| `core.trace.safe_ref` | `safe_ref`; a value it withholds stays withheld | `_walk_url(identifiers=True)`, `_walk_record`, `_blank_identifiers` |
| `proxy.redact.redact` | `redact` (restores A2's collapse, R3's every `url=` run) | `_walk` |
| `strip_secret_path_params`, `value_holds_secret` | none: 7393c90 had no counterpart (it stored a path as `to_path` gave it) | `FLOORLESS` / `WALK_PREDICATES` |

**A1 (where a floor raises).** The consumer raises `ValueError`, as on 7393c90, and each
caller behaves as it did there: the proxy history writer stores the flow with every body
`OMIT_FAILED` and the URL cut at its `?` (`_prepare_contained`); `safe_ref` returns
`(unparseable URL withheld)`; `page_url_is_clean`'s callers (the oracle's binder,
`_source_page`) and the importers' other URL steps raise where 7393c90's own
`store_url` / `urlparse` of the same URL raised (measured: `import_spider` over the
check's corpus raises on the same 7 URLs on 7393c90, 144d234 and r6). The one caller the
batch added where 7393c90 did not raise is `import_audit`'s target identifier (7393c90
stored it raw): r6's first draft let the floor's raise fail the whole import; now
`store_adapter._audit_text` returns its own marker `AUDIT_TEXT_WITHHELD` ("(unparseable
URL withheld)", as `safe_ref` withholds) for a text whose URL the floor rejects and the
import goes on (CC-AUD-0059, r6 sub-bullet). A finding *page* `urlsplit` rejects still
fails the import, in `_main_origin` / `store_url`, as 7393c90's `to_path` did (not a
floor; unchanged).

**The guards** (`tests/test_redaction_floor.py`, each proven on synthetic offenders,
PA-0034(2)): `test_the_floor_is_the_pushed_trees_code_verbatim` (each definition hashes
to `git show 7393c90`'s text after the recorded import substitutions, and the module holds
exactly those definitions) with `test_the_frozen_check_flags_an_edited_floor`;
`test_every_url_redaction_consumer_runs_its_floor_first` (by AST: the first statement of
each `LAYERED` function calls its floor on its own parameters as given, and the function
never reads its text parameter again) with
`test_the_layering_check_flags_a_consumer_that_skips_its_floor` (a consumer that skips
its floor, runs the walk first -- 144d234's `safe_ref`, R1 --, changes the floor's input
or reads its raw input after it); `test_no_function_runs_the_walk_or_the_floor_unregistered`
(every call of the walk is from a `LAYERED`, `WALK_HELPERS` or registered predicate
function, every call of the floor from a `LAYERED` consumer) with
`test_the_registry_scan_flags_an_unregistered_walk_or_floor_call`. The defined-once
guards (`tests/test_identifier_predicate.py::test_defined_once`,
`tests/test_shared_primitives.py::test_every_owner_is_defined_once`) exempt only the
frozen floor, naming its guard; `tests/test_query_placement.py` allows the floor's five
query builders, 7393c90's own entries moved with them.

**Counts, against the pushed tree 7393c90 (the owner's criterion: nothing 7393c90
redacted may leak; a 7393c90 raise or withhold counts as redacted).** Every corpus: **0
URLs leak at r6 that 7393c90 redacted.**
- The check's corpus (`r6/checkwork/diff.r6_vs_7393c90.txt`; every consumer, the proxy's
  request line, `Location`, `Content-Location` and `Refresh` and
  `redact_url_identifiers(placeholder=True)` included): 0 regressed; 39 852 leak at
  both; 68 297 fixed. 144d234 on the same corpus: 2 104 regressed.
- The tab/CR/LF merge set (`diff.tm_r6_vs_7393c90.txt`, 2 268 URLs): 0 regressed; 1 512
  at both; 522 fixed.
- r5b's corpus (`r6/r5b_rerun/diff_r6_vs_7393c90.txt`, 234 112 URLs, r5b's own scripts):
  0 regressed; 78 135 at both (as r5); 153 720 fixed; 7 benign outputs differ from
  7393c90's, as on 290fcfb and 144d234 (r5's over-redaction of `next=a=//host=1/x;a=1`).
- `import_spider` under a trace recorder (`impdiff.r6_vs_7393c90.txt`, 99 449 URLs,
  87 932 imported, 7 raising on all three trees): 0 regressed; 36 070 at both; 48 080
  fixed.
- The generated family-(a) set (`r6/checkwork/gen_tabboundary.py`, 480 URLs): 0
  regressed.

**The 144d234 deltas (information only: the owner dropped "0 against 144d234", the
orchestrator's own bar against an unpushed round).** The check's corpus: 3 URLs (4
pairs, all `safe_ref`; family (b)); r5b's corpus: 146 URLs, all `safe_ref` (family (b));
`import_spider`: 1 URL (family (b), through `trace_event` / `dg_flow`); the family-(a)
set: 100 URLs, 500 pairs (family (a)); the tab/CR/LF merge set: 0 (all 450 of 144d234's
regressions there fixed). Benign: 0 of the check's 500 and 1 of r5b's 19 760 outputs
differ from 144d234's (an over-redaction:
`http://h/app/p.php;next=a%3D%2F%2Fhost%3D1%2Fx?u=bob`). Each of the three families
leaks at 7393c90 too.

**The three families, pinned** (`tests/test_redaction_residual_pins.py`, "r6"; strict,
`raises=AssertionError`, reasons naming BUG-0556, owner CORE, the family and its
consumers; each case fails on its stated assertion on r6 and on 7393c90's export and
passes on 144d234's, which proves the family is one 144d234 redacted:
`scratchpad/lanes/REDACTURL/r6b/pins_r6new_plain_{wt,t7393c90,t144d234}.log`: 16 xfail,
16 xfail, 16 XPASS). The candidate rules are stated, not built.
- **(a)** `test_a_name_joined_by_a_tab_cr_or_lf_in_the_floors_output_is_redacted` (7
  cases): the floor reads a query through `urlsplit`, which removes every tab, CR and LF,
  and returns the URL so cleaned whenever it redacts another pair, so
  `?token=a&x<TAB>password=<w>` reaches the walk as `xpassword=<w>`, one token; kept by
  `redact_url`, `redact_url_identifiers` (both modes), `safe_ref` and the proxy's request
  line, `Location` and `Content-Location` (in a top-level pair, a raw or encoded nested
  query, a fragment pair and a route's query). Candidate: the walk judges a name holding
  a tab, CR or LF from the raw input.
- **(b)** `test_the_floors_userinfo_rule_never_lets_the_evidence_reference_keep_a_secret`
  (5) and `test_import_spider_under_a_trace_recorder_stores_no_identifier_behind_the_floors_userinfo`
  (1): the floor's `safe_ref` runs the record rule (`***@`) before the walk, which then
  sees no pair name (`;next=is:open label:bug&password=H@<w>` becomes `;next=is:open
  ***@<w>`) or no userinfo to redact a nested URL whole for (`#https://%26bob@<id>`
  becomes `#https://***@<id>`): kept by `safe_ref` and stored in `trace_event` and
  `dg_flow` (the record redactor's own reading of the rule is N7's pin). Candidate: the
  walk redacts whole any value holding the floor's `***@`.
- **(c)** `test_a_nested_userinfo_cut_by_the_records_size_bound_keeps_no_password` (3):
  the floor's record redactor cuts at 4096 characters after its userinfo rule and before
  the walk, so a percent-encoded nested userinfo straddling the cut loses its `%40` and
  the start of its password is kept by `redact_for_record` and `safe_ref` (10 cut
  positions each of `r6/probe3.py`'s 60). Candidate: when the floor truncated, the walk
  redacts the cut piece whole.

**Tests** (`tests/test_redaction_nested.py`, "r6"): 29 cases -- R1 6 and its store path
1, R2 8, R3 4, A1 3 and the history writer 1 and `import_audit` 2, A2 4. The plain runner
on 144d234's `fuzzlab/`: all 29 fail, each an `AssertionError` at its own assertion
(`scratchpad/lanes/REDACTURL/r6b/r6_tests_plain_t144d234.log`); on r6 all pass
(`r6_tests_plain_wt.log`); on 7393c90's, 26 pass and 3 fail on their leak assertion
(`import_audit`'s two: 7393c90 stored the target raw; R1's store path: 7393c90 stored the
password in `form.entries` and `parameter.example`, which the batch's first commit
fixed). The `import_audit` case fails on r6's first draft at "the import failed:
ValueError" (`a1_import_audit_plain_r6pre.log`). Edited for the floor:
`test_the_redactors_are_total` (a URL `urlsplit` rejects may raise `ValueError`, nothing
else) and the every-nested-spelling sweep (the top-level names kept may be the floor's:
`u=bob;a=1;k=<jwt>` becomes `u=`, as on 7393c90). After the last change the whole file
passes (`r6b/nested_wt.log`: 621 ok, 0 bad), the pins file holds (`pins_wt.log`: 101
strict xfails, none passing) and the floor's guards pass (`floor_wt.log`: 6 ok).

**Recurrence review.** The lane's seventh pass at the class, and a recurrence of r5's
defect (a regression against the pushed tree its own differential did not see). Prior
occurrences: r3 (BUG-0556 "Residuals after the owner's final round"; PA-0556(8)), r4
(PA-0556(9)) and r5 (PA-0556(10)). **Prior-preventive-action failure analysis:
PA-0556(10) was followed and was the wrong layer.** r5 ran its differential against
7393c90 with a corpus that drove the pushed code's parsing (`urlsplit`'s removal of tabs,
CRs and LFs, the `&`-only split), as item 10 asks, and found 0. The check found five more
behaviours of the replaced code: its order of steps (`safe_ref`'s URL redactor before
the record rule), a caller's split (the record redactor's whitespace split), a header's
grammar (`Refresh`'s every `url=` run), its exceptions as a withholding signal (A1) and
its container's side effect (A2). Items 8, 9 and 10 each extended a differential's
enumeration of what the replaced code did, and each round the next unenumerated
behaviour regressed: an enumeration of a replaced implementation's behaviours cannot be
proven complete. The new item 11 (in the lane's doc texts) removes the enumeration: a
redactor's fix is layered on the pushed redactor -- the pushed code is kept, frozen and
run first, and the change runs only on its output -- so no secret the pushed code
redacted can leak by construction, and `tests/test_redaction_floor.py`'s guards hold the
structure. What the walk then cannot see (information the floor's output lost: families
(a)-(c)) leaks at 7393c90 too and is pinned, never another design round (the owner's
rule).

### r6 review (3615cfb; branch `lane/REDACTURL-r6`, one more commit)

Two independent checks of 3615cfb (journal `wf_ef48570e-267`: a differential against
7393c90 over 70 888 generated URLs, and a review of the code and the records; evidence in
`scratchpad/checks-r6b-evidence/`) found no leak the pushed tree redacted, and six
defects: one functional regression of the batch against 7393c90 (D1), two holes in the
floor's guards (R1, R2), a family the floor-first design keeps that no record named (R3),
a record claiming an unreachable branch (R4) and an incomplete recurrence review (R5).
The owner's criterion stands: nothing 7393c90 redacted may leak; a regression of the
batch against 7393c90 (a leak or a broken import) is fixed in the batch; anything 7393c90
also leaks is pinned by a strict xfail. Each fix below has a test failing on 3615cfb at
its own assertion (a guard fix: its synthetic offenders pass 3615cfb's guard), proven by
the plain runner (pytest imported only as a library) in
`scratchpad/lanes/REDACTURL/r6c/`.

- **D1 -- `import_audit` failed where the pushed tree imported** (owner AUD,
  CC-AUD-0059 "r6 review"). *Finding:* `import_audit` raised `ValueError("Invalid IPv6
  URL")` for a finding page that is not an absolute URL and holds `[` or `]` in its first
  segment (`x[y/app/p.php?u=1&token=…`, `h]/app/p.php`, `[h/app/p.php`) or after a
  leading Unicode space (`\u3000http://[h/…`, `\xa0http://h]/…`), and stored nothing;
  7393c90 (`to_path` only) imported each (28 of the check's 888-URL supplement, 0 of its
  70 000 random URLs; out of reach of `fuzzlab audit --store`'s chain, whose
  `import_spider` fails on such a page first, but not of a standalone import or an
  `--append` findings DB). *Cause:* review round 2's `_main_origin` / `_audit_endpoint`
  (N3) read each finding page's origin with `core.urls.canonical_origin`, which strips
  whitespace and prefixes `http://` to a URL holding no `://`, so `urlsplit` judges the
  first segment as a netloc and rejects the bracket; r6's records said such a page
  "still fails the import, as 7393c90's `to_path` did", inferring from the absolute
  spelling (`http://[h/…`, which `to_path` rejects too) that the two reject the same
  strings -- a claim read from the code, never measured (PA-0556(4)), and no differential
  had run `import_audit` (the checks drove the consumers and `import_spider`). *Fix:*
  such a page names no origin: the run's main origin is read by `_readable_origin`
  (`canonical_origin`, `None` where it raises), and `_audit_endpoint` stores the page by
  its path, as `store_url` stores a URL whose origin is unknown and as 7393c90's
  `to_path` stored it (a `;` path parameter holding a secret dropped); the texts pass
  `_audit_text` as any other's. *Test:*
  `tests/test_redaction_nested.py::test_r6_review_d1_import_audit_imports_a_page_no_origin_reads_as_the_pushed_tree_did`
  (6 cases): on 3615cfb each fails at its first assertion ("the import failed:
  ValueError('Invalid IPv6 URL')"); on the revision each passes (the endpoint is
  `to_path` of the page, no secret stored); on 7393c90 each imports, three failing at the
  leak assertion (7393c90 stored the page URL's token raw in `sink_context`).
  *Measured:* The check's own import runner (`checks-r6b-evidence/run_imports.py`, an `import_audit` per URL under a trace recorder) on the revision, against its 7393c90 outputs (`scratchpad/lanes/REDACTURL/r6c/imp_compare.txt`, `extra_imp_compare.txt`): 0 import failures where 7393c90 imported (3615cfb: 28 of the 888-URL supplement) and 0 URLs leaking what 7393c90 redacted, on the 70 000 and the 888; the findings on a page 7393c90's import raised on (3 463 and 27, a page `urlsplit` rejects as written; 3615cfb raised too) are imported, no secret stored.
- **R1 -- the frozen check missed a decorator** (owner CORE, CC-CORE-0076 "r6 review").
  *Finding:* `frozen_problems` hashed `ast.get_source_segment(node)`, which starts at
  `def` / `class`, so `@dataclass(frozen=True)` made `@dataclass` on the floor's
  `RawMessage`, or `@lambda f: (lambda url: url)` above its `redact_url` or `safe_ref`,
  passed the guard while the floor stopped redacting. *Cause:* the guard hashed the AST
  node's span, which since Python 3.8 excludes its decorators, and its synthetic
  offenders were edit kinds its author listed (a constant, a line, an appended statement,
  a removed definition, an import, the docstring), not every part of a definition that
  changes what it does. *Fix:* `_segment` hashes from the first decorator's `@`;
  `RawMessage`'s digest is retaken from 7393c90's text with its decorator. *Test:*
  `tests/test_redaction_floor.py::test_the_frozen_check_flags_an_edited_floor` gains a
  decorator changed, removed and added (on `redact_url`, `safe_ref`); each of the four
  passes 3615cfb's `frozen_problems` and fails the revision's
  (`r6c/proof_guards_offenders.log`), and the reviewer's three real floor edits, applied
  to a copy of each tree, pass 3615cfb's guard file and fail the revision's
  (`r6c/proof_guards_tree.log`).
- **R2 -- the layering guards were bypassable** (owner CORE, CC-CORE-0076 "r6 review").
  *Finding:* a module-level re-binding of a `LAYERED` name after its `def`
  (`redact_spa_fragment = _walk_spa_fragment`, `redact_url = _walk_names`) or a
  decorator on a `LAYERED` def passed guards 2 and 3 while the live consumer skipped its
  floor (the first in `tools/spider.py`'s path); a new module using the walk or the floor
  without a call by an imported name -- `map(_walk_names, …)`,
  `functools.partial(_walk_url, …)`, `getattr(redaction, '_walk_names')`, `import
  fuzzlab.core.redaction` then `fuzzlab.core.redaction._walk_names(u)`, an unaliased
  import of the floor, `filter(looks_like_identifier, …)` from the floor -- passed guard
  3; and `stored_value`'s entry named only `value`, so `return raw_value if kept else
  kept` passed guard 2. *Cause:* guard 2 modelled a consumer as its function body and
  guard 3 a use as a `Call` by a name bound by `from … import` or an alias: the module's
  namespace (a later binding, a decorator) and Python's other references (a function
  passed as a value, a dotted chain, `getattr`) were outside the model; `LAYERED` named
  "the parameter that holds the text it redacts" -- one -- and `stored_value` has three.
  Its offenders, like R1's, were the shapes its author thought of. *Fix:* guard 2 checks
  that each `LAYERED` name is bound once in its module, by its undecorated `def`, never
  re-bound (assignment, import, `global`, a second `def`), that a name bound to the floor
  is bound to nothing else, and that no **text parameter** -- every str parameter, now
  listed in `LAYERED` and checked against the signature -- is read after the floor except
  as a predicate's argument (`isinstance`, `is_sensitive_name`, `WALK_PREDICATES`);
  `redact_for_record` passes `""` to its walk instead of `dest` (the floor applied the
  option-name rule; the same output as 3615cfb's on 24 430 corpus URLs under seven option
  names, `r6c/rfr_equiv.py`). Guard 3 (`unregistered_uses`) counts any reference as a
  use, resolves unaliased dotted chains, relative imports and `getattr` / `setattr` with
  a literal name, treats a decorator's or default's use as module level, and flags an
  assignment to a `LAYERED`, walk or floor attribute from another module. *Stated
  limit*, in the guard's docstring and FR-CORE-537 instead of a claim: a name computed at
  run time (`getattr` with a computed name, `globals()`, `vars()`, `sys.modules`,
  `importlib`, `exec`) is not visible to a static guard. *Test:*
  `tests/test_redaction_floor.py::test_the_layering_check_flags_a_consumer_that_skips_its_floor`
  (11 new offenders: four re-bindings, a decorator, the floor alias re-bound or made a
  parameter, an import shadowing the parameter, `stored_value` returning or walking
  `raw_value`) and `::test_the_registry_scan_flags_an_unregistered_walk_or_floor_call`
  (12 new: each form above, a relative import, the floor module passed on, a walk in a
  decorator and in a default, a `LAYERED` consumer assigned and `setattr` from another
  module); all 23 pass 3615cfb's guard functions (`r6c/proof_guards_offenders.log`), and
  the reviewer's real edits (three re-bindings and decorators of `core/redaction.py`,
  `stored_value` returning `raw_value`, six new modules) each pass 3615cfb's guard file
  on a copy of 3615cfb and fail the revision's on a copy of the revision
  (`r6c/proof_guards_tree.log`). On 3615cfb's own tree the revision's guard file fails at
  `test_every_url_redaction_consumer_runs_its_floor_first`'s assertion (3615cfb's
  `LAYERED` names one text parameter per consumer: `stored_value`'s `value` of three,
  `redact_for_record`'s `value` of two; `r6c/floor_plain_t3615cfb.log`).
- **R3 -- family (d): what the proxy history writer stores where the floor raises**
  (owner PROXY, CC-PROXY-0031 "r6 review"; pinned, not fixed: 7393c90 stores the same).
  *Finding:* `_prepare_contained` stores a flow whose redaction raised with every body
  `OMIT_FAILED` and its URL cut at the first `?` (`rec.url.split('?', 1)[0]`), in
  `flow.url` and its `errors` line, so what precedes that `?` is stored as received:
  `http://[h/app;jsessionid=<hex>/p.php?u=1` keeps the session id on 3615cfb and on
  7393c90, where 144d234's walk (which never raised) stored `;jsessionid=__REDACTED__`.
  CC-PROXY-0031 r6 said such a flow is stored "never unredacted" and FR-PROXY-11 r6 that
  its URL is cut at the `?`, without what that keeps; the writer's docstring (7393c90's)
  said "never stored unredacted". *Cause:* the r6 differential counted any raise as
  redacted (the owner's criterion counts 7393c90's raise or withhold so) and never
  measured what the raising consumer's caller then stores; the records took the
  docstring's word for it. *Measured* (`r6c/fam_d.py` over the four corpora, 406 005
  URLs; `famd_compare.txt`, `famd_classify.txt`): the writer falls back on the same
  15 190 URLs on r6 and 7393c90 and on none on 144d234; it stores a secret in 651 of them
  on both (the r6b check's corpus; 225 in a `;` path parameter, 411 in a path segment,
  15 in a fragment written before the `?`), 0 at r6 that 7393c90 redacted; **144d234
  delta: 183 URLs** (171 path parameter, 12 fragment; the 411 path segments 144d234 kept
  too, as the proxy's name redactor reads no path segment on any tree). *Pin:*
  `tests/test_redaction_residual_pins.py::test_proxy_history_stores_no_path_parameter_of_a_flow_its_floor_rejects`
  (strict, `raises=AssertionError`, owner PROXY, 4 cases: xfail on the revision, on
  3615cfb and on 7393c90, XPASS on 144d234); candidate rule, not built: the fallback
  cuts the URL at its first `;`, `?` or `#`. The records (CC-PROXY-0031, FR-PROXY-11,
  FR-CORE-537, the writer's docstring) now say what is stored.
- **R4 -- a record claimed an unreachable branch** (owner AUD, CC-AUD-0059 "r6 review").
  *Finding:* FR-AUD-31 r6, CC-AUD-0059 r6 and 3615cfb's commit message said a text whose
  *page* URL the floor rejects is stored `AUDIT_TEXT_WITHHELD` and the import goes on;
  `_main_origin` / `_audit_endpoint` raised first, so `_audit_text`'s page-URL branch was
  unreachable through `import_audit`, untested, and the same records' next sentence
  contradicted the claim. *Cause:* the claim was written from `_audit_text`'s code, not
  from a test through its only caller (r6's test drove a rejected target on a good page
  only). *Fix:* with D1's fix the import is total: a page `urlsplit` rejects as written
  (`http://[h/…`, `//[h/…`, where `to_path` rejects it too and 7393c90's import raised)
  gets no endpoint (`_audit_endpoint` returns `None`; `parameter_id` NULL), and its
  target and context are `AUDIT_TEXT_WITHHELD`; the branch is reached and tested, and
  FR-AUD-31 says exactly this. *Test:*
  `tests/test_redaction_nested.py::test_r6_review_r4_import_audit_withholds_the_texts_of_a_page_its_floor_rejects`
  (2 cases): fail on 3615cfb at "the import failed: ValueError('Invalid IPv6 URL')", pass
  on the revision; on 7393c90 they fail at the same assertion (its `to_path` raised).
- **R5 -- r6's recurrence review was incomplete** (records only). *Finding:* it did not
  mention PA-0549(3c), though r6 pins 16 cases the batch's own unpushed 144d234 redacted
  (what 3c forbids on its face: "a defect a sweep finds in an unpushed change of the same
  batch is fixed in that batch, never pinned"); it did not name F-226, of whose class the
  r6 brief's extra bar was a recurrence; its corrective action named only CC-AUD-0059.
  *Cause:* the review was written for the design change (items 8-10 to item 11) and
  checked against PA-0556 only, not against every rule the round's pins touch. *Fix:*
  the completed review below; the pins' shared reason (`_ON_7393_R6`) and PA-0556(11)'s
  header (the lane's doc texts) state the reconciliation.

**Proofs** (plain runner, `scratchpad/lanes/REDACTURL/r6c/`): the 8 D1 and R4 cases fail
on 3615cfb and on 144d234 at "the import failed" and pass on the revision
(`r6review_tests_plain_{t3615cfb,t144d234,wt}.log`); family (d)'s 4 pin cases xfail on the
revision, 3615cfb and 7393c90 and XPASS on 144d234 (`pins_famd_plain_*.log`); the guard
proofs are in `proof_guards_offenders.log` and `proof_guards_tree.log`. After the last
change the whole of `tests/test_redaction_nested.py` passes (`nested_wt.log`: 629 ok),
the pins file holds (`pins_wt.log`: 105 strict xfails, none passing) and the floor's
guards pass (`floor_wt.log`: 6 ok).

**The r6 recurrence review, completed (R5).**
- *PA-0549(3c).* r6 pins 16 cases (and this review 4 more, family (d)) that the
  unpushed 144d234 redacted. PA-0549(3c) says a defect a sweep finds in an unpushed change
  of the same batch is fixed in that batch, never pinned. Its owner's reading -- the rule
  the owner gave for this batch (nothing the pushed 7393c90 redacted may leak; a
  regression against it is fixed in the batch; anything it also leaks is pinned) and
  F-226's correction (the owner's rule and PA-0549(3c) concern what a batch makes worse
  than what ships: the pushed tree) -- is that 3c's "defect" is a regression against the
  pushed tree. A leak 7393c90 has too is not one, whichever unpushed revision redacted it
  in between: the pins are within 3c so read, and each states it (`_ON_7393_R6`: "not a
  regression against the pushed tree, so pinned, not fixed in the batch -- PA-0549(3c)
  concerns regressions against the pushed tree (the owner's rule; F-226)").
  PA-0556(11)'s header now says it narrows PA-0549(3c) to that reading.
- *F-226.* F-226 recorded that briefing REDACTURL's follow-ups against an unpushed
  revision (f939778) made them chase intermediate states; its correction settled the lane
  against 7393c90 in one workflow (`wf_9a1e5879-609`). The r6 brief set an unpushed
  revision as a bar again ("0 leaks against 144d234"; F-248 in the stack, the doc texts'
  "The r6 brief added a bar the owner had not set"), and the lane blocked on it.
  **Why F-226's correction did not hold:** it corrected one brief, not the rule the
  briefs are written from. PA-0549(3c)'s text still says "an unpushed change of the same
  batch", which the r6 brief applied literally, and no rule says the regression bar is
  the pushed tree only (PA-0556(10) requires a differential against the pushed tree but
  does not forbid a second bar against an unpushed revision). PA-0556(11)'s header now
  narrows 3c in the rule's own text, so the next brief written from it reads the pushed
  tree; a brief's bar is not code, so no test enforces it (its Enforced-by line names
  the layering's tests).
- *Corrective action of r6, complete.* CC-CORE-0076 (the floor, `core/redaction_floor.py`,
  and every core consumer layered on it), CC-PROXY-0031 (the proxy's `redact` layered on
  the frozen pushed `redact`), CC-AUD-0059 (`import_audit` withholding a text the floor
  rejects), each in its "r6" sub-bullet, in commit
  3615cfb1bba77480371657873e09cb6139080729; PA-0556 item 11. This review: the same three
  entries' "r6 review" sub-bullets (D1 and R4: CC-AUD-0059; R1, R2 and R5: CC-CORE-0076;
  R3: CC-PROXY-0031), one commit on `lane/REDACTURL-r6` after 3615cfb, and PA-0556(11)
  amended (header and text, Enforced-by gaining the D1 and R4 tests).

**Recurrence review of this round.** D1 is the class r6 itself fixed for the target
identifier (A1): a URL step the batch added to a caller raises where the pushed tree's
caller did not, and so is R4's unreachable branch; both were missed because r6's A1
sweep of `import_audit` was read, not measured (PA-0556(4), followed for the target and
not for the page). R1 and R2 followed PA-0034(2) (each guard was proven on synthetic
offenders malformed the way it claims to catch) and recur PA-0556(9)'s class one layer
over: a guard's offenders, like a differential's inputs, were the shapes its author
chose rather than derived from the mechanism (every way Python binds a name or refers to
a function, every part of a definition). R3
is A1's caller side: a raise counted as redacted without measuring what the raising
consumer's caller stores. **Prior-preventive-action failure analysis:** PA-0556(4)
("a sweep of an owner's callers is measured, not read") was not followed for
`import_audit`'s page step (not enforced: its Enforced-by tests drive the target only);
PA-0556(11) required the floor's guards but not that their model cover every binding and
reference, nor that a raise's caller fallback be measured. PA-0556(11) is amended (the
lane's doc texts): a layered consumer's guards model every binding and every reference
the language allows, state what they cannot see, and are proven on offenders of each
kind; where the floor raises, each caller's fallback is measured for what it stores,
never counted as redacted; and the round's sweep drives every URL a caller the batch
changed reads (each `import_audit` text and page) through that caller. Enforced by the
guard tests above and the D1 and R4 tests.

## At the merge (coordinator's records round, owner-approved)

The fix check of 08eb900 (`scratchpad/r6c_checks.txt`, one check per r6-review finding)
closed D1 and R1 and left R2, R3, R4 and R5 open, none a regression against 7393c90 but
one (D1(b), below). The owner decided: merge now (5e80ea2, the merge of
`lane/REDACTURL-r6` 08eb900 into the stack); correct every record that claims too much;
pin by a strict xfail (`raises=AssertionError`) what the pushed tree 7393c90 also leaks
or also fails; state the guards' limits; add **no** new guard rule; fix only a
regression against 7393c90. This round did exactly that, in the merge worktree. Every
proof below is plain Python (pytest imported only as a library), on the merge tree and
on git-archive exports of 7393c90 and 08eb900 (the worktree's tests run against each
export's `fuzzlab`); scripts and logs are in `scratchpad/merge-r6/` (`scripts/`,
`logs/`), the exports removed afterwards.

- **R3(a) -- records that said a caller withholds what the floor rejects.** Corrected
  to what is stored: `proxy.redact.redact`'s docstring (the history writer does not
  withhold the flow: every body `OMIT_FAILED` and the flow's own URL cut at its first
  `?`, what precedes it as received, also when only a header value raised);
  `core.redaction.redact_url`'s and `redact_url_identifiers`' docstrings (each caller
  does what it did on 7393c90, not always to withhold; the floor raises only on a URL
  holding a `?`); `core.trace.safe_ref`'s ("the floor withholds a URL `urlsplit`
  rejects" -- only one holding a `?`; one without is redacted, not withheld, as on
  7393c90: measured on both trees); `tests/test_redaction_nested.py`'s A1 docstring and
  two comments that said "every caller withholds"; and the test
  `test_r6_a1_proxy_history_withholds_a_flow_whose_url_its_floor_rejects`, which asserts
  that the flow is stored, its bodies `OMIT_FAILED` and the query's secret cut, is
  renamed `test_r6_a1_proxy_history_stores_a_flow_its_floor_rejects_bodies_omitted_query_cut`
  (CC-PROXY-0031's r6 sub-bullet keeps the old name: it is history). The floor's head
  docstring (`core/redaction_floor.py`, lines 15-22) made the same claim; it is **the
  lane's own text, not 7393c90's** (the module is new: `git show
  7393c90:fuzzlab/core/redaction_floor.py` fails), so it is corrected and its pinned
  digest `HEAD_SHA` in `tests/test_redaction_floor.py` retaken (`ae2642a9…` ->
  `e73c8f97…`, the old digest reproduced first from 08eb900's file by guard 1's own
  head reading, `scripts/head_sha.py`); no frozen definition changed (`FROZEN` as it
  was), and guard 1 passes.
- **R3(b) -- the header-triggered family (d) case, pinned.**
  `tests/test_redaction_residual_pins.py::test_proxy_history_stores_no_path_parameter_of_a_flow_a_header_value_makes_it_fall_back`
  (owner PROXY, 4 cases: a `Location`, a `Refresh` `url=` and a `Content-Location`
  value `http://[h/x?y=1` on a flow whose own URL parses -- `;jsessionid=<hex>` in a
  middle segment, `;sid=<word>` in the last, a fragment `#a=1;password=<word>` before
  the `?`). *Measured first* (`logs/famd_header.log`): on the merge, on 7393c90 and on
  08eb900 each such flow makes the writer fall back and stores
  `http://h/app;jsessionid=<hex>/p.php` in `flow.url` and the `errors` line; the same
  flow without that header is redacted on the merge and on 08eb900 (7393c90 keeps a
  path parameter anyway); a quoted `Refresh: 0; URL='http://[h/x?y=1'` and a `?`-less
  `Location: http://[h/x` make no floor raise; the `observe.exchange` trace event of
  these flows (one each) held no secret (`logs/famd_header_trace_rows.log`). Each case fails at its own leak assertion on the
  merge, on 7393c90 and on 08eb900 (`logs/pin_famd_header.log`), and passes, with the
  four r6-review family (d) cases, on a scratch copy cutting the fallback URL at its
  first `;`, `?` or `#` (`logs/pins_satisfiable_candidate_rules.log`: 8 strict XPASS).
  The reason cites the fix check's corpus measurement, not re-run here: 67 371
  fallbacks, 14 082 storing a secret (on 7393c90 too), 3 517 of them redacted by
  144d234; the trace event kept a secret in 1 055 (45 redacted by 144d234).
  FR-PROXY-11 and FR-CORE-537 name the case and the pin, in place.
- **R4 -- `import_audit` is not total.** The r6 review's records (FR-AUD-31,
  CC-AUD-0059 "r6 review", the `import_audit` / `_audit_endpoint` / `_audit_text`
  docstrings, this document's R4 "Fix") said the import never fails on a finding's URL.
  Measured (`logs/import_audit_probe_before.log`, `import_audit_probe_nq_frames.log`):
  a page `urlsplit` rejects **with** a `?` is imported with its texts withheld; one
  **without** a `?` -- `http://[h/app/p.php`, `//[h/app/p.php`, `http://x＃y/app/p.php`,
  `//user:pw@x[y/app/p.php`, `http://[h]/app/p.php`, `http://h]/app/p.php`, a fragment
  or a `;` parameter instead of a query -- still fails the whole import, every other
  finding with it, at `_audit_text`'s `parts = urlparse(page_url)`
  (`fuzzlab/tools/store_adapter.py:1204` on the merge), because the floor returns a URL
  without a `?` unread and the withhold branch is never reached; 7393c90 fails all
  nine at `core/urls.py:18` (`to_path`). The 888-URL supplement through the check's own
  import runner on the merge tree, against its 7393c90 outputs
  (`logs/imp888_merge_vs_7393.txt`): 0 regressed and 0 new failures for every
  consumer; of the 54 pages 7393c90's audit import raised on, the 27 holding a `?` are
  imported with no canary stored and the 27 without one (every one) fail on both trees.
  So the r6 review's *Measured* line above ("the findings on a page 7393c90's import
  raised on (3 463 and 27 …) are imported") counted only the pages that import: 27 of
  the 888 still fail (the lane's own `r6c/imp_extra/imp_new_0.jsonl` recorded them
  `F:ValueError`, and its compare filed them under "neither"); the 70 000-URL corpus
  holds no URL without a `?`. Records corrected in place to say exactly this (FR-AUD-31;
  the three docstrings and `AUDIT_TEXT_WITHHELD`'s comment; FR-CORE-537's caller
  sentence) and that a page no origin is read from is stored by its path as 7393c90's
  `to_path` stored it, so it can keep a userinfo or a JWT segment, as on 7393c90
  (`\u3000http://u:<pw>@[h/app/p.php` -> `/\u3000http://u:<pw>@[h/app/p.php`, measured
  on both trees). Pinned (owner AUD; candidate rule, not built: catch that
  `ValueError` and withhold the texts):
  `tests/test_redaction_residual_pins.py::test_import_audit_imports_a_finding_page_urlsplit_rejects_without_a_query`
  (5 cases, the four pages above and `http://[h/app;jsessionid=<hex>/p.php`), each
  failing at its own first assertion ("the import failed: ValueError(…)") on the merge,
  on 7393c90 and on 08eb900, and passing with the candidate rule on a scratch copy.
- **D1(b) -- a regression of the batch, fixed.** A finding page stored as a BLOB with
  an empty path (`b"http://h"`, `b"x://"`, `b"http://h?u=bob"`): 7393c90's `to_path`
  read `urlparse(b"…").path == b""` as `/` and imported it; the batch's import (3615cfb,
  08eb900) raised `TypeError` in `canonical_origin` (`_readable_origin` and
  `_audit_endpoint` caught `ValueError` only) and stored nothing. A BLOB with a path
  (`b"http://h/app/p.php"`) or one `urlsplit` rejects fails on 7393c90 too
  (`TypeError` / `ValueError` in `to_path`). Unreachable from the auditor
  (`fetcher.log_finding` writes the crawler's str URL), reachable from any other writer
  of a findings DB. *Fix* (`fuzzlab/tools/store_adapter.py`): `_readable_origin` also
  catches `TypeError` (`None`: the page names no origin), and `_audit_endpoint` reads a
  BLOB page by `to_path` exactly as 7393c90 did, nothing it raises caught. A first
  draft caught `TypeError` beside `ValueError` in the existing branch, which
  withholds a page `to_path` rejects: the differential below found it importing 50
  BLOB pages 7393c90 failed on (`b"http://[h…"`) with their texts unjudged -- a leak
  under the owner's rule, a 7393c90 failure counting as redacted -- and it was replaced
  before anything was reported. *Proof:* a str/BLOB differential of 225 generated
  pages (9 heads x 5 paths x 5 tails, a canary in the page and the context;
  `scripts/blob_diff.py`, `logs/blob_compare2.txt`): every BLOB row identical to
  7393c90's (outcome, exception type, endpoints, canaries stored: 225 of 225) and every
  str row identical to 08eb900's (225 of 225). *Test:*
  `tests/test_redaction_nested.py::test_merge_d1b_import_audit_imports_a_blob_page_with_no_path_as_the_pushed_tree_did`
  (3 cases) fails on 08eb900 at its own assertion ("the import failed:
  TypeError(\"a bytes-like object is required, not 'str'\")") and passes on the merge
  and on 7393c90 (`logs/d1b_and_r6review_tests.log`). What 7393c90 also fails or leaks
  is pinned (owner AUD; candidate rule: decode a BLOB page before reading it, or
  withhold its texts):
  `tests/test_redaction_residual_pins.py::test_import_audit_imports_a_blob_finding_page_and_judges_its_texts`
  (3 cases: a BLOB with a path, fails the import; `b"http://h?token=<word>"`, imported
  with a context quoting the token stored, its texts never judged against a BLOB page),
  failing at its own assertions on the merge and on 7393c90.
- **R1 and R2 -- the guards' limits, stated** (no guard rule added, the owner's
  decision). The guards in `tests/test_redaction_floor.py` are lexical: they read the
  source text, not what Python binds at run time. They do not see a same-name
  rebinding in another scope (a function-local import or assignment shadowing an
  alias: guard 3 keeps one name map per file); a local or module-level rebinding of a
  trusted predicate's name (`WALK_PREDICATES`' `value_holds_secret`,
  `is_sensitive_name`, `isinstance`: guard 2 trusts the call by its name); a star
  import of the floor or the owner; a keyword-only text parameter (guard 2 reads
  positional parameters only); literal-name reflection (`__dict__`,
  `operator.attrgetter`); a shadow package replacing the floor module (guard 1 hashes
  the file, and a package of the same name takes precedence on import); and names
  computed at run time. Each is shown on the merge tree's own guard functions
  (`logs/guard_limits_wt.log`: each control flagged, each limit not) and the shadow
  package on a scratch copy (`logs/guard_limit_shadow_package.log`: the six guard
  tests pass while `fuzzlab.core.redaction_floor` imports from the package and its
  `redact_url` returns `token=SEKRETzq1` unredacted). The records that claimed more
  are corrected in place: the guard module's docstring ("every one" of the text
  parameters is every positional one; the stated limits listed),
  `frozen_problems`', `layering_problems`' and `unregistered_uses`' docstrings,
  `NOT_TEXT`'s comment and FR-CORE-537. The r6 review's R2 *Stated limit* above (a name
  computed at run time only) was incomplete; PA-0556(11)'s "state what they cannot see
  (a name computed at run time)" is the orchestrator's text (handed over).

**Correction of the r6 review's "Why F-226's correction did not hold"** (that paragraph
stands as written; this one corrects it). It said that "no rule says the regression bar
is the pushed tree only (PA-0556(10) requires a differential against the pushed tree but
does not forbid a second bar against an unpushed revision)". That was inaccurate:
**PA-0556(8) set the second bar.** Item 8 diffs the changed owner's output "against the
pre-fix revision's" and calls "a case clean before and kept after … a regression of the
batch, fixed in it (PA-0549(3c))"; r6's pre-fix revision was the unpushed 144d234, and
the r6 brief's "N(leak at r6, redacted at 144d234) -- must be 0" (which the r6 review
quoted as "0 leaks against 144d234") was item 8 applied as written, beside item 10's
bar against 7393c90; the brief never cited PA-0549. Item 10 added the pushed tree as a
baseline without retiring item 8's, item 11 kept "the differential of items 8-10"
running, and the r6 review's own fix -- narrowing PA-0549(3c) in item 11's header --
left item 8's "fixed in it" in force, so it would not have prevented the next brief from
setting the bar again (the next pre-fix revision, 08eb900, is unpushed too). F-226's
correction did not hold because it corrected one brief while the rule the briefs are
written from, item 8, still named an unpushed revision as a bar. At the merge the
orchestrator amends PA-0556(8) in place: the regression bar is the pushed tree; a case a
pre-fix revision of the batch redacted and the change keeps is information, reported
with its family, never a bar (what the pushed tree also keeps is pinned, item 11).

**Recurrence note.** This round's findings recur the r6 review's own classes one level
up, in the records: a claim written from the code read or from the change's intent
("the import is total", "every caller withholds", "every use", "every text parameter")
instead of from a measurement over the inputs that reach it -- R4's 27 pages were in the
check's own supplement and in the lane's own output, filed under "neither"; the
withholding claim was measured for the flow's own URL, not for a header that makes the
same writer fall back; and a lexical guard was described in the language's terms
("every binding", "every reference") rather than its own. PA-0556(4) (a sweep is
measured, not read) and PA-0556(11) (a raise's fallback is measured for what it stores;
the guards state what they cannot see) applied; each was followed for the case in hand
and not for its neighbours, and the measurement that would have caught R4 existed and was
misfiled. No new rule (the owner's decision): the records now say what is measured, the
guards' limits are stated, and what 7393c90 also leaks or fails is pinned; PA-0556(8)
is amended (above), by the orchestrator.

**Files changed at the merge by this round:** `fuzzlab/proxy/redact.py`,
`fuzzlab/core/redaction.py`, `fuzzlab/core/redaction_floor.py` (head docstring only),
`fuzzlab/core/trace.py` (docstring only), `fuzzlab/tools/store_adapter.py` (D1(b)'s
two `except` clauses; docstrings), `tests/test_redaction_floor.py` (`HEAD_SHA`;
docstrings), `tests/test_redaction_nested.py` (the rename, D1(b)'s test, the
`_import_audit_or_failure` helper also catching `TypeError`; docstrings),
`tests/test_redaction_residual_pins.py` (three pins), FR-CORE-537, FR-AUD-31,
FR-PROXY-11 (in place), CC-CORE-0076, CC-PROXY-0031, CC-AUD-0059 (appended
sub-bullets), and this section.

## After the push: the merge's independent check (coordinator, 2026-10-22)

- **Behaviour** (the checker's own corpora, 70 000 + 888 URLs, every consumer and import,
  plus 973 `import_audit` cases as str and BLOB, against 7393c90): 0 leaks the pushed tree
  redacted and 0 failures where it succeeded, counting a crashed 7393c90 import as
  redacted, except one class: a finding page `urlsplit` rejects that holds a `?`. 7393c90
  raised on it and stored nothing; 1ad0fd0 imports the DB.
  - **P2, fixed:** `_audit_text` returned any non-string before the rejected page's
    withhold, so a BLOB `html_context` was stored verbatim. Now every non-NULL text of a
    page the floor rejects is withheld, whatever its type.
    Test: `tests/test_redaction_nested.py::test_merge_p2_a_blob_text_of_a_page_its_floor_rejects_is_withheld`
    (fails on 1ad0fd0 at its own assertion; passes now). CC-AUD-0059.
  - **P1 and P3, stated, not changed:** the other findings of that DB and a finding's
    rule metadata are stored as both trees store them in a run without such a page;
    neither tree redacts them, and 7393c90 kept them out only by failing the whole import.
    Failing the import again would undo D1. FR-AUD-31.
- **Records:** ten claims in 1ad0fd0 were not true of the code, each corrected:
  the r6 and r6-review CHANGELOG lines (the floor raises only on a rejected URL holding a
  `?`; proxy history stores the URL cut at its first `?`; a page without a `?` still
  fails the import; the guards see positional parameters only, and two limits were
  missing); FR-CORE-537's totality and `import_audit` sentences; FR-PROXY-11 and the
  ARCHITECTURE redaction text (proxy history runs the floor's `redact` and then the walk,
  not `redact_url` per value); ARCHITECTURE's userinfo claim (the pinned N1(A) and N2
  spellings); PA-0556(11) ("every way" -> "the lexical ways"); the r6 ERROR_LOG symptom;
  `core.trace.safe_ref`'s docstring (sensitive values are replaced, not blanked; the
  frozen floor's copy of 7393c90's docstring is left as it is); and the BLOB pin's
  missing case (`b"http://[h/x"` fails the import on both trees; it is now the pin's
  fourth case, failing at its own assertion on the merge tree and on 7393c90).
- **Recurrence:** the same failure as F-276, in the merge's own texts (F-279): a claim
  copied from a lane's text or written from the case at hand, not measured over the
  inputs it covers. PA-0556(11)'s last sentence already requires the measurement; the
  correction is to run a records-truth check before the push, as this one ran after it.
