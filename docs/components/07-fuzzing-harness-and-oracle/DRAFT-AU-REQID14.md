# DRAFT AU-REQID14: every sender places a query value at one exact occurrence

- Item: `AU-REQID14`, audit defect 14 only. Owner-supplied audit at 6552276, F-096. Split
  from AU-REQID, and accepted by the coordinator on 2026-10-19.
- Status: **draft for the pre-change review gate** (`docs/components/README.md`). Nothing
  here is implemented.
- Base: `8100959`. Branch `worktree-agent-aef1371774d69f3f5`.
- Numbers: CC-FUZZ-0106, CC-CORE-0068, BUG-0531 / PA-0531, and FR-FUZZ-64 (the
  placement parts only).
  - Not used here: BUG-0530, PA-0530, CC-AUD-0056, FR-AUD-31 and SP-57 stay reserved
    for AU-REQID8.
  - The CORE requirement is FR-CORE-501, amended in place (Q2).
- Merge order: AU-OUTCOME merges first, because it also edits `oracle/oracle.py` (a
  comparability wrapper). Its result is merged into this branch before the final verify.
  This item's `oracle.py` change is one line inside `_FormBoundSender.send` (§3.4).
- Parked: defect 8 (the request-context identity) is in `DRAFT-AU-REQID8.md`. POST-action
  query points are a separate later item.

## 0. Summary

Each sender builds the query of a probe its own way:

- the anonymous senders append a second pair;
- the authenticated seam rebuilds the query through a `dict`, which loses duplicate
  siblings and rewrites untouched pairs;
- the oracle's binder replaces every occurrence of the name;
- the M6 browser appends.

The same point therefore sends a different request, depending on the sender. And the
conformance check that is meant to keep the senders in step cannot see a query: it reads
it as a `dict`, and its probe URL has none.

The fix:

- **One ordered query-entry representation and one placement function** in `core/urls.py`,
  as SP-42's extension beside `place_path_param`.
- Every sender, the binder and the M6 executor place through it.
- A conformance check that reads the raw request.
- An AST guard that keeps new query builders out.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

The measurement test file is committed: `tests/test_query_placement.py`. Each sender
sends to a loopback echo server started in the test (`require_loopback`), which records
the raw request target.

On `8100959`, with `--runxfail`: **30 failed, 6 passed**. With the strict-xfail pins in
place: 6 passed, 30 xfailed. The harness run on the committed tree gave 64 files, 2540
passed, 0 failed, 1 skipped (`test_packaging`'s Debian setuptools bug, unrelated) and 49
xfailed. That count included the parked defect-8 file.

### 1.1 What each sender put on the wire

`M` is the payload. The point is a standalone GET query point, so the first occurrence is
the addressed one.

| Query before / param | Contract | `RequestsProbeSender`, greybox `RequestsCorrelatingSender`, blind-sqli `RequestsSender` | `SeamProbeSender` (anonymous, and with an identity), blind-sqli `SeamSender` |
|---|---|---|---|
| `id=1&tag=a&tag=b` / id (the audit's case) | `id=M&tag=a&tag=b` | `id=1&tag=a&tag=b&id=M` | `id=M&tag=b` |
| `tag=a&id=1&tag=b` / tag | `tag=M&id=1&tag=b` | `…&tag=M` appended | `tag=M&id=1` |
| `a=%7E&flag&id=1&b=x+y` / id | `a=%7E&flag&id=M&b=x+y` | `a=~&flag&id=1&b=x+y&id=M` | `a=~&flag=&id=M&b=x+y` |
| `id=&x=1` / id (a blank value) | `id=M&x=1` | `id=&x=1&id=M` | `id=M&x=1` (holds) |
| `a%5B%5D=1&a%5B%5D=2` / `a[]` (an encoded name) | `a%5B%5D=M&a%5B%5D=2` | `…&a%5B%5D=M` appended | `a%5B%5D=M` |

27 of these 30 sender × case combinations fail. The three seam-family blank-value cases
hold.

- `test_the_anonymous_and_authenticated_senders_send_the_same_query` fails.
- **Bound path.** `oracle._FormBoundSender` uses `FormEntries.replace`
  (`core/forms.py:92`), which replaces every entry named `tag`. Entries
  `id=1&tag=a&tag=b`, point `tag`: the wire carried `id=1&tag=M&tag=M`.
- **M6, real Chromium.** `browserexec._with_query` (`:25-29`) appends: the wire carried
  `id=1&tag=a&tag=b&id=M`.
- **The seam with an identity** was measured through a real `HttpClient` and its real
  `requests` transport, with a session addon that applies nothing. A real
  `SessionManager` needs keyring credentials. Every session route of `SeamProbeSender`
  (main, isolated copy, anonymous) builds its URL in the same `_send_on` (`:774-824`).
- **The existing check is blind.** `tests/test_sender_conformance.py::_Wire` turns the
  query into a `dict`, and its probe URL is `http://h/a.php`, with no query. It cannot
  carry an occurrence, a duplicate or order (cf. PA-0311(2)).

### 1.2 The clients' own rewriting: the platform fact the contract rests on

Pinned by `test_platform_clients_rewrite_only_escapes_without_query_meaning`, a
real-process and real-Chromium test. It fails rather than skips under
`FUZZLAB_REQUIRE_BROWSER=1`. Measured 2026-10-19 with requests 2.34.2 and Chromium 1194,
sending a verbatim query.

- **requests** decodes escapes of unreserved characters (`%7E` → `~`), upper-cases other
  hex (`%2b` → `%2B`), escapes raw `|{}<>` and non-ASCII, and keeps raw `'`.
- **Chromium** keeps every escape as given, escapes raw `'`, `<>` and non-ASCII, and keeps
  raw `|{}`.
- **Neither client** changes a pair boundary, an `=` (`flag` stays `flag`), an empty part
  (`&&`, a trailing `&`), `+` vs `%20`, or an escape of `& = + % #`.

So byte equality is impossible across clients, but this relation holds through both:
pairs in order, `=` presence, and every escape decoded except those of `& = + % #`. It is
`canonical_pairs` in the test file. `test_the_equivalence_still_tells_apart_what_a_server_reads_apart`
proves it is not vacuous: a duplicate, a lost sibling, `flag` vs `flag=`, `+` vs `%2B`,
`&` vs `%26` and order all differ under it (PA-0034(2)).

### 1.3 Effect on tests and the oracle budget

**None in count.** Placement changes what a probe carries, never how many probes or tests
a run makes. No point builder or key changes; that is defect 8.

**On scored ground truth: no change on the wire.** No committed `lab/ground-truth*`
point URL carries a query: 0 of 178, measured with the real `points_from_ground_truth`.
Every ground-truth query point is a query-less URL, so the payload is appended exactly as
today, through the same encoder (`quote_plus`, what `urlencode` does).

**Crawl runs change on the wire in three cases:**
- a point whose URL keeps a query: a header point's representative query, unchanged in
  bytes; a POST action's query on a body point, unchanged because only body entries are
  placed;
- a link set with a repeated name: the first occurrence only (§3.4 and Q1);
- the M6 observe URL of a query point with a query.

## 2. Root cause (Five Whys)

1. **Why did a first-value server never see the anonymous payload?** `requests` appended a
   second `id` (`params=`).
2. **Why did the authenticated path lose `tag=a`?** `tools/authhttp.with_query_param`
   rebuilds the query through `dict(parse_qsl(...))`.
3. **Why do the two differ?** Each sender, and greybox, blind-sqli and the M6 executor,
   builds the query itself. Nothing owns "place a value in a query"; SP-42 owns only the
   path segment.
4. **Why did PA-0115's conformance check not catch it?** It checks placement per
   *location*, not per occurrence. Its wire collapses the query into a `dict`, and its
   probe URL has no query.
5. **Root cause.** Query placement is not a shared primitive. The check meant to keep the
   senders in step observes through a channel that cannot carry the violation.

## 3. Design

### 3.1 The owner: `core/urls.py`, SP-42 extended (CC-CORE-0068)

**`QueryEntries`** is the ordered query-entry representation. It is an immutable sequence
of parts, each `(name, value, raw)`:
- `name` and `value` are form-decoded, as a server reads them (`unquote_plus`);
- `raw` is the part's text exactly as given, or `None` for a part built or replaced here;
- `QueryEntries.parse(raw_query)` splits on `&` only, as both measured clients and the
  common parsers do. It keeps every part's raw text, order, duplicates, empty parts and
  `=` presence.
- `.replace_at(name, occurrence, value)` replaces exactly the `occurrence`-th part whose
  decoded name is `name`, in place. That part's raw name text is kept and the value is
  encoded by the one encoder.
  - Absent name and `occurrence == 0`: one `name=value` part is appended.
  - Absent `occurrence > 0`: `QueryPlacementError`, a sibling of `PathPlacementError`.
    Senders map it to `UnplaceableLocation`: refuse, never relocate (PA-0115).
- `.to_query()` emits each untouched part's raw text, and encodes the rest.

**The functions:**
- **`encode_query_pair(name, value)`** is the one encoder: `quote_plus(…, safe="")`, what
  `urlencode` does today. A query-less URL's wire bytes are therefore unchanged.
- **`place_query_param(url, name, value, occurrence=0) -> str`** returns the URL with its
  own query parsed, that occurrence placed, and everything else (fragment included)
  verbatim.
- **`place_route_query_param(url, name, value) -> str`** does the same inside an SPA hash
  route's query (`/#/route?…`). It keeps that route's existing `%20` encoding
  (`quote_via=quote`), which is what `_with_fragment` and its pinned test do today.
- **`with_query(url, entries) -> str`** is moved from `tools/authhttp.py`, and keeps its
  behaviour: the URL's query becomes `entries`. A plain list of 2-tuples (a form's or a
  stored link set's entries) is encoded with `urlencode`, as a browser serialises a form
  (PA-0111).

`core/forms.FormEntries` gains **`replace_at(name, occurrence, value)`**: the same
occurrence rule over a form's entries, for bodies and bound queries. `replace` (every
occurrence) stays for one caller only, `formnav.enumerate_form` (a selector option, a
crawler-side browser submission).

`tools/authhttp.with_query_param` and `with_query` are removed. `with_query` is defined
once, in the owner (`test_shared_primitives::test_every_owner_is_defined_once`).

### 3.2 The placement contract (FR-FUZZ-64(3))

**A query payload goes to the addressed occurrence of its name, in place.**
- Every other pair keeps its position, its `=` (or the absence of one) and its raw text,
  up to the client rewriting measured in §1.2.
- The payload is encoded by the one encoder.

**Missing occurrences:**
- A missing occurrence 0 is appended once.
- A missing occurrence above 0 is refused.

**Rules for every sender:**
- No sender adds a second pair for a name the query already has. That would be a
  deliberate duplicate-parameter probe. **None exists in fuzzlab today.** If one is added,
  it is its own mechanism with its own point field, never the default placement.
- Bodies (form-urlencoded) follow the same occurrence rule over the form's entries,
  serialised as the browser does.

**The addressed occurrence is 0 for every point until AU-REQID8** makes the occurrence
part of a point. The owner supports any occurrence now, and its tests cover it.

### 3.3 Every sender through the owner (CC-FUZZ-0106)

| Sender @8100959 | Change |
|---|---|
| `tools/probesender.RequestsProbeSender.send` | standalone query: `url = place_query_param(url, param, value)` and no `params=` (`:964`); bound: `core.urls.with_query` (`:946`) |
| `tools/probesender.SeamProbeSender._send_on` (every session route) | standalone: `place_query_param` (`:822`); bound: `core.urls.with_query` (`:793`) |
| `greybox/run.RequestsCorrelatingSender.send_correlated` | standalone: `place_query_param` (`:196`); bound query: `with_query`, never `params=list(entries)` (`:192`), which appends to a URL's own query |
| `tools/blind_sqli_fuzzer.RequestsSender.get` / `SeamSender.get` | `place_query_param` (`:58`, `:82`) |
| `tools/browserexec` (M6) | `_with_query` (`:25-29`) → `place_query_param`, for the observe navigation (`:552`) and the GET store step (`:539`); `_with_fragment` (`:32-48`) → `place_route_query_param` |
| `harness/pipeline._baseline` (`:107`) | `FormEntries.replace_at(point.param, 0, "1")` |
| `harness/auto.header_points_from_store` (`:510`) | `with_query(page_url, …)`, never `"?" + urlencode(...)`. The bytes are unchanged; it is a query builder outside the owner, so it moves (guard, §3.6) |

### 3.4 The binder: `oracle/oracle.py`, kept minimal for the merge with AU-OUTCOME

The whole `oracle.py` change is one line in `_FormBoundSender.send` (`:153`):
- `entries = self._base.replace(param, value)` becomes
  `entries = self._base.replace_at(param, 0, value)`.
- It passes the occurrence-addressed entries to the senders, which place them through
  `with_query` or the form body.
- The name and the signature are kept. The cross-account strategy constructs it too
  (`strategies.py:1750`), and that file is not edited. Its peer replays get the same
  placement.
- No `Candidate` field is added: the occurrence is 0 until AU-REQID8 supplies it.

### 3.5 The M6 browser: what the coordinator's instruction allows, flagged

The coordinator's instruction was: no oracle-side executor wrapper, the executor's own
placement fixed through the owner, the binder passing the occurrence and entries, and
`strategies.py` untouched.

**What can be done under it.** The executor's own placement is fixed:
- `_with_query` → `place_query_param`, at occurrence 0 in the URL's own query;
- `_with_fragment` → `place_route_query_param`.

That fixes the measured defect (`test_the_browser_executor_replaces_the_addressed_occurrence_in_place`).

**What cannot be done under it, which I am flagging rather than substituting.**
- The binder wraps the HTTP sender only.
- `DomXssStrategy._observe` builds `ExecRequest(url=candidate.url, param, value,
  location)` from the candidate and calls the executor the strategy holds.
- So the binder cannot hand the executor a crawled DOM query point's siblings
  (`base_entries`) or an occurrence. That needs either an executor wrapper (ruled out) or
  `DomXssStrategy` passing them (`strategies.py`, AU-OUTCOME's file).
- **Consequence:** a crawled query point's M6 load keeps today's gap. It is loaded as
  `url?param=payload` without its link-set siblings, while the HTTP senders send them.
- **Proposal:** a hand-off for after AU-OUTCOME merges. `ExecRequest` gains
  `entries`/`occurrence`, and `DomXssStrategy` passes `candidate.base_entries`; the
  executor places them through `with_query` + `FormEntries.replace_at`.
- Until then it is a stated gap (FR-FUZZ-64(4)), pinned by a strict xfail,
  `test_a_dom_query_point_is_loaded_with_its_siblings` (PA-0054(3)).
- `ExecRequest` gains no field in this item: a field nothing writes would be a contract
  with no producer (PA-0071).

### 3.6 How conformance is proven

**The fast, offline check.** In `tests/test_sender_conformance.py`:
- `_Wire` stops collapsing. A requests-style send records the URL the session would send,
  `requests.Request(method, url, params=…).prepare().url`: requests' own merge (PA-0035).
  The seam transport records its URL as given.
- New `test_every_sender_places_a_query_occurrence_in_place` runs the §1.1 table through:
  - every concrete sender in `PLACEMENT_FACTORIES` (found by AST; a new one must
    register);
  - greybox, standalone and bound;
  - both blind-sqli senders;
  - the binder over a recording sender.

  It asserts **byte equality** between the two requests-based senders (same owner, same
  client), and `canonical_pairs` equality against the contract.
- New `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`: synthetic
  offenders that append and that rebuild through a `dict` both fail the check
  (PA-0034(2)).

**The end-to-end proof** is `tests/test_query_placement.py`, on the loopback echo server,
with real Chromium for M6, under the measured equivalence.

**The guard.** `test_every_query_builder_goes_through_the_one_owner` is an AST check over
`fuzzlab/`, outside `core/urls.py`. It flags:
- `dict(parse_qsl(...))`;
- a `params=` keyword on a `requests` or session send (`.request` / `.get` / `.post`);
- a `"?"` or `"&"` concatenated with `urlencode(...)` or a `.query`;
- `._replace(query=...)`.

Every allowed site is listed with its reason (§4). A stale allow-list entry fails.
`test_the_query_builder_guard_catches_synthetic_offenders` proves each shape on a
synthetic module.

## 4. The sweep (PA-0002)

The sweep is by mechanism: every query builder in `fuzzlab`, not only the two senders the
audit named.

| Site @8100959 | Pattern | Disposition |
|---|---|---|
| `tools/authhttp.py:17-22` `with_query_param` | `dict(parse_qsl)` rebuild | **fix**: removed, replaced by `place_query_param` |
| `tools/authhttp.py:25-29` `with_query` | replace the query with entries | **fix**: moved to the owner |
| `tools/probesender.py:793,822,946,964` | `with_query`, `with_query_param`, `params=` | **fix** (§3.3) |
| `greybox/run.py:192,196` | `params=list(entries)` / `params={…}` (appends) | **fix** |
| `tools/blind_sqli_fuzzer.py:58,82` | `params=` / `with_query_param` | **fix** |
| `tools/browserexec.py:25-29,539,552` | `query + "&" + urlencode(...)` | **fix** |
| `tools/browserexec.py:32-48` `_with_fragment` | the route query's `+ "&" +` append | **fix**: `place_route_query_param` |
| `oracle/oracle.py:153` (binder), `harness/pipeline.py:107` (`_baseline`) | `FormEntries.replace`: every occurrence | **fix**: `replace_at` |
| `harness/auto.py:510` | `"?" + urlencode(...)` | **fix**: the owner, same bytes |
| `tools/browserexec.py` store step `form={s.param: s.value}` | a form-body store sends no siblings | **residual** (§7): ground truth enumerates JSON store bodies only |
| `core/redaction.py` `redact_captured_body` (`:514-`) | a captured form body becomes an object, "the last value of a repeated name winning" | **hand-off to AU-REDACT** (their file); allow-listed with that reason |
| `disco/runner.py:262` (contract runner) | `url += "&" + urlencode(query)` appends | **hand-off to AU-OUTCOME** (their file); allow-listed with that reason |
| `tools/store_adapter.py:274` (disco form-body import) | `dict(parse_qsl(body))` | **AU-REQID8** (the importer keeps repeated names); allow-listed with that reason |
| `disco/synth.py:309,450,507` | `dict(parse_qsl)`, per-name schema | **defect 9's item** (captured API schemas, not a sender); allow-listed |
| `labgen/oracle_wrapper.py:457-489` `_mark_query_param` / `_mark_body_param` | replaces every occurrence and re-encodes untouched pairs | **LAB follow-up** (no CC-LAB number): allow-listed, and pinned by a strict xfail in this item, `test_the_labgen_tool_wrapper_marks_one_occurrence` (PA-0054(3)) |
| `labgen/identifier_sqli_oracle.py:409-417` | `dict(base_query_params)` | allow-listed: the request type is a mapping, so a duplicate cannot be expressed; generated cells declare none |
| `labgen/conformance/{live_boot,rails_live_boot,django_live_boot,live_boot_spring_boot}.py`, `labgen/conformance/tier2.py:140` | `params=` / `"?" + urlencode` on a query-less path | allow-listed: test-harness clients of generated cells; no existing query to keep |
| `lab_fixtures/external.py:1089,1251` | `params=` constants | allow-listed: lab provisioning, not probing |
| `tools/spider.py:2842-2860` | GET form: action query replaced by the entries | allow-listed: HTML form submission semantics (PA-0111) |
| `session/detect.py:291,320`; `web/app.py:625,1116`; `web/projectroutes.py:41` | `parse_qsl` set comparison; the operator's own UI forms | not builders of a sent query (the guard matches only its listed shapes) |
| `tools/observe.py`, `ml/flow_anomaly.py`, `tools/fetcher.py:517`, `tools/spa.py`, `core/urls.py:122,313`, `core/redaction.py:236,413`, `proxy/server.py:72` | read names or features, redact, or forward verbatim | not builders |

## 5. Tests, each with the revert it must fail against (PA-0034(2))

**Measurement tests (committed).** Each becomes positive at implementation, and its strict
xfail is removed in the same change (MULTI_AGENT §6).

| Test | Must fail against |
|---|---|
| `tests/test_query_placement.py::test_every_sender_replaces_the_addressed_occurrence_in_place[*]` (27 pinned, 3 hold) | any sender's `params=` append or `dict` rebuild |
| `…::test_the_anonymous_and_authenticated_senders_send_the_same_query` | either sender family's old branch |
| `…::test_a_bound_duplicate_name_changes_one_occurrence_only` | `FormEntries.replace` in the binder |
| `…::test_the_browser_executor_replaces_the_addressed_occurrence_in_place` (real Chromium) | `browserexec._with_query` appending |
| `…::test_platform_clients_rewrite_only_escapes_without_query_meaning` | a client upgrade that changes §1.2 (a platform pin) |
| `…::test_the_equivalence_still_tells_apart_what_a_server_reads_apart` | a weakened `canonical_pairs` (for example, one that decodes `%2B`) |
| `…::test_control_a_query_less_url_gets_the_pair` | a sender that stops appending to a query-less URL (scored ground truth would move) |

**New at implementation:**

| Test | Must fail against |
|---|---|
| `tests/test_query_placement.py::test_the_owner_places_each_occurrence_in_place_and_keeps_raw_text`: occurrences 0..n, raw `%7E`, `flag`, `&&`, a trailing `&`, `+` vs `%20`, encoded names, a blank | an owner that decodes and re-encodes untouched parts, or matches raw names |
| `…::test_an_absent_occurrence_above_zero_is_refused_never_appended` | an append fallback for occurrence > 0 |
| `…::test_a_bound_body_duplicate_name_changes_one_occurrence_only` | `FormEntries.replace` for bodies |
| `…::test_every_query_builder_goes_through_the_one_owner` + `…::test_the_query_builder_guard_catches_synthetic_offenders` | a new `params=` / `dict(parse_qsl` / concatenating builder; a guard that misses a shape |
| `…::test_a_dom_query_point_is_loaded_with_its_siblings` (strict xfail: the §3.5 hand-off) | — (pins the stated gap until `DomXssStrategy` passes entries) |
| `…::test_the_labgen_tool_wrapper_marks_one_occurrence` (strict xfail: LAB follow-up) | — (pins the stated gap) |
| `tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place` | any sender's old branch; `_Wire` reverted to a `dict` |
| `…::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` | `_Wire` reverted to a `dict` (the offenders would pass) |
| `…::test_the_executor_places_a_fragment_point_inside_the_hash_route` (extended: `#/s?q=old&page=2` → `#/s?q=M&page=2`) | `_with_fragment` appending a second `q` |

**Existing tests amended in the same change** (before and after stated, PA-0073(3)):
- `tests/test_fuzzer_seam.py::test_with_query_param`: the function is removed, so this
  becomes a test of `place_query_param`.
- `tests/test_fuzzer_seam.py::test_requests_sender_unchanged_standalone_behavior`: it pins
  the call shape `params={"id": "1"}`. It now expects the placed URL and no `params`.
- `tests/test_sender_conformance.py::_Wire`: the raw URL.
- `tests/test_sender_conformance.py::test_the_placement_check_catches_a_relocating_sender`:
  re-checked on the raw wire.

The other test doubles that read a query into a `dict` (`test_forms_phase2._App`,
`test_json_points._JsonWire`) check no placement, so they stay as they are. AU-REQID8
revisits them when duplicate contexts reach points.

## 6. Requirement text (living specs, edited in place at implementation)

**FR-FUZZ-64** *(one query placement for every sender; `CC-FUZZ-0106`, BUG-0531)*. The
numbering of parts (1) and (2) is left to AU-REQID8.

(3) **Query placement.** Every sender places a query value through `core.urls`
(FR-CORE-501, SP-42). The value goes at the addressed occurrence of its name: the first,
for every point today. It is placed in place, and every other pair keeps its order, its
`=` and its text, up to the HTTP clients' own escaping. That escaping is pinned by a
real-browser test.
- A missing first occurrence is appended once. A missing later occurrence is refused
  (`UnplaceableLocation`).
- No sender adds a second pair for a name already present. There is no
  duplicate-parameter probe.
- These senders are covered: `RequestsProbeSender`, `SeamProbeSender` (every session
  route), greybox's `RequestsCorrelatingSender`, both blind-sqli senders, the oracle's
  binder (`_FormBoundSender`, which also serves the cross-account peer replays), and the
  M6 browser executor (query, and the SPA hash route's query).
- A form body addresses its occurrence the same way.
- `tests/test_sender_conformance.py` checks every sender on the raw request.

(4) **Stated gaps:**
- the M6 executor receives no siblings or occurrence from `DomXssStrategy`. A crawled
  query point is loaded without its link set until that strategy passes them (pinned);
- a stored link set's untouched siblings are sent from their stored, decoded values
  (`flag` as `flag=`, `%20` as `+`);
- a form-body store request sends no siblings;
- these query builders sit in other items' files: `disco/runner.py`'s contract-runner
  query (appends), the crawler's captured form bodies (a repeated name collapses at
  `core/redaction.py`), and the labgen tool wrapper (replaces every occurrence; pinned).

It supersedes FR-FUZZ-43's "Never relocated" wording only in that relocation is now also
refused per occurrence.

**FR-CORE-501**, amended in place (title: *URL placement: a path segment or a query
occurrence; `CC-CORE-0059`, `CC-CORE-0068`*). It keeps its current text and adds:

> `core.urls.QueryEntries` is the ordered query-entry representation. It holds every
> part's raw text, order, duplicates, empty parts and `=`, split on `&`.
> `place_query_param(url, name, value, occurrence=0)` replaces that occurrence's value in
> place: the name's raw text is kept, and the value is encoded by `encode_query_pair`
> (`quote_plus`). Every other part keeps its raw text.
> - A missing occurrence 0 is appended once; a missing later one raises
>   `QueryPlacementError`.
> - `place_route_query_param` does the same in an SPA hash route's query (`%20` encoding).
> - `with_query(url, entries)` replaces the query with entries (urlencoded).
> - `core.forms.FormEntries.replace_at` is the occurrence rule over form entries.
>
> This is the one placement (SP-42).

## 7. Residual limits

1. **M6 siblings and occurrence** (§3.5): a hand-off to after AU-OUTCOME (`strategies.py`).
   Pinned.
2. **Stored link-set siblings are re-encoded** from their stored, decoded and redacted
   values. Keeping the crawled raw text needs a store column written through the redaction
   boundary. That is AU-REQID8's importer work.
3. **A repeated name in a bound link set is probed at its first occurrence only** until
   AU-REQID8 makes each occurrence a point. Today every occurrence is replaced. A
   last-value server (PHP without `[]`) reading such a name no longer receives the payload
   at its effective input in the meantime (Q1).
4. **A form-body store step sends no siblings.**
5. **Query builders in other items' files**, allow-listed with their reasons:
   - `disco/runner.py:262` (AU-OUTCOME);
   - `core/redaction.py`'s captured form dict (AU-REDACT);
   - `store_adapter.py:274` (AU-REQID8);
   - `disco/synth` (defect 9);
   - `labgen/oracle_wrapper` (LAB; pinned).
6. **Greybox has gaps.** Greybox points carry no siblings
   (`greybox/run.points_from_store`), and M10 cannot place a bound candidate (no verdict,
   never a negative). These are unchanged.
7. **A query split on `;`** (an old CGI convention) is not modelled. The measured clients
   and the common parsers split on `&` only.

## 8. Draft change-control entries (pre-change gate; Effectiveness pending)

```
### CC-FUZZ-0106 — Every sender places a query value at one exact occurrence, through one owner (BUG-0531) (2026-10-19)
- Change: `RequestsProbeSender`, `SeamProbeSender`, greybox `RequestsCorrelatingSender`,
  blind-sqli `RequestsSender`/`SeamSender` and `browserexec` (`_with_query`,
  `_with_fragment`, the GET store step) place query values through
  `core.urls.place_query_param` / `place_route_query_param` / `with_query`; the bound
  branch of greybox uses `with_query` instead of `params=` (no append);
  `_FormBoundSender` and `pipeline._baseline` use `FormEntries.replace_at` (occurrence 0);
  `header_points_from_store` builds its query through `with_query` (same bytes);
  `tools/authhttp.with_query_param` / `with_query` are removed. Files:
  tools/probesender.py, greybox/run.py, tools/blind_sqli_fuzzer.py, tools/browserexec.py,
  oracle/oracle.py (one line), harness/pipeline.py, harness/auto.py, tools/authhttp.py
  (~70 LOC changed); tests ~350 LOC (§5).
- Impact (other components / project): CORE (the owner, CC-CORE-0068). No contract change:
  the `Sender` protocol, `Candidate`, `ExecRequest` and the store are unchanged.
  Consumers found by search (PA-0152): `with_query_param` (probesender, blind_sqli_fuzzer,
  tests/test_fuzzer_seam.py), `with_query` (probesender), `FormEntries.replace`
  (oracle._FormBoundSender, pipeline._baseline, tools/formnav — formnav keeps `replace`),
  `_FormBoundSender` (oracle; `strategies.py:1750`, unedited). Overlap: oracle.py with
  AU-OUTCOME (merges first; this change is one line in `_FormBoundSender.send`).
- Risk: medium. The wire changes for any URL that already carries a query (intended);
  scored ground truth is unchanged (no point URL carries a query, §1.3); a bound repeated
  name is probed at its first occurrence only until AU-REQID8 (residual 3, Q1).
- Deliverables:
  - [ ] senders, binder, baseline, header points and executor through the owner — todo
  - [ ] conformance check on the raw wire, the AST guard, the tests of §5 — todo
  - [ ] strict xfails of tests/test_query_placement.py removed — todo
  - [ ] BUG-0531, PA-0531, ERROR_LOG, CHANGELOG (at merge) — todo
- Effectiveness (assessed after landing): pending.

### CC-CORE-0068 — One query placement: the ordered query-entry list and `place_query_param` (SP-42, FR-CORE-501) (2026-10-19)
- Change: `core/urls.py` gains `QueryEntries`, `QueryPlacementError`, `encode_query_pair`,
  `place_query_param`, `place_route_query_param` and `with_query` (moved from
  tools/authhttp.py); `core/forms.FormEntries` gains `replace_at`. No schema change.
  (~120 LOC.)
- Impact: every caller in §3.3; SHARED_PRIMITIVES.md SP-42 row (owner list and guards;
  orchestrator, at merge); FR-CORE-501 amended in place.
- Risk: low-medium (a new primitive; unit-tested over every part shape of §1.2, and
  guarded).
- Deliverables: owner [ ] todo; unit tests [ ] todo; FR-CORE-501 [ ] todo.
- Effectiveness: pending.
```

## 9. Bug record and preventive action (drafts)

**BUG-0531: each sender placed a query value differently** (audit defect 14).
- The RCA is §2.
- The corrective action is CC-FUZZ-0106 and CC-CORE-0068.

**Recurrence review.** The same root cause, one seam's implementations not in step, has
come before:

| Prior bug | Rule | What it kept in step |
|---|---|---|
| BUG-0039 | PA-0041 | transport settings |
| BUG-0044 | PA-0046 | redirects |
| BUG-0071 | PA-0072 | the signature |
| BUG-0115 | PA-0115 | placement by location |

A related rule: BUG-0110 / PA-0111, form serialisation rule by rule. `core.forms.RULES`
has "duplicates-kept-in-order", for forms only.

**Prior-preventive-action failure analysis.**
- PA-0115(2) made placement checked "by discovery", but at **location granularity**. Its
  wire (`_Wire`) parses the query into a `dict`, and its probe URL has no query. The check
  could not observe an occurrence, a duplicate or order. It was not enforced at the level
  where the violation lives (cf. PA-0311(2)).
- PA-0041 and PA-0072 synchronise settings and signatures, not the request a sender
  builds.
- PA-0111's rule table covers `core.forms` serialisation. URL query mutation is a
  different code path, with no rule. Too narrow.

**Preventive action. PA-0531** strengthens PA-0115(2) and PA-0111:
1. A value placed in a URL, a query occurrence or a path segment, is placed only through
   the one owner (SP-42). An AST guard rejects `dict(parse_qsl`, a send's `params=`, and
   `urlencode` concatenated onto a query outside it, with a reasoned allow-list. It is
   proven on synthetic offenders.
2. A placement check observes the raw request through the real client's own URL
   preparation, never a parsed `dict`. It is shown to fail on a sender that appends and on
   one that collapses.
3. Two senders of one seam are compared on the same request, under an equivalence
   measured on the real clients and pinned by a real-browser test.

- Enforced by: `tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner`,
  `tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders`,
  `tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`,
  `tests/test_query_placement.py::test_platform_clients_rewrite_only_escapes_without_query_meaning`

## 10. Shared primitives

**SP-42**, extended (the orchestrator updates the row at merge; `SHARED_PRIMITIVES.md` is
a shared doc):
- New mechanism text: "Placing a value in its URL: a path segment (`/ticket/{id}`) or a
  query occurrence (in place, every other pair kept)".
- Owner: `fuzzlab/core/urls.py::place_path_param`, now with `place_query_param`,
  `place_route_query_param`, `QueryEntries`, `with_query` and `encode_query_pair`.
- Readers: both probe senders, greybox, blind-sqli, `browserexec`, the oracle binder (via
  `with_query`), `harness.auto` and `labels.contract` (as today).
- Added guards: `test_every_query_builder_goes_through_the_one_owner`,
  `test_the_query_builder_guard_catches_synthetic_offenders`,
  `test_every_sender_places_a_query_occurrence_in_place` and
  `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`.

**SP-20** (the sender protocol) gains the two conformance guards in its row.

## 11. Size, merge order and open questions

**Size.** About 190 LOC of production code (~120 for the owner, ~70 across the senders)
and about 350 LOC of tests. That fits one item.

**Merge order.** AU-OUTCOME first. Then merge its result into this branch, re-check that
the one-line binder change still applies inside `_FormBoundSender.send`, and run
`verify_change.py --full`.

**Open questions:**
- **Q1 (coordinator or owner).** Should the binder change land now, or wait for AU-REQID8?
  A repeated name in a bound link set is probed at its first occurrence only until
  AU-REQID8 makes each occurrence its own point.
  - Today every occurrence is replaced, which reaches a last-value server. That request is
    wrong, but it lands.
  - Option A, as instructed: land it now, with the transitional gap stated (residual 3).
  - Option B: keep `replace` in the binder until AU-REQID8. This leaves
    `test_a_bound_duplicate_name_changes_one_occurrence_only` pinned.
  - Crawl frequency is unmeasured; ground truth has no repeated names.
  - I recommend **A** if AU-REQID8 is registered soon, else **B**.
- **Q2.** Should FR-CORE-501 be amended in place (proposed, since SP-42 is the same
  primitive), or should the query placement get a new FR-CORE ID? No FR-CORE number was
  assigned.
- **Q3.** Is §3.5 accepted? The executor's own placement is fixed here. The sibling and
  occurrence hand-off waits for `DomXssStrategy` (AU-OUTCOME's file). The coordinator's
  "the binder passes the occurrence and entries" cannot reach the executor without a
  wrapper or a strategy edit.
