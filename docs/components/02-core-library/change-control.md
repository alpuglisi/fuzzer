# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0074 — Points fold only on the request they send, never on a shared DOM template (FR-FUZZ-68, BUG-0547) (2026-10-21)
- Placement: pre-assigned to lane DEDUP10 (audit defect 10, item AU-REQID78); CC-CORE-0073
  is another lane's.
- Change: `fuzzlab/core/dedup.py` (+128 / -6).
  - `wire_request_key(point) -> tuple`: every field of the point's dataclass, by name,
    as given (`dataclasses.fields`, so a field added later is in the key), lists frozen to
    tuples, sets to frozensets, an unhashable value replaced by a fresh `object()` (never
    equal: never folded). Only a **standalone query point**'s URL (`location == "query"`,
    no `base_entries`, no `store_url`) is taken as sent: its injected slot placed by
    `core.urls.place_query_param` (SP-42, the first occurrence in place), so
    `/item?id=1` and `/item?id=2` probing `id` share a key. A local stand-in for SP-57,
    replaced by it at merge (AU-REQID78).
  - `fold_points(points, pages_html, clusterer=None) -> Folded`: drops a point only when
    an earlier kept point has the same page template **and** the same `wire_request_key`;
    an unknown page (absent, or no tag structure) is its own template
    (`("unknown-page", url)`). `Folded(points, folded, unknown_pages, key=FOLD_KEY)`;
    `FOLD_KEY = "template+wire-request-v1"`.
  - `TemplateClusterer.known_cluster_id(html)`: `cluster_id`, or None for an absent or
    structureless page. `cluster_id` and `minhash` keep their results (the signature is
    factored into `_skeleton_signature`, the assignment into `_assign`).
- Impact (other components / project):
  - FUZZ: `harness/pipeline.py::_dedup` calls `fold_points` (CC-FUZZ-0112).
  - Consumers searched over `fuzzlab/` and `tests/` (PA-0152): `TemplateClusterer`,
    `minhash`, `similarity` are read only by `harness/pipeline.py` (now through
    `fold_points`) and `tests/test_fewer_requests.py`; no other module imports
    `core.dedup`. FR-CRAWL-3's crawler-side `template_cluster_id` column is not written
    by any code and is unchanged.
  - AU-REQID78 builds SP-57 (the request-context identity) concurrently: `wire_request_key`
    is replaced by it at merge, keeping this entry's guarantees (planned merge order:
    AU-REQID78, then DEDUP10).
  - No shared-primitive row: the key is a lane-local stand-in, not a new owner.
- Risk (low): the change can only keep points the old stage dropped; points it still
  folds send the same wire request on the same template. That a standalone slot is what
  every sender overwrites is SP-42's measured contract (FR-FUZZ-64: requests 2.34.2 and
  Chromium, `tests/test_sender_conformance.py`, `tests/test_query_placement.py`), not
  re-measured here. A URL `urlsplit` cannot parse is keyed as given (never a crash of
  the stage). Residual: a PRG follow-up of a
  fragment-only `Location` is resolved against the unplaced URL (FR-FUZZ-64), so two
  folded standalone points could differ in that one follow-up's target.
- Deliverables:
  - [x] `wire_request_key`, `fold_points`, `Folded`, `FOLD_KEY`, `known_cluster_id` — done
  - [x] `tests/test_dom_dedup_folding.py` (key guard over every dataclass field, the
    standalone-slot cases, the unhashable case), each failing on c483dc1 — done
  - [x] FR-FUZZ-68; the core requirements' interfaces note — done
- Effectiveness (assessed <date> or pending): pending.

### CC-CORE-0072 — One bounded reader of a target's HTTP body (SP-60, FR-CORE-536, BUG-0536) (2026-10-20)
- Placement: pre-assigned to AU-BOUNDED (audit defect 21); CC-CORE-0070 and CC-CORE-0071
  are other lanes'.
- Change: new `fuzzlab/core/bodyread.py`; `core/http.py::_requests_transport` reads through
  it (the change stays inside that function).
  - `read_body(resp, *, deadline, limits=None, clock=time.monotonic) -> Body`. It reads the
    undecoded stream one receive at a time (urllib3 `read1`), counts wire bytes
    (`MAX_WIRE_BYTES` 16 MiB), and decodes with an output ceiling per step
    (`MAX_DECODED_BYTES` 32 MiB): zlib `max_length` for gzip (several members) and
    deflate (zlib-wrapped or raw), and Brotli's `output_buffer_limit` from Brotli 1.2.
    It checks the deadline before every receive and at the end.
    - It returns `Body(data, complete, reason, wire)`, with `reason` one of `wire`,
      `decoded`, `deadline` or `encoding`. A complete body becomes `resp.content`.
    - urllib3's errors are translated as `iter_content` translates them, and a
      decoding failure is `ContentDecodingError`.
    - It never closes the response: the caller does.
    - A response with no raw stream is read through `iter_content`, its chunks counted
      on the smaller ceiling.
  - `BoundedAdapter` reads every response with `read_body` before `send` returns, with a
    deadline of `DEADLINE_TIMEOUTS` (4) x the read timeout (`DEFAULT_SECONDS`, 60, with
    none). An incomplete body raises `BodyIncomplete` (a `requests.RequestException`;
    the message names the reason only), with the response closed. `bound(session)`
    mounts the adapter on http and https; it is idempotent and returns the session.
  - Codings: `zstd`, a `br` body without a bounded Brotli, and a chain of codings are
    incomplete (`encoding`). A coding urllib3 has no decoder for is passed through, as
    urllib3 does.
  - The transport sends through `bodyread.bound(requests.Session())`, one session per
    send as `requests.request` made, so an incomplete body raises out of
    `HttpClient.send`.
  - *(Review round 1.)*
    - **One process-wide watchdog thread** (`watch`, `_Watchdog`): watched connections
      (`WatchedAdapter` pools; urllib3 connection subclasses arming their socket on
      connect, request and getresponse) are shut down (`SHUT_RDWR`, the plain socket's
      method) when still in use at the exchange's deadline. That cuts a dripped status
      line, header or chunk-size line, and a send with no timeout.
      `BoundedAdapter` extends it, and `watched(session)` gives a caller that reads
      itself (the contract runner) the same watch.
    - **Advertised codings:** `advertise` / `accept_encoding` set `Accept-Encoding` to
      `gzip, deflate` (plus `br` with a bounded Brotli) whenever a request names a
      coding the reader cannot bound. urllib3's default names `br` with any Brotli and
      `zstd` on Python 3.14, so every answer would have been incomplete. A bounded one
      a caller set is kept.
    - `read_body` on a response already read returns its kept `content`, never b""
      from the spent stream; one read and not kept raises.
- Impact (other components / project):
  - Every caller of `HttpClient.send` may now get `BodyIncomplete`:
    - `SeamProbeSender` maps it to `ProbeUnobserved` through SP-34 (CC-FUZZ-0109);
    - blind-SQLi's `SeamSender` lets it reach its `requests.RequestException` handlers:
      no baseline sample and no row;
    - the auditor's seam fetch lets it reach its "Fetch failed" handler.
  - FUZZ and CRAWL bound their own sessions with `bound` (CC-FUZZ-0109, CC-CRAWL-0054).
  - SESS's login fetcher is pinned by a strict xfail (AU-SESS403's file).
  - New shared primitive SP-60, and an ARCHITECTURE note (the coordinator writes both).
  - AU-SESS403 adds a `Request` field to the same file; this change touches only
    `_requests_transport`.
- Risk (medium): every target read now has ceilings and a deadline. A legitimate body
  over 16 MiB on the wire or 32 MiB decoded, or one that ends after 4 read timeouts, is
  now incomplete where it used to be read. That is the intended trade, and the values
  are module constants.
  - The watchdog is one daemon thread that shuts sockets down from outside the
    reading thread. A shutdown racing a just-finished exchange can drop a pooled
    connection, which urllib3 detects and replaces on reuse. The connect itself is not
    interrupted (stated limit).
  - `BoundedAdapter` and `read_body` set `resp._content` / `_content_consumed`, requests'
    own private fields, the way requests does. The watched pools subclass urllib3's
    connection pool and connection classes; a SOCKS proxy keeps its own, unwatched.
- Deliverables:
  - [x] `fuzzlab/core/bodyread.py`, `core/http.py::_requests_transport` — done
  - [x] `tests/test_bounded_reads.py`: each reader against a dripping and a gzip-bomb
    loopback peer, the peer's sent count showing the connection dropped; decoding
    memory (traced peak under a 1 MiB ceiling); the wire ceiling; every coding pinned;
    an undecodable or unbounded coding never a body; the session guard and its
    synthetic offenders; R2 as a strict xfail. Review round 1: a dripped status line
    and headers (every reader), a dripped chunk-size line and a send with no timeout
    cut by the watchdog; the advertised codings on a simulated zstd/brotlicffi host;
    the consumed-response guard — done
  - [x] Test-fixture defect, root-caused: the bomb peer built its 40 MiB gzip body on
    the first request (0.18 s idle, measured). Under the revert run's parallel load,
    the head came after the probe sender's 0.25 s read timeout and read as a timeout
    probe ("a normal body of 0 bytes"). The peer now builds it before it listens — done
  - [x] Regression the harness found on 209355c, root-caused. The spider's form tests
    (`test_forms_phase1.py`, `test_forms_phase2.py`, four tests) replace
    `requests.Session` with a factory of an in-memory site. That broke
    `get_checked`'s `isinstance(session, requests.Session)` ("arg 2 must be a type")
    and `bound()` on the stand-in (no adapters). `bound` now judges by the class
    itself (`requests.sessions.Session`) and returns any other object as given, the
    rule `get_checked` already stated; `get_checked` just calls `bound`. Pinned by
    `test_bound_mounts_on_a_real_session_and_leaves_a_stand_in_as_given` — done
  - [x] FR-CORE-536 — done
  - [ ] SP-60 row, SP-34 row note, ARCHITECTURE note, PA-0536, CHANGELOG, ERROR_LOG —
    todo (the coordinator, at merge; texts in the lane report)

### CC-CORE-0071 — One read-only opener; a SQLite file is touched only through SQLite; the listing's summary has an age bound (FR-CORE-508, BUG-0535) (2026-10-20)
- Placement: pre-assigned to AU-SITETREE (CC-CORE-0070 is another lane's). Design record:
  `docs/components/12-diagnostics-and-ui/DRAFT-AU-SITETREE.md` §3.2.
- Change:
  - **`fuzzlab/core/store.py`** (+~50): `open_read_only(path, *, timeout,
    fold_on_close=False, any_thread=False)` (an existing file only; `mode=ro`, or `mode=rw`
    with `fold_on_close`; `cache=private`; `query_only`; `trusted_schema=OFF`; closed if
    set-up fails) with its URI builder `_read_only_uri`; `is_sqlite(conn)` (`PRAGMA
    schema_version`; `SQLITE_NOTADB` is `False`, anything else propagates).
  - **`fuzzlab/core/project.py`**: `inspect` and `summary` no longer read the magic with
    `open()`: they open through `open_read_only` and ask `is_sqlite` (the refusal text
    is kept; the 0-byte branch kept; the length limit and the step budget are set first).
    `copy_to`'s source opens through `open_read_only` (SQLite's backup API). `_ro_uri`
    and the unused `SQLITE_MAGIC` removed. `summary` recomputes a cached summary older
    than `SUMMARY_MAX_AGE_S` (2 s, `_summary_clock = time.monotonic`); the cache holds
    `(taken_at, summary)`.
  - **`tests/test_query_placement.py`**: `ALLOWED` follows (the `core/project.py::_ro_uri`
    and `harness/auto.py::header_point_estimate` entries go; `core/store.py::_read_only_uri`
    comes, a SQLite `file:` URI, not HTTP).
  - **Tests**: `tests/test_core_store_read_only.py` (C1-C4), `tests/test_web_store_locks.py`
    (K1-K6, the whole-closure guard, the audit hook's proofs), L1-12 in
    `tests/test_web_sitetree.py`.
  - The FUZZ change that reads the spider DB through the opener is CC-FUZZ-0108.
- Impact:
  - Every caller of `inspect`, `summary` and `copy_to` (from the code: `web/projects.py`
    -- the listing, open, re-check, migrate, save as, snapshot, sidecar copies;
    `core/project.migrate_with_backup`): same results, same refusal message; a cached
    listing summary is at most 2 s old.
  - It fixes BUG-0535 for the web process (the proxy's held `Store` under
    `--with-proxy`, overlapping requests) and makes CC-UI-0068's watch safe.
  - `open_read_only` is a new shared primitive (SP-59), read by `core.project`,
    `web.sitetree` and `harness.auto`.
- Risk: low-medium. The magic check moves from bytes to SQLite: measured on text, a bare
  16-byte magic, random bytes, JSON (all `SQLITE_NOTADB`, no side file) and an empty file
  (an empty database: the callers' size check stays); the refusal text is kept. Mitigated
  by C1-C4, K1-K6 and the existing `tests/test_core_project.py` and
  `tests/test_web_projects.py` suites. Rollback: the two magic reads (which re-open
  BUG-0535).
- Deliverables:
  - [x] measurements (§1.4 N, the backup API; §1.7; the opener on non-SQLite files, §11) and failing tests (§5.2, L1-12) — done
  - [x] the opener, `is_sqlite`, the `inspect`/`summary`/`copy_to` changes, the age bound — done
  - [x] FR-CORE-508 added; BUG-0535; texts for PA-0535, SP-59, ERROR_LOG and CHANGELOG to the coordinator — done
  - [x] verified with CC-UI-0068 and CC-FUZZ-0108 (one harness run) — done
- Revision after the review of `eb95cd4` (DRAFT-AU-SITETREE §11.7; tests only, no CORE
  code change): K4 now proves the claim the reviewer found it did not (the side files
  after the listing, a version right after it, one watch epoch across the scan; it fails
  at its own assertion on the pre-fix `project.py` with the audit hook disarmed); the
  static guard of FR-CORE-508 resolves opener aliases (`import shutil as sh`, `from os
  import open as o`, `from shutil import copyfile`, `io.FileIO`), proven on synthetic
  offenders, with no new site in the web scope (still 60 allowances, 64 sites, 32
  modules); the audit hook does two set lookups per open instead of a union (0.86 ms
  per open at 20k stores, the reviewer's measurement).
- Effectiveness (assessed 2026-10-20): `scripts/verify_change.py --base 4ee8007` on the committed tree `eb95cd4` (`3fb76bb` plus the merge of `01192c3`; the whole suite, since `tests/conftest.py` changed): **408 files, 8248 passed, 0 failed, 0 errors, 42 skipped, 36 xfailed**, one parallel pass, 1729 s (`scratchpad/au-sitetree/impl/vc_eb95cd4/`). The 42 skips are sandboxes, optional extras and tools absent here; none is a web, store or browser test. `test_core_store_read_only.py` 5 passed,
  `test_web_store_locks.py` 8, `test_core_project.py` 90, `test_web_projects.py` 123,
  `test_query_placement.py` 118 (8 xfailed). Re-proved against the implementation
  (DRAFT-AU-SITETREE §11.4): the magic read with `open()` again, the same through
  `core/secretfile.py` (the old guard scope's miss), the opener without `query_only`, with a
  shared cache, and `summary` without its age bound are each caught by their named tests.

### CC-CORE-0070 — The request records its session generation and a lost-session mark; SP-56's guard list loses three session rows (FR-SESS-23, FR-FUZZ-65, BUG-0533) (2026-10-20)
- Change:
  - `fuzzlab/core/http.py::Request` gains `session_generation: int | None = None` and
    `session_lost: bool = False` (+11 lines with comments). The seam neither reads nor
    changes them: the session addon's `prepare` sets both, its `observe` reads the
    generation, and the sender that built the request carries the mark to its reader.
  - FR-CORE-6 declares both beside `session_decision` (B6).
  - `tests/test_core_comparability.py::ALLOWED` drops the rows for
    `SessionManager.verify_live`, `SessionManager._verify_authenticated` and
    `detect.detect_logout` (8 rows to 5): those decisions now go through SP-56.
- Impact (other components / project): SESS writes and reads both fields
  (CC-SESS-0029). FUZZ reads the mark (CC-FUZZ-0107: `Probe.session_lost`, layer 1).
  An optional field with a default changes no existing sender.
- Risk (low): two defaulted fields; the allowance list is exact (a stale or new row
  fails), and the three removed sites carry no classified literal.
- Deliverables:
  - [x] the fields — done
  - [x] FR-CORE-6 amended (`02-core-library/requirements.md`) — done
  - [x] three rows removed; `test_no_module_classifies_a_throttle_or_refusal_but_the_owner`
    green — done

- Effectiveness (assessed <date> or pending): pending.


### CC-CORE-0069 — One classification of an HTTP answer (SP-56, FR-CORE-507, BUG-0528, BUG-0529) (2026-10-20)
- Change: new `fuzzlab/core/comparability.py` (90 lines).
  - `response_class(status, headers=None, *, complete, credentialed,
    credential_submission, redirect_to_login) -> (class, reason)`. The four facts are
    required keyword inputs with no default.
  - The classes, first match wins: `incomplete` (no status, a status of 0 or below or
    not an integer, or `complete` false); `throttle-or-unavailable` (429; 503 with or
    without `Retry-After`, **by policy**: RFC 9110 §15.6.4 and nginx's documented
    `limit_req_status` default, not measured here); `gateway` (502, 504);
    `auth-failure` (407; a 401 or a redirect to a login page when the request was
    credentialed and is not itself a credential submission); `policy-block` (403, 451);
    `application` (anything else).
  - Pure and total: malformed input is `incomplete`, never an exception (PA-0500(1)).
    The reason names a class and a status, never a URL, header value or body. It imports
    nothing from `fuzzlab.session` or `fuzzlab.oracle`.
  - Whether a class is admitted is each consumer's decision.
- Impact (other components / project):
  - FUZZ reads it: the contract runner, the oracle's `require_observed` /
    `require_comparable`, the blind-SQLi builder (CC-FUZZ-0105). MUT reads it: the live
    WAF filter (CC-MUT-0403). SESS supplies the login facts (`login_facts`,
    CC-SESS-0028); `detect_logout` is defect 6's later item and will read it.
  - New shared primitive SP-56 and an ARCHITECTURE note (the coordinator writes both at
    merge).
- Risk (low): a new pure function; the risk sits with its consumers' admission
  decisions (CC-FUZZ-0105, CC-MUT-0403). A 503 classified by policy is residual R14
  (BUG-0529).
- Deliverables:
  - [x] `fuzzlab/core/comparability.py` — done
  - [x] `tests/test_core_comparability.py` (33 tests): the rule table over the full
    complete x credentialed x credential-submission x login-redirect matrix for 17
    statuses, the 503/`Retry-After` reason, totality, required keywords, the import
    guard and the status guard (each proven on a synthetic offender) — done
  - [x] FR-CORE-507 — done
  - [ ] SP-56 row, ARCHITECTURE note — todo (the coordinator, at merge)
- Effectiveness (assessed <date> or pending): pending.

### CC-CORE-0068 — One query placement: `QueryEntries`, `place_query_param`, `bind_query` (SP-42, FR-CORE-501, BUG-0531) (2026-10-20)
- Placement: pre-assigned to AU-REQID14; CC-CORE-0066 and CC-CORE-0067 are other lanes'.
- Change: `fuzzlab/core/urls.py` gains, beside `place_path_param` (SP-42):
  - `encode_query_value(text)`: the one encoder, `quote_plus(str(text), safe="")` (what
    `urlencode` does today, so a query-less URL's bytes are unchanged);
  - `QueryEntries`: a query's ordered raw parts, split on `&` only from `urlsplit`'s
    query (`;` stays data), an empty query having zero parts, empty parts kept, `=`
    presence kept; a part's name is decoded with `unquote_plus(…,
    errors="surrogateescape")` for matching only, so `n%E9` and `n%EF%BF%BD` are never
    one name; `replace_first(name, value)` puts the encoded value into the first part so
    named (its raw name text kept) or appends one encoded pair; `to_query()`;
  - `place_query_param(url, name, value)`: the standalone rule (the URL's own query, the
    first occurrence in place, the rest of the URL verbatim; an empty `?`/`#` is dropped,
    as `urlunsplit` does);
  - `with_query(url, entries)`: moved from `tools/authhttp.py`, same bytes (the query is
    `urlencode(list(entries))`);
  - `bind_query(url, entries, name, value)`: the bound rule,
    `with_query(url, FormEntries(entries).replace(name, value))`, idempotent on entries
    the oracle's binder has already bound;
  - `place_route_query_param(url, name, value)`: the standalone rule inside an SPA hash
    route's query (`%20` encoding, `quote`), a non-route fragment replaced by the pair
    (`#q=v+w`), as before.
  No schema change; `core/forms.py` unchanged. (~90 LOC.)
- Reason: BUG-0531 (audit defect 14): no owner for query placement, so every sender built
  it its own way.
- Impact (other components / project): FUZZ (every sender and the M6 executor place
  through it, CC-FUZZ-0106). FR-CORE-501 amended in place. The SP-42 row in
  `docs/SHARED_PRIMITIVES.md` and the `docs/ARCHITECTURE.md` line are written by the
  coordinator at merge (shared docs).
- Risk: low-medium: a new primitive on every probe's query. Mitigation: unit tests over
  every part shape the clients were measured to keep (`;`, `+`/`%20`, empty parts, a
  missing `=`, encoded names, non-UTF-8 escapes), byte-for-byte sender conformance, and
  the AST guard that keeps query building in this one module.
- Deliverables:
  - [x] the owner and its unit tests (`tests/test_query_placement.py`) — done
  - [x] FR-CORE-501 amended in place — done
  - [x] SP-42 row, ARCHITECTURE line — coordinator, at the part 1 merge (6551fbc)
  - [ ] the SP-42 owner names for the part 2 addition — coordinator, at merge
- Part 2 addition (2026-10-20, with CC-CRAWL-0053 and CC-FUZZ-0106 part 2; no new CORE
  number was assigned, so it is recorded here):
  - `encode_route_value(text)`: `quote(text, safe="")`, the route-query encoder
    `place_route_query_param` already used inline.
  - `place_route_query_pairs(url, pairs, encode=encode_route_value)`: each pair, in
    order, by the standalone rule in the URL's *route* query (a fragment's own query in
    hash mode; the URL's own query when it has no fragment, history mode).
  - `place_route_query_param`'s route branch now calls it (same bytes,
    `tests/test_json_points.py::test_the_executor_places_a_fragment_inside_the_hash_route`).
  - Caller: `tools/spa.query_url` (CC-CRAWL-0053), with its own encoder that keeps `/`.
  - Unit test: `tests/test_query_placement.py::test_the_route_query_owner_places_each_pair_by_the_standalone_rule`.
- Effectiveness (assessed after landing): pending.

### CC-CORE-0065 — Trace steps a strategy run cites, and the M6 browser in the testing overlay (FR-CORE-505, FR-FUZZ-62) (2026-10-19)
- Change: `fuzzlab/core/trace.py`:
  - `strategy_scope` also resets a new `_STEPS` contextvar.
  - New `emit_step(kind, body, *, scope=None, t=NOW)` emits and adds the key to
    `_STEPS`; the scope defaults to `test:<test>` or `run`.
  - New `collected_steps()`.
  - New `M6_BROWSER = "actor:tool-browser"`.
  - New `_apply` branch. A `browser.step` with `step` `store` or `navigate`, an
    `origin` and an outcome other than `not_sent` adds:
    - the `M6_BROWSER` actor ("Browser driven by the tool (M6)");
    - the origin and the interface (`tested`);
    - a `test`-view `http` flow from `M6_BROWSER`, keyed apart from the tool's exchange
      flow to the same interface (PA-0515(1)).

    `oob.wait` adds nothing to the model.
  - FR-CORE-505 is edited in place.
- Reason: FR-FUZZ-62 (CC-FUZZ-0102). A finding cites the confirmation steps its
  strategy run recorded, as it cites exchanges. The M6 browser's sends are traffic of
  their own.
- Impact:
  - Additive, with no migration. `scrub_event` is unchanged; every new body key passes
    its name rule (measured).
  - Read by FUZZ (the producers) and UI (the views).
- Risk: low. Only the existing set and min/max merges are used, and the SP-48 guards
  stay green.
- Review: covered by the CC-FUZZ-0102 gate (3/3 on revision 3).
- Deliverables (done):
  - the code;
  - `tests/test_trace_model.py::test_the_m6_browsers_overlay_flow_is_keyed_apart_from_the_tools_exchanges`;
  - `tests/test_trace_model.py::test_browser_steps_reduce_independently_of_order`;
  - the FR-CORE-505 edit.
- Effectiveness (assessed 2026-10-19): both tests fail on `56ede12`: on the old code
  `test_the_m6_browsers_overlay_flow_is_keyed_apart_from_the_tools_exchanges` and
  `test_browser_steps_reduce_independently_of_order` fail (no M6 flow). With the M6
  flow given the tool's id, the first fails: `assert {'flow:test:a...|GET|/a:http'} <=
  {'flow:test:a...|GET|/a:http'}`.

### CC-CORE-0066 — `safe_ref` blanks a token inside a path segment (BUG-0521) (2026-10-19)
- Change (`fuzzlab/core/trace.py::_blank_identifiers`): besides a whole identifier-like
  segment, an identifier-like run (`_TOKEN_RUN`, `[A-Za-z0-9_-+=]{8,}`) inside a segment is
  replaced by `REDACTED_SEGMENT`.
- Reason: an out-of-band payload's canary token, followed by `)` or a backtick, survived
  in `value_preview` (BUG-0521; found by DG-M6M8's gate reviewer 1).
- Impact: a segment holding a token among other characters shows `{redacted}` in place of
  the token. Ordinary paths (words, file names, short ids) are unchanged (checked).
- Risk: low.
- Review: a fix of a redaction gap found by a gate review; the number CC-CORE-0065 stays
  reserved for DG-M6M8.
- Deliverables:
  - [x] code; `tests/test_trace_model.py` (two shapes, four payload templates; fail on the
    old code) — done
  - [x] FR-CORE-505 in place; BUG-0521; PA-0521; ERROR_LOG; CHANGELOG — done
- Effectiveness: verified offline.

### CC-CORE-0064 — Trace review fixes: redaction, honest model, order independence, live counters (BUG-0514, BUG-0515, BUG-0516) (2026-10-19)
- Change (`fuzzlab/core/trace.py`):
  - `safe_ref`: `redact_url_identifiers`, then `redaction.redact_for_record` (userinfo,
    sensitive matrix parameters, query-shaped fragments), then identifier-like matrix,
    fragment and path values blanked; a path token becomes `REDACTED_SEGMENT`, which
    `interface_path` groups as `{id}`. Interface paths drop `;name=value`.
  - `scrub_event`: any string with a `/` under a URL key (`_URL_KEYS`) goes through
    `safe_ref`; the schema keys' exemption is documented.
  - Reducer: an entity's kind is the strongest by rank; a capped attribute keeps the
    `MAX_ATTR_VALUES` smallest values in a fixed order, and `<key>_more` is a flag.
    Proof: the stored set is always the smallest 40 of all values seen, since a value
    left out was larger than 40 kept ones; the flag is true iff more than 40 distinct
    values were seen. Both are therefore independent of order and batching, and equal
    to a rebuild.
  - A templated interface is `inferred`. The spider's own loads (`by: crawler`) come
    from a new `SPIDER` actor. A blocked request is a `blocked` flow with `refused`.
    A status 0 is no status.
  - `TraceRecorder` writes its counters at the first flush, at most every
    `METRICS_SECONDS` (1 s) after, at once after a drop, and at `close`.
- Reason: the after-the-fact review of the diagrams series (F-076): BUG-0514, BUG-0515
  and BUG-0516.
- Impact: event bodies redact more. Interface ids for token-shaped paths become `{id}`
  groupings, and matrix parameters leave interface ids. Stores written before this keep
  their old bodies; a `--rebuild` regroups them. Each live run gets one extra
  `run_metrics` rewrite per second at most.
- Risk: low-medium. Redaction now also blanks identifier-like path segments, so a
  hashed asset name groups as `{id}`; this is accepted (fails closed).
- Review: this entry follows the two-reviewer gate run after the fact over the diagrams series (F-076); both reviewers disagreed, and every confirmed finding in this component is fixed here or answered below.
- Deliverables:
  - [x] code; `tests/test_trace_model.py`: token shapes, relative URLs under URL keys,
    kind and capped attributes over three orders and three batch sizes, live counters,
    and *executed*; each new test fails on the old code — done
  - [x] FR-CORE-505 edited in place; BUG-0514, BUG-0515, BUG-0516; PA-0514..0516;
    ERROR_LOG; CHANGELOG — done
- Effectiveness: verified offline (the tests above); reviewer findings S2, S3, S6 and
  S7 (A) and B1, S1, S3, S4 and N1 (B) are closed.

### CC-CORE-0063 — The trace: the evidence model behind the data-flow and sequence diagrams (FR-CORE-505) (2026-10-19)
- Change: migration 24 (`trace_event`, `dg_entity`, `dg_flow`, `dg_evidence` and their
  indexes); new `fuzzlab/core/trace.py`:
  - the event vocabulary and execution context (`test_scope`, `strategy_scope`, `role`,
    `collected`, `recording`, `emit`);
  - `TraceRecorder`: bounded buffer, batched transaction, `scrub_event` at the write,
    dropped / duplicate / forced-flush / lag counters to `run_metrics`; `t` stays NULL
    when the source records none (`NOW` is the default);
  - `reduce`: idempotent and order-independent; `rebuild`;
  - `interface_id` / `interface_path`: id-shaped segments grouped, memoized per
    segment;
  - `FLUSH_KINDS`: a run's, test's or strategy's boundary and a finding are written at
    once. Measured on Juice Shop without it: a 38.7 s update lag after a quiet phase,
    such as a browser confirmation that sends nothing through the sender.

  Tests: `tests/_downgrade.py` undoes migration 24.
- Reason: the owner asked for data-flow and sequence diagrams backed by one persisted
  model, with observed / inferred / unknown evidence, stable ids, idempotency under
  duplicates, reordering, retries, restart and replay, and measured overhead. The
  survey found no event log, no persisted probe, no test ids and no
  finding-to-exchange link.
- Impact: four new tables, written only by `core.trace` (SP-48). A store of this
  version is refused by an older build (`SchemaTooNew`), as for every migration.
- Risk: low-medium. The store grows with traffic: 68.6 MB for 50,022 events, measured.
  A failed batch is dropped and counted, and the view says so.
- Deliverables:
  - [x] code; `tests/test_trace_model.py`: duplicates, out of order, replay equals
    incremental, restart and re-import, unknown time, backpressure, a failed batch
    counted, four concurrent runs on their own threads, interface grouping, and the
    SP-48 writer guard with its offender. `tests/test_storage_redaction.py`: the trace
    writer under the PA-0100 guard, with its offender — done
  - [x] FR-CORE-505, NFR-CORE-trace-overhead, SP-48/49, ARCHITECTURE, D72,
    `docs/DIAGRAMS.md`, CHANGELOG — done
- Effectiveness (assessed 2026-10-19, measured):
  - loopback pipeline (`scripts/measure_diagrams.py`, 40 points, 480 requests, 5 runs
    each): median 1.214 s with the trace, 1.100 s without (+0.114 s, +10.4 %); the
    recorder's own time 42 ms, 0.087 ms per request;
  - a 50,022-event trace (2,000 interfaces, 218 tests): written at 6.3k events/s,
    0 dropped, maximum lag 3.8 ms; store 68.6 MB; replay (`rebuild`) 5.3–5.9 s;
  - Juice Shop, spider-fed `auto`, alternating on/off: 250.8 / 255.3 s and 265.1 /
    291.7 s, 314 requests and tp=6 in all four (the second pair under other lanes'
    load): no overhead measurable at that noise. 646 events, 193 flushes, recorder
    287 ms in all, maximum lag 0.41 s after `FLUSH_KINDS` (38.7 s before).

### CC-CORE-0062 — Path variation decided on code and data evidence; JS placeholders; files (BUG-0507) (2026-10-19)
- Change (`fuzzlab/core/pathtemplate.py`): `varying_is_parameter` (the one variation
  decision, SP-45), `code_segments` (+ `MAX_CODE_SEGMENTS`), `JS_PLACEHOLDERS` as shape
  evidence, `path_templates(urls, code=...)` (data values only as examples; one
  template per origin and position), `FILE_EXTENSIONS` widened to documents, data,
  configuration, backups and archives.
- Reason: the owner asked for the path variation rules to be fixed after the discovery
  gaps; BUG-0507 (measured on Juice Shop: sibling API routes and an FTP listing's files
  became parameters; `undefined`/`NaN` segments were missed).
- Impact: fewer, truer path templates where the crawl recorded code segments; without
  them only the placeholder, file and one-per-position changes apply.
- Risk: low; pure. A data value the code happens to name no longer counts toward
  variation (two other data values still make the parameter).
- Deliverables:
  - [x] code; `tests/test_path_discovery.py` (the Juice and streaming shapes with their
    code segments, too few values, files, one parameter per position, `code_segments`,
    the one-decision guard and its offender, both kinds of evidence, both importers) —
    done
  - [x] BUG-0507, PA-0507, SP-45, FR-CORE-503, ERROR_LOG, F-074, CHANGELOG — done
- Effectiveness (Juice Shop v20.3.0, 2026-10-19, both tools re-crawled on this code;
  code segments recorded: disco 529, spider 535):
  - disco-fed path parameters: `/rest/products/{id}/reviews`, `/api/Products/{id}`,
    `/rest/track-order/{id}`, `/snippets/{id}`, `/snippets/fixes/{id}`. `/api/{api}`,
    `/rest/{rest}`, `/rest/admin/{admin}`, `/rest/web3/{web3}` and the duplicate
    `{track_order}` are gone (8 templates before, 5 after).
  - spider-fed: `/rest/basket/{id}` and `/rest/track-order/{id}` only (5 before, 2
    after).
  - Scores unchanged: disco-fed tp=5 fp=0, spider-fed tp=6 fp=0, with 31 / 17
    parameters fewer probed.

  Streaming was not re-crawled (its backend was restarting). Its live bundle's segments
  were checked instead: `live`, `username`, `play` present, `matthewpets`, `mr.robot`
  absent, so its templates stay (the test pins this).

### CC-CORE-0061 — `store_url` / `stored_absolute` / `is_loopback_origin` (FR-CORE-504) (2026-10-19)
- Change: `fuzzlab/core/urls.py` gains the three functions.
- Reason: the owner asked that crawled URLs keep their origin on import (2026-10-19);
  measured: secdevlabs-streaming's API template `/live/username/{username}` (on
  localhost:8080) was probed at the page's origin (127.0.0.1:3078).
- Impact: new functions (CC-AUD-0048, CC-FUZZ-0098 use them).
- Risk: low.
- Deliverables:
  - [x] code; `tests/test_import_origin.py::test_store_url_keeps_another_origin_and_reads_back`
    — done
  - [x] FR-CORE-504, SP-46 — done

### CC-CORE-0060 — `core.pathtemplate`: path templates from crawled URLs (FR-CORE-503) (2026-10-19)
- Change: new `fuzzlab/core/pathtemplate.py` (`path_templates`, `id_shaped`,
  `PathTemplate`, `ASSET_EXTENSIONS`, `FILE_EXTENSIONS`).
- Reason: the owner asked for path parameter discovery from crawls (2026-10-19).
  Measured on secdevlabs-streaming's disco capture: `/live/username/matthewpets` and
  `/mr.robot` (one varying position, word values: shape alone misses them), `/play/@…`
  routes, per-streamer assets under `/assets/images/lives/<name>/thumb.png` (must not
  template), and a dotted value (`mr.robot`) that is not a file.
- Impact: new module; used by the importers (CC-AUD-0047).
- Risk: low; pure.
- Deliverables:
  - [x] code; `tests/test_path_discovery.py` (the streaming crawl's URLs; id shapes
    seen once; two parameters, two templates; no template without evidence; variation
    within one origin, named after the segment before) — done
  - [x] FR-CORE-503, SP-45 — done

### CC-CORE-0059 — Path-segment placement; account values with a credential (FR-CORE-501, FR-CORE-502) (2026-10-19)
- Change: `fuzzlab/core/urls.py` (`place_path_param`, `path_placeholder`,
  `PathPlacementError`); `fuzzlab/core/credentials.py`
  (`CredentialStore.set_attributes` / `attributes`: per-account values stored in the
  same keyring entry as the credential; a new `set` drops them).
- Reason: FR-FUZZ-57 and FR-LAB-309 (CC-FUZZ-0096, CC-LAB-0315).
- Impact: new functions only; existing credentials read as before.
- Risk: low. The values are identifiers, kept in the keyring because an object id can
  be the only thing guarding the object.
- Deliverables:
  - [x] code; `tests/test_path_params.py` (placement and refusals; attributes round
    trip, refusals, dropped on a new credential) — done
  - [x] FR-CORE-501/502, SP-42/43 — done

### CC-CORE-0058 — Integration: the project listing reads run targets through `core.runtarget` (2026-10-15)
- Change: `core/project.py`'s run listing drops its own `SELECT base_url FROM target`
  subquery. It reads `runtarget.run_target_rows()` once per listing, the one reader the
  site-tree lane made of the `target` table (FR-CORE-500, its guard).
- Impact (other components / project): UI project pages: the same values (first target
  row by id). One query per listing instead of one per run.
- Risk: low.
- Deliverables:
  - [x] — done
- Effectiveness (assessed 2026-10-15): `tests/test_core_runtarget.py`,
  `tests/test_core_project.py` and `tests/test_web_projects.py` pass.

### CC-CORE-0057 — `procutil`: a started server is up only when its own process listens on its port (BUG-0143) (2026-10-15)
- Change: `fuzzlab/procutil.py` gains:
  - `port_owner(h, port)`: `ours`, `taken` or `none`, read from the server tree's own
    listening sockets (`listeners`, BUG-0130), with one connect to tell `taken` from
    `none`;
  - `wait_until_listening(h, port, timeout=)`: raises `PortTaken` or
    `ServerDidNotListen`, the latter with the server's output;
  - `free_port()`;
  - `start_server_on_free_port(argv_for, boot_timeout=, env_for=, attempts=3, **kw)`:
    pick a port, start, wait for its own listener, and retry a taken port on a fresh
    one.

  It is the one owner of "start a server and know it is up" (SP-31, PA-0003). There
  are two new exceptions, both `ProcUtilError`.
- Impact (other components / project):
  - **LAB** (CC-LAB-0257): the five live-boot harnesses use `port_owner` and
    `PortTaken`.
  - **Tests:** eleven server starts use `start_server_on_free_port`.
  - **Consumers checked from the code, not from memory** (`grep -rln "start_server("`,
    all 23 modules, none truncated):
    - 16 sites converted;
    - 2 allow-listed in the new guard with reasons (a server that reports its own
      address; one that prints READY after its bind);
    - 5 out of scope (`proxy/server.py` and `web/runner.py` use other launchers;
      `test_procutil.py`'s lifecycle tests and the two guard files pick no port).
  - **Guards that pin `start_server`:**
    - `test_loopback_listeners`' two BUG-0130 rules recognise only `start_server` and
      `astart_server`. Without a change, the 11 converted sites would have left both
      rules silently. The rules now also take `start_server_on_free_port` (and
      `env_for=`), with synthetic offenders.
    - `procutil.py`'s allowlisted unpinned launches: 2 → 3 (the delegating call),
      with the reason.
    - `test_procutil_guard`: unchanged here (no new spawn primitive).
  - No product behaviour change: only harnesses and tests call these.
- Risk: low-medium.
  - `port_owner` reads `/proc` socket tables, the same code BUG-0130 relies on at every
    boot.
  - A server whose listener sits outside the supervisor's tree would never be "ours".
    None of the 16 sites has one; all were booted.
  - Mitigated by: real-server tests (a foreign holder, a retry, an early exit), the
    real-Go reproduction, and the AST guard (16/16 pre-fix sites flagged).
- Deliverables:
  - [x] procutil API, tests, guard — done
  - [x] BUG-0143, PA-0149, ERROR_LOG, FR-CORE-41, SP-31 — done
- Effectiveness (assessed 2026-10-15): the deterministic reproduction that booted the Go
  harness against a stand-in server now retries and boots the real app. Parallel
  stability runs of the former serial list are recorded in CC-LAB-0257.

### CC-CORE-0055 — `core.urls.document_key`: which document a URL loads (origin, path and query) (BUG-0138 review) (2026-10-15)
- Change: `fuzzlab/core/urls.py` gains `document_key(url)`: the canonical origin, path
  and query of a URL, the fragment dropped. Unlike `url_key` (origin and path only), it
  tells `/p?a=1` from `/p?a=2`. It is the one definition (PA-0003) of "the document this
  URL loads" for the crawler's `_nav_key` (the reveal and query windows' own-reload
  exemption) and for navguard's `shows_own_document`, `_received_html` and the
  per-page `_RECEIVED` note (BUG-0138 review, reviewer A S1). Made in BUG-0138's review
  commit e7afbb8 and recorded there under CC-CRAWL-0030 / CC-AUD-0043; this entry files
  it in the core library's own log (final merge review, reviewer A M1). FR-CORE-40.
- Impact (other components / project): CRAWL (`spider._nav_key`, navguard) and AUD (the
  fetcher's not-reached cases through navguard) read it. `url_key` is unchanged, so every
  existing key, store row and finding path is unchanged. No schema change.
- Risk: low (an additive pure function). Mitigated:
  `tests/test_guarded_navigation.py` pins the `/p?a=1` → `/p?a=2` case (the old key fails it,
  mutation-checked in CC-CRAWL-0030), and every test file importing `core.urls` passed.
- Deliverables:
  - [x] `core/urls.py` `document_key` — done (e7afbb8)
  - [x] FR-CORE-40 — done
  - [x] cross-reference from CC-CRAWL-0030 — done
- Effectiveness (assessed 2026-10-15): the related run on e7afbb8 (33 files, every test file
  importing `core.urls` included): 1679 passed, 4 skipped, 6 xfailed, 0 failed; on the
  merged tree 80d7070, 118 affected files: 2791 passed, 0 failed.

### CC-CORE-0054 — `Request.session_decision`: the session addon's decision is a declared field (FR-SESS-20, BUG-0134 review round 2) (2026-10-14)
- Change: `fuzzlab/core/http.py` `Request` gains `session_decision: str | None = None`.
  `SessionManager.prepare` sets it to `"anonymous (out of origin)"` when it withholds the
  identity's session (FR-SESS-20); `SeamProbeSender` reads it into `Probe.session`.
  It replaces the dynamic attribute of CC-SESS-0023's round 1 (R6; reviewers A2-S3,
  B2-R6). `HttpClient` neither reads nor changes it.
- Impact (other components / project): SESS (writer), FUZZ (reader). The dataclass gains
  a trailing field with a default, so every existing construction is unchanged; the
  field is not persisted (flows are recorded without it).
- Risk: low (an additive, defaulted field). Mitigated: the seam, auditor and fuzzer seam
  suites pass; `tests/test_session_origin_scope.py::test_prepare_records_its_decision_on_the_request`
  asserts the default and the value prepare sets.
- Deliverables:
  - [x] `core/http.py` field — done
  - [x] FR-CORE-6 amended in place — done
  - [x] test (above) — done
- Effectiveness (assessed 2026-10-14): the related suites, the core seam suites included (`test_core_foundations.py`, `test_auditor_seam.py`, `test_fuzzer_seam.py`): **1490 passed, 2 xfailed, 0 skipped** with `FUZZLAB_REQUIRE_BROWSER=1`; the requirements traceability guard passes.

### CC-CORE-0053 — One open-redirect name set in `core.urls`; the importer skips SPA query seeds that blocked a write (FR-CRAWL-17 review) (2026-10-14)
- Change:
  - **`core/urls.py`:** `REDIRECT_PARAMS` (a frozenset), moved unchanged from
    `tools/fetcher.py`, which re-exports the same object for its redirect rule. The
    crawler's `spa.redirect_name` reads it (PA-0003, review A-S5 / B-S2). FR-CORE-39.
  - **`tools/store_adapter.py`:** `import_spider` imports a page whose `source` is
    `spa.WRITE_SEED_SOURCE` (`'spa-query-writes'`, a SPA query seed whose load blocked
    a write, FR-CRAWL-17) as a page only: no endpoint, parameter, route-query parameter
    or link set (counted `write_seed_skipped`; review A-M1). FR-AUD-22's text says so.
- Impact: AUD (the redirect rule reads the same set; behaviour unchanged), CRAWL (reads
  the set; writes the new source). Downstream FUZZ: a write seed is never a point, so M6
  never replays its write outside a window. No schema change.
- Risk: low. The move is mechanical (`fetcher.REDIRECT_PARAMS is
  core.urls.REDIRECT_PARAMS` is tested). The import skip only removes points, from rows
  that only FR-CRAWL-17 writes.
- Deliverables:
  - [x] code: `core/urls.py`, `tools/fetcher.py`, `tools/store_adapter.py` — done
  - [x] tests: `tests/test_spa_query.py::test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path`
    (the shared object), `::test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it`
    (import + real M6) — done
  - [x] FR-CORE-39 (new), FR-AUD-22 (one sentence) — done
- Effectiveness (assessed 2026-10-14): the S1 test is green with a real browser, and the
  mutation that drops the seed re-filing fails it; `tests/test_store_adapter.py` and the
  json-points suite are still green (numbers in CC-CRAWL-0027's review amendment).
- Amendment (2026-10-14, review round 2): the `store_adapter` import exclusion is filed
  under the auditor as **CC-AUD-0041** (the importer's owner by precedent, CC-AUD-0035 /
  CC-AUD-0040); this entry's core change is the `REDIRECT_PARAMS` move (FR-CORE-39).

### CC-CORE-0302 — PA-0301's spelling scan states its short-stem limit (review L3/L4) (2026-10-15)
- Reserved range: CC-<CODE>-0300..0349 (PA-0031); see CC-LAB-0300. Test and docs
  only, no gate needed.
- Change: `tests/test_destructive_routes_external_labs.py` states that `MIN_STEM = 5`
  never finds a 4-letter word (`wipe`, `drop`) inside a compound, and the rule's own
  token match still sees it standing alone (L3). PA-0301(1) states the same limit.
  `test_the_generated_labs_state_changing_routes_are_enumerated_and_judged` says that a
  failure means a scored cell became unscorable (L4). No assertion changed.
- Impact: none outside the comments; no production code.
- Risk: none (comments and a docstring).
- Deliverables:
  - [x] comment, docstring, PA-0301(1) limit — done
- Effectiveness (assessed 2026-10-15): effective (comments only).
  `tests/test_destructive_routes_external_labs.py`, run alone on a clean worktree at
  64d69a2: 83 passed, 4 xfailed (strict, BUG-0301). No assertion changed.

### CC-CORE-0301 — BUG-0301 recorded: the destructive rule misses Juice Shop's GET password change and data erasure (deferred to the `core/urls.py` lock owner); PA-0301's sweep (2026-10-15)
- Change: documentation and tests only; no production code changes (`fuzzlab/core/urls.py`
  is locked by another session).
  - BUG-0301 recorded in full: `ERROR_LOG.md`,
    `docs/bugs/BUG-0301-destructive-rule-missed-juice-password-change-and-data-erasure.md`,
    and PA-0301. `destructive_reason` and `transaction_reason` return None for
    `GET /rest/user/change-password?current=&new=&repeat=` and `/dataerasure`, so the
    send gate passes both, and the real erasure form passes `form_skip_reason`.
  - New `tests/test_destructive_routes_external_labs.py`:
    - strict xfails for both URLs: the URL rule, the send gate, and the erasure form as a
      POST action;
    - `test_bug_0301_is_what_the_xfails_claim`, and the compensating controls computed;
    - the Juice Shop PA-0114 table (36 routes) and the bWAPP table (39 routes; the
      existing `BWAPP_DESTRUCTIVE_GETS` checked as a subset), each row with its real
      gate's computed verdict, or a residual pinned to None;
    - the generated labs' state-changing routes, enumerated from `lab/manifests/*.yaml`
      and `lab/ground-truth*/`;
    - PA-0301's compound and verb-object spelling scan over every lab route, with
      synthetic offenders.
- Impact: CORE's rule is unchanged. Its consumers CRAWL (link and form gates), AUD
  (captured-request import) and FUZZ (send gate) keep today's behaviour. They gain the
  pinned gap and the tables. The requirement lines are under CC-CRAWL-0300 and
  CC-FUZZ-0300.
- Risk: medium until fixed: an imported change-password URL, or a crawled erasure form,
  would be fuzzed. Mitigated meanwhile by the compensating controls stated in BUG-0301
  (not by a live assertion: the design §5.6 one was not built, see BUG-0301's
  correction; one exploratory full crawl stored neither path). Uncovered residual: a full
  crawl that reaches `/dataerasure` would import and fuzz its server-rendered form. The
  tests carry no risk. The strict xfails turn into hard failures (XPASS(strict)) when
  the rule is fixed. That is intended: per MULTI_AGENT §6 the fixing lane deletes them in
  its own merge, and the stale-disposition check then asks it to drop the two
  `SPELLING_DISPOSITIONS` entries. **The orchestrator (Lane A) must tell the session
  that owns `core/urls.py` about these four markers before this branch merges**. This
  lane cannot reach that session, so the relay is Lane A's.
- Deliverables:
  - [x] BUG-0301 report, ERROR_LOG line, PA-0301 — done
  - [x] strict xfails, reason check, compensating-control test — done
  - [x] Juice Shop and bWAPP PA-0114 tables, generated-lab sweep, spelling scan with
    synthetic offenders — done
  - [ ] lock owner told about the strict-xfail markers (relayed by Lane A) — todo
  - [ ] corrective action in `core/urls.py` (lock owner; suggested fix in BUG-0301) — todo
- Review: the pre-change gate was cleared by design rev 2 (3/3 AGREE, §12); the drafts are in its §10 (CC-FUZZ-0300, CC-CORE-0301) and §12 (CC-CRAWL-0300).
- Effectiveness (assessed 2026-10-15): BUG-0301 itself stays pending until the corrective
  action lands. The tests are effective:
  - `tests/test_destructive_routes_external_labs.py` run alone: 83 passed, 4 xfailed;
  - the sweep found no further gap (BUG-0302..0305 unused).
  - Mutation checks, each restored after:
    - the compound scan matching whole tokens only fails
      `test_no_lab_route_hides_a_destructive_word_in_a_compound` and
      `test_the_spelling_scan_catches_synthetic_offenders`; so does disabling the
      verb-object branch;
    - dropping the `/dataerasure` disposition fails the scan test;
    - removing the `reset_code` field from bWAPP's real `secret_change` form fails that
      table row (its verdict is computed, not asserted).
  - With the corrective action simulated in memory (`dataerasure` token, `(change,
    password)` pair; no file edited), exactly the four strict xfails turn
    XPASS(strict). The reason pin and the stale-disposition check also fail. Those are
    the markers and entries the fixing lane must update in its own merge.
### CC-CORE-0300 — procutil: a public host LISTEN-table reader; the spawn guard knows shells and container CLIs (2026-10-15)
- Reserved range: CC-<CODE>-0300..0349 for this session (PA-0031); see CC-LAB-0300.
- Pre-change gate: part of design rev 2 (reviewers A and B, 3/3), as CC-LAB-0300.
- Change:
  - `fuzzlab/procutil.py`: `host_listen_sockets()` returns a `Listener` (pid 0) for every
    LISTEN socket of this process's network namespace, through the existing
    `_listen_table` parser (PA-0087: no second parser); `netns_of(pid)` / `host_netns()`
    expose the existing namespace readers (added in code review A1: the exposure check
    compares each container's namespace with the host's; BUG-0310, PA-0310(1)). ~20
    lines. FR-CORE-300.
  - `tests/test_procutil_guard.py`: `FORKING_TOOLS` gains `bash`, `sh`, `docker`,
    `podman`, `docker-compose`, `podman-compose`, with six synthetic offenders
    (PA-0034(2)). The sweep (the guard's own AST scan with the new list) found one site,
    `tests/test_lab_labctl_profile_parsing.py`'s `subprocess.run(["bash", ...],
    timeout=10)`, migrated to `run_bounded`.
- Impact: CORE helper consumed by LAB's exposure check (CC-LAB-0300); no existing caller
  changes. The guard flags `subprocess.run`-family calls with a `timeout=` only; an
  unbounded `docker`/`compose` call is held to `run_bounded` by review, not enforced
  (stated in FR-CORE-300 and NFR-LAB-cleanup).
- Risk: low.
- Deliverables:
  - [x] `host_listen_sockets` + real-socket test — done
  - [x] guard extension, offenders, sweep (1 site migrated) — done
  - [x] FR-CORE-300, NFR-LAB-cleanup `Enforced by:` line, CHANGELOG — done
- Effectiveness (assessed 2026-10-15): `host_listen_sockets` sees a real
  loopback listener (`tests/test_external_labs_static.py::test_host_listen_sockets_sees_a_real_loopback_listener`);
  `tests/test_procutil_guard.py` 30 passed, the migrated test 5 passed; the mutation check
  kills an empty host table and a guard without `bash`.

### CC-CORE-0402 — `modelinfo.trained_on`: an unknown value is unknown; the guard's wiring is tested (PA-0402(3)) (2026-10-15)
- Change:
  - **`core/modelinfo.trained_on`:** absent is `run`; `run`, `earlier` and `saved` are
    themselves (an explicit `run` is valid, reviewer B round 3); any other recorded value
    is `None`. It used to be `run`, a default standing in
    for malformed data (PA-0108(2), review A round 2).
  - **`tests/_store_guard.py`:** `guard_kwargs(basetemp)` is the fixture's wiring, now
    tested from a cwd outside and inside the repository.
  - `test_pytest_configure_clears_the_store_variables` calls the hook with host values
    set; the earlier module-fixture check was vacuous without a host value.
  - PA-0403's grep gains `--include="*.py"`, and the guard count is corrected to 33.
- Impact (other components / project): UI `report` shows `unknown` for such a row
  (CC-UI-0402); ML `list_models` shows `-`.
- Risk (level; mitigation or accepted-risk justification): low; such rows only arise
  from corrupt data.
- Deliverables:
  - [x] code and tests (`tests/test_storepath.py::test_a_malformed_trained_on_is_unknown_never_a_default`,
    `::test_the_guard_watches_an_outside_cwd_and_excludes_pytests_basetemp`,
    `::test_pytest_configure_clears_the_store_variables`) — done
  - [x] FR-CORE-400 updated in place — done
- Effectiveness (assessed 2026-10-15): each of the three mutations fails its test.
  Effective.

### CC-CORE-0401 — Store help from the one constant; `core/modelinfo.py`; the store guard is bounded (BUG-0402) (2026-10-15)
- Change:
  - **`core/storepath.py`:** `DEFAULT_RULE` and `store_help()` state the default rule
    from `DEFAULT_STORE`. Every `--store` help and the grouped help use them (no
    restated `./fuzzlab.db`).
  - **New `core/modelinfo.py`:** `trained_on(calibration)` is the one reading of a model
    row's provenance (`earlier` / `saved` / `run`). It lives in core because `report`
    must work in a no-ML build.
  - **`tests/_store_guard.py`:** walks only the repository tree, minus pytest's basetemp.
    A cwd outside the repository has only its own `fuzzlab.db*` stat-checked, never
    walked (BUG-0402). `pytest_configure` clears the store variables before any fixture.
  - **`.gitignore`:** adds `fuzzlab.db-journal`.
- Impact (other components / project):
  - FUZZ, UI, MUT, PROXY help texts.
  - UI `report` and ML `list_models` share `trained_on`.
  - The suite's guard no longer false-fails when pytest runs from outside the
    repository.
- Risk (level; mitigation or accepted-risk justification): low.
- Deliverables:
  - [x] the code above — done
  - [x] tests (`tests/test_storepath.py`):
    - `::test_the_store_guard_never_walks_pytests_temp_base_nor_an_outside_cwd`;
    - `::test_the_default_stays_the_shared_project_store` (pins the literal; a move is
      the owner's decision);
    - `::test_check_writable_refuses_a_fifo`;
    - `::test_tests_run_with_the_store_variables_cleared` (now also via a module-scoped
      fixture);
    - `::test_gitignore_ignores_a_default_store_at_any_depth` (`git check-ignore`)
    — done
  - [x] BUG-0402 (ERROR_LOG, bug report, PA-0402); FR-CORE-400 scoped and updated in
    place — done
- Effectiveness (assessed 2026-10-15):
  - Re-adding the basetemp walk, or walking the cwd, fails the guard test.
  - Removing the `pytest_configure` clear fails `test_tests_run_with_the_store_variables_cleared`
    under a host `FUZZLAB_STORE`.
  - Effective.

### CC-CORE-0400 — One store resolution for every CLI and the web UI; `--store` never required (FR-CORE-400) (2026-10-15)
- Change:
  - **New `core/storepath.py`:** `resolve(value)` → `ResolvedStore(path, source)`.
    - Order: `--store`, then `$FUZZLAB_STORE`, then `$FUZZLAB_STORE_PATH`, then
      `DEFAULT_STORE` (`fuzzlab.db` in the cwd).
    - Pure. An explicit `--store ""` raises a typed `StorePathError`.
    - `from_environ` (never raises: empty = unset, `~` expanded) is the one reader of
      both variables.
    - `check_readable` / `check_writable` are typed boundary checks (missing store,
      missing directory, a directory or FIFO). They only stat.
    - `describe` gives the printed `store: <path> (<source>)` line.
  - **`core/config.py`:**
    - `DEFAULTS["store_path"]` is `storepath.DEFAULT_STORE` (same value).
    - `store_path`'s environment layer goes through `storepath.from_environ` instead of
      the generic one.
    - The web UI therefore resolves exactly as the CLI does, with no `web/` edit.
- Impact (other components / project):
  - Every command that takes `--store` (UI `report`; FUZZ `train run`, `reveal-holdout`,
    `flow-anomaly`; MUT `mutate-run`; PROXY `--record`).
  - The web UI now also honours `FUZZLAB_STORE`. It expands `~` and treats an empty
    variable as unset. **Its default does not move** (`./fuzzlab.db`).
  - The config hash is byte-identical when neither variable is set.
  - `.gitignore` ignores `fuzzlab.db` at any depth. A writer run from a subdirectory
    never leaves a committable store.
  - `tests/conftest.py` gains the store isolation guard (`tests/_store_guard.py`).
- Risk (level; mitigation or accepted-risk justification): low.
  - `load_config` cannot fail because of the store (`from_environ` never raises).
  - The default and the hash are unchanged (tested against the source of truth).
  - Moving to a per-user location is an owner decision with listed preconditions
    (`docs/CLI_WORKING_VS_TRAINING_DESIGN.md` §4.8). It was deliberately not done here, because it would move the UI's
    store under the parallel UI session.
- Deliverables:
  - [x] `core/storepath.py`, `core/config.py`, `.gitignore` — done
  - [x] tests: `tests/test_storepath.py` (precedence, empty/explicit-empty, `~`, no
    writes, typed checks incl. a FIFO, UI-config == CLI for six environments, override
    wins, hash unchanged, never raises, isolation, guard) — done
  - [x] `tests/_store_guard.py` + `tests/conftest.py`: environment cleared per test;
    the session fails on any new or written `fuzzlab.db` (+ sidecars) in the tree — done
  - [x] FR-CORE-400; §8 open question answered — done
  - [x] design gate: `docs/CLI_WORKING_VS_TRAINING_DESIGN.md`, reviewers A and B, 3 rounds, 3/3 — done
- Effectiveness (assessed 2026-10-15):
  - Mutation checks: removing `config`'s `from_environ` use fails
    `test_the_ui_config_and_the_cli_pick_the_same_store`. Removing the explicit-empty
    refusal fails `test_an_explicit_empty_store_flag_is_a_usage_error_not_absent`.
    Making the guard ignore writes fails
    `test_the_store_guard_sees_a_new_store_and_a_write_to_an_existing_one`.
  - Full-suite counts: see CC-FUZZ-0400.
  - Effective.

### CC-CORE-0450 — Project files: migrations 22 and 23 (project metadata, launch provenance, identity), `core.project`, untrusted-file allowlist, newer-schema refusal (2026-10-15)
- Change:
  - `core/migrations.py`: migration 22 — `project` (one metadata row), `launch` (a UI
    job: random `token`, command, redacted argv, target, start/finish, status, exit code),
    `run.launch_id`; post-step stamps `PRAGMA application_id = 0x467A4C62` ("FzLb",
    `APPLICATION_ID`). New `head_version()`; `migrate()` raises `SchemaTooNew` before any
    write when a store is newer than this build (FR-CORE-452).
  - `core/store.py`: `open_store` / `connect` / `Store` take `create=False` (a `mode=rw`
    URI: an existing file only); every connection sets `trusted_schema=OFF`; `Store`
    closes its connection when `migrate()` raises; `start_run` links `launch_id` from
    `FUZZLAB_LAUNCH_TOKEN` (`LAUNCH_TOKEN_ENV`) only to a `launch` row of the same store
    (FR-CORE-451); `ABORTED_PREFIX` + `is_aborted`, the one reader of `mark_aborted`'s note.
  - New `core/project.py` (FR-CORE-450): `inspect` (read-only on the main file; typed
    `ProjectError` from a named error list; refuses non-fuzzlab files, triggers/views, a
    failed `quick_check`), `version_state`, `create` (0600, `O_EXCL`, `O_NOFOLLOW`),
    `ensure_metadata` (`BEGIN IMMEDIATE`; `created_at` = the store's real creation time;
    orphaned `running` launches → `unknown`), `read_metadata` (one validating parser),
    `set_meta` / `add_target` / `rename` (bounded, redacted), `insert_launch` /
    `finish_launch` / `status_for`, `run_history`, `copy_to` (backup API → private
    rollback-journal temp → side-file check → `quick_check` → fsync → hard link → dir
    fsync), `migrate_with_backup`, `make_private`, `sidecar_dir`.
  - `core/redaction.py`: `redact_for_record(dest, value)` — the one writer-side
    redactor for what the UI records (URL userinfo, scheme-less `user:pw@`, sensitive
    query values, a sensitive option's value).
  - `core/secretfile.py`: `locked(path)` — the shared interprocess lock (per-path thread
    lock + `flock` on `<path>.lock`, never mkdirs); `core/credentials.py` now uses it
    (PA-0003; its own mkdir kept).
  - `procutil.astart_server(..., umask=)` — set on the supervisor, inherited by the tree.
- Impact (other components / project): **every store** gains two empty tables, one NULL
  column and the application id on its next open (migration 22), and four project
  columns (`uuid`, `origin_uuid`, `copied_at`, `copy_kind`; migration 23, whose post-step
  gives an existing `project` row a `uuid`) — both additive. **A new refusal surface**:
  the UI now refuses a store whose schema differs in any object definition from what
  fuzzlab's migrations create at its version (the allowlist, BUG-0451/BUG-0453); a
  hand-altered legitimate store is refused there (the CLI still opens it). **Every tool**: `start_run`
  reads one environment variable (unset outside UI jobs → NULL, as before); a store from a
  newer build is now refused instead of written. UI (CC-UI-0450) is the consumer. Tests
  that fake older stores undo migration 22 through the new `tests/_downgrade.py`
  (`test_holdout_seal_table.py`, `test_login_form_isolation.py`). No locked file changed.
- Risk (level; mitigation or accepted-risk justification): medium (a migration and a
  change to the shared `start_run`). Mitigation: additive and atomic (injected-failure
  test, PA-0088), concurrent first opens tested with two processes, legacy-store upgrade
  tested, `SchemaTooNew` mutation-checked; `trusted_schema=OFF` is safe because
  migrations create no trigger, view or schema function (FTS5 works with it off). Stated
  exception to NFR-CORE-central-connection: `copy_to`'s private destination (a WAL
  destination could leave data in a `-wal` the hard link does not carry). Residual: the
  CLI still migrates an older store silently, as before. The allowlist's risk of refusing
  a legitimate store is mitigated by deriving it from the migrations themselves and by a
  history check (all 15 past versions of `migrations.py` build today's schema at every
  version) plus fixtures of every real shape (fresh, legacy v21, v22 migrated, `ANALYZE`d,
  FTS rows); a store altered by hand (or by `ALTER … DROP/RENAME`) is refused with a
  message naming the objects.
- Deliverables:
  - [x] migration 22 + post-step, `head_version`, `SchemaTooNew` — done
  - [x] migration 23 (identity and lineage) + backfill post-step; `mark_copy`, `file_facts`, bounded `summary` — done
  - [x] untrusted-file allowlist (`reference_schema`, `_foreign_objects`, `_version_table_trusted`; every definition compared) — done
  - [x] `Store(create=False)`, `trusted_schema=OFF`, close on migrate failure, launch linkage, `is_aborted` — done
  - [x] `core/project.py` — done
  - [x] `redact_for_record`, `secretfile.locked` (+ credentials), `astart_server(umask=)` — done
  - [x] tests: `tests/test_core_project.py` (new), `tests/_downgrade.py`, contract-writers tables (+`project`, `launch`) — done
  - [x] FR-CORE-450..453, NFR-CORE-central-connection (exception), §5; ARCHITECTURE store-as-contract — done
- Code review round 1 (with CC-UI-0450), fixed: `inspect` queries triggers and views on
  their own (a trigger may share a table's name; reviewer B made one named
  `schema_version` that deleted findings, and it was opened) and also refuses virtual
  tables other than `flow_fts`/fts5, and a non-empty file whose `schema_version` is empty;
  `redact_for_record` strips userinfo through the authority's **last** `@` (a password may
  contain `@`), scheme-relative `//u:p@`, and redacts sensitive names in query-shaped
  fragments and `;name=value` path parameters. Tests:
  `tests/test_core_project.py::test_inspect_refuses_what_is_not_a_fuzzlab_store`
  (same-name trigger, virtual table, empty schema version) and the extended
  `test_redact_for_record_*` matrices.
- Code review round 2 / layout pass: BUG-0451 — the schema check is now an allowlist
  (`reference_schema`, `_foreign_objects`), with foreign `application_id`, non-integer
  versions and a missing `run` table refused; migration 23 (`uuid`, `origin_uuid`,
  `copied_at`, `copy_kind`, post-step backfill) instead of amending the already-pushed
  migration 22 (a v22 store existed: BUG-0452's stray file); `mark_copy`, `file_facts`,
  `summary` (bounded), `run_history` labels; `copy_to(timeout=)`; `redact_for_record`'s
  userinfo pattern made linear (no `\b` scan) and values capped at 4096 characters.
- Code review round 3 (on 8569187; a correctness and a security reviewer, fresh agents):
  - (blocking) BUG-0453 — the allowlist matched tables by name only, so a crafted
    generated column / `CHECK` / `DEFAULT` ran SQLite's own functions without bound on
    open, listing and migrate (`trusted_schema=OFF` stops application functions only) →
    every definition is compared; `schema_version`'s definition is checked before its
    rows are read; a newer file is refused before any other read; length limits on the
    inspect/summary connections. PA-0453.
  - BUG-0454 — deep JSON (`RecursionError`) and oddly typed values (a BLOB `started_at`)
    from a crafted file crashed `inspect` / `run_history` → every value typed at one
    parser (`_text`, `_int`, `_JSON_ERRORS`). PA-0454.
  - BUG-0455 — `redact_for_record` cut values before stripping userinfo, keeping a
    straddling password → userinfo stripped from the whole value, cut last. PA-0455.
  - Non-blocking, fixed: a malformed `copy_kind` / `copied_at` is flagged
    (`identity_malformed`), never silently dropped; tests for migration 23's backfill on a
    v22 row, a v22-migrated and an FTS store in the allowlist's non-vacuity fixture, the
    "unknown exit" label.
- Code review round 4 (on bffa9c1; the same two reviewers): correctness — APPROVE;
  security — 1 blocking: BUG-0456, the definition check compared `str.split()`-normalised
  text (a U+00A0 or a moved comment end compared equal while SQLite read a different
  schema) → byte-for-byte comparison (`_exact_sql`); checked against fresh, `ANALYZE`d,
  v21/v22-downgraded stores and all 15 past migration sets (byte-identical). PA-0456.
  PA-0002 sweep: the only other `" ".join(….split())` in `fuzzlab/` is `core/forms.py`'s
  option-label text (HTML, collapsed as a browser does; not a safety comparison).
  `BACKUPS_DIRNAME` is now the one name for the backups directory (PA-0001).
- Code review round 5 (on 4f6c46b): both reviewers **APPROVE**. Applied the correctness
  reviewer's note: `reference_schema` bootstraps `schema_version` with the migrations' own
  `_ensure_version_table` instead of a second copy of its text (with byte-exact
  comparison, a drift in either copy would refuse every store; PA-0001). Verified: the
  reference equals a fresh store's `sqlite_master` exactly. The security reviewer's
  bypass attempts (NULL vs `''` sql, BLOB sql, NUL/invalid UTF-8, case and `tbl_name`
  variants, a repointed rootpage — refused by `quick_check`, and above its 512 MiB cap only
  wrong-but-typed rows) all failed. **Follow-up (not built; cross-component):**
  `SQLITE_DBCONFIG_DEFENSIVE` on `open_store` and the inspect/summary connections
  (Python ≥ 3.12 `setconfig`) as defence in depth for FTS5 shadow data `quick_check`
  does not validate — a change to every tool's connection, for its own CC entry.
- Effectiveness (assessed 2026-10-15): effective — full suite on a clean detached worktree of 578b2a4 (`FUZZLAB_REQUIRE_BROWSER=1`, real Chromium): **5782 passed, 44 skipped, 11 xfailed, 14 failed** in 63 min. The 14 failures are the labgen `--check` end-to-end tests, each failing on "'gitleaks' executable not found on PATH" (an environment gap; they fail identically on the base cdde39f, and none imports a module this change touches); the skips are missing external tools (gitleaks, nuclei, sqlmap, commix, sstimap, ZAP, gVisor/cgroup v1, MariaDB, bdist_wheel) and two documented spring_boot reproductions. The tree was clean after the run (no `./fuzzlab.db` or other default output; BUG-0452's guard armed). Every test file importing a changed module (48 files): 1681 passed, 0 skipped. Mutation checks: 62 mechanisms, each reverted with its named test failing, then restored. Review gate: two independent reviewers, five code-review rounds, both APPROVE on 4f6c46b (round 5). Store-level: `tests/test_core_project.py` 90 passed.

### CC-CORE-0501 — `runtarget.origin_of`: a malformed stored base URL reads "no origin" (BUG-0500) (2026-10-15)
- Change: `core.runtarget.origin_of(base_url)` -- `canonical_origin` with its documented
  failure (`ValueError` from `urlsplit` on a malformed authority) turned into ``None``;
  `run_origins` uses it, so ML's holdout origins and the site tree do too. FR-CORE-500
  updated in place.
- Why: BUG-0500 (found in the site tree's code review, reviewers A and B): one stored
  target row such as `http://[::1` took every origin reader down. The source fix belongs
  in `core/urls.py`, locked by another session: pinned by
  `tests/test_core_runtarget.py::test_canonical_origin_is_total_for_malformed_authorities`
  (`xfail(strict=True)`), so its fix turns that pin into a failure to remove.
- Impact: a run with such a row reads "origin unreadable" (site tree) / unsealed (ML)
  instead of crashing. No change for well-formed rows.
- Risk: low.
- Deliverables:
  - [x] `origin_of` (~12 LOC) — done
  - [x] tests: `::test_origin_of_is_total` (9 malformed inputs), the strict pin (3),
    `tests/test_web_sitetree.py::test_a_malformed_stored_base_url_is_an_unreadable_origin_not_a_crash`
    — done
  - [x] BUG-0500, PA-0500, ERROR_LOG, sweep with dispositions — done
- Effectiveness (assessed 2026-10-15): `tests/test_core_runtarget.py` 14 passed, 3 xfailed;
  a mutant without the `ValueError` catch fails the malformed-base-url test.

### CC-CORE-0500 — One reader for a run's recorded target; one method key (2026-10-15)
- Change: new `fuzzlab/core/runtarget.py` (`run_target_rows`, `run_target`,
  `run_origins`: a run's target is its first `target` row by id, its origin
  `canonical_origin(base_url)`); `core.evidence.method_key` moved verbatim from
  `ml.dataset`. The readers that each re-implemented the row choice now call it:
  `ml/dataset.target_of` / `target_runs`, `ml/holdout._run_origins` (CC-ML-0500),
  `report/report.build_report`, `web/results.run_detail` / `finding_detail`,
  `web/proxycontrol.create_from_finding` (CC-UI-0501). FR-CORE-500.
- Why: the site tree (CC-UI-0500, built next) needs a run's origin without the ML package, and the
  design gate's sweep (PA-0063(1)/(2), PA-0002) found five private copies of the row
  choice with three different rules: first row (ML), **last** row (`report`), an
  unordered `fetchone` (`run_detail`) and a non-unique `LEFT JOIN` (`finding_detail`,
  the Repeater pivot) that would duplicate a finding over several target rows.
- Impact: ML, report, web readers (CC-UI-0501). No output change for any store current tools write
  (one `run_pipeline` call per run writes at most one target row); only a degenerate
  store with two target rows per run now reads the same row everywhere.
  `core/migrations._backfill_holdout_seal` keeps its own read (a shipped migration
  post-step; allowlisted with that reason).
- Risk: low. Reviewed in the site-tree design gate (reviewers A and B, rev 1-3; the
  sweep list was checked by both against a grep).
- Deliverables:
  - [x] `core/runtarget.py` (~60 LOC), `core.evidence.method_key` (~8 LOC) — done
  - [x] reader switch in ML / report / web (~30 LOC) — done
  - [x] `tests/test_core_runtarget.py`: guard + synthetic offender, first-row rule,
    loopback alias, unusable origin, swept readers agree with the core reader — done
- Effectiveness (assessed 2026-10-15): `tests/test_core_runtarget.py` 5 passed; every
  test file importing a changed module re-run (see CC-UI-0501).

### CC-CORE-0052 — `text_destructive_reason`: texts are never judged through a URL (BUG-0131); card security codes are sensitive (2026-10-14)
- Change:
  - **`core/urls.py`:** `text_destructive_reason(text)` -- `destructive_reason`'s tokens
    and pairs over a whole text, decoded the same way (`_text_tokens`: up to 3 rounds of
    `unquote_plus`, camelCase split) but never parsed as a URL, so a `#` or `?` hides
    nothing. Both rules share `_destructive_tokens`. The URL rule's behaviour is
    unchanged.
  - **`core/redaction.py`:** `SENSITIVE_TOKENS` gains `cvv`, `cvc`, `cvn`, `csc` (a
    payment card's security code), for forms phase 4's G1b (never filled) -- and so
    also for every redaction and import rule that uses `is_sensitive_name`.
- Impact: CRAWL (`spa.form_refusal`, `formnav.option_refusal`, `spa.label_refusal`), AUD
  (`store_adapter.entries_refusal`) use the text rule (BUG-0131 corrective action). The
  new sensitive tokens add redaction and remove such fields from fuzzing (proxy history,
  captured bodies, form import); no benign name in the existing tests collides.
- Risk: low; both changes only add refusals / redactions. The text rule is checked
  against the URL rule on every destructive token and pair and on ordinary texts
  (identical where the old embedding read the text whole).
- Deliverables:
  - [x] code: `core/urls.py`, `core/redaction.py` — done
  - [x] tests: `tests/test_forms_phase4.py::test_a_hash_in_a_label_name_value_or_option_hides_nothing`,
    `::test_the_text_rule_agrees_with_the_url_rule_on_texts_without_a_hash`,
    `::test_no_text_is_judged_through_a_url` (AST guard, PA-0131),
    `::test_the_text_guard_catches_synthetic_offenders`,
    `::test_g1_never_fills_a_sensitive_or_credential_control` (`cvv`, `cardCvc`);
    `tests/test_proxy_redaction.py`, `tests/test_storage_redaction.py` still green — done
  - [x] FR-CORE-28 and FR-CORE-25 text — done
- Effectiveness (assessed 2026-10-14): the `#` cases are refused at all four sites; the
  mutation that restores the old embedding at one site fails its test. Effective.

### CC-CORE-0051 — `procutil` reads a server tree's real listening sockets; exposure fails the stop (BUG-0130) (2026-10-14)
- Change (`fuzzlab/procutil.py`): `listeners(h)` -> `Listener(pid, address, port)` for
  every TCP LISTEN socket held by the server's tree (the supervisor and its
  descendants, only while its pid is held): `/proc/<pid>/fd` socket inodes mapped to
  `/proc/<pid>/net/tcp` and `tcp6` LISTEN rows (`_parse_tcp_table`, LISTEN state 0A
  only; `_decode_proc_net_address`, host-order words; a missing `tcp6` is empty).
  `Listener.is_loopback` uses `ipaddress` (127/8, `::1`, IPv4-mapped loopback).
  `exposed_listeners(h)`, `assert_loopback_only(h)` (raises the new
  `NonLoopbackListener`). `_stop_core` -- `stop_server`, `astop_server` and the safety
  net -- reads the exposed listeners while the server is still up, stops the tree, then
  raises `NonLoopbackListener`; `reap_registered` records it on the leak. The web
  launcher reports exposure on a job's stream at Stop (CC-UI-0053 note). FR-CORE-38's
  contract gains these functions (edited in place).
- Impact: every lab server launched through procutil is checked on its real sockets at
  the one choke point all sites go through; the harnesses also check after boot
  (CC-LAB-0255).
- Risk: low. Read-only `/proc` reads, identity-checked.
- Deliverables:
  - [x] code; tests `tests/test_procutil.py::test_a_server_listening_beyond_loopback_is_caught`
    (the server itself, and a process it forked), `::test_a_loopback_only_server_passes`,
    `::test_the_safety_net_reports_an_exposed_server`,
    `::test_proc_net_tcp_decoding_covers_ipv4_and_ipv6` (IPv6 and the LISTEN filter on
    synthetic rows: this sandbox has no `/proc/net/tcp6`),
    `tests/test_web_runner.py::test_runner_stop_reports_a_job_listening_beyond_loopback` — done
- Effectiveness (assessed 2026-10-14): final targeted offline run (one pytest process,
  `FUZZLAB_REQUIRE_LINT=1`, `FUZZLAB_REQUIRE_BROWSER=1`, including
  `test_loopback_listeners.py`, `test_lint.py`, `test_requirements_traceability.py`):
  **341 passed, 13 skipped** (runsc/cgroup v1 absent; github unreachable by design).
  Mutation (BUG-0130, runtime check and static rule): **15/16 killed**; the survivor
  drops the explicit IPv4-mapped branch, which Python 3.13's `ipaddress` already
  treats as loopback (equivalent here; kept for 3.11/3.12, which the project supports).
- Follow-up (2026-10-14, same branch: the netns change plus reviews A and B; BUG-0130
  "Follow-up"):
  - **Per-namespace reads.** `listeners()` reads one table per distinct
    `/proc/<pid>/ns/net`. A namespace that cannot be read is read per process. Each
    `Listener` gains `netns`.
  - **Exposed means host namespace.** A listener counts as exposed only if it is
    non-loopback and in the host's namespace (`_host_netns`, or the injected
    `host_netns=`). A wildcard listener in a private `unshare -rn` namespace is listed
    but not exposed.
  - **New exceptions.** `ExposedAndLost` (both a `NonLoopbackListener` and a
    `ServerLost`; review B1) and `ListenerCheckFailed`.
  - **Total stop check (review A-M1).** `_stop_core`'s check is total: any exception
    is recorded, the stop, sweep and collect always run, and the error is raised
    afterwards. `_parse_tcp_table` skips unparseable rows. `reap_registered` records
    both new exceptions on the leak.
  - **Docstrings and launcher.** The `run_bounded` docstring is corrected
    (`NonLoopbackListener` instead of `TimeoutExpired`). `assert_loopback_only` states
    "checked after boot, and at stop while live". In the launcher, `shutdown` reports
    an exposure ahead of a lost server, and `_enforce_stop` reports any
    `ProcUtilError`.
  - **Tests.** The deliberately exposed test servers now run in a private network
    namespace (`tests/_netns.py`), so nothing binds a wildcard on the host. FR-CORE-38
    is edited in place.
  - **New tests.**
    `tests/test_procutil.py::test_a_wildcard_bind_in_a_private_netns_is_listed_but_not_exposed`,
    `::test_an_exposed_server_that_was_also_lost_reports_both`,
    `::test_a_failing_listener_check_never_aborts_the_stop`.
  - **Effectiveness.** Final targeted offline run (one pytest process, `FUZZLAB_REQUIRE_LINT=1`, `FUZZLAB_REQUIRE_NETNS=1`, `FUZZLAB_REQUIRE_BROWSER=1`, including `test_procutil.py`, `test_loopback_listeners.py`, `test_lint.py`, `test_requirements_traceability.py`): **377 passed, 13 skipped** (runsc/cgroup v1 absent; github unreachable by design). Mutation: **9/9 killed** (B1 x2, B2 x4, A-M1 x3; BUG-0130 "Follow-up").

### CC-CORE-0050 — BUG-0125 review fixes: an id is trusted only while its leader pid is held (2026-10-14)
- Change (`fuzzlab/procutil.py`, on top of CC-CORE-0048; reviewer A's must-fixes, B's
  items; A-M1 supersedes B's should-fix 1):
  - **A-M1:** the supervisor's `_reap` reaps every exited child except the server (each
    zombie child found in `/proc`, by pid); `_reap_server` reaps the server only after
    the last `killpg` (bounded; loud if it cannot).
  - **A-M2(a):** the owner waits for the supervisor with `waitid(WNOWAIT)` (never
    reaping), sweeps its session while the pid is held, then reaps (`_stop_core`, used by
    `stop_server`, `astop_server` and `reap_registered`). `astart_server` spawns with
    `subprocess.Popen` and returns an asyncio view (`_AsyncSupervisorProc`: stream
    readers, non-reaping `wait()`, `communicate()`), because asyncio's child watcher
    reaps its own children on exit.
  - **A-M2(b):** the fallback's pgid kill requires `st.sid == supervisor pid` (anchor
    held: the supervisor is alive), and it also kills the supervisor's other
    descendants and session members before the supervisor itself.
  - **A-M2(c) + B-2:** `_members(kind, id, start, anchor=None)` trusts an id only while
    its leader pid is held (`_held`: present with the recorded start time, alive or
    an unreaped zombie), or -- for a group whose leader is gone -- inside a held
    anchor session; a start time of 0 is "identity unknown" and matches nothing;
    `start_server` refuses such a server loudly after stopping it; the safety net
    reports such a record (`Leak.note`) without signalling it.
  - **A-S1:** the server's `child_setup` re-checks `getppid()` after its `prctl`.
  - **B-3:** dead code in the safety net removed. **B-4:** `web/runner.py` documents
    why `allow_thread=True` is right (uvicorn's loop on the main thread).
  - **A-N1:** the "pids wrap quickly (pid_max 32768 here)" note in `_members`.
  - FR-CORE-38 updated in place; NFR-LAB-cleanup gains the new tests and the S2
    measurement; PA-0125 gains rule 5.
- Impact: no API change for callers (`kill_process_group` / `group_members` gain an
  optional `anchor`; `Leak` gains `note`). The web runner's `run.proc` is now the
  asyncio view (same `stdout` / `wait()` / `returncode`).
- Risk: medium (all kill paths). Mitigation: a test per must-fix that fails on its
  revert, and a measured Playwright check (S2: 0 of 9 descendants left 5 s after a
  pytest SIGKILL).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_procutil.py` (29, 7 new),
    `tests/test_web_runner.py::test_the_ui_event_loop_runs_on_the_main_thread`,
    `tests/_procs.py` (raw scans for assertions only), guard allowlist updated — done
  - [x] BUG-0125 corrective action (review round 1), PA-0125(5), FR-CORE-38,
    NFR-LAB-cleanup, CHANGELOG — done
- Effectiveness (assessed 2026-10-14): one offline pytest process over the targeted
  files: **283 passed, 13 skipped** (runsc/cgroup v1 absent; github unreachable by
  design). Mutation: **22/26 killed**; every must-fix revert killed (A-M1; A-M2(a)
  reap-before-sweep and asyncio-style reap; A-M2(c) absent leader without anchor, anchor
  session not required; B-2 unknown identity at start). Survivors: the fallback group
  TERM without its anchor (with the leader gone `_members` yields nothing and the
  descendant/session kill that follows reaches the same processes), B-2's explicit
  start-0 guard (subsumed by A-M2(c)), the "no older than the leader" filter
  (unreachable while the leader is held), and A-S1 (a race; not deterministic). None
  lets a signal reach a process this run did not start.
- Review round 2 (2026-10-14; A and B agreed on round 1, four items): **A** every failed
  start (no ready line, an error line, an unrecordable identity) now stops the
  supervisor in `_collect_locked`'s order -- request a stop, D15 fallback if needed,
  wait without reaping, `_sweep_session`, then `proc.wait()` -- instead of SIGKILL and
  reap; **B** `_peek_code` returns `CODE_UNKNOWN` (-256) for a supervisor reaped behind
  its `Popen`'s back, so `_AsyncSupervisorProc.wait()` cannot spin, and the stop path
  reports `killed`; **B nit** `Runner._pump` reads output in a task, waits for the
  supervisor's exit, then drains for at most `Runner.DRAIN_S` (2 s) and says so if a
  survivor still holds the pipe; **A ask** the escaped-grandchild test prints the
  supervisor's stderr on failure and checks "nothing alive" right after `stop_server`
  without waiting; its one intermittent failure was in pid parsing, not that check
  (BUG-0125). New tests: `test_a_server_that_misses_its_ready_timeout_leaves_nothing`,
  `test_a_supervisor_killed_before_ready_is_swept_before_it_is_reaped`,
  `test_an_async_wait_returns_when_the_supervisor_was_reaped_elsewhere`,
  `tests/test_web_runner.py::test_runner_stops_reading_output_a_survivor_holds_open`.
  Effectiveness: **287 passed, 13 skipped** (same targeted offline run); mutation
  **round 2: 4/4 killed**, all lists **26/30** (the same four survivors as round 1).
- Review round 3 (2026-10-14; A and B agreed on round 2): **B** `arun_bounded` returns
  `None`, never `CODE_UNKNOWN`, for an unknown exit status (the launcher and Lab page
  side is CC-UI-0053); **A nit** `_reap_supervisor` waits at most `KILL_BOUND_S`, then
  writes a loud `fuzzlab.procutil:` line and returns False: a failed start leaves the
  handle registered for the session safety net instead of hanging, and a stop marks it
  `unreaped` and keeps it registered (a later stop retries). New tests:
  `test_arun_bounded_never_returns_code_unknown_as_a_status`,
  `test_reaping_a_stuck_supervisor_is_bounded_and_loud`,
  `test_a_failed_start_that_cannot_reap_leaves_the_handle_for_the_safety_net`.
  Effectiveness: targeted offline run **292 passed, 13 skipped**; mutation **round 3:
  7/7 killed** (procutil, runner, labcontrol and both JS handlers).

### CC-CORE-0049 — Forms phase 3 integration: one leaf rule, one SPA-route definition (2026-10-14)
- Change:
  - `core/redaction.py`: `is_identifier_value` (a string by `looks_like_identifier`, a
    non-bool number by its text) and `redact_leaf(segments, value)` (blank by type when a
    key segment is sensitive or the value is identifier-like): the one leaf rule.
    Lane S's `_blank_tree` and lane J's importer (`store_adapter.redact_leaf`, now a
    delegate) both use it; lane J's version had missed numbers (reviewer A, J1).
  - `core/urls.py`: `SPA_ROUTE_PREFIXES` and `is_spa_route_fragment`, the one definition
    of "this fragment is a SPA route"; `core.urls.spa_route` (lane J),
    `tools/spa.spa_fragment` (lane S) and `core.redaction.redact_spa_fragment` (lane S)
    use it (reviewers A and B, J5; PA-0003).
- Impact: FR-CORE-36 / FR-CORE-37 unchanged in behaviour except that a JSON leaf whose
  number looks like an identifier is now blanked at import too.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_json_points.py::test_one_spa_route_definition_serves_every_lane`,
    `::test_one_leaf_rule_serves_capture_and_import` — done
- Review: reviewers A and B asked for both at merge (lane J reviews J1, J5).
- Effectiveness: verified offline.

### CC-CORE-0048 — `procutil`: one owner for every child process tree (BUG-0125) (2026-10-14)
- Change: new `fuzzlab/procutil.py` (FR-CORE-38), a stdlib-only leaf.
  `start_server` launches a supervisor (`sys.executable -I -S fuzzlab/procutil.py`) in a
  new session; the supervisor sets `PR_SET_PDEATHSIG(SIGTERM)` and
  `PR_SET_CHILD_SUBREAPER` (ctypes `prctl`), re-checks `getppid()` against the owner,
  starts the server in a new process group (`PDEATHSIG(SIGKILL)`, `oom_score_adj`
  +500), reports `ready child=… start=… oom_*=…` on a status pipe, and on a stop request
  (stop token on a control pipe + SIGTERM), an unrequested SIGTERM (counted, acted on
  once), owner death (PDEATHSIG, changed parent, control-pipe EOF) or the server's
  exit: SIGTERMs the group and each re-parented descendant once, waits the grace,
  SIGKILLs, reaps, reports `exit reason=… code=… signals=…`, and exits with the
  server's code. No `preexec_fn` in the owner (the single-threaded supervisor uses one
  for the server). `stop_server` / `finish` / `request_stop`, `run_bounded`, asyncio
  `astart_server` / `astop_server` / `arun_bounded`, `kill_process_group`,
  `group_members` / `session_members` / `read_stat`, the registry and
  `reap_registered`. Identity: pidfd + `/proc` start time on every signal; groups and
  sessions member by member, only under a matching or absent leader.
- Impact: LAB (CC-LAB-0254) and UI (CC-UI-0053) use it; labgen's import guard allows it.
- Risk: **medium** (every long-lived child depends on it). Mitigation: real-process
  tests for each property, a mutation check (17/18 killed), loud failure where a
  capability is missing (`SupervisorUnavailable`) or a server is lost (`ServerLost`).
- Design decisions (BUG-0125): D12 thread rule (`allow_thread`), D13 SIGTERM death
  signal, D15 wedged-supervisor fallback, D16 `oom_score_adj`, D17 `allow_thread`
  documented and loud. Deviation from the draft: the supervisor runs by file path with
  `-I -S`, not `-m fuzzlab.procutil` (no dependency on `fuzzlab` being importable from
  the server's cwd; isolated from `PYTHON*` variables).
- Deliverables:
  - [x] `fuzzlab/procutil.py` — done
  - [x] `tests/test_procutil.py` (22), `tests/test_procutil_guard.py` (24) — done
  - [x] FR-CORE-38; ARCHITECTURE (core section, cross-cutting testing) — done
- Effectiveness (assessed 2026-10-14): 22 + 24 passed; owner SIGKILLed with a
  grandchild that escaped group and session (and with `go run` + its binary): nothing
  survives within 10 s; a reused pid is never signalled; mutation 17/18 killed.

### CC-CORE-0047 — The redaction boundary for the crawler's captured requests and SPA route URLs (forms phase 3, lane S) (2026-10-14)
- Change:
  - `core/redaction.py`: `CAPTURE_MAX_BYTES` (64 KiB), `CAPTURE_MAX_DEPTH` (8),
    `redact_captured_body(body, content_type) -> (value, None) | (None, reason)`,
    `redact_url_identifiers(url)`, `redact_spa_fragment(url)` (FR-CORE-37). The body
    redactor first runs `redact_body` (fail closed: a body it would omit is not
    recorded), then blanks sensitively named keys (whole subtree) and identifier-like
    strings keeping the type (`""`, `null`, an empty container). It is total.
  - Why in `core`: the draft (Revision 1) required capture to go through
    `core.redaction` with no second redactor (PA-0003, PA-0100); a typed blanking walk
    and identifier-aware URL redaction did not exist there.
  - Found while building it: SPA fragments are now kept as pages (FR-CRAWL-12), and
    `redact_url` never reads a fragment, so `#/cb?access_token=…` would have been stored
    verbatim. `redact_spa_fragment` closes that before any such row is written.
- Impact (other components / project): FR-CORE-37 (new). Used by the crawler only
  (CC-CRAWL-0016/0017); lane J reads the stored, already-redacted rows. Nothing that
  exists changes (`redact_url` / `redact_body` untouched).
- Risk (level; mitigation or accepted-risk justification): low. New functions; the
  failure direction is "not recorded" (a missed body costs a point, never a secret).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_spa_capture.py` (each name form × value shape, PA-0091;
    identifier values, JSON and form; every "not recorded" reason incl. 64 KiB, depth 9,
    NaN, a 5,000-digit integer, a trailing comma with a secret, multipart, a scalar;
    sniffed `text/plain`; totality; URL and fragment redaction); the PA-0100 producer
    guard in `tests/test_storage_redaction.py` extended to `discovered_requests` (both
    capture redactors required), proven on synthetic offenders — done
  - [x] FR-CORE-37; NFR-CORE-secrets `Enforced by` — done
- Review: design agreed by reviewers A and B (p3 draft revisions 1–4); code review
  pending.
- Effectiveness (assessed 2026-10-14): verified offline (unit and real-browser tests;
  the mutation check of lane S's gates kills each redaction mutant). The live Juice
  Shop re-crawl is pending.
- Code-review fixes (2026-10-14; reviewers A and B AGREE subject to these; a new
  commit on top of the first):
  - *Must-fix 1 (B; A: should-fix): the boundary must not depend on the encoding.*
    `redact_captured_body` now blanks a non-bool `int`/`float` whose text
    `looks_like_identifier` to `null` (`{"cardNum": 4716190207394368}` was stored while
    its form twin was blanked), and replaces an identifier-like key or form name with
    `REDACTED_KEY` (`__REDACTED_KEY_<n>__`, numbered per body, the same key one name),
    its value blanked. Tests: a card number, a 19-digit id and a nested PAN become
    `null` while `expMonth`, `expYear`, `quantity` and `price` are kept; identifier-like
    keys in JSON and form bodies; a JSON-vs-form parity test over the same values.
  - *Should-fix 2 (decided under the operator's standing instruction): security
    answers.* `is_sensitive_name` gains `SENSITIVE_PAIRS` -- the adjacent whole tokens
    (`security`, `answer`), (`secret`, `answer`), (`recovery`, `answer`), plural
    folded. The bare token `answer` is deliberately not added (quiz and survey fields).
    This widens the one predicate every redaction site uses (proxy history, the HTTP
    recorder, logs, crawled forms): only the safe direction (more is redacted). Tests:
    `securityAnswer` (JSON) and `security_answer=` (form) blanked; `answer`, `answers`,
    `quizAnswer`, `answer_security`, `securityQuestion` kept.
  - FR-CORE-37 updated in place.
  - Effectiveness of the fixes: each new redaction gate is mutation-checked (killed;
    46 of 46 over lane S, CC-CRAWL-0017).
### CC-CORE-0046 — The `json` point location; SPA routes; the send-time DELETE gate (forms phase 3, lane J) (2026-10-14)
- Change:
  - `core/jsonbody.py` (new): the one convention for JSON-body points (PA-0003).
    `LOCATION = "json"`, `ENCTYPE = "application/json"`, `MAX_LEAVES = 64`,
    `MAX_DEPTH = 16`; `leaves(body)` (a JSON object's leaves in document order, empty
    containers kept as leaves; None over the limits), `display_name(path)` /
    `parse_name(name)` (keys joined by `.`, indexes as `[n]`, `\ . [ ]` escaped in a
    key; exact inverses, linear), `name_segment`, `segments_of`, `decode_entries` (the
    one reader of a stored JSON entry list, PA-0108: shape, types, finite numbers,
    no repeated or nested paths), `encode_entries`, `build`, `normalize_entries`,
    `replace_leaf`, `body_for` (the body a `json` send carries; `JsonPlacementError`
    when a leaf cannot be placed), `loads` (NaN/Infinity rejected).
  - `core/urls.py`: `spa_route(url)` (an SPA hash route's path and query, `#/` or
    `#!/`), `to_route_path(url)` (`to_path` plus `#<route path>`: how a `fragment`
    point's endpoint is stored), `REFUSED_SEND_METHODS = {"DELETE"}` and a `method`
    argument on `check_send_url` (a DELETE is refused unless its URL was explicitly
    enumerated).
  - `core/features.py`: `extract_candidate_v1`'s `loc_body` is 1 for `json` too
    (`_BODY_LOCATIONS`); documented as CC-ML-0030. No stored vector changes (no row had
    location `json` before), so `CANDIDATE_FEATURE_VERSION` stays 1.
- Impact: FR-CORE-36 (new). No migration: `form.enctype`, `form.entries` and
  `parameter.location` are free text (confirmed: `form.enctype` has no CHECK and is
  read only by `core.forms`, whose `is_link_set` is false for `application/json`;
  `parameter.location` has no CHECK). Users: the importer (AUD, CC-AUD-0035), the
  point builder, senders, oracle binding and the M6 executor (FUZZ, CC-FUZZ-0068).
  Every existing `check_send_url` caller keeps its behaviour for every method but
  DELETE.
- Risk: low. A route endpoint (`/#/search`) is stored outside `to_path` form; only
  `fragment` parameters use it, and their findings are written at `to_path` (`/`).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_json_points.py` (round trip over adversarial keys, the
    malformed-name and malformed-entry tables, limits, route helpers, the DELETE gate
    per sender) and `tests/test_sender_conformance.py` (the `json` location) — done
  - [x] FR-CORE-36 — done
- Review: phase 3 design (`p3-spa-draft.md`, revisions 1–4), agreed by reviewers A and
  B; implementation review by the orchestrator pending.
- Effectiveness: verified offline, 2026-10-14 (lane J test run; the DELETE gate,
  the leaf/depth limits and the entry parser are killed mutants — see CC-FUZZ-0068).
  The live Juice Shop run is the remaining check.
- Review follow-up (2026-10-14; reviewers A J2 and B4):
  - `core/oracle_status.py`: the `INCONCLUSIVE` comment now reads "could not be
    decided: a cost cap stopped a started check, or no mechanism could place the
    point" (value and `UNLABELLED` unchanged); FR-CORE-33 reworded to match.
  - `core/jsonbody.replace_leaf` raises `JsonPlacementError` for a leaf the captured
    entries do not have, instead of appending it; an empty entry list still takes the
    leaf as the whole body. FR-CORE-36 updated.
  - Effectiveness: both are killed mutants (CC-FUZZ-0068's follow-up).

### CC-CORE-0045 — One transaction-word rule (forms phase 3, shared prerequisite) (2026-10-14)
- Change:
  - `core/urls.py`: `TRANSACTION_TOKENS` (checkout, purchase, pay/payment, order,
    transfer, redeem, wallet, membership, subscribe/subscription, buy, donate/donation,
    deposit, withdraw/withdrawal, topup), `TRANSACTION_PAIRS` (top up, check out) and
    `transaction_reason(text)`: a URL (path, query and SPA fragment), a route path or a
    button label, tokenised like `destructive_reason`, a trailing plural folded.
- Impact: FR-CORE-35 (new). Used by forms phase 3: lane I refuses to submit such a form
  (route, label), lane J never imports a captured request to one (URL). Visiting such a
  page is not refused; nothing else changes.
- Risk: low (a new predicate; no caller yet).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_transaction_words.py` (every word as label, route, URL and
    plural; pairs; decoded and camelCase; ordinary words) — done
  - [x] FR-CORE-35 — done
- Review: phase 3 design, reviewer B must-fix 2 (one shared list next to
  `DESTRUCTIVE_TOKENS`, PA-0003); agreed by reviewers A and B.
- Effectiveness: verified offline.

### CC-CORE-0044 — One origin-scope predicate (BUG-0123) (2026-10-14)
- Change:
  - `core/urls.py`: `origin_scope(*urls)` (the canonical origins of the non-empty
    URLs) and `in_origin_scope(url, origins)` (`ws`/`wss` compared as `http`/`https`; a
    URL with no `://` is never in scope). Both build on `canonical_origin`, so loopback
    aliases on one port are one origin and other 127/8 addresses stay distinct.
- Impact: FR-CORE-34 (new). Used by the spider, the auditor's fetcher, the M6 executor
  and `navguard`.
- Risk: low (new functions).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_origin_scope_is_scheme_host_and_port`,
    `test_origin_scope_ignores_empty_inputs` — done
  - [x] FR-CORE-34 — done
- Review: with CC-CRAWL-0015.
- Effectiveness: verified offline.

### CC-CORE-0042 — Link sets in `form`; one header-point name rule; credential-name predicate (forms phase 2, lane A) (2026-10-14)
- Change:
  - `core/forms.py`: `LINK_SET_ENCTYPE` (NULL), `is_link_set(row)`,
    `first_link_set(conn, run_id, path)` — the one store reader of `form.enctype`
    (guard test: no other module selects it). The migration-20 comment states the
    widened meaning. No schema change, no migration.
  - `core/http.py`: `HEADER_POINT_DENY` (framing, routing incl. `x-forwarded-proto/
    scheme/ssl/port/prefix/server/uri`, `x-original-host`, `x-http-host-override`,
    method override, credential), `header_point_refusal`, `HeaderPointRefused`,
    `check_send_header`. `X-Forwarded-For`, `X-Real-IP` and `Client-IP` are allowed.
  - `core/redaction.py`: `CREDENTIAL_TOKENS` / `is_credential_name` (moved from
    `harness.auto`, which keeps `_credential_name` as an alias).
  - `core/oracle_status.py`: `PENDING`'s definition also covers rows a safety breaker
    stopped (reason in metrics); no value or set changes.
- Impact: as FR-CORE-32. Existing stores are read unchanged: every Phase-1 `form` row
  has a non-NULL `enctype`.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase2.py`) — done
  - [x] FR-CORE-32 — done
- Review: as CC-FUZZ-0063 (item 3: one predicate; item 2: deny-list; should-fix 2).
- Effectiveness: verified offline.

### CC-CORE-0043 — `inconclusive` oracle status (FR-FUZZ-45) (2026-10-14)
- Change: `core/oracle_status.INCONCLUSIVE = "inconclusive"`, in `UNLABELLED`. It means
  a confirmer started a check but could not decide within its cost cap. FR-CORE-14
  and FR-CORE-17 are amended, and FR-CORE-33 is added.
- Impact:
  - **ML:** every consumer reads labelled vs unlabelled from `UNLABELLED` alone
    (`ml/dataset`, `ml/train` gate and metric inputs, `web/mlview`), so these rows
    are never training labels, with no consumer edit.
  - **Other paths:** `forward_skip_reason` and `oracle_skipped` key on
    `SKIPPED_BUDGET` only and are unaffected.
  - **Schema:** none (migration 13's column has no CHECK).
  - **History:** the migration-13 comment is left as history; `oracle_status.py` is
    the single definition.
- Risk: low.
- Deliverables:
  - [x] constant — done
  - [x] tests: `tests/test_oracle_sqli_string.py::test_cap_exhaustion_is_inconclusive_never_a_negative`
        (status, dataset exclusion, metrics) — done
  - [x] FR-CORE-33 — done
- Review: reviewers A and B (lane C cap-exhaustion decision: B required a status; A
  agreed).

### CC-CORE-0041 — Migration 21: `form.password_fields` (forms phase 2, lane B) (2026-10-14)
- Change:
  - **Migration 21:** `ALTER TABLE form ADD COLUMN password_fields TEXT NOT NULL
    DEFAULT '[]'`: the names of a form's password controls, as a JSON list.
  - **Writer:** `store_adapter._import_forms`, from the control kinds (the authoritative
    signal, PA-0008). **Reader:** `harness.auto._password_fields`, the one parser
    (PA-0108); a malformed value fails closed.
  - **Legacy rows** read `[]`, truthfully: no password form was imported before.
  - `tests/test_holdout_seal_table.py` now derives the schema head from `MIGRATIONS`
    (PA-0001) instead of the literal `20`.
- Impact:
  - **Store contract:** one column with a default; existing readers are unaffected.
    ARCHITECTURE's store-contract table is updated.
  - **Consumers:** `harness.auto` (CC-FUZZ-0064).
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_login_form_isolation.py`: a v20 store upgrades and its rows
        read `[]`; a malformed value fails closed) — done
  - [x] FR-CORE-31; ARCHITECTURE — done
- Review: lane B v2 (Option M approved with migration 21, CC-CORE-0041, FR-CORE-31).
- Effectiveness: verified offline; live pending.

### CC-CORE-0040 — Shared identifier-like value predicate (`looks_like_identifier`) (2026-10-14)
- Change:
  - **`core/redaction.looks_like_identifier(value)`:** one total predicate (PA-0096)
    for "this value looks like a secret identifier", whatever its parameter is
    called.
  - **How it decides:** the value is split on `. : @` and whitespace, and on `/` too
    when it is a URL or an absolute path (contains `://` or starts with `/`).
    Elsewhere `/` belongs to standard base64. A piece drawn only from
    `[A-Za-z0-9_-+/=]` is identifier-like when either rule holds:
    - **R1:** at least 16 characters, with a digit or with both upper and lower case;
    - **R2:** 8–15 characters, with a letter and a digit, and a Shannon estimate of at
      least 32 bits.
  - **Exemptions:** a matching piece is still exempt when it is
    - **word-shaped:** every `_`/`-`/`/`/`+` part is a word (lower, Capitalised, ALLCAPS or
      CamelCase) with at most four trailing digits, or one to four digits, as in
      `directory_traversal_1` or `ProductDetailsPage`;
    - **a date:** `2026-10-14` or `2026-10-14T10`.
  - **Accepted misses:** about 0.3% of random hex, base32 and base64 tokens the rules
    would otherwise catch (79 of 29,471 measured), 0.6% of 16-character standard base64
    tokens (58 of 10,000), and almost none at 24 or more characters.
  - **Raw query text:** splitting word parts on `+` keeps raw multi-word text
    (`The+Fellowship+of+the+Ring`) from counting as an identifier.
  - **Linear time:** the word pattern has no nested quantifier over the same
    characters. The first version's `(?:[A-Z]?[a-z]+)+` backtracked exponentially on a
    long word followed by `=` (caught at review; never committed). A sweep of
    `fuzzlab/` for nested quantifiers found only deliberate ReDoS payloads in
    `oracle/strategies.py` and labgen, plus the delimiter-separated `livefilter._RULE_ID`
    and `redaction._FORM_SHAPE`, which are safe.
  - **Caller contract:** pass the raw value (percent-decoded, not form-decoded),
    because form decoding turns base64's `+` into a space.
  - **Partial claim:** a URL whose path has a random-looking piece (`/a/c123456789`)
    is identifier-like by R2.
  - **Why:** forms phase 2 lanes A (redacting tokens in link sets and header-point
    URLs) and B (cookie-value distinctness) need the same convention; one definition
    keeps them from drifting apart (PA-0003, PA-0021).
- Impact:
  - **New API, no callers yet:** lanes A and B import it; their own CC entries
    record the behaviour.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_identifier_predicate.py`): the table (bWAPP names and
        values, the importer's fillers, word-shaped names, paths, standard base64 with
        `/`), totality extremes (PA-0096), linear time on 1 MB and near-miss values
        (PA-0095; shown to hang on the backtracking pattern first), and a
        defined-once check — done
  - [x] mutation check: 14/14 mutants killed (thresholds, exemptions, splits,
        totality; with CC-SESS-0017's listener) — done
  - [x] FR-CORE-30 — done
- Review:
  - **Specs:** reviewer A and reviewer B each specified a version; both misfired on
    ordinary values (fillers, `lang_en.php`, long text).
  - **Unified spec:** proposed by the orchestrator. Reviewer A required a split on
    `/` and `@` as well, so URLs with digits in the path are not identifiers.
    Reviewer B required the word-shaped and date exemptions (names like
    `directory_traversal_1.php` matched R1) and the extremes in the table test.
  - **Second round:** both reviewers found the backtracking word pattern. Reviewer B
    found that the unconditional `/` split missed 10% of 16-character standard
    base64. Both are fixed as above.
  - **Third round:** reviewer A AGREED, after the `+` word split. Reviewer B
    AGREED on the same state; their should-fix (an atomic "once" in the logout
    listener) is recorded under CC-SESS-0017.

### CC-CORE-0039 — Form records and classification; migration 20 (`form`); `update`/`insert` deny tokens (BUG-0114); anti-CSRF names redacted (2026-10-13)
- Change:
  - **`core/forms.py`:** `control_kind`, `controls`, `is_selector_form`, `form_method`,
    `form_record` (entries with password and sensitive values blanked; selector
    options).
  - **Migration 20:** `form(id, run_id, endpoint_id, enctype, entries)` and
    `parameter.form_id` (NULL for legacy rows).
  - **`core/redaction`:** `nonce`, `wpnonce` and `csrfmiddlewaretoken` are now
    sensitive.
  - **`core/urls`:** `insert`, `updatedb` and `dbupdate` are deny tokens.
    `update`/`upgrade` are denied as a script name, a query verb (`?action=update`), or
    next to a database word. The bare word would block the ForgeCart lab's
    ground-truth routes (BUG-0114 / PA-0114; reviewers A/B).
- Impact:
  - **Store contract:** a new table and a column; readers are unaffected.
  - **Redaction:** it covers more names, in logs too.
  - **Behaviour:** `update.php`-style scripts and URLs with an `insert` token are no
    longer crawled or probed (unless explicitly enumerated).
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase1.py`; the migration-19 downgrade test now undoes
        20 too) — done
  - [x] FR-CORE-29 — done
- Review: reviewers A and B, forms phase 1 draft v1 (changes required) → v2 (AGREED,
  both, with A's two required changes and B's nit adopted), plus the live-run filler
  deviation (AGREED, with `.invalid` fillers).
- Effectiveness: verified offline (mutation check 27/27) and live (bWAPP).

### CC-CORE-0038 — `core.urls.destructive_reason` / `check_send_url` (BUG-0111/0112); NFR traceability (PA-0112) (2026-10-13)
- Change:
  - `core/urls.py` gains:
    - `destructive_reason(url)`: decoded, camelCase-split, whole-token and pair
      matching against `DESTRUCTIVE_TOKENS` / `DESTRUCTIVE_PAIRS`; `format` is
      excluded;
    - `url_key(url)`: canonical origin plus path;
    - `check_send_url(url, explicit)`, raising `DestructiveUrlRefused`;
  - `requirements.md` gains traceability lines for NFR-CORE-no-bypass (not yet
    enforced) and NFR-CORE-secrets (partly).
- Impact:
  - **CRAWL, AUD, FUZZ, SESS:** they use the rule (their own entries);
  - no store or schema change.
- Risk: low. The rule only adds refusals. False positives cost coverage, recorded
  (`password_reset`).
- Deliverables:
  - [x] the rule and the gate — done
  - [x] tests: positives (encoded, camelCase, pairs), negatives — done
  - [x] FR-CORE-28 — done
- Review: reviewers A and B, draft v1 (changes required) → v2 (AGREED, both).
  - **Adopted:** the extended token list and decoding (A3/B5), canonical allowance
    keys (B nit).
  - **[DEV] `format` excluded:** accepted by both.
- Effectiveness: verified by `tests/test_destructive_urls.py`; the mutation check
  killed 31/31.

### CC-CORE-0037 — `core.forms`: HTML form entry-list serialisation (BUG-0110) (2026-10-13)
- Change:
  - new `fuzzlab/core/forms.py`:
    - `form_entries(form)` returns an ordered `FormEntries` list of `(name, value)`
      pairs, following §4.10.21.4;
    - `submitter` / `submitter_overrides`, `owned_controls` (form ownership,
      including `form=`), `select_values`, `option_value`, `textarea_value`,
      `default_value`, `is_disabled`;
  - `RULES` lists each implemented rule with its spec step (PA-0111);
  - `FormEntries.get` returns the last value for a name (what `$_POST` and `dict()`
    see); `replace` sets a name in place.
- Impact:
  - **SESS:** the login detector uses it;
  - **AUD:** `tools/fetcher.py` uses `default_value`;
  - no store or schema change.
- Risk: low. A new pure module; every rule has a fixture, and the mutation check killed
  26/26.
- Deliverables:
  - [x] `core/forms.py` — done
  - [x] `tests/test_form_entries.py` (rule-table guard plus a fixture per rule) — done
  - [x] FR-CORE-27 — done
- Review: reviewers A and B both AGREED the BUG-0110 draft with required changes, and all
  were adopted:
  - **A:** form ownership, listbox and optgroup rules, the first enabled submitter
    stated as a deviation, the unnamed image submitter, the FR ids, the PA wording, the
    sweep widened to redirects and cookies;
  - **B:** ordered pairs instead of first-wins, presence-not-truthiness fixtures, a
    machine-checked rule table, submitter overrides refused.
  - **Implementation round:** both AGREED. Both found that a disabled `selected`
    option was replaced by the first enabled one (a browser sends nothing for it); that
    is fixed (`select-selected-disabled-not-sent`). Their nits are recorded as module
    limitations: duplicate form ids and `_charset_`.
- Effectiveness: verified live. `session print` against the loopback bWAPP now
  authenticates.

### CC-CORE-0036 — One fail-closed storage-redaction boundary (BUG-0099/0100); recorder redacted; durable-or-told fsync (BUG-0105); keyring lock and verified delete (BUG-0108/0109); evidence parser (BUG-0107); migration 19 (BUG-0104) (2026-10-13)
- Change:
  - **`core/redaction.py` (BUG-0099 / BUG-0100).** It gains the storage boundary:
    - `redact_query` / `redact_url` / `redact_body` and the per-type helpers, moved
      from `proxy/redact.py`;
    - `MAX_REDACT_BYTES`, `MAX_JSON_DEPTH`;
    - the whole-body scan `mentions_sensitive_name`;
    - sniffing (`body_kind`);
    - the omission markers.
  - **`core/http.py`.** `_record` redacts the URL and both bodies (a case-insensitive
    content type). `send` calls `session.authorize` after a plugin changes the URL.
  - **`core/secretfile.py` (BUG-0105).** `_fsync_dir` skips only `UNSUPPORTED_ERRNOS` or
    a missing `O_DIRECTORY`; otherwise `DurabilityUnknown` after the rename.
  - **`core/credentials.py` (BUG-0108 / 0109).** A lock (thread + `flock` on
    `<keyring>.lock`) is held across load → save; `delete` verifies the entry is gone;
    `DurabilityUnknown` becomes a `CredentialError` saying "retry is safe".
  - **`core/evidence.py` (new, BUG-0107):** `parse_evidence` / `display_evidence`.
    `core/anomaly_flags` uses the display form.
  - **`core/migrations.py` (BUG-0104).** Migration 19 adds `holdout_seal` and
    `holdout_seal_meta`. `POST_STEPS = {19: _backfill_holdout_seal}` runs in the
    migration's own `BEGIN IMMEDIATE` transaction.
- Impact (other components / project):
  - **PROXY** re-exports the redaction functions.
  - **ML** reads and writes `holdout_seal` and uses the evidence parser.
  - **SESS:** `authorize`.
  - **PLUG** (CC-PLUG-0009): the guard allow-list.
  - **Contract changes:**
    - schema version 19;
    - FR-CORE-6's "raw bytes" becomes "redacted bodies";
    - an unparseable or oversized redactable body is stored as a marker.
- Risk: medium (a schema migration with a backfill). Mitigated by:
  - the migration being transactional;
  - an upgrade test from 18;
  - six concurrent upgraders backfilling once;
  - readers proven write-free.
- Deliverables:
  - [x] storage boundary + recorder — done
  - [x] directory-fsync swallow list — done
  - [x] keyring lock + verified delete — done
  - [x] evidence parser — done
  - [x] migration 19 + backfill — done
  - [x] tests: `test_storage_redaction`, `test_secretfile`, `test_holdout_seal_table`,
        `test_dataset_evidence` — done
  - [x] FR-CORE-6 / FR-CORE-25 amended, FR-CORE-26 added — done
- Implementation divergence: none.
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-CORE-0035 — Plural-aware secret names (BUG-0090); complete, fsynced, atomic secret files (BUG-0096) (2026-10-13)
- Change:
  - **`core/redaction.py` (BUG-0090).** `_fold` drops a trailing plural `s` only when
    the folded form is itself sensitive (`passwords`, `secrets`, `sessions`, `jwts`,
    `pwds`, `apiKeys`). `keys` follows `key`'s rule. `passes`, `passage`, `hotkeys`,
    `monkeys` and `keystrokes` stay readable, and `pass` is never folded to `pas`.
    Accepted harmless false redactions: the whole names `codes` / `pins`, and
    `session_count`.
  - **`core/secretfile.py` (BUG-0096).**
    - `write_secret` loops `os.write` over a `memoryview` until complete, raises
      `OSError` on no progress, and `fsync`s.
    - New `create_secret`: `O_EXCL|O_NOFOLLOW` 0600; a partial file is removed on
      failure.
    - New `replace_secret`: a unique temp file (via `create_secret`), `os.replace`, and a
      guarded directory `fsync`. On error the temp file is removed and the original is
      untouched.
  - **`core/credentials.py`:** the encrypted-file keyring saves through
    `replace_secret` instead of a fixed `.tmp` name plus an unconditional replace.
- Impact (other components / project):
  - **PROXY** (CC-PROXY-0020): the redactor and the CA use these.
  - **Logs:** `core.obs` redaction gains the plural fold through the shared predicate.
  - No interface removed: `write_secret` keeps its signature.
- Risk: low. Each helper is tested with a real kernel short write (`RLIMIT_FSIZE`, in a
  child process), injected zero-progress, rename failures and symlinks. The keyring
  round-trip and its failure path are tested.
- Deliverables:
  - [x] plural fold — done
  - [x] `write_secret` loop + fsync; `create_secret`; `replace_secret` — done
  - [x] keyring on `replace_secret` — done
  - [x] tests: `test_secretfile` (new), `test_proxy_redaction` (names) — done
  - [x] FR-CORE-25 amended — done
- Implementation divergence: none.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-CORE-0034 — Shared safety helpers (`core.net`, `core.redaction`, `core.secretfile`); atomic, race-safe migrations (BUG-0080, BUG-0084, BUG-0079 sweep, BUG-0087) (2026-10-13)
- Change:
  - **`core/net.py` (BUG-0080):** `is_loopback_host` (`localhost`, 127/8, `::1`,
    IPv4-mapped) and `require_loopback`. This is the one listener gate (FR-CORE-25).
  - **`core/redaction.py` (BUG-0084):** `is_sensitive_name` by name token.
    `core.obs` uses it. **Behaviour change:** log extras `author` and `tokenizer` are
    no longer redacted; `key`, `api_key` and `session_id` now are.
  - **`core/secretfile.py` (BUG-0079):** `write_secret`, which creates the file 0600
    with `O_NOFOLLOW` and `fchmod`s it before writing. The encrypted keyring backend
    (`core/credentials.py`) uses it, a sweep fix (it used to write, then chmod), and
    creates its directory `0700`.
  - **Migrations (BUG-0087).** `migrate` applies each migration in an explicit
    `BEGIN IMMEDIATE` transaction:
    - the version is re-read inside the lock;
    - statements run one by one (`split_statements`, via SQLite's
      `complete_statement`);
    - `COMMIT`, or `ROLLBACK` and re-raise;
    - `isolation_level` is restored in a `finally`.

    `open_store` sets `busy_timeout` first and retries the WAL switch (`_set_wal`,
    10 s), which bypasses the busy handler (FR-CORE-24).
- Impact (other components / project):
  - PROXY, SESS, the web app and the oracle's OOB listener use the helpers.
  - No schema change: the migrations build the identical schema, as a test asserts.
- Risk: low-medium. The migration runner is on every store open. A
  schema-equals-reference test, a failure-injection test, and a 4-process race test
  cover it.
- Deliverables:
  - [x] `core.net`, `core.redaction`, `core.secretfile` — done
  - [x] atomic migrations and the WAL retry — done
  - [x] tests: `test_migrations_atomic`, `test_loopback_listeners`, the keyring mode in
        `test_credentials`, obs in `test_proxy_redaction` — done
  - [x] FR-CORE-24 / FR-CORE-25 added — done
- Implementation divergence: the WAL-switch retry was added after the race test still
  failed on "database is locked" (reviewer B had predicted it), and `core.secretfile`
  was split out when the sweep found the keyring backend.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-CORE-0033 — `pending` oracle status (BUG-0071); `Store.mark_aborted` (BUG-0078) (2026-10-13)
- Change:
  - `core.oracle_status.PENDING = "pending"`, and `UNLABELLED` now includes it. The
    pipeline writes it for every confirmable row before the oracle loop. A row a crash
    never reached is therefore unlabelled (never training data), but still scored,
    ranked and anomaly-scored.
  - `Store.mark_aborted(run_id, exc)` records `notes = "aborted: <Type>: <msg>"` (or
    `"aborted: exit N"` for `SystemExit`, truncated to 500 characters) after a rollback
    of any half-written statement. It is best effort and never masks the error being
    handled. It is used by `fuzzlab auto`, `greybox-run` and `run_targets`.
- Impact (other components / project):
  - **The status vocabulary gains one value** (no migration: `oracle_status` is free
    text). Every reader goes through `UNLABELLED` (`ml/dataset.py`, `ml/train.py`,
    `web/mlview.py`, `web/results.py`, swept).
  - The `run.notes` column, already shown in the runs list and the report, now carries
    abort reasons.
- Risk: low.
- Deliverables:
  - [x] `PENDING` — done
  - [x] `Store.mark_aborted` and its test — done
  - [x] FR-CORE-14 note — done
- Review: the review-phase draft agreed 3/3. `mark_aborted` moved into core from the
  CLI during implementation, so the three guarded paths share it (PA-0003).
- Effectiveness (assessed 2026-10-13): effective offline. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **26 of 26** review-batch mutants killed (one survivor, the ranker reader passing the classifier's score column, was killed after adding `test_each_family_reader_backs_a_legacy_row_with_its_own_score_column`). Every new regression test fails on the pre-fix code. Suite results: see the related suites (83 files: auto, pipeline, plugins, ML, web incl. real-browser, report, oracle, scheduler, CLI, contract writers, lint, no-ML, packaging, harness, store, migrations, diagnostics; `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1054 passed, 1 skipped, before the last three tests were added, which pass with their files; greybox / multitarget / auto / store / CLI: 143 passed. The non-labgen and full-suite runs were still in progress at commit time and are recorded in a follow-up entry.

### CC-CORE-0032 — Packaging ships every tracked data file (BUG-0068); FR-CORE-22 (2026-10-13)
- Change:
  - **Package data.** `pyproject.toml` `[tool.setuptools.package-data]` drops the
    per-directory, non-recursive globs for one recursive rule, `"*" = ["**/*", "**/.*"]`.
  - **Deny-list.** `[tool.setuptools.exclude-package-data] "*"` names what never ships:
    - caches;
    - `.env` and its `.local` / `.production` / `.development` / `.staging` / `.test`
      variants;
    - `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*id_rsa*`;
    - `*.sqlite*` and `*.db-journal`, `-wal`, `-shm`;
    - OS and editor junk.

    These are fnmatch patterns, so `*` crosses `/`. `**/` patterns do nothing in
    setuptools 68 (measured).
  - **The FR-ML-6 no-ML switch** is documented as two lines.
  - **`pyflakes` added to the `dev` extra** (for `tests/test_lint.py`).
  - **New `tests/test_packaging.py` (8 tests):**
    - build_py equality with the tracked set;
    - executable bits kept;
    - the deny-list matching no tracked file;
    - planted secrets and junk never built, while `.env.example` is;
    - an untracked store/secret guard (a disk walk minus `git ls-files`);
    - sdist ships every tracked file, with modes;
    - the wheel (skips with the Debian `install_layout` reason unless
      `FUZZLAB_REQUIRE_WHEEL=1`);
    - the no-ML switch removes exactly `fuzzlab/ml/`.
- Impact:
  - **Every non-editable install** now has the web UI's templates and assets, the lab
    generator's trees and skeletons, and all packaged data.
  - **The FR-ML-6 knob** gains its required second line.
  - **The project-level `pyproject.toml`** is recorded here because FR-CORE-22 states
    the distribution contract.
  - No runtime code changes.
- Risk: low-medium.
  - **Shipping more could ship something unintended.** Mitigated by the deny-list (proven
    by planted files), the converse check, and the untracked-file guard.
  - **Residual, stated:** a stray `*.db` or an unlisted `.env` variant can't be denied
    by setuptools, so release builds come from a clean checkout (runbook).
- Deliverables:
  - [x] package-data rule + deny-list — done
  - [x] tests — done
  - [x] FR-CORE-22 — done
  - [x] BUG-0068 report, ERROR_LOG, PA-0070 — done
  - [x] runbook "Release builds" — done
- Implementation divergence:
  - `*.env.staging` and `*.env.test` were added to the deny-list (A3/B3 nits).
  - The untracked guard walks the disk (A4), so it also sees ignored files.
- Review: pre-change review gate cleared 3/3 over drafts v1 and v2 (the proposing agent
  plus 2 independent reviewer agents; every issue adopted). The decisive items were
  A1/B1: the recursive rule re-shipped `fuzzlab/ml` as data under the documented no-ML
  exclude. Both reviewers reproduced it.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (95 files: ML, auto, web incl. real-browser, plugins, report,
    no-ML incl. the real no-ML build, harness, multitarget, pipeline, diagnostics, core,
    CLI, store, migrations, packaging, lint, contract writers, on-host script, greybox,
    store adapter, session, labgen CLI, mutation, oracle;
    `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1249 passed, 3 skipped,
    11 failed.
    - 10 failures are `test_labgen_cli.py` tests, among the 33 known environmental
      failures (no scipy, sklearn or gitleaks).
    - The 11th, the multitarget live-boot test, failed with a connection reset from its
      locally booted server while two other suites held the CPU. It passes alone
      (2 passed).
  - **Mutation check** (a staged git copy, bytecode caches cleared): all 21 batch-5
    mutants are killed. Three were first mis-anchored by shell expansion in the
    mutation script and were re-run correctly. Killed:
    - old per-directory globs; no dotfiles;
    - deny-list missing pem / env; an over-broad deny pattern; a one-line no-ML switch;
    - report union missing models / stage metrics / flow;
    - the anomaly version on the read-only path, or missing;
    - flow-version duplicates; prioritizer / pipeline version missing;
    - CSV / greybox schema missing;
    - `_check_sql` never failing; the reveal not opt-in; a literal 5 in the budget check;
    - a lint regression; the dropped `Probe` import.

### CC-CORE-0031 — Migration 18 (flow anomaly columns); candidate features in `core/features.py` (2026-10-13)
- Change:
  - **Migration 18** adds `flow.anomaly_score REAL` and `flow.anomaly_flag INTEGER`.
  - **`core/features.py`** gains `CANDIDATE_FEATURE_NAMES`,
    `CANDIDATE_FEATURE_VERSION = 1` and `extract_candidate_v1`, with their regexes. They
    were moved verbatim from `ml/dataset._features`, and the body diff is empty. They
    import no ML.
  - **Golden file.** `tests/data/candidate_features/v1_golden.json` holds 45 cases, all
    captured from the old function **before** the move: cases 1–12 from the working
    tree, cases 13–45 (one per name-regex alternative) from commit 7a2b3d7, the last
    commit before it.
- Impact:
  - The schema head moves 17 → 18. It is additive.
  - ML reads the vector from core under its old names (FR-ML-5, partly met: recomputed
    on read).
  - The response extractor's `FEATURE_VERSION` is independent.
- Risk: low. Identity is proven by the golden vectors, and the name order is pinned.
- Deliverables:
  - [x] migration 18 — done
  - [x] extractor moved — done
  - [x] FR-CORE-20/21 — done
  - [x] tests: golden vectors (core and the ML alias), names / version, the no-ML
    import AST check (`tests/test_candidate_features_core.py`, 3), and migration 18
    columns (`tests/test_ml_batch4.py`) — done
- Review: covered by CC-ML-0021's 3/3 pre-change review (A6, A8, B4-5). Pre-assigned
  number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (61 files incl. real-browser, no-ML, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 953 passed. Batch-4 files (`test_ml_batch4.py`, `test_candidate_features_core.py`, `test_no_ml.py`, `test_web_ml_context.py`): 57 passed after the mutation-driven additions. Its mutants are among CC-ML-0021's 28, all killed.

### CC-CORE-0030 — Migration 17: the sealed holdout tables; `core/sealed.py` (2026-10-13)
- Change:
  - **Migration 17** adds two tables, plus an index on `holdout_metric.run_id`:
    - `holdout_metric(id, run_id → run, model_id → model, holdout_version, key, value)`;
    - `holdout_reveal(id, run_id → run, holdout_version, revealed_at)`.
  - **New `core/sealed.py`:**
    - `SEALED_TABLES`;
    - `write_metrics(store, run_id, model_id, version, metrics)` (no commit; the
      trainers commit);
    - `reveal(store, run_id) -> {metrics, reveals, version}`, which records a reveal
      row only when there are metrics. The count is store-wide per version.
  - It has no ML import, so a reveal works without the ML package.
- Impact:
  - The schema head moves 16 → 17. It is additive, and no existing table changes.
  - **ML (CC-ML-0020)** writes `holdout_metric`.
  - **UI (CC-UI-0045)** hides both tables.
  - **FUZZ (CC-FUZZ-0053)** `reveal-holdout` reads through `reveal`.
  - **PLUG (CC-PLUG-0007)** guard: INSERT on `holdout_metric` is allowed.
  - Nothing reads `holdout_metric` except `reveal`.
- Risk: low. The migration only adds tables, and the version tests read
  `max(MIGRATIONS)`.
- Deliverables:
  - [x] migration 17 — done
  - [x] `core/sealed.py` — done
  - [x] FR-CORE-19 — done
  - [x] tests: reveal counter, nothing-to-reveal, sealed surfaces
    (`tests/test_ml_holdout_calibration.py`) — done
- Review: covered by CC-ML-0020's 3/3 pre-change review (A1, B3v2-1, the final B nit
  2). Pre-assigned number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (58 files: ML, auto, web incl. real-browser, plugins, report, no-ML, harness, multitarget, pipeline, diagnostics, core, CLI, store, migrations; `FUZZLAB_REQUIRE_BROWSER=1`): 901 passed. `tests/test_ml_holdout_calibration.py`: 42 passed. Its mutants are among CC-ML-0020's 27, all killed.

### CC-CORE-0029 — `oracle_status` vocabulary in one place; canonical target origin; migration 16 (2026-10-13)
- Change:
  - **New `fuzzlab/core/oracle_status.py`** holds `CHECKED`, `SKIPPED_BUDGET`,
    `NO_CONFIRMER` and `UNLABELLED = {SKIPPED_BUDGET, NO_CONFIRMER}`. `harness/pipeline.py`,
    `ml/dataset.py` and `ml/train.forward_skip_reason` import them, replacing duplicate
    literals (PA-0003).
  - **`core/urls.canonical_origin(url) -> str | None`.**
    - It lower-cases scheme and host, strips a trailing dot, and normalises the host
      through `ipaddress` (compressed form; IPv4-mapped IPv6 → IPv4).
    - `localhost` and `::1`, in any spelling, become `127.0.0.1`. Other 127/8 hosts
      stay distinct.
    - The default port is made explicit; userinfo, path, query and fragment are
      dropped. A URL without a scheme reads as `http`.
    - It returns `None` (never matches) for an empty or missing host, or for a
      non-numeric or out-of-range port.
  - **Migration 16** adds `candidate.score_oof REAL` and `candidate.rank_score_oof REAL`.
    Head 15 → 16 (BUG-0067).
- Impact:
  - **Behaviour:** pipeline runs are unchanged. Target matching for earlier-run training
    and budget ordering now joins loopback aliases (CC-ML-0018).
  - **PA-0063 reader audit:** the new columns are read only per row, by the run page and
    the ML tab (per run), through `train.gate_input`.
  - **IDs:** FR-CORE-17 (oracle_status vocabulary) and FR-CORE-18 (canonical origin and
    migration 16).
- Risk: low. Additive.
- Deliverables:
  - [x] `oracle_status`, `canonical_origin`, migration 16 — done
  - [x] Tests — done: 20 `canonical_origin` cases, including every alias and edge case
    from review; target-run matching; the migration head derived from `MIGRATIONS`.
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-CORE-0028 — Migration 15: `run_plugin.config` / `status` / `error` (2026-10-13)
- Change: `ALTER TABLE run_plugin ADD COLUMN config TEXT`, `status TEXT` and
  `error TEXT`. They are nullable; legacy rows are NULL. Head 14 → 15.
- Impact:
  - A run now records how each attached plugin, the ML stages included, was configured
    and how it ended (CC-PLUG-0005).
  - **PA-0063 reader audit:** the only reader is `report.py` (`build_report`). It is per
    run and filtered by `run_id`, so it matches its reader's scope.
  - The optional-ML helper was moved to `fuzzlab/plugins/optional.py` during review, so
    `core/` does not mention `fuzzlab.ml`.
  - FR-CORE-16 is added.
- Risk: low. Additive.
- Deliverables:
  - [x] Migration 15 — done
  - [x] Tests: the head is derived from `MIGRATIONS` and the columns exist
    (`test_plugins_post_run.py::test_migration_15_adds_run_plugin_config_status_error`);
    legacy rows read NULL (`test_report.py`) — done
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective offline. Migration 15 is applied at head; config, status and error are written and read back; legacy rows read NULL. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set.

### CC-CORE-0027 — Migration 14: `model.params` + `model.params_sha256` (2026-10-13)
- Change: `_M0014`:
  ```sql
  ALTER TABLE model ADD COLUMN params TEXT;         -- canonical JSON of the trained model
  ALTER TABLE model ADD COLUMN params_sha256 TEXT;  -- sha256 of exactly that text
  ```
  - The migration is additive. Rows trained before it read NULL and are "not
    reloadable" (no backfill is possible).
  - Only the ML trainers write these columns.
- Impact: ML writes them; UI and report read them through ML's loader. ARCHITECTURE's
  store-contract `model` row is updated.
- Risk: low; additive.
- Deliverables:
  - [ ] `_M0014` + registry — done
  - [ ] Migration test — done
  - [ ] FR-CORE-15 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; both reviewers independently found BUG-0066; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — a fresh store is at head 14 with `model.params` / `params_sha256` (`tests/test_ml_persist.py::test_migration_14_adds_the_model_params_columns`, head derived from `MIGRATIONS`). Full suite at `a3b782d` (2026-10-13, whole `tests/`, `FUZZLAB_REQUIRE_BROWSER=1`): 2915 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same environmental labgen tests as at `369e887` (diffed, identical set); none is caused by this change.

### CC-CORE-0026 — Migration 13: candidate oracle status + anomaly score/flag (2026-10-13)
- Change: `fuzzlab/core/migrations.py` gains `_M0013`, appended as `(13, _M0013)`:
  ```sql
  ALTER TABLE candidate ADD COLUMN oracle_status TEXT;   -- 'checked' | 'skipped_budget' | 'no_confirmer'
  ALTER TABLE candidate ADD COLUMN anomaly_score REAL;   -- ECOD outlier score (advisory)
  ALTER TABLE candidate ADD COLUMN anomaly_flag INTEGER; -- 1 = in the flagged top fraction
  ```
  - The migration is additive, and existing rows read NULL.
  - `oracle_status` NULL means "unknown": written before migration 13, or by a writer
    outside the pipeline (`tools/store_adapter.py:119`). It keeps today's semantics,
    i.e. it is treated as oracle-labelled.
  - Only the pipeline writes `oracle_status`, and only `ml/anomaly.detect_anomalies`
    writes the anomaly columns. Neither is a `finding` label.
- Impact (other components / project):
  - ML and FUZZ consume the new columns.
  - Head-version tests derive the head from `MIGRATIONS`
    (`test_ml_ranker.py:43`, `test_plugins.py:45`).
  - ARCHITECTURE's store-contract `candidate` row is updated.
- Risk: low. The migration is additive and idempotent through `schema_version`.
- Deliverables:
  - [ ] `_M0013` + registry — done
  - [ ] Test: a fresh store has the columns, and a store at 12 migrates to 13 with NULLs — done
  - [ ] FR-CORE-14 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; the budget-ordering objective was put to the user, who chose `score` as the default; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — a fresh store is at head 13 with `oracle_status`, `anomaly_score`, `anomaly_flag` (`tests/test_ml_budget_and_scope.py::test_migration_13_adds_the_candidate_columns`, head derived from `MIGRATIONS`); head-version tests in `test_ml_ranker.py`/`test_plugins.py` pass unchanged. Full suite (2026-10-13, whole `tests/` at `369e887`, `FUZZLAB_REQUIRE_BROWSER=1`): 2868 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same labgen `--check`/fingerprint-gate tests that fail identically on `origin/main` in this environment (no scipy, scikit-learn or `gitleaks` binary); none is caused by this change.

### CC-CORE-0025 — Add `DEFAULT_BROWSER_HEADERS` (full header set, not UA alone) to `fuzzlab/core/http.py` (2026-09-25, BUG-0060/PA-0062)
- **Change:** adds `DEFAULT_BROWSER_HEADERS` (a dict: `DEFAULT_USER_AGENT` plus a
  matching `Accept`, `Accept-Language`, `Sec-Fetch-*` set, and
  `Upgrade-Insecure-Requests`) to `fuzzlab/core/http.py`, applied in place of
  `DEFAULT_USER_AGENT` alone at the same 6 call sites `CC-CORE-0024` introduced.
- **Why:** `CC-CORE-0024`'s UA-only constant fixed `BUG-0059`'s symptom but left every
  other header at `requests`' own non-browser defaults, which a WAF checks for as an
  internal-consistency signal independent of the UA string — see `CC-CRAWL-0010`/
  `BUG-0060` for the full incident; this entry is CORE's own half, the widened shared
  constant.
- **Verification:** offline — inspected a `DEFAULT_BROWSER_HEADERS`-configured
  session's prepared request headers directly; covered indirectly by the 6 importing
  tools' own test suites (83 tests total) continuing to pass.
- **Scope:** additive/widened constant only, no change to `HttpClient`'s own
  behavior/contract (`requirements.md` unaffected).

### CC-CORE-0024 — Add shared `DEFAULT_USER_AGENT` constant to `fuzzlab/core/http.py` (2026-09-25, BUG-0059/PA-0061)
- **Change:** adds `DEFAULT_USER_AGENT` (a realistic Chrome-on-Linux UA string) to
  `fuzzlab/core/http.py`, so every tool that opens its own bare `requests.Session()`
  sets the same header from one place instead of a hand-copied literal per call site
  (PA-0027).
- **Why:** `requests`' own default UA (`python-requests/x.y`) caused a real,
  live-reported failure (crawl returns `200` but `0` links against a real external
  target) — see `CC-CRAWL-0009`/`BUG-0059` for the full incident; this entry is CORE's
  own half, the shared constant 6 call sites across `fuzzlab/tools/`,
  `fuzzlab/greybox/`, and `fuzzlab/session/` now import and apply.
- **Verification:** offline only — no existing CORE test exercises `http.py`'s module
  constants directly; covered indirectly by `tests/test_spider_scope.py` (unaffected)
  continuing to pass after the importing side (`spider.py`) changed.
- **Scope:** additive constant only, no change to `HttpClient`'s own behavior/contract
  (`requirements.md` unaffected).

### CC-CORE-0023 — Map `csv_formula_injection` to the new `csv-formula-injection` category in `_VULN_TO_CATEGORY` (FR-CORE-13) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"csv_formula_injection": "csv-formula-injection"`. Mirrors `CC-CORE-0022`'s own `price_integrity_bypass` precedent: a genuinely new rule+strategy pair (`R-CSV-FORMULA-INJECTION`/`CsvFormulaInjectionStrategy`, built in `CC-FUZZ-0030` — that entry's own record has the full review-gate history: three blocking adequacy-review findings, all fixed pre-implementation) was needed, not a reuse of an existing one. This entry is the CORE-owned half: the one dict-entry mapping that lets `fuzzlab.harness.pipeline`'s own `evaluate()`/`category_to_oracle_class()` dispatch reach the new strategy at all for ground-truth-sourced runs.

  Live-verified end to end, mirroring `CC-CORE-0021`/`CC-CORE-0022`'s own discipline: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment scores `tp=3, fn=0, fp=0` — all three of this app's own ground-truth cases now match, closing its detection coverage entirely.

  This is the last of category 5's four classes for Booking.com's own ground truth — no further mapping is scoped for this app (only Expedia's own `insecure_deserialization` remains unmapped in this category, and it has no verified confirmer yet, flagged as requiring larger cross-cutting infrastructure work per this category's own change-control history, not attempted here).

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `2/3 -> 1.0`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (FUZZ component owns the new strategy/rule — see `CC-FUZZ-0030` for that component's own entry), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions).
- Risk (level; mitigation or accepted-risk justification): low. One dict entry, scoped and precedented by `CC-CORE-0020`/`0021`/`0022`. The real risk (a wrong or over-broad confirmer) was retired by `CC-FUZZ-0030`'s own pre-change review gate before this mapping was added; live end-to-end verification and the full whole-repo suite (see Effectiveness) confirm zero regressions.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["csv_formula_injection"]` — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/02-core-library/requirements.md`: `FR-CORE-13` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met. Real, verified result: `tp=3, fn=0, fp=0` against Booking.com's real, locally-booted deployment, recall `2/3 -> 1.0`. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0022 — Map `price_integrity_bypass` to the new `price-integrity-bypass` category in `_VULN_TO_CATEGORY` (FR-CORE-12) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"price_integrity_bypass": "price-integrity-bypass"`. Unlike `CC-CORE-0021`'s own `open_redirect` mapping (which reused a pre-existing rule+strategy pair), this class needed a genuinely new one — `R-PRICE-INTEGRITY`/`PriceIntegrityBypassStrategy`, built in `CC-FUZZ-0029` (this component's own FUZZ counterpart entry has the full record: pre-change review findings, canary design, live verification). This entry is the CORE-owned half: the one dict-entry mapping that lets `fuzzlab.harness.pipeline`'s own `evaluate()`/`category_to_oracle_class()` dispatch reach the new strategy at all for ground-truth-sourced runs.

  Live-verified end to end, mirroring `CC-CORE-0021`'s own discipline: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment scores `tp=2, fn=1, fp=0` for the real vulnerable twin (`LABGEN-BC-0005`) — a real, correctly-attributed true positive alongside `open_redirect`'s own (`CC-CORE-0021`), not a coincidence.

  Scoped to `price_integrity_bypass` only, not category 5's remaining unmapped class (`csv_formula_injection`): it has no verified confirmer yet (no `ConfirmationStrategy`/`Rule` pair exists for CSV-formula-injection detection) — mapping it now would only relabel an honest false negative as a mis-wired one, not a real improvement, matching `CC-CORE-0020`/`CC-CORE-0021`'s own established scoping discipline.

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `1/3 -> 2/3`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (FUZZ component owns the new strategy/rule — see `CC-FUZZ-0029` for that component's own entry), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions).
- Risk (level; mitigation or accepted-risk justification): low. One dict entry, scoped and precedented by `CC-CORE-0020`/`CC-CORE-0021`. The real risk (a wrong or over-broad confirmer) was retired by `CC-FUZZ-0029`'s own pre-change review gate before this mapping was added; live end-to-end verification and the full whole-repo suite (see Effectiveness) confirm zero regressions.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["price_integrity_bypass"]` — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/02-core-library/requirements.md`: `FR-CORE-12` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met. Real, verified result: `tp=2, fn=1, fp=0` against Booking.com's real, locally-booted deployment, recall `1/3 -> 2/3`. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0021 — Map `open_redirect` to the existing `open-redirect` category in `_VULN_TO_CATEGORY` (FR-CORE-11) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"open_redirect": "open-redirect"`. Mirrors `CC-CORE-0020`'s own `ssti` precedent exactly: a real rule (`R-OPEN-REDIRECT`, `fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "url|next|redirect|return|dest|goto|continue|target"` — matches Booking.com's real `return_to` param via its `return` alternative) and a real confirmation strategy (`OpenRedirectStrategy`, `fuzzlab/oracle/strategies.py`) already existed and were already correctly scoped for category 5's real cell (`LABGEN-BC-0001`, `CC-LAB-0210`) — purely a missing mapping, not a missing detector.

  **Two real, distinct code defects were found and fixed during this entry's own live-verification step** (per its own newly-added `PA-0042`, run before landing rather than trusting `confirm()`'s return value alone):
  1. **`BUG-0039`**: `RequestsProbeSender.send()` never set `allow_redirects=False` (unlike `fuzzlab.core.http`'s own authenticated client, which already does), so a real confirmation attempt against Booking.com's real vulnerable twin raised an uncaught `requests.exceptions.ProxyError` instead of returning a `Verdict` — `requests` tried to follow the strategy's own canary redirect target into an attacker-controlled/unreachable host. Fixed additively (`allow_redirects=False` added to that one sender, matching the other). No prior category's ground truth included a redirect-based sink, so no real confirmation run had ever reached this code path before.
  2. **`BUG-0040`**: after fixing `BUG-0039`, the confirmed finding still scored as a false positive (`tp=0, fp=1`), not a hit — `OpenRedirectStrategy.vuln_class` was `"open-redirect"` (hyphenated, matching this strategy's own `category` attribute) while every ground-truth case for this class (this project's `labels.schema.json` enum, every `open_redirect` manifest's `class:` field, `lab/safety_matrix.yaml`'s own `open_redirect` concern) uses `"open_redirect"` (underscored) — `fuzzlab.harness.scoring.score()`'s exact-key match never linked the two. Every sibling strategy (`SqliErrorStrategy`, `ReflectedXssStrategy`, `SstiStrategy`, etc.) already gets this right; `OpenRedirectStrategy` was an isolated inconsistency, latent since it was first authored (no `open_redirect` ground truth existed anywhere in this project to catch it until category 5's own work). Fixed: `vuln_class` corrected to `"open_redirect"`; `category` left unchanged (a separate, correctly-hyphenated namespace every strategy already uses consistently).

  Re-verified live, end to end, after both fixes: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment now scores `tp=1, fn=2, fp=0` for the real vulnerable twin (`LABGEN-BC-0001`) — a real, correctly-attributed true positive, not a relabeled false negative.

  Scoped to `open_redirect` only, not category 5's other three built classes (`csv_formula_injection`/`price_integrity_bypass`/`spel_injection`): none has a verified confirmer yet (no `ConfirmationStrategy`/`Rule` pair exists for CSV-formula-injection, business-logic price trust, or SpEL-evaluation-context detection) — mapping them now would only relabel an honest false negative as a mis-wired one, not a real improvement, matching `CC-CORE-0020`'s own established scoping discipline.

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `0 -> 1/3`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/tools/probesender.py` (`BUG-0039`'s fix — affects every confirmation strategy and every Phase E `multitarget.py` test across every category, additively; no existing passing test's expectations changed except `test_probesender.py`'s own fake, updated to assert the new setting), `fuzzlab/oracle/strategies.py` (`BUG-0040`'s fix, `OpenRedirectStrategy.vuln_class` only — no other strategy touched), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions). Both bug fixes are corrective, not new capability — component FUZZ (07) owns `fuzzlab/oracle/` and `fuzzlab/tools/probesender.py`; see that component's own change-control log for its own entry cross-referencing these same two bugs.
- Risk (level; mitigation or accepted-risk justification): low for the mapping itself (one dict entry, scoped and precedented). The `RequestsProbeSender` fix (`BUG-0039`) is the widest-blast-radius change in this entry — touches every existing caller of that sender — but is strictly *safer* than the prior behavior (was: crash or silently-wrong redirect-following; now: matches the already-correct authenticated client's own behavior) and the full whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own Phase E tests.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["open_redirect"]` — done
  - [x] `fuzzlab/tools/probesender.py`: `BUG-0039` fix — done
  - [x] `fuzzlab/oracle/strategies.py`: `BUG-0040` fix — done
  - [x] `tests/test_probesender.py`: updated fake + new assertion — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/bugs/BUG-0039-*.md`/`BUG-0040-*.md`, `ERROR_LOG.md`, `docs/PREVENTIVE_ACTIONS.md` (`PA-0041`/`PA-0042`) — done
  - [x] `docs/components/01-target-lab/requirements.md`/`docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-CORE-11`, cross-referenced from LAB's own Phase E entries — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. Live-verified end to end through the real scoring pipeline before landing (`PA-0042`'s own new rule, applied to itself): real `tp=1, fn=2, fp=0` against Booking.com's real, locally-booted deployment. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0020 — Map `ssti` to the existing `server-side-template-injection` category in `_VULN_TO_CATEGORY` (FR-CORE-10) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"ssti": "server-side-template-injection"`. This closes, for the `ssti` class specifically, a gap `CC-LAB-0138` (category 3, TrackerNest Phase E) flagged but did not fix: TrackerNest's real SSTI cell (`LABGEN-SSTI-0001`, OGNL evaluation of a raw query parameter) was scoring recall=0 purely because its ground-truth `vuln_class` (`"ssti"`) had no entry in this map, so `resolve_run`'s ground-truth-derived category set never included it and `evaluate()` never nominated a candidate for it — despite a real rule (`R-SSTI`, `fuzzlab/audit/rules_data/default_rules.json`, `category: server-side-template-injection`, `when: {location_in: [query, body]}`) and a real confirmation strategy (`SstiStrategy`, `fuzzlab/oracle/strategies.py`, already wired to that same category via `category_to_oracle_class`) already existing and already correctly scoped for this exact point shape (`macroExpr`, `location=query`).

  Scoped to `ssti` only, not all 6 of category 3's new classes: `xxe`/`insecure_deserialization`/`webhook_signature_bypass`/`ssrf`/`outbound_header_injection` have no confirmer built yet — mapping any of them now would only relabel an honest false negative as a mis-wired one (`evaluate()` would nominate a candidate `category_to_oracle_class()` returns `None` for, still never confirmed), not a real improvement, so they stay unmapped until each has its own verified confirmer (adequacy review's own finding, incorporated).

  `_VULN_TO_CATEGORY` is read only via `.get()` inside `to_category()`; nothing else iterates its keys or checks its size, so adding one key cannot affect any other, already-mapped class's behavior (checked directly, not assumed).

  Verified for real, not assumed: booted TrackerNest's real vulnerable SSTI cell live and sent `SstiStrategy`'s own existing payload set (`_ssti_payloads`, unmodified) directly against it — two of the five payloads (`{{a*b}}`, `#{a*b}`) genuinely evaluate under OGNL (`{{7*7}}` → `Rendered macro result: [[49]]`; OGNL's own list/map-literal syntax happens to nest the arithmetic result inside brackets/a map, but the product substring still appears and the un-evaluated expression string does not, which is exactly `SstiStrategy.confirm()`'s own pass condition: `product in text and expr not in text`) — so the existing strategy confirms this real vulnerability with zero changes to its own payload set or confirm logic. Also booted the real secure twin (`LABGEN-SSTI-0002`) with the same payloads and confirmed it never returns anything containing the product (`"Unknown macro"` for all payloads tested), so this mapping introduces no false-positive risk for that twin. Also checked no other ground truth anywhere in this now-consolidated branch uses `vuln_class: "ssti"` (only `lab/ground-truth-trackernest/labels.json` does, across all 10 `lab/ground-truth*/` directories currently on this branch), so this mapping's behavior change is scoped to exactly the one case it's meant to fix.

  Updates two of `CC-LAB-0138`'s/`CC-LAB-0140`'s own Phase E tests. `tests/test_labgen_spring_boot_trackernest_multitarget.py`: `tp==0`/`recall==0.0` → `tp==1`/`fp==0`/`fn==2`/`precision==1.0`/`recall≈1/3`, docstring corrected. `tests/test_multitarget_category3_combined.py`: the adequacy review caught a real gap in the first draft here — its single shared `for outcome in outcomes: assert tp==0` loop checked both targets identically, but only TrackerNest's outcome changes (Huddle Hub's own three classes remain entirely unmapped); restructured into per-target assertions (`trackernest_outcome.tp==1`/`recall≈1/3`, `huddlehub_outcome.tp==0`/`recall==0.0`), and the module's own docstring/inline comment corrected to state this precisely rather than the blanket "every class unmapped" framing the first draft would have left stale.
- Impact: Component 2 (CORE) primary; Component 1 (LAB)'s own two Phase E tests updated as a direct consequence (documented above, not a silent side effect). No change to `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (both already correctly built for this category; this entry only connects a third mapping this project's own docs already named as the missing piece).
- Risk: Low. One additive dict entry; verified against real running code (both twins) before landing, not just unit-level reasoning.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py` `_VULN_TO_CATEGORY["ssti"]` entry — done
  - [x] `tests/test_runmode.py`: `test_categories_from_vuln_classes_maps_ssti` + `test_categories_from_vuln_classes_leaves_unmapped_classes_unchanged` — done, both passing
  - [x] `tests/test_labgen_spring_boot_trackernest_multitarget.py`/`tests/test_multitarget_category3_combined.py` assertions + docstrings updated — done, re-run and passing (real `mvn package`/`java -jar` + real `composer install`/`artisan serve` boots)
  - [x] `docs/components/02-core-library/requirements.md` FR-CORE-10 entry — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met. `tests/test_runmode.py`'s 2 new unit tests pass. All 3 of `CC-LAB-0138`'s/`CC-LAB-0139`'s/`CC-LAB-0140`'s own Phase E tests re-run for real after this change: TrackerNest's own test now shows `tp=1`, `fn=2`, `precision=1.0`, `recall=1/3` (was `tp=0`/`recall=0.0`); the combined test correctly shows TrackerNest at `tp=1`/`recall≈1/3` and Huddle Hub still at `tp=0`/`recall=0.0`, with `generalizes` still correctly `False` (needs both scored targets above zero recall, not just one); Huddle Hub's own individual test unaffected (re-run, unchanged, still passing). Full non-slow suite re-run post-merge (this branch is now consolidated with categories 1/2/4/5's own work): 1838 passed, 52 skipped, 18 failed — every failure the same pre-existing `gitleaks`-binary/`scikit-learn`-dependency environment gap present before this change (more instances than category 3's own earlier baseline of 15, because the merged tree now has more manifests hitting the same missing-dependency gate — verified: identical failure shape, `2 gate(s) FAILED: secret scanner ... / metadata leakage gate ...`), zero regressions attributable to this entry.
- Pre-change review gate: drafted, reviewed by 2 independent agents (accuracy: all 6 specific factual claims checked — including an independent re-run of the exact live-boot reproduction against both real twins — found ACCURATE, no inaccuracies; adequacy: 6 findings — an undercounted test-update scope in `test_multitarget_category3_combined.py` (the real gap above, now fixed), a missing one-sentence statement of the dict-mutation-safety reasoning, a missing one-sentence statement of why only `ssti` and not the other 5 classes, a missing `Effectiveness: pending` placeholder line, an under-specified "unit coverage" deliverable (now named exactly), and a missing deliverables-checklist line for the docstring/comment corrections — all incorporated). 3/3 agreement reached by incorporating every concrete finding from both reviews without contesting any of them; implementation proceeds on this revised entry, matching this component's own gate discipline in full (unlike `CC-LAB-0138`-`0140`'s own acknowledged after-the-fact deviation).

### CC-CORE-0019 — Migration 12: `saved_views` table (U2-table, Findings workbench) (2026-09-22)
- Change: migration 12 (append-only registry; head → 12) adds
  `saved_views(id, table_key, name, spec_json, is_pinned, created_at,
  updated_at)` — a durable, server-side store for named filter/sort/column
  specs a person saves in a faceted workbench (the Findings workbench,
  `CC-UI-0029`, is the first caller; `table_key` names the logical dataset the
  view is over, e.g. `"finding"`, so other workbenches can reuse the same
  table later rather than inventing their own). `spec_json` is opaque to the
  store — it is only ever read/written as JSON by `fuzzlab.web.savedviews`,
  never queried by field. One index, `idx_saved_views_table(table_key)`, for
  the one read pattern (`GET /api/views?table=`). Additive; no existing
  table/column changed. **Note on bookkeeping numbering:** this CC-CORE number
  was not in lane U2's pre-assigned block (`docs/PARALLEL_LANE_BUILD_PLAN.md`
  reserved only `CC-UI-0029` for U2) — the lane's own scope statement
  (`fuzzlab/web/app.py` read route(s) plus the shared UI files) did not
  foresee needing a new store table. `CC-CORE-0019` was computed as "highest
  existing + 1" at the time this entry was written (mirroring how `B0`'s
  `metric_series` migration got both a `CC-CORE-0018` and a `CC-UI` entry);
  per PA-0031, an integrator merging this lane alongside others touching
  `02-core-library/change-control.md` should re-verify no other lane claimed
  `CC-CORE-0019` in the meantime before merging, rather than assuming this
  number is uncontested.
- Impact (other components / project): additive only. UI-owned data (view
  definitions a person authored in the panel), not a `finding`/`attempt`/
  `candidate`/flow result table, so it does not touch `NFR-UI-read-only`
  ("the UI writes no result tables") — see `CC-UI-0029`'s own impact note for
  why this is the one deliberate write path that requirement still allows.
  No other component reads or writes this table.
- Risk (level; mitigation): low — one additive table + one index, written only
  through `fuzzlab.web.savedviews`'s four functions (`list_views`/`get_view`/
  `create_view`/`update_view`/`delete_view`), each parameterized (no string-built
  SQL). Mitigated by `tests/test_web_findings.py`'s saved-view round-trip tests
  (direct store functions and the `/api/views` HTTP surface) and the existing
  `tests/test_core_foundations.py::test_migrations_are_idempotent` pattern
  (re-run here implicitly via every other store-backed web test creating a
  fresh store on migration 12).
- Deliverables:
  - [x] Migration 12 added to the append-only `MIGRATIONS` registry — done.
  - [x] `fuzzlab.web.savedviews` CRUD module — done.
  - [x] Round-trip tests (store-level + HTTP) — done.
- Effectiveness (assessed 2026-09-22): effective — saved views persist across
  store reopens and are visible to any reader of the same store file, unlike
  the `localStorage`-only alternative R-03 explicitly rejected for this data.

### CC-CORE-0018 — Migration 11: `metric_series` table + `open_store()`/`log_scalar`/`MetricLogger` (B0-table, Phase 4b) (2026-09-22)
- Change: migration 11 (append-only registry; head → 11) adds `metric_series(id, run_id,
  source, key, step, ts, value)`, the generic cross-run scalar-series sink for per-step
  emitters (GBT/logistic training curves, bandit posterior/regret, coverage-frontier
  growth, `MutationSearch` reward/novelty, stage wall-clock/throughput — those emitters
  themselves are separate lanes, not part of this change). `run_id INTEGER REFERENCES
  run(id)` (the store's actual runs table is `run`, singular — matches every other
  migration; R-05's "`runs(id)`" phrasing was generic, not a literal table name);
  `value REAL NOT NULL`; two indexes for the two read patterns: `idx_metric_series_run
  (run_id, source, key, step)` (one series within a run) and
  `idx_metric_series_overlay (source, key, run_id, step)` (cross-run overlay). Also:
  added `fuzzlab.core.store.open_store()`, the central WAL-configured connection
  constructor R-08 calls for (`journal_mode=WAL`, `busy_timeout=10000`,
  `synchronous=NORMAL`, `foreign_keys=ON`, connect-time `timeout=10.0`); `connect()` is
  now a thin backward-compatible alias for it (previously `connect()` set
  `busy_timeout=5000` with no connect-time `timeout=` — now centralized and raised to
  match R-08's resolved design). Added `log_scalar(store, run_id, source, key, step,
  value, ts=None)` (accepts a `Store` or a raw connection from `open_store()`) and
  `MetricLogger(store, run_id, source, flush_every=200)`, a buffered context-manager
  writer that batches an `executemany` every `flush_every` rows and flushes on
  `__exit__`/exception. Both reject non-finite (`NaN`/`inf`) values — dropped with a
  `UserWarning`, never written — per R-05 (no `is_nan` column, no NaN read-branch).
- Impact (other components / project): additive only; no existing table, column, or
  pragma value that any current caller depended on changed in a breaking way (raising
  `busy_timeout` 5000→10000 and adding connect `timeout=10.0` only widens the lock-wait
  window). This is the **table-only** slice of the B0 lane — the GBT/logistic,
  bandit-loop, coverage-frontier, and `MutationSearch` emitters that will write through
  `log_scalar`/`MetricLogger` are separate, later lanes (reserved `CC-ML-0009`,
  `CC-SCHED-0005`, `CC-FUZZ-0021`, `CC-MUT-0011` per
  `docs/PARALLEL_LANE_BUILD_PLAN.md`), not built here. The diagnostics UI (U5) reads this
  table once it lands.
- Risk (level; mitigation): low — one additive table + two indexes + a new always-central
  connection constructor that the existing `connect()` now simply delegates to. Mitigated
  by `tests/test_core_foundations.py::test_migrations_are_idempotent` (now also asserts
  `metric_series` exists), `test_open_store_is_wal_smoke` (R-08's required WAL smoke
  test), `test_metric_series_schema_and_indexes`, `test_log_scalar_roundtrip`,
  `test_log_scalar_accepts_raw_connection`, `test_log_scalar_rejects_non_finite`
  (parametrized NaN/+inf/-inf), `test_metric_logger_flushes_every_n`, and
  `test_metric_logger_drops_non_finite_and_flushes_on_exception`. Full suite (excluding
  pre-existing, unrelated collection failures in this environment from a missing
  `covertable` package and an unavailable `starlette.testclient` — both present before
  this change, confirmed via `git stash`): 486 passed / 2 skipped / 2 pre-existing
  failures unrelated to this change (`test_web_commandspec.py`, same `covertable`-driven
  registration gap, reproduced identically on the pre-change tree).
- Deliverables:
  - [x] Migration 11 (`metric_series` table + both indexes) — done.
  - [x] Central `open_store()` (WAL/busy_timeout/synchronous/foreign_keys/timeout),
    `connect()` kept as an alias — done.
  - [x] `log_scalar()` + `MetricLogger` (buffered, `flush_every=200` default,
    non-finite rejection) — done.
  - [x] R-08 WAL smoke test — done.
  - [ ] Per-component emitters (GBT/logistic, bandit-loop, coverage-frontier,
    `MutationSearch`) — explicitly out of scope for this lane; separate dispatches.
- Effectiveness (assessed 2026-09-22): effective — migration is additive/reversible-safe
  (no data touched, no column type changed), the full suite is unaffected, and the write
  path (`log_scalar`/`MetricLogger`) is ready for the emitter lanes to adopt.

### CC-CORE-0017 — Credentials keyed by bare hostname (BUG-0007) (2026-09-21)
- Change: `CredentialStore` now normalizes the host to its bare hostname
  (`_norm_host`: strips scheme/port) on `set`/`get`/`require`/`delete`, so credentials
  saved as `127.0.0.1`, `127.0.0.1:8080`, or `http://127.0.0.1:8080/` all resolve to the
  same key — matching how the session layer looks them up (`urlparse(url).hostname`). The
  `require` error message now prints the exact `set-credential` command with the
  normalized host.
- Impact (other components / project): fixes the on-host `CredentialError` where
  `set-credential --host 127.0.0.1:8080` stored a key the crawler's hostname lookup
  (`127.0.0.1`) missed (BUG-0007). No API change; existing hostname-only usage is
  unaffected (normalization is a no-op there).
- Risk (level; mitigation): low — normalization at the store boundary; the session layer
  and `HttpClient` scope already use `hostname`. Mitigated by
  `tests/test_credentials.py::test_host_is_keyed_by_hostname_regardless_of_port_or_scheme`.
  Suite 392 passed / 4 skipped.
- Deliverables:
  - [x] `_norm_host` normalization + actionable `require` message — done.
- Effectiveness (assessed 2026-09-21): effective — save-with-port / look-up-by-hostname
  now agree; the runbook was corrected to `--host 127.0.0.1`.

### CC-CORE-0016 — Migration 10: active-plugin recording (Phase 10 T10.1) (2026-09-21)
- Change: migration 10 adds the `run_plugin` table (append-only registry; head → 10):
  one row per active plugin per run (`run_id, name, version, priority`), so a run records
  exactly which plugins/versions produced its results (NFR-PLUG-reproducible).
- Impact (other components / project): the PLUG component's `PluginManager.record()`
  writes here; the reproducibility report (T10.4) reads it. Additive; a zero-plugin run
  writes no rows. Version-pinning tests derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one additive table + index. Mitigated by
  `tests/test_plugins.py::test_migration_10_adds_run_plugin` and `test_record_writes_active_plugins`.
  Suite 360 passed / 4 skipped.
- Deliverables:
  - [x] Migration 10 (`run_plugin`) — done.
- Effectiveness (assessed 2026-09-21): effective — active plugins persist per run.

### CC-CORE-0015 — Migration 9: flow protocol tag (Phase 9 T9.1) (2026-09-21)
- Change: migration 9 adds a `protocol` column to `flow` (append-only registry; head → 9)
  so history distinguishes `http/1.1` / `h2` / `ws` flows. Additive; existing rows read as
  NULL and the proxy's `HistoryWriter` defaults new rows to `http/1.1`.
- Impact (other components / project): lets the PROXY component record WebSocket and (later)
  HTTP/2 flows alongside HTTP/1.1 without touching existing rows. Version-pinning tests
  derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one nullable column. Mitigated by
  `tests/test_proxy_ws.py::test_migration_9_adds_flow_protocol`. Suite 328 passed / 4 skipped.
- Deliverables:
  - [x] Migration 9 (`flow.protocol`) — done.
- Effectiveness (assessed 2026-09-21): effective — WebSocket flows persist with their
  protocol tag.

### CC-CORE-0014 — Migration 8: mutation-engine payload variants (Phase 8 T8.1) (2026-09-21)
- Change: migration 8 adds the `payload_variant` table (append-only registry; head → 8):
  the provenance of each accepted mutation — `base_payload`, `variant`, the `operators`
  chain (JSON), `sink_context`, `bypassed_rule`, the `semantics_ok` verdict, and any
  `coverage_gain`. Variants are still sent through the `attempt` path; this is for reuse
  and analysis (decision 3 of the Phase 8 plan).
- Impact (other components / project): gives the MUT component its write-back target
  (FR-MUT-6) without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — additive table + index. Mitigated by
  `tests/test_mutation_operators.py::test_migration_8_adds_payload_variant`. Suite 289
  passed / 4 skipped.
- Deliverables:
  - [x] Migration 8 (`payload_variant`) — done.
- Effectiveness (assessed 2026-09-21): effective — the table is present for T8.5's
  variant write-back.

### CC-CORE-0013 — Migration 7: candidate ranker scores (Phase 7 T7.2) (2026-09-21)
- Change: migration 7 adds advisory `rank_score` and `rank_uncertainty` columns to
  `candidate` (append-only registry; head → 7), kept separate from the Phase-5
  `candidate.score` so the ranker and the detection classifier coexist.
- Impact (other components / project): gives the ML ranker (A.2) its store columns
  without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive nullable columns. Mitigated by
  `tests/test_ml_ranker.py::test_migration_7_adds_rank_columns`. Suite 266 passed / 3 skipped.
- Deliverables:
  - [x] Migration 7 (`candidate.rank_score`, `candidate.rank_uncertainty`) — done.
- Effectiveness (assessed 2026-09-21): effective — the ranker writes advisory ranks into
  the new columns.

### CC-CORE-0012 — Migration 6: proxy flow history (Phase 6 T6.3) (2026-09-21)
- Change: migration 6 extends `flow` with `host`, `in_scope`, and byte-exact
  `req_raw_sha`/`resp_raw_sha` (raw wire bytes content-addressed via `body`), adds the
  `flow_fts` FTS5 index and a `repeater_tab` table (append-only registry; head → 6).
- Impact (other components / project): gives the PROXY component the store contract for
  FR-PROXY-3/FR-PROXY-4 (searchable history with raw bytes; persisted repeater tabs)
  without changing any existing table's rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive columns/tables with NULL defaults (ADD
  COLUMN … REFERENCES is valid because the default is NULL). Mitigated by
  `tests/test_proxy_history.py::test_migration_6_schema`. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (`flow` raw bytes + FTS5 + `repeater_tab`) — done.
- Effectiveness (assessed 2026-09-21): effective — the proxy history writer round-trips
  byte-exact raw bytes and FTS search works over the new index.

### CC-CORE-0011 — Migration 5: bandit cost columns (Phase 4 T4.4) (2026-09-21)
- Change: migration 5 adds `cost_sum`/`cost_n` to `bandit_posteriors` (append-only
  registry; head → 5), so the bandit's per-(context, arm) mean cost persists next to the
  reward posterior for cost-normalized selection.
- Impact (other components / project): the SCHED bandit's `load`/`save` now round-trip
  cost; no other reads change. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes 5.
- Risk (level; mitigation): low — additive columns with defaults. Suite 183 passed / 2 skipped.
- Deliverables:
  - [x] Migration 5 (`cost_sum`, `cost_n`) — done.
- Effectiveness (assessed 2026-09-21): effective — cost persists across runs
  (`tests/test_scheduler.py::test_cost_persists_across_stores`).

### CC-CORE-0010 — Headless credential backend on `cryptography` (BUG-0005) (2026-09-21)
- Change: reimplemented the D12 encrypted-file credential backend in
  `fuzzlab/core/credentials.py`. It was `keyrings.alt.file.EncryptedKeyring` (needs
  PyCrypto/pycryptodome, undeclared and absent → crash on first use). It is now
  `_CryptographyFileBackend`: a single AES-Fernet-encrypted JSON file, key derived
  from `FUZZLAB_KEYRING_PASSPHRASE` via PBKDF2-HMAC-SHA256 over a random per-file
  salt, `0600` perms, atomic write, loud failure on a wrong passphrase — built on
  `cryptography` (the intended lib, already present). Declared `cryptography>=42,<51`
  in `pyproject.toml`.
- Impact (other components / project): fixes BUG-0005, which blocked every headless
  authenticated run (`fuzzlab session set-credential` / `--identity`). The session
  manager (component 03) consumes the store unchanged; the injectable-backend seam and
  the OS-keyring/env-fallback paths are unchanged. File format is new (`FZLB1` magic);
  no prior headless store existed to migrate.
- Risk (level; mitigation): medium — credentials are high-impact. Mitigated by
  encryption at rest (Fernet/AES128-CBC+HMAC), `0600` perms, ciphertext-verified in a
  test, password-masked `repr`, and new real-backend tests (round-trip, persistence,
  wrong-passphrase) that exercise the actual `cryptography` path and skip only when the
  native lib is unavailable. Suite 126 passed / 2 skipped.
- Deliverables:
  - [x] `_CryptographyFileBackend` (Fernet+PBKDF2, atomic, 0600) — done.
  - [x] `cryptography` declared; `keyrings.alt` EncryptedKeyring dependency dropped — done.
  - [x] Real round-trip/wrong-passphrase tests (skippable) — done.
  - [ ] Confirmed on the host: `set-credential` + `session print` + `--identity` run — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests where `cryptography` works;
  to be confirmed on the Fedora host (where the crash was seen) after `pip install -e .`.

### CC-CORE-0009 — Grey-box consumer layer (offline scaffolding, Phase 3) (2026-09-21)
- Change: added `fuzzlab/greybox/` — the consumer side of Phase 3 grey-box
  instrumentation, built behind injected-source protocols so it is fully testable
  without a lab: `coverage.py` (`CoverageSource` + `InMemoryCoverageSource` fake,
  `app_lines` filter, `CoverageFrontier` novelty tracking, coverage encode/decode),
  `dbfault.py` (`DbFaultSource` + fake), `reward.py` (`GreyboxSignal` + `shaped_reward`
  multi-tier: screening / coverage-novelty / db_fault), `reset.py` (`LabControl`
  protocol + `FakeLabControl`), `confirm.py` (the pure M10 decision), and
  `recorder.py` (`record_attempt_signals` filling the reserved `attempt.coverage`
  /`attempt.db_fault`/`reward` columns). No schema change (columns were reserved in
  migration 1).
- Impact (other components / project): gives Phase 3 turnkey seams — the on-host work
  is reduced to backing the protocols with live pcov/DB-fault/reset sources
  (`docs/ON_HOST_TASKS.md`) and wiring M10 into the oracle/pipeline (FUZZ). The
  shaped reward is the input the Phase 4 bandit will consume. Safety unchanged
  (live readers bind loopback-only; grey-box corroborates, oracle stays sole
  finding-writer).
- Risk (level; mitigation): low — pure, dependency-light logic with no live I/O in
  this layer. Mitigated by 17 offline tests (app-line filtering, frontier novelty +
  saturation, reward ordering incl. the new-code-scores-higher exit property, M10 per
  class, recorder writing the reserved columns end-to-end). Full suite 125/125.
- Deliverables:
  - [x] `fuzzlab/greybox/` package (coverage/dbfault/reward/reset/confirm/recorder) — done.
  - [x] `tests/test_greybox.py` (17 tests) — done.
  - [ ] Live sources + M10 oracle/pipeline wiring + exit measurement — on-host (T3.1/3.5/3.6/3.7).
- Effectiveness (assessed 2026-09-21): effective offline — the reward math, frontier,
  filtering, M10 decision, and column persistence are verified with fakes; live
  confirmation pending the instrumented lab.

### CC-CORE-0008 — Single home for URL path-normalization (`urls.to_path`) (2026-09-21)
- Change: added `fuzzlab/core/urls.py::to_path(url)` — the one shared function that
  normalizes a result URL to path form (`/product.php`), the convention every
  stored, ground-truth-cross-referenced URL must follow. The oracle's finding
  writer and `tools/store_adapter` (which had a private `_path` duplicate) both now
  call it; the duplicate is removed.
- Impact (other components / project): fixes BUG-0003 (the oracle stored full URLs,
  so scored pipeline runs reported every true finding as a false alarm). Any future
  writer of a cross-referenced URL imports `to_path` rather than re-implementing the
  rule (PA-0003). No schema change; behavior change is that oracle findings are now
  stored in path form like every other URL.
- Risk (level; mitigation): low — a pure, well-tested normalization helper.
  Mitigated by the pipeline tests (scored TP/FP now correct) and the existing
  store-adapter/harness tests (unchanged, still green). Suite 108/108.
- Deliverables:
  - [x] `core/urls.py::to_path` with the convention documented in-module — done.
  - [x] Oracle + store_adapter call it; local duplicate removed — done.
  - [x] BUG-0003 investigation + PA-0003 recorded — done.
- Effectiveness (assessed 2026-09-21): effective — the previously-failing scored
  pipeline test passes and no writer stores a verbatim URL for cross-referencing.

### CC-CORE-0007 — Run-mode category resolver (D14/D15) (2026-09-21)
- Change: added `core/runmode.py` — the pure decision logic for category selection
  and the no-ground-truth fail-safe. `resolve_run(mode, ...)` returns a `RunPlan`
  (categories, scored, source): automatic + ground truth → auto-derived + scored
  (D14); automatic + no ground truth → explicit selection required or **fail loud**,
  unscored (D15); manual → user selection, defaulting to all known categories,
  unscored (D14). `categories_from_vuln_classes` normalizes ground-truth classes
  (e.g. `sqli`→`sql-injection`, `xss-*`→`xss`) to reference-style categories; unknown
  categories/modes fail loud. Dependency-light (callers pass the ground-truth and
  known categories in), so no layering inversion.
- Impact (other components / project): the launcher/harness and tools call this to
  scope the auditor rules (T2.3 `categories` filter), payload sources, and oracle
  strategies (T2.9), and to enforce the D15 fail-safe. No schema change.
- Risk (level; mitigation): low — pure function; the safety-relevant path (D15) is
  fail-closed (raises rather than guessing/blasting). 7 unit tests cover D14 lab
  auto-derive (scored), manual selection/default, D15 fail-loud + unscored, and
  unknown-category/mode errors.
- Deliverables:
  - [x] `runmode.py` resolver + normalization + 7 tests — done.
  - [ ] Wire into the launcher/harness (scope tools; scored vs unscored) — todo (with T2.8/UI).
- Effectiveness (assessed 2026-09-21): effective in unit tests — each D14/D15 branch
  resolves correctly and fails loud on unsafe/unknown input. Suite 105/105.

### CC-CORE-0006 — Migration 4: rule-evaluation logging (negatives) (2026-09-21)
- Change: added migration 4 (an `evaluation` table + indexes) recording every
  per-(injection point, rule) evaluation with its outcome (`fired` 0/1), so the
  store holds negatives, not just hits. Supports the auditor's T2.3 rules-as-data
  engine.
- Impact (other components / project): the auditor writes here; the ranker/ML
  (later) train on the negatives. Schema head is now version 4; additive.
- Risk (level; mitigation): low — additive table + indexes; idempotent migration
  runner + tests. (The version-pinning tests already derive the head from the
  registry per PA-0001/PA-0002, so migration 4 needed no test edits.)
- Deliverables:
  - [x] Migration 4 (`evaluation` table + indexes) — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 4;
  the auditor engine writes fired + not-fired evaluations (98/98 tests green).

### CC-CORE-0005 — Migration 3 + session-state store methods (2026-09-21)
- Change: added migration 3 (a `session_state` table for **non-secret** session
  metadata — host, identity, kind, valid, login/logout URLs, token_exp) and Store
  methods `upsert_session_state`/`get_session_state`/`all_session_states`. Supports
  T1.7 persistence. Secrets (cookies/tokens/creds) are never stored — the table has
  no column for them.
- Impact (other components / project): the session manager (#3) persists non-secret
  state here; the diagnostics UI can later read it. Schema head is now version 3;
  additive migration, existing data untouched.
- Risk (level; mitigation): low — additive table + upsert. Mitigated by the
  idempotent migration runner and tests. Discovered BUG-0002 (a test still
  hardcoding the schema head `== 2`); fixed to derive from the registry and added
  PA-0002 (sweep for a bug class when adding its preventive action).
- Deliverables:
  - [x] Migration 3 (`session_state`) + Store methods — done.
  - [x] Fix BUG-0002 + PA-0002 — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 3,
  session state round-trips, suite 71/71 green.

### CC-CORE-0004 — Per-host credential store implemented (2026-09-21)
- Change: implemented `fuzzlab/core/credentials.py` (T1.1, D12) — a
  `CredentialStore` keyed by `(host, identity)` over `keyring`, with backend
  resolution (OS Secret Service → encrypted-file via `keyrings.alt` at
  `FUZZLAB_KEYRING_PATH`/`FUZZLAB_KEYRING_PASSPHRASE` → gated lab-only env fallback
  `FUZZLAB_CRED_<HOST>_<IDENTITY>`). Backend is injectable; `Credential` masks its
  password in `repr`. Exported from `core`. Added `keyring`/`keyrings.alt` deps;
  dropped the planned PyJWT dep (JWT `exp` is read by base64url-decoding the
  payload — no crypto dependency).
- Impact (other components / project): the session manager (component #3) draws
  per-host credentials from here; no other component affected. Secrets never enter
  the project store or repo (config holds references only).
- Risk (level; mitigation): medium — mishandled credentials are high-impact.
  Mitigated by keyring-only storage, password-masked repr, redaction discipline,
  and the env fallback being default-off and lab-scope-gated. The real
  encrypted-file backend is environment-dependent (needs a working `cryptography`);
  the store's own logic is covered by tests with an injected in-memory backend.
- Deliverables:
  - [x] `CredentialStore` (set/get/require/delete), per-host keying — done.
  - [x] Backend resolution incl. encrypted-file + gated env fallback — done.
  - [x] 6 unit tests (per-host, env-fallback gating, repr masking) — done.
  - [ ] Live check of the encrypted-file backend on a host with `cryptography` — todo.
- Effectiveness (assessed 2026-09-21): effective — 6/6 tests green; credentials
  round-trip per host, env fallback honored only when enabled + in scope, password
  never appears in `repr`.

### CC-CORE-0003 — Migration 2: self-describing findings (2026-09-21)
- Change: added migration 2, which ALTERs `finding` to add `url`, `method`, and
  `param` columns so a confirmed finding carries its own location and the
  integration harness can score by `(url, method, param, vuln_class)` without a
  candidate/parameter join. Registered as a new, higher-numbered migration (the
  registry is append-only; migration 1 is untouched).
- Impact (other components / project): the store schema head is now version 2; the
  harness (T0.7) reads these columns. Additive only — existing rows/columns
  unchanged; a fresh store applies 1 then 2.
- Risk (level; mitigation): low — additive `ALTER TABLE ADD COLUMN`. Mitigated by
  the idempotent migration runner and tests; the two foundation tests that pinned
  version 1 were updated to assert the current head rather than a literal.
- Deliverables:
  - [x] Migration 2 (finding url/method/param) + registry entry — done.
  - [x] Update version-pinning tests to the head version — done.
- Effectiveness (assessed 2026-09-21): effective — a fresh store reports version 2,
  re-migration is a no-op, and the harness scores from finding rows (22/22 tests).

### CC-CORE-0002 — Phase 0 core library implemented (2026-09-21)
- Change: created the `fuzzlab` package with a `core/` subpackage and built the
  Phase 0 foundations — the project store (`store.py`) with WAL/foreign-key
  pragmas and content-addressed bodies; a numbered, forward-only, idempotent
  migration runner (`migrations.py`) creating the core tables from the store
  contract (reserving grey-box coverage/fault columns); layered config
  (`config.py`, defaults → file → env → overrides) with a stable run hash and
  redaction; structured JSON logging (`obs.py`); the request budget + per-host
  timing mutex (`budget.py`); and a session-aware, scope-enforcing HTTP seam
  (`http.py`). Adds `pyproject.toml`. Realizes Phase 0 tasks T0.1, T0.3, T0.4.
- Impact (other components / project): every tool now has a real `core/` to
  import (D6) and the shared store exists as the integration bus (D5). Establishes
  the store schema other components will read/write (T0.8 migrates them onto it).
  No external interface beyond the store contract; the schema is versioned so
  later changes are additive migrations.
- Risk (level; mitigation): medium — the most depended-on component. Mitigated by
  numbered forward-only migrations (idempotent, transactional), a versioned
  feature store, config validation (e.g. timing_concurrency must be 1), and unit
  tests covering migrations idempotency, config precedence/hash/redaction, budget
  caps, the timing mutex, and HTTP scope enforcement + flow recording.
- Deliverables:
  - [x] Package layout with `core/` (T0.1) — done.
  - [x] Store + migrations (T0.3) — done.
  - [x] Config, logging, budget+mutex, HTTP seam (T0.4) — done.
  - [x] Versioned feature extractor `features.py` + golden tests (T0.5) — done.
  - [x] Foundation unit tests (12) passing — done.
  - [ ] Session manager replaces the HTTP-seam addon stub — todo (Phase 1).
- Effectiveness (assessed 2026-09-21): effective — `python -m pytest` is green
  (12/12); a fresh store migrates to version 1 and re-migration is a no-op; config
  hash is deterministic; the timing mutex serializes per host in a threaded test.

### CC-CORE-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented; the
  existing tools currently carry their own ad-hoc storage and helpers.
- Impact (other components / project): once built, every tool depends on it; it
  establishes the store as the integration bus (D5) and removes duplicated
  storage/logging/HTTP logic from the tools (D6). Until then, tools remain
  loosely coupled through separate SQLite files.
- Risk (level; mitigation): medium — this is the most depended-on component, so a
  bad schema or API is expensive to change later. Mitigated by numbered
  migrations, a versioned feature store, and building it first (Phase 0) before
  much depends on it.
- Deliverables:
  - [ ] Package layout with `core/` — todo (Phase 0 T0.1).
  - [ ] Store + migrations — todo (Phase 0 T0.3).
  - [ ] Config, logging, budget+mutex, HTTP seam — todo (Phase 0 T0.4).
  - [ ] Versioned features + golden tests — todo (Phase 0 T0.5).
- Effectiveness (assessed or pending): pending — not yet built.
