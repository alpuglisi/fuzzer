# BUG-0554 — A captured body holding a lone surrogate was lost at the write: the capture writer raised, and the request was neither stored nor counted

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0061, FR-CRAWL-42; the importer's side of the same change
  needs an AUD change-control number, requested at merge), with one pinned instance of
  the class in the redaction boundary (a strict xfail, below)
- Severity: medium. Every captured JSON request whose body held a lone surrogate escape
  was dropped by the spider's capture writer without a trace in its counts: not stored,
  not in `requests_not_recorded`, logged only at info level by the browser guard's
  observer catch. The input is realistic: a script that cuts a string by UTF-16 index
  (`slice`, `substring`, a length cap on text holding an emoji) sends half a pair, and
  Chromium's `JSON.stringify` writes it as a `\udXXX` escape (measured below). An
  importer given such a row failed the whole import, which disco's import already
  reached.

## Description
`tools/spider.py::StorageManager.record_request` is the one writer of the spider table
`discovered_requests` (FR-CRAWL-13, FR-CRAWL-37). `{"q":"\ud800"}` is valid JSON, and
`json.loads` decodes the escape to a lone surrogate code point. The writer then put that
code point into three sinks that only take valid UTF-8:
- the stored body, `json.dumps(doc, ensure_ascii=False)`, bound into SQLite (Python's
  `sqlite3` encodes a `str` parameter as strict UTF-8);
- the operation key, `tools/apiop.py::operation_key`, written the same way, whose
  signature prefix is bound into the lookup `SELECT`;
- the shape digest, `apiop.row_signature`, and the digest of a GraphQL document over the
  token cap, `apiop.graphql_operations`: a strict `.encode("utf-8")`.

Each raised `UnicodeEncodeError` out of `record_request`. Its caller (`_observe`, and
`_record_dry` for a dry-submitted write) counts only the reasons the writer returns, so
the exception reached `tools/navguard.py`'s observer catch, which logs it at info and
lets the request through. Nothing counted it.

## Where encountered
Lane SPIDER9's reproduction
(`scratchpad/lanes/SPIDER9/r1/scripts/surrogate.py`), reproduced on 33b423e: each of
`{"a\ud800": 1}`, `{"action": "x\ud800"}` and `{"q": "\ud800"}` made `record_request`
raise. The key raised in `row_signature`'s encode, the selector value at the bind of the
signature prefix in the lookup, and the plain value at the bind of `body_json` in the
`INSERT`. Lane SURROGATE then found, on the same base
(`scratchpad/lanes/SURROGATE/scripts/importer.py`):
- `store_adapter.import_spider` raised `UnicodeEncodeError` on a `discovered_requests`
  row holding such a body: `_store_request` binds `jsonbody.encode_entries(...)`
  (`ensure_ascii=False`) into `form.entries`, and the leaf's name and value into
  `parameter`. `import_disco` reaches the same function with disco's capture, which
  keeps the body as sent.
- `core.redaction.redact_body` raised on a body with a sensitive field and a lone
  surrogate (`redact_json_body` re-encodes a rewritten body strictly);
  `redact_captured_body` turns that into the reason "redaction failed".

**Measured (2026-10-21, `scratchpad/lanes/SURROGATE/scripts/dom_surrogate.py`, Chromium
through Playwright, `set_content` only, no network):** `JSON.stringify({q:
'😀'.slice(0, 1)})` returns `{"q":"\ud83d"}`. A lone surrogate set into the
DOM (the title, a text node, an attribute) or returned by `evaluate` reaches Python as
U+FFFD. So the way a lone surrogate reaches fuzzlab from a browser is a JSON parser
decoding an escape, not a DOM string.

## What it caused to fail
- **Coverage, silently.** The request's inputs never reached the importer, so they were
  never tested. `requests_not_recorded`, the crawl's report line and `crawl_stats`
  showed nothing; the only trace was an info-level log line.
- **Dry-submitted and blocked writes** (FR-CRAWL-26, `_record_dry`): lost the same way.
- **The import.** Once such a row exists (a fix that stores it, or disco's capture
  today), `import_spider` and `import_disco` raised and the import failed as a whole.
- Nothing was wrongly reported.

## What the bug was identified to be
Text decoded from a target's JSON was treated as text that every UTF-8 sink accepts.
The writer bound raw `ensure_ascii=False` JSON text into SQLite and digested target
text with a strict encode. And the writer had no path for a failed write: its exception
went to a guard that logs, never to the count its caller keeps.

## Root cause analysis (Five Whys)
1. Why was `{"q":"\ud800"}` lost? `record_request` raised `UnicodeEncodeError`; `_observe`
   counts only returned reasons, and navguard's observer catch logged the exception at
   info and moved on.
2. Why did it raise? `json.loads` decodes `\ud800` to a lone surrogate. The writer wrote
   it raw (`ensure_ascii=False`) into text it bound into SQLite, and digested key paths
   with a strict `.encode("utf-8")`. Neither accepts a surrogate.
3. Why were those sinks written that way? `ensure_ascii=False` keeps stored non-ASCII
   text readable (forms phase 3, CC-CRAWL-0017), and the digests were written for
   well-formed text. BUG-0546's review round 1 knew the case: it gave `_selector_value`
   `surrogatepass` "so it is total", but swept that one function. `row_signature` and
   the GraphQL digest (in the same module) and the writer's binds kept the strict forms, while
   `apiop`'s docstring said "Everything here is total on its input".
4. Why did the exception lose the request instead of counting it? The writer's contract
   ("returns None when stored, else why not") had no reason for a failed write, and the
   one containment on the path (navguard's observer catch, PA-0086(2)) reports by a log
   line only. No count reads a log line.
5. Why did no test catch it? The writer's and `apiop`'s tests (FR-CRAWL-13, BUG-0546) use
   well-formed text. PA-0500(1) asks for a lone surrogate among the malformed inputs of
   "a function whose contract promises a sentinel", and was applied to URL parsers; the
   writer promises a reason and `apiop` promises totality, and neither was recognised as
   covered.

**Root cause:** text decoded from a target's JSON can hold a lone surrogate that no
UTF-8 sink accepts. The capture writer and its keying module wrote it into such sinks
(raw JSON text bound into SQLite, strict digests), under a totality claim tested only
with well-formed text. And the writer had no accounting path for a failed write, so the
exception went to a guard that logs instead of counting.

## Corrective action (CC-CRAWL-0061, FR-CRAWL-42; importer: an AUD entry, number requested)
- **`tools/apiop.py`.**
  - `storable_json(value)`: `json.dumps(value, ensure_ascii=False)` with every surrogate
    written as its `\uXXXX` escape (`.encode("utf-8", "backslashreplace")`). A surrogate
    can only stand inside a JSON string there, so the escape is the JSON spelling of the
    same code point, and `json.loads` gives back the value. For text without a surrogate
    it is byte-identical to the old form.
  - `_digest(text)`: SHA-256 of the UTF-8 with `surrogatepass`, byte-identical to the
    strict form for any other text. `row_signature`, the GraphQL digest of a document
    over the token cap and `_selector_value` use it.
  - `operation_key` returns `storable_json(...)`, so `signature_prefix` and every
    signature are text SQLite can bind.
- **`tools/spider.py::StorageManager.record_request`** is total. It calls
  `_record_request` (the work, unchanged but for the two texts below) and turns any
  exception into a rollback and the reason `write failed (<error class>)`, which its
  callers count (`_observe`: `requests_not_recorded` and the log line; `_record_dry`: not
  counted as captured). `body_json` is `apiop.storable_json(doc)`. The probe-marker
  scrub still runs on the raw `ensure_ascii=False` text: in the escaped text the hex
  digits of `\ud800` would end the token before a marker and hide it from the scrub
  (`(?<![A-Za-z0-9])`).
- **`tools/store_adapter.py::captured_request`** (the one import decision, for
  `import_spider` and `import_disco`) refuses a body with a field name or string value
  holding a lone surrogate, as "a field holding a lone surrogate (not storable text)",
  counted in `request_refused`. No store row can hold it (its form entries, parameter
  names and examples are SQLite text), and before this the import failed on it.
- **Store and wire contract.** No stored text or signature changes for a body that
  could be stored before (tested byte for byte against BUG-0546's formula). A row may now
  hold a `\udXXX` escape in `body_json` and `signature`: valid JSON, valid UTF-8, read
  back by `json.loads` as the body the app sent.
- **Tests** (`tests/test_capture_surrogates.py`, new; each defect test fails on 33b423e):
  - `test_a_body_holding_a_lone_surrogate_is_stored_losslessly`: a key, a selector value,
    a value, nested in an array; read back exactly; duplicates and new inputs keyed as
    any other text.
  - `test_the_operation_keys_and_digests_are_total_on_lone_surrogates`.
  - `test_a_marker_next_to_a_lone_surrogate_is_still_scrubbed`.
  - `test_a_write_the_store_refuses_is_counted_never_raised`: through `_observe`, a
    surrogate body is captured, and a write refused under another connection's lock is
    counted in `requests_not_recorded` with its reason.
  - `test_the_spider_import_refuses_and_counts_a_captured_lone_surrogate` (with the
    import's trace recorded) and
    `test_the_disco_import_refuses_and_counts_a_lone_surrogate_instead_of_failing`.
  - `test_text_without_a_surrogate_is_stored_and_keyed_byte_for_byte_as_before` (a
    regression guard; it passes on 33b423e too).
  - The guards below, and the strict xfail pinning the redaction instance.

## PA-0002 sweep (instances of the class)
Searched `fuzzlab/` for `ensure_ascii=False` (16 sites), for strict `.encode()` /
`.encode("utf-8")` (45 sites outside `labgen/` and `labs/`), and, with the AST guard
`tests/test_capture_surrogates.py::unsafe_text_binds`, for every SQLite `execute` /
`executemany` whose parameters hold such text directly, through a local name, or through
a function that returns it:
- `tools/spider.py::StorageManager.record_request`, `body_json` bound as
  `json.dumps(doc, ensure_ascii=False)`: fixed here.
- `record_request`'s marker scrub, `json.loads(spa.scrub_markers(json.dumps(doc,
  ensure_ascii=False)))`: not an instance. It is parsed back to a value and never bound;
  it stays raw on purpose (the scrub reads the raw text).
- `tools/apiop.py::operation_key`, whose `signature_prefix` is bound in the lookup and
  whose text starts every signature: fixed here.
- `tools/apiop.py::row_signature`, a strict encode of the shape text: fixed here.
- `tools/apiop.py::graphql_operations`, a strict encode of an over-cap document: fixed
  here.
- `tools/apiop.py::operation_selectors`, sorted `ensure_ascii=False` texts: not an
  instance. It is an internal sort key, parsed back, and its result is written through
  `operation_key`.
- `tools/store_adapter.py::_store_request`, which binds `jsonbody.encode_entries(...)`
  (`core/jsonbody.py:238`, `ensure_ascii=False`) into `form.entries`, and a leaf's name
  and example into `parameter`: fixed here, at the import decision. `captured_request`
  refuses the body before `_store_request` runs, for both importers; `encode_entries` has
  no other caller. The guard keeps `_store_request` as a reviewed allowance that names
  this reason.
- `core/redaction.py::redact_json_body`, `json.dumps(new, ..., ensure_ascii=False)
  .encode("utf-8")`: an instance. Its output is bound into SQLite by the proxy history
  (body table) and by `core.http`'s exchange log, and it gates the spider's capture. A
  body with a sensitive field and a lone surrogate raises there. The proxy history
  contains it (`OMIT_FAILED`); `core.http.HttpClient.send` raises out of the send when a
  store is attached; the capture refuses it as "redaction failed" (counted, not
  stored). Owner: the storage boundary, `core/redaction.py` (CORE); a fix there needs a
  CC-CORE number this lane does not hold. Pinned by the strict xfail
  `tests/test_capture_surrogates.py::test_the_redaction_boundary_rewrites_a_body_holding_a_lone_surrogate`.
- `core/jsonbody.py::body_for` and `body_with`, a strict encode of a probe body: not an
  instance. The bytes go to a target and are never bound. Their values come from stored
  entries (SQLite text, which cannot hold a surrogate) and payloads, and `body_with`
  turns the error into `JsonPlacementError`.
- `web/sitetree.py`: `NodeKey.dump` (`ensure_ascii=False` and a strict length encode),
  `_pack` and the parameter group's sort key: not instances. Their values are read from
  SQLite text, which is valid UTF-8, or from evidence JSON that `_encodable` and
  `_bounded_str` check first (CC-UI-0503); the sort key is never bound.
- `disco/capture.py::CaptureRecord.to_json` (`ensure_ascii=False`, a JSONL file): not an
  instance. Every text field is decoded with `errors="replace"` or latin-1, so none holds
  a surrogate; its `redact_body` call is the redaction row above.
- `session/browserlogin.py` (`ensure_ascii=False` at line 127 and its `.encode()` calls):
  not an instance. They match the operator's own secret in captured bytes and are never
  bound.
- The other strict encodes (`disco/fingerprint.py`, `ml/persist.py`, `core/config.py`,
  `ml/holdout.py`, `tools/observe.py::_tag`, `core/credentials.py`,
  `session/manager.py`, `web/projects.py`, `web/results.py`, `web/app.py`,
  `disco/runner.py`, `tools/probesender.py`, `oracle/strategies.py`, `proxy/redact.py`,
  `core/dedup.py`): not instances. Each encodes ASCII text (`json.dumps` with its ASCII
  default), the operator's own values, a payload sent to a target, or text read back
  from SQLite. None is target-decoded JSON text bound into SQLite.
- Direct binds of target text that no JSON parser decoded (the spider's page titles and
  contents, its form records): not instances. Measured, Playwright hands Python a DOM
  string's lone surrogate as U+FFFD, and response bodies are decoded with
  `errors="replace"`.
- `labgen/conformance/django_live_boot.py::_seed_db`, a strict encode bound as a digest:
  not an instance. It is a lab's constant seed password (the guard's second reviewed
  allowance).
- `tools/observe.py::observe_spider` with `core/trace.py`, which carry a captured field
  name into the trace: not an instance. Event bodies and attributes are written by
  `json.dumps` with its ASCII default, and the spider import test records the import's
  trace with a surrogate field name.

## Recurrence review
Checked `docs/bugs/` for `surrogate`, `UnicodeEncodeError`, `encode` and failures lost to
a guard that logs, and `docs/PREVENTIVE_ACTIONS.md` for totality, encoding and failure
accounting:
- **BUG-0500 / PA-0500(1)**: `canonical_origin` promised a sentinel and raised on a
  malformed authority; PA-0500(1) names "a lone surrogate" among the inputs a total
  function's tests must feed. Same root cause: a totality claim over target text tested
  only with well-formed text. **A recurrence of the root cause.**
- **BUG-0546** (its review round 1): it made `_selector_value` total with `surrogatepass`
  and left the module's other strict encodes and the writer's binds as they were. A
  sweep by function, not by mechanism (PA-0002). **The same defect's near miss.**
- **BUG-0085 / PA-0086(2)**: "every per-unit handler contains its own failures and
  reports them". The observer catch contained this failure but reported it by a log line
  only. **A recurrence of the accounting half.**
- BUG-0548 / PA-0548(3): a loss "is counted where the run's operator reads it", written
  for queues. The same principle, not followed here.
- BUG-0107 / PA-0108(2): malformed rows are quarantined and counted by their reader. The
  importer now does that for these rows. Related, not a recurrence.
- CC-UI-0503 (no bug): the site map's `_bounded_str` and `_encodable` already knew that a
  lone surrogate cannot be bound, as private checks in the web layer, under no rule.

## Prior-preventive-action failure analysis
- **PA-0500(1)** (from BUG-0500) did not prevent this:
  - **Too narrow.** It covers "a function whose contract promises a sentinel for
    unusable input", and its example grammar is a URL. A writer that promises a reason,
    and a keying module that promises totality in its docstring, were not read as
    covered.
  - **Not enforced by mechanism.** Its tests are `origin_of`'s and the site map's.
    Nothing feeds a lone surrogate to any other function that claims totality.
- **PA-0086(2)** (from BUG-0085) did not prevent the silent loss:
  - **"Reports" was undefined.** The navguard observer catch logs, which reads as
    reporting, but no count the operator reads changes.
  - **Not enforced here.** Its tests are the proxy's.
- **BUG-0546's corrective action** (PA-0546, review round 1) fixed the case in one
  function. Its PA-0002 sweep went by the symptom (the selector's digest), not by the
  mechanism (every strict encode and every bind of `apiop`'s and the writer's text).
- **PA-0546(3)** ("a merge or dedupe that feeds a consumer judging the whole item is
  checked against that consumer before it ships") was worded for a merge or dedupe. This
  fix lets new rows into a table, and the importer failed on them. Without the importer
  check this lane added, the fix would have turned a silent loss into a failed import.

## Preventive action (PA-0554)
Strengthens PA-0500(1), PA-0086(2) and PA-0546(3):
1. **Text decoded from a target's JSON may hold a lone surrogate.** A writer that binds
   such text into SQLite writes each surrogate as its JSON escape (`apiop.storable_json`;
   never `ensure_ascii=False` text into a bind). A digest or key of such text encodes
   with `surrogatepass`, never a strict `.encode("utf-8")`. A totality claim over target
   text is tested with a lone surrogate in each position its grammar has (a key, a
   value, a selector value, nested, a GraphQL document over the token cap).
2. **A writer of target-derived rows never raises to its caller.** What it cannot store
   comes back as a reason, and its caller counts the reason where the run's operator
   reads it. An exception guard that only logs is containment, not the report PA-0086(2)
   asks for.
3. **A fix that lets new rows into a table is run through every reader of the table on
   those rows before it ships.** A reader that cannot hold them refuses and counts them;
   it never fails on them.
4. **Enforced by** the defect tests above, a whole-package AST guard (no SQLite bind
   takes `ensure_ascii=False` text or a strict encode, directly, through a local name or
   through a function that returns it; two reviewed allowances), a keying guard (no
   strict encode in `tools/apiop.py` or the capture writer), both proven on synthetic
   offenders (BUG-0554's writer, `row_signature` and the `encode_entries` shape among
   them), and a guard over this sweep's rows (PA-0546(5)).
   - The guards' limits: the bind guard follows one level of functions, by name, and
     names assigned in the same function. It cannot see unsafe text carried in through
     an attribute, a container built elsewhere, or a deeper call chain. The keying guard
     covers `tools/apiop.py` and the writer only.
