# Intercepting Proxy — Change Control Log

Component code: **PROXY**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PROXY-0032 — The age-batch test waits for the history writer's counter, not its rows; a guard over every history test (BUG-0560, PA-0560) (2026-10-22)
- Change (tests only; no product code):
  - **`tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age`:**
    - The test now polls `h.stats["written"] == 2` as a presence claim (PA-0511).
      This is the last of the writer thread's publications for a batch.
    - Before the fix, it waited until the rows were visible and read the counter at
      once. The writer moves the counter only after the rows' commit and the trace
      events' commit, so that read could fall between them.
    - After the poll, the test asserts the rows (now the exact URLs in order, not a
      count) and the batch sizes. Both are in place before the counter moves.
  - **The guard (new), in the same module:**
    - `_PUBLISHED` lists the writer's publications in order: rows, trace events,
      `stats`, `run_metrics`.
    - `_read_after_visible_offenders` flags a read of a later publication after a poll
      on an earlier one, up to a `close`, `aclose`, `flush`, `drain` or `join`.
      Submit-side counters are exempt. A poll is a call named `*until*` or a loop that
      sleeps. The module's own helpers are followed by name.
    - `test_no_history_test_reads_a_later_publication_than_it_waited_for` runs the
      guard over every test module that drives `HistoryWriter` or `ProxyController`
      (21 modules). It checks it is not vacuous by requiring polls on publications in
      this module and in `test_proxy_trace.py`.
    - `test_the_read_after_visible_guard_on_synthetic_code` proves the guard: it flags
      BUG-0560's own lines and four other offenders, and passes five safe shapes (the
      fix among them).
- Impact (other components / project):
  - None on behaviour. `fuzzlab/proxy/history.py` is unchanged.
  - The UI component's history tests (`test_web_*` that drive `ProxyController`) are
    now scanned by the guard. They pass it unchanged.
- Risk (level; mitigation or accepted-risk justification):
  - Low. The change is to tests only. The fixed test still proves that a batch is cut
    by age: nobody flushes, and the counter reaches 2 well before the 30 s poll
    bound, with `flush_seconds` at 0.2 s.
  - The guard's limits are stated in BUG-0560. It knows only this writer's
    publications, and it is lenient on any `close`/`flush`/`drain`.
- Deliverables:
  - [x] the test fixed; proven by delay injection — done. Plain Python, a 0.3 s delay
    in `HistoryWriter._trace` (after the rows' commit, before the counter):
    - the pre-fix test failed 5 of 5 (and 1 of 5 with no delay, on the first run in a
      process);
    - the fixed test passed 5 of 5 with the delay and 5 of 5 without.

    Log: `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/age-race/age_race_proof.log`.
  - [x] the natural window measured — done. `_trace` on a writer's first batch takes
    6.9-9.3 ms for the first writer in a process (a lazy import and a new recorder)
    and 1.2-5.6 ms after that, against a 10 ms poll (`.../age-race/trace_window.log`).
  - [x] PA-0002 sweep of the 21 history-test modules: one instance, this test (BUG-0560
    "Sweep") — done.
  - [x] guard and its synthetic proof. On the pre-fix file it reports exactly the
    BUG-0560 line (`:237`) — done.
  - [x] BUG-0560 — done. The ERROR_LOG line, PA-0560, the CHANGELOG line and the
    failure-record entry are handed to the orchestrator for the shared docs — done.
  - [ ] `scripts/verify_change.py` on the merged tree — todo. It is the orchestrator's
    step; this lane ran the one targeted pytest invocation it was given.
- Effectiveness (assessed 2026-10-22): verified offline.
  - The delay injection that failed the pre-fix test every time passes the fixed test
    every time.
  - The guard finds 0 offenders in the 21 modules after the fix and exactly one before
    it.

### CC-PROXY-0031 — The request target and every URL-bearing header value pass the URL redactor, with or without a query (FR-PROXY-11, BUG-0556 review rounds 1-2) (2026-10-22)
- Placement: lane REDACTURL (item GAP-VALUES); a caller of CC-CORE-0076's owner. Review
  round 1 on branch `lane/REDACTURL-r1` from c3a13f7, review round 2 on
  `lane/REDACTURL-r2` from f939778. The number is the coordinator's (assigned at round
  2; the round-1 text was handed over unnumbered).
- Change (`fuzzlab/proxy/redact.py` only):
  - *(Review round 1.)* `redact` passed the request target, `Location`,
    `Content-Location` and `Refresh`'s `url=` to `core.redaction.redact_url` only when
    they held a `?`; now every one is passed whole. `redact_url` returns a URL holding
    no value byte-identical, so a clean message is unchanged.
  - *(Review round 2, N6.)* Four neighbouring paths in the same function, all older
    than BUG-0556:
    - **Duplicates:** the loop read each URL header's first value only
      (`RawMessage.get`), and a changed one went through `with_header`, which replaced
      every duplicate by it. Now every header line is read and a changed value is
      rewritten in place (`_redact_header_value`), keeping the order and every other
      line byte-exact; `_original_name` is gone.
    - **Which headers:** `Referer` (a browser sends the full same-origin URL, so a
      URL-rewritten app's session id came back in the next request's raw head), `Origin`
      (a well-formed one holds no path: byte-identical), `Destination`, `X-Original-URL`,
      `X-Rewrite-URL`, `Ping-From`, `Ping-To`, any other header whose value starts as a
      URL (`_URL_VALUE`: a scheme's `://` or `/`), and each `<URI>` of `Link` join
      `Location` and `Content-Location`.
    - **`Refresh`:** read as the HTML shared declarative-refresh steps read it
      (`_redact_refresh`: the delay, an optional `;` or `,`, an optional `url` `=` with
      any spacing and case, then the URL, quoted or to the end); only `url=` without
      spaces was read.
    - **The request target:** `_target_span` reads it after the method and its run of
      spaces or tabs, up to the run before a final `HTTP/` version (or the line's end);
      `msg.target` (`split(b" ")[1]`) gave an empty target for a doubled space or a tab,
      and cut a raw space's target short.
  - Module docstring updated.
  - *(r6, 2026-10-22, branch `lane/REDACTURL-r6` from 144d234; BUG-0556 "r6 (layered on
    the pushed redactor)", with CC-CORE-0076.)* `redact` runs 7393c90's own `redact`
    first (`core.redaction_floor.redact`, frozen verbatim with 7393c90's
    `RawMessage`), then the walk above (`_walk`, the 144d234 code) on its output only.
    The check of 144d234 found three classes the pushed `redact` redacted and the walk
    kept: R3, `Refresh`'s every `url=` run, quotes and the tail after them included (the
    walk read only the quoted URL, and only the first `url=`); A1, a URL `urlsplit`
    rejects in the request line, `Location`, `Content-Location` or `Refresh` (7393c90
    raised, and the history writer stored the flow `OMIT_FAILED` with its URL cut at the
    `?`; the walk kept the secret); A2, a duplicate `Location` / `Content-Location`
    (7393c90's `with_header` collapsed it into the value it rewrote). Each is redacted
    again by the floor; `_redact_refresh` and `_redact_header_value` call the walk
    (`_walk_names`), never `redact_url` (its floor has run on the whole message). Tests:
    `tests/test_redaction_nested.py::test_r6_r3_a_quoted_refresh_url_keeps_nothing_the_pushed_tree_redacted`
    (4), `::test_r6_a1_a_url_urlsplit_rejects_is_withheld_by_every_consumer` (3, the
    proxy's four places among the consumers),
    `::test_r6_a1_proxy_history_withholds_a_flow_whose_url_its_floor_rejects` and
    `::test_r6_a2_a_duplicate_url_header_keeps_nothing_the_pushed_tree_dropped` (4), each
    failing on 144d234 at its own assertion. Pinned (owner CORE, family (a)): a name the
    floor's `urlsplit` reading joins across a removed tab in the request line, `Location`
    or `Content-Location`
    (`tests/test_redaction_residual_pins.py::test_a_name_joined_by_a_tab_cr_or_lf_in_the_floors_output_is_redacted`).
  - *(r6 review, 2026-10-22, branch `lane/REDACTURL-r6` after 3615cfb; BUG-0556 "r6
    review", R3.)* **Correction: a flow whose URL the floor rejects is not "never
    stored unredacted".** The r6 Impact line said the history writer stores such a flow
    `OMIT_FAILED` "visible, never unredacted, as on 7393c90", and the r6 sub-bullet above
    said "with its URL cut at the `?`" without saying what that keeps. What
    `_prepare_contained` stores is every body `OMIT_FAILED` and the flow's URL cut at
    its first `?` (`rec.url.split('?', 1)[0]`), in `flow.url` and in its `errors` line:
    whatever precedes that `?` is stored as received -- a `;name=value` path parameter
    (`http://[h/app;jsessionid=<hex>/p.php?u=1` keeps the session id), a query-shaped
    fragment written before the `?`, a path segment. 7393c90 stores the same (its
    fallback is this code, unchanged), so under the owner's rule it is **pinned, not
    fixed**: family (d), `tests/test_redaction_residual_pins.py::test_proxy_history_stores_no_path_parameter_of_a_flow_its_floor_rejects`
    (strict, `raises=AssertionError`, owner PROXY; 4 cases: xfail on r6 and on 7393c90,
    XPASS on 144d234, whose walk did not raise and stored `;jsessionid=__REDACTED__`).
    Measured over the four corpora (`scratchpad/lanes/REDACTURL/r6c/famd_compare.txt`,
    406 005 URLs): the writer falls back on the same 15 190 URLs on r6 and on 7393c90
    (none on 144d234), stores a secret in 651 of them on both (225 in a path parameter,
    411 in a path segment, 15 in a fragment), 183 of which 144d234 redacted (171 path
    parameter, 12 fragment); 0 leak at r6 that 7393c90 redacted. Candidate rule, not
    built: the fallback cuts the URL at its first `;`, `?` or `#`. The writer's
    docstring, which made the same claim (7393c90's text), now says what is stored.
  - *(At the merge, 2026-10-22, the merge 5e80ea2 of `lane/REDACTURL-r6` 08eb900, the
    coordinator's records round, owner-approved; BUG-0556 "At the merge", R3. No code
    of this component changed.)*
    - **R3(a):** `redact`'s docstring said "the history writer withholds the flow"; it
      now says what `_prepare_contained` stores (every body `OMIT_FAILED`, the flow's own
      URL cut at its first `?`, what precedes it as received). The test
      `tests/test_redaction_nested.py::test_r6_a1_proxy_history_withholds_a_flow_whose_url_its_floor_rejects`
      named above is renamed
      `::test_r6_a1_proxy_history_stores_a_flow_its_floor_rejects_bodies_omitted_query_cut`,
      which is what it asserts.
    - **R3(b), pinned:** the header-triggered family (d) case -- a flow whose own URL
      parses, with a `Location`, `Refresh` (`url=`) or `Content-Location` value
      `urlsplit` rejects that holds a `?` (`http://[h/x?y=1`), makes the floor raise and
      the writer store the flow's own `;jsessionid=<hex>` path parameter (or a fragment
      before the `?`) raw; measured the same on 7393c90 and 08eb900.
      `tests/test_redaction_residual_pins.py::test_proxy_history_stores_no_path_parameter_of_a_flow_a_header_value_makes_it_fall_back`
      (strict, `raises=AssertionError`, owner PROXY, 4 cases, each failing at its leak
      assertion on the merge, 7393c90 and 08eb900); the fix check's counts in its reason
      (67 371 fallbacks, 14 082 storing a secret on 7393c90 too, 3 517 redacted by
      144d234; the trace event 1 055 / 45). FR-PROXY-11 amended in place.
- Impact (other components / project): proxy history's stored raw request and response
  and their full-text index no longer keep a `;jsessionid=` (or any sensitively named)
  value in a URL with no query (round 1), in a duplicate URL header, `Referer`, `Origin`,
  `Link`, a custom URL header or a spaced `Refresh`, or in a malformed request line
  (round 2), which `flow.url` already redacted. No schema change; the forwarded bytes
  are untouched (only the persisted copy).
- Risk (level; mitigation or accepted-risk justification): low. Cost: one `redact_url`
  call per URL-bearing header value and per request target, which returns at once for
  a URL with no `?`, `;` or `#`. A header whose value merely starts with `/` and is not a
  URL is walked too; only a sensitively named value in it changes. Not covered: a URL
  inside another structured header's grammar (a CSP `report-uri`, `Reporting-Endpoints`,
  `Report-To`'s JSON) -- BUG-0556 residual R4, pinned by the strict xfail
  `tests/test_redaction_nested.py::test_proxy_history_redacts_a_url_inside_a_structured_header`
  -- and an obs-folded header continuation line (obsolete in HTTP/1.1, RFC 9112 §5.2).
  *(r6:)* a duplicate `Location` or `Content-Location` is collapsed again when the floor
  rewrites one (as on 7393c90; the walk still rewrites every other URL header's every
  value in place), and a flow whose URL `urlsplit` rejects is stored `OMIT_FAILED` again
  (visible, never unredacted, as on 7393c90). Cost: the pushed `redact` runs once more
  per message before the walk. *(r6 review, R3: "never unredacted" was wrong -- such a
  flow's URL is stored cut at its first `?`, keeping a path parameter or fragment before
  it, as on 7393c90; pinned, family (d), see the r6 review sub-bullet.)*
- Deliverables:
  - [x] the `?` gates removed (round 1) — done
  - [x] every value of every URL-bearing header, `Refresh` and `Link` parsing, the
    whitespace-tolerant target (round 2) — done
  - [x] FR-PROXY-11 amended in place (both rounds) — done
  - [x] `tests/test_redaction_nested.py::test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query`
    (fails on c3a13f7 on its own assertion) and
    `::test_proxy_history_redacts_every_url_bearing_header_and_any_request_line` (fails
    on f939778 on its own assertion); R4's strict xfail — done
  - [x] *(r6)* `redact` layered on the frozen pushed `redact`; FR-PROXY-11 amended in
    place; the R3, A1 and A2 tests (each failing on 144d234 at its own assertion) —
    done
  - [x] *(r6 review)* family (d) pinned (owner PROXY); FR-PROXY-11 and the writer's
    `_prepare_contained` docstring corrected to what is stored — done
  - [x] *(At the merge)* `redact`'s docstring corrected; the A1 history test renamed;
    the header-triggered family (d) case pinned; FR-PROXY-11 amended in place — done
- *(After the push: the merge's check, 2026-10-22.)* FR-PROXY-11 corrected: since r6 a message passes the pushed tree's `redact` (the floor) and then the walk, so `redact_url` is no longer called on every value; the floor reaches its own `redact_url` for the target and the `Location` / `Content-Location` values holding a `?` and for `Refresh`'s `url=` runs in such a value. No behaviour change. BUG-0556, "After the push".
- Effectiveness (assessed 2026-10-22): the round-1 probe (`rev1probe/proxy_probe.py`)
  found the canary in `body`, `flow_fts` and `flow_fts_content` on c3a13f7; on f939778
  the round-2 test's messages (duplicates, `Referer`, `Origin`, `Link`, a custom header,
  three `Refresh` spellings, a doubled space, a tab and a raw space in the request line,
  a nested URL's userinfo in the target and `Location`) kept it in `redact()`'s output;
  on the revision none does, in the output or in a `HistoryWriter` store, and a clean
  message is byte-identical. *(r6:)* the check's corpus through the proxy's request
  line, `Location`, `Content-Location` and `Refresh` (`scratchpad/lanes/REDACTURL/r6/
  checkwork/diff.r6_vs_7393c90.txt`): 0 URLs kept that 7393c90 redacted or withheld
  (144d234: 878 per place, all A1); the "r6" proxy cases fail on 144d234 and pass on
  the revision (`r6b/r6_tests_plain_{t144d234,wt}.log`).

### CC-PROXY-0030 — The flow history is written off the proxy's event loop (BUG-0550, FR-PROXY-404) (2026-10-21)
- Change:
  - **`proxy/history.py`:** `HistoryWriter.submit(rec)` (new) does bounded work on the
    calling thread: it admits the flow into a queue and returns. The first call starts
    the writer thread (`_Pump`), which opens its own `Store` on the writer's file
    (`create=False`) and builds an inner `HistoryWriter` on it; that thread alone does
    every redaction, hash, insert, commit and trace event, in submission order.
    - Batches are cut by count (`batch_size`), bytes (`flush_bytes`, `FLUSH_BYTES` 4 MiB)
      or age (`flush_seconds`, `FLUSH_SECONDS` 0.5 s), or at once for a `flush` or
      `close`; a transaction holds at most `BATCH_MAX_FLOWS` (500) flows and
      `flush_bytes` plus the flow that crosses it.
    - The queue is bounded by `max_pending_flows` (10,000) and `max_pending_bytes`
      (256 MiB) waiting or being written; one larger flow is admitted only into an empty
      queue. A flow that does not fit is dropped from the history, counted
      (`HistoryWriter.stats`), logged (`fuzzlab.proxy.history`) and written to
      `run_metrics` (`history_*`) at once; the counters are rewritten at most once a
      second otherwise, and at close.
    - A batch is tried `WRITE_ATTEMPTS` (3) times, `RETRY_SECONDS` (0.2 s) doubling,
      then counted `failed` and logged. `_write` (split out of `flush`, with
      `_prepare_batch` and `_write_prepared`) rolls back the transaction it opened on
      any failure, a failed commit included, so a retry never duplicates a flow.
    - `flush()` on a writer with a thread waits until everything submitted before it is
      written or counted. `close(run_end)` writes everything pending, then the run's
      end and the counters on the thread's connection, within `CLOSE_TIMEOUT` (60 s;
      the rest counted `unwritten`); idempotent. A writer dropped without `close` is
      drained (`weakref.finalize`), and so is one open at interpreter exit (`atexit`,
      10 s each). A store the thread cannot open (no file) counts every flow and logs.
    - `record()` stays synchronous, now also cut by `flush_bytes`; on a writer that has
      a thread it hands the flow to the thread (one writer of a run's flows).
    - `aclose(run_end)` (new, review round 1, R3): `close` for a caller on an event
      loop. The writer thread's drain is awaited through `asyncio.to_thread`; a writer
      with a file store and nothing of its own on the caller's connection starts its
      thread first, so the run's end and the counters are written there too. A writer
      that wrote synchronously on the caller's thread, or whose store is in memory, is
      closed on the caller's thread, where it wrote (PA-0023). `_close_own` and
      `_thread_path` are split out of `close` and `_start_pump`.
  - **`proxy/cli.py` (review round 1, R1):** a SIGTERM is a requested stop like Ctrl-C:
    `_serve` waits on an event that `loop.add_signal_handler(SIGTERM, ...)` sets
    (`_stop_on_sigterm`), so the loop ends, the server stops, and `main`'s `finally`
    closes the writer, which writes every queued flow and the run's end (`complete`).
    Before, SIGTERM's default action ended the process with the queue unwritten and
    uncounted.
  - **`web/proxycontrol.py::ProxyController.stop` (UI component; review round 1, R3):**
    `await self._history.aclose(run_end="complete")` in place of a `close` on the web
    loop. The UI component's change-control entry needs a CC-UI number that was not
    pre-assigned to this lane; its text is in the lane's `doc_texts.md` (§8).
  - **`proxy/server.py` (`ProxyEngine._record`, lines 148-168 at `c483dc1`):** calls
    `history.submit`, and takes the method, target and status from each message's first
    line (`_first_line_of`, new, right below it), never parsing or copying a body on the
    loop.
  - **Tests:** `tests/test_proxy_history_writer_thread.py` (new);
    `tests/test_proxy_trace.py` waits for the writer where it read the store straight
    after a request, and its module fixture closes its writer;
    `tests/test_proxy_rules_and_scope.py`'s fake history gains `submit`. Review round 1
    adds to the new file: `test_a_sigterm_stops_the_recording_proxy_like_ctrl_c_and_writes_every_answered_flow`
    (R1: a real `fuzzlab proxy --store` process on a 0.2 s store, ten answered flows,
    stopped by procutil's supervisor with SIGTERM), `test_a_failed_commit_is_rolled_back_and_the_retry_writes_once`
    (R2: the writer thread's first `RELEASE history_flush` fails),
    `test_stopping_the_web_proxy_drains_its_history_off_the_web_loop` (R3: the loop
    runs while the stop's drain is held), and the whole-package AST guard
    `test_no_event_loop_path_blocks_on_a_history_writer` with
    `test_the_history_loop_guard_on_synthetic_code` (four offenders, the pre-fix line
    among them, and four near-misses).
  - *(Review round 2 of the merge integration, 2026-10-21; lane INTEG, branch
    `integ/proxy-r2` from the local merge stack 4e0c2c6; finding P2-3, owner-approved.)*
    **The exit drain covers every started writer and is not stopped by one**
    (BUG-0550 "Review round 2"). `_Pump.__init__` added the pump to `_LIVE` before
    `thread.start()`. A thread that could not start ("can't start new thread") left a
    pump in `_LIVE` whose `close` raised "cannot join thread before it is started" in
    `_close_live_pumps` at exit, and that ended the loop, so the writers after it were
    never drained.
    - Now `_Pump.__init__` starts the thread first and joins `_LIVE` only once it has
      started; `submit` still raises the start failure to its caller (the engine counts
      it, BUG-0543 I1).
    - `_close_live_pumps` closes each live pump in its own `try`, and reports one that
      fails (`_report`: error class and run id) before going on.
    - Test: `tests/test_proxy_history_writer_thread.py::test_a_writer_thread_that_cannot_start_never_stops_the_exit_drain`.
      The writer thread's start is refused; the refused pump must not be live; a live
      writer whose close fails is added; `_close_live_pumps` must return and drain
      another writer's three pending flows. The test's own `_LIVE` keeps it from
      draining other tests' writers.
  - *(Merge integration of review round 2, 2026-10-21; coordinator, at the merge of
    integ/proxy-r2.)* The round-2 check found one more stop path a writer thread that
    cannot start breaks: `HistoryWriter.aclose` (the web proxy's stop) starts the
    thread for a writer that buffered flows with `record`, and the start's
    `RuntimeError` left `aclose`, so the buffered flows and the run's end were never
    written. `aclose` now catches it, reports it (`_report`, warning) and closes on the
    caller's thread, as a writer with no thread does (PA-0550(9)). Test:
    `tests/test_proxy_history_writer_thread.py::test_a_stop_whose_writer_thread_cannot_start_still_writes_what_it_buffered`.
- Impact (other components / project):
  - **Callers swept** (`grep HistoryWriter` over `fuzzlab/`): `proxy/cli.py` and
    `web/proxycontrol.py::ProxyController` build `HistoryWriter(batch_size=1)` and pass
    it to the engine: the engine's `submit` starts the thread. The CLI closes it after
    its loop ends, on Ctrl-C and, since review round 1, on SIGTERM (`kill`, the web
    UI's Stop of a `proxy` job through procutil's supervisor, a service manager). The
    web proxy's `stop` (lifespan shutdown) closes it through `aclose`, the drain off the
    web loop (review round 1). `proxy/repeater.py` and
    `web/proxycontrol.py::RepeaterController` use the synchronous `record`, unchanged.
  - **Every stop path of a recording process** (review round 1, R1): Ctrl-C and SIGTERM
    drain (`close`); interpreter exit drains (`atexit`, 10 s); a writer dropped without
    `close` drains (`weakref.finalize`). SIGKILL, a crash, or a second signal while the
    drain runs, end it: what is still queued is lost, up to the queue bound. The web
    UI's `proxy` job is stopped by procutil's supervisor: SIGTERM, then SIGKILL after
    its grace (`DEFAULT_GRACE_S`, 5 s), so a backlog that takes longer than that to
    write is cut there (stated residual, UI component: BUG-0550).
  - **Consumers of what changed** (PA-0138(3)): flows and their trace events appear a
    batch later, not inside the request (with `batch_size=1`, as soon as the thread
    takes the flow; else within `flush_seconds`). `web/proxyview.py` and the diagrams
    read committed rows and poll; `tests/test_proxy_trace.py`'s two immediate reads now
    wait. The UI component's `web/app.py` repeater routes are not changed; their
    blocking sends on the web loop are pinned by a strict xfail (BUG-0550 sweep).
  - **Store contract:** additive `run_metrics` keys `history_*` for a proxy run (no
    schema change). The Diagnostics page lists them with the other keys. No wire change.
  - **A history failure no longer reaches the client:** before, a store error in
    `_record` answered the client 502 although its response had arrived.
  - *(Review round 2:)* every process that records (`fuzzlab proxy`, the web proxy)
    drains every started writer at interpreter exit, even when one writer's close
    fails. A writer whose thread never started holds no flows (its `submit` raised), so
    there is nothing of it to drain. No contract change.
- Risk (level; mitigation or accepted-risk justification): medium. A second store
  connection per proxy run, owned by one thread (PA-0023), on the same WAL store; the
  outer connection is not touched by the thread. Durability window (corrected in review
  round 1; it read "a crash loses at most ... one flow at `batch_size=1`"): a flow's
  response goes back before the flow is written, so a hard kill (SIGKILL, also the
  supervisor's after its grace) or a crash loses whatever is still queued, up to the
  queue bound (10,000 flows, 256 MiB), uncounted at that moment; the live `history_*`
  counters show `accepted` against `written` as of their last rewrite (at most a second
  old while the writer is not stuck in one write). On an idle store the queue is near
  empty; on a slow one it grows, which is the point (the traffic no longer waits for
  the store). A requested stop (Ctrl-C, SIGTERM, the web proxy's stop) drains, within
  `CLOSE_TIMEOUT`. Overflow drops history, never traffic, and is counted and reported;
  the bounds are generous. Since review round 1 the web proxy's stop drains off the web
  loop. *(Review round 2:)* low for the change itself: a pump is registered a moment
  later, after its thread started. A thread that finishes first (a store it cannot
  open) is then a live entry whose `close` joins a finished thread, which returns at
  once. The exit drain still waits up to 10 s per stuck writer, as before.
- Deliverables:
  - [x] `proxy/history.py` writer thread, batching, bounds, counters; `proxy/server.py`
    `_record` — done
  - [x] tests: `tests/test_proxy_history_writer_thread.py`, each new behavioural test
    shown failing once on the pre-fix code — done
  - [x] BUG-0550 (RCA, recurrence review, prior-PA failure analysis, sweep, latency
    before/after); FR-PROXY-404 added, FR-PROXY-3/12/13 and NFR-PROXY-nonblocking
    edited in place — done
  - [x] CHANGELOG, ERROR_LOG, PA-0550, ARCHITECTURE §11 and failure-record texts in the
    lane's `doc_texts.md` for the merge — done
  - [x] review round 1 (R1 SIGTERM drain, R2 a test at the commit, R3 the web stop off
    the loop with a whole-package guard): code, tests, BUG-0550 "Review round 1",
    FR-PROXY-404/FR-PROXY-13/NFR-PROXY-nonblocking edited in place, PA-0550(5)-(7) and
    the failure-record texts in `doc_texts.md` — done
  - [ ] the UI component's change-control entry for `ProxyController.stop`: its text is
    in `doc_texts.md` §8; a CC-UI number was not pre-assigned to this lane — todo (the
    orchestrator, at merge)
  - [x] *(Review round 2 of the merge integration, P2-3)* `_Pump` registered only once
    its thread started; `_close_live_pumps` contains each writer's failure. A test fails
    on 4e0c2c6's `history.py` (one run) and passes now. FR-PROXY-404 was edited in
    place, BUG-0550 has a "Review round 2" section, and the PA-0550(9) text is in lane
    INTEG's doc texts — done
- Effectiveness (assessed 2026-10-21): verified offline. Latency through the real proxy
  under a slow store (+50 ms per write): p50/p95 433/726 ms → 20/42 ms, the loop's
  longest stall 437 → 23 ms; with the store's write lock held 2.0 s elsewhere, the
  longest stall 2077 → 33 ms; 200 of 200 flows stored in every run (BUG-0550's table).
  Targeted run (12 test files, one invocation): 227 passed, 1 xfailed (the strict pin
  of the web repeater, BUG-0550 sweep). On the pre-fix code (`c483dc1`, a scratch copy,
  one invocation) the new file gave 20 failed, 7 passed, 1 xfailed: the blocked-write
  test answered both later requests only after the hold (`[False, False]`); the loop
  guard flagged the pre-fix `history.record` call; the batching, bound, failure and
  close tests failed on the API the pre-fix writer lacks; the 7 passing are the guards'
  synthetic-offender cases and the repeater check's own shape test. The first-line test
  failed there on its fake's missing `record`; with the fake given both names, a direct
  call fails on its byte assertion on the pre-fix code and passes now
  (`scratchpad/lanes/HIST25/prefix_firstline.out`). The harness run on the committed
  tree is reported with the lane.
  **Review round 1:** the writer-thread file, one invocation: 39 passed, 1 xfailed (with
  13 other proxy, web-proxy and guard files beforehand: 265 passed, 1 xfailed, the only
  failure then being the new SIGTERM test's own assertion on an HTTP/1.0 status line,
  corrected). Each new test shown failing once, one invocation, on a scratch copy of
  this commit with `proxy/cli.py` and `web/proxycontrol.py` from `7fdd869` and
  `_write`'s release and commit moved back outside the rollback
  (`scratchpad/lanes/HIST25/r1/prefix_proof.out`): 4 failed, 8 passed. The SIGTERM test
  stored 0 of 10 answered flows; the commit test stored `[p0, p0, p1]`; the web-stop
  test's loop got control back only after the held write (`False`); the guard flagged
  `web/proxycontrol.py:stop:102:close`. The 8 passing are the guard's synthetic cases,
  which do not read the product code. The commit test passes on `7fdd869` itself, whose
  `_write` is unchanged here: that code was right, its test was missing.
  *(Review round 2 of the merge integration, 2026-10-21; P2-3:)*
  - Proof on the pre-fix code: one pytest invocation on a scratch copy of 4e0c2c6's
    product files with the round's test files (`scratchpad/lanes/INTEG/proof_r2.log`).
    `test_a_writer_thread_that_cannot_start_never_stops_the_exit_drain` failed for its
    stated reason: the pump whose thread start was refused was in `_LIVE`. That run
    covered all 12 of the round's tests: 12 failed, 0 passed.
  - Targeted run on d897885 (one invocation, 67 files, `targeted_r2b.log`): 2 341
    passed, 10 xfailed, 0 failed, 0 skipped. The 10 xfailed include this file's
    pre-existing web-repeater pin.
  - The harness run is the orchestrator's, at merge.
  *(Merge integration, coordinator:)* the `aclose` test fails on 910047a (the start's
  `RuntimeError` escapes `aclose`; 0 of 3 buffered flows written) and passes with the
  fix, run as plain Python calls of the test function (no pytest session); the stack's
  harness run covers it.

### CC-PROXY-0029 — The upstream sender keeps exactly framed connections (FR-PROXY-405, BUG-0549) (2026-10-21)
- Placement: pre-assigned to POOL24 (audit defect 24). CC-PROXY-0028 is AU-PROXY's, which
  rewrites the framing in lines ~35-105 of the same file; this change touches only the
  `SocketSender` class and adds helpers after it. Planned merge order: AU-PROXY, then
  POOL24.
  *(Review round 1:)* the round also changes one line of `fuzzlab/web/proxycontrol.py`
  (the Repeater's sender, finding B2), a UI-component file outside the lane's set; it
  merges with POOL24-r1, after AU-PROXY. No CC-UI number was pre-assigned: the
  coordinator's CC-UI entry text is in the lane's doc texts.
- Change (`fuzzlab/proxy/socketsender.py`):
  - `SocketSender` builds one SSL context per sender (`_context`, under a lock) instead
    of one per call.
  - It keeps upstream connections in an `_IdlePool` per (host, port, TLS), only after an
    exchange that was exactly one well-formed HTTP/1.1 request (`reusable_request`) and
    one fully framed HTTP/1.1 answer (`reusable_response`, with a strict chunked parse
    `_chunked_exact`) with no `Connection: close`, upgrade or connection-bound
    authentication; anything else is closed after its exchange, as before.
  - Only a reusable, idempotent request takes a kept connection (`_IDEMPOTENT`: GET,
    OPTIONS, TRACE, PUT, DELETE), after a check (`_quiet`: nothing readable, no buffered
    TLS byte; idle at most `IDLE_SECONDS`, 4 s). When the peer closed it before a byte of
    answer (an empty read before the idle timeout, or `_PEER_CLOSED`), the request is
    sent once more on a fresh connection; a timeout is never resent.
  - Bounds: `MAX_IDLE_PER_UPSTREAM` (8) and `MAX_IDLE_TOTAL` (64), the oldest closed
    first, the expired closed at each return. New `close()` (idempotent; also run when
    the sender is collected, `weakref.finalize`) and `keep_alive=False` (one socket per
    call); `idle_seconds` and `max_idle` are configurable.
  - New `tests/test_socketsender_pooling.py` (6 tests, 19 cases) on the shared loopback
    peer `tests/_keepalive_peer.py` (CC-CORE-0075).
  - *(Review round 1.)*
    - **A body is never kept (B1).** `reusable_request` now also refuses a request with
      body bytes or a `Content-Length` other than `0`, and one with a framing header
      spelled with an underscore (`Transfer_Encoding`, `Content_Length`). Such a request
      neither takes nor leaves a kept connection. A well-formed CL.0 probe (`POST
      /static` whose body is a request prefix) had its connection kept; the upstream had
      left the body unread, so the next request on it, another tab's or another
      identity's, completed the smuggled request with its request line and `Cookie`.
    - **No resend after an answer byte (B3).** The kept-connection path reads through
      `_Counted`, which counts the answer bytes received (it offers only `sendall`,
      `settimeout`, `recv`, `recv_into`). A `_PEER_CLOSED` failure after a byte came is
      raised to the caller; only one before any byte is resent. A partial answer
      followed by a reset had been discarded and the request replayed.
    - **The Repeater keeps fresh sockets (B2).** `web/proxycontrol.py::RepeaterController.
      _writer` builds `SocketSender(verify_tls=False, keep_alive=False)` (verification
      as before; only `keep_alive` added). Its per-thread sender had shared kept
      connections across tabs and the identities their cookies carry, against audit
      defect 24's "retain fresh sockets for deliberate desynchronization probes and
      connection-sensitive experiments".
    - Tests: `NOT_FRAMED` gains "a GET with a body" and "a framing header spelled with an
      underscore"; new `test_a_body_the_upstream_leaves_unread_never_reaches_the_next_request`,
      `test_a_kept_connection_reset_after_part_of_its_answer_is_never_resent`, and
      `tests/test_web_repeater.py::test_each_repeater_send_gets_a_fresh_upstream_connection`;
      the stale-connection test now asserts the POST's connection is closed after it.
      `tests/_keepalive_peer.py` gains `Reset` (part of an answer, then a reset) and
      `unread_body` (a CL.0 peer).
  - *(Merge integration, 2026-10-21; lane INTEG on d83876f, branch `integ/proxy-r1`.)*
    AU-PROXY (CC-PROXY-0028), POOL24 (this entry) and HIST25 (CC-PROXY-0030) were each
    green on its own base; merged (3cfd912, then d83876f) the harness counted 8
    failures in 135 files. Three findings, each confirmed by a skeptic:
    - **I2 (security): nothing may follow a kept connection's framed answer.** Before
      SP-63, `recv_http_response` returned bytes past an answer's `Content-Length` as
      part of the answer, so `reusable_response` refused it. SP-63 returns the framed
      answer only; bytes read past it stayed in the reader's `leftover` (dropped) and
      bytes not yet read stayed on the socket, so the connection was kept: a stray
      answer was dropped unseen or, arriving later, read as the next request's answer.
      New `socketsender.read_http_response` returns ``(response, past)``, ``past`` being
      SP-63's `leftover` (`recv_http_response` is its first element, unchanged for its
      callers). `SocketSender._finish` keeps a connection only when ``past`` is empty,
      `reusable_response` holds and nothing waits on the socket (`_quiet`, the check
      `take` already made before reuse). The end decision is SP-63's alone;
      `reusable_response` and `_chunked_exact` stay as a stricter grammar filter (one
      `Content-Length` header, `chunked` alone, no whitespace in a chunk-size line,
      token trailer names), which can only refuse what SP-63 accepted (BUG-0549 R1
      closed for the end decision; the stricter grammar kept by choice).
    - **I1: a history failure never changes the client's answer.**
      `server.ProxyEngine._record` (CC-PROXY-0030's hand-over) now contains any
      exception raised while building or submitting the flow. It counts it in the new
      `ProxyEngine.history_failures` (a `Counter` by error class) and never raises it
      into the flow, so the client gets the upstream's answer, or the 502 of the
      upstream's own failure with that failure in `AsyncProxyServer.errors`.
      `fuzzlab proxy` prints the count at stop, beside the listener's refusals
      (`proxy/cli.py`). The trigger: AU-PROXY's `tests/test_proxy_framing.py` fake
      history had `record` only, so `_record` raised after the upstream answered and
      four tests got a 502 for a relayed 200. That fake gains `submit`. The two other
      fakes handed to the engine (`test_proxy_rules_and_scope.py`,
      `test_proxy_history_writer_thread.py`) already had it.
    - **I3 (test-side): SP-63's exceptions in POOL24's tests.** An answer SP-63 cannot
      frame (a non-hex chunk size; chunked with `Content-Length`) raises
      `UpstreamFramingError`, and its kept connection is still closed (the kept path's
      `except BaseException` closes it, as the fresh path does). A stall on a kept
      connection raises `UpstreamIncomplete("idle")`, is never resent and its connection
      is never kept. A clean close after part of an answer raises
      `UpstreamIncomplete("eof")`, never resent. A close before any byte still returns
      `b""` and is resent once, as is a reset before any byte (`_PEER_CLOSED`, counted by
      `_Counted`): SP-63's exceptions are not `_PEER_CLOSED`, so the two stay apart.
    - Tests: `tests/test_socketsender_pooling.py` gains
      `test_bytes_after_a_framed_answer_never_leave_its_connection_kept` (the stray
      answer read with the first, or left on the socket by a receive that stopped at
      the end), `UNFRAMEABLE` in the not-exactly-framed test, the `UpstreamIncomplete`
      expectations and a `/cut` case. `tests/test_proxy_rules_and_scope.py` gains
      `test_a_history_failure_never_changes_the_clients_answer`.
    - Sweep pins (strict xfail, not fixed here):
      `tests/test_http_pooling.py::test_an_answer_followed_by_another_never_leaves_its_pooled_connection`
      (the core seam keeps such a connection; owner CORE) and
      `tests/test_proxy_repeater.py::test_a_history_failure_never_loses_the_repeaters_response`
      (a history store error replaces the Repeater's response; owner PROXY, with the UI
      for where it is shown). BUG-0549 and BUG-0543 hold the sweeps. No CC-CORE number was
      pre-assigned for the test-only pin in a CORE test file; it is recorded here.
  - *(Review round 2 of the merge integration, 2026-10-21; lane INTEG, branch
    `integ/proxy-r2` from the local merge stack 4e0c2c6; owner-approved single fix
    round.)* Both of round 1's sweep pins are now fixes. The core seam's (P2-1) is under
    CC-CORE-0075 and BUG-0549 "Review round 2". This entry holds the Repeater's:
    - **P2-2: a history failure never replaces the Repeater's response** (BUG-0543
      "Review round 2").
      - `proxy/repeater.py::Repeater.send` contains whatever building or recording the
        flow raises after the upstream answered. A real case is the synchronous
        `record`'s flush re-raising `database is locked` while another connection holds
        the store. The method returns the response and counts the failure in the new
        `Repeater.history_failures` (a `Counter` by error class). It names the failure in
        `Repeater.last_history_error` (None when recorded) and logs the error class
        only.
      - The flow stays in the writer's buffer (BUG-0106), so a later successful write
        stores it. The upstream is asked once.
      - Before, the error replaced the response, and the web route answered 500 for a
        request the target had answered.
    - `web/proxycontrol.py::RepeaterController.send` (a UI-component file, as in round 1;
      no CC-UI number was pre-assigned, and the coordinator's text is in the lane's doc
      texts) returns `history_error` and `history_failures` beside `response`. The
      count is the controller's, across its per-thread Repeaters, under its lock. The
      route in `web/app.py` is unchanged.
    - Tests: `tests/test_proxy_repeater.py::test_a_history_failure_never_loses_the_repeaters_response`
      is no longer a strict xfail. The real `HistoryWriter`'s `_write` raises
      `database is locked`, and the test asserts the response, one upstream send, the
      count, the name, and that a later successful send stores both flows. New
      `tests/test_web_repeater.py::test_a_history_failure_answers_the_repeaters_response_and_says_so`
      drives the real route against a loopback upstream and asserts 200, the answer,
      `history_error`, `history_failures` and one upstream request.
- Impact (other components / project):
  - The proxy engine, `fuzzlab proxy` and the web proxy's Repeater forward well-framed
    traffic on kept connections; bytes on the wire and the answers returned are
    unchanged (NFR-PROXY-byte-exact).
  - A deliberately malformed request (duplicate `Content-Length`, a transfer coding, a
    pipelined second request) never rides a kept connection and its connection is
    closed after it: the desync experiments keep a fresh connection. *(Review round 1:
    this held for malformed requests only. A well-formed request with a body, the CL.0
    class, was kept and could poison the next request; it now gets a fresh connection
    closed after it, as does every request with a body.)*
  - UI: `fuzzlab/web/proxycontrol.py` and `fuzzlab/proxy/cli.py` (not this lane's files)
    do not call `close()` at stop; the idle connections are closed when the sender is
    collected (residual R2 in BUG-0549).
  - No store or wire contract change.
  - *(Review round 1.)* Kept connections now serve bodiless requests only: a proxied
    POST, PUT or PATCH with a body pays a connect (and a handshake) as before the lane.
    The web Repeater opens one upstream connection per send, as before the lane (BUG-0549
    R4 closed). The proxy engine and `fuzzlab proxy` keep connections for bodiless
    requests; a reset after part of an answer now reaches the engine as an upstream
    failure instead of a silent replay.
  - *(Merge integration:)* a connection whose answer is followed by any byte, read with
    it or waiting on the socket, is closed after it. An upstream that sends nothing after
    its framed answers keeps its connection as before (measured below). `ProxyEngine`
    has a new public counter, `history_failures`, which `fuzzlab proxy` prints at stop.
    The web proxy's status shows neither it nor the listener's `counts`, as before. No
    store or wire contract change.
  - *(Review round 2:)*
    - UI: the Repeater send route's JSON gains `history_error` and `history_failures`
      (additive; `response` unchanged). The Proxy page's script still shows only the
      response. Showing the error beside it is a UI change that needs a real-browser
      test (PA-0065), not built here and noted for the owner.
    - A store error during a Repeater send now gives 200 with the answer instead of
      500. Nothing else changes for a send whose history write succeeds.
    - No store or wire contract change.
- Risk (medium):
  - A misbehaving upstream that sends bytes after a fully framed answer could have them
    read as the next request's answer if they arrive between the check and the next
    read. Mitigated: such bytes already waiting make the connection be closed, and only
    an exactly framed exchange is kept; accepted as the residual of any keep-alive
    client.
  - `reusable_response` parses the answer bytes a second time, strictly, beside
    `recv_http_response`'s own framing (AU-PROXY's region). When AU-PROXY lands, the two
    must agree: if AU-PROXY exposes an exact-end decision, this check should call it
    (BUG-0549 R1).
  - A HEAD request is never kept (its answer's framing depends on the request the reader
    does not see).
  - *(Review round 1.)* `_Counted` relies on the reader receiving through `recv` or
    `recv_into`; a reader that needs any other socket method fails loudly
    (`AttributeError`) instead of reading uncounted. AU-PROXY's reader (d84f97e) uses
    `settimeout` and `recv` only, and lets a reset from `recv` propagate, so the rule
    holds after that merge. A bodiless request a server still reads as framed (an
    unknown spelling not covered by the underscore rule) is the residual; the classic
    CL.0 and TE.0 shapes are covered.
  - *(Merge integration:)* bytes that arrive after `_finish`'s check (and after `take`'s)
    and before the next answer is read are still read as that answer. This is the
    residual of any keep-alive client, now narrowed to bytes the upstream sends late,
    not bytes already received. `_quiet` at `_finish` also closes a connection whose
    peer sent anything after the answer (a FIN, a TLS record): an upstream that sent a
    TLS 1.3 session ticket after its first answer would lose reuse. Measured: Python's
    `ssl` server (OpenSSL) does not; 300 calls kept one connection over TLS 1.2 and 1.3.
    A history that raises loses that flow from the history (counted), never the traffic.
  - *(Review round 2:)* a Repeater send whose history write keeps failing (a store held
    by another writer) still waits for the write's busy timeout (measured by the
    checker: 10.1 s) before the operator gets the response, and the unwritten flows
    accumulate in that thread's writer buffer, one per send, until a write succeeds.
    Accepted: they are bounded by the operator's own sends, and moving the Repeater's
    record off the request (the writer thread) is a separate change to its durability
    contract.
- Deliverables:
  - [x] `SocketSender` kept connections, one SSL context, `close`, helpers — done
  - [x] `tests/test_socketsender_pooling.py`: well-framed (Content-Length and chunked)
    exchanges share a connection; 14 not-exactly-framed exchanges never leave their
    connection and a malformed request never rides a kept one; a stale kept connection
    resent once, a timeout never; TLS: one connection, one handshake, one context; 8
    threads each get their own answers on at most 8 connections; `close` and collection
    close the idle connections. Each failed on c483dc1 (one run) — done
  - [x] FR-PROXY-405 added; FR-PROXY-12 edited in place — done
  - [x] *(Review round 1)* B1, B2, B3 fixed, each with a test that failed on 093685e (one
    run) and passes now; FR-PROXY-405 corrected in place ("a POST's may be kept after
    it" removed; a body is never kept; resend only before any answer byte; the
    Repeater's fresh sockets) — done
  - [x] *(Merge integration)* I1, I2, I3 fixed; the I1 and I2 tests fail on d83876f's
    product files and the eight d83876f failures reproduce there (one run on d83876f's
    `socketsender.py`, `server.py` and `cli.py` with the d83876f test files beside the
    new ones: 12 failed, 39 passed, each failure for its stated reason);
    the targeted run passes (one pytest on 57b054c, the 21 files `tests/test_proxy*.py`,
    `test_socketsender_pooling.py` and `test_http_pooling.py`, `-n 3 --dist loadfile`:
    354 passed, 3 xfailed (the two sweep pins and the history writer's pre-existing
    web-repeater pin), 0 failed, 0 skipped); FR-PROXY-402, 404 and 405 edited in place
    — done
  - [x] *(Review round 2)* P2-2 fixed (`Repeater.send` contained and counted; the web
    Repeater's JSON carries it). Round 1's Repeater pin is a passing test, and there is
    a new route test; both fail on 4e0c2c6's product files (one run) and pass now.
    FR-PROXY-404 and 405 were edited in place, and BUG-0543 has a "Review round 2"
    section. The CC-UI text for `RepeaterController.send` is in the lane's doc texts —
    done
  - [ ] *(Review round 2)* the Proxy page's script showing `history_error` beside the
    response (needs a real-browser test, PA-0065) — not in this round, for the owner
- Effectiveness (assessed 2026-10-21): on loopback, 2 000 plain calls used 8 connections
  instead of 2 000; sequential calls/s 1 489 -> 10 271 (an earlier pair: 1 781 -> 4 650),
  8-thread 1 205 -> 3 140; over TLS 20 -> 3 826 sequential; a fresh TLS call built a
  20 ms system-CA context that is now built once (BUG-0549). The harness result is in this
  lane's report. *(Review round 1:)* the reviewers' repro scripts, run on the fixed tree:
  CL.0 (`cl0.py`, `cl0_demo.py`) two connections and the victim's `GET /me` intact with
  its own answer (was one connection, absorbed); partial answer then reset
  (`midreset_demo.py`) raises `ConnectionResetError` and the upstream saw `/2` once (was
  twice, answer swallowed). The measured numbers are for bodiless GETs and stand.
  *(Merge integration:)* with `_finish`'s new check, 300 sequential loopback calls kept
  one connection over plain HTTP (4 763 calls/s), TLS 1.2 (one handshake, 2 934 calls/s)
  and TLS 1.3 (one handshake, 2 628 calls/s)
  (`scratchpad/lanes/INTEG/measure_tls_keep.py`, one run each, same host). An upstream
  that answers twice in one segment now costs one connection per such answer; the
  earlier numbers stand.
  *(Review round 2, 2026-10-21:)*
  - **Proof on the pre-fix code:** one pytest invocation on a scratch copy of 4e0c2c6's
    product files with the round's test files (`scratchpad/lanes/INTEG/proof_r2.log`):
    12 failed, 0 passed.
    - The Repeater test failed with `sqlite3.OperationalError: database is locked`
      raised out of `Repeater.send`.
    - The route test failed with the same error raised through the route, the 500 the
      operator saw.
  - **Targeted run** on d897885 (one invocation, 67 files; `targeted_r2b.log`): 2 341
    passed, 10 xfailed, 0 failed, 0 skipped. The run on 5078fc5 before it failed one
    guard, recorded in CC-CORE-0075.
  - The harness run is the orchestrator's, at merge.

### CC-PROXY-0028 — HTTP/1 framed by the protocol on both sides; the listener's reads bounded (BUG-0543; audit defects 18-20) (2026-10-21)
- Change:
  - **New `proxy/framing.py` (SP-63):** `MessageReader`, a sans-I/O HTTP/1 reader
    (`feed` / `eof`), with `request_framing`, `response_framing`, `response_status` and
    `closes_connection` (RFC 9112 §6-7). It parses chunked bodies (sizes, extensions,
    CRLFs, trailers), `Content-Length` (identical duplicates are one; conflicting or
    invalid is `FramingError`; `raw_length` frames conflicting ones by the first) and
    close-delimited bodies. HEAD / 1xx / 204 / 304 / a 2xx to CONNECT have no body.
    Interim 1xx responses are passed over (at most 8). Head and body bounds are checked
    as bytes arrive (`OverLimit`); a close before the framed end is `Incomplete`. It
    counts the bytes it copies (`copied`).
  - **`proxy/server.py`:** `AsyncProxyServer(limits=InboundLimits(...),
    raw_framing=False)`.
    - `_next_request` reads each request whole through SP-63 under a per-request
      deadline and forwards a chunked one de-chunked with a `Content-Length` (trailer
      fields dropped).
    - Refusals: 400 for what cannot be framed, 431 / 413 for a head / body over its
      bound, 408 at the deadline, each with a lingering close (write side shut, client
      bytes discarded for at most 1 s). A connection over `max_connections` is answered
      503 and closed. All are counted in `counts`.
    - Bytes after a request are the next one (`_Inbound`). The CONNECT/TLS loop ends
      after a response that ends its connection.
    - `_read_http_message` is removed.
  - **`proxy/socketsender.py`:** `recv_http_response(..., method=)` reads through SP-63
    and returns the final response's exact bytes. It raises `UpstreamIncomplete`
    (`reason`: `eof`, `idle`, `deadline`, `head`, `wire`) or `UpstreamFramingError`, both
    `UpstreamResponseError`s. A close before any byte still returns `b""`. Each receive
    waits at most the time left to the deadline. `SocketSender` passes the request's
    method. The receive size and the deadline factor are SP-60's (`READ_SIZE`,
    `DEADLINE_TIMEOUTS`); `_body_complete` and `_CHUNK` are removed.
  - **`proxy/cli.py`:** `--max-connections`, `--max-request-bytes`, `--max-header-bytes`,
    `--request-deadline` (`inbound_limits`; a bound that is not positive is a usage
    error) and `--raw-framing`. The non-zero refusal counts are printed at stop.
  - **`fuzzlab/cli_taxonomy.py`** (FUZZ's file, the proxy's own flags only, as CRAWL
    lanes classify theirs): the five new dests, class `B`.
  - **`scripts/proxy_e2e.sh`** (on-host Part I): step 3 starts the proxy with
    `--raw-framing`, which step 5's conflicting-`Content-Length` request now needs.
- Reason: audit defects 18-20 (BUG-0543). A chunked request was forwarded as its head
  alone and its chunks were left on the connection. A response ended at payload bytes
  that looked like the last chunk, or at an idle receive or a close, and a cut response
  was relayed and recorded as whole. The listener read a declared body without a cap or
  deadline and admitted connections without bound.
- Impact (other components / project):
  - **Wire contract of the listener (FR-PROXY-1, FR-PROXY-401).** A request with
    conflicting `Content-Length` values, both `Transfer-Encoding` and `Content-Length`, a
    non-`chunked` transfer coding or a malformed request line is now answered 400 and
    not forwarded. It used to be forwarded (framed by the first length).
    `--raw-framing` keeps the conflicting-length case; the Repeater still sends any bytes
    verbatim. A chunked request now reaches the upstream de-chunked with a
    `Content-Length`. ARCHITECTURE's "exit criterion in miniature" sentence needs the
    raw-mode qualifier (text in the lane report).
  - **History and the trace (FR-PROXY-13).** A cut or stalled upstream response is now a
    flow with no response and error `UpstreamIncomplete` (a lost arrow in the proxy
    sequence), not a 200. A response preceded by 1xx is recorded with its final status.
  - **The web UI** (`web/proxycontrol.py`, UI) builds `AsyncProxyServer` with the default
    `InboundLimits`; no code change. The repeater route (`web/app.py`) already answers
    500 on any sender exception; `UpstreamIncomplete` joins those (R5).
  - **Clients:** a refused connection or request gets `Connection: close` (PA-0153(4));
    an interim 1xx is not relayed (R4).
  - No store, schema or `Sender` seam change.
- Risk: medium. The listener's request handling is rewritten on the browser's path. The
  mitigation is the real-socket tests below plus the existing proxy suites (plain HTTP,
  trace, intercept, rules, live). Accepted residuals:
  - **R1:** `h2transport._drain` / `send_raw` have a deadline but no byte cap, and
    re-decode `bytes(buf)` per receive. Not on the listener's path; flagged for its own
    item.
  - **R2:** `redact._dechunk` is a second, lenient chunk decoder (redaction only; it
    fails closed). Routing it to SP-63 is a redaction change (two reviews, PA-0541(1)).
  - **R3:** no `100 Continue` from the listener. A client that waits for one (curl,
    over 1 MiB) sends after its own timer; the result is correct but slower.
  - **R4:** interim 1xx responses are read and not relayed (the proxy holds whole
    messages; RFC 9110 §15.2 says forward). A 101 is relayed and then the connection
    ends: upgrades through the listener are still unsupported.
  - **R5:** the web repeater route answers 500 on a sender exception (UI file).
  - **R6:** `scripts/proxy_e2e.sh` with `--raw-framing` is not run on-host here (no
    lab); `docs/ON_HOST_RUNBOOK.md` Part I needs the matching line (text in the lane
    report).
  - **R7:** the connection cap's default (64) is not measured against a browser's own
    connection limit (CLAUDE.md step 8). It is configurable.
  - **R8:** no aggregate byte reservation or disk spooling. The worst case buffered is
    connections × (head + request body + one upstream response): about 5 GiB at the
    defaults.
- Deliverables:
  - [x] code (`proxy/framing.py` new; `server.py`, `socketsender.py`, `cli.py`;
    `cli_taxonomy.py`; `scripts/proxy_e2e.sh`) — done
  - [x] tests: new `tests/test_proxy_framing.py`, over real loopback sockets (client →
    `AsyncProxyServer` → `SocketSender` → an upstream socket), plus the SP-63 guard and
    its synthetic offenders; `test_the_body_is_never_recopied_per_chunk` reads the
    reader's copy count; `test_async_server_forwards_duplicate_content_length_byte_exact`
    runs in raw mode — done
  - [x] proof on the pre-fix code (the new test file against 08e3eaa's `fuzzlab/`, one
    run) — done: 26 failed, 1 passed (the guard's synthetic-offender test, which tests
    the oracle only), in 109 s.
    - Behavioural on the old code:
      - the chunked request reached the upstream as `…Transfer-Encoding: chunked\r\n\r\n`
        with no body;
      - all six unframeable requests and both over-limit ones were forwarded or hung, with
        no 400 / 413;
      - `abc0\r\n\r\n` ended the response;
      - the three cut responses were returned (DID NOT RAISE);
      - the trailer / HEAD / 204 / 304 / 103 cases each took 20.0 s, the idle timeout;
      - the cut upstream response reached the client and history as a 200;
      - a 100 KiB head got no 431;
      - the guard found `server.py`'s `readuntil` / `readexactly` and `socketsender.py:46`.
    - By a missing API: the 408, 503, CLI and raw-mode tests (`InboundLimits`,
      `raw_framing`) and the reader-level leftover test (`fuzzlab.proxy.framing`).
  - [x] FR-PROXY-1, FR-PROXY-12 and NFR-PROXY-byte-exact amended; FR-PROXY-401, 402 and
    403 added — done
  - [x] BUG-0543 — done
  - [ ] CHANGELOG, ERROR_LOG, PA-0543, SHARED_PRIMITIVES (SP-63), ARCHITECTURE,
    ON_HOST_RUNBOOK, the failure record — the orchestrator's (text in the lane report)
- Effectiveness (assessed 2026-10-21): the targeted proxy files pass (112 passed: the
  new file, the upstream/flush, live, server, rules, trace, intercept-live and
  hand-written-response suites). The pre-fix proof is above. The one
  `scripts/verify_change.py --base 08e3eaa` run on this commit (d84f97e, detached
  worktree): 77 files, 3014 passed, 0 failed, 0 errors, 1 skipped (test_packaging
  bdist_wheel, environment), 20 xfailed.
- Review round 1 (2026-10-21, two reviewers and a skeptic on d84f97e: REVISE, five
  blocking findings, each reproduced; fixed on top of d84f97e):
  - **B1 (security): malformed field syntax still framed and forwarded.** `_start`
    read fields through `RawMessage`, which splits a head at `\n\n` and skips lines it
    cannot match. Four inputs were framed and forwarded on the default path: a bare-LF
    pipeline (`X: y\n\nGET /smuggled …`), `Transfer-Encoding\t: chunked`,
    `Transfer-Encoding : chunked` or an obs-folded one beside a `Content-Length`, and
    `X: a\rContent-Length: 5`. Fix: `framing.parse_head` parses a head once, strictly,
    from the bytes up to the first CRLF CRLF. It refuses a bare CR or LF, an empty start
    line, obs-fold, a field line with no colon or a non-token name, a NUL in a value,
    and a malformed request or status line. Framing reads its fields from that parse:
    a request is answered 400, a response is a 502 (`UpstreamFramingError`).
    `closes_connection` uses the same parse. Only CRLF pairs before a request line are
    skipped. Raw mode still changes only the conflicting-length rule.
  - **AU-PROXY-1: a cut or unanswered upstream inside the TLS tunnel closed it empty.**
    The tunnel loop now contains each request's failure (`errors`). On a failure or an
    empty response it answers `_BAD_GATEWAY` in the tunnel (a lingering close), then
    ends it. The plain path answers an empty upstream response with 502 too.
  - **B3: the keep-alive case had no listener-level test.**
    `test_the_bytes_after_a_chunked_request_in_a_tunnel_are_the_next_request` sends a
    chunked POST and a GET in one write through a real TLS tunnel (LocalCA, offline).
  - **B2 / AU-PROXY-2: PA-0102's test lost its proof.**
    `test_the_body_is_never_recopied_per_chunk` checks the body buffer's identity after
    every receive as well as the copy count. `test_the_copy_oracle_flags_a_quadratic_reader`
    proves the oracle on an honest quadratic reader (over 60 times the bytes received).
  - **AU-PROXY-3: PA-0543(2) claimed every accept path.** Its admission and time clause
    is scoped to the proxy listener (lead's option (a)). `oracle/oob.py`'s
    `ThreadingHTTPServer` (a thread per connection, no cap, a 5 s socket timeout) and
    the web UI's uvicorn listener are residuals R9 and R10 in BUG-0543's sweep: other
    components' listeners, not widened here.
  - Tests: five new 400 cases (the four inputs, the third in both forms), a three-case
    strict-response test, the two tunnel tests
    and the quadratic-oracle test. Proof on d84f97e and harness: recorded in the lane
    report.
  - Effectiveness of review round 1: Review round 1 fixed on 92024c8. The new tests on d84f97e: 9 failed, 40 passed (the five B1 request cases forwarded with a 200, the three strict-response cases did not raise, and the tunnel test got an empty close). The B3 tunnel test on 08e3eaa sent three requests (the head, the chunk bytes, the GET). `scripts/verify_change.py --base d84f97e` on 92024c8: 74 files, 2959 passed, 0 failed, 0 errors, 1 skipped (test_packaging, environment), 20 xfailed.

### CC-PROXY-0027 — A proxied flow's redirect target keeps its own key (BUG-0517) (2026-10-19)
- Change (`fuzzlab/proxy/history.py::flow_event`): the redacted `Location` is
  `redirect`, not `location`.
- Reason: one event key, one meaning across producers (PA-0517).
- Impact: proxy events gain `redirect`. Readers fall back to an older event's
  path-valued `location`.
- Risk: low.
- Review: this entry follows the two-reviewer gate run after the fact over the diagrams series (F-076); both reviewers disagreed, and every confirmed finding in this component is fixed here or answered below.
- Deliverables:
  - [x] code; `tests/test_proxy_trace.py` updated — done
- Effectiveness: verified offline.

### CC-PROXY-0026 — A closed proxy run records its end (FR-PROXY-13) (2026-10-19)
- Change:
  - `proxy/history.py`: `HistoryWriter.close(run_end=None)`. Given a status, it emits a
    `run.end` event through the writer's recorder (created if no flow made one), when
    no transaction it does not own is open, then writes the counters.
  - `proxy/cli.py`: `fuzzlab proxy` closes the writer with `complete` on Ctrl-C, or
    `aborted: <class>` when the loop raised.
  - `web/proxycontrol.py::ProxyController.stop` (UI component, CC-UI-0061) calls
    `close(run_end="complete")` instead of `flush()`.
- Reason: found in CC-PROXY-0025's lane report. A proxy run never recorded an end, so
  its diagram status always read `partial`. The web proxy's stop only flushed, so its
  trace counters were never written.
- Impact: one `run.end` event per closed proxy run. Flow history is unchanged.
- Risk: low. A failure to record the end is suppressed; the status then reads
  `partial`, which is honest.
- Deliverables:
  - [x] code; `tests/test_proxy_trace.py::test_stopping_the_web_proxy_records_its_end_and_its_counters`
    drives the real `ProxyController` with a store: after `stop()` the run's status is
    `complete` with its counters. It fails with the old `flush()` (`run_end` None) — done
  - [x] FR-PROXY-13 edited in place; CHANGELOG — done
- Effectiveness: verified offline (the test above).

### CC-PROXY-0025 — The proxy's recorded flows are trace events, live (FR-PROXY-13) (2026-10-19)
- Change:
  - **`proxy/history.py`:** `HistoryWriter` owns a `core.trace.TraceRecorder` (created
    on first use, on the writer's thread and store connection, under its lock, with the
    writer's `run_id`). After each flush has committed, `_trace` emits one
    `observe.exchange` event per written in-scope engine flow (scope `proxy`, key
    `proxy:flow:<flow id>`) and flushes it. New pure `flow_event` builds the body from
    the prepared (redacted) values; parameter names come from `tools.observe`
    (`_query_params`, `_body_params`, imported, not copied). A flush inside a
    transaction the writer does not own emits later, only for a flow still stored
    (`_still_stored`). `_insert` returns the flow id. `close()` emits what waited and
    writes the `trace_*` counters. `FlowRecord` gains `t`, `error`, `intercept` and
    `source` (none of them a stored column); `HistoryWriter` gains `trace=True`, and
    its `run_id` may be None (nothing traced).
  - **`proxy/server.py`:** `ProxyEngine.handle_request` stamps `t` when an in-scope
    request arrives; records the operator's held-message decisions (`request edited` /
    `request forwarded`, `response edited` / `response forwarded`); and records a flow
    whose upstream failed (no response, its error class) before re-raising, so the
    connection still answers 502.
  - **`proxy/repeater.py`:** repeater flows carry `source="repeater"` (not traced).
  - **`proxy/cli.py`:** `fuzzlab proxy` ends with `history.close()` (was `flush()`), so
    the counters are written.
- Reason: the intercepting proxy's history was missing from the trace, so the Diagrams
  page could not show user/browser traffic through the proxy (FR-CORE-505 gap).
- Impact (other components / project): new `trace_event` / `dg_*` rows for proxy runs
  (the trace's one writer, SP-48; no new writer of those tables). Consumers, found by
  searching `HistoryWriter(` and `FlowRecord(` across `fuzzlab/`: `proxy/cli.py`,
  `proxy/server.py`, `proxy/repeater.py`, `web/proxycontrol.py` (two constructions;
  unchanged, works as is: its `stop()` calls `flush()`, so its `trace_*` counters are
  written only after a dropped event, not at stop; the fix is `close()` there, outside
  this lane's files). `report.diagram` reads the events (CC-UI-0059). History gains a
  row for an in-scope flow whose upstream failed (status NULL); it used to be absent.
- Risk: low to medium. A trace failure is contained (counted `dropped`, logged) and
  never fails the history; the recorder commits only when no transaction is open.
  Cost, measured (400 flows, `batch_size=1`, two runs): median 0.30–0.38 ms per flow
  without the trace, 1.38–1.46 ms with it (p95 1.3–2.5 ms vs 5.8–13.4 ms), on the
  loop thread, like the history write itself (FR-PROXY-12). Accepted for hand-driven
  traffic; `HistoryWriter(trace=False)` turns it off.
- Deliverables:
  - [x] code — done
  - [x] tests: new `tests/test_proxy_trace.py` (11): the real `AsyncProxyServer` +
    `SocketSender` + `HistoryWriter(batch_size=1)` against a loopback upstream; one
    event per flow, live, stable keys; no Cookie / Authorization / password / token /
    JSON-key / Location secret in events, model or exports; out-of-scope and repeater
    flows give none; a failed upstream is a lost arrow; a re-flush, a failed flush and
    its retry, and re-processing add nothing; an owner's rollback traces nothing;
    intercept decisions recorded and drawn — done
  - [x] FR-PROXY-13; NFR-PROXY-safe's Enforced-by line; §5 interfaces — done
  - [ ] CHANGELOG, `docs/DIAGRAMS.md`, ARCHITECTURE — the orchestrator's (text in the
    lane report)
- Effectiveness (assessed 2026-10-19): 15 mutation runs against
  `tests/test_proxy_trace.py`; 13 were caught:
  - no in-scope / source filter; no rollback check; tracing inside an owner's
    transaction; no `t`; no failed-upstream record; `flush` raising after the trace
    call; no `proxy` scope listing;
  - a lost arrow drawn as a reply; a reply to the browser after a lost arrow; the
    Cookie header of the unredacted request in the body; query values as params; no
    edit note; no drop note.
  - two were not caught; both were mis-aimed first tries of mutations listed above. One
    changed the identical line in the capture sequence, not the proxy's. The other read
    the Cookie header from the prepared request, which is already redacted. Re-aimed
    at the proxy's own line and at the unredacted request, both are caught.

### CC-PROXY-0024 — The proxy's hand-written 501 says `Connection: close` (BUG-0147 sweep) (2026-10-15)
- Change: `fuzzlab/proxy/server.py`: the 501 sent for a CONNECT with no CA, after which
  the connection is closed, carries `Connection: close` (the 502 already did).
- Impact (other components / project): proxy clients only; no API, store or UI change.
  Found by BUG-0147's PA-0002 sweep of hand-written responses.
- Risk: low; one header.
- Residual recorded in BUG-0147 (not changed here): forwarded upstream responses keep
  their own `Connection` semantics although the proxy closes after each one. Rewriting
  the forwarded head is a design decision for this component.
- Deliverables:
  - [x] code — done
  - [x] guard (the same hand-written-response test, mutation-checked) — done
- Effectiveness (assessed 2026-10-15): full suite on 7c1fb91 (`scripts/verify_change.py --full`): 7106 passed, 0 failed, 42 skipped, 28 xfailed. `test_multitarget_category4` (BUG-0147's failure) passed; it had failed in the previous full run of the merged tree (7077 passed, 1 failed). `tests/test_probe_unobserved.py` 26 passed; 16 mutation checks each caught. Round 2 review: both reviewers AGREE.

### CC-PROXY-0023 — A captured session records the origins it was seen on (FR-SESS-20, BUG-0134) (2026-10-14)
- Change: `proxy/session_capture.py` records the canonical origin of every URL passed to
  `observe_request` / `observe_response` on the capture's host (loopback aliases one
  host) and sets `SessionState.origins`; `SessionManager.adopt` refuses a capture with
  none (O7).
- Impact: a captured session is sent only to the origins it was observed on; a capture
  fed without URLs can no longer be adopted (loud refusal).
- Risk: low (narrows). The proxy's own callers do not adopt yet (SessionCapture is used
  by tests and the planned FR-SESS-11 flow).
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_session_origin_scope.py`: recorded origins, refusal with none,
    an adopted capture never sent to another port; `test_proxy_session_capture.py` and
    `test_session_transport_binding.py` pass URLs) — done
  - [x] FR-PROXY-9 amended in place — done
- Effectiveness (assessed 2026-10-14): the capture tests pass; the prepare mutation
  (CC-SESS-0023) also fails the adopted-capture test.
- Review round 1 (2026-10-14; R5, A-N2): `SessionManager.adopt` unions the manager's
  `auth_origins` into an adopted capture's origins
  (`tests/test_session_origin_scope.py::test_adopt_adds_the_operators_auth_origins`).

### CC-PROXY-0402 — A bad `--store` fails before the dry-run plan is printed (2026-10-15)
- Change:
  - **`proxy/cli.py`:** in the dry-run branch, `_recording` runs before `report(...)`.
    `proxy --dry-run --store ""` used to print the whole plan and then exit 2 (reviews A
    and B, round 2).
- Impact (other components / project): none.
- Risk (level; mitigation or accepted-risk justification): low.
- Deliverables:
  - [x] code; FR-PROXY-400; test
    `tests/test_cli_default_store.py::test_proxy_dry_run_with_an_empty_store_prints_no_plan`
    — done
- Effectiveness (assessed 2026-10-15): reverting the order fails the test. Effective.

### CC-PROXY-0401 — `--export-ca` before any store resolution; `--store ""` is a usage error (2026-10-15)
- Change:
  - **`proxy/cli.py`:** store resolution (`_recording`) runs in the dry-run branch, and
    otherwise after `--export-ca`. `fuzzlab proxy --export-ca --store ""` exports the CA
    as before.
  - An explicit `--store ""` without `--export-ca` is now a usage error (PA-0105). It
    used to mean "do not record", because it was falsy. **This was not recorded in
    CC-PROXY-0400.**
  - The `--record` help comes from `storepath.DEFAULT_RULE`.
  - NFR-PROXY-dry-run gains a "Not yet enforced (BUG-0400)" line.
- Impact (other components / project): none beyond the proxy CLI.
- Risk (level; mitigation or accepted-risk justification): low.
- Deliverables:
  - [x] `proxy/cli.py`; FR-PROXY-400 updated — done
  - [x] tests: `tests/test_cli_default_store.py::test_proxy_export_ca_comes_before_any_store_resolution`,
    `::test_proxy_explicit_empty_store_is_a_usage_error` — done
- Effectiveness (assessed 2026-10-15): resolving before `--export-ca` (a mutation)
  fails the test. Effective.

### CC-PROXY-0400 — `proxy --record`: record flow history into the default store (FR-PROXY-400) (2026-10-15)
- Change:
  - **`proxy/cli.py`:**
    - New `--record` records into the resolved store (`core.storepath`). `--store PATH`
      alone still records there; with both, `--store` wins.
    - Recording stays **opt-in**.
    - The order is `--dry-run` / `--export-ca`, then `--authorized`, then
      `require_loopback` (the existing order), then `check_writable`, then `Store`.
    - The banner and the dry run name the store.
- Impact (other components / project):
  - The web launcher's proxy form gains a `--record` checkbox (commandspec
    introspection).
  - `web --with-proxy` is unchanged: it records to the UI's own `store_path`, which now
    resolves the same way.
- Risk (level; mitigation or accepted-risk justification): low.
  - Nothing is recorded unless asked.
  - The loopback and `--authorized` gates come before any store work, which is tested.
- Deliverables:
  - [x] `proxy/cli.py` — done
  - [x] tests: `tests/test_cli_default_store.py::test_proxy_records_nothing_unless_asked`,
    `::test_proxy_record_checks_come_before_any_store_work`;
    `tests/test_web_commandspec.py` and `tests/test_loopback_listeners.py` still green
    — done
  - [x] FR-PROXY-400 — done
- Effectiveness (assessed 2026-10-15): the dry runs name the store only when recording;
  usage errors leave nothing. Effective.

### CC-PROXY-0022 — Safety-NFR traceability lines (PA-0112, BUG-0111/0112 sweep; documentation only) (2026-10-13)
- Change: `requirements.md` gains `Enforced by:` / `Not yet enforced:` lines under
  NFR-PROXY-safe, NFR-PROXY-dry-run, naming the enforcing code and the test functions that fail without it
  (checked by `tests/test_requirements_traceability.py`). Open: the Repeater has no scope check; `--dry-run` over `--export-ca` is untested. No code change.
- Impact: none at run time. The guard now fails if these lines go stale (a renamed or
  deleted test) or if a new NFR is left unclassified.
- Risk: none (documentation, plus a test that reads it).
- Deliverables:
  - [x] traceability lines — done
  - [x] open clauses recorded and reported to the operator — done
- Review: reviewers A and B (BUG-0111/0112 draft v2, AGREED) asked for one doc-only entry
  per touched component.
- Effectiveness: verified by the guard (3 passed, incl. synthetic offenders).

### CC-PROXY-0021 — Fail-closed history redaction incl. framed bodies (BUG-0100); bounded upstream reads off the loop (BUG-0101); atomic history flush (BUG-0106) (2026-10-13)
- Change:
  - **`proxy/redact.py` (BUG-0100).**
    - It delegates body and URL redaction to `core.redaction`.
    - Chunked or compressed bodies are decoded with bounds (de-chunked;
      gzip/deflate) and checked: a clean one is kept byte-exact; a secret, or an
      undecodable redactable body, becomes the marker, with TE/CE dropped and
      Content-Length set.
    - `redact_body_for` follows the same rule.
  - **`proxy/socketsender.py` (BUG-0101).**
    - One bytearray and no per-chunk copy.
    - `MAX_HEAD_BYTES`, `max_body` and an overall `deadline`, breached with
      `UpstreamResponseError`.
    - `SocketSender(max_body=, deadline=)` and `fuzzlab proxy --max-response-bytes /
      --response-deadline`.
  - **`proxy/server.py`.** Both sender calls use `await asyncio.to_thread(...)`.
  - **`proxy/history.py` (BUG-0106).**
    - `flush` prepares first, contains a failed record with omitted bodies, and writes
      in `SAVEPOINT history_flush` (roll back and re-raise on error).
    - It commits only a transaction it owns, and keeps only the written records out of
      the buffer.
    - An `RLock` guards `record` / `flush`.
  - **`proxy/session_capture.py`.** `secure_only` is set from https URLs or `Secure`
    cookies (BUG-0098).
- Impact (other components / project):
  - **CORE:** the boundary.
  - **SESS:** capture.
  - **Behaviour changes:**
    - the former framed-body residual is closed;
    - an oversized or unparseable sensitive body is stored as a marker;
    - long-lived or large responses are cut off at the configurable bounds;
    - history `errors` lists contained records.
- Risk: medium. These are proxy data-path changes. The proxy suites pass, and bounds
  and containment are tested.
- Deliverables:
  - [x] framed-body redaction — done
  - [x] bounded reads + thread offload + CLI options — done
  - [x] atomic flush — done
  - [x] tests: `test_proxy_upstream_and_flush` (new), `test_proxy_redaction` (the
        residual test replaced), `test_storage_redaction` — done
  - [x] FR-PROXY-11 amended, FR-PROXY-12 added — done
- Implementation divergence: none.
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-PROXY-0020 — Whole-subtree JSON redaction (BUG-0090); CA key never silently replaced, pair checked, atomic leaf writes (BUG-0096) (2026-10-13)
- Change:
  - **Redaction (BUG-0090).** `proxy.redact._redact_json` replaces a sensitive key's
    **whole value**, whatever its type (scalar, list, object or nested). It no longer
    recurses into a sensitive container. Plural names are sensitive through
    `core.redaction` (CC-CORE-0035).
  - **CA (BUG-0096).**
    - `ensure_ca` creates the CA key with `core.secretfile.create_secret` (`O_EXCL`), so
      a trust root is never silently replaced. It is written key first, then the cert,
      atomically.
    - On load the key must match the certificate (SPKI comparison), and a half CA (one
      file without the other) is refused. Both raise the new `CAError`, naming the fix.
    - `leaf_cert_files` writes the key, then the cert, each with `replace_secret`
      (complete, atomic, 0600).
- Impact (other components / project):
  - **CORE** (CC-CORE-0035): `create_secret`, `replace_secret`, the plural fold.
  - **Behaviour change, listed:** a JSON container under a sensitive key is now stored
    as the placeholder string, and its shape is not kept. A store whose CA directory
    holds only one of the two files, or a mismatched pair, now stops with `CAError`
    instead of re-minting the CA silently.
  - Leaf certs are now 0600 (they were umask-default). They are only read by the proxy
    itself.
- Risk: low to medium. These are safety controls, with hostile and benign fixtures. A
  user-visible stop on a broken CA is intended (re-trusting a new root is a deliberate
  act).
- Deliverables:
  - [x] whole-subtree JSON redaction — done
  - [x] CA `O_EXCL` key, pair check, half-CA refusal — done
  - [x] atomic leaf writes — done
  - [x] tests: `test_proxy_redaction` (name forms × value shapes through
        `HistoryWriter`), `test_secretfile` (CA and leaf cases) — done
  - [x] FR-PROXY-10 / FR-PROXY-11 amended — done
- Implementation divergence: the draft's "a mismatched leaf pair is re-minted on load".
  Leaves are never loaded from disk: they are rewritten from the in-memory pair on
  every use, and `ssl.load_cert_chain` refuses a mismatch itself. Stated in BUG-0096
  rather than built as dead code.
  - **Reviewed:** taken back to both reviewers under PA-0093(2), and AGREED 3/3.
  - **Cross-process residual (both reviewers' nit).** Two proxies sharing one `ca_dir`
    (the web panel's in-process proxy and `fuzzlab proxy`) each mint their own leaf
    for a host. The two files are replaced one at a time, so one process can load
    the other's key. `load_cert_chain` then raises, and per-connection containment
    closes that connection: a handshake failure, never a wrong certificate. A
    re-mint would not fix it; per-process leaf names would, if it ever matters.
  - **Pinned by** `test_a_corrupted_leaf_on_disk_heals_on_the_next_use`.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-PROXY-0019 — CA leaf hardening (BUG-0079); loopback-only bind (BUG-0080); persisted-copy redaction (BUG-0084); rule validation and per-connection containment (BUG-0085); one scope decision and IPv6 authorities (BUG-0086) (2026-10-13)
- Change:
  - **CA (BUG-0079).**
    - `ca.leaf_host` validates a CONNECT host: an IP literal, or an IDNA, lower-cased
      hostname of `[a-z0-9_-]` labels, at most 253 characters.
    - IPv6 leaf files are named `ip6-<hex>`.
    - A path backstop keeps every leaf directly in `leaves/`.
    - Keys go through `core.secretfile.write_secret` (0600 from creation,
      `O_NOFOLLOW`), and the directories are `0700`.
  - **Loopback (BUG-0080).** The proxy CLI exits 2 on a non-loopback `--host`, and
    `AsyncProxyServer.start` refuses one too (`core.net.require_loopback`).
  - **Redaction (BUG-0084).**
    - `proxy.redact` covers sensitively named headers; query parameters of the request
      target and of `Location` / `Content-Location` / `Refresh`; and form / JSON / multipart
      request **and** response bodies.
    - Matching is by name token (`core.redaction`).
    - JSON is re-serialised only on a hit, and Content-Length is recomputed when it was
      consistent.
    - Chunked or compressed bodies are stored as received (a stated residual).
    - `HistoryWriter` also redacts `flow.url` and the separately stored bodies.
  - **Rules and containment (BUG-0085).** `MatchReplaceRule` and `ScopeRule` validate
    at creation (latin-1 encodability, regex compilation). `_on_client` contains any
    exception: `502` if nothing was written yet, else close; the CONNECT path never
    writes a 502 into the tunnel. Errors are kept on `AsyncProxyServer.errors`.
  - **Scope and IPv6 (BUG-0086).**
    - New `proxy/authority.py`: `split_authority` / `join_authority`.
    - The engine decides scope once, on the authority.
    - `_host_matches` parses both the pattern and the host.
    - Used by `parse_connect`, `target_from_request`, `_authority` and the CA.
- Impact (other components / project):
  - **CORE** (CC-CORE-0034): `core.net`, `core.redaction`, `core.secretfile`.
  - **UI** (CC-UI-0049): API 400s, the in-process proxy gate, `create_from_flow`
    IPv6.
  - **Trade-off, stated:** Repeater tabs seeded from history carry placeholders.
    Replaying JWT / session / CSRF flows needs a fresh capture or
    `redact_secrets=False`.
  - Underscore hostnames are allowed; anything outside the grammar is refused.
- Risk: medium. These are safety controls. Each one is tested against hostile input,
  and the benign paths (byte-identical messages, valid hosts, valid rules) are tested
  too.
- Deliverables:
  - [x] CA hardening — done
  - [x] loopback gate — done
  - [x] redaction — done
  - [x] rule validation and containment — done
  - [x] authority parser and single scope decision — done
  - [x] tests: `test_proxy_ca_hardening`, `test_loopback_listeners`,
        `test_proxy_redaction`, `test_proxy_rules_and_scope` — done
  - [x] FR-PROXY-10 / FR-PROXY-11 added; FR-PROXY-5 amended — done
- Implementation divergence:
  - The draft's "refuse underscore" is superseded by A's nit: `_` is allowed.
  - WebSocket and h2 are not in the server's connection loop, so their containment is
    noted in BUG-0085's sweep rather than coded.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-PROXY-0018 — Incidental: Proxy workbench UI rebuild on a shared message editor (lane U3) (2026-09-22)
- Change: lane U3 rebuilt the web control panel's Proxy section UI on a shared
  `<message-editor>` component and resizable panes (see `CC-UI-0030` for the
  full detail — this is the PROXY-side bookkeeping entry, per this lane's
  dual reservation). **No PROXY-component code changed**: `fuzzlab/proxy/*`
  (engine, interceptor, repeater, scope, match-replace, history) and
  `fuzzlab/web/proxycontrol.py` / `fuzzlab/web/proxyview.py` (the read/write
  surfaces the UI calls) are all untouched. This entry exists to record that
  PROXY-facing UI effect, the same pattern `CC-UI-0027`/`CC-PROXY-0017` used
  for D0a's cross-component UI note.
- Impact (other components / project): none on PROXY's own behavior or data
  contracts (`flow`/repeater-tab schema, scope/match-replace semantics,
  intercept hold/forward/drop) — purely a client-side re-lay of how those
  existing `/api/proxy/*` routes are displayed and edited. `RepeaterController`
  (`CC-PROXY-0016`, BUG-0021's per-thread SQLite fix) is unmodified. The
  `--authorized` gate on Repeater sends, and the "not running in-process"
  fallback messaging for Intercept/Repeater/Scope, are unchanged — proxy/
  desync tooling's default-off, lab-only posture (CLAUDE.md Safety) is not
  affected.
- Risk (level; mitigation): low — no PROXY code path changed; the only risk
  surface is the UI's byte-exact round-trip through the new editor, mitigated
  as described under `CC-UI-0030` (unchanged `toWire()` CRLF-restore path,
  `getBytes()` reading only the plain-textarea source of truth, existing
  Repeater/Intercept/History test suites re-run unmodified).
- Deliverables:
  - [x] Confirmed no `fuzzlab/proxy/*` or `fuzzlab/web/proxycontrol.py` /
    `fuzzlab/web/proxyview.py` changes were needed or made — done.
  - [x] Confirmed the existing proxy/repeater/intercept test suites
    (`tests/test_proxy_*.py`, `tests/test_web_intercept.py`,
    `tests/test_web_repeater*.py`, `tests/test_web_proxy_history.py`,
    `tests/test_web_scope.py`) pass unmodified against the new UI — see
    `CC-UI-0030`'s Effectiveness for the run's pass/skip counts.
- Effectiveness (assessed 2026-09-22): effective — the PROXY backend and its
  contract are provably untouched (no diff under `fuzzlab/proxy/` or the
  proxy control/view modules), and its test suites pass unmodified against
  the rebuilt UI.

### CC-PROXY-0017 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/proxy/cli.py::build_parser()` gained `--dry-run` (via the shared
  `fuzzlab/cli_dryrun.add_dry_run_flag()`). `main()` checks `args.dry_run` first —
  before `LocalCA` is constructed, before the `--export-ca` branch, and before the
  `--authorized` gate — and calls `fuzzlab/cli_dryrun.report("proxy", args)`, reusing
  the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then returns 0. No listener is started, no
  CA file is written, and no upstream traffic is sent. `--dry-run` takes priority
  over `--export-ca` (both send no traffic, but `--export-ca` still writes files;
  `--dry-run` performs neither). Unchanged when `--dry-run` is absent.
- Impact (other components / project): PROXY only, plus an incidental UI effect —
  see CC-UI-0027 (introspected `build_parser()` surfaces the new checkbox in the web
  launcher automatically; `fuzzlab/web/app.py` untouched). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect (including the `--export-ca` file write). Mitigated by
  `tests/test_cli_dry_run.py` (proxy case: flag present, report printed, `LocalCA`/
  `SocketSender`/`asyncio.run` patched to raise if called) and the unchanged full
  suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `proxy`'s parser — done.
  - [x] Short-circuit ahead of `LocalCA`/`--export-ca`/`--authorized` in `main()`,
    calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab proxy --dry-run` prints
  the planned argv/command and returns 0 without creating a CA, opening a listener,
  or sending any traffic; verified directly and via the new tests.

### CC-PROXY-0016 — Fix (BUG-0021): `RepeaterController` per-thread SQLite connection (2026-09-21)
- Change: `fuzzlab/web/proxycontrol.py::RepeaterController` no longer caches one shared
  `Store`/`Repeater` on `self`. It now keeps them per calling OS thread
  (`threading.local()`), created lazily on that thread's first write, while a single
  `repeater` run row (`self._run_id`) is created once under a lock and shared by every
  thread's `Repeater` so tabs from any thread still appear together. `list_tabs()` and
  `create_from_flow()` use a new `_thread_store()` helper in place of the old shared
  `self._store` for their "open a throwaway connection when nothing persistent exists
  yet" read path.
- Impact (other components / project): fixes an intermittent
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that
  same thread` in `tests/test_web_repeater.py`'s route tests (found incidentally by
  another lane; see `ERROR_LOG.md` 2026-09-21 and `docs/bugs/BUG-0021-*`). No change to
  `Repeater`/`HistoryWriter`/`Store` themselves, to any HTTP route contract, or to
  `ProxyController` (the in-process proxy-engine controller, which remains correctly
  single-threaded by construction — its cached `self._store` is safe and unchanged).
- Risk (level; mitigation): low — internal correctness fix, no interface/schema change.
  Mitigated by: reproduced the race directly (a thread-churn stress harness driving the
  same route-handler path showed ~50-75% failure rates across 300-400 iterations before
  the fix; 0 failures across 600+ iterations after); `tests/test_web_repeater.py` (5
  tests) still green; full suite green (642 passed / 5 skipped across repeated runs; the
  2 `test_mutation_operators.py` failures are pre-existing and unrelated).
- Deliverables:
  - [x] Per-thread `Store`/`Repeater` in `RepeaterController` (`threading.local()`) — done.
  - [x] Shared `run_id` across threads under a lock — done.
  - [x] `list_tabs()`/`create_from_flow()` updated to the per-thread store helper — done.
  - [x] Stress-reproduced pre-fix, verified fixed post-fix; full suite re-run — done.
- Effectiveness (assessed 2026-09-21): effective — the same stress harness that
  reliably reproduced the cross-thread error pre-fix shows zero failures post-fix across
  600+ iterations, and the full suite is stable across repeated runs.

### CC-PROXY-0015 — Optional response interception (engine hook + Interceptor flag) (2026-09-21)
- Change: `ProxyEngine.handle_request` now runs an **awaited response-intercept hook** after
  the byte-exact forward: if the interceptor opts in, the response is wrapped as a
  `RawMessage`, held for a forward/edit/drop decision, and its `.raw` returned (a dropped
  response sends nothing). `Interceptor` gained `intercept_responses` (default **off**) and
  `set_intercept_responses(on)` (turning it off releases any held responses). The engine
  gates the hook on that flag, so the default path is unchanged and **byte-exact** (the
  wrap + `.raw` round-trips the exact bytes); request interception is unchanged.
- Impact (other components / project): completes the Burp-style intercept model — requests
  were already pausable; responses are now optionally pausable/editable — which the Phase-2.2
  web Intercept UI drives (CC-UI-0017). No schema change; no change to the record/forward
  path when response interception is off.
- Risk (level; mitigation): low — additive and gated. Mitigated by
  `tests/test_proxy_response_intercept.py` (request edit/forward, request drop sends
  nothing, response NOT held by default incl. byte-exact passthrough, response edit, response
  drop) and `tests/test_proxy_intercept_live.py` (a real request through `AsyncProxyServer`
  is paused, edited, forwarded, and reaches a threaded upstream with the edit). Existing
  proxy intercept/server/live suites still pass. Suite 484 passed / 6 skipped.
- Deliverables:
  - [x] Gated response hook in `ProxyEngine`; `Interceptor.intercept_responses` + setter — done.
  - [x] Engine + over-socket integration tests — done.
- Effectiveness (assessed 2026-09-21): effective — responses can be held/edited/dropped when
  enabled, and the default request-only path stays byte-exact; verified over real sockets.

### CC-PROXY-0014 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/proxy/cli.py` now factors its argparse setup into `build_parser()`;
  `main()` keeps the `p` reference (so `p.error(...)` on `--export-ca`/`--authorized` still
  works) and delegates parsing. Behavior-preserving — same flags, defaults, and gates.
- Impact: lets the web launcher introspect the proxy's flags (CC-UI-0011). Independent of
  the Phase-2 proxy-workbench wiring. No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the proxy's spec
  from this parser.

### CC-PROXY-0013 — Fix (BUG-0012): proxy_e2e.sh self-test uses conflicting Content-Length (2026-09-21)
- Change: `scripts/proxy_e2e.sh` step 5 now sends **conflicting** Content-Length values
  (`0` and `5`) instead of two identical `0`s. Duplicate-*identical* Content-Length is
  valid per RFC 7230 (h11 accepts it), so the old assertion (`is_valid_request` is False)
  produced a false FAIL even though the proxy forwarded byte-exact correctly. Runbook
  Part I.4 clarified to use conflicting values.
- Impact (other components / project): the Part I exit self-test now matches the validated
  offline unit test (which already used 5/6) and passes on-host. No product-code change —
  the proxy's raw byte-exact forwarding was already correct.
- Risk (level; mitigation): low — test/script-only. The offline
  `test_async_server_forwards_duplicate_content_length_byte_exact` already covers the
  correct (conflicting) case. Suite 415 passed / 6 skipped.
- Deliverables:
  - [x] Conflicting-CL request in `proxy_e2e.sh`; runbook wording — done.
  - [x] RCA `docs/bugs/BUG-0012-*`; rule PA-0013; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): the on-host Part I run's exit check now reflects the
  true HTTP contract (only conflicting CL is rejected) and passes.

### CC-PROXY-0012 — Fix (BUG-0010/BUG-0011): leaf-cert AKI/SKI + bounded async shutdown (2026-09-21)
- Change: fixed two on-host proxy defects found running Part I. (BUG-0010) `LocalCA` now
  mints certs strict verifiers accept — CA with SKI + keyCertSign KeyUsage; leaf with SKI,
  an AKI referencing the CA, serverAuth EKU, a leaf KeyUsage, and an IPAddress SAN for IP
  hosts; dropped deprecated `datetime.utcnow()`. (BUG-0011) `AsyncProxyServer` tracks and
  cancels its per-connection tasks and bounds `wait_closed()` with a 3s timeout so stop()
  can't hang on live connections (a Python 3.12+ behavior); the proxy CLI persists flow
  history per-record (`batch_size=1`, WAL) and `scripts/proxy_e2e.sh` bounds its shutdown
  with a `-KILL` fallback.
- Impact (other components / project): HTTPS interception now actually works on-host (the
  minted leaf verifies and a browser will trust it), and `fuzzlab proxy` /
  `scripts/proxy_e2e.sh` exit cleanly instead of hanging. No interface change; the flow
  store is written incrementally now (WAL-safe concurrent reads).
- Risk (level; mitigation): low — additive cert extensions + a more careful teardown.
  Mitigated by a skip-guarded extension-assertion test (leaf AKI matches CA SKI, serverAuth
  EKU, IP SAN) plus the existing on-host tunnel test that reproduced BUG-0010 and now
  passes; the offline connection tests still pass with the new stop(). Suite 415 passed /
  6 skipped.
- Deliverables:
  - [x] SKI/AKI/EKU/KeyUsage + IP SAN in `LocalCA`; non-deprecated UTC (BUG-0010) — done.
  - [x] Tracked+cancelled conns and bounded `wait_closed()`; per-record history; bounded
        script shutdown (BUG-0011) — done.
  - [x] RCAs `docs/bugs/BUG-0010-*`, `BUG-0011-*`; PA-0011/PA-0012; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): offline suite green; the on-host CONNECT/TLS tunnel
  test that failed with "Missing Authority Key Identifier" now has the extensions it needs,
  and shutdown is bounded so the Part I script can no longer hang.

### CC-PROXY-0011 — Live h2c socket transport for the raw HTTP/2 client (Phase 9 on-host, T9.x) (2026-09-21)
- Change: built the Phase 9 on-host last mile so runbook Part K is a one-command flow. New
  `fuzzlab/proxy/h2transport.py::H2Transport` is the socket send/receive around the
  already-built `H2RawClient`/`h2frames`/`hpack`: `request(...)` opens a plaintext TCP
  socket to an h2c (prior-knowledge) endpoint, sends preface+SETTINGS+HEADERS, ACKs the
  server SETTINGS, reads to END_STREAM, and decodes an `H2Response` (`:status` when
  static-indexed; reassembled DATA body); `send_raw(...)` writes exactly the bytes from
  `build_raw(...)` for malformed/length-desync/CRLF-in-header primitives. Orchestration
  `scripts/h2_desync_e2e.sh`.
- Impact (other components / project): the from-scratch HTTP/2 client can now talk to the
  lab's opt-in h2→h1 downgrade front-end over a real socket — no TLS/ALPN/Upgrade needed
  (nginx `http2 on;` prior knowledge). Depends on the LAB desync profile (CC-LAB-0010 adds
  `PFF_PROFILE` to `labctl.sh`). No change to the byte-building modules. Dual-use protocol
  tooling; loopback + opt-in profile only.
- Risk (level; mitigation): low–medium — a real socket to a smuggling research target.
  Mitigated by: loopback-only, the front-end being opt-in (`desync` profile, default off),
  the transport reading with bounded timeouts, and tests (`tests/test_proxy_h2_transport.py`)
  that exercise the real socket path against a one-shot loopback server: a normal request
  decodes `:status`/body, `send_raw` puts a length-desync frame on the wire byte-exact, and
  a CRLF-in-header value is carried verbatim. The desync exit is framed as emitting the
  primitive (a patched nginx correctly rejects it), not a successful smuggle. Suite 411
  passed / 5 skipped.
- Deliverables:
  - [x] `H2Transport.request` / `send_raw` (live h2c socket) + tests — done.
  - [x] `scripts/h2_desync_e2e.sh`; runbook Part K rewritten to one command — done.
  - [ ] Live smuggle against a deliberately-mishandling front-end — out of scope (nginx is patched).
- Effectiveness (assessed 2026-09-21): effective offline — the transport round-trips a real
  h2 response and emits both desync primitives byte-exact over a socket. The live front-end
  exchange is driven by `scripts/h2_desync_e2e.sh`.

### CC-PROXY-0010 — Live upstream SocketSender + CONNECT/TLS termination + `fuzzlab proxy` CLI (Phase 6 on-host, T6.x) (2026-09-21)
- Change: built the Phase 6 on-host last mile so runbook Part I is a one-command flow.
  New `fuzzlab/proxy/socketsender.py::SocketSender` is a real upstream `Sender`
  (`(host,port,use_tls,raw)->bytes`): TCP/TLS-connect, send byte-exact, read the whole
  HTTP/1 response (Content-Length / chunked / close-delimited). `AsyncProxyServer` gained
  a `ca` param and a `_handle_connect` that replies `200 Connection Established`,
  TLS-terminates the client with a CA-minted per-host leaf (new
  `LocalCA.leaf_cert_files` materializes the leaf to 0600 files; server-side upgrade via
  `loop.start_tls`), and forwards tunnelled requests through the same engine to the HTTPS
  upstream; without a CA, CONNECT still answers 501. New `fuzzlab/proxy/cli.py`
  (`fuzzlab proxy`, dispatched in `cli.py`): `--export-ca` (no `--authorized`; sends
  nothing) and the run path (requires `--authorized`), with scope/store/ca-dir flags.
  Orchestration `scripts/proxy_e2e.sh`.
- Impact (other components / project): the proxy can now intercept live traffic against
  the lab and record flows to the store; HTTPS interception works once the CA is trusted.
  Reuses the existing sans-I/O engine/repeater seam unchanged (the sender is injected), so
  no change to match-replace/history/scope/intercept. Per D5 the proxy stays optional and
  out of the timing path. Depends on `cryptography` on-host for minting + the handshake.
- Risk (level; mitigation): medium — real sockets + a server-side `loop.start_tls`
  upgrade (an internal-ish streams idiom) and MITM TLS. Mitigated by: byte-exact
  forwarding (no reserialization), full upstream TLS verification by default
  (`--no-verify-tls` opt-in for self-signed lab origins), the CA key staying 0600 and
  never distributed, `--authorized` gating the run, loopback defaults, and tests —
  `tests/test_proxy_live.py`: SocketSender Content-Length + close-delimited reads, the
  byte-exact duplicate-Content-Length forward through the async server (parsed path
  rejects it), and a skip-guarded on-host CONNECT+TLS tunnel that forwards byte-exact.
  Suite 408 passed / 5 skipped.
- Deliverables:
  - [x] `SocketSender` (real upstream, byte-exact) + tests — done.
  - [x] CONNECT/TLS termination in `AsyncProxyServer` + `LocalCA.leaf_cert_files` — done.
  - [x] `fuzzlab proxy` CLI (+ `--export-ca`) and dispatch — done.
  - [x] `scripts/proxy_e2e.sh`; runbook Part I rewritten to one command — done.
  - [ ] Live browser-trust + HTTPS interception walk-through — on-host (script prints steps).
- Effectiveness (assessed 2026-09-21): effective offline — the real sender round-trips and
  the duplicate-Content-Length request forwards byte-exact while the parsed path rejects
  it. The CONNECT+TLS tunnel and CA minting are covered by skip-guarded tests that run
  on-host, and `scripts/proxy_e2e.sh` drives the live lab exit.

### CC-PROXY-0009 — HTTP/2 frames + minimal HPACK + raw-frame client (T9.2/T9.3) (2026-09-21)
- Change: from-scratch, byte-exact HTTP/2 for the raw path. `fuzzlab/proxy/h2frames.py`
  encodes/decodes the frame types (DATA/HEADERS/SETTINGS/WINDOW_UPDATE/RST_STREAM/PING/
  GOAWAY/…), the connection preface, and lets the caller **override the declared length**
  independent of the payload (a length-desync primitive). `fuzzlab/proxy/hpack.py` is a
  minimal HPACK (integer/string primitives, the static table, literal representations,
  decode of static-indexed + literal; dynamic table + Huffman-encode out of scope) that
  passes **arbitrary header bytes** through unchanged. `fuzzlab/proxy/h2client.py::H2RawClient`
  assembles a request (preface → SETTINGS → HEADERS → optional DATA) and, via `build_raw`,
  arbitrary/malformed frame sequences — the desync/smuggling tool for the **self-owned
  lab** (the T9.5 h2→h1 front-end). Dependency-light; the parsed `h2` path is declared +
  skip-guarded (on-host).
- Impact (other components / project): realizes the HTTP/2 half of protocol depth — raw
  frame construction with arbitrary bytes for authorized desync research, offline-testable.
  The live socket + TLS + ALPN override and sending to a real h2 endpoint are on-host
  (T9.4/T9.6). Lab-only posture unchanged; no store change.
- Risk (level; mitigation): medium (dual-use tooling) — mitigated structurally by scope
  enforcement, loopback/lab-only, no-auto-run, and the target being infrastructure we run
  ourselves; the raw client only *builds bytes* here (no network). Correctness mitigated
  by 13 tests (`tests/test_proxy_h2.py`): HPACK integer RFC vectors, header round-trip
  incl. arbitrary CRLF, static-indexed decode, Huffman-decode raises; frame round-trip +
  flags, the length-override desync primitive, all builders, multi/partial-tail decode,
  truncation errors; client request structure, body DATA frame + odd/incrementing stream
  ids, arbitrary-header passthrough, and arbitrary-frame `build_raw`. Suite 341 passed / 4 skipped.
- Deliverables:
  - [x] HTTP/2 frame layer (T9.2) — done.
  - [x] Minimal HPACK (T9.2) — done.
  - [x] HTTP/2 raw-frame client (T9.3, offline builder) — done.
  - [ ] Parsed `wsproto`/`h2` path (T9.4); lab h2→h1 front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — HPACK matches the RFC integer
  vectors and preserves arbitrary bytes, frames round-trip byte-exact with a working
  length-desync primitive, and the client builds valid and deliberately-malformed requests;
  live ALPN/socket + the desync exit are on-host.

### CC-PROXY-0008 — WebSocket framing + flow.protocol (Phase 9 T9.1) (2026-09-21)
- Change: began protocol depth. `fuzzlab/proxy/ws.py` is a from-scratch, byte-exact RFC
  6455 WebSocket frame codec — `encode_frame`/`decode_frame`/`decode_frames` (FIN/RSV/
  opcode, MASK, 7/16/64-bit lengths, masking key), `apply_mask` (self-inverse),
  `reassemble` (fragmented data frames → messages), control-frame handling, and the
  handshake (`accept_key`, `is_upgrade_request`/`is_upgrade_response`) reusing the
  HTTP/1.1 machinery. The Phase 6 history now tags each flow's protocol: `FlowRecord`
  gains `protocol` (default `http/1.1`) and the writer persists it (migration 9's
  `flow.protocol`). Dependency-light (stdlib); the `wsproto` parsed path is declared and
  skip-guarded (on-host).
- Impact (other components / project): the raw WebSocket path — inspect/edit/replay
  frames (including masked/malformed) without a library normalizing them — recorded and
  searchable in the existing history and replayable via the existing repeater (encoded
  frames are raw bytes). Sets up HTTP/2 (T9.2/T9.3) and the parsed-path integration
  (T9.4). No behavior change to HTTP/1.1 flows (protocol defaults to `http/1.1`).
- Risk (level; mitigation): low — pure, dependency-light byte logic; optional (D5).
  Mitigated by 11 tests (`tests/test_proxy_ws.py`): migration-9 schema; the RFC handshake
  vector; upgrade detection; byte-exact unmasked frame; masking hides payload + round-trips
  + self-inverse; 16/64-bit lengths; control frames; fragmentation reassembly; multi-frame
  + partial-tail decode; truncated-frame errors; history records the protocol tag. Suite
  328 passed / 4 skipped.
- Deliverables:
  - [x] WebSocket frame codec + handshake + history protocol tag (T9.1) — done.
  - [ ] HTTP/2 frames + HPACK (T9.2); raw-frame client (T9.3); parsed-path wsproto/h2
        (T9.4); lab downgrade front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — frames round-trip byte-exact
  (masked and unmasked), the handshake matches the RFC vector, and flows carry a protocol
  tag; live WS interception through the running proxy is on-host.

### CC-PROXY-0007 — Local CA, flow engine, and async server wiring (T6.6) (2026-09-21)
- Change: tied the proxy together. `fuzzlab/proxy/server.py::ProxyEngine` is the
  **sans-I/O** flow pipeline — scope check → match-and-replace → interception →
  byte-exact forward (via an injected upstream sender seam) → history — where
  FR-PROXY-1/3/5/6 meet; out-of-scope traffic is forwarded untouched and unrecorded.
  `parse_connect`/`target_from_request` handle CONNECT and rewrite absolute-form
  requests to origin-form. `AsyncProxyServer` is the asyncio socket layer; its
  **plain-HTTP** path is exercised offline over loopback. `fuzzlab/proxy/ca.py::LocalCA`
  is the local CA (FR-PROXY-2) with a per-host **leaf-cert cache** behind an injectable
  minter seam; the real X.509 minting is lazy `cryptography` (on-host).
- Impact (other components / project): completes the offline-buildable proxy stack — the
  engine, CONNECT/target parsing, the async plumbing, and the CA cache are all in place
  and tested. The **live last mile** is on-host: CONNECT + TLS socket serving and
  browser trust of the CA (the sandbox has no working `cryptography`/TLS), tracked in
  `docs/ON_HOST_TASKS.md`. Optional per D5; timing traffic bypasses it.
- Risk (level; mitigation): low offline (seam-isolated, pure pipeline); the security-
  sensitive TLS MITM is on-host with a local-only CA, scope enforcement, and redaction.
  Mitigated by 12 tests (`tests/test_proxy_server.py`, 1 skipped for broken sandbox
  crypto): CONNECT + absolute/origin/https target parsing; leaf-cache mints once per
  hostname (port-independent) + a skip-guarded real-minting test; engine forwards +
  records in scope, bypasses out-of-scope untouched/unrecorded, applies match-replace,
  and drops/edits via the interceptor; and the async server round-trips a plain-HTTP
  request over loopback (absolute→origin rewrite) and returns 501 for CONNECT offline.
  Suite 248 passed / 3 skipped.
- Deliverables:
  - [x] `ProxyEngine` sans-I/O pipeline (scope/match-replace/intercept/forward/log) — done.
  - [x] `parse_connect` + `target_from_request` (absolute↔origin) — done.
  - [x] `AsyncProxyServer` plain-HTTP path (offline loopback) — done.
  - [x] `LocalCA` leaf-cert cache + lazy `cryptography` minting — done.
  - [ ] Live CONNECT + TLS serving + browser trust of the CA — on-host.
  - [ ] Exit: browse the lab, hand-edit a duplicate `Content-Length`, see exact bytes — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the engine enforces scope,
  forwards byte-exact, intercepts, and records; the CA caches leaves per host; the async
  server round-trips plain HTTP. The live TLS browse-and-edit exit is on-host.

### CC-PROXY-0006 — Manual-login session capture + manager adoption (T6.5) (2026-09-21)
- Change: implemented FR-PROXY-9. `fuzzlab/proxy/session_capture.py::SessionCapture`
  watches the flows of a **manual browser login** through the proxy
  (`observe_request`/`observe_response`), accumulates the established cookies (from
  Set-Cookie and the browser's Cookie header) and any bearer token (with JWT `exp`,
  reusing `session/detect.py`), and builds a `SessionState`; `adopt_into(manager)` hands
  it to the session manager. Added `SessionManager.adopt(state)` (FR-SESS-11): marks the
  session valid, brings its host into scope, caches it for `prepare`/`apply`, and
  persists only NON-SECRET metadata. No per-host config file.
- Impact (other components / project): gives the session manager (#3) a way to stay
  authenticated on logins detection can't parse (MFA/CAPTCHA/multi-step/SPA) — the
  escape hatch D13 promised. Secrets live only in memory and are never written to the
  store (the `session_state` table has no secret columns), consistent with the D12
  secret model. Realizes CC-SESS-0004's spec (see CC-SESS-0007).
- Risk (level; mitigation): low — pure observation + in-memory handoff; adoption reuses
  the existing persistence path (non-secret only). Mitigated by 5 tests
  (`tests/test_proxy_session_capture.py`): cookie capture, bearer+exp capture, adoption
  authenticating `prepare` with no login handshake, and non-secret-only persistence.
  Suite 237 passed / 2 skipped.
- Deliverables:
  - [x] `SessionCapture` (cookie/token capture from flows) — done.
  - [x] `SessionManager.adopt` (FR-SESS-11) — done.
  - [ ] Live capture while browsing the lab through the running proxy — on-host (T6.6).
- Effectiveness (assessed 2026-09-21): effective in tests — a captured session
  authenticates the manager without a login handshake and no secret is persisted; the
  live browser capture is on-host.

### CC-PROXY-0005 — Interception (awaited future) + repeater (T6.4) (2026-09-21)
- Change: `fuzzlab/proxy/intercept.py::Interceptor` models interactive interception as
  an `asyncio.Future` (FR-PROXY-6): when enabled, the data path `await`s a per-message
  decision; `pending()`/`forward(id, edited?)`/`drop(id)` release it (edited via
  `RawMessage`), and disabling releases everything unedited — off means transparent
  pass-through (D5). `fuzzlab/proxy/repeater.py::Repeater` (FR-PROXY-4) persists tabs to
  `repeater_tab` (a saved raw request + target) and replays them through an injected
  **sender seam**, sending the exact bytes (raw path) and optionally recording the
  exchange to history.
- Impact (other components / project): the manual-testing surface — hold/edit/release
  and edit/replay — over the byte-exact core. The sender seam keeps it offline-testable
  (fake sender) while the on-host server supplies a real socket sender (T6.6).
- Risk (level; mitigation): low — sans-I/O logic behind seams; optional (D5). Mitigated
  by 9 tests (`tests/test_proxy_intercept.py`): disabled pass-through, forward-with-edit,
  forward-unedited, drop→None, disable-releases-held; tab persistence, byte-exact send,
  edited-raw replay persisting + sending exact bytes, and history recording.
- Deliverables:
  - [x] `Interceptor` awaited-future model (T6.4) — done.
  - [x] `Repeater` DB-persisted tabs + raw-path replay (T6.4) — done.
  - [ ] Wire both into the async server (T6.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — held flows release edited or
  dropped, and the repeater replays byte-exact requests through the seam.

### CC-PROXY-0004 — Flow history: migration 6 + batched writer + FTS5 (T6.3) (2026-09-21)
- Change: added the proxy's shared history. **Migration 6** extends `flow` with a
  `host`, an `in_scope` flag, and byte-exact `req_raw_sha`/`resp_raw_sha` (raw wire
  bytes content-addressed via `body`, like decoded bodies), adds a standalone `flow_fts`
  FTS5 index, and a `repeater_tab` table (registry head → 6).
  `fuzzlab/proxy/history.py::HistoryWriter` buffers `FlowRecord`s and flushes them in
  **one transaction** (batched, non-blocking data path — NFR-PROXY-nonblocking),
  content-addressing raw bytes + bodies, indexing the head text for search, and
  offering `search()` (FTS5, punctuation-safe phrase queries) and byte-exact
  `raw_request`/`raw_response` retrieval. Persisted bytes are **redacted** first
  (`fuzzlab/proxy/redact.py`) so secrets never land in the store or the FTS index
  (NFR-PROXY-safe); the wire path stays byte-exact.
- Impact (other components / project): realizes FR-PROXY-3 — flows land in searchable
  shared history with raw bytes the anomaly detector, UI, and analysis read (D5). Adds
  the store columns/tables the proxy contract needs without touching existing rows
  (append-only migration). `repeater_tab` is the persistence for T6.4's repeater.
- Risk (level; mitigation): low — additive schema, batched writes, redaction on write.
  Mitigated by 7 tests (`tests/test_proxy_history.py`): migration-6 schema; batching
  defers then auto-flushes; byte-exact raw round-trip when no secrets; secret
  redaction (not stored, not searchable); FTS search by url/host/header; content-
  addressed dedup of identical raw. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (flow raw bytes + FTS5 + `repeater_tab`) — done.
  - [x] Batched `HistoryWriter` + redaction + FTS search (T6.3) — done.
  - [ ] Interception + repeater (T6.4); session capture (T6.5); CA + server (T6.6) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — flows persist with
  byte-exact raw bytes, secrets are redacted, and history is searchable; the live
  capture-while-browsing path is on-host.

### CC-PROXY-0003 — Dual-path core: message model, parsers, scope, match-and-replace (T6.1/T6.2) (2026-09-21)
- Change: began Phase 6 with the offline-testable heart of the proxy — the **dual
  path** (D4). `fuzzlab/proxy/message.py::RawMessage` is a byte-exact container: it
  round-trips received bytes unchanged, exposes head/body and duplicate-preserving
  header views, and edits by **byte surgery** (`with_appended_header`, `with_header`,
  `without_header`, `with_request_line`, `with_body`) that leave untouched lines
  verbatim (NFR-PROXY-byte-exact). `fuzzlab/proxy/parser.py` is the parsed path over
  `h11` (`parse_request`/`parse_response`/`is_valid_request`) that validates and
  normalizes. `fuzzlab/proxy/scope.py::Scope` is a **default-deny** include/exclude
  engine (host + optional path regex; subdomain-suffix and port-less matching).
  `fuzzlab/proxy/matchreplace.py` applies ordered byte-level rewrites to the
  request/status line, a named header, or the body. Wrote `docs/PHASE_6_PLAN.md`.
- Impact (other components / project): delivers the phase's exit criterion in
  miniature — a hand-edited request with a conflicting duplicate `Content-Length` is
  forwarded byte-for-byte on the raw path while the parsed path rejects the ambiguous
  framing — establishing the byte-exact substrate the history, repeater, interception,
  and session-capture tasks build on. No store change yet (that is T6.3, migration 6).
  `h11` is a declared dependency (already installed); no new runtime dep this task.
- Risk (level; mitigation): low — pure, dependency-light byte logic; the proxy is
  optional (D5) and untouched by the core pipeline. Mitigated by 21 tests
  (`tests/test_proxy_message.py`): byte-exact round-trip, LF-only preservation,
  duplicate-header order, the duplicate-`Content-Length` raw-exact-but-parsed-rejects
  case (+ CL/TE smuggling primitive), all edit helpers, parser happy paths, and the
  scope + match-and-replace engines. Suite 217 passed / 2 skipped.
- Deliverables:
  - [x] `RawMessage` byte-exact model + edits (T6.1) — done.
  - [x] `h11` parsed path (T6.1) — done.
  - [x] Scope engine + match-and-replace (T6.2) — done.
  - [ ] Flow history + migration 6 (T6.3); interception + repeater (T6.4); session
        capture (T6.5); CA + async server wiring (T6.6, live on-host) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the raw path preserves
  malformed framing the parsed path rejects, which is the crux of the dual-path design;
  the live browse-and-forward exit is on-host.

### CC-PROXY-0002 — Planned: manual-login session capture (spec) (2026-09-21)
- Change: added FR-PROXY-9 — capture the authenticated session (cookies/tokens)
  from a **manual browser login** performed through the proxy and hand it to the
  session manager to adopt (FR-SESS-11). This is the escape hatch for logins the
  session manager's detection can't parse (MFA, CAPTCHA, multi-step, exotic SPA),
  with no per-host config. Spec only — no code (proxy is Phase 6).
- Impact (other components / project): gives the session manager (component #3) a
  way to stay authenticated on hosts detection can't handle; recorded in D13 and
  the Phase 6 roadmap; `ARCHITECTURE.md` #11 updated. No change to the store
  contract beyond the flows the proxy already records.
- Risk (level; mitigation): low (planning). Captured secrets are sensitive;
  mitigated by the proxy's existing redaction-on-write and lab-only/scope rules
  (NFR-PROXY-safe) and by not persisting them in cleartext.
- Deliverables:
  - [x] FR-PROXY-9 recorded — done.
  - [ ] Implement session capture + handoff to the session manager — todo (Phase 6).
- Effectiveness (assessed or pending): pending — built in Phase 6.

### CC-PROXY-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented.
  Decision D4 sets the build-from-scratch hybrid (sans-I/O parsed path + raw byte
  path); decision D5 fixes it as an optional observer on the shared store.
- Impact (other components / project): once built, it writes `flow` rows the
  anomaly detector, UI, and analysis read; it attaches the session manager as an
  addon so manual traffic is authenticated. Because it is optional (D5), no other
  component gains a hard dependency on it, and timing-sensitive fuzzing must be
  able to bypass it. Adds `flow` (+ raw bytes) to the store contract.
- Risk (level; mitigation): medium — a proxy in the data path can distort timing
  and is a security-sensitive component (TLS MITM, stored raw traffic). Mitigated
  by keeping it optional and out of the timing path (D5), a local-only CA, scope
  enforcement, redaction on write, and batched non-blocking history. The raw path
  isolates byte-exact study from the parsed path.
- Risk justification (accepted): building from scratch instead of adopting
  mitmproxy is accepted for the flexibility it buys (D4) — the byte-exact raw path
  and full control over interception — at the cost of more implementation work,
  sequenced after the session manager (Phase 6).
- Deliverables:
  - [ ] Async core; parsed (`h11`/`h2`/`wsproto`) + raw byte paths — todo (Phase 6).
  - [ ] CONNECT + TLS interception (local CA, cached leaf certs) — todo (Phase 6).
  - [ ] History: `flow` rows, FTS5, batched writes, content-addressed bodies — todo (Phase 6).
  - [ ] Repeater (DB-persisted tabs) + match-and-replace + scope engine — todo (Phase 6).
  - [ ] Interception-as-awaited-future workflow — todo (Phase 6).
  - [ ] Session-manager addon integration — todo (Phase 6).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  byte-exact replay, searchable shared history, and zero impact on timing-sensitive
  runs (which bypass it).
