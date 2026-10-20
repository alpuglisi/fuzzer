# BUG-0536 — Reads of untrusted input were bounded only after the work: whole target bodies, a JSONL line cap after buffering, contract regexes with unbounded CPU

- Date: 2026-10-20
- Status: fixed (CC-CORE-0072, CC-CRAWL-0054, CC-FUZZ-0109), with stated residuals
- Severity: high. The audit rated defects 21, 23 and 27 CRITICAL. A target, or a corrupt
  capture file, could hold a worker for as long as it kept sending, fill memory from a
  small compressed body or one unterminated line, or pin the contract runner's CPU with
  one short answer.

## Description
Three reads of untrusted input checked their bound on the finished artefact, never while
the work was done:

1. **Audit defect 21 (target bodies).** Every `requests` reader of a target's body read
   it whole: `core/http.py::_requests_transport` (`resp.content`),
   `tools/navguard.py::get_checked` (a non-streamed `session.get`, then `resp.text`), and
   `tools/probesender.py::RequestsProbeSender._request` (`r.text`). The sweep found the
   same in greybox's `RequestsCorrelatingSender`, the blind-SQLi `RequestsSender`'s
   session, and the spider's static form submission (`iso.post`, which reads the body
   it never uses). `requests` decodes a whole body without a ceiling, and its timeout
   bounds each receive, not the total. The contract runner streamed, but checked its
   deadline only between 64 KiB `iter_content` steps, and one step blocks until 64 KiB
   arrive.
2. **Audit defect 23 (the JSONL tail).** `disco/capture.py::JsonlTail.lines` appended
   every unterminated chunk to `_rest` (`_rest + data`), and the line cap
   (`MAX_LINE_BYTES`) was applied by `_parse_line` to complete lines only. An
   unterminated line was held whole, and its reading was quadratic. The explorer's
   action log reads through the same tail.
3. **Audit defect 27 (contract regexes).** `disco/contract.py::case_problems` only
   compiled a `body_matches` pattern; `disco/runner.py::Runner.judge` ran `re.search`
   with it on target text in the runner's own thread.

## Where encountered
The external adversarial audit at 6552276 (defects 21, 23, 27), confirmed against the
source by F-096; reproduced at 4ee8007 by `tests/test_bounded_reads.py`, written first.

## What it caused to fail
Measured at 4ee8007 (loopback peers, no target contacted):
- **A dripped body** (120 bytes, one every 50 ms, each well inside a 0.25 s read
  timeout, done after 6 s): the core seam's transport, the static fetch, both probe
  senders and greybox's sender each waited the whole 6 s and returned "a normal body of
  120 bytes".
- **A gzip bomb** (40 KiB decoding to 40 MiB): each decoded it whole and returned it as
  a normal body.
- **The JSONL tail:** an unterminated line past the cap was held, and nothing was
  quarantined. A 16 MiB line under a 64 KiB cap peaked at 33 559 459 traced bytes. The
  action log never numbered the line.
- **The contract runner:** `(a+)+$` against `a` x 36 + `!` was still running in the
  runner's thread when a 60 s alarm stopped it (the audit measured 1.09 s at 24 `a`s,
  doubling with each).
- **BUG-0528's residual R6:** a drip held the runner until the peer stopped.

## What the bug was identified to be
- A whole-body read, `resp.content` / `r.text` on a response that was not streamed, was
  taken as the only way to read; a `requests` timeout was taken as an overall deadline.
- A line cap enforced by the parser of a finished line, not by the reader that buffers
  it; a per-read buffer concatenation.
- Pattern validation by compilation only, and matching in the caller's own thread, which
  nothing can stop while `re` backtracks.

## Root cause analysis
Five Whys, across the three defects:
1. *Why could a target hold a reader, or fill its memory?* No read loop had a total
   deadline or a decoded ceiling: the body was read by one library call.
2. *Why was that accepted?* Each reader passed a timeout, and the timeout was read as
   the bound. BUG-0101's sweep (2026-10-13) cleared "greybox, probe and tool senders:
   `requests` with timeouts, outside asyncio" on that premise, without measuring it.
   Measured here: one `iter_content` step took 1.96 s for 40 bytes dripped under a 1 s
   timeout, and a `read1` receive returned each byte.
3. *Why did each new reader repeat it?* There was no owner for "read a target's body".
   Five readers had three styles, the contract runner (CC-FUZZ-0089) added a fourth, and
   BUG-0528 deferred its drip to "defect 21's read-deadline owner", who did not exist.
4. *Why were the JSONL cap and the regex the same failure?* Each bound was checked on
   the finished artefact: a whole line at the parser, a compiled pattern at validation.
   The work that needed the bound (buffering, matching) ran before the check, or with
   none.
5. *Why did PA-0102 not stop it?* PA-0102 was enforced only by the proxy's own tests,
   and it named one swept pattern (`bytes(buf)` in a loop).

**Root cause:** bounds on untrusted input were stated as a rule (PA-0102) and enforced
at the one site of the bug that produced it. No owner existed for reading untrusted
input, and the checks sat on the finished artefact instead of inside the loop that does
the work.

## Corrective action
(CC-CORE-0072, CC-CRAWL-0054, CC-FUZZ-0109.)
- **One bounded reader, `fuzzlab/core/bodyread.py`** (SP-60, FR-CORE-536).
  `read_body(resp, deadline=, limits=)` reads the undecoded stream one receive at a time (urllib3
  `read1`). It counts wire bytes (`MAX_WIRE_BYTES`, 16 MiB) and decodes incrementally
  with an output ceiling per step (`MAX_DECODED_BYTES`, 32 MiB): zlib's `max_length`,
  and Brotli's `output_buffer_limit` from Brotli 1.2. It checks the deadline before each
  receive and once more at the end, so a late body is incomplete too. It returns a typed
  `Body`; an incomplete one never becomes a normal body.
  - `bound(session)` mounts `BoundedAdapter` on a `requests.Session`. It reads every
    response before `send` returns, with a deadline of 4 x the read timeout (60 s
    without one). An incomplete body raises `BodyIncomplete`, a
    `requests.RequestException`, with the response closed and its connection dropped.
  - Codings as urllib3 decodes them. A coding urllib3 passes through is passed through.
    `zstd`, a `br` body with a Brotli that cannot bound its output, and a chain of
    codings are incomplete (`encoding`), never text.
- **The readers:**
  - the core seam's transport (a bounded session per send);
  - `navguard.get_checked` (it bounds the `requests.Session` it is given; that covers
    the spider's and the auditor's static fetch);
  - `RequestsProbeSender`, greybox's sender, the blind-SQLi session and the spider's
    three sessions (bounded where they are made).
  - The contract runner reads through `bodyread.read_body` with its own limits
    (`max_body_bytes` on the wire and decoded, `timeout_ms`). This closes BUG-0528 R6
    for body bytes.
- **SP-34:** `probesender._unobserved` maps `BodyIncomplete` to `ProbeUnobserved`
  ("incomplete body (<reason>)"). It is never re-sent, and never read as latency: a body
  that kept arriving proves no delay. The oracle's SP-56 path is unchanged: a `Probe` is
  still a whole response or a status-0 stand-in, so no truncated body reaches it.
- **`JsonlTail`:**
  - The cap holds while a line is read. Once the held part of a line passes the cap,
    `OVERLONG` is yielded once in its place, the held bytes are dropped, and the rest
    of the line is discarded up to its newline, across reads.
  - The held part grows in one `bytearray` and is copied out once. `copied` counts the
    copies.
  - `CaptureTail` quarantines `OVERLONG`. `DiscoActionLines` numbers it as one malformed
    line, so the action log is capped too.
  - The old boundary holds: a line, newline included, over `MAX_LINE_BYTES`; a final
    unterminated line of exactly the cap is read.
- **The runner's `body_matches`:** `search_bounded` runs the case's patterns on its
  answer and its baseline in one worker, `python -I -S` through `procutil.run_bounded`.
  The worker is killed with its process tree after `MATCH_SECONDS` (5 s). An answer
  that is not one boolean per pattern and text is no answer. When the patterns could not
  be evaluated, the case is an `error` "body_matches not evaluated within 5 s
  (inconclusive)", unless other evidence matched. It is never a no-match.
- **Tests:** `tests/test_bounded_reads.py`: 30 test cases and 3 strict xfails. Every reader
  is driven against a dripping and a bombing loopback peer, and the peer's sent-byte
  count shows the connection was dropped. Decoding memory is measured, each coding is
  pinned, decoding stops exactly at the ceiling for gzip, deflate, raw deflate and
  Brotli fed in small receives, and the runner's drip is tested. The tail tests cover the over-cap line, the
  boundary, the action log, memory and the copy count, and the copy oracle is proven on
  the pre-fix algorithm. The regex tests cover the catastrophic pattern under a 60 s
  smoke alarm, pins through the worker, the matcher guard and the worker's shape check.
  The session guard (AST) is proven on synthetic offenders.

**Review round 1 (REVISE; one round).** The reviewer confirmed defects 23 and 27 closed
and the decoded-size and short-body logic sound, and required:
- **Greybox scored an incomplete body.** Its status-0 probe carried the error text,
  which `_screening` scored 0.5 as a boolean divergence (measured on a gzip bomb). It
  flowed into the reward, the attempt, the accepted variants and M10, and it could
  become the point's baseline. Now the sender returns a typed `UnobservedProbe`, and
  `run_greybox` never scores, records, accepts or adopts it; it counts it.
- **Sessions advertised codings the reader rejects.** urllib3's default
  `Accept-Encoding` names `br` with any Brotli (brotlicffi too) and `zstd` on Python
  3.14. On such a host every answer would have been `BodyIncomplete("encoding")`. Every
  bounded send, and the runner's, now advertises only what `read_body` can bound
  (`advertise`).
- **R1 closed, as defect 21 asks for a total-time bound.** The reviewer measured a
  dripped status line and headers at 6 s against a 1 s deadline. One process-wide
  watchdog thread (`watch`) shuts down (`SHUT_RDWR`) the socket of any watched exchange
  still in use at its deadline. That cuts a dripped status line, header or chunk-size
  line, and a send with no timeout. The runner's session is watched too.
- **Correctness fixes:**
  - `read_body` on an already-read response returns its kept content, never b"";
  - blind-SQLi drops a payload whose later repeat failed, where it wrote a `repeats=1`
    row;
  - the in-process matcher guard also sees `re.compile(rx).search(...)`.
- **Not built (optional):** a persistent matcher worker. Residual R6 records its cost.

**Residuals (stated):**
- **R1, the connect.** Closed for framing lines by the watchdog (above). What remains:
  the connect itself, and a TLS handshake, are bounded by the connect timeout only,
  because a socket shutdown does not interrupt a connect.
- **R2, the session manager's login fetcher.** `session/manager.py::
  _requests_fetch_factory` reads `r.text` unbounded. The file is AU-SESS403's; the
  remedy is `bodyread.bound(requests.Session())`. Pinned by the strict xfail
  `test_the_session_managers_login_fetch_is_bounded`.
- **R3, `formfill._fits`.** It runs a page's own `pattern` attribute (target-controlled)
  with `re.fullmatch` on a short candidate value we generate. That is the defect-27
  class, bounded only by the value's length. Pinned by the strict xfail
  `test_formfill_never_runs_a_pages_pattern_unbounded`.
- **R4, browser bodies.** Playwright response bodies (`navguard`'s route fetch,
  `spider`'s and `explore`'s `response.text()`) are a different mechanism: Chromium
  downloads the body whatever is read. Flagged, not in this class.
- **R5, a cut exchange's byte count.** The runner's evidence of a cut exchange now
  records 0 bytes: what was read before the cut is not kept. The body is still never
  written (PA-0528(1)).
- **R6, the matcher's cost.** A judged case with `body_matches` starts one worker
  interpreter, measured at 130-165 ms per call on this host (`procutil.run_bounded`,
  `python -I -S`). A persistent worker, restarted only after a kill, would remove this.
  It was not built: the leak guard requires every started server to be stopped, and a
  `Runner` has no close.
- **R7, greybox's other request errors.** A request error that is not an incomplete
  body (refused, timeout) is still greybox's status-0 try, scored by `_screening`
  from its error text, as before this change (its documented contract, for M10's side
  channel). Flagged as a follow-up, not changed here.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for unbounded reads, quadratic
buffering, caps applied after the work and unbounded pattern evaluation:
- **BUG-0101 / PA-0102:** a network read with no byte cap and no overall deadline,
  re-copied per chunk. **The same root cause**: a recurrence.
- **BUG-0528 / PA-0528:** the runner's in-read deadline fired only between chunks.
  Residual R6 was deferred to this defect.
- **BUG-0094 / PA-0095, BUG-0135 / PA-0135:** quadratic work, and complexity proven on
  an operation count. `JsonlTail`'s concatenation is that class.
- **BUG-0085 / PA-0086(1):** "user-supplied rules are validated when created (regexes
  …)". Validation was compilation, which says nothing of cost.
- **BUG-0095 / PA-0096(1)** and **BUG-0454 / PA-0454(1):** sizes bounded before
  allocation, values capped at one parser. The parser capped the line; the reader
  buffered it first.
- **BUG-0147 / PA-0153:** a cut-off body is `ProbeUnobserved`. Extended here to a body
  the reader stopped.
- **F-096:** the live `JsonlTail` (CC-CRAWL-0050) made defect 23 quadratic as well.

## Prior-preventive-action failure analysis
- **PA-0102 (BUG-0101): not enforced beyond the bug's own path; its sweep was judged by
  presence, not by measurement.** All three of its enforcing tests are the proxy's.
  - Its sweep cleared every `requests` sender because each passed a timeout. A
    `requests` timeout is per receive (measured above). Nothing tied the rule to a
    reader written later (the contract runner, the live tail).
  - Its swept pattern, `bytes(buf)` in a loop, did not name `rest + data`.
- **PA-0086(1) (BUG-0085): too narrow.** It asks that a regex be validated when it is
  created. Compilation proves the pattern parses, not that its matching ends. The rule
  said nothing of cost, so the contract runner met it and still ran `(a+)+$` without
  bound.
- **PA-0096(1) / PA-0454(1): wrong layer.** "Bounded before allocation" and "capped at
  one parser" were applied at the parser. The reader that allocates is the layer that
  must bound.
- **PA-0528 (BUG-0528): a residual deferred to an owner that did not exist.** R6 named
  "defect 21's read-deadline owner". No owner existed, so the residual had no
  enforcement until this item.
- **PA-0095 / PA-0135: not applied.** `JsonlTail` made no complexity claim, so nothing
  counted its copies.

## Preventive action
**PA-0536.** It strengthens PA-0102, PA-0086(1) and PA-0096(1) / PA-0454(1), and closes
PA-0528's R6 for body bytes. A bound on untrusted input is enforced inside the loop that
does the work: each receive, each buffered chunk, each match. It is never checked only on
the finished artefact (a whole body, a whole line, a compiled pattern).
1. **Reading a target's HTTP body has one owner** (SP-60, `core.bodyread`), with:
   - a wire ceiling and a decoded ceiling;
   - a wall-clock deadline checked at every receive, and held by a watchdog that cuts
     the socket wherever a library reads in one call (status line, headers, chunk
     lines);
   - a typed incomplete marker that no consumer takes for a body (SP-34 maps it to "not
     observed");
   - a request that advertises only the codings the reader can decode under its
     ceiling.

   Every `requests` session fuzzlab makes is bounded where it is made. An AST guard
   fails on a new unbounded `requests.Session()` or module-level `requests.<verb>()`,
   apart from listed and reasoned sites; it is proven on synthetic offenders.
   *(Review round 1.)* **Every consumer keeps the marker typed.** A stand-in that only
   looks like a response (status 0, error text as its body) is not a type, and no
   consumer scores, records, accepts or adopts as a baseline what the marker names.
2. **A timeout argument is not a deadline.** A sweep verdict that a read is bounded in
   time cites a test against a dripping peer, never the presence of a timeout.
3. **A line or record cap is enforced by the reader that buffers it**, as soon as the
   buffer passes it. Accumulation is linear, with an exposed copy count (PA-0135(2)).
4. **A pattern from a contract, a generator or a target runs on target text only under a
   time bound that can stop it**: a killable worker, never a thread. A timeout is
   inconclusive, never a no-match. Compiling a pattern validates its syntax, not its
   cost.

**The PA-0002 sweep.** By mechanism: every whole-body read of target data, every
buffered line reader of a file another process writes, and every untrusted pattern. It
re-sweeps every site BUG-0101's sweep cleared (PA-0067(3)). Each verdict names the
reader's scope (PA-0067(1)).

| Site | Reads | Disposition |
|---|---|---|
| `core/http.py::_requests_transport` | target bodies through the seam (both probe senders' seam path, the blind-SQLi seam, the auditor's seam fetch) | fixed |
| `tools/navguard.py::get_checked` | the spider's and the auditor's static fetch | fixed: bounds the session it is given |
| `tools/probesender.py::RequestsProbeSender` | the oracle's anonymous probes | fixed; SP-34 maps the marker |
| `greybox/run.py::RequestsCorrelatingSender` | greybox probes | fixed: a typed `UnobservedProbe`, never scored, recorded or adopted (review round 1) |
| `tools/blind_sqli_fuzzer.py` (`main`'s session) | timing probes | fixed; a failed later repeat drops the payload (review round 1) |
| `tools/spider.py` (`self.session`, the worker clone's, `iso`) | the crawl; `iso.post` read a body it never used | fixed |
| `disco/runner.py::Runner.send` | the contract runner | fixed through `read_body`, contract limits |
| `tools/fetcher.py` (`self.session`) | the auditor's static fetch, through `get_checked` only | covered by `get_checked`; listed (AUD, no CC in this item) |
| `session/manager.py::_requests_fetch_factory` | the login handshake | R2: strict xfail; AU-SESS403's file |
| `lab_fixtures/external.py` (`_default_session`, the bWAPP download) | provisioning the operator's own pinned containers; the download streams up to its pinned size | out of class (no crawl or probe); listed, flagged |
| `labgen/identifier_sqli_oracle.py::default_http_runner` | the conformance oracle of an app this project generated and booted | out of class; listed |
| `labgen/conformance/*live_boot.py`, `lab_fixtures/external.py::_pypi_get` (`urllib`) | own generated apps; PyPI artefacts | out of class (not a target) |
| Playwright `response.text()` / `body()` (`navguard`, `spider`, `disco/explore`) | browser-delivered bodies | R4: another mechanism, flagged |
| `disco/capture.py::JsonlTail` (`read_capture`, `CaptureTail`, `DiscoActionLines`) | capture and action logs | fixed |
| `disco/runner.py::Runner.judge` (`body_matches`) | contract patterns on target text | fixed |
| `disco/formfill.py::_fits` | a page's `pattern` on a generated value | R3: strict xfail, flagged |
| `disco/runner.py::LEAK_PATTERNS`, `mutation/xss.py::_blocked`, the proxy's match/replace rules | reviewed constants; our own payloads; operator-written rules | out of class: author trusted, or subject our own |
| BUG-0101's cleared proxy readers (`proxy/server._read_http_message`, `h2client`, `ws`) | the native proxy | audit defects 18-20 are another item's; not re-judged here, flagged |

- Enforced by: tests/test_bounded_reads.py::test_every_requests_session_fuzzlab_makes_is_bounded, tests/test_bounded_reads.py::test_the_session_guard_catches_synthetic_offenders, tests/test_bounded_reads.py::test_a_dripped_body_is_cut_at_its_deadline_and_never_taken_whole, tests/test_bounded_reads.py::test_a_gzip_bomb_stops_at_the_decoded_ceiling_and_is_never_taken_whole, tests/test_bounded_reads.py::test_an_unterminated_line_over_the_cap_is_quarantined_once_and_never_held, tests/test_bounded_reads.py::test_reading_a_long_line_in_small_pieces_copies_each_byte_a_bounded_number_of_times, tests/test_bounded_reads.py::test_the_copy_oracle_flags_a_quadratic_tail, tests/test_bounded_reads.py::test_a_catastrophic_pattern_is_an_error_never_a_hang_nor_a_no_match, tests/test_bounded_reads.py::test_the_matcher_never_runs_a_contract_pattern_in_the_runners_process, tests/test_bounded_reads.py::test_a_dripped_status_line_and_headers_are_cut_at_the_deadline, tests/test_bounded_reads.py::test_a_bounded_send_advertises_only_codings_it_can_bound, tests/test_bounded_reads.py::test_greybox_never_scores_records_or_adopts_an_incomplete_probe
