# BUG-0147 — a connection reset from the target ended the whole confirmation run (`test_multitarget_category4`)

- Date: 2026-10-15
- Status: fixed (CC-FUZZ-0088, CC-LAB-0259, CC-PROXY-0024, CC-UI-0056)
- Severity: high. One probe that got no response ended confirmation for every
  remaining candidate of every target in the run. In the suite this showed as one
  intermittent failure in about 7,000 tests. Against a real target that drops a
  connection, the whole scan stops.

## Description
`tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`
failed with `ConnectionResetError` (errno 104). Two defects combined:

1. **The lab app.** The Go Twitch clone's response-splitting twin
   (`raw_socket_response_write.go.j2`) takes over the raw connection and hand-writes
   `HTTP/1.1 302` with `Content-Length: 0`. It did not send `Connection: close`, and
   then closed the connection (`defer conn.Close()`). By HTTP/1.1's rules (RFC 9112
   §9.6) a client may reuse such a connection.
2. **The fuzzer.** Nothing defined what a probe that gets no response means.
   - `RequestsProbeSender._request` caught only `requests.Timeout`.
   - `SeamProbeSender` caught nothing.

   A reset raised out of the sender, the strategy and the oracle, and `run_targets`
   (which marks the run aborted and re-raises, by design, for a defect) ended both
   targets.

## Where encountered
- twice on 2026-10-14, under concurrent pytest load (parked as a "WATCH" item);
- `ser10`, the former serial list run in parallel (BUG-0142 work);
- the 2026-10-15 integration branch's full suite, after BUG-0143's fix.

## What it caused to fail
- The full suite's one remaining failure, which blocked a green verification of the
  merged branch.
- Any scan in which one probe meets a reset or a cut-off body: every later candidate
  went unconfirmed, with no finding and no inconclusive record. A reset is an ordinary
  event against deliberately vulnerable apps (response splitting, crashing handlers,
  hand-written servers).

## What the bug was identified to be
**Every time, the same request.** The template-injection confirmer (`SstiStrategy`,
opted in to post/redirect/get observation) probed the twin's `/channels/redirect`. The
twin answered with a 302 to `/channels/${603*129}`. The sender's PRG follow-up
(`GET /channels/$%7B603*129%7D`) met the reset.

**Mechanism.**
1. `requests` pooled the connection, because the response never said it would close.
2. The follow-up went out on that pooled connection at once.
3. When the Go handler's deferred `Close()` ran after the follow-up had arrived, the
   kernel closed a socket with unread data, which sends a reset instead of a FIN.
4. When the close ran first, urllib3 saw the dead connection before reusing it and
   opened a new one.

**Why only under load.** Which of the two orders happens depends on scheduling: whether
the Go goroutine reaches `Close()` before the client's next request arrives. Pure CPU
contention from six busy processes did not change that order in 10 runs. The full
parallel suite, with many processes starting, stopping and doing I/O, did, about once
per run. The exact ordering on the real Go app is inferred from the mechanism; it is
not observed.

**Reproduced deterministically, with no load** (`tests/test_probe_unobserved.py`): a
server that writes the twin's exact response and resets once the next request is on the
same connection. The unfixed sender raises the same
`ConnectionError(ProtocolError(ConnectionResetError(104)))`; with a prompt close the
same exchange passes. Reviewer B reproduced it independently with a plain `close()`
(no `SO_LINGER`), so the reset comes from the unread data, not from the test's linger
setting. **Tied to the real app:** the real Go twin, booted by `GoLiveBootHarness`,
answered `HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n` (no
`Connection: close`) and closed after that one response.

Ruled out earlier: CPU contention alone (above), the OOM killer (`oom_kill 0`), a Go
idle timeout (none is set), and BUG-0143's wrong-server hazard (it recurred with that
fix in place).

## Root cause analysis
**Method: barrier analysis.** The reset had to pass several controls before it could
end a run, and each one has to be explained. Five Whys would follow only one chain.

| Barrier | Why it did not stop this |
|---|---|
| HTTP correctness of the lab app | The twin's author worked on the CRLF injection, never on connection semantics. Nothing checks a hand-written response. |
| urllib3's stale-connection check | It detects only a close that has already happened. |
| A retry of an idempotent request | None: `requests`' default adapter retries nothing on a read. Browsers re-send an idempotent request that met a reset on a reused connection (RFC 9110 §9.2.2). |
| `RequestsProbeSender` / `SeamProbeSender` error handling | Timeout only, or nothing. The greybox sender already turned every request error into a probe, so three copies of "send a probe" had three error contracts and no owner. |
| The oracle's containment (PA-0137) | Applied to the M6 browser executor only. The HTTP send, the external work every other mechanism depends on, had none. |
| PA-0138(3)'s sweep ("swept across every caller of that primitive") | Swept page navigation, the primitive of the bug it came from, not the HTTP send. |
| The target boundary (`run_targets`, PA-0086(2)) | It re-raises on purpose so a defect stays loud (PA-0106); it relies on the layer below to contain external failures. That layer did not. |
| Triage | On 10-14 parked as "WATCH". On 10-15 attributed to BUG-0143 without a test, which the next recurrence disproved (corrected in 10a6b78). |

**Root cause:** the confirmation path had no defined outcome for a probe that got no
response. Each sender handled transport failures its own way, mostly not at all, so an
ordinary network event became an exception that nothing between the sender and the
target boundary was built to contain. The lab app's missing `Connection: close` was the
trigger that made the event common under load.

## Corrective action
Commit with CC-FUZZ-0088, CC-LAB-0259, CC-PROXY-0024 and CC-UI-0056 (FR-FUZZ-50,
FR-LAB-175):
- **`oracle.probe.ProbeUnobserved`**: the one named class for "sent, no complete
  response".
- **`probesender._unobserved`** is the one classifier (SP-34):
  - mapped: a reset or abort, a cut-off body (`ChunkedEncodingError`), an undecodable
    body (`ContentDecodingError`);
  - not mapped, so they fail loudly: a refused connection, DNS, TLS or proxy failure
    (a dead or unreachable target must never turn every candidate into a quiet
    inconclusive);
  - a timeout is not mapped either. `_is_timeout` also recognises a timeout while
    reading the body, which `requests` reports as a `ConnectionError`.
  - The message names error classes only, never the payload or URL.
- **`RequestsProbeSender`:**
  - re-sends a GET/HEAD/OPTIONS probe once, on a fresh connection, when the connection
    failed with no response (a reset, an abort, a close before any response). It
    never re-sends a cut-off or undecodable body, because the server had already
    answered. The re-send is counted (`Probe.resent`, and `ProbeUnobserved.resent`
    when it fails too) in the run's requests and the mechanism's cost;
  - otherwise raises `ProbeUnobserved`;
  - a PRG follow-up that gets no response sets `prg = "unobserved"`, and the probe
    keeps its own response;
  - a body-read timeout is a status-0 probe of the full timeout, like any timeout.
- **`SeamProbeSender`:**
  - maps transport failures of every network call a send makes (the probe, its
    follow-up, a first login, an isolated copy's login, a liveness check);
  - a timeout still raises, unchanged (see residuals);
  - an isolated copy whose login gets no response is a failed copy login: the copy is
    released, the path is failed with a fixed reason and probed anonymously, and the
    failure counts toward the failed-login breaker. A liveness check with no response
    is retried at the next copy;
  - the header breaker's note and a copy's re-login check also run when a probe got
    no response.
- **`Oracle._confirm_outcome`:**
  - `ProbeUnobserved` means no verdict from that mechanism; the other mechanisms still
    run;
  - with no confirmation the candidate is inconclusive (mechanism `unobserved`);
  - under a scheduler the arm gets reward 0 and its real cost;
  - logged with host and error class; any other exception still propagates.
- **Out-of-band mechanisms** (command injection, SSRF, XXE) still wait for the
  callback after a probe got no response, and raise `ProbeUnobserved` only if none
  came. A listener that is not running is no verdict (`UnplaceableLocation`), as a
  browser that cannot start.
- **The pipeline's baseline probe:** no response gives an unprobed target row, as for
  header points only. The inconclusive detail carries the reason.
- **Reports:**
  - the CLI prints an `unobserved` row with its reason;
  - the run page's and results' definitions of "inconclusive" name it.
- **The Go twin** sends `Connection: close`, after `Location` and `Content-Length`, in
  the original header order. An injected blank line still ends the head first, so
  the twin's classic full split (a second, attacker-controlled response) is
  unchanged.
- **The proxy's** hand-written 501 sends `Connection: close` too (found by the sweep).

### The unit of "not observed": a recorded deviation from PA-0137(4)
PA-0137(4) makes the probe the unit: one unobserved probe ends only that probe, and the
mechanism goes on within a stated bound. M6 can do that because its strategy handles
`NotObserved` itself. For HTTP, the oracle would have to hand the strategy a stand-in
for the response that never came. Then about 30 strategies, which compare responses
(differential, boolean, timing), would compare against a response that does not exist,
and a differential could confirm on it. A false confirmation becomes a finding and a
training label.

So the unit here is the mechanism: it gives no verdict, the candidate is never a
negative, and the other mechanisms still run. The cost of this choice is narrowed in
two ways:
- `RequestsProbeSender`, the only sender that pools connections, re-sends an idempotent
  probe once when its connection failed with no response, so a stale pooled
  connection does not cost a verdict. `SeamProbeSender` sends each request on a new connection
  (`core.http._requests_transport` uses `requests.request`), so a stale pooled
  connection cannot occur there; it does not retry;
- the OOB mechanisms, which never read the response, keep waiting.

Making the probe the unit for HTTP needs each strategy to handle an unobserved probe
explicitly. It is recorded as follow-up work, not done here.

## Recurrence review
- **BUG-0137 / PA-0137:** the same failure class. A mechanism's external failure
  raised out of the oracle and ended confirmation for every remaining candidate. There
  it was a page the browser could not load; here, an HTTP response that never came.
  **A recurrence; prior-PA analysis below.**
- **BUG-0138 / PA-0138:** the sweep rule that should have carried PA-0137 to the HTTP
  senders. **Prior PA failure** (below).
- **BUG-0085 / PA-0086:** PA-0086(2), "every per-unit handler contains its own failures
  and reports them (per connection, per plugin, per run)", applies here, at the target
  boundary. `run_targets` deliberately re-raises after marking the run aborted, so a
  defect stays loud (PA-0106). PA-0086 is satisfied only if the layers below contain
  every expected external failure. This fix contains a probe with no response, but not
  every external failure: a dead or unreachable target (loud by design), a seam
  timeout, and a GET whose retry meets a refused connection after its payload crashed
  the app still end every remaining target. These are residuals (below).
- **BUG-0143 / PA-0149(2):** this report exists because PA-0149(2) forbade parking the
  failure again. That rule worked as intended: the failure was reproduced before it was
  set aside.
- **BUG-0039 / PA-0046:** the senders must behave consistently. It covered redirects
  only, not error handling.

## Prior-preventive-action failure analysis
- **PA-0137(1)** says a confirmation mechanism maps "every expected failure of the
  external work it depends on" to no verdict. The wording is general, but it was
  applied and enforced for the browser only: its tests are all M6 tests, and nothing
  checked any other mechanism. **Too narrow in application, and not enforced beyond its
  first instance.**
- **PA-0137(4)** (the probe is the unit) could not be met for HTTP as the code stands.
  The deviation and its reasons are recorded above, not hidden.
- **PA-0138(3)** requires a rule about a shared primitive to be "swept across every
  caller of that primitive, not along the path its bug came from". The sweep after
  BUG-0137/0138 covered navigation waits. The HTTP send, which every non-browser
  mechanism depends on, was not treated as a primitive of PA-0137, so it was never
  swept. **Not followed: the primitive was chosen from the bug's path, the exact failure
  the rule warns against. It had no structural guard that would have caught that.**
- **PA-0046:** the senders' behaviour was made consistent for redirects only. Error
  handling diverged across three copies with no owner. **Too narrow.**

## Preventive action
PA-0153 (`docs/PREVENTIVE_ACTIONS.md`), strengthening PA-0137 and PA-0138. Each item is
enforced by a test, which is the failure mode of its predecessors:
1. A probe that gets no response is `ProbeUnobserved`, classified in one place (SP-34);
   the oracle makes it no verdict, never a negative and never the end of the run.
2. Every sender that issues HTTP itself is listed with its contract; an AST guard fails
   on a new one.
3. **Every default mechanism is run against a sender with no responses and a stopped
   out-of-band listener;** none may raise or return a negative (a structural guard
   over `default_strategies()`; it reaches 28 of 31; the other 3 need a browser or a
   coverage source and refuse before sending).
4. A hand-written HTTP response that closes its connection says `Connection: close`.

**PA-0002 sweep.**
- **Probe senders that issue HTTP themselves:**
  - `RequestsProbeSender` and `SeamProbeSender`: fixed.
  - `greybox.run.RequestsCorrelatingSender`: it records every request error as a
    status-0 attempt with the error text. M10 confirms from coverage and DB faults, but
    the run's advisory screening also reads that status-0 attempt. Its error text is
    `str(exc)`, which can carry the probe URL into the run's own attempt rows (the
    store already holds those probes). It is left as is; that contract is recorded
    in the guard.
  - `labgen/identifier_sqli_oracle.default_http_runner` and
    `tools/blind_sqli_fuzzer.RequestsSender` already handle `RequestException`.
  - The `auto` and oracle wrappers delegate to an inner sender.
- **Sends outside the oracle:**
  - the pipeline's baseline: fixed;
  - `Oracle._restore`: already contained;
  - `mutation/livefilter.HttpFilter` (`mutate-run`): a probe with no response now
    raises `ProbeUnobserved` instead of `requests.ConnectionError`. It still ends that
    command, as before. Residual.
- **Hand-written responses:**
  - fixed: the Go twin, the proxy's 501;
  - already correct: the proxy's 502;
  - not affected: the PHP twin, which uses PHP's own `header()`;
  - test-only: the CircleFeed responder, whose client sends `Connection: close`.

  No other hand-written status line exists in `fuzzlab/` or `lab/`.

**Residuals** (recorded, not fixed here):
- **Seam timeouts still raise** and end the run. Mapping them needs a timing contract
  for the seam: its successful probes are timed inside the transport, while a wall
  clock around the send includes logins and lock waits. A first attempt here gave two
  timed-out delay probes an unequal "delay", which can confirm timing SQLi falsely; it
  was withdrawn after review.
- **Status-0 timeout probes** in the anonymous sender are read as an ordinary response
  by non-timing strategies (a possible negative). This predates this fix.
- **The intercepting proxy** closes its client connection after every response, but
  forwards the upstream response's own `Connection` semantics unchanged. Proposed fix:
  rewrite the forwarded head to `Connection: close`. That is a PROXY design decision
  (default-off, lab-only).
- **The probe as the unit for HTTP strategies** (above).
- **`run_targets` ends every remaining target** on a failure that stays loud: a dead or
  unreachable target, a seam timeout, or a retry that meets a refused connection
  after the payload crashed the app. Failing loudly is deliberate for a dead target.
  Recording that target as failed and going on to the next one (PA-0086(2)) is a
  harness design decision, not made here.

## Review
Two independent reviewers (correctness and consumers; accuracy and adequacy) reviewed
the first version (local commit bd36ff2, never pushed). That version was implemented
before its change-control entries were reviewed, a breach of the pre-change gate.
- Reviewer A agreed, with should-fix findings.
- Reviewer B disagreed: the probe-vs-mechanism unit, unenforced PA-0153(3), and
  uncontained escape paths.

Every finding was addressed in the second version, as described above, or recorded as
a residual. A seam timeout change that opened a false-confirmation path was withdrawn.

Round 2 (commit 422ebaf, unpushed): both reviewers agreed, and both raised should-fix
items. They are addressed in this version:
- the retry is counted and narrowed to "no response" (A);
- a copy login or liveness check with no response leaves no half-made copy (A);
- the structural guard names its three exemptions instead of a ratio, and checks
  every listener user with the listener stopped (B);
- the Go twin keeps its original header order, so the full split stays realistic (B;
  this reverses round 1's suggestion to put `Connection: close` first);
- the records were corrected where they overclaimed (B: the retry is
  anonymous-sender only, PA-0086 is not fully met, the real-app ordering is
  inferred).

Nits kept as they are, with reasons:
- a stopped listener is reported as "unplaceable" (no verdict, with its reason);
- an unobserved arm gets reward 0 under the bandit, like every other inconclusive arm;
- the header breaker's note is also set when a send was refused before it went out
  (OutOfScope, BudgetExceeded). Nothing catches those, so the run ends anyway.
