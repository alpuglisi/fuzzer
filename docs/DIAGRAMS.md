# Data-flow and sequence diagrams

fuzzlab draws two kinds of diagram for every `fuzzlab auto` run, from one persisted
evidence model (FR-CORE-505, FR-FUZZ-60, FR-AUD-28, FR-UI-510/511):

- **Data flow**: who talks to whom. Actors (the browser, the automated explorer),
  the target application, its origins and their interfaces, and external hosts the
  browser asked for. The tool's own traffic is an optional overlay.
- **Sequences**: the order of events in one scope. A scope is a test, a captured
  explorer workflow, the spider's crawl, the traffic through the intercepting proxy,
  one exchange, or a finding.

## Running it

The trace is on by default; `--no-trace` turns it off.

```
fuzzlab auto --base-url http://127.0.0.1:3000 --spider-db crawl.db --points crawl --authorized
fuzzlab auto --base-url http://127.0.0.1:3000 --disco-run out/ --points crawl --authorized
fuzzlab proxy --record --authorized     # browser traffic through the proxy, live
fuzzlab disco capture --start http://127.0.0.1:3000 --out run/ --record --authorized   # the capture, live
```

With `--store`/`--record`, a capture is its own run (`disco`): each exchange and explorer
action is in the store about 0.3 s (p95) after it is captured, and the page shows it at its
next poll when that store is the one the web has open. When the capture ends, its
directory is imported into the run (refused hosts with their final counts, old-log
actions, anything the live passes could not write), then the run's end is recorded.
Importing the directory into that run again adds nothing; `fuzzlab auto --disco-run`
imports it into its own run.

The web proxy records the same way when it has a store.

- **From a finding:** on the **Findings** page, each finding's **Diagram** link opens
  `/diagrams?run=<run>&finding=<id>`: that run, the finding's own sequence, and the data
  flow filtered to it, with the testing overlay on (a finding's own flow is the tool's).
  The run stays selected while the run writes, even when it is older than the 200 runs
  the list shows, until you choose another run; the scope and the finding filter stay
  until you choose another run, scope or finding. A finding without a diagram says why:
  its run has no trace (recorded before diagrams, or with `--no-trace`), its trace event
  was not recorded, or the event names no test or no interface. The page refuses a
  malformed link with 400, and names a link that does not hold (another run's finding,
  an unknown one) without applying it.

Then:

- **Web:** `fuzzlab web`, then **Diagrams**. The page refreshes while a run writes,
  checking every 3 s (`diagram_poll_ms`).
- **CLI** (read-only; no traffic):

```
fuzzlab diagram --run latest --format status        # completeness, dropped events, lag
fuzzlab diagram --run 7 --format json --out run7.json
fuzzlab diagram --run 7 --format mermaid-flow --overlay
fuzzlab diagram --run 7 --format scopes             # the sequence scopes
fuzzlab diagram --run 7 --format mermaid-seq --scope finding:3
fuzzlab diagram --run 7 --rebuild                   # replay the events into the model
```

## How the model works

### Events

Every producer records what it actually saw or did as one `trace_event` row:

- discovery import: one event per spider row and per capture record, plus explorer
  actions and refused external hosts;
- the pipeline: every send, each test's start and end, each strategy run's outcome,
  and each finding; the browser (M6) confirmation's steps per visit (`browser.step`) and
  each out-of-band (M8) wait's result (`oob.wait`), FR-FUZZ-62;
- the disco capture itself, live, when given a store (FR-CRAWL-30);
- the intercepting proxy: one event per recorded in-scope flow, written as soon as the
  flow is stored, and the run's end when the proxy stops (`proxy/history.py`,
  FR-PROXY-13).

Events are append-only. Each carries a version and a key that is unique within its
run, so a repeated delivery or a re-import adds nothing. Bodies are redacted twice:
by the producer, and again at the write (`trace.scrub_event`, PA-0100). A URL loses
sensitive and identifier-like query values, userinfo, `;jsessionid=`-style parameters,
token fragments (`#access_token=`) and token-shaped path segments (shown `{redacted}`,
grouped as `{id}`); only parameter names, never values, are kept for what the target
or the browser sent.

### The diagram model

`dg_entity`, `dg_flow` and `dg_evidence` are derived from the events:

- incrementally, as each batch is written;
- or completely, with `--rebuild`.

Reduction is idempotent and does not depend on event order:

- first and last seen are taken as the minimum and maximum;
- attributes are sets, so conflicting observations (two statuses, two auth
  contexts) are both kept;
- observation counts are counted from evidence links, never incremented.

### Correlation

Correlation is explicit and is never inferred from timestamps:

- a test id for every confirmation;
- a strategy scope for each strategy run, whose exchange keys a finding cites
  exactly;
- the explorer's action id, carried on its requests through the capture proxy;
- the spider's `found_from`: the page whose load queued a page, carried in the crawl
  queue entry (FR-CRAWL-29);
- a follow-up's parent exchange.

Capture records with no action id are listed as uncorrelated.

### Knowledge levels

- **Observed:** directly supported by captured traffic, a browser event, a tool
  exchange or explicit configuration.
- **Inferred:** supported indirectly; the basis is shown. For example, path segments
  grouped as `{id}` because they are id-shaped.
- **Unknown:** not established.

An interface whose path holds a template segment (`{id}`) is drawn *inferred*: the
requests to it were observed, the grouping is not. The spider's own page loads come from
a "Spider (crawler, tool)" actor, never the browser. A request learnt in the browser and
blocked before sending is drawn dashed, "blocked, never sent"; a host the scope refused,
"refused, never sent".

Each origin states that its internals are unknown. No server-side component, store or
internal call is ever drawn. Trust zones between origins are unknown too: a host name
is not evidence.

### Coverage

Each interface counts six states separately, each in its own unit:

- *discovered*: observations of it (crawl rows, capture records, proxied flows);
- *captured*: browser traffic to it that was answered (disco's capture or the
  intercepting proxy);
- *scheduled*: tests on it;
- *executed*: those tests' own sends, answered or not (a follow-up, a restore or a retry
  is part of a send, not one), and an M6 visit's store and observe loads;
- *evaluated*: strategy runs that reached a verdict on the test's candidate (a run that
  does not decide it, and did not confirm it, reached none);
- *finding*: findings.

An interface with no finding shows what was tested; it is never presented as "secure".

### Roles of a send

A send is labelled `baseline`, `mutation`, `control`, `follow-up` or `restore` only
where the code knows which it is:

- the pipeline's fingerprint baseline;
- a differential's base value, benign variant and payload;
- a timing check's baseline samples and its delays;
- the SQL error check's payloads and controls;
- a PRG restore;
- a sender's earlier try of an exchange (`retry`, a re-send after a reset): its own
  exchange, with `parent` the exchange it retried and `attempt` its number. The
  exchange carries `attempts`, its count of tries (FR-FUZZ-61).

Every other send is `probe`: its strategy does not say. Each send names the identity
it went out as: the run's account, and for the cross-account check the peer account and
`anonymous`.

### Responses that never came

- A missing response is drawn as a lost arrow (Mermaid `-x`), labelled `timeout`,
  `unobserved` (connection reset or cut off), `not_sent` (refused before sending) or
  `error`. A retry's missing response is drawn lost too.
- A PRG follow-up is recorded whenever it was sent: answered by another redirect,
  timed out or unobserved included (BUG-0510).
- A request the browser made inside the tool's write-blocking window (FR-CRAWL-26) is
  marked *blocked, never sent*.
- A finding is a tool record (an evaluator note), never a target response.

## Exports

- **JSON** (`fuzzlab.diagram/1`): the whole model, with each entity's and flow's
  evidence keys, the sequence scopes, and the completeness status. Mermaid cannot carry
  most of this metadata; the JSON is the full record.
- **Mermaid:** a `flowchart` for the data flow and a `sequenceDiagram` per scope. Every
  label is reduced to a safe alphabet, with numeric entities for everything else
  (`diagram.mermaid_text`). Captured text can never become diagram syntax.

## Completeness

`status` (on the page, and with `--format status`) reports:

- the run's state: `complete`, `partial` or `empty`, while the run is live too (the
  counters are written at least every second);
- whether a run end was recorded, and how the run ended;
- the recorder's written, dropped and duplicate events, forced flushes (queue
  pressure) and maximum lag;
- the gaps listed below.

A run that stopped, or a batch that could not be written, shows as **partial**.

## Browser and out-of-band confirmations

An M6 visit is drawn under "Browser driven by the tool (M6)":

- the store and the observe navigation, each with its status, a lost arrow, or "not
  sent: the tool refused to place it";
- the first refused request: "refused by the guard, never sent";
- "load fired" or "load did not fire (superseded …)";
- "payload executed: the sentinel fired (+N ms after load)", or "at about load time" when
  the two events are under 100 ms apart;
- "N page request(s) answered, N failed, N refused";
- the result: executed, "the sentinel did not fire within N ms", "not observed: …" or
  "not placed: …".

A strategy run that does not decide its candidate (the candidate's `decided_by` names
another mechanism, FR-AUD-30) is drawn "(does not decide this candidate)"; a confirmation
always counts, whoever made it.

An out-of-band wait is drawn as "callback received from <address>" or "no callback
within N s". A step that did not happen is never drawn as a reply or as executed. Stamps
are when Python received the driver's event, not the browser's clock. Per visit, what the
server received is the API stores + answered + failed + the redirect hops the guard
fetched itself (the documented gap), checked against the server's own count through
`run_auto` (PA-0520).

## Known limits

- The M6 browser's page requests are counted per visit, not drawn one by one; the
  browser guard's own redirect-hop fetches are not counted (the server gets one request
  more per hop); in-scope WebSockets, popups and Chromium's background traffic are not
  traced. An M8 callback after its window, and the in-band marker checks' callbacks, are
  not traced.
- Each try is recorded by the sender where it happens (FR-FUZZ-61). The authenticated
  sender never re-sends, and records a failed try only when it reached the network; an
  error after the response arrived (the store write or the session's `observe`) is not
  recorded as a try.
- A spider DB from before FR-CRAWL-29 records no times and no initiator for a page,
  so its events have no first or last seen time. A newer one records when each page's
  load began and which page's load queued it (none for the start URL and the
  well-known files). Links found in a load that redirected are attributed to the URL
  loaded, not to the landing. The spider's sequence stays in crawl order.
- WebSocket messages appear only from a disco capture. The pipeline sends none.
- The `proxy` sequence draws Browser → Intercepting proxy → origin per flow, ordered by
  the time the proxy received each request. An edited request is noted on the forward;
  a missing response is a lost arrow. Messages the operator dropped and repeater
  replays are not recorded as flows, so they are not traced.
- The proxy's trace costs about 1 ms per flow on its event-loop thread (p95 up to
  13 ms; measured, FR-PROXY-13). `HistoryWriter(trace=False)` turns it off; there is no
  command-line switch for it yet.
- A sequence for one proxied flow's key (`proxy:flow:<n>`) is not offered; the `proxy`
  scope shows every flow.
- External hosts come from both layers that refuse: the capture proxy and the browser
  guard (`explore.json`), counted by hostname; a host refused by both shows both counts.
  A capture that crashed has no `explore.json`, so its guard refusals are missing. The
  browser's own background traffic, such as autofill services, is included and labelled
  as possibly the browser's.
- A live disco run that was killed (SIGTERM/SIGKILL) has no end recorded and reads
  partial; a batch the store refused stays counted as dropped even after the final
  import wrote it.

## Measured cost

See `scripts/measure_diagrams.py`, and CC-CORE-0063's effectiveness for the recorded
numbers.
