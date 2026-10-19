# BUG-0506 — The spider learnt a form's request only by sending it: Juice Shop's login SQL injection was never probed

- Date: 2026-10-19
- Status: fixed (CC-CRAWL-0045)
- Severity: high for discovery. Every endpoint reached only through an SPA form was
  missing from a default crawl, including the most common injection point there is: a
  login form's JSON body. Juice Shop's `POST /rest/user/login` `email` SQL injection
  (the answer key's first entry) was found from the ground truth and never from a
  crawl.

## Description
Measured on Juice Shop v20.3.0 (CC-LAB-0317, 2026-10-19). Spider-fed `auto` found 5 of
15 answer-key entries, and not `/rest/user/login` `email` (sqli). The spider DB held no
row for `/rest/user/login`. The spider records a request body from two sources only:

- **passive capture** (FR-CRAWL-13): a request the page makes by itself; and
- **SPA form submission** (`--submit-spa-forms`): off by default, because a submission
  changes lab state.

A login form's request is made only when the form is submitted. So in a default crawl,
the request's shape (`{"email": …, "password": …}` as JSON) was never seen, and no point
existed to probe.

The reveal window (FR-CRAWL-16) already did half of the job. It blocks every write a
reveal click or G1 interaction makes (W2), and logs "blocked a browser POST". But it
threw the blocked request away: its method, URL and body were never recorded.

## Where encountered
The owner asked why the spider missed the login SQL injection, and for that gap to be
remediated (2026-10-19).

## What it caused to fail
- Crawl-fed discovery of every SPA-form endpoint in a default crawl: login, contact,
  feedback, search-by-button.
- Crawl-fed detection on those endpoints: the Juice Shop login SQL injection.
- The shapes of writes made by menus and dialogs, which the reveal window blocked.

## What the bug was identified to be
Learning a request's shape was coupled to sending it. With sending off (the safe
default), discovery of what sending would have shown was off too, although the crawler
already had a window that stops a write in the browser.

## Root cause analysis (Five Whys)
1. Why was the SQL injection not found? No point for `email` on `/rest/user/login`
   existed in the crawl's import.
2. Why no point? The spider never saw the request: it is made only on submit, and
   submission is off by default.
3. Why is submission off? It sends the request, and a request changes lab state. That
   is correct (D11).
4. Why did off mean "not discovered"? The only path to a form's request shape was the
   request being sent. The window that blocks writes in the browser (W2) existed, but
   it was built to *prevent* writes, and discarded what it blocked.
5. Why was that not seen? The spider's capture was measured with submission on. The
   default configuration's coverage of form endpoints was never compared with an
   answer key until this run.
   **Root cause:** a safety gate implemented as "do not do the action" rather than "do
   the action without its effect". The gate removed discovery along with the effect.

## Corrective action (CC-CRAWL-0045)
- **Dry submission** (FR-CRAWL-26, `--no-dry-submit` to turn it off). With
  `--submit-spa-forms` not given (Playwright engine, SPA routes on), each eligible form
  on an SPA route (`spa.form_refusal`, once per signature, `spa.MAX_SUBMISSIONS`) is
  filled with the fillers and its vetted button clicked inside the write-blocking
  window. The window is never lifted. The write the click makes is recorded
  (`_record_dry`, source `dry-submit`, through `record_request`'s redaction) and
  aborted. The server receives nothing.
- **Session safety.** The app's own code still runs, and an aborted request is a
  failed one to it. Juice Shop's login clears its token on any error, and the fixture's
  profile form clears its cookie before any request. So:
  - a password form is dry-submitted only in a fresh unauthenticated context (as real
    submission is);
  - any other form's click is bracketed by a client-state snapshot and rollback
    (cookies, `localStorage`, `sessionStorage`) inside the window;
  - an authenticated crawl then runs the client-side session check. A loss stops dry
    submission and is reported. This was caught before commit, after a measurement
    crawl had been started on the unsafe code (F-073).
- **Blocked writes recorded** (the sweep). A write any non-query window aborts (a
  reveal or G1 click) is recorded with source `reveal-blocked`. Neither source records
  while a vetted submission has lifted the window. Neither records in a seed or probe
  window (FR-CRAWL-17: its URLs carry markers).
- Counters (`forms_dry_submitted`, `requests_captured_dry`,
  `requests_captured_blocked`) count stored rows, never clicks (PA-0502). The summary
  reports them.

## Recurrence review
- **BUG-0503 / PA-0503(1)**: a URL whose evidence implies a write reaches the target
  only through the gated paths that know its method (form submission, observed browser
  requests). That rule is right, and this bug is its other half. With the gated path
  off by default, those endpoints were never discovered at all.
- No earlier bug has this root cause: a gate that discards discovery along with the
  effect. The closest are the FR-CRAWL-17 seed windows, which record that a write was
  blocked (`spa-query-writes`) but not its shape. They stay so, by design: their URLs
  carry probe markers.

## Prior-preventive-action failure analysis
PA-0503 was not a failed prevention of this bug: it addresses the safety half (what may
be sent) and says nothing about discovery. It is extended, not replaced: PA-0506 adds
that the gated path discovers by default without sending.

## Preventive action
PA-0506:
1. A safety gate withholds an action's effect, not its discovery. Where a request's
   shape can be learnt without sending it (the window blocks and records it),
   discovery does that by default. A gate that discards what it blocked is a defect.
2. A dry action leaves no trace: the server receives nothing, and client state the
   app's code changed during it is rolled back before the crawl goes on. A
   session-bearing context is checked after it (fail closed).

The PA-0002 sweep:
- The reveal window and G1: blocked writes are now recorded (`reveal-blocked`).
- FR-CRAWL-17 seed and probe windows: not recorded (markers; see above).
- Disco: it submits forms for real (D70), so a form's request is captured. A request
  its guard refuses is destructive, and is never a point (FR-FUZZ-47). Not applicable.
- `fuzzlab/session` login discovery: it reads the login form and script statically
  (SP-44), and never needed a send to learn the shape.
