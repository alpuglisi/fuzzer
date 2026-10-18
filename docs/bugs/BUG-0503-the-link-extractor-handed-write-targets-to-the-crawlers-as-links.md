# BUG-0503 — The shared link extractor handed write targets to both crawlers as links to GET

- Date: 2026-10-18
- Status: fixed before push (CC-CRAWL-0039); introduced by the unpushed 6a30ec9
  (CC-CRAWL-0038)
- Severity: high (safety). Both discovery tools would have sent GETs to URLs whose only
  evidence was a write: a POST form's `action`, a `formaction`, a `ping` beacon, and
  any path-like string literal in a script (`fetch('/api/after-close', {method:
  'POST'})`), outside every reveal/query window. Caught by `scripts/verify_change.py`;
  never pushed, never run against a lab other than the Security Crawl Maze.

## Description
`core/linkextract.py` (CC-CRAWL-0038) returned, as "links", every URL-valued HTML
attribute including `form@action`, `button/input@formaction`, `isindex@action` and
`a/area@ping`, and every path-like string in inline scripts and script responses
(`js_urls`). The spider queued them all for a GET; disco's harvest loaded them. The
spider's rendered engine also queued, as pages, the scripts, stylesheets and images the
browser had already loaded for the page (`/main.js` fetched three times).

## Where encountered
`verify_change --base` on 6a30ec9: 16 failures. Six forms-phase-4 tests saw
`/api/after-close`, `/api/review`, `/api/autosave` (POST-only fixture endpoints)
reach the server; the M6 import test saw `/api/order/confirm?ref=` GET; the bundle
test saw `/main.js` fetched three times; the rest were exact-order expectations the
known-file seeds changed and an unregistered base-URL function family.

## What it caused to fail
The project's write-safety contract (NFR-CRAWL-safe, FR-CRAWL-16 W2, FR-CRAWL-17 S1):
"a URL whose only evidence is a write never reaches the server".

## What the bug was identified to be
The extractor answered "what does this document mention?" while its callers ask "what
may I GET?". A submission target and a script string are mentions whose method is a
write or unknown.

## Root cause analysis (Five Whys)
1. Why did write endpoints get GETs? The extractor returned them and the crawlers GET
   whatever it returns.
2. Why did it return them? It was written from the HTML spec's list of URL-valued
   attributes, and a script heuristic, to maximise Crawl Maze coverage.
3. Why was the method not considered? The module doc left "scope and destructive-URL
   decisions" to the caller, and the caller's gates are about *where* (scope) and
   *what words* (destructive), not *which method the page uses*.
4. Why did no earlier rule stop it? The write-safety rules (W2, S1) are enforced by
   browser-window tests, not by a contract on any URL source feeding the queue.
5. Why was the Maze score trusted? It rewards GETting `js-post.found` / `js-delete.found`;
   the benchmark's goal (find every URL) and this project's (never write unasked) differ.
   **Root cause:** a URL source added to the crawl queue without its contract (every URL
   it returns is GET-safe) being stated or tested.

## Corrective action (CC-CRAWL-0039)
- `linkextract` returns no `action`, `formaction`, `ping`, and no script strings
  (`js_urls` removed; inline `<script>` text is not read). Its module doc states the
  contract. Forms reach a target only through the crawlers' gated submission paths;
  what a script requests is what the browser was seen to request.
- The rendered spider never re-fetches, as a page, a subresource the browser already
  requested in this crawl (one set shared by the workers).
- Tests: `tests/test_linkextract.py::test_a_submission_target_or_a_script_string_is_never_a_link`,
  `tests/test_spider_links.py::test_every_linked_resource_is_followed_and_the_gates_still_refuse`
  (shown to fail on 6a30ec9's extractor), `tests/test_spa_routes.py::test_hash_routes_are_read_from_the_bundle_and_crawled_as_pages`.

## Recurrence review
Prior bugs with the same class ("a discovery source reached the queue unchecked"):
BUG-0111 (destructive links followed; PA-0112/PA-0123 per-layer gates). Those gates ran
here and did their job; the gap is a different axis, the request *method* a URL's
source implies. Not a recurrence of BUG-0111's root cause; PA-0503 adds the missing axis.

## Preventive action
PA-0503 (`docs/PREVENTIVE_ACTIONS.md`). Sweep (PA-0002): every other reader of
`action` / `formaction` / `ping` in `fuzzlab/` is a refusal check or a gated
form-submission path (`disco.explore` denylist, `core.forms`, `fetcher`, `spa`,
`session.detect`, `browserlogin`); none queues a GET.
