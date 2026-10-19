# BUG-0505 — The disco harvest explored a catch-all's copy of the app as a second app, and never loaded the routes the app's scripts declare

- Date: 2026-10-19
- Status: fixed (CC-CRAWL-0044)
- Severity: medium. On Juice Shop, half of disco's actions went to a second copy of the
  app, and the resulting points gave a duplicate finding (a false positive in the
  score). Two answer-key routes were never reached: `#/track-result` has no link, and
  `/profile` needs a session. Nothing outside `fuzzlab/disco` was affected.

## Description
Measured on Juice Shop v20.3.0 (2026-10-19, CC-LAB-0317: disco-fed `auto` scored tp=4
fp=1 fn=11; the spider-fed run scored tp=5 fp=0):

1. **Alias documents.** The harvest loads the origin's well-known files
   (`/robots.txt`, `/sitemap.xml`). Juice Shop has no sitemap. Its server answers any
   unknown path with the app's shell (an SPA fallback route), so `/sitemap.xml` loaded
   the whole app, and Angular routed it to `/sitemap.xml#/`. `state_fingerprint` keys a
   state on its route, and the route includes the document path. So every state under
   `/sitemap.xml#/…` was new. The explorer explored the app a second time there, and
   `#/search` under `/sitemap.xml` became a second endpoint, scored as a false positive.
2. **No script routes.** The spider reads the routes and route-query names an app's
   scripts declare (`spa.scan_script`: FR-CRAWL-12, FR-CRAWL-17). Disco never did. Its
   harvest followed only links in rendered documents and responses. Juice Shop's
   `#/track-result?id=` is reached only from code: `navigate(['/track-result'],
   {queryParams: {id}})` after an order is placed. No link names it, so disco never
   loaded it, and its DOM XSS was never probed. The spider found it.
3. **Loads unlogged.** A harvest load was not written to `actions.jsonl`. A hash
   route's query never reaches the server, so the importer (which reads page URLs from
   that log) could not see a seed's query names even when one was loaded.

## Where encountered
The owner asked to run the tools on the Juice Shop lab (CC-LAB-0317). Disco-fed scoring
gave fp=1 and missed `#/track-result`. The owner then asked for the algorithmic gap to
be remediated, not worked around by running disco logged in (F-072).

## What it caused to fail
- Disco's budget: about half of its 600 actions went to the duplicate copy.
- The disco-fed score: one false positive (the duplicate `#/search` route), and a
  missed DOM XSS (`#/track-result` `id`).
- Any app whose server has a catch-all route (most SPA servers) and declares routes
  only in its bundle.

## What the bug was identified to be
Disco identified a state by the address it was reached at, not by what the document
is. The same document under two paths was two apps. Its harvest also lacked a
discovery mechanism the other crawler already had: routes declared in scripts.

## Root cause analysis (Five Whys)
1. Why a duplicate finding? `/sitemap.xml#/search` was imported as an endpoint beside
   `/#/search`.
2. Why was it explored? Its states were new: the fingerprint holds the document path,
   and nothing compared the document with one already loaded.
3. Why did nothing compare documents? The harvest assumed one URL is one document. A
   catch-all breaks that, and the disco fixture had no catch-all.
4. Why was `#/track-result` never loaded? Disco's harvest had no route scanner. The
   spider gained one in forms phase 3, and the two tools' discovery mechanisms were
   never compared when disco was built (D70).
5. Why was the gap not caught when disco replaced the spider as the default discovery
   path (FR-CRAWL-21)? Its acceptance compared answer-key inputs reached on a fixture
   and Juice Shop, not each discovery mechanism the spider has.
   **Root cause:** a discovery tool's identity of "what is new" used the address, not
   the content. And when one tool replaced another, its mechanisms were not reconciled
   with the old tool's.

## Corrective action (CC-CRAWL-0044)
- **Alias documents** (`Explorer._document_first`, `_alias_state`). The sha256 of each
  HTML document's body is kept with the path it was first loaded at. A harvest load
  whose body was first loaded under another path is an alias, and is not explored, if
  either:
  - the app routes by fragment (its URL or one of its links holds `#/`; a hash router
    never reads the path), or
  - its rendered state, read as if at the first path, is already a known state (a soft
    404).

  A history-mode route served from the same shell renders a view of its own, so it is
  still explored. A body-only rule would have broken those (caught in review, F-073).
  Counted as `harvest_aliases`.
- **Script routes** (`Explorer._script_routes`). Every JavaScript response body is
  read with `spa.scan_script`, the spider's scanner (SP-47). Each OK route (by
  `spa.classify_route`), and each route-query seed that passes
  `spa.query_url_refusal`, is queued for the harvest in the page's routing mode. That
  mode is decided as the spider decides it: a `#/` in the page URL or in one of its
  links. Routes go in a queue loaded before the links (`harvest_routes`). On Juice
  Shop the 695 linked URLs starved them otherwise (measured: harvest 0 states from
  routes).
- **Load lines.** A harvest load of a route URL writes an `actions.jsonl` line of kind
  `load`, with every key an action line has (`_log_load`). The importer gives its query
  as `fragment` parameters.
- Fixture (`tests/_disco_app.py`) gains:
  - a route table entry and `navigate("/track?id=")` behind a key nothing presses, with
    `#/track?id=` fetching `/api/track`;
  - a catch-all serving the shell for any other non-API GET;
  - a `#/` link.

## Recurrence review
- **BUG-0502 / PA-0502(3)** (the same component, the day before): "element identity
  carries no context of where the element was seen". This bug is the same class one
  level up: the *state's* identity carried the document's path, the address it was
  reached at, so one document was two apps.
- **BUG-0039 / PA-0041:** "a setting adopted in one implementation of a seam is
  applied to every other implementation". Defect 2 is that class: two discovery tools,
  one with a route scanner, the other without.

## Prior-preventive-action failure analysis
- **PA-0502(3) was too narrow.** It named element identity only. The rule behind it
  (identity is the content, never the address it was reached at) was not stated for
  states or documents, so the state fingerprint kept the document path, and no test
  loaded one document under two paths.
- **PA-0041 was too narrow and not enforced.** It is phrased for transport settings of
  a sender seam, and its enforcement line is "none". When disco replaced the spider as
  the default discovery path (FR-CRAWL-21), nothing required its discovery mechanisms
  to be compared with the spider's.

## Preventive action
PA-0505 (strengthens PA-0502(3) and PA-0041):
1. A discovery mechanism identifies what it has seen by its content, never by the
   address it was reached at: the same document under two addresses is one document,
   unless it renders differently there.
2. Two tools that discover the same surface use the same mechanism for each kind of
   evidence (a shared owner in `docs/SHARED_PRIMITIVES.md`). A mechanism one has and
   the other lacks is either added to the other in the same change or recorded as a
   known gap.

The PA-0002 sweep:
- Disco's other identities: an element's signature carries no route (PA-0502). Steps
  are keyed by route. A route is the identity of a view, and stays.
- The spider: it de-duplicates pages by `spa.visit_key` (URL). A catch-all there costs
  one load per linked URL, and its route pages are queued only from scanned routes. It
  is not changed. The spider is deprecated (D70), and its import already lands on the
  app's own routes.
- Discovery mechanisms the spider has that disco did not:
  - the route scanner and route-query seeds: added here;
  - FR-CRAWL-17 probe loads (marker reflection of unpaired names): not added, recorded
    as a known gap in FR-CRAWL-27;
  - dry submission and blocked-write capture (FR-CRAWL-26): disco submits forms for
    real (D70), so a form's request is captured directly.
