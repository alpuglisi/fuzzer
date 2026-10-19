# BUG-0507 — Path variation took sibling routes and files for a parameter, and missed a segment the app built from an empty variable

- Date: 2026-10-19
- Status: fixed (CC-CORE-0062)
- Severity: medium. On Juice Shop every crawl-fed run imported and probed false
  endpoints (`/api/{api}`, `/rest/{rest}`, `/rest/admin/{admin}`, `/ftp/{ftp}`,
  `/rest/web3/{web3}`): wasted requests, payloads sent to routes that are not
  parameters, and false endpoints in the store. Two real parameters
  (`/rest/track-order/{id}`, `/rest/basket/{id}`) were found only when another rule
  happened to fire.

## Description
`core.pathtemplate` (CC-CORE-0060, FR-CORE-503) turned a run's crawled URLs into path
templates by **variation**: among URLs of one origin that agree on every segment but
one, a position (never the first) holding at least two distinct values is a parameter.

Measured on Juice Shop's spider and disco crawls (2026-10-19):

1. **Sibling routes.** `/api/Cards` and `/api/Challenges` became `/api/{api}`;
   `/rest/admin/application-version` and `/application-configuration` became
   `/rest/admin/{admin}`; `/rest/languages`, `/rest/memories`, … became `/rest/{rest}`.
   They are distinct routes. Every one of those names is hard-coded in the app's bundle
   (`this.host + '/application-version'`); a parameter's values come from data.
2. **Files.** A directory listing's `/ftp/legal.md`, `/ftp/acquisitions.md` and
   `/ftp/incident-support.kdbx` became `/ftp/{ftp}`: `FILE_EXTENSIONS` named server
   pages and assets only, so a document's name counted as a value.
3. **Empty-variable segments.** `/rest/track-order/undefined` and `/rest/basket/NaN` are
   URLs the app built from a variable that was empty. JavaScript writes `undefined` or
   `NaN` for it, so the segment is a parameter by construction. Shape evidence did not
   know that.
4. **Two templates for one parameter.** Disco saw `/rest/track-order/undefined` and
   `/rest/track-order/fuzzlab` (its route seed). Shape gave `{id}` and variation gave
   `{track_order}`: one parameter, two endpoints.

The streaming lab, the only lab the rule was designed on, holds none of these shapes.
Its varying values (`matthewpets`, `mr.robot`) are usernames, absent from its scripts.

## Where encountered
The Juice Shop measurement (CC-LAB-0317) listed the false templates. The owner asked
for the path variation rules to be fixed after the discovery gaps (2026-10-19).

## What it caused to fail
- Crawl-fed `auto` on Juice Shop: four or five false path endpoints probed in every run.
- The store's endpoint inventory (false `path` parameters).
- Discovery of `/rest/basket/{id}` when it is seen only with `NaN`.

## What the bug was identified to be
A classification rule (route or value) used one kind of evidence: variation. It never
asked for the evidence that separates the confusable alternative, sibling routes, and
it was measured only on an app where that alternative does not occur.

## Root cause analysis (Five Whys)
1. Why `/api/{api}`? Two values varied in one position, which the rule takes as
   sufficient.
2. Why is variation sufficient? The rule was designed from the streaming lab's URLs,
   where every variation was data.
3. Why only that lab? PA-0501(1) asks for one application its author did not write,
   and streaming satisfied it. It held no sibling routes, so the rule's negative case
   was never exercised.
4. Why was the negative case not known? It was known. `disco.synth.template_paths`
   fixed the same defect a day earlier (BUG-0501: "an API's resource names collapsed
   into one endpoint, measured on Juice Shop") by requiring positive data evidence. The
   new module was written as a second implementation of the same decision, without
   reading the first.
5. Why could a second implementation be written unnoticed? Path templating had no
   shared owner. SP-45 was registered for the new module alone, and nothing tied it to
   synth's rule.
   **Root cause:** a decision with a known confusable alternative was implemented a
   second time, without the evidence the first implementation had been fixed to need,
   and measured only where the alternative cannot occur.

## Corrective action (CC-CORE-0062, CC-CRAWL-0046, CC-AUD-0049)
- **One decision, both kinds of evidence:** `core.pathtemplate.varying_is_parameter`
  (SP-45). A varying position is a parameter when at least `min_distinct` of its
  values are not segments the app's code names. When response data is known, every
  such value must also be data.
  - `path_templates` (both importers) decides through it with code evidence.
  - `disco.synth.template_paths` decides through it with its data evidence and
    `SLUG_MIN_DISTINCT`, so its behavior is unchanged.
- **Code evidence** (`code_segments`, FR-CRAWL-28): the path segments a script holds
  (one linear regex; identifier-like segments never kept; capped). The spider records
  them in a `script_segments` table when it scans a script. Disco writes
  `script_segments.json` beside its action log from the full bodies it reads. The
  capture truncates bodies at 200,000 characters, and 556 of Juice Shop's 1,954
  scripts were truncated, so the capture alone is not enough. Both importers pass
  them on. An older crawl without them imports as before.
- **Placeholders** (`JS_PLACEHOLDERS`: `undefined`, `null`, `NaN`, `Infinity`,
  `[object Object]`) are shape evidence: named `id`.
- **Files:** `FILE_EXTENSIONS` gains documents, data, configuration, backups and
  archives (`md`, `yml`, `kdbx`, `bak`, `sql`, `tar`, …).
- **One template per position:** the first evidence names it (shape before variation).

Measured offline on the Juice Shop crawls' URLs with the code segments of its full
bundle:
- spider: 5 templates → 2 (`/rest/basket/{id}`, `/rest/track-order/{id}`);
- disco: 8 → 4 (`/rest/products/{id}/reviews`, `/api/Products/{id}`,
  `/rest/track-order/{id}`, and `{track_order}` before the one-per-position fix).

On the streaming lab, the full bundle holds `live`, `username` and `play`, and never a
username, so its templates stay.

## Recurrence review
- **BUG-0501 / PA-0501:** the same defect (resource names collapsed into one endpoint)
  in `disco.synth`, fixed with positive data evidence. This bug is its recurrence in a
  second implementation of the same decision.
- **BUG-0505 / PA-0505(2)** (the same day): two tools discovering the same surface
  without a shared mechanism. Path templating had two owners.
- F-049 (lab-fitting): the variation rule fit the one lab it was designed on.

## Prior-preventive-action failure analysis
- **PA-0501(1) was too weak for a classification rule.** "Run against one application
  its author did not write" was met by an application holding only positive cases. It
  says nothing about the confusable alternative.
- **PA-0505(2) came too late, and was too narrow.** Written the same day for crawlers'
  discovery mechanisms, it did not name a decision inside an importer. SP-45 was
  registered without looking for an existing implementation (synth's), so the shared
  primitives table, the place that should have caught it, recorded the duplicate as a
  new primitive.

## Preventive action
PA-0507 (strengthens PA-0501(1) and PA-0505(2)):
1. A rule that classifies (route or value, file or value, page or asset) names the
   evidence that separates its confusable alternative. It is measured on an
   application where that alternative occurs, before it ships.
2. Before a mechanism is registered as a new shared primitive, the codebase is searched
   for an existing implementation of the same decision (its docstrings, its bug
   records). One found is made the owner, or both are made to decide through one owner,
   in the same change.

The PA-0002 sweep (by decision, every implementation):
- `disco.synth.template_paths`: now decides through the owner.
- `core.pathtemplate.path_templates`: the owner's other caller.
- `labels.contract._check_path_template`: validates an answer key's template, and
  decides nothing about crawled values. Not this class.
- `tools.fetcher.rule_template_parameters`: an auditor rule about server-side template
  parameters, a different meaning of "template". Not this class.
