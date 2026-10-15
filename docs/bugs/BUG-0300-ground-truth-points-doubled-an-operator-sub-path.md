# BUG-0300 — Ground-truth points doubled an operator base URL's sub-path

- Date: 2026-10-15
- Status: open — recorded and pinned; the corrective action is deferred to the owner of
  the locked `fuzzlab/harness/auto.py` and `fuzzlab/greybox/run.py` (CC-FUZZ-0300).
  Pinned by strict xfails (PA-0054(3)) in `tests/test_base_url_subpath_registry.py`.
- Severity: medium. A ground-truth run (`fuzzlab auto --points ground-truth`, or
  `greybox-run`) with a base URL carrying the app's path probes URLs that do not exist,
  and every case scores as missed. The run does not fail: it reports a recall of zero.
  Passing the origin as `--base-url` avoids it.

## Description
`fuzzlab.harness.auto.points_from_ground_truth(ground_truth, base_url)` builds every
point's URL as `base_url.rstrip("/") + path`. A ground-truth `url` is the full request
path (`/bWAPP/sqli_1.php`), so a base that carries the app's sub-path
(`http://127.0.0.1:8092/bWAPP/`) yields `http://127.0.0.1:8092/bWAPP/bWAPP/sqli_1.php`.
This contradicts PA-0113(1): "stored absolute paths join to the origin". There are
four join sites:
1. `auto.py:105` — server-rendered GET query, POST body and header points;
2. `auto.py:114` — DOM / client-only points (with a browser);
3. `auto.py:128-131` — stored-XSS points: both `url` and `store_url`;
4. `greybox/run.py:457-460` — `points_with_classes` delegates to (1)-(3), then builds its
   own `(base + path, method, param) -> vuln_class` lookup with the same join. A fix to
   `points_from_ground_truth` alone would leave every greybox point with no class.

## Where encountered
The design of the bWAPP and Juice Shop lab fixtures (design rev 2 §5.3, reviewer B2):
bWAPP is served under `/bWAPP/`, and its ground truth must be written with the full path
so that findings (`core.urls.to_path`) match it. Verified in-process on `cdde39f` in this
lane: the four bases `…/bWAPP/`, `…/bWAPP`, the origin, and `…/app/` give
`/bWAPP/bWAPP/sqli_1.php`, `/bWAPP/bWAPP/sqli_1.php`, `/bWAPP/sqli_1.php` and
`/app/bWAPP/sqli_1.php`.

## What it caused to fail
- **FR-FUZZ-41** (sub-path targets): it was built for crawl points only.
- **PA-0113(1)**, and FR-FUZZ-13's ground-truth points: the gt pass cannot use the
  operator's own sub-path base. Design §5.3 makes it pass the origin for that reason.
- Scoring would be wrong if a ground-truth url were written app-relative instead
  (`/sqli_1.php`). The probe would then reach the page, but its finding
  (`/bWAPP/sqli_1.php`) would never match the case's key. So either convention fails
  under a sub-path today.

## What the bug was identified to be
The point builder treats a ground-truth url as **app-relative** and joins it to the
base's path. The scorer treats it as the **full request path** (findings are stored by
`to_path`). The two agree only when the app is served at `/`.

## Root cause analysis
Five Whys:
1. *Why is the sub-path doubled?* The join is `base_url.rstrip("/") + path`, and `path`
   already holds the sub-path.
2. *Why does the path hold it?* The ground-truth url must equal the finding's key to
   score, and findings are full request paths (`to_path`). So a ground-truth url is a
   stored absolute path. The builder joined it as an app-relative route.
3. *Why two conventions?* The ground-truth url's meaning is written nowhere. The schema
   says `"url": {"type": "string"}`, and every lab we generate serves at `/`, where the
   two conventions give the same URL. Nothing ever forced a choice.
4. *Why did BUG-0113's fix not cover it?* BUG-0113 fixed the same join for crawl points
   (`injection_points_from_store`). Its PA-0002 sweep then **cleared**
   `points_from_ground_truth` as "uses app-relative paths by contract", a contract that
   does not exist. PA-0113(3) ("every component that takes an operator URL has a test
   with the app under a sub-path") was not applied to it: no sub-path test was written.
5. *Why could PA-0113(3) be skipped?* It is a rule addressed to the author with no
   mechanical check. Nothing enumerates the functions that take an operator base URL,
   so a function can go without a sub-path test, by omission or by a sweep verdict,
   and nothing fails.

**Root cause:** the same as BUG-0113 (and BUG-0110): base-URL joins were checked only
against our own labs' root-served shape. PA-0113(3), the rule that would have caught it,
had no enforcement, and the ground-truth url convention was never stated, so a sweep
could clear the site on an assumption.

## Corrective action
**Deferred to the owner of the locked `fuzzlab/harness/auto.py` and
`fuzzlab/greybox/run.py`** (CC-FUZZ-0300 records this). This lane makes no code change
to either. It adds:
- **Strict xfails** (PA-0054(3)) in `tests/test_base_url_subpath_registry.py`:
  - `test_ground_truth_points_join_absolute_paths_to_the_origin`: server, DOM and
    stored-XSS points, for bases with and without a trailing slash;
  - `test_greybox_ground_truth_points_join_absolute_paths_to_the_origin`: the URL
    **and** the class lookup.
  `test_bug_0300_is_what_the_xfails_claim` pins today's doubled URLs, so each xfail
  fails for the stated reason.
- **PA-0300's registry**, the same file: every function in `fuzzlab/` that takes an
  operator base URL, each with its sub-path test or its bug.

Suggested fix, for the owner: join every ground-truth path to the base's origin, as
`injection_points_from_store` does (`f"{scheme}://{netloc}" + path`). Do it in all four
sites, ideally through one shared helper (PA-0003; there are now five copies of the
origin derivation in `auto.py` and `greybox/run.py`). Then state the convention in the
labels contract: a ground-truth url is the full request path. When the fix lands, the
owner deletes the two strict-xfail markers in the same merge (MULTI_AGENT §6) and
changes their registry entries to `Covered`.

Interim workaround (design §5.3, and the runbook for the fixtures): ground-truth runs
pass the origin as `--base-url`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for base-URL and deployment-layout
bugs:
- **BUG-0113 / PA-0113** — the same bug in a sibling function (crawl points), with the
  same root cause. A recurrence.
- **BUG-0110 / PA-0111** — the same root cause: behaviour checked only against our own
  labs' shape.
- **BUG-0050 / PA-0052** — related: a lab-shape assumption baked into a target filter.
- **BUG-0066 / PA-0067(3)** — a recurrence in a site a prior sweep cleared must trigger
  a re-sweep of every site that sweep cleared. That applies here, and is done below.

## Prior-preventive-action failure analysis
- **PA-0113 (from BUG-0113)** stated the right rule in (1) and (3). It failed for two
  reasons. It was **not enforced**: (3) is advice to the author, with no list of the
  functions it governs, so nothing failed when one had no sub-path test. And its own
  sweep **cleared this site without evidence**: "app-relative by contract" named no
  written contract and no test, the kind of verdict PA-0067(1) says counts as unswept.
  A sub-path test of `points_from_ground_truth` would have failed on the day.
- **PA-0111 (from BUG-0110)**, which PA-0113 strengthened, covered emulated algorithms.
  That is the wrong layer for layout.

**Re-sweep of BUG-0113's cleared sites (PA-0067(3)):**
- `pipeline.py` (fingerprint keyed per origin), `web/app.py:119` (CSRF origin check),
  `proxy/server.py`, `proxy/repeater.py` and `oob.py`: each still derives an origin for
  an origin-semantic purpose, and none joins a path. Still correct.
- `points_from_ground_truth`: wrong. This bug.
- The greybox, mutation and oracle `app_root` values are filesystem paths (`rstrip("/")
  + "/"` there joins directories). Still correct.
- By mechanism, every other `rstrip("/")` join and `urljoin` on a base in `fuzzlab/`:
  - `identifier_sqli_oracle._build_url` joins a generated cell's **route path** to the
    base's path. A route path is app-relative, so that is correct, and it now has a
    sub-path test;
  - `session/manager.py:729` joins relative login candidates to the base directory
    (BUG-0113's fix; tested);
  - `greybox/run.py:457` is site 4 above.

## Preventive action
**PA-0300** (strengthens PA-0113):
1. **Every function in `fuzzlab/` that takes an operator base URL is registered** in
   `tests/test_base_url_subpath_registry.py`. Functions are found by AST: a parameter
   whose name ends in `url` with a qualifier `base`/`start`/`target`/`root`/`app`/
   `site`/`entry`, or a bare `base`/`start`/`root` used as a URL. Each entry points
   either to a test that drives the function with a sub-path base (checked by AST to
   exist and to contain a sub-path URL), or to a strict xfail naming its bug. A new such
   function without an entry fails, and a stale entry fails. The discovery rule is
   proven on synthetic offenders (PA-0034(2)).
2. **A join states its convention.** A stored or observed path (`to_path`, a
   ground-truth url) joins to the base's origin. An app's own route path joins to the
   base's path. A sweep verdict "by contract" names where that contract is written, or
   it counts as unswept (PA-0067(1)).
3. **A recurrence in a site a prior sweep cleared re-sweeps every site that sweep
   cleared** (PA-0067(3)), recorded in the bug report as above.

**Sweep (PA-0002), by the registry:** 53 functions discovered. Each has a sub-path test:
an existing one, or one added in this change for functions that had none. The
exceptions are the BUG-0300 sites, which are strict xfails. No other defect was found
(BUG-0302..0305 unused).
