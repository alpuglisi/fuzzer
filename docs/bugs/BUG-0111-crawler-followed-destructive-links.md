# BUG-0111 — The crawler followed destructive links: NFR-CRAWL-safe was never built

- Date: 2026-10-13
- Status: fixed (CC-CORE-0038, CC-CRAWL-0011, CC-AUD-0029, CC-SESS-0015, CC-FUZZ-0060)
- Severity: high. On a real target, an authenticated crawl would have dropped its
  database and logged its own session out.

## Description
NFR-CRAWL-safe ("Deny-list destructive actions (delete/logout/reset); default to not
clicking them") had no implementation and no test:
- `tools/spider.py::LocalSpider.crawl` queued and fetched every in-scope `<a href>` and
  XHR URL;
- `requests` followed any redirect;
- in the rendered engine, the browser loaded every subresource and script fetch;
- the passive auditor (`tools/fetcher.py`) then re-fetched every URL in the spider DB.

## Where encountered
While preparing an authenticated crawl of the operator's self-hosted, loopback-only
bWAPP (`127.0.0.1:8090`), before anything was run. Its `portal.php` links `reset.php`,
which on a plain GET runs `DROP DATABASE IF EXISTS bWAPP` and unlinks files (its JS
`confirm()` does not stop a crawler), and `logout.php`.

## What it caused to fail
- **NFR-CRAWL-safe:** nothing enforced it.
- **FR-CRAWL-5:** an authenticated crawl that fetches `logout.php` continues
  unauthenticated.
- **NFR-AUD-safe:** the auditor re-fetches the same URLs.

## What the bug was identified to be
A safety requirement written into the spec and never implemented. Nothing traced it to
code or to a test.

## Root cause analysis
1. *Why would reset.php be fetched?* The spider follows every same-host link.
2. *Why no deny-list?* It was specified (NFR-CRAWL-safe) but never built. The
   component's status, "[built; to harden]", did not distinguish built requirements from
   unbuilt ones.
3. *Why did nothing fail?* No test was tied to the NFR, and no guard checks that a
   safety NFR has one.
4. *Why didn't our labs show it?* Our own lab has no destructive GET link, and is
   fuzzed mostly from ground truth, not crawls.
5. *Why did no earlier rule catch it?* PA-0083(2) ("every never/always safety claim in a
   docstring is backed by a test") looked at docstrings, not at the requirement specs
   where the NFRs live.

**Root cause:** safety NFRs were not traced to enforcing code and a test, and nothing
failed when one was missing.

## Corrective action
- **One rule:** `core.urls.destructive_reason` (CC-CORE-0038, FR-CORE-28). It decodes,
  splits camelCase, and matches whole tokens and pairs.
- **Crawler (CC-CRAWL-0011):**
  - no destructive link or XHR URL is queued;
  - the static engine follows redirects by hand (`navguard.get_checked`), each hop in
    scope and not destructive;
  - the rendered engine installs `navguard.guard_page`, which aborts destructive
    navigations, fetch/XHR and subresources in the browser;
  - the start URL is exempt.
- **Auditor (CC-AUD-0029):**
  - `load_urls` drops destructive URLs, which covers old spider DBs;
  - its raw static fetch follows redirects by hand, same-origin and not destructive;
  - its browser page is guarded.
- **M6 browser (CC-FUZZ-0060):** guarded, with the observe and store targets allowed.
- **Login discovery (CC-SESS-0015):** it never follows a hop to a destructive URL.
- **Tests:** `tests/test_destructive_urls.py`:
  - a static crawl with a destructive link and a 302 to one;
  - a real-browser crawl of a loopback page with `<img src=logout.php>`,
    `fetch('reset.php')` and a delete link: the server sees none of them;
  - the route handler, the auditor and discovery.

  They fail on `fa53b9e` (the new module does not exist there). The mutation check
  killed 31/31 (two tests were sharpened after survivors).

## Recurrence review
- **The prior is BUG-0082 / BUG-0084 → PA-0083:** "redacts token query parameters" was
  never implemented. That is the same class: a safety claim with no enforcement.
- **Related: PA-0020 and PA-0033** (enforce by mechanism, not memory).

## Prior-preventive-action failure analysis
PA-0083(2) failed for three reasons:
- **Too narrow, wrong layer:** it covered docstring claims, but NFRs live in the
  `requirements.md` specs.
- **Not enforced:** its "sweep greps docstrings" is a manual step, and no mechanism
  fails when a safety claim has no test.
- **Not followed at spec-writing time:** a safety NFR could be added with no plan to
  test it.

## Preventive action
**PA-0112** (strengthens PA-0083(2)):
- every NFR is classified SAFETY or NOT_SAFETY in
  `tests/test_requirements_traceability.py`;
- every SAFETY NFR names `tests/<file>.py::<test>` (checked by AST) in `Enforced by:`
  lines, or says `Not yet enforced:`;
- the guard is proven on synthetic offenders.

**Sweep (PA-0002):** two read-only agents traced every safety NFR clause to code and
tests. The crawl and fuzz gaps (this bug and BUG-0112) are fixed here. Everything else
is recorded as `Not yet enforced:` in its spec and reported to the operator:
- **LAB:** no outbound route;
- **CORE:** no-bypass, and secrets in config, repeater and plugin config;
- **IND:** no destructive flag;
- **FUZZ:** the payload gate on auto/fuzz, the "off localhost" wording, and untested
  CLI `--authorized`;
- **AUD:** gate and canary;
- **UI:** redaction in the Repeater, port pinning and other untested cases, read-only
  by convention;
- smaller test gaps.
