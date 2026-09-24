# BUG-0050 — the crawler followed only `localhost`/`127.0.0.1` links, so pointed at an authorized external host it dropped every discovered link and crawled a single page

## Description

`fuzzlab crawl` (and the web-UI "crawler" tool, which shells out to it) gated
every discovered link through `LocalSpider._is_local(url)`:

```python
def _is_local(self, url):
    return urlparse(url).hostname in ['localhost', '127.0.0.1']
```

Only links whose hostname was a loopback literal were enqueued. Pointed at any
**non-loopback** host — including an operator's *authorized* external target set
via the web UI's `target_base_url` — every extracted link failed that check and
was silently discarded, so the crawl fetched only the start page ("Crawled 1
page(s)") and reported no links, on any real site.

## Where encountered

Reported by the operator: crawling authorized live hosts via the web UI grabbed
no links. It was also visible (but masked as "expected") in the 2026-09-24
on-host run against the loopback lab, whose generated app happens to have no
anchors — so the loopback case never exercised the follow path either.

## What it caused to fail

The crawler could not discover any surface beyond the single start URL on any
target that is not on loopback — defeating its entire purpose (FR-CRAWL-1/2:
link and endpoint discovery) for real authorized targets, and starving the
auditor/fuzzer of endpoints.

## What the bug was identified to be

A link-following **scope filter hardcoded to loopback literals**. The crawler
class (`LocalSpider`, "Crawls a *local* site") was written for the loopback lab
and its `_is_local` guard doubled as both the "don't escape to the open web"
safety boundary and the follow filter — but expressed as "host must be
localhost," not "host must be the target the operator pointed at." The web UI
makes the target host configurable (`target_base_url`), so the two were in
direct contradiction: a configurable target whose links are then all dropped
unless it is loopback.

## Root cause analysis (Five Whys)

1. Why were no links followed on an external host? Every discovered link failed
   `_is_local`.
2. Why did they fail? `_is_local` returns true only for `localhost`/`127.0.0.1`;
   an external target's links are neither.
3. Why was the follow filter loopback-only? It was written as the lab-only
   "don't escape to the open web" guard, encoded as a fixed loopback allowlist
   rather than "same host as the start URL."
4. Why did that survive the tool becoming target-configurable? The web UI
   exposed a configurable `target_base_url`, but the crawler's scope guard was
   never generalised from "loopback" to "the configured target's host"; no test
   covered a non-loopback start (the loopback lab, with no anchors, never
   exercised the follow path).
5. **Root cause:** the crawler conflated its *safety boundary* ("stay on the one
   target, don't wander the open web") with a *fixed loopback allowlist*, so
   when the target became any authorized host the boundary silently excluded the
   target itself instead of scoping to it.

## Corrective action

- Replaced `_is_local` with `_in_scope(url)`: scope is the **start URL's own
  host** (`self._scope_host`, computed in `__init__`). Same-host links are
  followed; off-host links (third-party domains, other subdomains) are not, so
  the "don't escape to the open web" intent is preserved while the crawler can
  actually crawl whatever authorized host it was started on. Loopback aliases
  (`localhost`/`127.0.0.1`/`::1`) are treated as one host so the lab keeps
  working; `www.` is normalised so apex/`www` count as one host.
- Applies to both engines (static `requests` and headless `playwright`) — the
  follow logic is shared — and therefore to the web-UI crawl, which shells out
  to the same CLI.
- Added `tests/test_spider_scope.py` (12 cases) pinning the decision for
  external, subdomain, third-party, `www`, no-host, and loopback-alias links.
- Verified end-to-end: a 3-page same-host site is fully discovered (both
  engines) while an embedded third-party link is not followed. See
  CC-CRAWL-0008; new requirement FR-CRAWL-7.

## Whole-application sweep (PA-0002) — is the same lab-only assumption anywhere else?

Because the toolkit is intended for authorized **externally-hosted** targets,
every shipping module was swept for the same class of defect (a hardcoded
loopback assumption that would silently drop/refuse a real target). Result: the
spider was the **only** silent target-surface restriction. Every other loopback
reference is legitimate and was intentionally left as-is:

- **Traffic-senders don't filter on target host:** the auditor (`tools/fetcher.py`,
  `audit/engine.py` — its "scope" is rule *categories*, not hosts), the runtime
  oracle (`oracle/strategies.py`, `oracle/probe.py`), the probe sender
  (`tools/probesender.py`), the fuzzer (`tools/blind_sqli_fuzzer.py`), and the
  session/login layer (`session/*`, `tools/authhttp.py`) all operate on the
  operator-supplied URL with no loopback gate.
- **Attack traffic is gated on `--authorized`, not on host** (`fuzz`, `auto`,
  `proxy`) — correct per D11; the authorized operator passes it.
- **Proxy scope is configurable default-deny** (`proxy/scope.py`; default
  `scope_hosts=("127.0.0.1",)`): an external target is reached by passing
  `--scope <host>`, not blocked silently — a deliberate safety design, left as-is.
- **Local listener binds stay loopback** (correct — these are where the *tool*
  listens, not the target): the web panel and proxy listener
  (`web/app.py` refuses a non-loopback bind), and the OOB canary
  (`oracle/oob.py`, default-off).
- **Lab-generation/verification oracles keep `assert_loopback`** (`labgen/*`):
  they build/verify the generated loopback lab, not for testing external apps.

**Flagged (design limitation, not fixed here):** OOB-callback confirmation
strategies (blind command-injection M8 `CommandInjectionOobStrategy`, and any
SSRF/OOB) embed a **loopback** canary listener an external target cannot call
back to, so those *blind* strategies won't confirm against a remote target
without a callback host reachable by that target. They are default-off and
fail-closed, so they don't affect the mainline SQLi/XSS/etc. flows; making the
callback host configurable is a deliberate future decision (it means exposing a
listener) and is left to the operator/roadmap, not silently changed.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. `BUG-0048`/`PA-0050`
(this same session) is the closest relative: it, too, was a check that
hardcoded an assumption about the target's shape (`/` returns 200) that held for
the old hand-built lab but not for a real/generated target, and `PA-0050`
generalised "don't hardcode target-shape assumptions in a reachability check."
This bug is the same *class* (a lab-only assumption baked into a filter) in a
different place (the crawler's follow scope) and predates that session's target
work — the loopback allowlist is original crawler code. `PA-0050` is about
*readiness* probes specifically; it did not reach the crawler's *scope* filter.
No prior PA covered "scope a crawl to the configured target host, not a fixed
allowlist," so this is a new, adjacent rule rather than a repeat.

## Prior-preventive-action failure analysis

`PA-0050` (from `BUG-0048`, same session) established "don't hardcode a
target-shape assumption in a reachability check," but was scoped to readiness
probes and landed after this crawler code. The new PA extends that doctrine from
"reachability checks" to **any target-scoping/allowlist filter**: express it as
"the target the operator configured," never as a fixed host literal that a
lab-only default happens to satisfy — and cover a non-default (non-loopback)
target with a test.

## Preventive action

**PA-0052** (see `docs/PREVENTIVE_ACTIONS.md`) — a tool's scope/allowlist filter
must be derived from the operator-configured target (e.g. the start URL's host),
never a hardcoded lab literal such as `localhost`/`127.0.0.1`; and any
lab-only-default guard must be exercised by a test with a non-default
(non-loopback, real-host) target so a filter that silently excludes real targets
cannot ship. Strengthens/generalises `PA-0050` from readiness probes to every
target-scoping filter.
