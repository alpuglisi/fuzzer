# BUG-0059 — Crawler's default `python-requests` User-Agent yields 200-but-0-links against real external targets

- Date: 2026-09-25
- Status: fixed
- Severity: medium (crawl silently produces an empty map against affected targets — no
  error, no non-zero exit, just nothing to audit downstream)

## Description

Running a crawl (via the web UI, static/`requests` engine) against an external,
non-loopback authorized test target returned `200 OK` for the start URL but discovered
zero links, so the crawl map stayed empty and nothing downstream (audit/fuzz) had
anything to work with.

## Where encountered

Reported live by the operator running a crawl from the web UI against one of their own
external testing labs (`--engine auto`, falling back to `requests` where Playwright isn't
available).

## What it caused to fail

A crawl against an affected target silently produces zero discovered pages/links —
`200` on the start URL, nothing else — with no exception, no warning distinguishing this
from "the target genuinely has one page," so a caller has no signal that anything is
wrong short of noticing the crawl map is suspiciously empty.

## What the bug was identified to be

`LocalSpider.__init__` (`fuzzlab/tools/spider.py`) creates `self.session =
requests.Session()` and never sets a `User-Agent` header, so every static-engine
request goes out with `requests`' own default (`python-requests/<version>`). This string
is trivially fingerprintable as a non-browser script client, and a number of real
external sites — behind bot-mitigation/WAF layers, or simply serving a
reduced/interstitial page to non-browser clients — return `200 OK` with little or no
markup (no `<a href>` tags) to that UA, while serving full content to a real browser UA.
The local lab (`Puppy Fort Factory`) never surfaced this because it does not discriminate
by User-Agent, so this gap was invisible until a real external target was crawled.

Investigated first as a possible re-introduced loopback-only restriction (the operator's
own hypothesis) — ruled out: `crawl` has no `--authorized` gate at all (confirmed by
grepping every `.authorized` check in the repo — only `fuzz`/`auto`/`greybox-run`/
`proxy`/`mutate-run` have one), and `_in_scope()`'s own scope-following logic already
explicitly supports a non-loopback start host (`CC-CRAWL-0008`/`BUG-0050`, a prior,
different fix in this same component). The actual defect is upstream of scope-filtering
entirely: the raw link list returned by the fetch itself was empty.

## Root cause analysis

Five Whys:
1. Why did the crawl find 0 links? The fetched page's HTML had no `<a href>` tags to
   parse (`_fetch_static`'s `find_all('a', href=True)` legitimately found none).
2. Why did the fetched page have no links? The target served a different (reduced/
   interstitial) response body to this request than it would to a normal browser
   request.
3. Why did the target treat this request differently? The request's `User-Agent` header
   was `requests`' own unmodified default, which many real-world sites use as a simple,
   effective signal to distinguish scripted/bot traffic from a browser.
4. Why was the UA never set? The static engine was originally built and tested only
   against the local lab, which serves identical content regardless of `User-Agent` —
   nothing in that environment could have surfaced the gap.
5. Why wasn't this caught before now? This is the first time the static engine was
   exercised against a real external target with UA-sensitive serving behavior; every
   prior live-boot/navigability test in this repo targets the local generated lab apps.

**Root cause:** the static-engine HTTP client was authored and validated exclusively
against a UA-agnostic local lab, so its default (unset, library-default) `User-Agent`
was never exercised against a real target where that default causes materially
different server behavior.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. No prior bug in this class
(HTTP client fidelity/fingerprintability affecting real-target behavior) was found. The
closest related entry, `BUG-0050`/`PA-0052`/`CC-CRAWL-0008`, fixed a different mechanism
in the same component (link-following *scope*, not the *request* itself) — not a
recurrence, but flagged as the same general area (crawler assumptions that only hold
against the local lab) worth keeping in mind together.

## Corrective action

Added one shared constant, `fuzzlab.core.http.DEFAULT_USER_AGENT` (a current
Chrome-on-Linux UA string), so the fix and any future rotation live in one place
(PA-0027) rather than a hand-copied literal per tool. Applied it to every bare
`requests.Session()` the sweep below found:
- `fuzzlab/tools/spider.py` (`LocalSpider.__init__`) — the crawler, this bug's original
  report.
- `fuzzlab/tools/fetcher.py` (`ContentFetcher.__init__`) — the auditor's static-fetch
  path, same bare-session gap.
- `fuzzlab/tools/blind_sqli_fuzzer.py` (its no-`--identity` `RequestsSender` path).
- `fuzzlab/tools/probesender.py` (`RequestsProbeSender.__init__`'s default session) —
  the oracle's unauthenticated confirmation sender.
- `fuzzlab/greybox/run.py` (`RequestsCorrelatingSender.__init__`'s default session) —
  the grey-box coverage/DB-fault correlation sender.
- `fuzzlab/session/manager.py` (`_requests_fetch_factory`'s login-handshake session).

The Playwright/rendered engine paths (crawler and auditor both) are unaffected — a real
headless Chromium already sends its own authentic browser UA.

Verified offline: `tests/test_spider_scope.py`'s 12 tests still pass unchanged (they
exercise `_in_scope`/`_norm_host`, not session headers, so this change is additive and
non-breaking there). Live re-verification against the operator's own external target
that originally showed 0 links is the operator's own follow-up (this sandbox's outbound
network is proxied/restricted and cannot reach arbitrary external hosts to confirm
live).

## Sweep (PA-0002)

First pass (during the initial write of this doc) grepped only `fuzzlab/tools/` and
`fuzzlab/proxy/`, and **incorrectly asserted `fetcher.py`/`authhttp.py` already set a
UA without actually checking** — a direct instance of the exact mistake this project's
own sweep discipline exists to prevent (a sweep is not done until every claim in it is
verified, not assumed). Caught and corrected by re-grepping the whole `fuzzlab/` package
for `requests\.Session\(\)` (not just the two dirs first guessed), which found three
more bare-session instances the first pass missed entirely:

Complete list, all now fixed via the shared `DEFAULT_USER_AGENT` constant:
- `fuzzlab/tools/spider.py` (`LocalSpider.__init__`) — this bug's original report.
- `fuzzlab/tools/fetcher.py` (`ContentFetcher.__init__`).
- `fuzzlab/tools/blind_sqli_fuzzer.py` (no-`--identity` `RequestsSender` path).
- `fuzzlab/tools/probesender.py` (`RequestsProbeSender`'s default session).
- `fuzzlab/greybox/run.py` (`RequestsCorrelatingSender`'s default session).
- `fuzzlab/session/manager.py` (`_requests_fetch_factory`'s login-handshake session).

Confirmed not affected:
- `fuzzlab/tools/authhttp.py` has no bare `requests.Session()` of its own — it composes
  the caller's already-configured session/client.
- `fuzzlab/oracle/strategies.py` and `fuzzlab/tools/corpus_validation_sandbox.py` route
  through `fuzzlab.core.http.HttpClient`'s own transport (`_requests_transport`), a
  single already-shared function, not a duplicated bare-session instance of this class —
  out of scope for this fix.

## Preventive action

`PA-0061` (see `docs/PREVENTIVE_ACTIONS.md`).
