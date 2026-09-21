# BUG-0012 — Proxy self-test asserted rejection of a *valid* duplicate Content-Length

- Date: 2026-09-21
- Status: fixed
- Severity: low (false failure in a self-test; the product code was correct)

## Description
`scripts/proxy_e2e.sh` step 5 sent a request with **two identical** `Content-Length: 0`
headers and asserted the parsed path rejects it (`is_valid_request(...) is False`). But a
duplicate Content-Length with *identical* values is **valid** per RFC 7230 §3.3.2 — h11
accepts it — so the assertion was wrong and the script reported a false `FAIL: the parsed
path did not reject the duplicate Content-Length`, even though the proxy had forwarded the
bytes byte-exact (its actual job) correctly.

## Where encountered
On the host: `scripts/proxy_e2e.sh` at "5/6 Forwarding a duplicate-Content-Length request".
The offline unit test `test_async_server_forwards_duplicate_content_length_byte_exact`
passed because it used *conflicting* values (5 and 6); only the on-host script diverged to
identical values.

## What it caused to fail
The Part I script reported failure at its exit check although the proxy behaved correctly,
blocking a green Part I run.

## What the bug was identified to be
The self-test encoded an incorrect premise about the system under test: that *any*
duplicate Content-Length is invalid. Only *conflicting* Content-Length values are rejected;
identical duplicates are allowed. The script also diverged from the validated offline test,
which had deliberately used conflicting values.

## Root cause analysis
Five Whys:
1. Why did the script FAIL? `is_valid_request` returned True for the crafted request.
2. Why True? The request had two *identical* `Content-Length: 0` headers, which h11 accepts.
3. Why did the assertion expect False? It assumed duplicate ⇒ invalid.
4. Why was that assumption wrong? RFC 7230 permits duplicate identical Content-Length;
   only conflicting values are rejected.
5. Why wasn't it caught earlier? The offline unit test used conflicting values (correct)
   and passed; the on-host script was hand-written with identical values — a weaker,
   incorrect construction that no test exercised.

**Root cause:** the on-host self-test's assertion encoded a wrong premise about HTTP
framing (duplicate-identical Content-Length is valid) and used a different construction
than the validated offline test, so it asserted something untrue of the target.

## Corrective action
- `scripts/proxy_e2e.sh` now sends **conflicting** Content-Length values (`0` and `5`),
  matching the offline unit test; the proxy reads the first (0 → no body) and forwards
  byte-exact, and `is_valid_request` correctly returns False.
- Runbook Part I.4 clarified: use conflicting values, because duplicate-identical is valid.

## Recurrence review
Reviewed the other `docs/bugs/` logs and `docs/PREVENTIVE_ACTIONS.md`. The closest prior
rules are PA-0001 (don't hardcode a source-of-truth value in tests), PA-0006 (integration
tests must feed real-upstream-shaped inputs), and PA-0010 (verify the actual produced
signal). None covers this mechanism — an assertion whose *premise about the target's
contract* is wrong, and an on-host self-test that diverged from the validated offline
assertion. **Not a recurrence** of a specific prior bug/PA; no prior-preventive-action
failure analysis required.

## Preventive action
PA-0013 (see `docs/PREVENTIVE_ACTIONS.md`): a self-test assertion must reflect the true
contract of the system under test (e.g. only *conflicting* Content-Length is invalid;
duplicate-identical is allowed), and an on-host / integration self-test must use the same
construction the validated offline test proved — never a weaker or hand-rolled variant
that asserts something the offline test did not establish.
