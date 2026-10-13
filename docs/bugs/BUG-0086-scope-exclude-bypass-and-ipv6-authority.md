# BUG-0086 — A port-specific scope exclude was bypassed; IPv6 authorities were misparsed

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0019, CC-UI-0049)
- Severity: medium. A service the operator excluded (e.g. an admin port) was
  intercepted and recorded. IPv6 targets were unusable.

## Description
- **The bypass.** `ProxyEngine.handle_request` checked `in_scope(authority) or
  in_scope(host)`. With `include("127.0.0.1").exclude("127.0.0.1:9000")`, the authority
  check said "out", but the bare-host check said "in", so the excluded service's flows
  were recorded.
- **IPv6 (every authority split was `partition(":")`):**
  - `parse_connect` turned `CONNECT [::1]:8443` into host `"["`;
  - origin-form `Host: [::1]:8443` was misparsed the same way;
  - `_authority` produced `::1:8443`;
  - scope patterns containing `:` were treated as port-specific, so `::1` never
    matched;
  - `proxycontrol.create_from_flow` produced host `"["`.

## Where encountered
The error-review phase (`scratchpad/review7/r1_scope_exclude.py`). Reviewers A and B
found the scope-pattern and `create_from_flow` instances in the sweep.

## What it caused to fail
FR-PROXY-5 (scope: "an explicit exclude always wins"), NFR-PROXY-safe, and IPv6
loopback labs.

## What the bug was identified to be
A policy decision evaluated twice, where the less specific fallback could turn a deny
into an allow. Authority parsing was duplicated and IPv6-unaware.

## Root cause analysis
1. *Why recorded?* The second, host-only check allowed it.
2. *Why the second check?* It was added so a port-less rule matched a `host:port`, but
   `_host_matches` already did that.
3. *Why IPv6?* There was no shared authority parser: five `partition(":")` copies.
4. *Why no test?* No exclude-with-port test, and no IPv6 test.

**Root cause:** a duplicated, less specific policy check, and a convention (authority
parsing) kept as copies.

## Corrective action
- **One authority parser:** `proxy/authority.py`. `split_authority` handles `[v6]:p`,
  `[v6]`, bare `v6`, `host:port` and `host` (lower-cased); `join_authority`
  re-brackets. It is used by `parse_connect`, `target_from_request`, `_authority`,
  `_host_matches` (which parses **both** the pattern and the host),
  `proxycontrol.create_from_flow`, and the CA's `leaf_host`.
- **One scope decision,** on the authority.
- **Tests** (`tests/test_proxy_rules_and_scope.py`):
  - the exclude is forwarded transparently and not recorded;
  - 9 pattern/authority pairs (port-less, port-specific, `::1`, `[::1]`, `[::1]:8443`,
    subdomain);
  - IPv6 CONNECT, origin-form and absolute-form;
  - IPv6 flows are recorded bracketed.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0050 / PA-0052** governs *where scope comes from*: derived from the operator's
  target, tested with a non-default host. This bug is a scope decision evaluated twice,
  with a fallback that turns a deny into an allow. **Same area, new root cause**;
  PA-0052 is not strengthened.
- **PA-0003** (one convention, one helper): not followed for authority parsing.

**Result:** a new root cause for the double decision. The parser duplication is a
PA-0003 lapse, addressed by the shared parser.

## Preventive action
**PA-0087:**
1. A policy decision (scope, allow/deny) is evaluated in exactly one place, on the most
   specific key. A fallback on a less specific key must never be able to turn a deny
   into an allow.
2. Authorities are parsed by one IPv6-aware helper, never by `partition(":")`.

**Sweep (PA-0002)**, by grep for `partition(":")` / `split(":", 1)` on authorities:
- **proxy:** fixed.
- **`proxycontrol`:** fixed.
- **Session `_scope`:** host-only by design, compared after `urlparse`, which is
  IPv6-safe.
- **Crawler link scope (BUG-0050):** uses `urlparse`.
- **Oracle loopback gate:** `core.net`.
