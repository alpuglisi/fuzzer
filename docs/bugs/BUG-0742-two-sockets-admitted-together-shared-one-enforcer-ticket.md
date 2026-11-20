# BUG-0742 — Two sockets admitted together to one host and port shared one enforcer ticket

- Date: 2026-11-20
- Status: fixed (CC-CRAWL-0690)
- Severity: low (availability of a page's WebSocket; fail-closed). The second of two
  WebSockets admitted together to one host and port was refused by SP-04's enforcer
  as a reuse, and its own admission stayed live for its TTL, where the next ``CONNECT``
  to that host and port -- a prefetch's -- could take it (the pinned orphan-ticket gap of
  BUG-0559, made more likely). Never an out-of-scope or unadmitted host reached.
- Records: ERROR_LOG 2026-11-20, PA-0742, CC-CRAWL-0690, CC-LAB-0440, F-742.

## Description
`navguard._take_tunnel` gives a ``CONNECT`` the oldest live unclaimed ticket of its host
and port, and a ticket admits up to 4 tunnels within 3 s of its first, so a certificate
error's retry rides the same admission (BUG-0559 review round 3). With two admissions
live for one key, the second ``CONNECT`` took the first ticket's retry slot; the first
tunnel claimed that ticket, and the second, finding it claimed, was closed as
"a tunnel carried already" -- though its own admission sat unused.

## Where encountered
Lane M6CONC's measurement of SP-04 under concurrent M6 browsers (CC-LAB-0440): Juice
Shop's search page, which opens socket.io's WebSocket on every load, 60 visits per arm
interleaved: `enforcer_refusals()["reuse"]` 0 one at a time, 1 at 3 browsers at once,
with every verdict identical. A single page opening two sockets to one host at once
meets the same order of events (shown by the deterministic test).

## What it caused to fail
The page's second WebSocket was refused (socket.io then falls back to polling through
the route); the unused ticket stayed live up to `SOCKET_TICKET_TTL_S`. No verdict
changed in the measurement.

## What the bug was identified to be
A ticket chosen at take time, by age, for a connection whose identity (retry or new
admission) is only known at claim time.

## Root cause analysis (Five Whys)
1. Why was the socket refused? Its tunnel's ticket was already claimed.
2. Why did it hold another connection's ticket? `_take_tunnel` handed it the oldest
   ticket's retry slot while a fresh admission existed.
3. Why can take time not tell? A ``CONNECT`` names only host and port: a certificate
   error's retry and a second socket look the same; only the first tunnel's claim
   shows which ticket is spent.
4. Why was it not measured? BUG-0559's review round 3 measured a ticket against every
   way the browser uses *one* admission (a retry, the keep-alive pool, HTTP/2), never two
   admissions in flight to one key.
- **Root cause:** the enforcer bound a tunnel to an admission before it could know
  which admission the tunnel was for, and the design was measured with one admission
  per key at a time.

## Corrective action (CC-CRAWL-0690)
- `_TunnelTicket.key`; `navguard._claim(ticket)` returns the ticket the tunnel carries:
  its own while unclaimed, else a live, untouched ticket of the same key and kind (a
  spare admission), else None; `_HeldTunnel._claim` carries what it returns. Take order
  is unchanged (a certificate error's retry still rides its admission), a tunnel still
  carries one admission only, and only an admitted one.
- `tests/test_enforcer_ticket_claim.py` (deterministic, the real ticket functions; fails
  on the old code); measured after the fix at volume (CC-LAB-0440).

## Recurrence review
BUG-0559 built the tickets; its review round 3 found and fixed a tunnel reused past its
exchange and a certificate error's retry refused -- the same mechanism, different uses.
PA-0559(11) is the prior rule.

## Prior-preventive-action failure analysis
PA-0559(11) ("an exception a guard grants is measured against every way the browser
uses what it admits") did not prevent this: **too narrow.** Its list (a retry, the
keep-alive pool, multiplexing) enumerates the uses of one admission; two admissions to
one key in flight together -- two sockets of a page, or concurrent browsers sharing the
process-wide enforcer -- were not on it, and the measurement ran one browser at a time.

## Preventive action
PA-0742 (strengthens PA-0559(11)): a ticket-style exception is also measured and tested
with two admissions of one key in flight at once, and with the process's concurrent
browsers (the enforcer is process-wide); a choice that cannot be made at take time is
made where it becomes known (the claim), pinned by a deterministic order-of-events
test. The sweep: the http landing tickets (`_TICKETS`, `_take_ticket`) are a count per
landing URL with no retry slot, so concurrent admissions of one URL draw
interchangeable tickets (no fix needed); `_take_tunnel` has one caller (the enforcer
handler) and `_claim` one (`_HeldTunnel._claim`, its three uses).
