# BUG-0147 — `test_multitarget_category4` gets a connection reset under the full parallel suite

- Date: 2026-10-15
- Status: **open, investigating** (not reproduced in isolation)
- Severity: medium (test validity and suite reliability). One intermittent failure in
  about 7,000 tests, but its cause is unknown, and a reset could also hide a real
  application or harness defect.

## Description
`tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`
fails with `ConnectionResetError` (errno 104).

## Where encountered
Every occurrence:
- twice on 2026-10-14, under concurrent pytest load;
- `ser10` (the serial list run in parallel), before BUG-0143's fix;
- the 2026-10-15 integration branch's full suite, **after** BUG-0143's fix.

It did **not** occur in:
- the two consecutive parallel runs of the former serial list on `6e44a3f`;
- the dev branch's full suite on `5322658`;
- the integration's first full run, which failed elsewhere.

## Evidence so far
- **Always the same request.** The template-injection confirmer (`strategies.py:802`)
  probes the Go Twitch clone's header-injection twin (`/channels/redirect`). Its
  post/redirect/get follow-up (`probesender._follow`) is
  `GET /channels/$%7B603*129%7D`, the payload echoed into `Location`. The reset happens
  on reading that response.
- **Not reproduced in isolation:** 10 of 10 passes with six CPU-bound processes running
  alongside, so CPU contention alone is not enough.
- **Not the OOM killer:** `/proc/vmstat` shows `oom_kill 0`; 16 GB total, about 15 GB
  available afterwards.
- **Not the Go server's idle timeout:** the generated `main.go` uses
  `http.ListenAndServe` with Go's defaults, which never close idle keep-alive
  connections.
- **Not explained by BUG-0143's wrong-server hazard:** it recurred with ownership
  checking in place.

## Open hypotheses, to test next
1. **A stale pooled connection.** The server half-closes after the 30x, and urllib3
   reuses the socket in the window before the FIN arrives. Test: capture the Go
   server's stdout and the client's connection reuse (urllib3 debug) in a
   full-suite-like load.
2. **The Go app dies mid-request** (a runtime fatal error). Test: keep the server's
   stdout and exit status from `procutil` on failure.
3. **Interference from a concurrent test** acting on loopback sockets or process groups
   in another worker. Test: record the tests running in other workers at the failure's
   timestamp.

## Root cause analysis
Not yet determined. This report replaces the earlier "WATCH" note, per PA-0149(2): it
stays open until the failure is reproduced or tied to a specific shared resource.

## Corrective action
None yet. The test is **not** moved to a serial pass. That would hide the cause without
reproducing it (`scripts/verify_change.py`'s rule).

## Recurrence review
- **BUG-0143:** first believed to be the cause; disproven by the recurrence.
- **BUG-0144** and **BUG-0145:** same class (load-only failures), each since
  reproduced and fixed.

## Prior-preventive-action failure analysis
To be written with the root cause.

## Preventive action
To be decided with the root cause.
