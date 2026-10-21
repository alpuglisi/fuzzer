# BUG-0544 — Stored evidence was replayed as the request

- Date: 2026-10-21
- Status: fixed (CC-FUZZ-0111, CC-AUD-0056, CC-CORE-0073)
- Severity: high (CRITICAL in the owner's audit, defect 7)

## Description

A stored sibling set is evidence: redaction (PA-0100) blanks a CSRF token, any sensitive
name and an identifier-like value, and the point builder replaced a host-shaped default
with loopback (FR-AUD-20). The pipeline then sent those stored values as the request's
own: `csrf_token=""`, `id=""`, `ref=http://127.0.0.1/`. A one-time token's form was
rejected before its handler ran, a blanked object key reached another code path, and the
result read as a negative (or as session loss).

## Where encountered

Owner-supplied adversarial audit at 6552276, defect 7 (`core/forms.py` `form_record`,
`tools/store_adapter.py` `redact_sibling`, `harness/auto.py` `_send_value` and the
builder's entries). Reproduced in `tests/test_replay_bindings.py` on c483dc1:
`csrf_token=one-time` is stored blank and sent blank on every probe.

## What it caused to fail

- Every fuzzed POST of a form with a one-time or session-bound token was refused before
  the vulnerable handler; the candidate was marked `checked`: a false negative (FR-FUZZ-42
  even listed "forms needing a fresh CSRF token do not confirm" as a residual).
- A link or captured body whose identifier sibling was blanked exercised a different
  handler path.
- A request carrying a loopback stand-in for the app's own host value was a request the
  app never made; header points' queries did the same.

## What the bug was identified to be

The stored entry list served two roles: persisted evidence (which must be redacted) and
runtime replay material (which must be the app's real request). Nothing recorded which
stored values were placeholders, nothing re-obtained them before a send, and nothing
refused a send that could not be rebuilt.

## Root cause analysis (Five Whys)

1. Why was `csrf_token` sent blank? The binder sent the stored entry list as is.
2. Why was the stored value blank? Redaction blanks a token before storage (PA-0100,
   correct for evidence).
3. Why did the binder not obtain a real one? Nothing told it the value was a placeholder,
   and no sender could fetch a page on the probe's session route.
4. Why was a send that could not be rebuilt still made? A missing prerequisite had no
   outcome other than "send what we have": the oracle's only no-verdict outcomes were
   unplaceable, unobserved and not comparable.
5. **Root cause:** persisted evidence was used as the replay template. The redaction
   boundary had no counterpart that separates "what may be stored" from "what must be
   sent", so every redaction or substitution silently became part of the request.

## Corrective action

- The importer records each sibling set's replay recipe (migration 25: `form.source_page`,
  `form.fresh`): the page it came from and the names of the placeholders; names and a page
  only (CC-AUD-0056, CC-CORE-0073).
- Before each send the oracle's binder fetches that page through the new sender `fetch`
  on the probe's own route and binds the placeholders' current values in memory
  (`core.forms.page_template_entries`); otherwise `PrerequisiteUnavailable`, and the
  candidate is inconclusive (`UNBOUND`) with the reason (CC-FUZZ-0111).
- A sibling naming a host outside the lab is never sent and never replaced: its point
  carries a `replay_refusal`; a loopback value is sent as given (FR-AUD-20 amended,
  `value_shape.names_outside_lab`).
- The fingerprint baseline, header points and the M6 browser never send a placeholder.
- Tests: `tests/test_replay_bindings.py` (the reproduction, the inconclusive paths, D12,
  a real-socket session jar), the fetch guards in `tests/test_sender_conformance.py`;
  amended with before/after: `test_forms_phase2` (three), `test_json_points` (one, split
  in two).

## Recurrence review

Checked `docs/bugs/` and `PREVENTIVE_ACTIONS.md` for a stored or redacted value reused as
a live value, or a substitution sent as the app's value:
- BUG-0099 / PA-0100 (the storage boundary): the cause of the placeholders, correct for
  evidence; it says nothing about replay.
- BUG-0124 (the redirect seed, FR-AUD-21's exception): about sending an app's host, not
  about placeholders.
- BUG-0110 / PA-0111 (form serialisation like a browser): the entry list's *shape*, not
  its values' provenance.
- FR-FUZZ-42's stated residual "forms needing a fresh CSRF token do not confirm".

No prior bug with this root cause. Related rule gap: a stated residual hid a false-negative
source (the same failure mode as BUG-0530's "first wins" residuals).

## Prior-preventive-action failure analysis

Not required (no same-root-cause match). PA-0100 is not weakened: storage stays redacted.

## Preventive action

**PA-0544** (complements PA-0100):
1. A persisted value is evidence, never replay material. A value redaction blanked or a
   stand-in replaced is recorded as a placeholder (by name, never by value) where it is
   stored, and is never sent as the request's own.
2. Before a send that needs it, the value is re-obtained by an authorized setup step on
   the probe's own session route and bound in memory only (D12).
3. A send whose prerequisites cannot be rebuilt is not made: the test is inconclusive
   with the reason, never a negative.
4. A wrapper of the sender protocol reports and forwards every optional capability its
   inner sender has (`fetch_capable` like `prg_capable`), proven on a synthetic wrapper
   that hides it.

- Enforced by: tests/test_replay_bindings.py::test_a_blanked_csrf_token_is_bound_fresh_before_each_send, tests/test_replay_bindings.py::test_a_token_that_cannot_be_fetched_is_inconclusive_never_negative, tests/test_replay_bindings.py::test_no_fresh_value_reaches_the_store, tests/test_replay_bindings.py::test_a_sibling_naming_a_host_is_sent_as_given_on_loopback_and_never_off_it, tests/test_sender_conformance.py::test_every_wrapper_reports_and_forwards_its_inner_senders_fetch, tests/test_sender_conformance.py::test_the_fetch_guard_catches_a_wrapper_that_hides_it

PA-0002 sweep (by mechanism: every path that sends stored siblings): the oracle binder
(every strategy, the PRG restore, the access-control peer replay, which now binds in the
peer's own session), the fingerprint baseline, header points' representative query, the
M6 DOM executor (refuses), ground-truth JSON and store bodies (the host rule; 15 leaves
measured, none affected). Not swept here: greybox points carry no siblings
(FR-FUZZ-8); the blind-SQLi fuzzer sends an operator URL (no stored siblings).
