# BUG-0117 — SQLi (and three other) oracle strategies confirmed on evidence the probe did not cause

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0065)
- Severity: high. These are false positives in the sole finding-writer, which become
  wrong training labels.

## Description
Four confirmation strategies accepted evidence they had not shown to be caused by
their probe:

1. **`SqliErrorStrategy`** confirmed when the response to `'` matched a SQL error
   signature, even if every response matched.
   - **Example:** a page whose benign state already prints `Warning: mysql_num_rows()`
     (`display_errors` is on in the bWAPP sandbox image).
   - **Example:** a bound parameter into a strict-mode INT column, which errors
     (`HY000/1366`) on any non-numeric value.
2. **`SqliBooleanStrategy`** decided from one unreplicated sample of each probe. A
   payload-independent page whose length changes in the order A, A, B (a rotating
   banner, two backends) confirmed. 2 of 8 two-state sequences confirm.
3. **`PathTraversalStrategy`** confirmed on `root:x:0:0:` with no control. Its sibling
   `PathTraversalFsPathReadStrategy` has one.
4. **`SstiStrategy` / `SpelInjectionStrategy`** confirmed on a single random number
   appearing anywhere. A page full of numbers is "an evaluator".

## Where encountered
Forms phase 2, lane C's design review. The strategies were read while adding
string-context SQLi confirmation. Tests T7, T7b, T8, T12 and T27 in
`tests/test_oracle_sqli_string.py` fail on `ad352db`.

## What it caused to fail
- Precision (NFR-FUZZ-precision) on any target with a noisy page or an always-present
  signature.
- Wrong positive labels written to `finding` and used for training.

## What the bug was identified to be
These strategies predate the project's rule that evidence must be shown absent
without the probe (a control) or replicated with fresh randomness.

## Root cause analysis
1. *Why did the SQLi strategies confirm on a page that always shows the signature?*
   They never sent a control.
2. *Why no control?* They were written before the control standard
   (`PathTraversalFsPathRead`, the CRLF strategy, PA-0090).
3. *Why was the standard not applied to them later?* PA-0084 and PA-0090 were scoped to
   the mechanisms that were broken then (XSS structure, in-band SSRF/XXE proofs). Each
   added fixtures only for the strategy it fixed.
4. *Why did no guard catch the older strategies?* No test ran **every** confirmation
   strategy against payload-independent noise. The sweeps under PA-0002 looked at the
   failing mechanism's own class.

**Root cause:** the "evidence must be caused by the probe" rule was enforced per
strategy, by fixtures, never across all strategies of a category by discovery.

## Corrective action (CC-FUZZ-0065)
- **`SqliErrorStrategy`:** a signature counts only when absent from the quote-free,
  non-numeric control `fz…`, plus `1fz…` for a digit-led probe. At most 6 requests.
- **`SqliBooleanStrategy`:** runs on the bracketed, replicated engine (FR-FUZZ-45 (a)).
  P[confirm] ≤ 1/1458 per family for any probe-independent sequence, proven by an
  exact search over the engine's own draws.
- **`PathTraversalStrategy`:** a `passwd` control.
- **`SstiStrategy` / `SpelInjectionStrategy`:** a second sample with a different value,
  each value digit-bounded in its own response and absent from the other's.

## Recurrence review
The same family of defect occurred three times before, each time as evidence not
attributable to the probe:
- **BUG-0083 → PA-0084:** reflected XSS confirmed on a substring anywhere.
- **BUG-0089 → PA-0090:** in-band SSRF/XXE confirmed on the token the request itself
  carried.
- **BUG-0093 → PA-0094:** a structure matched inside an inert container.
- Also related: `PathTraversalFsPathReadStrategy`'s own docstring argues for an
  "always-echoes" control, but that control was never back-ported to
  `PathTraversalStrategy`.

## Prior-preventive-action failure analysis
- **Too narrow:** PA-0084, PA-0090 and PA-0094 each cover one mechanism (XSS
  structure, OOB/in-band proofs, container executability).
- **Not enforced across strategies:** their fixtures exercise only the strategy that
  was fixed. Nothing ran the older SQLi, file-inclusion, SSTI and SpEL strategies
  against payload-independent noise.
- **Sweeps stayed local:** the PA-0002 sweeps looked within the failing mechanism.

The new rule must be enforced by **discovery** over a whole category, as PA-0072 did
for keys, and its guard proven on offenders.

## Preventive action
**PA-0117** strengthens PA-0084(2), PA-0090 and PA-0094 from their mechanisms to
every confirmation strategy:
1. A fixed signature counts only when absent from a benign control of the same point.
2. A response differential counts only with the baseline shown stable around it and
   replication with fresh tokens. Its bound is stated and tested as stated.
3. It is enforced by discovery, proven on offenders (`_ControlLessError`, the
   single-sample engine): `test_payload_independent_noise_never_confirms_any_sqli_strategy`.
4. The PA-0002 sweep covers every strategy with a fixed marker or a single sample.

## PA-0002 sweep
| Strategy | Instance? | Action |
|---|---|---|
| `SqliErrorStrategy` | yes | fixed (controls) |
| `SqliBooleanStrategy` | yes | fixed (engine) |
| `PathTraversalStrategy` | yes | fixed (`passwd` control) |
| `SstiStrategy`, `SpelInjectionStrategy` | yes (weaker) | fixed (two-sample cross-check) |
| `GoTemplateSsti`, `CsvFormula`, `HttpHeaderInjectionCrlf`, `PathTraversalFsPathRead`, `XxeInBandMarker` / `SsrfInBandMarker` (HMAC), `JwtAlgNone`, `MassAssignment`, `UnrestrictedFileUpload` | no: each has a control, a cross-check or an HMAC | reviewed |
| `tools/fetcher.SQL_ERROR_SIGNATURES` | no: a passive fingerprint hint, not a label writer | reviewed |
| `labgen/identifier_sqli_oracle.py` | no: it has a baseline (build-time tool) | reviewed |

The noise guard covers the `sql-injection` category. Extending it by discovery to the
other categories' strategies is a recorded follow-up. The four instances outside SQLi
are fixed here, each with its own fixture.
