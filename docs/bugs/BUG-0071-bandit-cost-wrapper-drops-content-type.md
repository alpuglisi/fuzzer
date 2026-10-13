# BUG-0071 — `fuzzlab auto --bandit` crashed on any content-typed probe, leaving candidates read as negatives

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0056, CC-CORE-0033, CC-UI-0048)
- Severity: high. Today's lab hits it: netflix/twitch uploads, XXE, and JSON-body points.
  The run aborted mid-oracle-loop, and every candidate was left with a NULL
  `oracle_status`, which the ML dataset reads as *labelled*. So unchecked candidates
  would have trained as confirmed negatives on the next `--score`.

## Description
`oracle/oracle.py::_CostCounter` is the per-strategy cost wrapper the oracle puts around
the sender when a bandit scheduler is attached. Its `send` lacked the `content_type`
parameter that the `Sender` protocol gained for whole-body points (CC-FUZZ-0032,
FR-FUZZ-19). Every strategy that sends a JSON / multipart / XML body passes
`content_type=`, so under `--bandit` the first such probe raised `TypeError: send() got
an unexpected keyword argument 'content_type'`. Without `--bandit` the wrapper is not
used, and the same run was fine. `harness/auto.py::_CountingSender`, the other wrapper of
the same seam, already had the parameter.

A second defect made the crash worse. `run_pipeline` wrote `oracle_status` only **after**
the oracle loop. A raise inside the loop left every candidate of the run NULL, and NULL
is the legacy "oracle-labelled" status (migration 13).

## Where encountered
The error-review phase (a read-only review agent; reproduced by me:
`--bandit -> RAISED TypeError …`, no bandit → fine).

## What it caused to fail
- Every `fuzzlab auto --bandit` run whose candidates include a content-typed point: the
  run aborted.
- The aborted run's candidates had NULL statuses. A later `--score` /
  `--confirm-budget` read them as negatives, so a crash silently poisoned the training
  labels.

## What the bug was identified to be
1. A wrapper of a project protocol did not accept the protocol's full signature. It was
   written before `content_type` existed and was never updated.
2. The oracle loop's bookkeeping was not crash-safe: the "nobody looked yet" state was
   NULL, which reads as a label.

## Root cause analysis
Five Whys:
1. *Why did the probe crash?* `_CostCounter.send` had no `content_type` parameter.
2. *Why was it missing?* When `Sender` gained `content_type`, the implementations named
   in the docs were updated (`SeamProbeSender`, `RequestsProbeSender`), and so was the
   wrapper next to the change (`_CountingSender`). The oracle-internal wrapper was not
   found.
3. *Why was it not found?* Nothing enumerated the seam's implementations. Each was found
   by memory or by grep for the class names someone already knew.
4. *Why did no test catch it?* No test ran the bandit path over a content-typed point,
   and no test compared each implementation's signature with the protocol.
5. *Why did the crash corrupt labels?* The status write was placed after the loop, and
   the pre-loop state (NULL) has a labelled meaning.

**Root cause:** protocol conformance was maintained by hand, so a wrapper drifted from
the protocol. Separately, the oracle loop's "not yet checked" state was a value that
reads as a label.

## Corrective action
- **CC-FUZZ-0056:**
  - `_CostCounter.send(..., content_type=None)` forwards `content_type` only when set,
    with the same three-branch shape as `_CountingSender`.
  - Crash safety in `run_pipeline`: one committed write **before** the loop sets
    `no_confirmer` rows to their final status and every confirmable row to `pending`.
    The loop runs in `try/finally`, and the `finally` writes the statuses gathered so
    far, then the error re-raises.
- **CC-CORE-0033:** `core.oracle_status.PENDING = "pending"`, a member of `UNLABELLED`.
  Pending rows are never training labels, but are still scored and ranked.
- **CC-UI-0048:** the run page's Oracle-coverage card counts pending rows ("run
  interrupted before the oracle reached them").
- **Tests:**
  - `tests/test_sender_conformance.py` finds every class in `fuzzlab/` whose `send`
    takes `(self, url, param, value, …)` by AST. It asserts each one's parameters and
    defaults ⊇ `Sender.send`'s, and that each wrapper (delegating to `self._inner.send`)
    forwards every non-default protocol argument. Both guards are proven on synthetic
    wrappers: one lacking `content_type`, one dropping it.
  - `tests/test_pipeline_invariants.py`:
    - a bandit run over a JSON-body point completes, and `content_type` reaches the
      sender;
    - a mid-loop raise with a no-confirmer row: the reached row is `checked`, the
      no-confirmer row is `no_confirmer`, unreached rows are `pending`, no row is
      NULL, and `build_dataset` labels only the reached row;
    - a budgeted crash leaves every row `pending`.
  - All of these fail on the pre-fix code (verified on a copy).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0039 / PA-0041** ("when a project maintains more than one implementation of the
  same seam, a security-relevant transport setting adopted in one must be applied to
  every other implementation in the same change"). **Same class:** implementations of
  the `Sender` seam drifted apart.

**Result:** a recurrence. A prior-PA failure analysis follows.

## Prior-preventive-action failure analysis
**PA-0041 was too narrow, and not enforced:**
- **Too narrow:** it covered "security-relevant transport settings" (redirects, TLS,
  timeouts) on *senders*. It did not cover the seam's **signature**, or **wrappers**
  of the seam: `_CostCounter` sends nothing itself.
- **Not enforced:** it relied on whoever changed the seam remembering every
  implementation. The implementation that drifted was the one nobody listed.

## Preventive action
**PA-0072** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0041:
1. **Every implementation or wrapper of a project protocol accepts the protocol's full
   signature and forwards every argument it accepts.**
2. **Enforced by discovery, not by a list.** For `Sender`,
   `tests/test_sender_conformance.py` finds implementations by shape, checks signatures
   against the protocol, and calls each wrapper against a recording inner sender.
3. **A loop that writes per-row state writes a non-label "pending" state first and
   flushes in a `finally`.** A crash must never leave a value that reads as a label.

**Sweep (PA-0002):**
- **`send` seam:** `_CostCounter` was fixed. `_CountingSender`, `SeamProbeSender`,
  `RequestsProbeSender` and the `Sender` protocol itself conform, as the test asserts.
  `proxycontrol.send(tab_id, …)`, `proxy/repeater.send` and `core/http.send(request)`
  are different protocols, not this seam.
- **Per-row status writers:** `run_pipeline` was fixed. Any other loop writing
  `oracle_status` would go through it; it is the only writer of that column.
- **Other NULL-means-labelled states:** `candidate.oracle_status` is the only status
  whose NULL has a label meaning. Every reader goes through `UNLABELLED`, swept by grep:
  `ml/dataset.py`, `ml/train.py`, `web/mlview.py`, `web/results.py`.
