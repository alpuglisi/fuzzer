# Target Lab and Ground Truth — Change Control Log

Component code: **LAB**. Entry format and required fields: see
`../README.md`. Newest first.

### CC-LAB-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — the Puppy Fort Factory app
  (~30 pages, ~10 JavaScript-rendered) with a hand-written `VULNERABILITIES.md`,
  deployed by copy-to-webroot on a bare Fedora host.
- Impact (other components / project): the crawler, auditor, and fuzzer target
  this app; ground truth is currently prose, which the integration harness cannot
  consume, so automated scoring is not yet possible.
- Risk (level; mitigation): low. Hand-maintained labels can drift from the app;
  mitigated going forward by the machine-readable label contract (D9) and the
  manifest-driven generator (D8), and by pinning the environment (D7).
- Deliverables:
  - [x] Vulnerable app built and deployed — done.
  - [x] Human-readable vulnerability map — done.
  - [ ] Machine-readable label contract — todo (Phase 0 T0.6).
  - [ ] Containerize with pinned versions — todo (Phase 0 T0.2).
  - [ ] Grey-box instrumentation — todo (Phase 3).
  - [ ] Manifest-driven generator — todo (Lab track).
- Effectiveness (assessed or pending): pending — this is the baseline record.
