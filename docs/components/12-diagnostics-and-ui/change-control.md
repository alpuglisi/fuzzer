# Diagnostics and UI — Change Control Log

Component code: **UI**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-UI-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  today's observability is per-tool stdout plus the root `CHANGELOG.md`/
  `ERROR_LOG.md`.
- Impact (other components / project): read-only over the store, so it adds no
  hard dependency for any tool; it relies on `core/`'s store and structured
  logging existing. Adds a `run_metrics` table to the store contract. Realizes the
  research-platform diagnostics posture (D2) used to verify functionality and find
  bugs.
- Risk (level; mitigation): low — read-only and off the data path. Main risk is
  rendering secrets; mitigated by redaction-on-write in `core/` and a
  render-redacted-only rule here.
- Deliverables:
  - [ ] `textual` TUI for live runs/interception — todo.
  - [ ] Datasette-over-the-store exploration — todo.
  - [ ] `run_metrics` table — todo.
  - [ ] Structured audit/debug logs (`run_id`/`tool`/`identity`/`flow_id`) — todo.
  - [ ] `--dry-run` mode — todo.
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  whether a live run is legible in the TUI and bugs are locatable from the store
  and logs without instrumenting each tool by hand.
