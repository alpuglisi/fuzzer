# Plugin System — Requirement Specification

Component code: **PLUG** · Status: `[planned]` (Phase 10) · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #13; `DECISIONS_AND_ROADMAP.md` (D6, Phase 10);
`./change-control.md`.

## 1. Purpose
Let the toolkit be extended — ML models, extra rules, custom oracles, payload
sources — without changing core code, via a registry of hooks on `core/`.

## 2. Scope
- **In:** entry-point discovery, a hook registry, per-plugin isolation and
  priority.
- **Out:** the plugins themselves (ML components, rules, oracles) — they are
  consumers of this system.

## 3. Functional requirements
- **FR-PLUG-1** Discover plugins via `importlib.metadata` entry points.
- **FR-PLUG-2** Provide a hook registry: `on_request`, `on_response`,
  `on_candidate`, `on_finding`, `register_rules`, `register_payload_source`,
  `register_oracle`.
- **FR-PLUG-3** Isolate plugins so one plugin's failure does not crash a run
  (errors are contained and logged).
- **FR-PLUG-4** Support deterministic ordering via per-plugin priority.
- **FR-PLUG-5** Enforce that plugins honor the oracle/advisory split: a plugin may
  `register_oracle` but ML-style plugins write scores/uncertainty, not `finding`
  labels.

## 4. Non-functional requirements
- **NFR-PLUG-optional** The toolkit runs fully with zero plugins; enabling ML or
  extra rules is a config/packaging change, not a core edit (D6).
- **NFR-PLUG-safe** Plugins run in-process but are contained; a misbehaving plugin
  is disabled rather than allowed to corrupt the store.
- **NFR-PLUG-reproducible** The set and versions of active plugins are recorded
  onto the run.

## 5. Interfaces and data contracts
Exposes the hook API from `core/`; plugins register against it. Plugins read/write
the store only through `core/` interfaces, subject to the same contract (e.g. only
an oracle may write `finding`).

## 6. Dependencies (components)
`core/`.

## 7. Acceptance criteria
- A sample plugin registers on each hook and runs at the right point.
- A failing plugin is contained and logged without aborting the run.
- Active plugins/versions are recorded on the run; running with none works.

## 8. Open questions
- Trust model for third-party plugins (this is a lab tool; how much isolation is
  warranted).
- Whether hooks need an async variant for the proxy data path.
