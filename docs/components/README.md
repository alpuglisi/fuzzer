# Component documentation

Each primary component in `docs/ARCHITECTURE.md` has two documents in its folder
here:

- **`requirements.md`** — the component's requirement specification: purpose,
  scope, functional and non-functional requirements (with stable IDs),
  interfaces and data contracts, component dependencies, and acceptance criteria.
- **`change-control.md`** — the component's change-control log.

## How the component change-control log differs from the root CHANGELOG

The root `CHANGELOG.md` is a **high-level project history**: what changed and
why, across the whole project. The component change-control logs are
**lower-level and per-component**, and each entry is a controlled record with a
fixed set of assessments (below). A single project change may produce one root
CHANGELOG line and several component change-control entries.

## Required fields for every change-control entry

Every time a component changes, add an entry with all of these:

1. **ID and date** — `CC-<CODE>-NNNN`, newest first.
2. **Change** — outline what changed.
3. **Impact assessment** — effect on other components and on the project as a
   whole (name the components; note contract/interface changes).
4. **Risk assessment** — the risk level; if the risk is substantial, how it is
   mitigated, or a justification for accepting it.
5. **Deliverables** — the tasks the change requires, each with a completion
   status (`todo` / `in-progress` / `done`).
6. **Effectiveness** — assessed after the change lands: did it achieve its
   intent, with evidence. Left as `pending` until it can be judged.

## Entry template (copy for each change)

```
### CC-<CODE>-NNNN — <short title> (YYYY-MM-DD)
- Change:
- Impact (other components / project):
- Risk (level; mitigation or accepted-risk justification):
- Deliverables:
  - [ ] <task> — <status>
- Effectiveness (assessed <date> or pending):
```

## Component index

| # | Component | Code | Folder |
| --- | --- | --- | --- |
| 1 | Target lab and ground truth | LAB | `01-target-lab/` |
| 2 | `core/` shared library | CORE | `02-core-library/` |
| 3 | Session manager | SESS | `03-session-manager/` |
| 4 | Crawler / spider | CRAWL | `04-crawler/` |
| 5 | Auditor / fetcher | AUD | `05-auditor/` |
| 6 | Indicator database and payload catalogs | IND | `06-indicator-db-and-catalogs/` |
| 7 | Fuzzing harness and oracle | FUZZ | `07-fuzzing-harness-and-oracle/` |
| 8 | Payload scheduler (bandit) | SCHED | `08-payload-scheduler/` |
| 9 | Mutation engine | MUT | `09-mutation-engine/` |
| 10 | ML components | ML | `10-ml-components/` |
| 11 | Intercepting proxy | PROXY | `11-intercepting-proxy/` |
| 12 | Diagnostics and UI | UI | `12-diagnostics-and-ui/` |
| 13 | Plugin system | PLUG | `13-plugin-system/` |
