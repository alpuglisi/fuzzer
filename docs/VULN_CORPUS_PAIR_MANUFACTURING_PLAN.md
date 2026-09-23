# Vuln corpus Phase 3 — manufactured-pair plan (not yet built)

Status snapshot as of 2026-09-23. This is the concrete gap analysis and execution
plan for the one remaining unchecked Phase 3 item in
`docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Status section:

```
- [ ] Phase 3: manufactured pairs generated (floor met per CWE — see "Pair generation")
```

Nothing in this file has been built yet — this is the plan, saved so the next
session (or this one, later) can pick it up without re-deriving the gap analysis.

## Floor rule (from `docs/VULN_CORPUS_EXPANSION_PLAN.md`, "Pair generation")

Per (feature+language cell, CWE): generate manufactured pairs until natural +
manufactured pairs reach `max(2, ceil(available_examples / 2))`. A naturally
collected pair (the wild genuinely offered both a vulnerable and a fixed
real-world example) counts toward the floor — only the shortfall between what's
naturally paired and the floor needs deliberate alteration.

## Gap analysis (computed directly from all 35 collected manifests)

| Feature | Lang | CWE(s) | vuln | idiom | natural pairs | floor | gap |
|---|---|---|---|---|---|---|---|
| access-control | python | CWE-639/CWE-862/CWE-915 | 1 | 0 | 0 | 2 | **2** |
| access-control | python | CWE-639/CWE-862 | 0 | 1 | 0 | 2 | **2** |
| auth-session | node | CWE-347 | 1 | 1 | 1 | 2 | **1** |
| auth-session | node | CWE-330/CWE-338 | 1 | 1 | 1 | 2 | **1** |
| auth-session | php | CWE-347/CWE-757 | 1 | 1 | 1 | 2 | **1** |
| auth-session | php | CWE-330/CWE-640 | 1 | 1 | 1 | 2 | **1** |
| auth-session | php | CWE-287/CWE-613/CWE-863 | 1 | 1 | 1 | 2 | **1** |
| auth-session | python | CWE-347 | 1 | 1 | 1 | 2 | **1** |
| auth-session | python | CWE-330/CWE-338 | 1 | 1 | 1 | 2 | **1** |
| ecommerce-logic | node | CWE-20/CWE-840 | 3 | 2 | 2 | 3 | **1** |
| ecommerce-logic | php | CWE-840 | 1 | 1 | 1 | 2 | **1** |
| ecommerce-logic | python | CWE-20/CWE-840 | 1 | 1 | 1 | 2 | **1** |
| ecommerce-logic | python | CWE-362/CWE-367 | 1 | 0 | 0 | 2 | **2** |
| file-handling | node | CWE-20/CWE-434 | 1 | 2 | 1 | 2 | **1** |
| file-handling | node | CWE-22 | 1 | 1 | 1 | 2 | **1** |
| file-handling | node | CWE-20/CWE-22/CWE-434 | 1 | 0 | 0 | 2 | **2** |
| file-handling | php | CWE-434 | 1 | 1 | 1 | 2 | **1** |
| file-handling | php | CWE-22 | 1 | 1 | 1 | 2 | **1** |
| file-handling | python | CWE-434 | 1 | 1 | 1 | 2 | **1** |
| file-handling | python | CWE-22 | 1 | 1 | 1 | 2 | **1** |
| header-injection | python | CWE-20/CWE-93 | 1 | 1 | 1 | 2 | **1** |
| insecure-deserialization | python | CWE-20/CWE-502 | 1 | 1 | 1 | 2 | **1** |
| search-export | node | CWE-89 | 1 | 1 | 1 | 2 | **1** |
| search-export | node | CWE-1336 | 1 | 0 | 0 | 2 | **2** |
| search-export | php | CWE-89 | 2 | 1 | 1 | 2 | **1** |
| search-export | php | CWE-611 | 1 | 0 | 0 | 2 | **2** |
| search-export | python | CWE-89 | 1 | 2 | 1 | 2 | **1** |
| ssrf | python | CWE-20/CWE-441/CWE-918 | 1 | 1 | 1 | 2 | **1** |
| ssti | python | CWE-1336/CWE-94 | 1 | 1 | 1 | 2 | **1** |
| ugc-xss | node | CWE-79 | 2 | 1 | 1 | 2 | **1** |
| ugc-xss | php | CWE-79 | 1 | 2 | 1 | 2 | **1** |
| ugc-xss | python | CWE-116/CWE-79 | 2 | 3 | 2 | 3 | **1** |
| webhook-signature | python | CWE-345/CWE-347 | 1 | 1 | 1 | 2 | **1** |

**Total manufactured pairs needed: 39**, across 33 (cell, CWE) groups spanning
all 12 wave-1 feature areas (access-control, auth-session, ecommerce-logic,
file-handling, header-injection, insecure-deserialization, mass-assignment,
search-export, ssrf, ssti, ugc-xss, webhook-signature) — `mass-assignment`
(node-only, 10 entries) is the one cell already fully at floor everywhere, no
gap.

**Worst gaps (zero natural pairs today, need 2 manufactured each):**
- `access-control/python` — CWE-639/862/915 split across two one-sided entries
- `ecommerce-logic/python` — CWE-362/367 (only a vulnerable side collected)
- `file-handling/node` — CWE-20/22/434 combined shape (only a vulnerable side)
- `search-export/node` — CWE-1336 (only a vulnerable side)
- `search-export/php` — CWE-611 (only a vulnerable side)

## Per-pair mechanics (from the plan's own spec)

1. Take the collected source for that (cell, CWE) — whichever role is on hand —
   and produce an altered variant that is deliberately made vulnerable (or
   fixed) to the matched CWE, using the collected code's own real
   structure/idiom as the base. The two files must differ *only* in the
   specific mechanism the CWE describes (the same minimal-pair discipline
   `fuzzlab.labgen.minimal_pair` enforces for generator output).
2. Name it `vulnerable-<n>-altered.<ext>` / `idiomatic-<n>-altered.<ext>` —
   never overwrite or rename the original collected file.
3. Add a `manifest.yaml` entry for the new file with a `derived_from` field
   pointing at the original collected file's own entry, plus the same `cwe`
   field already established for that group.
4. Validate before it counts: static-analysis tools always; dynamic execution
   through the gVisor sandbox (`fuzzlab/tools/corpus_validation_sandbox.py`,
   `CC-LAB-0084`/`FR-LAB-112`) when the check requires actually running the
   code. Report validation as "N of M", never rounded up.

## Not yet done

None of the 39 pairs have been manufactured. No code has been written for this
task beyond this plan and the gap-analysis script it was generated from.

## Execution options (pick one when scheduling this work)

1. **Sequential**: work through all 33 groups in this session, committing
   incrementally, until all 39 pairs are done and validated.
2. **One-cell proof first**: fully manufacture + validate one representative
   cell (e.g. `access-control`, which has the worst gaps) end to end, then
   check in before continuing.
3. **Workflow-parallelized**: use multi-agent orchestration to parallelize
   pair manufacturing across independent cells, then review/validate each
   before merging.
