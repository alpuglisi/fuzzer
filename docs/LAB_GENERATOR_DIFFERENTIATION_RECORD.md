# Lab generator — architectural differentiation record

Evidence-based record that the manifest-driven lab generator's design (see
`docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md`)
is independently architected, not derived from any of the other
deliberately-vulnerable-app/benchmark projects this project's own docs cite
as general "spirit" precedent. Nothing in this project has ever copied code,
templates, or text from any project below, and this record exists to make
that an evidenced claim rather than an assumption. Sourced from a dedicated
research pass (2026-09-21) that cloned and read most of the projects below
directly — see the provenance marker on each row.

**Provenance markers:** **[M]** = measured — read directly from a cloned
repository or fetched artifact during that research pass. **[D]** = per the
project's own documentation/README/license text as quoted. **[S]** =
third-party/secondary description, weakest evidence.

## Licensing

| Project | License | Evidence | Consequence |
|---|---|---|---|
| OWASP Benchmark | GPL-2.0 | **[M]** — `LICENSE` verbatim GPL-2.0 text; per-file headers | Copyleft. Read-only, never adapted. |
| DVWA | GPL-3.0 | **[M]** — `COPYING.txt` verbatim GPL-3.0 | Copyleft. Read-only. |
| Mutillidae II | GPL-3.0 | **[M]** — `LICENSE` verbatim GPL-3.0 | Copyleft. Read-only. |
| WebGoat | GPL-2.0-or-later | **[M]** — `LICENSE.txt` SPDX identifier, per-file headers match | Copyleft. Read-only. |
| XVWA | GPL-3.0 | **[M]** — `LICENSE` verbatim GPL-3.0 | Copyleft. Read-only. |
| **bWAPP** | **CC BY-NC-ND 4.0** | **[M, third-party mirror]** — license notice embedded in the project's own page-footer markup | **Not open source** — NoDerivatives forbids distributing any modified version at all, stricter than GPL. **Cite as inspiration only; derive nothing, not even with attribution.** |
| **Google Gruyere** | **CC BY-ND 3.0 US** | **[D]** — credits text carried in redistributions, © Google Inc. | **Not open source** — same NoDerivatives consequence as bWAPP. |
| NIST VTSG (our acknowledged architectural basis) | MIT | **[M]** | Schema/methodology adapted with attribution; no code reused. |
| BaxBench (cited for the multi-file-routing question) | MIT | **[M]** | Methodology (its `Env`/`Scenario` decomposition) referenced; no code reused. |
| OpenAPI Generator (cited for template-cardinality vocabulary) | Apache-2.0 | **[D]** | Methodology (template cardinality) referenced; no code reused. |

**The finding worth flagging on its own:** bWAPP and Gruyere are routinely
described — including by bWAPP's own README — as "free and open source."
Under the OSI definition they are not: NoDerivatives fails the modification
requirement, and forbids derivation more strictly than the GPL projects
above (which at least permit derivation under copyleft obligations). This
project's posture toward both is stricter than toward the GPL-licensed
projects: cite as inspiration, derive nothing at all.

## Architecture comparison

| Axis | OWASP Benchmark | DVWA | Mutillidae II | WebGoat | bWAPP | XVWA | Google Gruyere | **Ours** |
|---|---|---|---|---|---|---|---|---|
| **Verdict model** | Asserted — literal `true`/`false` in a CSV column **[M]** | Asserted by filename (`impossible.php`) **[M]** | Asserted by `switch` arm on session level **[M]** | Asserted by lesson design; judged **in-app** by `AttackResult` **[M]** | Asserted by level cookie **[D]** | Asserted implicitly — every page vulnerable **[M]** | Asserted by codelab answer key **[D]** | **Derived** — pure `verdict(transform pipeline, sink context, matrix version)`, never hand-written |
| **Code organization** | 2,740 checked-in servlets + 1 HTML form each + 15 shared helpers; **no generator in the repo** **[M]** | Hand-authored PHP, 4 files × 19 classes **[M]** | Hand-authored PHP, 63 pages, inline switch **[M]** | 32 Spring `@Component` lesson plugins, convention-discovered **[M]** | Hand-authored PHP, ~100 bugs **[D]** | Hand-authored PHP, 16 classes **[M]** | Hand-authored Python **[D]** | **Generated** by module composition from a manifest |
| **Pairing** | **Latent only** — 110/400 consecutive-ID pairs >90% similar, best pair 98.7% (16-line diff) — **no pairing field in the contract** **[M]** | Difficulty ladder; differs by more than a transform; undeclared **[M]** | Ladder via switch arms; undeclared **[M]** | `mitigation` lessons are separate lessons, not twins **[M]** | Ladder via level; undeclared **[D]** | None **[M]** | None **[D]** | **Declared minimal pairs**, diff-gated across the whole twin's file set, transform-only difference |
| **Machine-readable ground truth** | **Yes** — `expectedresults-1.2.csv`, 4 columns, 2,740 rows, asserted **[M]** | None **[M]** | None **[M]** | None — app self-reports **[M]** | None **[D]** | None **[M]** | None **[D]** | **Out-of-band contract**, opaque IDs, derived verdicts, sink/transform/stack/pair metadata |
| **Oracle** | None in repo **[M]** | None (smoke test only) **[M]** | None **[M]** | **In-band**, inside the vulnerable app **[M]** | None | None **[M]** | None | **Out-of-band dynamic oracle** — vulnerable confirmed exploitable, secure twin confirmed not |
| **Routing** | `@WebServlet` annotation inside the case file **[M]** | Filesystem path **[M]** | Filesystem path **[M]** | `@PostMapping` on `@RestController` **[M]** | Filesystem path **[D]** | Filesystem path **[M]** | Python handlers **[S]** | Framework-native, multi-file, per-stack `StackEnv` + accumulator route file (see CR-LAB-0001 Addendum D) |

**The defensible claim, stated precisely:** no cited precedent derives its
verdict, declares minimal pairs, or combines an out-of-band machine-readable
contract with an out-of-band dynamic oracle. This design does all three,
and none of its code, templates, or text is derived from any project above.

**Two claims this record explicitly avoids making, because the evidence
contradicts them** — precision here matters more than a stronger-sounding
claim, since a reader who checks will find the counterexample quickly:

- *Not* "existing benchmarks have no machine-readable ground truth" —
  OWASP Benchmark does. Say **asserted**, not absent.
- *Not* "existing benchmarks have no vulnerable/secure pairs" — OWASP
  Benchmark has latent near-twins and DVWA has a difficulty ladder. Say
  **undeclared and unconstrained**, not absent.

## Open gaps in this record

1. **The tool that produced OWASP Benchmark's 2,740 test cases was not
   found.** It is not in the `BenchmarkJava` repository (a measured
   absence, not proof none ever existed) and was not located elsewhere in
   the OWASP-Benchmark org during this pass. If a stronger differentiation
   record is ever needed, this is the remaining gap worth closing.
2. **bWAPP's license was read from a third-party GitHub mirror**, not the
   canonical SourceForge distribution — the notice matches the project's
   own published statements, but this is the single weakest evidentiary
   link here. Verify against the canonical release before relying on this
   formally (e.g. in a public-facing statement).
3. **Gruyere's license is documentation-only**, relying on credits text
   carried in redistributions rather than Google's canonical codelab
   download. Same recommendation: verify at source if this record is ever
   relied on formally.

See `CR-LAB-0001` Addendum D for how this record's architectural findings
(specifically the multi-file-routing comparison against BaxBench and
OpenAPI Generator) changed the generator's module schema.
