# `java_spring_boot` skeleton — provenance

**Source:** a real `pom.xml` inheriting `spring-boot-starter-parent` 3.4.1
(the standard Spring Boot Maven-project convention, the JVM equivalent of
`rails new`/`express-generator`'s generated output) with exactly one
dependency, `spring-boot-starter-web`, resolved for real against Maven
Central through this sandbox's proxy on 2026-09-22 (`mvn package`
succeeded, producing a real bootable jar; a raw, unauthenticated `curl`
against Maven Central directly returned a real `429` during this same
session's research — the checked-in harness always uses the real `mvn`
client, never a raw HTTP probe, for exactly this reason). `Application.java`
and `PlaybackResumeRequest.java` are new, hand-written.

**Trim list:** none beyond dependency choice. No GraphQL/DGS dependency
(`spring-boot-starter-graphql`, the Netflix DGS framework itself) is
included in this Phase A skeleton — see `CC-LAB-0091`'s change-control
entry for the explicit scope call (the CWE-502 shape this stack's Phase A
proves lives in *how a request body is deserialized*, not in GraphQL's own
query-execution model; the GraphQL/DGS federation layer is Phase B work).
No test-scaffolding/dev-tools dependencies were added in the first place
(unlike a fuller IDE-driven Spring Initializr export might include), so
there is nothing to strip.

**The package/component-scan convention every generated cell relies on.**
`Application.java` (`@SpringBootApplication`) lives at `com.fuzzlab.lab`,
whose default component scan covers that package and every subpackage.
Every cell `fuzzlab.labgen.emitters.java_spring_boot.JavaEmitter` renders
is hardcoded to declare `package com.fuzzlab.lab.cells;` — a subpackage of
the scanned root — so it is always discovered as a `@RestController` bean
at boot, without a router/accumulator file (Spring Boot needs none; see
that emitter package's own module docstring for the full architectural
rationale).

**`PlaybackResumeRequest.java`** is the fixed, closed DTO class the secure
twin's Jackson deserialization targets (`jackson_typed_allowlist_deserialize`)
— a plain POJO with three fields (`profileId`, `eventType`, `positionMs`)
and JavaBean getters/setters, the shape Jackson's default bean
deserializer binds to without any polymorphism.

**What is deliberately *not* here yet (Phase B, not this dispatch):** a
per-run database (this Phase A's one illustrative cell is stateless — see
`CC-LAB-0091`'s explicit scope call), the GraphQL/DGS federation layer and
its CWE-862 field-authorization pick
(`docs/research/site-architecture-survey-functionality-netflix.md` §2),
and any actual `ysoserial`-style gadget chain on the classpath (this Phase
A's vulnerable twin demonstrates the unsafe deserialization *API call
shape*, `activateDefaultTyping()`, not a working RCE payload — matching
this project's own existing `insecure-deserialization` corpus convention).
