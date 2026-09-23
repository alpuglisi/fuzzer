# `spring_boot` `StackEnv` — skeleton provenance

Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9 (category 3, the
Atlassian pick) and `docs/components/01-target-lab/change-control.md`'s
`CC-LAB-0130`.

## `skeleton/`

The real, minimal, bootable Spring Boot project the live-boot conformance
harness (`fuzzlab/labgen/conformance/live_boot_spring_boot.py`) overlays a
manifest's generated content onto — the same role `php_laravel/stack/skeleton/`
plays for that stack, following **its** provenance convention specifically
(verified during this entry's pre-change review: `node_express`'s own
`scaffold/` directory has no equivalent provenance README or "real generated
output, trimmed" story — this skeleton does not claim to follow that one).

**Provenance — one real deviation from the usual method, stated plainly.**
The normal way to produce this shape is Spring Initializr
(`https://start.spring.io`), the same way `php_laravel`'s skeleton is a real
`composer create-project laravel/laravel` output. Spring Initializr's own
web endpoint (`start.spring.io`) is **not reachable from this build
sandbox** (`curl https://start.spring.io/starter.zip` fails the outbound
proxy with `CONNECT tunnel failed, response 403` — confirmed, not assumed,
on 2026-09-22) — that proxy's allowlist covers `repo.maven.apache.org` (this
stack's actual dependency source) but not the Initializr web service. This
skeleton is therefore **hand-authored to the exact shape Spring Initializr
would produce for this dependency set** (`spring-boot-starter-parent`,
`spring-boot-starter-web`, Java 21, Maven build) — a minimal `pom.xml`, one
`@SpringBootApplication` class, one `application.properties` — rather than
copied from a real generator run. Every dependency coordinate/version in
`pom.xml` is real and was resolved live against Maven Central on
2026-09-22, not guessed:

```sh
curl https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/maven-metadata.xml
# -> latest stable release line: 4.1.1 (4.2.0-M1 is a pre-release milestone, not used)
curl https://repo.maven.apache.org/maven2/ognl/ognl/maven-metadata.xml
# -> latest stable release: 3.4.13 (3.5.0-BETAx line is pre-release, not used)
```

A real, bounded HTTPS GET through this sandbox's configured proxy to
`repo.maven.apache.org/maven2/org/springframework/boot/spring-boot/maven-metadata.xml`
returns `200` — confirmed on 2026-09-22 (see `CC-LAB-0130`'s change-control
entry for the exact command) — so a real `mvn package` against this `pom.xml`
is buildable in this environment; only the Initializr *convenience* endpoint
itself is unreachable, not Maven Central dependency resolution.

**If a future session gets Initializr access** (a different sandbox/proxy
config): the correct fix is to regenerate this skeleton for real
(`curl https://start.spring.io/starter.zip?...` with the same coordinates
above) and diff it against this hand-authored version, updating this README
accordingly — not to silently leave the substitution undocumented.

**OGNL dependency.** `ognl:ognl:3.4.13` is declared for real (not a
lab-invented library) — the same library the real Confluence
CVE-2021-26084/CVE-2022-26134 OGNL-injection RCEs exploited. See
`docs/research/category3-saas-functionality-and-cwe-research.md` §4 for the
full citation and why this is the stack-idiomatic choice for TrackerNest's
SSTI cell.

## SBOM

`syft` is not installed in this build sandbox (same situation
`python_fastapi`'s own `StackEnv` build documented — see that package's
`__init__.py` module docstring). Per the same "skip, don't block, document
the intended command" convention:

```sh
syft dir:fuzzlab/labgen/emitters/spring_boot/stack/skeleton -o cyclonedx-json \
    > fuzzlab/labgen/emitters/spring_boot/stack/sbom.cdx.json
```

Not yet run; tracked as a follow-up once `syft` is available in a build
environment.
