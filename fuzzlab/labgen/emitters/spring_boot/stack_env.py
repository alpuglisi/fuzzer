"""``StackEnv`` for the ``spring_boot`` stack (`CC-LAB-0090`, category 3's
Atlassian pick).

Mirrors ``fuzzlab.labgen.emitters.php_laravel.stack_env``'s ``StackEnv``
shape (Addendum D field-for-field) but is package-local, same scoping
rationale that module's docstring already gives -- no shared ``StackEnv``
type exists in ``fuzzlab.labgen.schema`` yet for any stack to import.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StackEnv:
    language: str
    framework: str
    framework_version: str
    #: Digest-pinned, e.g. ``"eclipse-temurin:21-jre-alpine@sha256:<64 hex>"``.
    #: Resolved live against the Docker Hub registry API on 2026-09-22 (a
    #: real anonymous-token + manifest-list HEAD, same method
    #: ``python_fastapi``'s own ``StackEnv`` build documented) -- not guessed.
    base_image: str
    workdir: str
    entrypoint_cmd: tuple[str, ...]
    is_multi_file: bool
    scaffold_files: tuple[str, ...] = field(default_factory=tuple)
    #: Empty here -- Spring Boot's own classpath component scan discovers
    #: every ``@RestController`` under ``com.fuzzlab.trackernest`` with no
    #: central routes file to accumulate into, the same reasoning
    #: ``python_fastapi``'s ``StackEnv`` gives for its own empty
    #: ``accumulators`` (a static package-discovery scaffold, not a per-cell-
    #: fed accumulator file).
    accumulators: tuple[str, ...] = field(default_factory=tuple)
    file_roles: dict[str, str] = field(default_factory=dict)


#: Spring Boot 4.1.1 -- the latest stable release on Maven Central as of
#: 2026-09-22 (`4.2.0-M1` is a pre-release milestone, not used); matches
#: `stack/skeleton/pom.xml`'s `spring-boot-starter-parent` version exactly.
#: See `stack/README.md` for the resolution command.
SPRING_BOOT_VERSION = "4.1.1"

#: `eclipse-temurin:21-jre-alpine`, digest-pinned per decision D7's
#: convention -- resolved live against the Docker Hub registry API
#: (anonymous pull token + `Accept: application/vnd.docker.distribution.
#: manifest.list.v2+json` HEAD, reading the `Docker-Content-Digest` response
#: header) on 2026-09-22, matching the pinned Java 21 this stack's `pom.xml`
#: targets.
_BASE_IMAGE_TAG = "eclipse-temurin:21-jre-alpine"
_BASE_IMAGE_DIGEST = "sha256:1a29e1fe337eb28b5bec30f0ee8ed29f0ff80ab6f75dcf9313efe82911065a52"
BASE_IMAGE = f"{_BASE_IMAGE_TAG}@{_BASE_IMAGE_DIGEST}"

WORKDIR = "/app"
#: Matches `fuzzlab.labgen.conformance.live_boot_spring_boot`'s own real
#: boot command shape (`java -jar trackernest.jar`); a future Dockerfile for
#: this stack (out of this entry's scope, see `CC-LAB-0090`'s "Out of scope"
#: section) would use this literally as its `ENTRYPOINT`.
ENTRYPOINT_CMD: tuple[str, ...] = ("java", "-jar", "trackernest.jar")

SPRING_BOOT_STACK_ENV = StackEnv(
    language="java",
    framework="spring_boot",
    framework_version=SPRING_BOOT_VERSION,
    base_image=BASE_IMAGE,
    workdir=WORKDIR,
    entrypoint_cmd=ENTRYPOINT_CMD,
    is_multi_file=True,
    scaffold_files=("pom.xml", "src/main/resources/application.properties"),
    accumulators=(),
    file_roles={
        "controller": "src/main/java/com/fuzzlab/trackernest/generated/{cell_slug}.java",
    },
)
