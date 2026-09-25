# Target-lab web tier: Spring Boot serving one of the three generated
# `spring_boot` apps (TrackerNest/ReelQueue/WanderFare). CC-LAB-0247 (Lane 7,
# §2b). Three stages: `gen` runs the real generator
# (`fuzzlab.labgen.emitters.spring_boot.assemble_spring_boot_app`, the same
# assembly `SpringBootLiveBootHarness`'s own `app=` mode uses -- PA-0027) to
# produce the Java source tree for `APP`; `build` runs a real `mvn package`;
# the final stage is a minimal JRE runtime for the built jar. No database
# (matches every other spring_boot app's own live-boot harness scope).
#
# `ARG APP` has NO default -- unlike PFF's own `web.Dockerfile`, there is no
# single "default" spring_boot app (three siblings, no natural default), so
# a build without `--build-arg APP=...` fails loud at the `gen` stage rather
# than silently picking one.
#
# Build context is the REPO ROOT (`lab/compose.yaml`'s `build.context: ..`).

FROM python:3.12-slim AS gen
ARG APP
WORKDIR /src
COPY . /src
RUN test -n "$APP" || (echo "APP build-arg is required (one of trackernest/reelqueue/wanderfare)" >&2 && exit 1)
RUN pip install --no-cache-dir -e . \
    && python3 -c "from fuzzlab.labgen.emitters.spring_boot import assemble_spring_boot_app; assemble_spring_boot_app('$APP', '/app')"

# pom.xml pins `<java.version>21</java.version>` -- matches this build
# stage's JDK exactly.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY --from=gen /app /app
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
# Every spring_boot app's pom.xml shares the same `trackernest` artifactId
# (`assemble_spring_boot_app` only varies each app's rendered site/cell
# content, not its Maven coordinates or Java package -- see
# `SpringBootEmitter.render_site`'s hardcoded `com.fuzzlab.trackernest.*`
# package, confirmed by reading it during this Dockerfile's own authoring),
# so the built jar's name is the same regardless of `APP` -- globbed rather
# than hardcoded so this Dockerfile does not silently break if that ever
# changes.
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080

# `server.address` is not forced to 127.0.0.1 (the handoff plan's original
# assumption, corrected here after live verification): Spring Boot's own
# default is already 0.0.0.0, exactly what a container's published port
# needs to be reachable from the host's port-forwarding path -- binding to
# 127.0.0.1 *inside* the container would make it unreachable from outside
# the container's own network namespace (verified live building the other
# stacks' Dockerfiles). The loopback-only guarantee is enforced by the
# compose/`docker run` host-side bind (`127.0.0.1:<host>:8080`), not by
# this process's own listen address. `--server.address=0.0.0.0` is passed
# explicitly anyway, purely as documentation of that decision, not a
# behavior change from Spring Boot's own default.
CMD ["java", "-jar", "app.jar", "--server.port=8080", "--server.address=0.0.0.0"]
