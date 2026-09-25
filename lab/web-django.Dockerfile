# Target-lab web tier: Django serving the generated `django` (PicTrail) lab
# app. CC-LAB-0247 (Lane 7, §2b). Two stages, mirroring `lab/web.Dockerfile`'s
# own shape: a `gen` stage runs the real generator
# (`fuzzlab.labgen.emitters.django.assemble_django_app`, the same assembly
# procedure `fuzzlab.labgen.conformance.django_live_boot.
# DjangoLiveBootHarness._assemble()` uses -- PA-0027, never a second,
# hand-maintained copy) to produce the app tree; the real stage installs the
# pinned Django release and serves it for real.
#
# Build context is the REPO ROOT (see `lab/compose.yaml`'s
# `build.context: ..`), same reason as `web.Dockerfile`: the `gen` stage
# needs `fuzzlab/` importable.
#
# No seed data (Lane 7 Gate D's own scope call, recorded in
# `docs/LAB_LANE7_INTEGRATION_PLAN.md`'s Gate D report): the live-boot
# harness's `_seed_db()` inserts rows via a direct sqlite3 connection as a
# *test-only* convenience for that harness's own assertions, not a shared,
# importable helper -- copying its SQL into this image would be a second,
# hand-maintained copy of harness-internal test logic (PA-0027), and an
# empty database still proves this container boots and serves every page
# (a browsable-app/S10 build-and-boot proof does not require realistic
# content, unlike PFF's own seeded MariaDB, which is seeded via a
# shared `sql/schema.sql` this stack has no equivalent of).

FROM docker.io/library/python:3.12-slim AS gen
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -c "from fuzzlab.labgen.emitters.django import assemble_django_app; assemble_django_app('/app')"

FROM docker.io/library/python:3.12-slim

# Matches `fuzzlab.labgen.conformance.django_live_boot.DJANGO_PIN`/`REQUESTS_PIN`
# exactly (the link-preview SSRF shape's generated view imports `requests`,
# already a declared project dependency) -- one pinned pair, not
# independently re-derived (PA-0003/PA-0021).
RUN pip install --no-cache-dir django==5.2.17 "requests>=2.31,<3"

WORKDIR /app
COPY --from=gen /app /app

RUN python3 manage.py migrate --no-input

EXPOSE 8000

# `HOST` defaults to 0.0.0.0 here (unlike the live-boot harness's own direct
# host-process boot, which forces 127.0.0.1 -- CLAUDE.md's Safety section is
# about this container's *published* port never reaching beyond loopback,
# enforced by the compose/`docker run` host-side bind
# (`127.0.0.1:<host>:<container>`), not by this process's own listen
# address. Binding this process itself to 127.0.0.1 *inside* the container
# would make it unreachable from the host's port-forwarding path entirely
# (verified live building this Dockerfile) -- the opposite of what D11
# wants, since it would make the loopback-only publish silently boot but
# never actually serve anything.
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000", "--noreload"]
