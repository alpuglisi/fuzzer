# CC-LAB-0247 (Lane 7, Gate D/D3): byte-identical copy of this content as
# rendered by `fuzzlab.labgen.emitters.python_fastapi.render_scaffold_files()`
# (its Jinja placeholders resolved to real values by that same emitter code,
# not hand-filled here -- PA-0027). Built-and-booted live in Gate D (S10:
# this Dockerfile previously existed but had never been built or booted).
# Deliberately NOT wired into `lab/compose.yaml` (Gate E): the generic
# python_fastapi sample has no app identity and no reserved port (plan §1),
# unlike every other stack here.
#
# Target-lab web tier: Python + FastAPI serving the generated python_fastapi
# stack (Tier-A depth, CR-LAB-0001 Addendum C's "stacks 2-3 to Tier-A-only"
# pacing decision -- see docs/LAB_IMPLEMENTATION_PLAN.md Phase 3 L-P3.2).
#
# Digest-pinned per decision D7's convention (see lab/web.Dockerfile): the tag
# (python:3.12-slim-bookworm) is kept alongside the digest for readability, but the
# `@sha256:...` digest is what's actually resolved at pull time, so a rebuild
# always gets byte-identical Python/Debian userland. Digest fetched live
# against the Docker Hub registry API on 2026-09-21 (docker-content-digest
# header for the python:3.12-slim-bookworm multi-arch manifest list); re-fetch and
# update at the next scheduled base-image refresh, the same convention
# REFRESH_LOG.md already uses for the pattern corpus.
FROM docker.io/library/python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
