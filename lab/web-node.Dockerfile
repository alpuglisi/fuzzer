# Target-lab web tier: Node/Express serving the generated `node_express`
# (MeadowMart) lab app. CC-LAB-0247 (Lane 7, §2b/D3). Two stages: `gen` runs
# the real generator (`fuzzlab.labgen.emitters.node_express.
# assemble_meadowmart_app`, the same assembly `tests/_meadowmart_app.py`'s
# own test harness uses -- PA-0027) to produce the app tree; the real stage
# mirrors `fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile` (Lane
# 6's own generic Tier-A scaffold, built-and-booted standalone for the first
# time in this same Gate D -- see that file's own history) so the two share
# one base image / install / runtime recipe, not two independently
# maintained ones.
#
# Build context is the REPO ROOT (`lab/compose.yaml`'s `build.context: ..`).

FROM python:3.12-slim AS gen
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -c "from fuzzlab.labgen.emitters.node_express import assemble_meadowmart_app; assemble_meadowmart_app('/app')"

# Digest-pinned per CR-LAB-0001 Addendum D (node:22-bookworm-slim, live-
# verified `linux/amd64` -- see the scaffold Dockerfile's own comment for
# how/when this was confirmed).
FROM node@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2

LABEL org.opencontainers.image.title="fuzzlab-lab-node-express" \
      org.opencontainers.image.description="fuzzlab lab-only Node/Express Tier-A vulnerable app (MeadowMart) -- loopback-only, never exposed" \
      lab.fuzzlab.authorized-only="true"

WORKDIR /app
COPY --from=gen /app/package.json /app/package-lock.json ./
RUN npm ci --omit=dev
COPY --from=gen /app .

# Express's own built-in error handler writes `err.stack` into the response
# unless NODE_ENV=production (docs/LAB_IMPLEMENTATION_PLAN.md Sec 4).
ENV NODE_ENV=production

# `app.js`'s own `app.listen(port, host)` defaults `host` to 127.0.0.1 --
# correct for a direct-host-process boot, unreachable from a container's
# published port (verified live: see `web-go.Dockerfile`'s identical note
# for the general mechanism). Explicitly overridden here; the loopback-only
# guarantee (D11) is enforced by the host-side compose bind.
ENV HOST=0.0.0.0

EXPOSE 3000

ENTRYPOINT ["node", "app.js"]
