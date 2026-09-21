# Generated Node/Express Tier-A lab image (fuzzlab.labgen.emitters.node_express).
#
# Digest-pinned per CR-LAB-0001 Addendum D's "soft-guarantee digest-pinned +
# SBOM-recorded" rule (bit-reproducible images across runtimes is explicitly
# out of scope, per CR-LAB-0001 Sec 9 -- only the base layer's digest is
# pinned, not a promise the whole built image is byte-identical).
#
# Base image: node:22-bookworm-slim (Node 22 "Jod", active LTS as of this
# pinning -- https://nodejs.org/en/about/previous-releases). Digest below
# was read directly from a Docker Hub image-layer page for this tag
# (confirmed via web search during authoring, 2026-09-21); it was NOT
# verified with a live `docker pull` in this build environment (no Docker
# daemon here) -- re-pin before a real build with:
#   docker pull node:22-bookworm-slim && \
#     docker inspect --format='{{index .RepoDigests 0}}' node:22-bookworm-slim
# or, without pulling the full image:
#   docker buildx imagetools inspect node:22-bookworm-slim
FROM node@sha256:93a7d0e0f6a1407b7e3d83325f9efcc096ead281667613141430347a925fe918

LABEL org.opencontainers.image.title="fuzzlab-lab-node-express" \
      org.opencontainers.image.description="fuzzlab lab-only Node/Express Tier-A vulnerable app -- loopback-only, never exposed" \
      lab.fuzzlab.authorized-only="true"

WORKDIR /app

# Lockfile-pinned install (CR-LAB-0001 Addendum C "digest-pinned bases +
# lockfiles + SBOM recording"). `npm ci` refuses to run if package.json and
# package-lock.json disagree, so a stale lockfile fails the build loud
# rather than silently resolving different versions (PA-0009's "verify
# usable in the same step" pattern applied to a dependency install step).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# Framework-debug-page research (docs/LAB_IMPLEMENTATION_PLAN.md Sec 4):
# Express's built-in default error handler writes `err.stack` into the HTTP
# response unless NODE_ENV=production. Set here as the build-time default so
# a generated container never ships in a debug-leaking state; this covers
# only Express's *own* built-in handler -- any custom error middleware this
# emitter's scaffold adds must independently avoid leaking internals.
ENV NODE_ENV=production

# Loopback-only per D11 -- this EXPOSE is documentation, not a network
# grant; the compose/orchestration layer (out of this lane's scope) is what
# actually decides whether this port ever binds beyond loopback.
EXPOSE 3000

ENTRYPOINT ["node", "app.js"]
