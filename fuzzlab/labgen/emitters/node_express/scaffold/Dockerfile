# Generated Node/Express Tier-A lab image (fuzzlab.labgen.emitters.node_express).
#
# Digest-pinned per CR-LAB-0001 Addendum D's "soft-guarantee digest-pinned +
# SBOM-recorded" rule (bit-reproducible images across runtimes is explicitly
# out of scope, per CR-LAB-0001 Sec 9 -- only the base layer's digest is
# pinned, not a promise the whole built image is byte-identical).
#
# Base image: node:22-bookworm-slim (Node 22 "Jod", active LTS as of this
# pinning -- https://nodejs.org/en/about/previous-releases).
#
# CC-LAB-0247 (Lane 7, Gate D): the previous digest here
# (`sha256:93a7d0e0f6a1...`) was read from a Docker Hub web page, never
# verified with a live pull (this stack's own comment said so), and turned
# out to resolve to the `linux/ppc64le` manifest, not `linux/amd64` -- a
# real defect, only caught once a real Docker/Podman was available to build
# against (`podman pull` warned "image platform (linux/ppc64le) does not
# match the expected platform (linux/amd64)"). Re-pinned below against a
# live `skopeo inspect --raw docker://docker.io/library/node:22-bookworm-slim`
# multi-arch manifest list on 2026-09-25, taking the `architecture: amd64`
# entry explicitly. Re-pin the same way at the next scheduled base-image
# refresh:
#   podman pull node:22-bookworm-slim && \
#     podman inspect --format='{{index .RepoDigests 0}}' node:22-bookworm-slim
# or, without pulling the full image:
#   skopeo inspect --raw docker://docker.io/library/node:22-bookworm-slim
FROM node@sha256:25330af3531fb5e23318554a0aa911125b6e91b1b777edf7655501d207c067a2

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

# CC-LAB-0247 (Lane 7, Gate D): `app.js`'s own `app.listen(port, host)`
# defaults `host` to 127.0.0.1 -- correct for a direct-host-process boot
# (this stack's own live-boot/navigability test harnesses), but unreachable
# from a container's published port (verified live: a host-side
# `-p 127.0.0.1:<host>:<container>` bind forwards to the container's own
# non-loopback interface, never to a listener bound only to that
# container's 127.0.0.1). Explicitly overridden here; the loopback-only
# guarantee (D11) is enforced by the host-side publish bind, not by this
# process's own listen address.
ENV HOST=0.0.0.0

# Loopback-only per D11 -- this EXPOSE is documentation, not a network
# grant; the compose/orchestration layer (out of this lane's scope) is what
# actually decides whether this port ever binds beyond loopback.
EXPOSE 3000

ENTRYPOINT ["node", "app.js"]
