# secDevLabs Comment Killer's page at the pinned commit (CC-LAB-0311). Lab-only,
# loopback-only. Its npm packages were installed on the host by `npm ci` (checked
# against the lockfile; `python -m fuzzlab.lab_fixtures.external fetch
# secdevlabs-comment-killer`), so the build copies them and fetches nothing.
FROM docker.io/library/node:13.12.0-alpine@sha256:cc85e728fab3827ada20a181ba280cae1f8b625f256e2c86b9094d9bfe834766
COPY .cache/app/app /app
WORKDIR /app
RUN chown -R node:node /app
USER node
CMD ["node", "node_modules/react-scripts/bin/react-scripts.js", "start"]
