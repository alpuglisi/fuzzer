# secDevLabs Mongection at the pinned commit (CC-LAB-0309). Lab-only, loopback-only.
# Its npm packages were installed on the host by `npm ci` (checked against the
# lockfile; `python -m fuzzlab.lab_fixtures.external fetch secdevlabs-mongection`), so
# the build copies them and fetches nothing.
FROM mirror.gcr.io/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
COPY .cache/app/package.json /usr/share/mongection/package.json
COPY .cache/app/node_modules /usr/share/mongection/node_modules
COPY .cache/app/src /usr/share/mongection/src
WORKDIR /usr/share/mongection
USER node
CMD ["node", "src/app.js"]
