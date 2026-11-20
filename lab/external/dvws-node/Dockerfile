# DVWS-node at the pinned commit (held-out lab, lab/HOLDOUT.md). Lab-only, loopback-only.
# `python -m fuzzlab.lab_fixtures.external fetch dvws-node` checked the source out at
# DVWS_NODE_COMMIT (its files hashed against DVWS_NODE_TREE_SHA256) and installed its
# locked npm packages on the host by `npm ci --ignore-scripts` (each checked against the
# lockfile's integrity hash): the frontend's build set and the backend's production set.
# compose builds this with no network (`build.network: none`): the build stage runs
# upstream's own frontend build (vite, adapter-static into ../public) and compiles
# bcrypt's native addon from its source against the image's own Node headers (the
# install script that would download a prebuilt binary is never run).
FROM mirror.gcr.io/library/node:22-bookworm@sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb AS build
COPY --chown=node:node .cache/app /home/node/app
WORKDIR /home/node/app
USER node
ENV npm_config_nodedir=/usr/local npm_config_offline=true
RUN cd frontend && npx --no-install vite build && rm -rf node_modules .svelte-kit
RUN npm rebuild bcrypt --build-from-source && node -e "require('bcrypt')"

FROM mirror.gcr.io/library/node:22-bookworm@sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb
COPY --from=build --chown=node:node /home/node/app /home/node/app
WORKDIR /home/node/app
USER node
# upstream's compose re-seeds both databases (scripts/seed-database.js) before every
# start; compose starts this only once both answer their health checks
CMD ["sh", "-c", "node scripts/seed-database.js && exec node src/server.js"]
