# OWASP NodeGoat at the pinned commit (CC-LAB-0330). Lab-only, loopback-only.
# `python -m fuzzlab.lab_fixtures.external fetch nodegoat` checked the source out at
# NODEGOAT_COMMIT (its files hashed against NODEGOAT_TREE_SHA256) and installed its
# production npm packages on the host by `npm ci --omit=dev` (each checked against the
# lockfile's integrity hash); the build copies them and fetches nothing.
FROM mirror.gcr.io/library/node:12-alpine@sha256:d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68
COPY .cache/app /home/node/app
WORKDIR /home/node/app
USER node
# upstream's compose re-seeds the database (artifacts/db-reset.js) before every start;
# the seed is retried until MongoDB answers
CMD ["sh", "-c", "until node artifacts/db-reset.js; do sleep 2; done; exec node server.js"]
