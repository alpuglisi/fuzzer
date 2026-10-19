# secDevLabs Streaming's page at the pinned commit (CC-LAB-0314). Lab-only,
# loopback-only. Serves the Angular bundle the repository ships (app/frontend/dist,
# matching src/app/lives), with upstream's nginx config; nothing is fetched.
FROM mirror.gcr.io/library/nginx:1.17.1-alpine@sha256:17bd1698318e9c0f9ba2c5ed49f53d690684dab7fe3e8019b855c352528d57be
COPY .cache/app/app/frontend/dist/streaming /usr/share/nginx/html
COPY .cache/app/app/frontend/nginx-custom.conf /etc/nginx/conf.d/default.conf
