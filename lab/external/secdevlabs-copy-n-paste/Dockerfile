# secDevLabs CopyNPaste API at the pinned commit (CC-LAB-0303). Lab-only, loopback-only.
#
# The app and its vendored Go modules come from the gitignored .cache/app, which the
# host fills from the pinned checkout (modules verified against the app's go.sum:
# `python -m fuzzlab.lab_fixtures.external fetch secdevlabs-copy-n-paste`). The build
# needs no network: GOPROXY=off and -mod=vendor.
FROM docker.io/library/golang:1.14@sha256:1a7173b5b9a3af3e29a5837e0b2027e1c438fd1b83bbee8f221355087ad416d6
ENV GOPROXY=off GOFLAGS=-mod=vendor CGO_ENABLED=0
WORKDIR /srv/app
COPY .cache/app/app/ ./
RUN go build -o /usr/local/bin/copy-n-paste . && rm -rf vendor
USER nobody
CMD ["/usr/local/bin/copy-n-paste"]
