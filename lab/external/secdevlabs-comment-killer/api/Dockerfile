# secDevLabs Comment Killer's API at the pinned commit (CC-LAB-0311). Lab-only,
# loopback-only. Its Go modules were verified against go.sum and vendored on the host;
# the build needs no network (GOPROXY=off, -mod=vendor).
FROM docker.io/library/golang:1.14@sha256:1a7173b5b9a3af3e29a5837e0b2027e1c438fd1b83bbee8f221355087ad416d6
ENV GOPROXY=off GOFLAGS=-mod=vendor CGO_ENABLED=0
WORKDIR /srv/api
COPY .cache/app/api/ ./
RUN go build -o /usr/local/bin/comment-killer-api . && rm -rf vendor
USER nobody
CMD ["/usr/local/bin/comment-killer-api"]
