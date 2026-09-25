# Target-lab web tier: Go (net/http) serving the generated `go_net_http`
# (LoopCast) lab app. CC-LAB-0247 (Lane 7, §2b). Three stages: `gen` runs the
# real generator (`fuzzlab.labgen.emitters.go_net_http.assemble_go_net_http_app`
# -- the same assembly procedure `GoLiveBootHarness._assemble()` uses,
# PA-0027) to produce the Go source tree; `build` compiles it for real with
# the real `go` toolchain; the final stage is a minimal runtime for the
# compiled binary. No database (this stack's Phase A scope call -- see
# `fuzzlab/labgen/conformance/go_live_boot.py`'s own module docstring).
#
# Build context is the REPO ROOT (see `lab/compose.yaml`'s
# `build.context: ..`), same reason as `web.Dockerfile`.

FROM python:3.12-slim AS gen
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -c "from fuzzlab.labgen.emitters.go_net_http import assemble_go_net_http_app; assemble_go_net_http_app('/app')"

# go.mod pins `go 1.22` -- matches this build stage's toolchain exactly.
FROM golang:1.22-bookworm AS build
WORKDIR /app
COPY --from=gen /app /app
RUN go build -o server .

FROM debian:bookworm-slim
COPY --from=build /app/server /server
EXPOSE 8080

# HOST defaults to 127.0.0.1 in the binary itself (unchanged for every
# direct-host-process caller, e.g. this stack's own live-boot/navigability
# test harnesses) -- explicitly overridden to 0.0.0.0 here so the
# container's published port (compose's `127.0.0.1:<host>:8080`) can
# actually reach this process. Binding the process itself to 127.0.0.1
# *inside* the container is unreachable from the host's port-forwarding
# path (verified live) -- the loopback-only guarantee is enforced by the
# host-side bind, not by this process's own listen address.
ENV HOST=0.0.0.0
ENV PORT=8080

CMD ["/server"]
