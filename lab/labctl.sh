#!/usr/bin/env bash
# One-command control for the containerized target lab (D7).
#
#   ./labctl.sh up       build + start (loopback only)
#   ./labctl.sh down     stop and remove containers (keeps the DB volume)
#   ./labctl.sh reset    down + drop the DB volume + up (clean re-seed)
#   ./labctl.sh status   show container + health status
#   ./labctl.sh logs     follow logs
#   ./labctl.sh pin      print pulled image digests to pin in web.Dockerfile (D7)
#
# Uses `docker compose` (Podman-compatible: `podman compose` or podman-compose
# also work against compose.yaml).
set -euo pipefail

cd "$(dirname "$0")"

# Prefer docker compose; fall back to podman compose.
if command -v docker >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v podman >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  echo "need docker or podman" >&2; exit 1
fi

PORT="${PFF_WEB_PORT:-8080}"

case "${1:-}" in
  up)
    "${COMPOSE[@]}" up -d --build
    echo "lab up: http://127.0.0.1:${PORT}/  (loopback only)"
    ;;
  down)
    "${COMPOSE[@]}" down
    ;;
  reset)
    "${COMPOSE[@]}" down -v
    "${COMPOSE[@]}" up -d --build
    echo "lab reset + up: http://127.0.0.1:${PORT}/"
    ;;
  status)
    "${COMPOSE[@]}" ps
    ;;
  logs)
    "${COMPOSE[@]}" logs -f
    ;;
  pin)
    echo "Pin these digests into web.Dockerfile / compose.yaml for reproducibility:"
    docker image inspect php:8.3-apache-bookworm --format 'php:  {{index .RepoDigests 0}}' 2>/dev/null || true
    docker image inspect mariadb:11.4 --format 'mariadb: {{index .RepoDigests 0}}' 2>/dev/null || true
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
