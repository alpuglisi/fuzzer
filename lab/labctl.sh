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

# Pick a *working* compose provider. A `docker`/`podman` CLI existing does NOT mean
# a compose provider is installed (e.g. podman-docker without podman-compose), so
# probe each candidate's `version` and use the first that actually runs.
COMPOSE=()
for cand in "docker compose" "podman compose" "docker-compose" "podman-compose"; do
  if $cand version >/dev/null 2>&1; then
    read -r -a COMPOSE <<< "$cand"
    break
  fi
done
if [ ${#COMPOSE[@]} -eq 0 ]; then
  echo "No working Compose provider found (the docker/podman CLI alone is not enough)." >&2
  echo "Install one, e.g. on Fedora:" >&2
  echo "  sudo dnf install -y podman-compose        # Podman (Fedora-native)" >&2
  echo "  # or the Docker Compose plugin:  sudo dnf install -y docker-compose-plugin" >&2
  exit 1
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
