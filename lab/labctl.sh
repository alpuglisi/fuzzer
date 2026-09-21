#!/usr/bin/env bash
# One-command control for the containerized target lab (D7).
#
#   ./labctl.sh up       build + start (loopback only)
#   ./labctl.sh down     stop and remove containers (keeps the DB volume)
#   ./labctl.sh reset    down + drop the DB volume + up (clean re-seed)
#   ./labctl.sh status   show container + health status
#   ./labctl.sh logs     follow logs
#   ./labctl.sh snapshot [name]  dump the DB to .snapshots/<name>.sql (default baseline)
#   ./labctl.sh restore  [name]  restore the DB from .snapshots/<name>.sql (T3.5)
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

# Optional compose profile (top-level flag, must precede the subcommand). Set
# PFF_PROFILE=desync to also start the opt-in h2->h1 downgrade front-end (D17).
PROFILE_ARGS=()
[ -n "${PFF_PROFILE:-}" ] && PROFILE_ARGS=(--profile "${PFF_PROFILE}")

case "${1:-}" in
  up)
    "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build
    echo "lab up: http://127.0.0.1:${PORT}/  (loopback only)"
    [ -n "${PFF_PROFILE:-}" ] && echo "profile '${PFF_PROFILE}' enabled"
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
  exec)
    # Passthrough: ./labctl.sh exec <service> <cmd...>  (e.g. exec web php -m)
    shift
    "${COMPOSE[@]}" exec -T "$@"
    ;;
  snapshot)
    # Fast DB snapshot for deterministic resets between fuzzing iterations (T3.5).
    # Not a container rebuild — just a mariadb-dump into lab/.snapshots/.
    name="${2:-baseline}"
    mkdir -p .snapshots
    "${COMPOSE[@]}" exec -T db sh -c \
      'MYSQL_PWD="$MARIADB_PASSWORD" mariadb-dump --no-tablespaces --skip-comments \
         -u"$MARIADB_USER" "$MARIADB_DATABASE"' > ".snapshots/${name}.sql"
    echo "snapshot saved: lab/.snapshots/${name}.sql"
    ;;
  restore)
    name="${2:-baseline}"
    if [ ! -f ".snapshots/${name}.sql" ]; then
      echo "no snapshot lab/.snapshots/${name}.sql (run: ./labctl.sh snapshot ${name})" >&2
      exit 1
    fi
    "${COMPOSE[@]}" exec -T db sh -c \
      'MYSQL_PWD="$MARIADB_PASSWORD" mariadb -u"$MARIADB_USER" "$MARIADB_DATABASE"' \
      < ".snapshots/${name}.sql"
    echo "restored DB from lab/.snapshots/${name}.sql"
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
