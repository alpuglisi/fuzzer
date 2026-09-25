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

# Optional compose profile(s) (top-level flag, must precede the subcommand).
# Set PFF_PROFILE=desync to also start the opt-in h2->h1 downgrade front-end
# (D17), PFF_PROFILE=apps for the 10 browsable-app services (CC-LAB-0247),
# or a comma-separated combination (PFF_PROFILE=apps,desync) -- one
# `--profile` flag per entry, since Compose only accepts one value per flag.
# tests/test_lab_labctl_profile_parsing.py extracts and exercises exactly
# this block by its sentinel markers -- keep them if this logic moves.
# PROFILE_ARGS_BLOCK_BEGIN
PROFILE_ARGS=()
if [ -n "${PFF_PROFILE:-}" ]; then
  IFS=',' read -ra _profiles <<< "$PFF_PROFILE"
  for p in "${_profiles[@]}"; do
    PROFILE_ARGS+=(--profile "$p")
  done
fi
# PROFILE_ARGS_BLOCK_END

# Force-clear a wedged podman stack. podman-compose can leave containers "improper" or
# running that `down`/`down -v` cannot remove; `podman rm -f` kills+removes them, then the
# now-empty pod(s) and the project network go. Pass "drop-volume" to also remove the DB
# volume (reset's clean re-seed). No-op without podman (docker compose recreates fine).
# Used by BOTH `up` and `reset` — every path that recreates containers must self-heal
# (BUG-0013 recurred because the earlier fix patched only `up`; see BUG-0017).
_force_clean() {
  command -v podman >/dev/null 2>&1 || return 0
  # CC-LAB-0247 (Lane 7, Gate F): the 10 browsable-app containers/networks
  # were missing from this list entirely (a real, live-discovered gap --
  # `PFF_PROFILE=apps ./labctl.sh down` right after `up` left every one of
  # them running and their dedicated networks undropped, since this
  # function only ever knew about the pre-Lane-7 3 services). Every
  # container-remove path must self-heal for every profile, not just the
  # default one (the same PA-0018 discipline `up`/`down`/`reset` already
  # cite for each other).
  for c in pff-lab_frontend_1 pff-lab_web_1 pff-lab_db_1 \
           pff-lab_circlefeed_1 pff-lab_huddlehub_1 pff-lab_booking_1 \
           pff-lab_pictrail_1 pff-lab_loopcast_1 pff-lab_trackernest_1 \
           pff-lab_reelqueue_1 pff-lab_wanderfare_1 pff-lab_forgecart_1 \
           pff-lab_meadowmart_1; do
    podman rm -f "$c" >/dev/null 2>&1 || true      # -f removes even running/wedged ones
  done
  podman pod prune -f >/dev/null 2>&1 || true        # drop the emptied pod(s)
  for n in pff-lab_default \
           pff-lab_circlefeed-net pff-lab_huddlehub-net pff-lab_booking-net \
           pff-lab_pictrail-net pff-lab_loopcast-net pff-lab_trackernest-net \
           pff-lab_reelqueue-net pff-lab_wanderfare-net pff-lab_forgecart-net \
           pff-lab_meadowmart-net; do
    podman network rm "$n" >/dev/null 2>&1 || true
  done
  if [ "${1:-}" = "drop-volume" ]; then
    podman volume rm pff-lab_pff-db-data >/dev/null 2>&1 || true
  fi
  return 0
}

case "${1:-}" in
  up)
    # podman-compose cannot recreate a running stack in place when the env or profile
    # changes (it errors on existing container names / dependent containers, and can leave
    # the pod half-torn-down and wedged). If `up` fails, bring the stack down — the DB
    # volume is kept — force-clear any wedged containers/pod/network, and recreate. Makes
    # `PFF_WAF=on ./labctl.sh up` and profile changes robust + self-healing.
    if ! "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build; then
      echo "up failed (in-place recreate not supported here); recreating cleanly..." >&2
      "${COMPOSE[@]}" down >/dev/null 2>&1 || true
      _force_clean keep-volume
      "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build
    fi
    echo "lab up: http://127.0.0.1:${PORT}/  (loopback only)"
    # Use an `if` (not `[ -n ] && echo`): a trailing `A && B` as the case's last command
    # returns non-zero when A is false (empty profile), making `labctl.sh up` exit 1 on
    # success and aborting callers under `set -e`. An `if` with no else always returns 0.
    if [ -n "${PFF_PROFILE:-}" ]; then echo "profile '${PFF_PROFILE}' enabled"; fi
    ;;
  down)
    # Teardown keeps the DB volume. A wedged podman stack can make `down` itself fail to
    # remove "improper"/running containers, so on failure force-clean (keep-volume) — the
    # same self-heal as up/reset (PA-0018: every container-remove path routes through the
    # shared helper, keyed on the operation not the trigger).
    #
    # CC-LAB-0247 (Lane 7, Gate F): `podman compose down`'s own exit code is
    # NOT trustworthy here (a real, live-discovered defect) -- it printed
    # per-container "container state improper"/per-network "is being used"
    # errors for every one of the 10 apps-profile containers yet still
    # exited 0, so the old `if ! down; then force-clean` never ran and
    # `PFF_PROFILE=apps ./labctl.sh down` silently left the whole stack up.
    # Checking real post-state (any `pff-lab_*` container still present)
    # instead of trusting the exit code is what actually detects this.
    "${COMPOSE[@]}" down || true
    if podman ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^pff-lab_'; then
      echo "down left containers behind; force-clearing wedged stack (DB volume kept)..." >&2
      _force_clean keep-volume
    fi
    ;;
  reset)
    # Clean re-seed: drop the volume and recreate. On a wedged stack `down -v` fails to
    # remove "improper"/running containers, so force-clean (dropping the volume) before and,
    # if needed, after the up — the same self-heal as `up` (BUG-0017: this path recreates
    # containers too and must clear a wedged podman stack).
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    _force_clean drop-volume
    if ! "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build; then
      echo "reset up failed; force-cleaning and retrying..." >&2
      _force_clean drop-volume
      "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build
    fi
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
