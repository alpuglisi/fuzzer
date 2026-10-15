#!/usr/bin/env bash
# Lifecycle of one external lab fixture (bWAPP, Juice Shop): CC-LAB-0300, FR-LAB-301.
# Run it through lab/labctl.sh, which picks the compose provider:
#
#   ./labctl.sh up        <lab> [--authorized]   pre-flight, start, exposure check
#                                                (+ bootstrap with --authorized)
#   ./labctl.sh down      <lab>                  stop and remove (data volumes kept)
#   ./labctl.sh reset     <lab> [--authorized]   drop everything incl. volumes, then up
#   ./labctl.sh status    <lab>                  0 running + loopback-only, 1 not running,
#                                                2 engine error, 3 exposed
#   ./labctl.sh bootstrap <lab> --authorized     install / register the lab identity
#
# <lab> is a directory here with a compose.yaml (bwapp, juice-shop). Nothing sends
# traffic to a lab without --authorized (D11). Containers are removed only by the exact
# compose project label, never by a name pattern.
#
# Environment: LABCTL_COMPOSE (set by labctl.sh), FUZZLAB_PYTHON (default python3; a
# bare name is looked up on PATH, a relative path resolves against the repo root, where
# Python runs -- give an absolute path to be sure),
# FUZZLAB_EXT_PROJECT_SUFFIX (isolates a test run's project), BWAPP_PORT / JUICE_PORT.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

if [ -z "${LABCTL_COMPOSE:-}" ]; then
  echo "run this through lab/labctl.sh (it picks the compose provider)" >&2
  exit 2
fi
read -r -a COMPOSE <<< "$LABCTL_COMPOSE"
case "${COMPOSE[0]}" in
  docker|docker-compose) ENGINE=docker ;;
  podman|podman-compose) ENGINE=podman ;;
  *) echo "unknown compose provider: ${COMPOSE[0]}" >&2; exit 2 ;;
esac

op="${1:-}"
lab="${2:-}"
AUTHORIZED=0
for arg in "${@:3}"; do
  case "$arg" in
    --authorized) AUTHORIZED=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
if [[ ! "$lab" =~ ^[a-z0-9][a-z0-9-]*$ ]] || [ ! -f "$lab/compose.yaml" ]; then
  echo "unknown external lab: ${lab}" >&2
  exit 2
fi
SUFFIX="${FUZZLAB_EXT_PROJECT_SUFFIX:-}"
if [[ ! "$SUFFIX" =~ ^[a-z0-9-]*$ ]]; then
  echo "invalid FUZZLAB_EXT_PROJECT_SUFFIX" >&2
  exit 2
fi
# The project name comes from the compose file's own `name:` (PA-0059(2)).
NAME="$(sed -n '/^name:/{s/^name:[[:space:]]*//p;q;}' "$lab/compose.yaml")"  # no pipe (BUG-0145)
if [ -z "$NAME" ]; then
  echo "$lab/compose.yaml has no top-level name:" >&2
  exit 2
fi
PROJECT="${NAME}${SUFFIX}"
if [[ ! "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "invalid compose project name: ${PROJECT}" >&2
  exit 2
fi
LABEL="com.docker.compose.project=${PROJECT}"
DC=("${COMPOSE[@]}" -p "$PROJECT" -f "$lab/compose.yaml")
PY="${FUZZLAB_PYTHON:-python3}"
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

# Run from the repo root, so lab/external is not first on Python's import path.
_py() { (cd "$REPO_ROOT" && "$PY" -m fuzzlab.lab_fixtures.external "$@"); }

# The project's resources, by the exact compose project label.
_ids() {  # <ps|network|volume|pod>
  case "$1" in
    ps) "$ENGINE" ps -a -q --filter "label=${LABEL}" ;;
    pod) "$ENGINE" pod ls -q --filter "label=${LABEL}" ;;
    *) "$ENGINE" "$1" ls -q --filter "label=${LABEL}" ;;
  esac
}

# The one self-heal helper (PA-0018): every lifecycle operation that removes or
# recreates containers goes through it. Removes the project's containers (by the ids
# the engine lists for its label), its pod (podman), its networks and, with
# drop-volumes, its volumes.
_force_clean() {
  local ids=()
  read -r -a ids <<< "$(_ids ps 2>/dev/null | tr '\n' ' ')" || true
  if [ "${#ids[@]}" -gt 0 ]; then "$ENGINE" rm -f "${ids[@]}" >/dev/null 2>&1 || true; fi
  if [ "$ENGINE" = podman ]; then
    read -r -a ids <<< "$(_ids pod 2>/dev/null | tr '\n' ' ')" || true
    if [ "${#ids[@]}" -gt 0 ]; then podman pod rm -f "${ids[@]}" >/dev/null 2>&1 || true; fi
  fi
  read -r -a ids <<< "$(_ids network 2>/dev/null | tr '\n' ' ')" || true
  if [ "${#ids[@]}" -gt 0 ]; then "$ENGINE" network rm "${ids[@]}" >/dev/null 2>&1 || true; fi
  if [ "${1:-}" = drop-volumes ]; then
    read -r -a ids <<< "$(_ids volume 2>/dev/null | tr '\n' ' ')" || true
    if [ "${#ids[@]}" -gt 0 ]; then "$ENGINE" volume rm -f "${ids[@]}" >/dev/null 2>&1 || true; fi
  fi
  return 0
}

# True when the project still has containers -- or when the engine cannot say (an
# engine error never reads as "nothing left", PA-0059(1)).
_leftovers() {
  local out
  out="$(_ids ps 2>/dev/null)" || return 0
  [ -n "$out" ]
}

# Refuse a resolved config that publishes beyond loopback, before anything starts.
_preflight() {
  local rendered
  if ! rendered="$("${DC[@]}" config --format json 2>/dev/null)"; then
    rendered="$("${DC[@]}" config)"
  fi
  # A here-string, not a pipe: under pipefail a checker that stops reading (an early
  # error) killed the writer with SIGPIPE and `up` exited 141 with no message (BUG-0145).
  _py check-config "$lab" <<<"$rendered"
}

_exposure() { _py check-exposure "$lab" --engine "$ENGINE" --project "$PROJECT"; }

_bootstrap() {
  if [ "$AUTHORIZED" -ne 1 ]; then
    echo "bootstrap sends traffic to the lab: pass --authorized" >&2
    return 2
  fi
  # The port the running project publishes, not whatever the port variable says now.
  _py bootstrap "$lab" --authorized --engine "$ENGINE" --project "$PROJECT"
}

_up() {
  local info
  info="$(_py info "$lab")"         # validates the port variable
  _py fetch "$lab"
  _preflight
  if ! "${DC[@]}" up -d --build; then
    echo "up failed; removing the project and retrying once..." >&2
    "${DC[@]}" down --remove-orphans >/dev/null 2>&1 || true
    _force_clean
    "${DC[@]}" up -d --build
  fi
  if ! _exposure; then
    echo "exposure check failed: tearing ${PROJECT} down" >&2
    "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    _force_clean drop-volumes
    if _leftovers; then
      echo "EXPOSED STACK STILL RUNNING: containers of ${PROJECT} could not be removed;" \
           "stop them now (${ENGINE} ps --filter label=${LABEL})" >&2
    fi
    exit 3
  fi
  if [ "$AUTHORIZED" -eq 1 ]; then _bootstrap; fi
  echo "${lab} up: ${info#* * }  (loopback only)"
}

case "$op" in
  up)
    _up
    ;;
  down)
    # PA-0130(4): check while live, report, never abort the cleanup.
    if _leftovers && ! _exposure; then
      echo "warning: exposure check failed while live" >&2
    fi
    "${DC[@]}" down --remove-orphans || true
    if _leftovers; then
      echo "down left containers of ${PROJECT} behind; force-cleaning" >&2
      _force_clean
    fi
    if _leftovers; then
      echo "containers of ${PROJECT} remain after force-clean" >&2
      exit 1
    fi
    echo "${lab} down"
    ;;
  reset)
    "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    _force_clean drop-volumes
    _up
    ;;
  status)
    "${DC[@]}" ps || true
    if ! running="$("$ENGINE" ps -q --filter "label=${LABEL}" 2>/dev/null)"; then
      echo "${lab}: cannot query ${ENGINE}" >&2
      exit 2
    fi
    if [ -z "$running" ]; then
      echo "${lab}: not running"
      exit 1
    fi
    if ! _exposure; then exit 3; fi
    echo "${lab}: running, loopback only"
    ;;
  bootstrap)
    _bootstrap
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
