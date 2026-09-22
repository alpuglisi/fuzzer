#!/usr/bin/env bash
#
# deploy.sh - assemble the generated PHP lab (php_laravel) and copy it into a
# bare-metal (non-Docker) LAMP web root.
#
# `L-P3.3c-CUT`: the app this script deploys is no longer the hand-built
# `puppy-fort-factory/` directory -- it is generated fresh from
# `fuzzlab.labgen.assemble` (the same manifest-derived cell set the cutover
# coverage gate proves covers every non-exempted `PFF-` case), then
# `composer install`ed. The containerized path (`lab/compose.yaml` /
# `lab/web.Dockerfile`) does the equivalent at image-build time; this script
# is the manual alternative documented in `docs/ON_HOST_RUNBOOK.md`.
#
# Usage:
#   ./deploy.sh
#
# Defaults:
#   destination: /var/www/html/pff-lab   (Apache DocumentRoot must point at
#                                          $DEST/public, NOT $DEST itself --
#                                          Laravel's front controller lives
#                                          under public/)
#
# Override with environment variables:
#   DEST           destination app root (default /var/www/html/pff-lab)
#   WWW_USER       owner user  for the deployed files (default www-data)
#   WWW_GROUP      owner group for the deployed files (default www-data)
#   ASSUME_YES=1   skip the confirmation prompt before wiping DEST
#   SKIP_COMPOSER=1   skip `composer install` (e.g. for an air-gapped re-run
#                      that only wants the generated tree refreshed)
#
# Examples:
#   ./deploy.sh
#   DEST=/var/www/html/pff-lab ASSUME_YES=1 ./deploy.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

DEST="${DEST:-/var/www/html/pff-lab}"
WWW_USER="${WWW_USER:-www-data}"
WWW_GROUP="${WWW_GROUP:-www-data}"

PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || { echo "ERROR: python3/python not found on PATH." >&2; exit 1; }

# --- 1. assemble the generated app into a scratch directory ------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Assembling the generated php_laravel lab into $TMP ..."
( cd "$SCRIPT_DIR" && "$PYTHON" -m fuzzlab.labgen.assemble --out "$TMP" )

# --- 2. install real Laravel dependencies -------------------------------------
if [ "${SKIP_COMPOSER:-0}" != "1" ]; then
    command -v composer >/dev/null 2>&1 || {
        echo "ERROR: composer not found on PATH (needed for the generated Laravel app's" >&2
        echo "       own dependencies). Install it, or set SKIP_COMPOSER=1 to skip this" >&2
        echo "       step (only useful if DEST already has a vendor/ you trust)." >&2
        exit 1
    }
    ( cd "$TMP" && composer install --no-dev --no-interaction --no-progress --prefer-dist )
fi

# Use sudo when not already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "ERROR: not running as root and 'sudo' is not available." >&2
        echo "       Re-run as root, or install sudo." >&2
        exit 1
    fi
fi

echo "Destination: $DEST"
echo "Owner      : $WWW_USER:$WWW_GROUP"
echo

if [ -d "$DEST" ]; then
    echo "WARNING: $DEST already exists and will be REPLACED (the app is generated,"
    echo "         never hand-edited in place -- see this script's header)."
    if [ "${ASSUME_YES:-0}" != "1" ]; then
        if [ -t 0 ]; then
            read -r -p "Proceed? [y/N] " ans
            case "$ans" in
                y|Y|yes|YES) ;;
                *) echo "Aborted."; exit 1 ;;
            esac
        else
            echo "Refusing to replace an existing $DEST non-interactively without ASSUME_YES=1." >&2
            exit 1
        fi
    fi
    $SUDO rm -rf "$DEST"
fi

$SUDO mkdir -p "$(dirname "$DEST")"

# Copy. Prefer rsync; fall back to cp.
if command -v rsync >/dev/null 2>&1; then
    $SUDO rsync -a "$TMP"/ "$DEST"/
else
    $SUDO cp -a "$TMP"/. "$DEST"/
fi

# Ownership and permissions.
if id "$WWW_USER" >/dev/null 2>&1; then
    $SUDO chown -R "$WWW_USER:$WWW_GROUP" "$DEST"
else
    echo "Note: user '$WWW_USER' not found; skipping chown."
    echo "      Set WWW_USER/WWW_GROUP to your Apache user if different."
fi
$SUDO find "$DEST" -type d -exec chmod 755 {} +
$SUDO find "$DEST" -type f -exec chmod 644 {} +
# Laravel needs storage/ and bootstrap/cache/ writable by the web server.
$SUDO chmod -R ug+rwX "$DEST/storage" "$DEST/bootstrap/cache"

echo
echo "Done. Deployed to $DEST"
echo
echo "Next steps:"
echo "  1. Import the database (first time only):"
echo "       sudo mysql < \"$SCRIPT_DIR/lab/sql/schema.sql\""
echo "  2. Set the DB_HOST/DB_DATABASE/DB_USERNAME/DB_PASSWORD env vars (or edit"
echo "     $DEST/.env) to match — the deployed .env ships lab defaults only."
echo "  3. Point your Apache vhost's DocumentRoot at:"
echo "       $DEST/public"
echo "     (NOT $DEST itself — Laravel's front controller lives under public/)."
echo "  4. Browse to your vhost's URL."
