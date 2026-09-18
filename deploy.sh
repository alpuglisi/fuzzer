#!/usr/bin/env bash
#
# deploy.sh - copy the Puppy Fort Factory web app into the Apache web root.
#
# By default the app is deployed to the web root so it is served at
# http://localhost/ (not a subdirectory).
#
# Usage:
#   ./deploy.sh [SOURCE_DIR]
#
# Defaults:
#   SOURCE_DIR : the puppy-fort-factory/ folder next to this script
#   destination: /var/www/html   (served at http://localhost/)
#
# Override with environment variables:
#   DEST_ROOT=/var/www/html     # web root to deploy into (http://localhost/)
#   DEST=/var/www/html/pff      # exact destination (subdir -> http://localhost/pff/)
#   WWW_USER=www-data           # owner user  for the deployed files
#   WWW_GROUP=www-data          # owner group for the deployed files
#   CLEAN=1                     # delete files at the destination that are
#                               #   not in the source (mirror the source)
#   ASSUME_YES=1                # skip the CLEAN confirmation prompt
#   FORCE_CONFIG=1              # overwrite an existing config/config.php
#                               #   (by default it is preserved)
#
# Examples:
#   ./deploy.sh                                        # serve at http://localhost/
#   DEST=/var/www/html/puppy-fort-factory ./deploy.sh  # serve in a subdirectory
#   CLEAN=1 ./deploy.sh                                # mirror (prune stale files)
#   ./deploy.sh ~/fuzzer/puppy-fort-factory            # explicit source

set -euo pipefail

APP_NAME="puppy-fort-factory"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

SRC="${1:-$SCRIPT_DIR/$APP_NAME}"
DEST_ROOT="${DEST_ROOT:-/var/www/html}"
DEST="${DEST:-$DEST_ROOT}"
WWW_USER="${WWW_USER:-www-data}"
WWW_GROUP="${WWW_GROUP:-www-data}"

# Normalise SRC (strip any trailing slash) and validate it looks like the app.
SRC="${SRC%/}"
if [ ! -f "$SRC/index.php" ] || [ ! -f "$SRC/config/config.php" ]; then
    echo "ERROR: '$SRC' does not look like the $APP_NAME app" >&2
    echo "       (expected index.php and config/config.php inside it)." >&2
    echo "       Pass the path to the $APP_NAME folder as the first argument." >&2
    exit 1
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

echo "Source     : $SRC"
echo "Destination: $DEST"
echo "Owner      : $WWW_USER:$WWW_GROUP"
echo

# CLEAN mirrors the source and prunes anything else at the destination. Since
# the default destination is the web root, guard it behind a confirmation.
if [ "${CLEAN:-0}" = "1" ]; then
    echo "WARNING: CLEAN=1 will DELETE everything in $DEST that is not part of the app."
    if [ "${ASSUME_YES:-0}" != "1" ]; then
        if [ -t 0 ]; then
            read -r -p "Proceed? [y/N] " ans
            case "$ans" in
                y|Y|yes|YES) ;;
                *) echo "Aborted."; exit 1 ;;
            esac
        else
            echo "Refusing to CLEAN non-interactively without ASSUME_YES=1." >&2
            exit 1
        fi
    fi
fi

$SUDO mkdir -p "$DEST"

# Preserve an existing config.php (holds DB credentials) unless FORCE_CONFIG=1.
STASH=""
if [ -f "$DEST/config/config.php" ] && [ "${FORCE_CONFIG:-0}" != "1" ]; then
    STASH="$(mktemp)"
    $SUDO cp "$DEST/config/config.php" "$STASH"
    echo "Preserving existing config/config.php (set FORCE_CONFIG=1 to overwrite)."
fi

# Copy. Prefer rsync; fall back to cp.
if command -v rsync >/dev/null 2>&1; then
    RSYNC_OPTS=(-a --exclude '.git' --exclude '*.csv')
    [ "${CLEAN:-0}" = "1" ] && RSYNC_OPTS+=(--delete)
    $SUDO rsync "${RSYNC_OPTS[@]}" "$SRC"/ "$DEST"/
else
    if [ "${CLEAN:-0}" = "1" ]; then
        echo "Note: rsync not found; CLEAN=1 ignored (cp cannot prune)."
    fi
    $SUDO cp -a "$SRC"/. "$DEST"/
fi

# Restore the preserved config.php.
if [ -n "$STASH" ]; then
    $SUDO cp "$STASH" "$DEST/config/config.php"
    rm -f "$STASH"
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

# Work out the URL to show.
if [ "$DEST" = "$DEST_ROOT" ]; then
    URL="http://localhost/"
else
    URL="http://localhost/$(basename "$DEST")/"
fi

echo
echo "Done. Deployed to $DEST"
echo
echo "Next steps:"
echo "  1. Import the database (first time only):"
echo "       sudo mysql < \"$SRC/sql/schema.sql\""
echo "  2. Set your DB credentials in:"
echo "       $DEST/config/config.php"
echo "  3. Browse to:"
echo "       $URL"
