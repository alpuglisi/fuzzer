#!/usr/bin/env bash
# CC-LAB-0247 (Lane 7, §2b/§2h, D12): ForgeCart's (`ruby_rails`) container
# entrypoint. Generates a fresh, ephemeral SECRET_KEY_BASE on every
# container start -- never a fixed literal, never written to a file this
# image or the repo persists (D12: credentials live in the OS
# keyring/credential store, never committed) -- runs the per-container
# SQLite `db:prepare`, then execs `bin/rails server`.
set -euo pipefail

export SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(bin/rails secret)}"
export RAILS_ENV="${RAILS_ENV:-production}"

# `config/database.yml`'s checked-in `production:` section has its
# `database:` key commented out (the stock Rails template's own placeholder
# for "fill this in for your real deployment" -- confirmed live: without
# this, `bin/rails db:prepare` under RAILS_ENV=production fails with
# "ArgumentError: No database file specified"). `DATABASE_URL` overrides
# `database.yml` entirely and needs no skeleton edit; the DB lives inside
# this container's own ephemeral filesystem (matches every other stack's
# per-container SQLite, no persisted volume -- a fresh, empty DB every
# container start is correct for this lab, not a gap).
export DATABASE_URL="${DATABASE_URL:-sqlite3:storage/production.sqlite3}"

bin/rails db:prepare

# `-b 0.0.0.0`: Rails' own dev/production server binds where told; a
# container's published port (compose's `127.0.0.1:<host>:3000`) can only
# reach a process listening on the container's own non-loopback interface
# -- binding to 127.0.0.1 *inside* the container is unreachable from the
# host's port-forwarding path (verified live building this stack's sibling
# Dockerfiles). The loopback-only guarantee is enforced by the host-side
# compose bind, not by this process's own listen address.
exec bin/rails server -b 0.0.0.0 -p "${PORT:-3000}"
