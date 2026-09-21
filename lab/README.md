# Target lab (containerized)

The Puppy Fort Factory app and its database, run in containers so the
PHP/Apache/MariaDB/libxml versions are pinned and reproducible (decision D7), with
one-command up and reset.

> **Lab-only.** The app is deliberately vulnerable. The web tier is published on
> `127.0.0.1` only and the database is not published at all. Never expose this
> stack on a shared or public network.

## Run

```bash
cd lab
cp .env.example .env          # local lab credentials (not real secrets)
./labctl.sh up                # build + start; serves http://127.0.0.1:8080/
./labctl.sh status            # container + health
./labctl.sh reset             # drop the DB volume and re-seed a clean database
./labctl.sh down              # stop
```

**Prerequisite — a Compose provider.** `docker compose`, `podman compose`,
`docker-compose`, or `podman-compose` all work against `compose.yaml`, and
`labctl.sh` uses the first one it finds. A bare `docker`/`podman` CLI is **not**
enough — the compose provider is a separate package. On Fedora (podman-docker):

```bash
sudo dnf install -y podman-compose            # Podman (Fedora-native)
# or, on Docker Engine:  sudo dnf install -y docker-compose-plugin
```

If none is installed, `labctl.sh` stops with this instruction instead of a raw
"looking up compose provider failed" dump.

## What it does

- **web** (`web.Dockerfile`): `php:8.3-apache` + `mysqli`, serving the app
  bind-mounted from `../puppy-fort-factory` (edits are live). Published on
  `127.0.0.1:${PFF_WEB_PORT:-8080}` only.
- **db** (`mariadb:11.4`): seeded on first start from
  `../puppy-fort-factory/sql/schema.sql` (creates and seeds everything, including
  `posts`). No host port — reachable only by the web container.

The app reads `PFF_DB_HOST/USER/PASS/NAME` from the environment (see
`config/config.php`); compose wires the web tier to the `db` service.

## Reproducibility (D7)

The tags pin the major/minor versions. For a full lock, pin to image **digests**:

```bash
./labctl.sh pin               # prints php: / mariadb: @sha256 digests
# then replace the tags in web.Dockerfile and compose.yaml with @sha256:...
```

Record the exact versions and any label-affecting PHP settings (e.g.
`display_errors`, libxml entity handling) in the env-profile as instrumentation
lands (Phase 3).

## SELinux (Fedora)

Bind mounts use the `:Z` / `:ro,Z` relabel option so the container can read the
app and the seed file under SELinux. If a mount is shared between containers, use
`:z` instead.
```
