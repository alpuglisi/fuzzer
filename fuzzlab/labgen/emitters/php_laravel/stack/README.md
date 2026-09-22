# `php_laravel` `StackEnv` dependency pins

Per `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 step 4 (lane L-P3.3a).

- **`composer.json`** — the minimal project descriptor used to resolve the
  stack's base dependency set: `php: ^8.3` (matching the `StackEnv`'s pinned
  `php:8.3-fpm-alpine` base image), `laravel/framework: ^13.0`.
- **`composer.lock`** — a *real* lockfile, generated for real against
  Packagist on 2026-09-21 (`composer update --no-dev --no-scripts --no-install`
  from this directory's `composer.json`), not hand-written or guessed. It
  resolved `laravel/framework` to `v13.32.0` (pinned exactly in
  `stack_env.py`'s `PHP_LARAVEL_STACK_ENV.framework_version`) plus 73
  transitive dependencies, 74 packages total.

## SBOM

`syft` was **not available** on this build host (`which syft` — not found).
Per this task's own fallback instruction, generation was skipped and the
intended command is recorded here to run once `syft` is available:

```sh
syft dir:fuzzlab/labgen/emitters/php_laravel/stack -o cyclonedx-json \
    > fuzzlab/labgen/emitters/php_laravel/stack/sbom.cdx.json
```

(`dir:` scans the `composer.json`/`composer.lock` pair in this directory;
`cyclonedx-json` matches the CycloneDX SBOM format this task specifies.)

## `skeleton/` (`CC-LAB-0054`/`FR-LAB-52`, 2026-09-22)

The real, minimal, **bootable** Laravel 13 project skeleton the live-boot
conformance harness (`fuzzlab/labgen/conformance/live_boot.py`) overlays a
manifest's generated content onto. This directory's own `composer.json`/
`composer.lock` above are a *library-pin* resolution only (no `artisan`,
`bootstrap/app.php`, `config/*.php`, or a real `public/index.php` front
controller) -- `skeleton/` is the actual project shape those pins are
resolved for.

**Provenance.** A real, un-doctored `composer create-project laravel/laravel
.` run in a scratch directory (2026-09-22, same Packagist access this
directory's own lockfile was resolved against), resolving the same
`laravel/framework` `v13.32.0` `stack_env.py` already pins. Copied in as-is
and trimmed of everything a bootable app does not need: `vendor/` (installed
fresh per harness run, never checked in), `.git/`, `tests/` (this project's
own test suite covers it, not Laravel's scaffolded PHPUnit stubs),
`.github/` (CI workflow templates), `resources/{css,js}` and the npm/Vite
front-end build pipeline (`package.json`, `vite.config.js` -- no rendered
cell needs a JS build step), `public/favicon.ico` (binary, cosmetic), and
`routes/web.php` (this harness overlays its own, assembled from a manifest's
`LaravelEmitter.route_fragment_for()` fragments via `RouteAccumulator` --
see `live_boot.py`'s `_assemble()`). `.env`/`.env.example` are not carried
either: the harness writes its own SQLite-backed `.env` at build time (see
`live_boot.py` for why that is deliberately not
`StackEnv.env_file_content()`, which pins the real lab's own MySQL
production default).

**One real edit from the `composer create-project` output**:
`bootstrap/app.php` disables Laravel's default session-CSRF middleware
(`validateCsrfTokens(except: ['*'])`). The real `puppy-fort-factory/` pages
this stack reproduces have no CSRF framework of their own, so leaving
Laravel's default enabled silently adds an unmodeled security control on
every migrated POST page (found for real: `contact.php`/`newsletter.php`
both returned HTTP 419 until this was disabled). `StackEnv.index_php_content()`
was checked against this real skeleton's own `public/index.php` and found
byte-for-byte equivalent -- no change needed there.

**Scope**: this skeleton is a test-harness / conformance-check asset. It is
not, and does not need to be, wired into the real lab's Docker-based
deployment (`lab/compose.yaml`, `deploy.sh`) -- that remains untouched, per
this task's own explicit boundary, pending the separate, later
`L-P3.3c-CUT` atomic cutover.
