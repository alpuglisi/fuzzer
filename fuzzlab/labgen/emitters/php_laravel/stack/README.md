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
