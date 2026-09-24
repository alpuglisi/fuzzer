# BUG-0047 — the generated app's checked-in `composer.lock` resolved to PHP-8.4-only Symfony 8.1, so a from-scratch lab image build fails `composer install` on the pinned `php:8.3` base

## Description

Building the containerized target lab from scratch (`lab/labctl.sh up`, i.e. the
first on-host step of every `docs/ON_HOST_RUNBOOK.md` Part) failed in the web
image's `composer install` step with a wall of platform-requirement errors:

```
symfony/http-foundation v8.1.7 requires php >=8.4.1 -> your php version (8.3.33) does not satisfy that requirement.
laravel/framework is locked to version v13.32.0 ...
    -> satisfiable by symfony/http-foundation[v8.1.7].
    -> symfony/http-foundation v8.1.7 requires php >=8.4.1 ...
```

(~17 such "Problem N" blocks, one per locked Symfony 8.1 component.)

## Where encountered

On-host run of `docs/ON_HOST_TASKS.md` / `ON_HOST_RUNBOOK.md` Part A, on the
Fedora host, 2026-09-24. `web.Dockerfile`'s final stage runs
`composer install --no-dev` against the generated app tree assembled from
`fuzzlab/labgen/emitters/php_laravel/stack/skeleton/` (see `assemble.py`'s
`SKELETON_DIR`).

## What it caused to fail

The lab image could not be built at all, so **every** on-host task that needs a
running lab (Parts A, C–L) was blocked. This is a from-scratch-build-only
failure: the 3-day-old cached `pff-lab_web:latest` image predated the lock
drift, so it masked the defect until a clean rebuild was forced.

## What the bug was identified to be

The skeleton `composer.json` declares `"php": "^8.3"` and the runtime base image
is pinned to `php:8.3-apache-bookworm` (per D7), but the checked-in
`composer.lock` beside it had been regenerated to **Symfony 8.1.x /
Laravel 13.32.0**, whose components require **PHP ≥ 8.4.1**. Laravel 13.32.0
permits `symfony/* ^7.4 || ^8.0`; a correct resolution for a PHP-8.3 target
picks the 7.4 branch (PHP 8.2+), but the lock had the 8.x branch — a lockfile
internally inconsistent with its own `"php": "^8.3"` constraint. `composer
install` honours the lock exactly and fails the platform check on `php:8.3`.

The **why**: unlike its sibling `stack/composer.json` (which pins
`"config": {"platform": {"php": "8.3.33"}}`), the skeleton `composer.json` had
**no `config.platform.php` pin**. Whoever last regenerated the skeleton lock ran
`composer update` on a PHP-8.4 host; with no platform pin, Composer resolved to
the newest packages its host PHP allowed (Symfony 8.1), baking a PHP-8.4-only
lock into a PHP-8.3 project.

## Root cause analysis (Five Whys)

1. Why did the build fail? `composer install` rejected the locked Symfony 8.1
   packages: they need PHP ≥ 8.4.1, the base image is PHP 8.3.33.
2. Why were PHP-8.4-only packages locked for a PHP-8.3 project? The
   `composer.lock` was resolved on a PHP-8.4 host and picked the newest allowed
   Symfony branch (8.1) instead of the 7.4 branch a PHP-8.3 target needs.
3. Why did resolution use the host's PHP instead of the target's? The skeleton
   `composer.json` had no `config.platform.php`, so Composer used the running
   interpreter's version as the resolution platform.
4. Why was there no platform pin, when the sibling `stack/composer.json` has
   one? The pin was added to `stack/composer.json` but never propagated to the
   `skeleton/composer.json` — the two composer roots were treated as
   independent, and only one carried the reproducibility guard.
5. **Root cause:** a reproducibility invariant that the whole `php_laravel`
   stack depends on (resolve/lock against the *pinned runtime* PHP, not the
   build host's) was enforced in only one of the two composer roots the stack
   ships, so a routine `composer update` on a newer host silently produced a
   lock incompatible with the pinned runtime image, and nothing failed until a
   from-scratch build.

## Corrective action

- Added `"platform": {"php": "8.3.33"}` to the skeleton `composer.json`'s
  `config` block, matching `stack/composer.json`.
- Regenerated `skeleton/composer.lock` with `composer update --no-install`
  resolving against the pinned platform (via the `composer:2` container, so the
  build host's own PHP is irrelevant). Symfony downgraded 8.1.x → 7.4.19; no
  package now carries a hard `php >= 8.4` floor.
- Verified the lab image builds and serves (`product.php?id=1` → 200) and that
  the sibling `stack/composer.lock` was already consistent (Symfony 7.4.19).
- See CC-LAB-0234.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. The closest prior bugs
are `BUG-0001`/`BUG-0002` (schema version *hardcoded* and a recurrence of the
same), which are about a value duplicated instead of derived from one source —
thematically adjacent (a single source-of-truth was not honoured) but a
different artifact and mechanism (a test constant, not a dependency lockfile /
platform pin). No prior bug concerns Composer, lockfiles, or PHP-version
pinning, and no existing PA covers "resolve/lock a dependency set against the
pinned runtime, not the build host." This is therefore not a recurrence; it is
a new class. No prior-preventive-action failure analysis applies.

## Preventive action

**PA-0049** (see `docs/PREVENTIVE_ACTIONS.md`) — every committed dependency
lockfile must be resolved against the project's *pinned runtime*, and each
distinct dependency root that ships a lockfile must carry that pin itself, plus
the PA-0002 sweep for other lockfiles missing the pin.
