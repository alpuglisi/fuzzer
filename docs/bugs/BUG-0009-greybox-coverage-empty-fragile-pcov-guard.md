# BUG-0009 — Grey-box coverage empty: fragile pcov guard + unverified extension build

- Date: 2026-09-21
- Status: fixed
- Severity: medium (feature-blocking: Phase 3 grey-box produced no coverage on the host)

## Description
The first live run of `scripts/greybox_e2e.sh` failed the step-3 self-test with
"benign request recorded no covered lines". The side-channel file *was* written — so the
`cov.php` shim ran and the host↔container bind mount worked — but its `files` map was
empty: pcov never collected anything.

## Where encountered
On the Fedora host, running `scripts/greybox_e2e.sh` against the containerized lab
(podman-compose). The image build reported `--> Using cache` for the pcov layer and the
run reached the self-test before failing.

## What it caused to fail
The Phase 3 exit (a request reaching new application code scores a strictly higher
`attempt.reward`) cannot be demonstrated without live coverage, so Part E was blocked at
the self-test — correctly, before any misleading "results".

## What the bug was identified to be
Two compounding defects:

1. **Fragile capability detection (code defect).** `includes/cov.php` gated pcov on
   `function_exists('\pcov\start')`. The leading-backslash string form of a namespaced
   name is unreliable for `function_exists` — it can return false even when the extension
   is loaded — so the shim never called `\pcov\start()`/`\pcov\collect()` and always wrote
   an empty coverage map. The self-test file loading fine (shim ran) but empty (collect
   skipped) is the exact fingerprint of this branch never being taken.

2. **Unverified extension provisioning (build/deploy defect).** `lab/web.Dockerfile` ran
   `pecl install pcov` without `$PHPIZE_DEPS` (autoconf/gcc/make). Building a PECL
   extension needs that toolchain; without it the install can no-op/partially fail, and a
   stale cached layer (`--> Using cache`) then serves an image where pcov is not actually
   loadable. Nothing asserted pcov was loaded, so the failure surfaced only at run time
   as "empty coverage", far from its cause.

## Root cause analysis
Five Whys:
1. Why was coverage empty? The shim skipped `\pcov\start()`/`collect()`.
2. Why skipped? Its guard `function_exists('\pcov\start')` was false.
3. Why false? The leading-backslash namespaced-name form is unreliable for
   `function_exists`; the unambiguous check for an extension is `extension_loaded()`.
4. Why did the image possibly lack pcov anyway? `pecl install pcov` ran without the build
   toolchain, and a cached layer hid whether it truly installed.
5. Why did it surface only at run time? No step verified the provisioned extension was
   loadable; the build "succeeded" (exit 0) and the gap appeared later as empty output.

**Root cause:** a capability was gated on a fragile name-string check instead of the
authoritative capability probe, and the build that provisions that capability never
verified it was actually loadable — so a broken/misbuilt extension degraded silently to
"no signal" instead of failing loudly at its source.

## Corrective action
- `includes/cov.php` now gates on `extension_loaded('pcov')` (both at start and in the
  shutdown collector) — unambiguous regardless of namespace-name quirks.
- `lab/web.Dockerfile` installs `$PHPIZE_DEPS` before `pecl install pcov` and asserts
  `php -m | grep -qi '^pcov$'` in the same `RUN`, so a broken layer fails the build; the
  changed `RUN` line also invalidates the suspect cache.
- Sweep (PA-0002): the app's `mysqli` install now carries the same build-time
  `php -m | grep -qi '^mysqli$'` assertion; no other `function_exists('\ns\fn')`-style
  guards or unverified extension installs exist in the repo.
- Tooling: `labctl.sh exec` added; `scripts/greybox_e2e.sh` now checks pcov is loaded in
  the container before the curl self-test and prints the exact `build --no-cache` command
  if not; the health-wait no longer prints per-retry curl errors.

## Preventive action
- PA-0008 — gate on the authoritative capability probe, not a fragile name string.
- PA-0009 — a build/deploy step that provisions a runtime capability must verify it is
  actually usable in the same step (fail the build, not a live run).
(Both recorded in `docs/PREVENTIVE_ACTIONS.md`.)
