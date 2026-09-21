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
Three independent defects, each sufficient on its own to produce an empty coverage map;
they were found and fixed in sequence (the host self-test caught each):

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

3. **Wrong-granularity `\pcov\collect()` filter (code defect — the decisive one).** With
   pcov loaded, the shim still returned empty because it called
   `\pcov\collect(\pcov\inclusive, ['/var/www/html'])`. pcov's inclusive filter is a list
   of **file** paths, not directories; a directory matches no file, so `collect()`
   returned nothing. This alone produces "pcov loaded, coverage empty" — the exact final
   symptom after the first two fixes. Fixed by collecting all recorded coverage
   (`\pcov\collect()`; `pcov.directory` already scopes it to the app) and keeping app
   files by **path prefix** in the shim.

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

**Root cause:** the coverage signal degraded silently to empty through three separate
"present but not producing" failures — a capability gated on a fragile name-string check
instead of the authoritative probe; a build that provisioned the capability without
verifying it loads; and an API call whose argument was the wrong granularity (a directory
where a file list was required). The common thread: each dependency was assumed to *work*
because it appeared *present*, and nothing verified the actual produced signal until the
end-to-end self-test — which is what caught all three.

Note (why the build-time check was not enough): the build assertion `php -m | grep pcov`
proves pcov **loads**, not that it **produces coverage**. "Loads" ≠ "works"; the decisive
defect (the collect filter) sits past the load check and was caught only by the runtime
self-test that inspects the actual output.

## Corrective action
- `includes/cov.php` now gates on `extension_loaded('pcov')` (both at start and in the
  shutdown collector) — unambiguous regardless of namespace-name quirks.
- `lab/web.Dockerfile` installs `$PHPIZE_DEPS` before `pecl install pcov` and asserts
  `php -m | grep -qi '^pcov$'` in the same `RUN`, so a broken layer fails the build; the
  changed `RUN` line also invalidates the suspect cache.
- `includes/cov.php` now calls `\pcov\collect()` (no directory filter) and keeps app files
  by path prefix (`strpos($file, '/var/www/html/') === 0`), so a wrong-granularity filter
  can no longer silently zero the result.
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
- PA-0010 — when an API takes a filter/selector argument, confirm the expected
  granularity (file vs directory vs prefix vs glob); a wrong-granularity argument commonly
  yields a silently-empty result. Verify the actual produced signal end-to-end, since a
  dependency loading is not proof it produces output ("loads ≠ works").
(All recorded in `docs/PREVENTIVE_ACTIONS.md`.)
