# BUG-0142 — live boots reinstalled the same pinned dependencies every boot, and every live-boot module re-probed the network

- Date: 2026-10-15
- Status: fixed
- Severity: medium. No wrong result, but the full suite took about 68 minutes (parallel
  7 min + serial 61 min). Every push waited on it, and on 2026-10-14/15 it was run about
  eight times. The user asked for the waste to be found by measurement, not assumed.

## Description
- **Repeated installs, Laravel.** `LiveBootHarness.build()` ran `composer install` into
  every freshly assembled Laravel app. The skeleton has a committed `composer.lock`, so
  every run installed the identical 409 MB, 16,140-file `vendor/`.
- **Repeated installs, Django.** `DjangoLiveBootHarness.build()` built a fresh `venv`
  and `pip install`ed the same pinned `django` and `requests` on every boot.
- **Repeated probes.** Every live-boot test module evaluated its toolchain's
  network-capability probe at import, with no caching.

## Where encountered
The full suite's serial pass (`run_split.sh`, `ser8.log`: 61 min 28 s). The slowest-30
list was almost all Laravel live-boot tests at a uniform 32–40 s. A uniform cost like
that points to a fixed step rather than to the work under test.

## What it caused to fail
Turnaround: every verification and push waited about an hour, and 51 of the 105 serial
files are live-boot files. Nothing returned a wrong result.

## What the bug was identified to be
Measured on one real boot (`LABGEN-HHB-0003`, the SSRF test's cell):

| Step | Time |
|---|---|
| assemble the app | 0.01 s |
| `composer install` | **51.61 s** (27 s with a warm Composer download cache) |
| `artisan key:generate` | 0.27 s |
| boot | 0.3 s |
| one request | 0.25 s |
| close | 1.6 s |

Measured on one Django boot (`test_labgen_django_live_boot_phase_b.py`):
`python -m venv` took 2.7–3.0 s and `pip install` 4.4–5.2 s, out of a boot of about
10 s.

Measured on one Spring Boot boot: `mvn package` took 3.9 s, then the JVM boots. Each
app's Java code differs, so the compile is real work, not invariant: not changed.

Measured on test collection, with cProfile over the 66 Laravel live-boot files:
- collection took 121 s, of which 105 s was the five uncached network probes, re-run
  in every importing module;
- Maven alone: 24 calls × 2.7 s = 66 s;
- Composer 16 s, Bundler 10 s, pip 8 s, Go 4 s.

## Root cause analysis
Five Whys:
1. *Why did each Laravel test take 30–50 s?* `composer install` ran on every boot.
2. *Why did it run every boot?* The harness assembles each app in a fresh temporary
   directory and installs into it. That is correct for the app's own files, but the
   dependency set never changes, because the lock pins it.
3. *Why was that not noticed?* The suite was split into a parallel and a serial pass,
   and the serial time was attributed to "live boots are slow" without measuring the
   phases of one boot. The decision log's own entry from 10-14 ("Laravel live-boot
   tests ~33 s each, one boot per test; module-scoped boot fixtures are the real
   speed-up") guessed at the fix without measuring the cause. It was never acted on.
4. *Why were the probes repeated?* Each module's `skipif` calls its `*_available()`
   function at import, and the probe beneath it had no cache. That is invisible per
   file and adds up to minutes per process.

**Root cause:** expensive, invariant setup (a locked dependency install, a capability
probe) was placed in the per-boot and per-module path instead of being done once and
reused. The suite's duration was never broken down by measurement, so the cost was
taken as inherent.

## Corrective action
Commit `deecf49` and the bookkeeping commit after it (CC-LAB-0256, FR-LAB-173):
- **One install per host.**
  - `live_boot.cached_vendor()` runs one real `composer install --no-scripts` per key:
    the skeleton's `composer.json` and `composer.lock` plus the php and composer
    versions.
  - It works under an exclusive file lock (concurrent workers wait), builds in a
    scratch directory, and publishes by rename plus a `complete` marker. An unmarked
    entry is rebuilt.
  - The cache lives at `~/.cache/fuzzlab/laravel-vendor/` (`$XDG_CACHE_HOME`, or
    `FUZZLAB_LARAVEL_VENDOR_CACHE`).
- **Per app.**
  - `materialize_vendor()` hard-links the package files and copies `vendor/composer/`
    and `vendor/autoload.php`, the only files `dump-autoload` rewrites in place.
  - Then `composer dump-autoload --optimize` builds this app's classmap and runs the
    post-autoload-dump scripts (`package:discover`), as the install did.
- **Django:** `django_live_boot.cached_venv()` builds the pinned environment once per
  pin and interpreter, at its final path under a file lock, used only once `complete`
  exists. Apps only import from it.
- **The five `*_available()` checks are `functools.lru_cache`d** (one probe round trip
  per process). The probes themselves stay uncached.

  The first attempt cached the probes, and that broke two tests in
  `test_labgen_conformance_live_boot_probe.py`: they patch the environment and call the
  probe repeatedly. My search for the change's consumers was piped through `head -20`
  and the output was cut off before that file. The truncated search was then trusted
  as complete. This is the impact-identification failure analysed in the BUG-0141
  supplement, repeated here. It was found by running the serial pass, not by review.
- **Measured after:**

  | | Before | After |
  |---|---|---|
  | cold boot (fills the cache) | — | 26.7 s |
  | warm boot | 27–52 s | 3.05 s |
  | collecting the Laravel live-boot files | 121 s | 10 s |

  Both twins of the measured cell still answer as their tests require: the vulnerable
  twin 200, the secure twin 400.
- **Django test file** (`..._phase_b.py`): 57 s → 8.7 s warm.
- **Serial pass:** 61 min 28 s (`ser8`) → 38 min 45 s (`ser9`, Laravel fix only, with
  the probe-cache regression above, since fixed).
- **The serial pass removed.**
  - Run in parallel (3 workers), the former serial files hit one failure. Its
    investigation found a real defect: a live boot could run against another test's
    server (BUG-0143, fixed). **Correction:** that failure itself recurred later with the
    fix in place; its cause is open as BUG-0147.
  - A second failure, BUG-0144, was a racy test oracle, fixed the same way.
  - On the fixed commit `6e44a3f`, two consecutive parallel runs of those files passed:
    1716 passed, 0 failed, 14 min 20 s each.
  - `scripts/verify_change.py` now runs every file in one parallel pass; a file is
    serial only with a recorded, measured reason.

## Recurrence review
- **PA-0012 / PA-0035 / BUG-0125:** bounded and complete subprocess lifecycles. Related
  area (the same harnesses), different defect (correctness, not cost). No match.
- **PA-0005 / PA-0009:** probe that a capability is actually usable. Those PAs created
  the probes. Caching keeps the probe real (one real round trip per process), so the
  rule still holds.
- **BUG-0141:** the same pattern one level up. A cost was accepted as inherent instead of
  measured, and an hour-long verification loop was repeated without asking why it was
  an hour. Not a prior PA failure (PA-0141 is newer), but the same lesson: measure
  before accepting.

No prior bug or PA covers test-suite cost; none found.

## Preventive action
PA-0148 (`docs/PREVENTIVE_ACTIONS.md`):
- invariant setup is done once and reused, never per test;
- a step that takes more than a few seconds is measured, phase by phase, before
  anyone calls it inherent;
- the guard test pins that the harness has no per-boot install and that every
  toolchain probe is cached.

**PA-0002 sweep:**
- the other harnesses (Spring Boot `mvn package`, Rails `bundle install`, Django, Go
  `go build`) are measured per test in the full-suite breakdown below, and anything
  invariant found there is moved out of the per-boot path the same way;
- `tests/test_labgen_node_bff_multitarget.py`'s npm probe is per module fixture and
  already runs once per module.
