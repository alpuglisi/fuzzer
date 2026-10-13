# BUG-0068 — The built package shipped 87 of its 485 non-Python files

- Date: 2026-10-13
- Status: fixed (CC-CORE-0032, CC-ML-0022)
- Severity: high for any non-editable install. An installed `fuzzlab web` serves 404s
  for every tab template and every JS/CSS asset. `fuzzlab lab-generate` fails on missing
  templates and stack skeletons. A development checkout (editable install) never showed
  it.

## Description
`pyproject.toml`'s `[tool.setuptools.package-data]` listed per-directory,
**non-recursive** globs, such as `"fuzzlab.web" = ["templates/*.html", "static/*"]`.
setuptools then shipped only the files directly matched. Measured with setuptools
`build_py` on the tracked tree, **87 of 485** non-Python files under `fuzzlab/`
shipped. The missing files included:
- `web/templates/sections/*.html`, which is every tab;
- `web/static/js/*`, `static/css/*` and `static/vendor/*`;
- the lab generator's nested template trees and stack skeletons, dotfiles included;
- data files of packages the table did not name.

## Where encountered
In the ML work's packaging review: FR-ML-6's "packaged no-ML distribution" was flagged
as not built, and building a package to test it showed the file count.

## What it caused to fail
Every user of a real build (`pip install .`, a wheel, an sdist install): the web UI, the
lab generator, and anything reading packaged data outside the few named globs.
Development, CI-in-checkout and every test used the editable install, which reads the
source tree directly, so nothing failed there.

## What the bug was identified to be
The package-data rules were written per directory and were not recursive. Each new
nested directory (`templates/sections/`, `static/js/`, the labgen trees) needed its own
line, which no one added. No check compared the built artefact with the source tree.

## Root cause analysis
Five Whys:
1. *Why did files not ship?* The globs matched only the listed directories' top level.
2. *Why were the globs not updated as directories were added?* Nothing failed when they
   were missed: the editable install hides missing package data.
3. *Why did nothing fail?* Every test and every run used the development stand-in (the
   editable install), never the built artefact.
4. *Why was the built artefact never tested?* The project's verification rules say to
   verify behaviour in the real runtime: the real browser (PA-0065(3)) and the real
   operation path (PA-0035). Each was scoped to one layer, and the shipped package was
   not one of them.
5. *Why per-directory globs at all?* They started small (a DB, a schema dir) and grew by
   accretion, with no recursive rule.

**Root cause:** a shipped artefact was only ever verified through a development
stand-in, and the package-data rule was non-recursive.

## Corrective action
In CC-CORE-0032:
- **One recursive rule.** `"*" = ["**/*", "**/.*"]`: every non-Python file in every
  package, dotfiles included.
- **A deny-list** (`exclude-package-data "*"`) for:
  - caches;
  - credentials and keys: `.env` and its `.local` / `.production` / `.development` /
    `.staging` / `.test` variants, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*id_rsa*`;
  - SQLite side files and `*.sqlite*`;
  - OS and editor junk.

  setuptools matches these with fnmatch (`*` crosses `/`); `**/` patterns do nothing
  there (measured). `*.db` cannot be denied without dropping the tracked indicator DB,
  because there is no re-include. Stray stores are therefore caught by an
  untracked-file guard test plus the clean-checkout release rule (runbook). This
  residual risk is stated.
- **The no-ML switch (FR-ML-6) is now two lines,** documented in `pyproject.toml`:
  `packages.find exclude = ["fuzzlab.ml*"]` **and** `exclude-package-data "fuzzlab" =
  ["ml/*"]`. The recursive rule would otherwise ship `fuzzlab/ml/*.py` as data of the
  parent package (reproduced by both reviewers).
- **`tests/test_packaging.py` (new):**
  - `build_py` from a `git ls-files` copy, whose built set must **equal** the tracked
    set;
  - the deny-list must match no tracked file (the converse);
  - planted secrets and junk are never built, while a planted `.env.example` is;
  - no untracked store or secret sits under `fuzzlab/` (a disk walk minus `git
    ls-files`, so ignored files are seen too);
  - `sdist` ships every tracked file with executable bits kept;
  - the **wheel** is checked too. It skips here, with the reason, because of Debian's
    setuptools `install_layout` bug (an environment issue, ERROR_LOG);
    `FUZZLAB_REQUIRE_WHEEL=1` makes the skip fail;
  - the no-ML switch removes `fuzzlab/ml/` and nothing else.
- **`tests/test_no_ml.py::test_a_real_no_ml_build_passes_the_same_checks` (CC-ML-0022)**
  runs the no-ML child checks against a genuinely ML-free built tree, with no import
  blocker. The editable install's dev-only finder is dropped and asserted.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0063 / PA-0065(3).** No chart rendered in a real browser while every
  server-side test passed. The root cause is the same: behaviour verified in a stand-in
  (the TestClient) rather than the real runtime (the browser).
- **PA-0035.** A capability probe must exercise the actual operation path. Again the
  same class, a stand-in path.

**Result:** a recurrence of the "verified in a development stand-in, not the real
runtime or artefact" class, at a new layer (the installed package).

## Prior-preventive-action failure analysis
- **PA-0065(3) was too narrow.** It required real-browser verification of the web UI,
  so its scope was rendering. The shipped package was outside it.
- **PA-0035 was too narrow.** It was scoped to capability probes.
- **Neither was enforced at the artefact layer.** No test built the package, so the
  editable install answered every question the installed package should have.

## Preventive action
**PA-0070** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens and generalises PA-0065(3)
and PA-0035:
1. **Any claim about shipped or installed behaviour is verified on the built artefact**
   (or the real runtime), never only on the development stand-in. For the package, a
   test builds it and compares it with the tracked source.
2. **Package-data rules are recursive and include dotfiles; exclusions are an explicit
   deny-list.** The deny-list is asserted never to match a tracked file. Hidden
   *directories* are not matched by `**/.*`, so the equality test is the backstop.
3. **The PA-0002 sweep for this class covers every build and ship path.** That means
   package data, `scripts/*.sh` file copies, and the lab Dockerfiles' COPY lists.

**Sweep (PA-0002):**
- **Package data:** fixed.
- **`scripts/*.sh`:** they copy nothing into a distribution. They run from a checkout.
  Not an instance.
- **Lab Dockerfiles:** `lab/` builds copy whole directories (`COPY . …` per
  stack), not per-file globs. They are verified by the existing live-boot tests, which
  build the real images. Not an instance.
- **`labgen`'s `copytree` of skeletons:** it reads from the installed package. Now
  shipped and tested, with modes kept (sdist).
- **No `MANIFEST.in` exists;** the sdist uses the same package-data rule, and is tested.
