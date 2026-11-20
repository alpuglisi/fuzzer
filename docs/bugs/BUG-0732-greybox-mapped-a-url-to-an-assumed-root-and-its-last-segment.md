# BUG-0732 — Grey-box mapped a URL to an assumed document root and its last path segment

- Date: 2026-11-20
- Status: fixed
- Severity: medium

## Description
Both grey-box call sites decided "was the endpoint's file covered?" by building a file
name from an assumed root and the URL's last segment: `fuzzlab/greybox/run.py`
(`DEFAULT_APP_ROOT = "/var/www/html"`, `_endpoint_file`) and `fuzzlab/oracle/strategies.py`
(`_GREYBOX_APP_ROOT = "/var/www/html"`, `_greybox_sink_file`), each mapping a URL to
`<root>/<basename of the path>` (any directories flattened, `index.php` for `/`). The run's
coverage filter (`include`) was the same assumed root.

## Where encountered
Lane HEUR's review of lab-fitted heuristics in component 07 (2026-11-20), sub-task
HEUR-CD (C).

## What it caused to fail
On any app not installed as a flat directory at `/var/www/html` the sink was never
covered (M10 never confirmed, `sink_covered` features false, the coverage filter dropped
every line), and on an app with directories `/admin/login.php` was read as the root's
`login.php` -- another file, so a covered root `login.php` made an uncovered admin page
look covered. A front controller (`/users/5`) was mapped to `<root>/5`. Only the flat PHP
lab (CC-LAB-0009's PFF image) matched both assumptions.

## What the bug was identified to be
Lab knowledge (the lab image's document root and flat layout) in the grey-box decision,
instead of reading the endpoint from the coverage the target produced.

## Root cause analysis
Five whys:
1. Why `/var/www/html/<basename>`? CC-FUZZ-0016 wrote the driver for the PFF image, whose
   `pcov.directory` is `/var/www/html` and whose pages are flat PHP files.
2. Why was the layout encoded rather than read? The coverage map was treated as a filter
   input (a prefix) and the URL-to-file mapping as a string build, not as a lookup in the
   coverage the request produced.
3. Why did CC-FUZZ-0024 repeat it? It copied the driver's mapping into the M10 strategy
   to match its advisory count -- two implementations of one mechanism, no owner.
4. Why did no test catch it? Every fixture used `/var/www/html/<flat>.php`: the tests
   restated the lab's layout.
5. Why did no rule stop it? PA-0660 (black-box rule) was written for names, parameters and
   fields; a filesystem layout was not named, and its guard reads answer-key and manifest
   tokens, not paths of a lab image.

**Root cause:** a target-environment assumption (document root and layout) was encoded in
detection logic, duplicated across two call sites with no owner, and only tested against
the lab it came from.

## Corrective action
CC-FUZZ-0710 (FR-FUZZ-710): one owner, `fuzzlab.greybox.coverage.endpoint_file` (SP-145,
proposed), decides the endpoint from the coverage itself -- the covered file whose path ends
with the URL's whole segments (RFC 3875 `SCRIPT_NAME`/`PATH_INFO`, Apache `DocumentRoot`,
`mod_dir`), no verdict when none maps or on a tie; `document_root` derives the coverage
filter from that file; both call sites use it; no default root is kept.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for detection fitted to a lab:
BUG-0660 / BUG-0661 and PA-0660 (the black-box rule: lab names in rules and strategies),
BUG-0124 / PA-0124 (a classifier mapping one lab's shapes), F-011/F-013/F-014. Same root
cause (lab knowledge in detection logic); a different carrier (a filesystem layout, not a
name). Also BUG-0016 (greybox per-point novelty) -- unrelated cause.

## Prior-preventive-action failure analysis
PA-0660(1) names "a name, path, parameter name, field, claim, element, attribute or
value taken from a lab": "path" was read as a URL path, and its guard (PA-0660(5)) builds
its token set from answer keys and manifests, which never contain the lab image's
document root, so `/var/www/html` passed. PA-0124 is narrower still. The prior PA was
**too narrow in its enforcement**: it caught vocabulary, not environment assumptions
(a root, a layout, a server's file naming), and it was not applied to the grey-box
package by any sweep.

## Preventive action
PA-0730 (written by the lane). Proposed content: extend PA-0660 from vocabulary to
environment assumptions -- a detection decision that needs a fact about the target's
deployment (a root, a layout, a framework's file naming) reads it from what the target
produced (coverage, the response) or from a cited public convention, and gives no
verdict otherwise; a mechanism with two call sites gets one owner (SP row). Enforcement
proposal: a guard over `fuzzlab/greybox/` and `fuzzlab/oracle/` string literals for
absolute filesystem roots (`/var/www`, `/srv/`, `/app/`), proven on a synthetic offender,
plus `tests/test_greybox.py::test_both_greybox_call_sites_use_the_one_endpoint_owner`.
