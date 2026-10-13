# BUG-0064 — Templates used inline script/style that the app's own CSP blocks: saved preferences never applied, Overview severity bar empty

- Date: 2026-10-13
- Status: fixed
- Severity: low–medium (UI only. A saved theme, density or collapsed sidebar was never
  restored on any page; the Overview "Findings by severity" bar drew no segments. No
  data, security gate or finding was affected; the CSP itself was correct.)

## Description
`CC-UI-0026` (2026-09-22) gave every response a strict Content-Security-Policy,
`default-src 'none'; script-src 'self'; style-src 'self'; …` (`fuzzlab/web/app.py::_CSP`).
Several templates still used constructs that policy refuses:
- an inline `<script>` in `templates/base.html` (every page): the "no-FOUC" script that
  applies the saved `fl-theme` / `fl-density` / `fl-collapsed` before first paint;
- inline `style=""` attributes:
  - `sections/overview.html:120`, the severity segments' widths;
  - `sections/launcher.html:129` (rendered once per activity, so 10 violations per page
    load) and `sections/launch.html:126`, a margin.

The browser blocked them all silently.

## Where encountered
Found on 2026-10-13 in the same real-Chromium check that found BUG-0063. Every page
logged "Refused to execute inline script because it violates … script-src 'self'".
`/` also logged "Refused to apply inline style … style-src". Both reviewer agents of
this change's review gate confirmed it independently (`/launcher`: 10 `style-src-attr`
violations), as did a worktree of `origin/main` @ `0800e42`.

## What it caused to fail
- **Saved display preferences were lost on every page load.** `shell.js` only *writes*
  `fl-theme` / `fl-density` / `fl-collapsed` when you toggle them (`shell.js:24-44`);
  the blocked inline script was the only reader. So a chosen dark theme, compact
  density or collapsed sidebar reset to the default on every navigation. Reviewers
  confirmed this live: `data-theme` was null after a reload with `fl-theme=dark` saved.
- **The Overview "Findings by severity" bar was empty.** Its segments had no width, so
  only the bar's background showed. The counts in the legend below it were unaffected.
- A small spacing loss on the Launcher (cosmetic).

## What the bug was identified to be
Markup that a CSP added later forbids, left in templates: one inline `<script>` block
and three inline `style` attributes. `templates/sections/launch.html` is rendered by no
route; it was fixed anyway so the static guard holds, and is recorded here as dead.

## Root cause analysis
Five Whys:
1. Why were the preferences never applied? The browser refused the inline script that
   applies them.
2. Why? `CC-UI-0026` added `script-src 'self'` (correctly), and the templates still
   carried an inline script written earlier (`CC-UI-0021`'s app shell). `CC-UI-0025`
   had even noted "the no-FOUC inline `<head>` script is unchanged".
3. Why didn't `CC-UI-0026`'s verification catch it? Its checks were `TestClient` tests
   of the security headers and the gate (`test_web_security.py`), which never execute a
   page. Its two real-browser tests were recorded as "2 skipped (… Chromium isn't
   installed)". When they do run, they assert DOM text, not CSP violations.
4. Why did a test actually assert the bug? `tests/test_web_frontend.py:110` asserted
   `'localStorage.getItem("fl-theme")' in body  # no-FOUC inline script`, so the inline
   script was locked in as expected markup.
5. Why was nothing in place to check page markup against the policy? Nothing tied the
   templates to the CSP that governs them: no static check, and no browser check.

**Root cause:** the same as BUG-0063. The panel's client-side behavior (here, what the
browser executes or applies under the app's own CSP) had no test that ran in a real
browser and failed on a violation. Tightening the CSP was verified only at the header
level. The one browser path was optional and skipped where verification happened.

## Corrective action
Delivered in `CC-UI-0037` (`docs/components/12-diagnostics-and-ui/change-control.md`),
after a 3/3-agreed pre-change review, in the same commit as `CC-UI-0036`:
- **`base.html`:** the no-FOUC script moves verbatim to `static/js/prefs.js`, loaded as
  a classic blocking `<script src>` at the same place in `<head>`, so it still runs
  before first paint. The CSP is unchanged: a hash would break on any whitespace edit,
  and a nonce needs per-response plumbing through the raw ASGI middleware.
- **`overview.html`:** the severity bar becomes one server-rendered inline `<svg>`. Each
  segment is a `<rect x width>`; those are presentation attributes, which CSP does not
  treat as inline style. Colors come via `fill:` in `overview.css`. It keeps
  `role="img"` and the `aria-label`, puts each count in a `<title>`, and needs no JS
  (the page's own no-JS contract).
- **`launcher.html` / `launch.html`:** the margin becomes class `ft2--spaced`.
- **Tests:**
  - `tests/test_web_frontend.py` now asserts `prefs.js` is referenced in `<head>`
    before the stylesheets, that the inline script is gone, and that `prefs.js` is
    served as JavaScript (required under `nosniff`).
  - New static guard `tests/test_web_templates_csp.py` (20 tests): no template may
    contain an inline `<script>`, a `<style>` block, a `style=` attribute, an `on*=`
    handler or a `javascript:` URL. Each pattern is proven first on must-match and
    must-not-match fixtures. With the fix reverted it flags exactly the four original
    sites.
  - The browser tests from `CC-UI-0036` check zero CSP violations on every page, that
    a saved theme is applied, and that severity widths are proportional to the counts.
    All fail with the fix reverted.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0063 / PA-0065**, found the same day. Same root cause (client-side behavior
  never run in a real browser by any test that runs); a different mechanism (CSP
  enforcement, not a library option). Filed as its own bug because the fix differs,
  under the shared PA-0065.
- **BUG-0005 / PA-0005**: the same root-cause class as for BUG-0063 (a real path
  bypassed by a double, here `TestClient`, which never applies a CSP). The failure
  analysis is the one in BUG-0063 and is not repeated here.
- **BUG-0012 / PA-0013** (a self-test must assert the system's true contract, not an
  intuitive-but-wrong premise). Related to Why 4: `test_web_frontend.py` asserted that
  the blocked construct was present, encoding the wrong premise that the inline script
  works.

**Result: a recurrence of the BUG-0005 / PA-0005 class, the same as BUG-0063.**

## Prior-preventive-action failure analysis
The same as BUG-0063's analysis of PA-0005 (escape hatch with no backstop, too narrow
in what it named, not mechanized), plus one point specific to this bug:
- **PA-0013** says a test must assert the true contract. It did not catch a test that
  asserted a construct the app's own policy forbids, because nobody compared that test
  to the policy. The contract (`_CSP`) and the markup lived in different files, with
  nothing linking them.

## Preventive action
**PA-0065**, shared with BUG-0063 (see that report and `docs/PREVENTIVE_ACTIONS.md`).
For this mechanism specifically:
- `tests/test_web_templates_csp.py` mechanically ties the templates to the CSP. It
  includes a test that fails if `_CSP` ever gains `unsafe-inline` or loosens
  `script-src`/`style-src`, so the guard's premise is revisited if the policy changes.
- Any change that tightens a security policy (CSP, Permissions-Policy, Trusted Types)
  must be verified in a real browser over every page (`test_web_pages_browser.py`
  under `FUZZLAB_REQUIRE_BROWSER=1`), not only by asserting the header is sent.

**PA-0002 sweep** of the templates and static JS:
- Inline `<script>`: `base.html` only (fixed).
- `style=` attributes: three (fixed).
- `<style>` blocks, `on*=` handlers, `javascript:` URLs: none.
- JS writes styles only through the CSSOM (`el.style.*`) in `chart.js`, `msgeditor.js`
  and uPlot. CSP does not block those writes, as reviewers confirmed in a browser.
- No `innerHTML`, `setAttribute("style")`, `eval` or `new Function`.
