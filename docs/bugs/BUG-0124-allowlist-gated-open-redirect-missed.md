# BUG-0124 — An allowlist-gated open redirect was never detected (Juice Shop)

- Date: 2026-10-14
- Status: fixed (CC-AUD-0034, CC-FUZZ-0067; CC-ML-0029 documentation)
- Severity: medium (a missed finding on the lab as shipped; no safety impact).

## Description
OWASP Juice Shop v20.3.0 has a real open redirect: `GET /redirect?to=X` answers
`302 Location: X` whenever X **contains** one of its allowlisted URLs
(`url.includes(allowed)`). Verified with curl against the loopback lab:
- `?to=https://fzlb-canary.invalid/` → `406`;
- `?to=https://fzlb-canary.invalid/?x=https://github.com/juice-shop/juice-shop` →
  `302 Location: https://fzlb-canary.invalid/?x=…`.

The first `fuzzlab auto` run over all ten categories did not find it.

## Where encountered
Juice Shop testing after phase 2, on the operator's question "wasn't the open redirect
meant to be discovered?". The crawl had linked `/redirect?to=https://github.com/…`
(the link BUG-0123's browser followed off the lab).

## What it caused to fail
The operator's goal: detect the lab's vulnerabilities as shipped, for the classes we
implement. Open redirect is one (`OpenRedirectStrategy`).

## What the bug was identified to be
Two defects:
1. **Candidate selection:** `R-OPEN-REDIRECT` matches parameter names only
   (`url|next|redirect|return|dest|goto|continue|target`); `to` is not one, so
   `/redirect?to` was a candidate for SQLi, XSS and SSTI only. The value, a URL,
   implied the category, but no rule used it.
2. **Confirmation:** the strategy sent one plain canary and confirmed on a `Location`
   prefix. An allowlist checking containment refuses that canary.

## Root cause analysis
1. *Why no open-redirect candidate?* The only rule selects by name, and `to` is not in
   the list.
2. *Why no value rule?* Forms phase 2 (CC-AUD-0032) added value-shape rules for the
   categories its lane needed (command injection: ip/hostname; file inclusion:
   filename/path). `value_shape` already classified `url`, but nothing mapped it to a
   category.
3. *Why did the sweep not add it?* The PA-0002 sweep was run per lane ("the categories
   this lane needs"), not per mechanism ("every category each emitted shape implies").
4. *Why would a candidate still have failed?* The confirmer assumed an unconditional
   reflector: one canary form, no stated list of the server-side filters it cannot pass.

**Root cause:** category selection keyed on names, with the value classifier's shapes
mapped to categories ad hoc per lane; and a confirmer with one probe form and no record
of what it cannot pass.

## Corrective action
- **CC-AUD-0034:** `value_shape.SHAPE_CATEGORIES` (one table: url → open-redirect,
  ssrf; url → file-inclusion deliberately excluded in `SHAPE_EXCLUSIONS`);
  `R-OPEN-REDIRECT-VALUE` and `R-SSRF-VALUE`; `redirect_seed` (http/https only, sliced
  from the original example up to its query, userinfo cut, none for an identifier-like
  path piece), set on crawl points and written to open-redirect evidence only.
- **CC-FUZZ-0067:** `OpenRedirectStrategy` confirms by host (`_lands_on`: urljoin +
  urlsplit, http/https, our token host, `/cb`), and, only after the plain canary
  failed, sends one seeded canary `https://oracle<tok>.example/cb?fzlb=<seed>`.
- **The FR-AUD-20 exception** (operator-approved twice, the second time with its
  corrected reach): fuzzlab never requests the seed's host and never follows the
  redirect, but a target that extracts and fetches embedded URLs could contact it.
  Written into FR-AUD-20/21; enforced by an AST guard on where `redirect_seed` appears
  and a test that the evidence write is gated on the open-redirect category.

## Recurrence review
- **BUG-0121** (open): name-only and unanchored rules. `R-OPEN-REDIRECT`'s regex is
  itself unanchored; this bug is the same class from the other side (a name-only rule
  that *misses*).
- **CC-AUD-0032 / PA-0002:** the value-shape rules came from a per-lane sweep.
- **BUG-0117 → PA-0117:** confirmation assumptions per strategy (single-sample,
  fixed-marker). This is a single-form assumption.

## Prior-preventive-action failure analysis
- **PA-0002 (sweep for the bug class) was too narrow in practice:** CC-AUD-0032 swept
  the categories of its own lane, not every category each shape implies. Nothing
  required the classifier's output set to be mapped completely.
- **PA-0117 (confirmation assumptions)** covered noise and evidence causality, not
  server-side filters a single canary form cannot pass.

## Preventive action
**PA-0124** (strengthens PA-0002 for classifiers and PA-0117 for confirmers):
1. A classifier whose outputs select categories maps **every** output to its
   categories in one table, with deliberate exclusions recorded with a reason; a test
   fails on a shape without a row and on rules that differ from the table.
2. A confirmer that relies on one probe form states the server-side filters it cannot
   pass, or carries a stated second form.

## PA-0002 sweep
| Site | Result | Disposition |
|---|---|---|
| `value_shape.SHAPES` × default rules | url had no rule (open-redirect, ssrf) | fixed (`R-OPEN-REDIRECT-VALUE`, `R-SSRF-VALUE`) |
| url → file-inclusion | deliberately excluded (lane A Q5) | recorded in `SHAPE_EXCLUSIONS` |
| ip/hostname, filename/path | rows present | cleared |
| `OpenRedirectStrategy` | one form, prefix test | fixed (second form, host-based) |
| `SsrfInBandMarkerStrategy` / `SsrfOobStrategy` | send only our loopback listener URL | cleared (no seed, no exception) |

## Residuals
- A protocol-relative example (`//host/x`, shape `path`) gets no rule and no seed.
- An allowlist keyed on a query string is not matched (the seed drops the query).
- A crawled URL with an identifier-like path piece gets no seed (by design).
- The reach of the FR-AUD-20 exception (above), accepted by the operator.
