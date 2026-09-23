# BUG-0035 — `ruby_rails` skeleton's unpinned `json` gem breaks the second request in any session

## Description

Every second (or later) real HTTP request in the same browser-style session
against a `ruby_rails`-emitted app raised a real, uncaught
`ActionView::Template::Error` wrapping `ArgumentError: wrong number of
arguments (given 2, expected 1)`, returning HTTP 500, whenever that request
carried the encrypted `_fuzzlab_app_session` cookie the *first* request's
response set.

## Where encountered

Building `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`'s Phase D
whole-app conformance test for category 1's Shopify/`ruby_rails` pick
("ForgeCart") — `tests/test_labgen_ruby_rails_whole_app_live_boot.py`'s own
first draft, and independently `tests/test_multitarget_ruby_rails_forgecart.
py`'s Phase E test (`fuzzlab.oracle.strategies.ReflectedXssStrategy`
necessarily sends two sequential requests to the same URL/session to detect
a break-out).

## What it caused to fail

Every prior `ruby_rails` live-boot test (Phase A's illustrative cell, and
Phase B's three vulnerable/secure pairs) sent **exactly one** real HTTP
request per booted instance before tearing the app down — so this defect
was latent and unobserved through every one of those tests, despite being
100% reproducible on request #2 of *any* session, on *any* route, including
the app's own inert static pages. The first symptom actually encountered
was a spurious HTTP 500 on the real `/search` reflected-XSS page's second
probe request (the ordinary detection round trip
`fuzzlab.oracle.strategies.ReflectedXssStrategy.confirm` performs: a marker
request, then a break-out request) — which, before root-causing, looked
exactly like a false negative in this app's own new XSS page, not an
environment defect.

## What the defect was

`fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/Gemfile` did not pin the
`json` gem. `activesupport` 8.1.3.1 (this skeleton's pinned Rails version)
declares only `json >= 0` (no upper bound) in its own gemspec, so an
unconstrained `bundle install` resolved the newest available line, `json
3.0.2`. The `json` gem's 3.x series made `JSON.parse`'s second parameter
keyword-only (`def parse(source, on_load: nil, ..., **options)`), but
`ActiveSupport::JSON.decode` (`activesupport-8.1.3.1/lib/active_support/
json/decoding.rb:25`) still calls `::JSON.parse(json, options)`
**positionally**, passing a plain `Hash` as a second positional argument.
Under Ruby 3.x's strict positional/keyword-argument separation, a Hash
passed positionally to a keyword-only parameter list raises exactly this
`ArgumentError`.

`ActiveSupport::JSON.decode` is on the read path of every encrypted
cookie/session read (`ActionDispatch::Middleware::Session::CookieStore
#get_cookie` -> `Cookies::EncryptedKeyRotatingCookieJar#parse` ->
`MessageEncryptor#decrypt_and_verify` -> ... ->
`ActiveSupport::Messages::Metadata.deserialize_from_json` ->
`ActiveSupport::JSON.decode`), so it fires on the **first** request that
presents an already-set session cookie — never the request that *creates*
one. A test suite of only single-request live-boot checks structurally
cannot hit this path.

Root-cause chain, Five Whys:

1. Why did `/search`'s second probe request 500? Because reading the
   session cookie raised `ArgumentError`.
2. Why did reading the session cookie raise `ArgumentError`? Because
   `ActiveSupport::JSON.decode` called `JSON.parse` with an incompatible
   calling convention for the resolved `json` gem version.
3. Why was an incompatible `json` version resolved? Because the skeleton's
   `Gemfile` never pinned `json`, and `activesupport`'s own gemspec
   constraint (`json >= 0`) does not prevent Bundler from resolving a
   `json` major version that breaks `activesupport`'s own internal call
   site.
4. Why did this ship unnoticed through Phase A and all of Phase B? Because
   every live-boot test built so far (Phase A's illustrative cell, three
   Phase B pairs) sent exactly one HTTP request per booted app instance,
   and this defect is invisible on any request that does not carry an
   already-set session cookie.
5. Why did every prior test only send one request? Because each was
   designed to prove its own cell's specific vulnerable/secure divergence
   in isolation — a narrower, sufficient goal for what those dispatches
   scoped, but one that never exercised the "real multi-page session" shape
   a whole assembled app (and any realistic detection strategy that sends
   more than one probe per candidate, like `ReflectedXssStrategy`) actually
   needs. **Root cause: an under-constrained transitive dependency
   (`json`, via `activesupport`'s own unbounded requirement) resolved to a
   version incompatible with a framework internal it is not itself tested
   against, combined with a live-boot test suite whose per-test scope never
   exercised a second same-session request — the two together let a
   100%-reproducible defect ship latent through two full build phases.**

## Corrective action

- Pinned `gem "json", "~> 2.7"` in `fuzzlab/labgen/emitters/ruby_rails/
  stack/skeleton/Gemfile`, with an inline comment recording the root cause
  and this bug ID; regenerated `Gemfile.lock` for real (`bundle install`),
  resolving `json (2.21.2)` — the last pre-3.0 line, whose `JSON.parse`
  still accepts the second argument positionally, restored via a real,
  reproduced-then-fixed `bundle install` (not hand-edited).
- Verified via `bin/rails runner` + `Rack::Test` (bypassing the dev error
  page's backtrace cleaning) that the exact two-request session sequence
  that 500'd before the fix now returns 200/200 after it, with the full
  original backtrace captured for this record (see the reproduction script
  history in this lane's own working notes — the backtrace bottoms out at
  `json-3.0.2/lib/json/common.rb:296:in 'parse'` before the fix, and does
  not appear at all after).
- Re-ran the full `ruby_rails` live-boot test suite (all prior Phase A/B
  tests, plus the new Phase C/D/E tests this same lane added) after the
  fix: all pass for real, including `tests/test_labgen_ruby_rails_whole_app_
  live_boot.py` (12 cells, one shared boot) and `tests/
  test_multitarget_ruby_rails_forgecart.py` (a real `run_auto` pass that
  now genuinely confirms the real `/search` reflected-XSS case).
- Change-control: `CC-LAB-0079` (this fix travels with the Phase D
  whole-app conformance entry it was found while building).

## Recurrence review

Checked `docs/PREVENTIVE_ACTIONS.md` and every prior `docs/bugs/` entry for
a prior occurrence of "an unpinned/under-constrained dependency resolves to
a version incompatible with the code that uses it" or "a test suite's
narrow per-unit scope never exercises a multi-step/stateful interaction a
real deployment needs." Neither matches an existing entry:

- `BUG-0033`/`PA-0035` is the closest by theme (a *capability probe* must
  exercise the real operation path, not an easier proxy) but is about
  pre-flight probes specifically, not about a shipped dependency
  incompatibility reachable only via a usage pattern (multi-request
  sessions) the existing test suite never took. Applying PA-0035 as
  written would not have caught this: `rails_boot_available()`'s network
  probe already does a real `bundle lock` round trip and was never wrong
  about *whether* installation would succeed — `json 3.0.2` installs and
  boots the app fine; the defect only manifests on a specific *request
  pattern* after a successful boot, a different failure class PA-0035's
  own scope (probe fidelity) does not cover.
- `PA-0033`/`PA-0034` are about mechanically enforcing a quantitative floor
  and adversarial-input testing for code-generation sinks — not applicable
  here (no manifest cell's own generated code is at fault; the skeleton's
  dependency graph is).
- No existing bug or preventive action addresses "a test suite whose
  per-unit tests are each individually sufficient for their own narrow
  purpose can, in aggregate, still never exercise a realistic multi-step
  interaction (e.g. two requests sharing one session) that only a
  whole-app/integration-shaped test would." This is a genuinely new failure
  mode for this project's bug taxonomy, not a recurrence — no prior-PA
  failure-analysis section is owed.

## Preventive action

See `docs/PREVENTIVE_ACTIONS.md` `PA-0037` (new preventive action derived
from this bug, per the process above; no prior PA is superseded).
