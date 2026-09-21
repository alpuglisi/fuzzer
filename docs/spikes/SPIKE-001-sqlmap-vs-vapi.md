# Spike 001 — sqlmap as an independent oracle against vAPI

**Date:** 2026-09-21 · **Status: succeeded.** This is the first executed
action in the lab-generator program — everything before this was planning.
Implements the "Recommended next action" from `LAB_SEED_AUTHORING_PLAYBOOK.md`
/ `CR-LAB-0001` Addendum E §8: validate that an independent tool-oracle can
confirm a label without anyone (human or LLM) hand-authoring exploit logic.

## What was done

1. Cloned `roottusk/vapi` (a PHP/Laravel OWASP-API-Top-10 vulnerable app) and
   `sqlmapproject/sqlmap` into the session scratchpad — **not** into this
   repository. Neither is committed or referenced from generator code; this
   was purely a throwaway local test.
2. **License correction, confirmed by reading the file directly:** vAPI is
   **GPL-3.0**, not MIT as an earlier research report had guessed and
   explicitly flagged as unverified. Used here only as a live test target
   (running it and pointing a scanner at it creates no derivation or
   distribution obligation); still never a source to copy code from, per
   this project's existing posture.
3. Ran vAPI **natively** (PHP built-in server + a local MariaDB install),
   not in Docker — the environment's egress policy blocks Docker Hub
   pulls (`production.cloudfront.docker.com` returned a 403 policy denial,
   correctly not routed around per this environment's own guidance). All
   ports bound to `127.0.0.1` only, consistent with this project's
   loopback-only posture even for a throwaway spike.
4. Identified a genuine SQL injection by reading the source
   (`API8UsersController::login`, string-concatenated into `whereRaw()`) and
   a same-shape, properly-parameterized twin in the same app
   (`API3UsersController::login`, Eloquent `where()` calls) to serve as the
   negative control.
5. Ran `sqlmap` headlessly (`--batch`, no interaction) against both:
   - **Vulnerable endpoint:** sqlmap correctly identified `username` as
     injectable via error-based, time-based-blind, and UNION techniques in
     ~19 seconds / 1106 requests, with no prompts requiring a human.
   - **Secure twin:** sqlmap correctly reported "does not seem to be
     injectable" for both parameters — no false positive.

## Findings that matter for the actual implementation

- **The core thesis holds.** An independently-authored tool can confirm a
  positive on the vulnerable variant and a negative on the secure twin
  without anyone writing exploit logic. This is the first real evidence for
  it in this program, not just a citation from someone else's paper.
- **sqlmap treats a 401 as an auth failure and refuses to test past it by
  default.** vAPI's secure endpoint returns `401` for a failed login, which
  made sqlmap immediately abort with "not authorized" until
  `--ignore-code=401` was added. **This is a real design input for the
  generator's oracle wrapper**: any cell whose "no vulnerability" response
  is a 401/403 needs the wrapper to pass the matching `--ignore-code`, or
  the oracle will silently under-test rather than correctly report secure.
  Add this to the T-LAB0.7 tiered-oracle design.
- **Error verbosity varies the confirmation signal, but doesn't gate it.**
  vAPI's own (opaque) exception handler still leaked a PDO `errorInfo` array
  via `json_encode()` on the exception object — enough for sqlmap's
  error-based technique to fire even without verbose debug output. A
  generator cell with a fully generic 500 page still gave sqlmap enough
  signal via the time-based and UNION techniques. Useful reassurance:
  the oracle doesn't depend on the target being unusually chatty.
- **Docker is not reliably available in every environment this project
  might run in.** This session's egress policy blocks Docker Hub image
  pulls outright. The generator's Level-2 (container) determinism work
  should not assume Docker Hub is reachable in every execution context;
  worth a fallback note when T-LAB0.5/T-LAB0.7 are actually implemented.
- **Running old Laravel/Symfony under a very new PHP is friction, not a
  blocker, but it's real friction.** Getting vAPI (Laravel 8, built for PHP
  7.3–8.0) running under PHP 8.4 required patching ~700 vendor call sites
  for the "implicitly nullable parameter" deprecation (now fatal by
  default) plus one Carbon/PHP-8.4 `date_get_last_errors()` behavior
  change. None of this touched vAPI's own application code — only
  third-party vendor library compatibility with a newer PHP than the
  library targets. **Implication for Phase 3's Laravel emitter:** pin the
  PHP version in the `StackEnv` to something the chosen Laravel version
  actually supports (per `CR-LAB-0001` Addendum D's `StackEnv.base_image`
  field) rather than "whatever PHP happens to be installed" — this spike's
  friction was entirely a self-inflicted version mismatch, avoidable by
  pinning correctly from the start.

## What this does and doesn't prove

**Proves:** the sqlmap-as-oracle half of Addendum E's architecture works,
end to end, against a real (if GPL-licensed, cite-only) vulnerable
application, with zero original exploit code written by anyone.

**Doesn't prove:** anything about the generator itself — no manifest, no
verdict engine, no emitter, no generated cell was involved. This is
evidence for one component of the planned architecture (the tool-oracle),
not a working piece of the generator. The three gap classes (IDOR/BOLA,
business logic, race conditions) and the AutoBaxBuilder trial from
Addendum E remain untested.

## Cleanup

Everything from this spike lived under the session scratchpad
(`/tmp/.../scratchpad/spike-sqlmap-vapi/`), not this repository. The PHP
dev server was stopped; the local MariaDB install remains running
(loopback-only) for the remainder of this session in case follow-up testing
is wanted, and will not persist beyond it. Nothing from vAPI's or sqlmap's
source was copied into this repository.
