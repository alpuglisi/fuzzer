# Spike 002 — commix as an independent oracle against DVWA

**Date:** 2026-09-21 · **Status: succeeded.** Second executed action in the
lab-generator program, completing the "Recommended next action" item 1 from
`LAB_SEED_AUTHORING_PLAYBOOK.md` (validate commix the same way Spike 001
validated sqlmap).

## What was done

1. Cloned `digininja/DVWA` into the same session scratchpad as Spike 001 —
   not into this repository. **License confirmed by reading `COPYING.txt`
   directly: GPL-3.0**, consistent with every other "spirit" precedent this
   project has checked. Used purely as a live test target; nothing copied.
2. Ran DVWA **natively** (PHP built-in server, local MariaDB), loopback-only,
   same rationale as Spike 001 (Docker Hub pulls are blocked by this
   environment's egress policy). DVWA's `disable_authentication` +
   `DEFAULT_SECURITY_LEVEL` env vars made this much lower-friction than
   vAPI/Laravel — plain procedural PHP, no Composer vendor tree, no PHP 8.4
   compatibility patching needed at all.
3. Used DVWA's own vulnerable/secure pair for command injection:
   **`vulnerabilities/exec/source/low.php`** (raw `shell_exec('ping ' .
   $target)`, no validation) as the vulnerable variant, and
   **`impossible.php`** (octet-by-octet numeric validation of the IP before
   use, plus an unrelated anti-CSRF check) as the secure twin — confirmed
   manually with curl before involving any tool: `127.0.0.1 ; id` leaked
   `uid=0(root)...` on `low.php` and was correctly rejected
   (`ERROR: You have entered an invalid IP.`) on `impossible.php`.
4. Ran `commix` headlessly (`--batch`) against both.

## Results

- **Vulnerable (`low.php`):** commix correctly identified the `ip` parameter
  as injectable via three independent techniques — results-based classic,
  time-based blind, and file-based blind — in well under a minute, with no
  human confirming or writing anything.
- **Secure (`impossible.php`):** commix correctly reported **"POST
  parameter 'ip' does not seem to be injectable"** — the actual target
  parameter cleared with no false positive, within about 20 seconds. It
  then moved on to sweep the irrelevant `Submit` parameter (a static
  button value, never a real injection candidate) and got stuck in a
  false-positive re-verification retry loop against a timing-based noise
  signal there, running for several minutes without concluding before it
  was killed manually. **The parameter that actually mattered gave a
  clean, fast, correct negative; the tool's default behavior of sweeping
  every POST field is what caused the runaway, not the oracle question
  itself.**

## Two methodological findings, both useful design input

- **`disable_authentication` mode reads the security level from the
  environment variable, not the session cookie.** Setting a
  `security=impossible` cookie against a server started with
  `DEFAULT_SECURITY_LEVEL=low` had no effect — DVWA's own source
  (`dvwaPage.inc.php`) hard-codes this when authentication is disabled. Had
  to run two separate server instances (one per security level) rather than
  one server with a cookie switch. Not a finding about the oracle tools
  themselves, but a reminder that a generator's own test harness needs to
  know which "mode" a given app instance is actually honoring, rather than
  assuming a client-supplied parameter controls it.
- **A rotating anti-CSRF token defeats a naive tool run, for reasons
  unrelated to the vulnerability class being tested.** `impossible.php`
  regenerates its CSRF token on every page load (`generateSessionToken()`),
  so a token captured once and replayed by commix was stale by the second
  request, and commix — reasonably — kept treating every response as a
  rejection without ever concluding cleanly, running far past a reasonable
  timeout. **Fix applied for this isolated test: the CSRF check was
  disabled in a local copy of `impossible.php`** (one line commented out,
  diff below), specifically to test the command-injection defense
  (input validation) in isolation from an unrelated defense (CSRF), the
  same "test one transform at a time" principle this project's own
  minimal-pair design already relies on. **Design implication for the real
  generator:** the oracle wrapper (or the cell's manifest declaration) needs
  to either scope each security assertion to the one transform under test
  (not incidentally blocked by an unrelated control), or the wrapper needs
  session/token-refresh awareness before invoking a tool like sqlmap/commix
  against a token-protected endpoint. This is the same class of lesson as
  Spike 001's `--ignore-code=401` finding: **tool-oracles need the wrapper
  to handle a target's ambient defenses that aren't the class under test,
  or they will under-test rather than fail loudly.**

  ```diff
  - checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
  + // CSRF check disabled for isolated command-injection oracle test (SPIKE-002)
  ```

## What this does and doesn't prove

**Proves:** commix, like sqlmap in Spike 001, works as an independent
oracle — correct positive, correct negative, zero original exploit code
written by anyone — extending the validated set of classes from
{SQL injection} to {SQL injection, OS command injection}.

**Doesn't prove:** anything about SSTImap, Nuclei, or ZAP (still
unintegrated per the playbook), and doesn't yet address the reusable
oracle-wrapper function (playbook item 2) that would encode the
`--ignore-code`/ambient-defense lessons from both spikes automatically
rather than requiring per-target manual tuning.

## Cleanup

The local `impossible.php` CSRF-check edit was reverted to the original
(`impossible.php.bak` diffed and restored) once the test concluded.
Everything lived under the session scratchpad; nothing was copied into this
repository. Both PHP dev server instances were stopped.
