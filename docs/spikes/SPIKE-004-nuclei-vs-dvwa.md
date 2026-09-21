# Spike 004 — Nuclei as an independent oracle against DVWA (path traversal / LFI)

**Date:** 2026-09-21 · **Status: succeeded**, with one genuine defect found and
fixed in the wrapper before it ever shipped (`BUG-0023`). Fourth executed
action in the lab-generator program, extending the Addendum-E tool-oracle set
from `{SQL injection (sqlmap), OS command injection (commix)}` to
`{..., path traversal / LFI (Nuclei)}`. Per the task scope for this lane, only
**one** class was implemented and validated for real (path traversal/LFI) —
the four classes Nuclei is mapped to in the wider research (path
traversal/LFI, XXE, open redirect, known-CVE) are explicitly not all in scope
here; XXE and known-CVE templates are flagged in the task brief as a much
larger, separate undertaking, and open redirect was left unattempted rather
than spreading this pass thin across two classes for shallower coverage of
each.

## What makes this spike different from Spikes 001/002

sqlmap and commix each auto-detect a vulnerability against a declared
parameter — the tool itself *is* the oracle. Nuclei has no such auto-detection:
it runs hand-authored YAML templates and reports which ones matched. So this
spike validates two things together: (1) a hand-authored template
(`lab/nuclei-templates/path-traversal-etc-passwd.yaml`) that actually
confirms the class it claims to, and (2) that Nuclei's CLI/output conventions
can be wrapped into the same `confirmed_vulnerable | confirmed_secure |
inconclusive` shape the sqlmap/commix wrapper uses — which turned out to need
a real design correction (below), not just glue code.

## What was done

1. **Searched for a permissively-licensed target first**, as asked, rather
   than reusing Spike 001/002's GPL-3.0 apps by default. Checked three real
   candidates by reading their source directly:
   - **OWASP Juice Shop** (`juice-shop/juice-shop`, confirmed **MIT** by
     reading `LICENSE`) — has a file-serving route
     (`routes/fileServer.ts`) that looks like a traversal candidate, but its
     own code explicitly rejects any `file` parameter containing `/`
     (`if (!file.includes('/'))`) before ever touching the filesystem path —
     genuinely hardened against classic dot-dot-slash traversal, not a
     usable positive case for this template. `routes/quarantineServer.ts` has
     the identical guard. Rejected as a target for this class (not a license
     or licensing problem — a real absence of the vulnerability in the
     current codebase).
   - **snyk-labs/nodejs-goof** (confirmed **Apache-2.0** by reading
     `LICENSE`) — its intentional-vulnerability surface is almost entirely
     *vulnerable npm dependencies* (it exists to demo dependency scanning),
     not custom traversal-sink code; grepping every route for
     `req.(query|params|body)` combined with `path|file|read|send` found
     nothing resembling an unsanitized filesystem read. Rejected: no genuine
     application-level path-traversal sink to test against.
   - **OWASP/railsgoat** (confirmed **MIT** by reading `LICENSE.md`) — has a
     genuine, unsanitized sink:
     `BenefitFormsController#download` builds a file path directly from
     `params[:name]` and calls `send_file` on it with no validation. This
     *is* a real permissively-licensed path-traversal vulnerability. Not used
     for the live run: its `Gemfile` pins Ruby `3.4.1` against this
     environment's installed `3.3.6` (the same class of version-pinning
     friction Spike 001 hit with vAPI/PHP 8.4), plus a full Rails app boot
     (database, session-backed login in front of the vulnerable route) was a
     larger time cost than this spike's scope justified once a working
     alternative was in hand. Recorded here rather than silently dropped,
     since it is a legitimate target for a future pass or for Phase 3's own
     seed authoring.
   - **Decision:** fell back to **DVWA** (`digininja/DVWA`, **GPL-3.0**,
     confirmed by reading `COPYING.txt` — same app Spike 002 already used),
     consistent with this project's established "cite/test-only, copy
     nothing" posture (Addendum D). This is a documented, justified deviation
     from "permissively-licensed," not an oversight: two permissive
     candidates were read and rejected for a genuine absence of the
     vulnerability, and the one with a real permissive-licensed flaw
     (railsgoat) cost materially more setup time than DVWA for the same
     validation value in this pass.
2. Ran DVWA **natively** (PHP built-in server, local MariaDB), loopback-only,
   `DISABLE_AUTHENTICATION=1` + `DEFAULT_SECURITY_LEVEL=low` /
   `DEFAULT_SECURITY_LEVEL=impossible` on two separate ports — identical setup
   to Spike 002, for identical reasons (DVWA reads the security level from the
   environment, not a client-controlled cookie, when auth is disabled).
3. **Confirmed both cases manually with `curl` before touching Nuclei**, per
   the playbook:
   - Vulnerable (`vulnerabilities/fi/source/low.php`): `$file = $_GET['page'];`
     then (in `index.php`) `include($file);` with **zero validation**.
     `?page=../../../../../../../../etc/passwd` returned
     `root:x:0:0:root:/root:/bin/bash` verbatim.
   - Secure twin (`vulnerabilities/fi/source/impossible.php`): an **allowlist**
     of exactly four filenames (`include.php`, `file1.php`, `file2.php`,
     `file3.php`); the identical traversal payload returned `ERROR: File not
     found!`.
4. **Installed Nuclei from source** (`go install
   github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`, v3.11.1) — no
   prebuilt binary was available in this environment and Docker Hub pulls are
   blocked here (same environment constraint Spike 001 already documented).
5. **Wrote one hand-authored template**,
   `lab/nuclei-templates/path-traversal-etc-passwd.yaml`: a parameterized GET
   request (`{{BaseURL}}{{endpoint_path}}?{{param_name}}={{payload}}`) fuzzing
   four dot-dot-slash/encoding variants against `/etc/passwd`, matching
   `status: 200` **and** a `root:[^:]*:0:0:` body regex (both conditions
   required, so a generic 200 page can never false-positive).
6. Ran `nuclei -u <base> -t <template> -var endpoint_path=... -var
   param_name=page -jsonl` (no `-silent` — see the finding below) against
   both DVWA instances, then against a third, deliberately unreachable target
   (`http://127.0.0.1:9999`, nothing listening) to specifically test the
   wrapper's handling of a broken/unreachable secure twin — a case neither
   Spike 001 nor 002 needed, for reasons explained below.

## Results

- **Vulnerable (`low.php`):** Nuclei's JSONL output contained one match,
  `matched-at: http://127.0.0.1:8091/vulnerabilities/fi/index.php?page=../../../../../../../../etc/passwd`,
  with `/etc/passwd`'s real content (including `root:x:0:0:root:/root:/bin/bash`)
  visible in the captured response body — correct positive, ~1 request
  (`stop-at-first-match: true`), well under a second.
- **Secure (`impossible.php`):** zero JSONL results, exit code `0` — correct
  negative.
- **Unreachable target:** also zero JSONL results, exit code `0` — **identical
  output to the correct negative above.** This is the real finding.

## The load-bearing finding: Nuclei silently reports "no results" for a target it never reached

Unlike sqlmap/commix, Nuclei has no explicit "not vulnerable" textual marker —
a clean scan and a scan against an unreachable target both produce *silence*
on stdout with exit code `0`. Nuclei's own health-check does detect the dead
target and logs (to **stderr**, and only when `-silent` is not passed):

```
[INF] Skipped 127.0.0.1:9999 from target list as found unresponsive permanently: Get "http://127.0.0.1:9999/...": cause="port closed or filtered" address=127.0.0.1:9999 chain="connection refused"
[INF] Scan completed in 2.117746ms. No results found.
```

The **first draft** of `fuzzlab/labgen/nuclei_oracle.py`'s classifier used
`-silent` (for cleaner stdout) and classified purely on "zero JSONL matches +
exit 0" → `confirmed_secure`. Testing it against the unreachable target
(added specifically because a match-only-output tool has no secure-side
marker to fall back on, unlike sqlmap/commix) immediately showed this would
misclassify **any** secure twin that failed to start, had a wrong port, or
was otherwise unreachable as `confirmed_secure` — a false-negative security
verdict silently poisoning the ground truth. Filed and fixed as `BUG-0023`
before this code was ever committed. The fix: never pass `-silent`; check
`run.stderr` for the unreachable-host phrasing before ever returning
`confirmed_secure`, downgrading to `inconclusive` when it's present regardless
of exit code. Verified live: the corrected wrapper returns `inconclusive`
(reason naming the unreachable-host signal) for the dead-port case, and still
returns the correct `confirmed_vulnerable`/`confirmed_secure` for the real
DVWA pair.

**General rule this adds to the oracle-wrapper design (now `PA-0019`,
generalizing the existing Addendum-E "ambient defenses" lesson that Spikes
001/002 left as prose): a tool-oracle wrapper that would classify "no
positive finding" as `confirmed_secure` must independently verify, from the
tool's own diagnostic output, that the tool actually reached and exercised
the target — never infer "secure" purely from a clean exit code and the
absence of a positive match.** This did not apply to `oracle_wrapper`
(sqlmap/commix): swept and confirmed both tools already print an explicit
"not injectable" marker only after actually probing the parameter, so an
unreachable target there already produces neither marker and is already
`inconclusive` by construction (see `BUG-0023`'s sweep note).

## What this does and doesn't prove

**Proves:** Nuclei, wired through a template written for this project, works
as an independent path-traversal/LFI oracle — correct positive, correct
negative, and (after the fix) correctly refuses to call an untested target
secure — with zero original exploit code written by anyone; the exploit logic
lives entirely in the four payload strings + one regex matcher in the
template, exactly as mature and independent of this project as sqlmap's/
commix's own detection engines.

**Doesn't prove:** anything about XXE, open redirect, or known-CVE templates
(explicitly out of scope for this task and not attempted), or about ZAP
(still unintegrated). Only one `(class, target)` pair was validated;
`LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain unintegrated"
line is updated to reflect Nuclei's path-traversal class only, not the whole
tool.

## Cleanup

Both DVWA PHP dev-server instances (ports 8091/8092) and the throwaway
`dvwa_spike004` MariaDB database/user created for this spike were stopped/
dropped once the spike concluded. Everything (Juice Shop, nodejs-goof,
railsgoat, DVWA, the Nuclei source build) lived under the session scratchpad,
never this repository; only the hand-authored template
(`lab/nuclei-templates/path-traversal-etc-passwd.yaml`, original content, not
derived from any cloned project) and the wrapper module were committed.
