# BUG-0311 — An external-lab negative and three live checks rested on premises nobody had observed

- Date: 2026-10-15
- Status: fixed (CC-LAB-0300, commit e74fba8)
- Severity: medium. The ground truth would have scored a real finding as a false
  alarm, and two live safety-of-labels checks could not fail (one always passed, one
  failed on harmless traffic). No scored result was published from the wrong label.
  Found in code review before merge.

## Description
Four defects in the external-lab ground truth and its live test, as first committed
(575962e):

1. **A wrong negative.** BWAPP-0047 (`/bWAPP/sqli_17.php`, `User-Agent`,
   `xss-reflected`) was labelled `expected_vulnerable=false`, noted "Rendered through
   htmlspecialchars at every level (sqli_17.php:204)". That covers the success path
   only. A User-Agent that breaks the page's INSERT makes it print `mysql_error()` raw
   (sqli_17.php:102), and the error message carries the value: `x' AND <b>zz</b>` comes
   back unescaped. The same error echo exists for `title` on sqli_1 and sqli_6, which
   had no row at all.
2. **A vacuous live check.** The bWAPP gt pass asserted that the run's session cookie
   still read `security_level=0`. The session manager never adopts response cookies,
   so the cookie is the one set at login whatever the probes did: the assertion could
   not fail.
3. **A wrong live check.** The crawl pass asserted that the web container's access log
   contained neither `security_level_set.php` nor `form_security_level`. The crawler
   harmlessly GETs the "Set Security Level" link, so the first half failed on benign
   traffic (the second live run failed exactly there). POST bodies never appear in an
   access log, so the second half could not fail.
4. **A hand-rolled status vocabulary.** `_checked_candidates` counted a candidate as
   checked when its `oracle_status` was not `None`, `"pending"` or `"skipped"`, so
   inconclusive and confirmer-less statuses counted as checked, and the strings did not
   come from `fuzzlab.core.oracle_status`.

## Where encountered
Code review round 1 of CC-LAB-0300 (reviewer B, findings B1-B3). B1 was then confirmed
live against the fixture (the probe above, on all three pages). B2's access-log half was
already red in the second live run.

## What it caused to fail
- Scoring: a tool that found BWAPP-0047 would have been charged a false alarm, and the
  live test asserts that no negative is flagged, so a correct run would have failed.
- The bWAPP label premise (security level 0 for the whole run) had no working check:
  one assertion always passed and the other failed on a harmless GET.
- The "every tagged row has a checked candidate" assertion could pass on candidates the
  oracle never decided.

## What the bug was identified to be
Labels and assertions written from a premise about the system that nobody had observed
in the system: a negative proven from one output path of several, assertions on a
channel (the session cookie, the access log) that cannot carry the violation they test
for, and a status filter that listed the values it knew to exclude instead of naming the
one value it meant.

## Root cause analysis
Five whys (one chain; the four defects share it):
1. Why was BWAPP-0047 a negative? The source read followed the value to its display
   site, where it is escaped, and stopped there.
2. Why stop there? The negative was treated as proven once the named sink was escaped.
   Nothing required every path the input reaches output by (here the DB error
   handler), or a live probe that drives those paths.
3. Why did the live checks not test what they claimed? Each was written from what the
   author expected the channel to show, never from a run where the premise was broken.
   The session does not change; POST bodies are not logged; a GET of a link is not a
   level change.
4. Why was that not noticed? None of the checks was asked to fail. No negative control
   (a run, a fixture or a reasoned argument) showed that the observation differs when
   the premise is false.
5. Why was the status filter hand-rolled? The test enumerated non-statuses from memory
   instead of importing the one positive constant.

**Root cause:** a label or a live assertion was accepted without showing that it would
come out differently if its premise were false. For a negative, that means probing
every output path. For a check, it means confirming that the observed channel can carry
the violation.

## Corrective action
Commit e74fba8 (CC-LAB-0300 "Code review round 1", B1-B3):
- BWAPP-0047 is now a positive, and BWAPP-0057/0058 were added for the same error echo
  on `title`. All three were verified live, and their notes cite the error path
  (`:102`).
- The two level checks were replaced. Neither pass may probe `security_level` or
  `form_security_level` (read from each run's candidates). A comment in the test states
  the structural reason the level stays 0: the senders adopt no response cookie, so
  only a probe of the level form itself could change it.
- `_checked_candidates` keeps `oracle_status == CHECKED` only, imported from
  `fuzzlab.core.oracle_status`.
- B8 (same review): a flagged negative fails the test in any pass, not only the pass
  its reach tag names.

## Recurrence review
Searched `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or the same root
cause:
- **BUG-0012 / PA-0013**: a self-test assertion must reflect the system's true
  contract, and an on-host self-test must use the construction the offline test proved.
  Same root cause (an assertion written from an intuitive but wrong premise), same layer
  (an on-host test).
- **BUG-0117 / PA-0117(1)**: a fixed signature counts only when a benign control of the
  same point lacks it. This is the same idea at the oracle layer: a claim needs a control
  that shows it can differ. No rule carries it to ground-truth negatives.
- **NFR-LAB-label-accuracy** ("labels derived, not hand-asserted"): a requirement, not
  a PA. The negative was derived from source, but only from part of it.
- **BUG-0001 / PA-0001** (derive expectations from the source-of-truth constant): the
  status filter violated it directly. The rule was in force and simply not followed.

Result: a recurrence of PA-0013's root cause, plus a violation of PA-0001, in a layer
(third-party lab labels and their live checks) that neither rule names.

## Prior-preventive-action failure analysis
- **PA-0013** (BUG-0012) asks for the true contract, but it gives no way to check that
  an assertion meets it. Its only test is "the same construction the offline test
  proved", and these live checks had no offline counterpart (the level premise exists
  only against the running app). It was too narrow and not enforced: it does not require
  showing that the assertion can fail.
- **PA-0117(1)** (BUG-0117) requires a control for oracle confirmations only. The labels
  that score those confirmations were never held to it (wrong layer).
- **PA-0001** was not followed in a new test file. Nothing caught it, because no guard
  greps for hand-written status strings (not enforced). The fix uses the constant.
  Enforcing this repo-wide is a follow-up: tests in locked files also compare status
  strings.

## Preventive action
**PA-0311** (strengthens PA-0013, and carries PA-0117(1) to ground-truth labels):
1. **A ground-truth negative is proven on every path the input reaches output by**,
   including error handlers (DB errors, exceptions, warnings). It is backed by a live
   probe that drives those paths (a quote-breaking value), and its note cites each path
   it checked.
2. **Every live or integration assertion of a premise names the observation that would
   differ if the premise were false, and confirms the observed channel can carry it.**
   An assertion on a channel that cannot carry the violation is replaced by one on a
   channel that can, or by a stated structural argument with a check of the argument's
   own premise (here: no probe of the level parameters).
3. **A status or enum filter names the value it means**, imported from the defining
   module (PA-0001), never a list of values to exclude.

The PA-0002 sweep for this class covered:
- every negative in both new ground-truth dirs (6 rows), each re-checked for paths
  other than the one its note names:
  - BWAPP-0048..0050 are `sqli` negatives. The value is SQL-escaped before the query is
    built, so an error path cannot add an injection. The tool's quote-breaking SQLi
    probes scored all three as true negatives in both exploratory passes.
  - JUICE-0011 and JUICE-0013 already cite the error handler, which escapes.
  - JUICE-0012 (open redirect) redirects to a fixed target on every path, verified
    live;
- every assertion in `tests/test_external_labs_live.py`, each checked against the
  channel it reads;
- the new tests' status comparisons.

This change did not re-sweep the generated labs' negatives for error-path echoes. That
is recorded as a follow-up in CC-LAB-0300, together with the repo-wide guard for
hand-written status strings.
