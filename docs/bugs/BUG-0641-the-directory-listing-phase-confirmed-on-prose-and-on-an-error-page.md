# BUG-0641 — The directory-listing traversal phase confirmed on prose and on an error page

- Date: 2026-11-20
- Status: fixed (CC-FUZZ-0641, FR-FUZZ-641); found by the orchestrator's independent review of
  lane ACC before merge, never merged or released
- Severity: high for the oracle (a false-positive path traversal on ordinary pages), caught
  before it reached the integration branch.

## Description
CC-FUZZ-0640's listing phase (`PathTraversalFsPathReadStrategy._directory_listing`, commit
684fab9) confirmed when an answer contained 4 of 25 `/etc` names as words anywhere in the
text, absent from a control naming bare `etc`. Seven names are English words (`group`,
`issue`, `profile`, `environment`, `hosts`, `shells`, `motd`); the probe's status was not
read; the control differed from the probe in its separators *and* its target.

## Where encountered
The orchestrator's review of branch `ccr-e5c7c0c6-r9ladz-accuracy` at 2275dcb. Reproduced by
this lane (2026-11-20) through the real `Oracle.confirm_outcome`: "Welcome to the group! Edit
your profile. Report an issue. Shells and hosts." answered to every value but the control →
confirmed; an "Internal Server Error: an environment issue in group profile hosts shells"
page answered to any value holding `/` → confirmed.

## What it caused to fail
Any page whose prose holds four such words, or any app that answers path-shaped values with
an error or help page naming them, would be reported as a path traversal on every
path-traversal candidate. The 11 labs' AFTER runs (CC-LAB-0360) did not happen to contain
such a page, so the numbers were right and the confirmer was not.

## What the bug was identified to be
(1) the signal was a word match anywhere, not the structure of a listing; (2) the name set
held common words; (3) the control was not of the probe's type (no separators), so the
separator alone could make the difference; (4) a non-2xx probe answer could confirm.

## Root cause analysis
Five Whys:
1. *Why did prose confirm?* Names were matched as tokens anywhere and four words sufficed.
2. *Why words?* The list was built from bWAPP's listing and an `ls /etc`, choosing entries
   present everywhere, without asking whether each is also an English word.
3. *Why did an error page confirm?* The control `etc` lacked the probe's separators, so an
   app keyed on separators answered the control differently.
4. *Why was neither caught by tests?* Every fixture was a listing (true positive) or a page
   that always shows the names (the control rule); none was prose, or a page that differs
   with the separator.
5. *Why were those fixtures not required?* PA-0084(2)/PA-0117 require a false-positive
   fixture per context and a control "of the probe's type, minus what the probe tests";
   I applied them as the existing strategy's file phase does, without deriving what "the
   probe's type" means for a new signal, and no guard checks it.

**Root cause:** a new confirmation signal was judged by token presence instead of by the
structure it claims (a listing's items), and its control changed more than the tested target;
the existing rules that forbid both were followed by analogy, not checked for the new signal.

## Corrective action
CC-FUZZ-0641 (FR-FUZZ-641): names count only as whole listing items (`_listing_items`: a
line, a JSON string, an HTML text node; a directory's `/` or http.server's `@` dropped); the
name set holds only non-English `/etc` files (27); the probe answer must be 2xx; the control
is the same value with `etc` replaced by a random sibling (same separators, same depth).
Measured on four independent listing implementations (os.listdir lines, Node
`fs.readdirSync` JSON, Python `http.server`, nginx 1.27 autoindex) plus bWAPP; the name set
on five bases (Debian/Ubuntu container 20, mariadb 22, mongo 20, Oracle Linux 17, Alpine 10).
Tests: the reviewer's prose and error-page cases do not confirm; every measured shape
confirms; the control is a sibling with the probe's separators.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for confirmers that matched a signal by
presence and controls not of the probe's type. Matches: **BUG-0083 / PA-0084** (reflected-XSS
confirmed on a break-out substring anywhere: same root cause, presence instead of structure)
and **BUG-0117 / PA-0117** (strategies confirmed on a signature a benign page also showed;
PA-0117(1): "the control has the probe's type, minus what the probe tests").

## Prior-preventive-action failure analysis
- **PA-0084** is written for XSS contexts ("an element outside inert content, an injected
  attribute ..."); its enforcement (`tests/test_oracle_xss_structural.py`) covers the XSS
  strategies only. A new non-XSS signal had no structural definition to meet, so it was
  never checked: **too narrow**, and **not enforced** beyond XSS.
- **PA-0117(1)** states the control rule generally but is enforced by discovery of
  strategies against fixed fixtures (`PA-0117(3)`), which cannot see whether a new phase's
  control keeps the probe's form: **not enforced** at the level it fails (the control's
  construction), and **not followed** here (I copied the file phase's bare-name control).

## Preventive action
**PA-0641** (strengthens PA-0084 and PA-0117(1)): (1) a content signal is matched as the
structure it claims, never as tokens anywhere, and its vocabulary excludes common words;
(2) a control is built from the probe by replacing only the tested target, keeping
separators, depth and encoding; (3) every confirmer phase has a prose fixture and an
error-page-for-any-similar-value fixture that must not confirm, and is measured on at least
two independent implementations of the behaviour it recognises (cited in its FR).
Enforced by `tests/test_path_traversal_directory_listing.py` (named in PA-0641).

Sweep (PA-0002): the other strategy whose control drops the probe's form is the file phase
of the same class and `PathTraversalStrategy` (`passwd` vs `../../etc/passwd`). Their signal
is `root:.*:0:0:` (a structure no prose holds), so the separator-only difference cannot make
a false confirmation from prose; an app that prints a passwd-shaped line only for
separator-holding values would. Recorded as a residual in CC-FUZZ-0641, not changed in this
lane (an existing confirmer outside the review's scope).
