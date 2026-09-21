# BUG-0007 — credential store keyed differently than it was looked up; raw traceback on a missing ground-truth dir

- Date: 2026-09-21
- Status: fixed
- Severity: medium (the credential defect made every on-host authenticated run fail with a
  misleading error; the ground-truth defect surfaced a raw traceback instead of an
  actionable message)

## Description
Two related on-host defects were fixed together and recorded as one `ERROR_LOG.md` entry and
one change-control entry (`CC-CORE-0017`), but neither was ever given the investigation
document this project's own process requires for a code defect. This backfills that
document. It covers both symptoms, mirroring how the `ERROR_LOG.md` entry itself already
groups them under one `BUG-0007` tag rather than minting a second number.

**Symptom (1) — credential host-key mismatch:** `CredentialStore` keyed a saved credential by
the exact `--host` string passed to `set-credential` (e.g. `127.0.0.1:8080`), while the
session/browser-auth path looked credentials up by `urlparse(base_url).hostname`, which never
includes the port (`127.0.0.1`). A credential saved with a port could never be found by the
code path that needed it.

**Symptom (2) — ground-truth path traceback:** `fuzzlab auto --ground-truth lab/ground-truth`,
run from inside `lab/`, raised a raw `FileNotFoundError` instead of a usable error message,
because the relative path was resolved against the current working directory rather than the
repo root.

## Where encountered
On-host runbook execution (`docs/ON_HOST_RUNBOOK.md` Part C), following the credential
setup and `fuzzlab auto` invocation steps as written.

## What it caused to fail
(1) `fuzzlab crawl --identity admin` / `fuzzlab session print` failed with
`CredentialError: no credentials for identity 'admin' on host '127.0.0.1'` even after the
runbook's own `set-credential --host 127.0.0.1:8080` step had been run — the store held a
credential, but under a key the lookup path could never construct. (2) `fuzzlab auto` run from
a non-repo-root working directory crashed with a raw, unhelpful `FileNotFoundError` for
`lab/ground-truth/labels.json` instead of naming the problem.

## What the bug was identified to be
(1) `CredentialStore.set`/`get`/`require`/`delete` used the caller-supplied host string
verbatim as the storage key, with no normalization, while the session layer's lookup always
derives a bare hostname via `urlparse(...).hostname`. Two different canonicalizations of "the
same host" were used at the write site and the read site, with nothing forcing them to agree.
(2) `contract.load` let a missing-directory `FileNotFoundError` propagate unchanged instead of
catching it and raising the project's own `ContractError` (already used elsewhere in
`fuzzlab/labels/contract.py` for other ground-truth validation failures) with an actionable
message naming the expected path and the repo-root/absolute-path fix.

## Root cause analysis
Five Whys (symptom 1, the more significant defect):
1. Why did the lookup fail despite a credential being stored? The stored key
   (`127.0.0.1:8080`) and the looked-up key (`127.0.0.1`) were different strings.
2. Why were they different? The write site (`set-credential --host`) took the operator's
   input literally; the read site normalized it through `urlparse(...).hostname` before
   looking it up. Nothing required these two sites to canonicalize identically.
3. Why wasn't that required? There was no single shared normalization function for "the host
   a credential is keyed by" — the convention for what counts as the same host existed only
   implicitly, in the read site's own `urlparse` call, and was never applied at the write site.
4. Why did that gap exist? The credential store was written before the session layer's
   hostname-only lookup was, and nothing revisited the store's key format once the lookup
   convention was fixed on hostname-only.
5. Why wasn't this caught before it reached the runbook? No test exercised save-with-port /
   look-up-by-hostname together — existing tests for `CredentialStore` and for session login
   each used a consistent host form within themselves, so the mismatch only appeared once the
   runbook's own wording (`--host 127.0.0.1:8080`) diverged from the session layer's derived
   form.

**Root cause:** a value (the credential host key) that must be canonicalized identically by
every writer and every reader had its canonicalization applied only at the read site, as an
inline `urlparse(...).hostname` call, rather than in one shared normalization function both
sides go through — the same class of gap PA-0003 already named for storage/serialization
conventions (there: result URL path-form; here: credential host keys), just not yet applied to
this second writer/reader pair.

Symptom (2)'s root cause is narrower: `contract.load`'s file-open path had no error handling
translating a missing-directory OS error into the module's own `ContractError`, which every
other validation failure in that module already raises — an inconsistency within one module
rather than a cross-component convention gap.

## Corrective action
`core/credentials.py` gained `_norm_host`, applied uniformly on `set`/`get`/`require`/
`delete`, so `127.0.0.1`, `127.0.0.1:8080`, and a full URL all resolve to the same stored key;
the `require` error message now prints the exact `set-credential` command with the normalized
host. `fuzzlab/labels/contract.py::load` now raises `ContractError` (naming the expected path
and the repo-root/absolute-path options) instead of letting `FileNotFoundError` propagate, and
`fuzzlab auto` exits cleanly on it. `docs/ON_HOST_RUNBOOK.md` Part C corrected to
`--host 127.0.0.1` and given a working-directory note. Delivered in `CC-CORE-0017` (see
`docs/components/02-core-library/change-control.md`), with `+3 tests` including
`tests/test_credentials.py::test_host_is_keyed_by_hostname_regardless_of_port_or_scheme`
(suite 392 passed / 4 skipped at the time).

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence. **BUG-0003**
("oracle stored findings with full URLs, not path form") is the same *root-cause class* as
symptom (1): a normalization convention (there, URL path-form; here, credential host form)
that must hold across more than one writer/reader was applied at only one site instead of
through one shared function — exactly PA-0003's stated scope ("a storage or serialization
convention that must hold across more than one writer lives in exactly one shared function
that every writer calls at the write site... New writers of the same column/field go through
that shared function"). This is a **recurrence of the BUG-0003/PA-0003 class**, on a different
field (credential host key vs. result URL), not a first occurrence.

## Prior-preventive-action failure analysis
PA-0003 did not prevent this instance because it is scoped by *example* to the convention it
was written against (result URLs / `fuzzlab.core.urls.to_path`) rather than stated as a
general obligation that applies whenever a *new* shared-key convention is introduced
elsewhere in the codebase. The credential store's key format was designed independently,
without being checked against PA-0003's general principle, because PA-0003 reads as "this
specific convention has one home" rather than "every convention like this must have one home."
The rule was not violated through inattention to a known rule — it was never consulted,
because nothing marked the credential-host-key convention as an instance of the *class*
PA-0003 already governs.

## Preventive action
**PA-0021** (see `docs/PREVENTIVE_ACTIONS.md`) — strengthens PA-0003: PA-0003's obligation
("a storage/serialization convention shared by more than one writer or reader lives in exactly
one shared function every participant calls") applies to *every* such convention in the
codebase, not only the one (result-URL path form) it was originally written against. When
introducing or modifying a value that a write path stores and a different read path
independently re-derives or re-parses (credential keys, cache keys, identifiers, normalized
hosts/URLs/paths), check whether a shared normalization function already exists for it before
adding a second, independent derivation — and if the two derivations can disagree, that is
this bug's exact shape regardless of which field is involved. Separately, for symptom (2)'s
narrower class: a validation module that raises a typed error (`ContractError`) for other
failure modes must raise that same typed error for every foreseeable failure at its boundary
(a missing file/directory), not let the underlying OS exception propagate raw.
