# BUG-0090 — Sensitive JSON containers kept their secrets in proxy history

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0020, CC-CORE-0035)
- Severity: high. Secrets reached every persisted copy of a flow (`flow` rows, the body
  table, the full-text index), which the web UI searches.

## Description
The fix for BUG-0084 redacted a sensitively named JSON key only when its value was a
scalar. A **container** value under a sensitive key was recursed into without the
parent's sensitivity, so its scalars stayed readable:
`{"tokens":["SECRET_A","SECRET_B"],"credentials":{"value":"SECRET_C"}}` came out of both
`redact_body` and the full-message `redact` unchanged. Plural names (`passwords`,
`secrets`, `sessions`, `apiKeys`) were not sensitive at all.

## Where encountered
A third-party review of head `5eb4be9` (finding #1). Reproduced with
`scratchpad/ext/f1_json.py`.

## What it caused to fail
NFR-PROXY-safe and FR-PROXY-11 ("persisted data must not carry credentials in
cleartext"), and `proxy/redact.py`'s own docstring ("JSON (any depth)").

## What the bug was identified to be
`_redact_json` exempted dict/list values from replacement
(`is_sensitive_name(k) and not isinstance(v, (dict, list))`) and recursed into them as
if they were benign. `core.redaction` compared tokens literally, so `tokens` and
`credentials` were in the set by hand but other plurals were not.

## Root cause analysis
1. *Why were the secrets persisted?* A container under a sensitive key was not
   replaced.
2. *Why not?* The implementation kept the container's shape and recursed, so only a
   sensitively named *descendant* would be redacted. `value` is not sensitive.
3. *Why did BUG-0084's tests miss it?* Every planted secret was a scalar.
4. *Why were they all scalars?* PA-0085(2) asked for "each promised class of secret"
   in "every persisted copy". It did not ask for every **value shape** under a sensitive
   name, or every **name form** (plural).

**Root cause:** the redaction test matrix covered where secrets are stored, not what
shape they take or how their name is spelled.

## Corrective action
- **CC-PROXY-0020.** A sensitive JSON key's **whole value** is replaced by the
  placeholder, whatever its type (scalar, list, object, nested). The container's shape
  is not kept: the key's subtree is the secret.
- **CC-CORE-0035.** `core.redaction` folds a trailing plural `s`, but only when the
  folded form is itself sensitive. `passwords`, `secrets`, `sessions`, `jwts`, `pwds`
  and `apiKeys` are now sensitive. `passes` (→ `passe`), `passage`, `hotkeys`,
  `monkeys` and `keystrokes` stay readable. `keys` follows `key`'s rule (the whole
  name, or qualified). Accepted harmless false redactions, stated and pinned by test:
  the whole names `codes` / `pins`, and `session_count`.
- **Tests** (`tests/test_proxy_redaction.py`):
  - 16 sensitive names (singular and plural) × 5 value shapes, planted through
    `HistoryWriter` and searched in every persisted copy and the FTS index;
  - benign containers keep their shape;
  - the review's payload through both entry points;
  - plural, non-over-matching and accepted-false-redaction name lists.

  28 of the new cases fail on `5eb4be9`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0084 / PA-0085:** the same module and the same defect class (a secret persisted
  in cleartext). This is a **recurrence**: my own fix of BUG-0084 left this gap.

## Prior-preventive-action failure analysis
**PA-0085 was too narrow.** Rule 2 said "plant each promised class of secret and search
every persisted copy", and it was followed: every class was planted and every copy
searched. But every planted value was a scalar under a singular name. The rule fixed
*where* to look, not *what shapes and spellings* to plant, so the test passed while
the container case was wrong by construction.

## Preventive action
- **PA-0091** (strengthens PA-0085):
  1. **A redaction test plants each name form × each value shape.** Name forms are
     singular, plural and qualified. Value shapes are scalar, list, object, nested,
     and list of objects. Each combination is searched in every persisted copy.
  2. **A sensitive key redacts its whole subtree.** A redactor never recurses into a
     sensitive container looking for a second sensitive name.

**Sweep (PA-0002):**
- **`core.obs._redact`:** already replaces a sensitive key's whole value (`"***"`),
  whatever its type. It gains the plural fold through the shared predicate.
- **Form and query bodies:** container names (`user[password]`) were already
  tokenised; no container values exist there.
- **Multipart:** the whole part's value is replaced, as before.
- **`config.redacted()`:** project-defined keys, already noted under BUG-0084.
