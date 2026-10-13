# BUG-0082 — `mutate-run` and greybox sent destructive payloads without `--allow-destructive`

- Date: 2026-10-13
- Status: fixed (CC-MUT-0012, CC-FUZZ-0057)
- Severity: high. With the flag **off**, `run_mutation` sent 10 of 10 `DROP TABLE`
  variants to the target. NFR-MUT-safe says destructive payloads are never emitted
  through the default path.

## Description
The destructive gate lived only in `catalog.record_variant`, at **record** time. Its
docstring said a destructive variant is "never persisted or sent", but every variant
was sent by `HttpFilter` during the search before any record decision.
`greybox.run_greybox` likewise sent `mutation_variant_probes` (and its base probes)
unchecked. The signature regex also ran only on the raw string, so mutation-operator
obfuscations (`DR/**/OP`, `%44ROP`, `+`, case) slipped past it.

## Where encountered
The error-review phase (`scratchpad/review7/r10_destructive.py`).

## What it caused to fail
NFR-MUT-safe and FR-MUT-6 ("refused unless explicitly allowed"), on a live lab target.

## What the bug was identified to be
A safety gate placed at a bookkeeping step (recording) instead of at the action it
guards (sending), and matching only un-normalised text.

## Root cause analysis
1. *Why sent?* No check stood between the search and the sender.
2. *Why was the record-time gate thought enough?* Its docstring asserted "never …
   sent", which was untrue and untested.
3. *Why untested?* The tests asserted only that nothing destructive was *recorded*.
4. *Why did obfuscation slip?* The gate matched raw strings, while the operators exist
   precisely to obfuscate.
5. *Why no rule?* No PA required a safety claim in a docstring to be backed by a test
   of the action it claims to prevent.

**Root cause:** a safety gate at the wrong layer, with an untested "never" claim.

## Corrective action
In CC-MUT-0012 and CC-FUZZ-0057:
- **`catalog.refuse_destructive(payload, allow_destructive)`** refuses when **either**
  the raw payload or one of its normalised forms matches, so normalising only ever adds
  refusals. Normalisation (`normalize_for_gate`):
  - up to 3 rounds of URL decoding, then HTML entities;
  - NUL removed, `+` read as a space;
  - `/*…*/` comments removed;
  - `--` / `#` comments removed to the end of the line (one form), or kept (the other);
  - whitespace collapsed, lower-cased.
- **`HttpFilter(allow_destructive=)`** has `refuses()`, and its send itself raises
  `DestructiveRefused`: the gate sits at the send.
- **`MutationSearch`** skips refused variants. They are counted as `refused`, **never as
  a WAF block**, so the WAF statistics stay clean.
- **`run_mutation`** skips a destructive **base** entirely, because an encoded variant
  can evade the signature, so the base decides. Its summary counts `refused`, and the
  CLI prints them.
- **`greybox.run_greybox`** checks every probe (base and variant) before sending, and
  counts `destructive_refused`; the CLI prints it.
- The catalog docstring now states the send-time gate truthfully.
- **Tests** (`tests/test_destructive_send_gate.py`):
  - 11 obfuscated destructive payloads refused, including `1;#\nDROP` and a
    line-comment-split `INSERT … INTO`;
  - 7 ordinary payloads pass;
  - a destructive base → 0 sends, `refused` 1, `blocked` 0;
  - the flag on → sent;
  - a variant turning destructive → not sent, counted;
  - the filter raises at the send;
  - greybox → 0 destructive sends.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0076 / PA-0077** (the containment boundary didn't cover every per-plugin step):
  **same shape**, a protective boundary at the wrong or a partial layer.
- **BUG-0084** (this batch): a redaction docstring promised what the code didn't do.
  **Same root cause:** an untested safety promise in a docstring.

**Result:** the "safety claim not backed at the action" class. PA-0077 was scoped to
plugins, so it could not cover this.

## Prior-preventive-action failure analysis
**PA-0077 was too narrow** (plugins only). No PA covered safety claims in docstrings,
which is how "never … sent" went unchecked.

## Preventive action
**PA-0083** (covers both BUG-0082 and BUG-0084's docstring promise):
1. A safety gate sits at the action it guards (sending, writing, binding), not at a
   later bookkeeping step.
2. **Every "never / always" safety claim in a docstring is backed by a test that fails
   when the claim is broken.** For a send gate, the test counts sends.
3. A gate matching an obfuscatable signature matches the normalised form too (and the
   raw form: normalising only adds refusals).

**Sweep (PA-0002)** — grep for `never` / `always` safety claims and for
`allow_destructive`:
- **mutation `catalog`:** fixed.
- **`livefilter`:** fixed.
- **`greybox.run`:** fixed.
- **`core/config` `allow_destructive`:** the default-off value.
- **`commandspec`** marks the flag as a destructive gate in the launcher. Verified.
- **The labgen safety matrix:** declarative.
- **The proxy redaction docstring:** BUG-0084.
- **The OOB "loopback-only" docstring:** backed by tests (BUG-0080).
- **`oracle` "sole finding-writer":** backed by tests (`test_oracle`, `test_plugins`, `test_store_adapter`).
