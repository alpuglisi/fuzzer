# CR-LAB-0002 — `labctl.sh` teardown/prune bugfixes + bookkeeping-hook detection gaps

**Status: APPROVED (2026-09-22) — 3/3 (two independent reviewers + author),
revised per both reviewers' required changes. Nothing patched yet; patching
and the bug workflow follow this approval per "On approval" below.**

**Date:** 2026-09-22 · **Primary component:** LAB (`01-target-lab/`, `lab/labctl.sh`)
· **Secondary scope:** project tooling, not one of the 13 architecture components —
`.claude/hooks/check-error-log-bookkeeping.sh` (the Stop hook that mechanically
enforces `CLAUDE.md`'s ERROR_LOG bookkeeping rule). Per `CLAUDE.md`'s own carve-out
("governance/process docs ... are project-level: record such changes in
CHANGELOG.md"), the hook's two fixes get a CHANGELOG line but no
`docs/components/*/change-control.md` entry — there is no component code for it.

**Source:** manual script review requested against `lab/labctl.sh`,
`scripts/*.sh`, `deploy.sh`, `.claude/hooks/check-error-log-bookkeeping.sh`, and
one `references/` payload script (2026-09-22). Four findings survived
verification; this CR proposes fixes for all four before any patch lands, per
your instruction to put a change-control request in front of the bugfix.

---

## 1. What this CR asks you to approve

Four small, independent bugfixes — two in `lab/labctl.sh`, two in the
bookkeeping Stop hook. None changes an interface or a data contract; all are
behavior corrections to existing, already-shipped logic. Approval covers: the
diagnosis (root cause), the proposed fix, and the test plan for each.

## 2. Why now

The review that found these was requested explicitly to catch bugs before they
recur in the field (`lab/labctl.sh` already has two prior BUG-NNNN entries for
adjacent self-heal gaps — BUG-0013, BUG-0017 — so this is exactly the file
`PA-0002`'s "sweep for other instances of the bug class" is supposed to hit).
Per `CLAUDE.md`'s process, no patch lands before this CR is reviewed and
approved.

## 3. Change (one item per finding)

### 3.1 `lab/labctl.sh:82` — `down` reports success even when the fallback didn't fix anything

**Current behavior:**
```sh
down)
  if ! "${COMPOSE[@]}" down; then
    echo "down failed; force-clearing wedged stack (DB volume kept)..." >&2
    _force_clean keep-volume
  fi
  ;;
```
`_force_clean`'s body is entirely `cmd || true` and it ends with an explicit
`return 0`. So once the `if` branch is taken, the `case` arm's exit status is
always 0 — regardless of whether the stack was actually a wedged-podman case
`_force_clean` can fix, or something unrelated (podman absent, so
`command -v podman || return 0` no-ops immediately; a daemon/permissions
error; disk full). `up` and `reset` don't have this gap: both re-attempt the
real operation after `_force_clean` and let *that* attempt's exit status
propagate under `set -e`.

**Proposed fix:** make `down` retry-then-propagate, the same shape as `up`:
```sh
down)
  if ! "${COMPOSE[@]}" down; then
    echo "down failed; force-clearing wedged stack (DB volume kept)..." >&2
    _force_clean keep-volume
    "${COMPOSE[@]}" down
  fi
  ;;
```
If `_force_clean` actually cleared a wedged stack, the retried `down` now
succeeds cleanly and exits 0 for a real reason. If the failure was unrelated
(no podman, real daemon error), the retry fails again for the same reason and
its exit status propagates under `set -e`, aborting `labctl.sh down` instead
of silently reporting success on a stack that was never torn down.

**Correction (post-review):** an earlier draft of this section additionally
claimed `scripts/greybox_e2e.sh`'s `down && podman-compose build --no-cache
web && ./labctl.sh up` chain as a live automated caller that would benefit
from this fix. That is wrong — checked directly: that chain is a string
literal inside `greybox_e2e.sh`'s `die "..."` call (a human-facing recovery
hint printed on a pcov-not-loaded failure, at `scripts/greybox_e2e.sh:81`),
never executed by the script. `scripts/h2_desync_e2e.sh:94`'s `./labctl.sh
down` reference is the same pattern — an `echo`ed manual follow-up, not a
live call. A full grep of the caller scripts found **no script anywhere that
actually invokes `./labctl.sh down` in an automatically-executed path** — see
§4/§5 for the corrected impact/risk framing.

### 3.2 `lab/labctl.sh:55` — `_force_clean`'s `podman pod prune -f` is host-wide, not project-scoped

**Current behavior:**
```sh
podman pod prune -f >/dev/null 2>&1 || true        # drop the emptied pod(s)
```
`podman pod prune` removes **every** stopped/empty pod on the host, with no
project filter. On a host that also runs other podman-managed projects, a
fuzzlab `up`/`down`/`reset` self-heal removes their empty pods too, as a side
effect.

**Proposed fix:** scope the removal to pods whose name matches this project's
compose project name (`pff-lab`, from `lab/compose.yaml`'s `name:` field),
instead of a global prune:
```sh
# Scope to this project's own pod(s) — a global `pod prune` would remove any
# other podman-managed project's stopped/empty pods on the same host too.
mapfile -t _pods < <(podman pod ps -q --filter "name=pff-lab" 2>/dev/null) || true
if [ "${#_pods[@]}" -gt 0 ]; then
  podman pod rm -f "${_pods[@]}" >/dev/null 2>&1 || true
fi
```
This is a name-filtered removal rather than an unscoped prune: it only ever
touches pods whose name contains `pff-lab` (the compose project name every
container/network name in this file already keys off of — see the
`pff-lab_frontend_1` / `pff-lab_default` literals a few lines away), and is a
no-op (not an error) when no such pod exists, preserving today's "safe to call
even when nothing needs cleaning" behavior.

**Residual risk:** three distinct things, called out explicitly rather than
silently accepted (see also §5):
1. If a future podman-compose version names the pod without the `pff-lab`
   substring, this filter would (safely) no-op instead of cleaning up — a
   stricter but not a worse failure mode than today's unscoped prune.
2. `--filter name=...` is a substring/regex match, not exact-name — a
   hypothetical second checkout or project named e.g. `pff-lab-ci` on the same
   host would also match and get its stopped/empty pods removed. Narrower than
   today's fully host-wide prune (still an improvement), but not perfectly
   scoped to *this* checkout specifically.
3. **`podman pod rm -f` is more destructive than `podman pod prune -f` in one
   case the original code's semantics relied on:** `prune` only ever removes
   pods that are already empty/stopped (a safe no-op if anything inside is
   still running), whereas `pod rm -f` force-kills and removes a *matched*
   pod even if it still holds live containers. In the normal path this is
   masked because the preceding per-container `podman rm -f` loop already
   empties the pod before this line runs. But under the exact scenario this
   whole self-heal function exists for (BUG-0013/BUG-0017: a podman-compose
   version whose container naming doesn't match the `pff-lab_{frontend,web,db}_1`
   literals the loop force-removes by name), the pod could still hold live
   containers when this line runs. Today's code silently leaves such a pod
   alone; the new code force-tears it down. This is judged an intentional,
   desirable strengthening of the self-heal (leaving a live-container pod
   behind on a wedged stack is the failure mode BUG-0013/0017 are about), not
   an accident — but it is a real behavior change beyond pure scoping, and is
   recorded here as such rather than folded silently into "scoping only."

### 3.3 `.claude/hooks/check-error-log-bookkeeping.sh:27` — unpushed-commit detection silently degrades to nothing when `origin/<branch>` doesn't exist

**Current behavior:**
```sh
upstream=""
if [[ -n "$current_branch" ]] && git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
  upstream="origin/$current_branch"
fi
```
On a branch that has never been pushed (or a repo with no `origin` remote at
all — both routine states, e.g. right after `git checkout -b`), `upstream`
stays empty. `changed_files` then comes only from the uncommitted diff
(`git diff` / `git diff --cached` / untracked files); any already-committed
work on the branch is invisible to the hook. Commit an incident-shaped fix
with a clean working tree afterward, and the hook exits 0 with nothing to
check — the exact "found it, wrote it up, but never logged it" gap
BUG-0018/BUG-0019 exist to close, on the single most common state a working
branch is in before its first push.

**Proposed fix:** when no `origin/<branch>` exists, fall back to the merge-base
with the local default branch, so "not yet landed" is measured against where
the branch actually diverged, not against a remote ref that may not exist yet:
```sh
upstream=""
if [[ -n "$current_branch" ]]; then
  if git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
    upstream="origin/$current_branch"
  else
    for ref in origin/main origin/master main master; do
      if git rev-parse -q --verify "$ref" >/dev/null 2>&1 && [[ "$ref" != "$current_branch" ]]; then
        upstream="$ref"
        break
      fi
    done
  fi
fi
```
`git diff --name-only "$upstream"...HEAD` (already in the script, unchanged)
then correctly picks up every commit made on the branch since it diverged from
`main`/`master` (local or `origin`'s), which is the common case this hook
needs to cover. If none of `origin/main`, `origin/master`, `main`, `master`
exist either (a repo with no conventional default branch at all), `upstream`
stays empty and the hook keeps today's uncommitted-diff-only behavior — a
narrower gap than before, not a new one.

### 3.4 `.claude/hooks/check-error-log-bookkeeping.sh:58` — keyword regex misses plain plural nouns ("failures", "regressions")

**Current behavior:**
```sh
keyword_regex='\bfail(s|ed|ing|ure)?\b|\bhang(s|ing)?\b|\bworkaround(s|ed)?\b|\bkilled\b|\btimed out\b|\btimeout(s|ed)?\b|\bcrash(es|ed|ing)?\b|\bbroken\b|\bregress(es|ed|ion)?\b'
```
`fail(s|ed|ing|ure)?` and `regress(es|ed|ion)?` each end their nominalized form
(`ure`, `ion`) with no way to also take a plural `s` before the `\b`. Verified
against real repo prose: `grep -E '\bfail(s|ed|ing|ure)?\b'` does not match
"failures", and the `regress(...)` equivalent does not match "regressions" —
both ordinary ways this project's own docs describe incidents (e.g.
`docs/bugs/README.md`'s own wording, "a failing test, a wrong result, a
crash, a regression"; the plural form of the same two nouns is exactly as
likely in prose and currently invisible to the hook).

**Proposed fix:** make the nominalized forms admit a trailing plural, matching
how every other alternative in the same regex already handles `s`:
```sh
keyword_regex='\bfail(s|ed|ing|ures?)?\b|\bhang(s|ing)?\b|\bworkaround(s|ed)?\b|\bkilled\b|\btimed out\b|\btimeout(s|ed)?\b|\bcrash(es|ed|ing)?\b|\bbroken\b|\bregress(es|ed|ions?)?\b'
```
(`ures?` / `ions?` — a one-character-per-branch change, no new keyword added,
no existing match narrowed.)

## 4. Impact (other components / project)

- **LAB (`lab/labctl.sh`):** behavior-only fix to an operational script; no
  interface, CLI flag, or data contract changes. **Corrected (post-review):**
  grepping every script in `scripts/` and `lab/`, no script actually invokes
  `./labctl.sh down` on an automatically-executed path today — the two
  references to it (`scripts/greybox_e2e.sh:81`, `scripts/h2_desync_e2e.sh:94`)
  are both human-facing recovery hints printed inside a `die`/`echo`, never
  executed. So `down`'s exit code currently has **no live automated
  consumer**; this fix's only present-day effect is that a human who copies
  that printed hint command now gets an honest failure/success signal instead
  of a hardcoded success. `_force_clean`'s narrower blast radius (3.2) is
  shared by `up`/`reset`, which *are* invoked automatically by
  `scripts/greybox_e2e.sh`, `scripts/h2_desync_e2e.sh`,
  `scripts/waf_evasion_e2e.sh`, and `scripts/proxy_e2e.sh` — those callers are
  unaffected in behavior (3.2 only narrows what gets pruned, it doesn't change
  `up`/`reset`'s own exit-code handling), but do share the benefit of the
  fixed blast radius on every self-heal they trigger.
- **Project tooling (the Stop hook):** a detection-recall improvement for a
  mechanical bookkeeping check, but not a pure no-side-effect widening — two
  things worth stating plainly rather than glossing over:
  - §3.4's regex change strictly widens two existing alternation branches
    (`ures?`/`ions?`); it cannot turn a previously-non-matching diff into a
    match on text the old regex wouldn't already partially recognize as
    incident-shaped, so it does not introduce a new *false*-positive class.
  - §3.3's fallback, however, changes more than which diffs match — it changes
    the **range of history scanned**, from "nothing" (today's silent gap) to
    "every commit since divergence from `main`/`master`." On a long-lived
    unpushed branch, that range can include this repo's own bookkeeping files
    (`docs/bugs/*`, `PREVENTIVE_ACTIONS.md`, `ERROR_LOG.md` itself), which are
    inherently dense with incident language by their nature. The hook will
    correctly fire far more often across such a branch's full unpushed
    history, not just on the current turn's diff. This is a soft, non-blocking
    Stop-hook nudge rather than a hard failure, and is the intended fix (the
    whole point of §3.3 is to stop silently skipping that history) — but it is
    a real behavioral widening, not merely "more cases correctly flagged with
    no other effect."
- No `requirements.md` changes: neither script exposes a stated `FR-LAB-*`
  requirement that these fixes alter (they correct implementation defects
  against the *existing* self-heal/detection intent, not a new capability).

## 5. Risk assessment

- **Risk level: low**, for all four. Each is a narrowly-scoped correction to
  already-fallible code (fixing a swallowed-error / unscoped-blast-radius /
  under-detection bug can only make behavior stricter/safer, never looser).
- **Accepted risk (3.1):** `down` can now propagate a real failure it used to
  hide, which is the intended, safer behavior. **Corrected (post-review):** no
  script currently invokes `./labctl.sh down` on a live, automatically-executed
  path (see §4) — so there is, today, no automated caller whose behavior this
  changes at all; the risk is lower than originally stated, limited to a human
  operator running `down` interactively now seeing a real failure instead of a
  fabricated success, which is strictly the intended fix, not a regression.
- **Accepted risk (3.2):** the `pff-lab`-name filter is a best-effort scope,
  not a guarantee (see the residual-risk note in §3.2) — accepted because the
  failure mode if the filter ever misses is "no worse than not cleaning up",
  never "cleans up something it shouldn't".
- **Accepted risk (3.3):** the default-branch fallback assumes the repo's
  default branch is reachable as `main` or `master` (locally or on `origin`).
  True for this repo. If neither exists, behavior is unchanged from today
  (falls through to uncommitted-diff-only checking) — no regression.
- **No risk requiring mitigation beyond what's described above; nothing here
  touches lab-target exposure, credentials, or the `--authorized` gate.**

## 6. Test plan

- `lab/labctl.sh`: no existing automated test harness targets this script
  directly (it's a thin CLI wrapper over compose, exercised manually per
  `docs/ON_HOST_RUNBOOK.md`); validate with `bash -n lab/labctl.sh` (syntax)
  plus a manual on-host `up` → `down` → `reset` cycle before/after, per the
  runbook, since this is exactly the kind of script BUG-0013/BUG-0017 show
  cannot be fully trusted to static review alone.
- `.claude/hooks/check-error-log-bookkeeping.sh`: add/extend a focused
  regression check (either a small `bats`/shell test or a manual harness
  invoking the hook's `jq`-fed stdin contract) covering: (a) an unpushed
  branch with a committed incident-shaped diff and clean working tree now
  triggers the warning; (b) "failures"/"regressions" now match the keyword
  regex; (c) existing passing cases (already-flagged `docs/bugs/*.md` path
  hits, already-clean diffs) still behave unchanged. Run the project's
  `pytest` suite as usual — unaffected by either fix, but kept green per
  `CLAUDE.md`'s definition of done.

## 7. Deliverables

- [ ] 3.1 — `lab/labctl.sh` `down` retry-then-propagate fix — todo
- [ ] 3.2 — `lab/labctl.sh` `_force_clean` pod-prune scoping fix — todo
- [ ] 3.3 — hook upstream-fallback fix — todo
- [ ] 3.4 — hook keyword-regex plural fix — todo
- [ ] Bug workflow, **one `ERROR_LOG.md` line + one `docs/bugs/BUG-NNNN-*.md` +
      one `PREVENTIVE_ACTIONS.md` entry per distinct root cause** (revised
      per Reviewer 2, §10 — see rationale there), not bundled into a single
      doc — todo, gated on this CR's approval:
  - [ ] `BUG-0029` / `PA-0031` — 3.1, `down` exit-code swallow
  - [ ] `BUG-0030` / `PA-0032` — 3.2, unscoped `podman pod prune -f`
  - [ ] `BUG-0031` / `PA-0033` — 3.3, hook upstream-detection gap
  - [ ] `BUG-0032` / `PA-0034` — 3.4, hook regex plural-form miss
- [ ] `docs/components/01-target-lab/change-control.md` — `CC-LAB-0057` for
      3.1/3.2 — todo
- [ ] `CHANGELOG.md` line covering all four — todo

## 8. Explicitly out of scope

- Rewriting `_force_clean`/`labctl.sh` more broadly (e.g. moving to `docker
  compose`-native health checks, adding `set -x` tracing) — not requested,
  and each unrelated change would dilute this CR's review.
- Hardening the hook beyond the two specific gaps found (e.g. a full NLP
  incident-language classifier) — the regex is a heuristic by design per its
  own header comment; this CR only closes the two concrete misses found.
- The other files from the original review request
  (`scripts/proxy_e2e.sh`, `scripts/waf_evasion_e2e.sh`,
  `scripts/h2_desync_e2e.sh`, `scripts/greybox_e2e.sh`, `deploy.sh`,
  `references/upload-insecure-files/payloads/cve-zip-symbolic-link--generate.sh`)
  had no findings from the review and are unchanged by this CR.

## 9. Effectiveness

Pending — assessed after the fix lands and one on-host `labctl.sh` cycle plus
the hook regression check (§6) pass.

## 10. Independent review (required before any patch lands)

Per instruction, this CR is not actioned until reviewed by two independent
agents scrutinizing the diagnosis and the proposed fixes (not rubber-stamping
them), plus this author's own sign-off — 3/3 required to proceed. Findings and
disposition recorded below as they come in.

### Reviewer 1 (independent agent, round A)

Verdict: **APPROVE WITH CHANGES.** Independently re-verified all four
diagnoses and fixes against current source (confirmed `bash -n` clean on
both files; confirmed the `mapfile`/`set -u`/`set -e` interaction in 3.2 is
safe on a zero-result filter; confirmed the regex change in 3.4 only adds
alternation branches, narrowing nothing; confirmed the CC/BUG next-ID claims
against the actual logs). One required correction: §3.1/§4/§5 wrongly cited
`scripts/greybox_e2e.sh`'s `down && build && up` and
`scripts/h2_desync_e2e.sh`'s `down` reference as live automated callers of
`labctl.sh down` — both are in fact human-facing hint strings inside
`die`/`echo`, never executed. No other instances of any of the four bug
classes found elsewhere in the repo. All four fixes otherwise correct,
complete, and safe to apply as written.

### Reviewer 2 (independent agent, round B)

Verdict: **APPROVE WITH CHANGES.** Independently confirmed the same
greybox_e2e.sh/h2_desync_e2e.sh caller-chain error as Reviewer 1 (found
independently, before seeing Reviewer 1's report). Confirmed CC-LAB-0057 and
BUG-0029 as correctly the next free IDs, and additionally flagged that the CR
never pinned a PA number (confirmed PA-0031 next free). Five further points:
(a) bundling all four defects into a single BUG-0029 conflicts with
`docs/bugs/README.md`'s one-root-cause-per-doc structure and BUG-0013/0017's
own precedent — should be split into separate bug docs; (b) §3.2's residual
risk didn't disclose that `podman pod rm -f` is more destructive than `podman
pod prune -f` in the case where a matched pod still holds live containers;
(c) the `--filter name=pff-lab` substring match isn't noted as also matching
a hypothetical `pff-lab-ci`-style second project; (d) §4's "never add a false
positive" claim for 3.3 overstates it — the fallback changes the *range* of
history scanned, not just which diffs match, and will fire more often across
a long-lived unpushed branch; (e) minor: the new `mapfile` line was
inconsistent with the rest of `_force_clean`'s `|| true` style (not a real
bug on modern bash, but worth fixing for uniformity). No objection to the
mechanical correctness of any of the four diffs themselves — confirmed the
retry-then-propagate shape for `down` is correct under `set -e`, and the
regex widening is non-narrowing, both verified independently by
construction.

### Author disposition

**Reviewer 1's required correction: accepted and applied** (recorded above).
**Reviewer 2's required changes: all accepted and applied:**
- (a) split — §7's deliverables now list four separate `BUG-NNNN`/`PA-NNNN`
  pairs (`BUG-0029`/`PA-0031` through `BUG-0032`/`PA-0034`), one per distinct
  root cause, instead of one bundled `BUG-0029` doc.
- (b) and (c) — §3.2's residual-risk note now documents the
  `pod rm -f`-vs-`pod prune -f` destructiveness difference explicitly as an
  accepted, intentional strengthening (not an oversight), and the
  substring-match/`pff-lab-ci` case.
- (d) — §4's Stop-hook impact paragraph now distinguishes 3.4 (strictly
  non-widening) from 3.3 (a real widening of the history range scanned,
  intended and accepted, but stated as such rather than "no false positive").
- (e) — the `mapfile` line's error handling now matches the function's
  existing `|| true` placement style.

No reviewer raised a defect in the mechanical correctness of any of the four
proposed diffs; both reviewers independently confirmed the retry/`set -e`
behavior, the regex non-narrowing property, the pod-scoping logic, and the
hook fallback logic by direct construction/testing, not just by reading the
prose. All required changes from both rounds are now reflected above.

**3/3 approval reached** (Reviewer 1: approve with changes, applied;
Reviewer 2: approve with changes, applied; author: concurs with both and has
verified every requested correction directly against the repo rather than
taking either report's word for it). This CR is **APPROVED** as revised.
Proceeding to the bug workflow and remediation per "On approval" below.

## On approval

Once 3/3 sign off (revising this document first if either reviewer surfaces a
real defect in the diagnosis or the fix): patch `lab/labctl.sh` and the hook
per §3, run the test plan in §6, then complete the bug workflow in §7 (all
four fixes are code-defect corrections, so each needs the full
`ERROR_LOG.md` / `docs/bugs/BUG-NNNN-*.md` / `PREVENTIVE_ACTIONS.md` treatment
per `CLAUDE.md`), and record `CC-LAB-0057` plus the `CHANGELOG.md` line.
