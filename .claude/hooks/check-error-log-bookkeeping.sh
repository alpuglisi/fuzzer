#!/bin/bash
# Stop hook: mechanically catch the BUG-0018 failure mode (an incident found
# and written up during the turn, but never given its ERROR_LOG.md entry)
# instead of relying on remembering PA-0019. See docs/bugs/BUG-0018-*.md and
# docs/bugs/BUG-0019-*.md.

input=$(cat)

# Recursion guard: only warn once per stop cycle, same pattern as
# ~/.claude/stop-hook-git-check.sh, so an unresolved case doesn't loop forever.
stop_hook_active=$(echo "$input" | jq -r '.stop_hook_active')
if [[ "$stop_hook_active" = "true" ]]; then
  exit 0
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel) || exit 0
cd "$repo_root" || exit 0

error_log="ERROR_LOG.md"
[[ -f "$error_log" ]] || exit 0

current_branch=$(git branch --show-current)
upstream=""
if [[ -n "$current_branch" ]] && git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
  upstream="origin/$current_branch"
fi

# Files touched by this turn's not-yet-landed work: uncommitted changes
# (staged, unstaged, untracked) plus any commits not yet on the remote.
changed_files=$(
  {
    git diff --name-only
    git diff --cached --name-only
    git ls-files --others --exclude-standard
    if [[ -n "$upstream" ]]; then
      git diff --name-only "$upstream"...HEAD
    fi
  } | sort -u
)

[[ -n "$changed_files" ]] || exit 0

# Bookkeeping already touched this cycle -> nothing to catch.
if echo "$changed_files" | grep -qx "$error_log"; then
  exit 0
fi

# Heuristic 1: a new/modified spike or bug write-up is exactly where a real
# "something broke" finding tends to get narrated instead of logged (BUG-0018).
suspect_paths=$(echo "$changed_files" | grep -E '^docs/(spikes|bugs)/.*\.md$')

# Heuristic 2: incident-shaped language added anywhere in the diff, excluding
# ERROR_LOG.md itself (already checked above) and this hook's own file.
keyword_regex='\bfail(s|ed|ing|ure)?\b|\bhang(s|ing)?\b|\bworkaround(s|ed)?\b|\bkilled\b|\btimed out\b|\btimeout(s|ed)?\b|\bcrash(es|ed|ing)?\b|\bbroken\b|\bregress(es|ed|ion)?\b'
keyword_hits=""
{
  git diff -U0 -- . ":(exclude)$error_log" ":(exclude).claude/hooks/check-error-log-bookkeeping.sh"
  git diff --cached -U0 -- . ":(exclude)$error_log" ":(exclude).claude/hooks/check-error-log-bookkeeping.sh"
  if [[ -n "$upstream" ]]; then
    git diff -U0 "$upstream"...HEAD -- . ":(exclude)$error_log" ":(exclude).claude/hooks/check-error-log-bookkeeping.sh"
  fi
} 2>/dev/null | grep -E '^\+' | grep -viE '^\+\+\+' | grep -qiE "$keyword_regex" && keyword_hits="yes"

if [[ -z "$suspect_paths" && -z "$keyword_hits" ]]; then
  exit 0
fi

{
  echo "This turn's not-yet-pushed changes look like they describe something breaking, failing, or being worked around,"
  echo "but $error_log was not part of those changes:"
  if [[ -n "$suspect_paths" ]]; then
    echo "  - new/modified spike or bug doc(s):"
    echo "$suspect_paths" | sed 's/^/      /'
  fi
  if [[ -n "$keyword_hits" ]]; then
    echo "  - incident-shaped language (fail/hang/workaround/killed/timed out/crash/broken/regress) added to the diff"
  fi
  echo "Per CLAUDE.md and PA-0019, check whether this needs an $error_log entry (and, if it's a code defect, the full"
  echo "docs/bugs/ protocol) before finishing. If it genuinely doesn't apply, that's fine — just confirm that."
} >&2
exit 2
