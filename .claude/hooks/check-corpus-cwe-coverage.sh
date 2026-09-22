#!/bin/bash
# Stop hook: mechanically catch the BUG-0029 failure mode (a corpus
# manifest.yaml entry given only a recalled CWE or two instead of the
# "more is better" research ceiling docs/VULN_CORPUS_EXPANSION_PLAN.md and
# docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md's Step 6 both call
# for) instead of relying on remembering PA-0032. See docs/bugs/BUG-0029-*.md.

input=$(cat)

# Recursion guard, same pattern as check-error-log-bookkeeping.sh.
stop_hook_active=$(echo "$input" | jq -r '.stop_hook_active')
if [[ "$stop_hook_active" = "true" ]]; then
  exit 0
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel) || exit 0
cd "$repo_root" || exit 0

current_branch=$(git branch --show-current)
upstream=""
if [[ -n "$current_branch" ]] && git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
  upstream="origin/$current_branch"
fi

# manifest.yaml files touched by this turn's not-yet-landed work
# (uncommitted changes plus any commits not yet on the remote).
changed_manifests=$(
  {
    git diff --name-only
    git diff --cached --name-only
    git ls-files --others --exclude-standard
    if [[ -n "$upstream" ]]; then
      git diff --name-only "$upstream"...HEAD
    fi
  } | sort -u | grep -E '^docs/research/corpus-examples/.*/manifest\.yaml$'
)

[[ -n "$changed_manifests" ]] || exit 0

python3 - "$changed_manifests" <<'PYEOF' 2>/tmp/check-corpus-cwe-coverage.err
import sys

try:
    import yaml
except ImportError:
    # yaml not available in this environment -- fail open, matching this
    # project's "never assumed present" posture (PA-0005) for an
    # environment-dependent check rather than blocking on a missing tool.
    sys.exit(0)

manifests = sys.argv[1].split("\n") if len(sys.argv) > 1 else []
thin = []

for path in manifests:
    path = path.strip()
    if not path:
        continue
    try:
        with open(path) as f:
            entries = yaml.safe_load(f) or []
    except (FileNotFoundError, yaml.YAMLError):
        continue
    if not isinstance(entries, list):
        continue
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cwe_list = entry.get("cwe") or []
        rationale = entry.get("cwe_count_rationale")
        if len(cwe_list) < 2 and not rationale:
            thin.append((path, entry.get("file", "<unnamed>"), len(cwe_list)))

if thin:
    print(
        "One or more docs/research/corpus-examples/*/manifest.yaml entries touched by "
        "this turn have fewer than 2 CWE IDs and no cwe_count_rationale field:",
        file=sys.stderr,
    )
    for path, fname, count in thin:
        print(f"  - {path}: {fname} (cwe count = {count})", file=sys.stderr)
    print(
        "Per docs/VULN_CORPUS_EXPANSION_PLAN.md / "
        "docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md Step 6 and PA-0032, "
        "research the MITRE CWE index (https://cwe.mitre.org/data/index.html) for "
        "additional substantiated CWEs before finishing, or add a "
        "cwe_count_rationale: field explaining why fewer than 2 genuinely apply.",
        file=sys.stderr,
    )
    sys.exit(1)

sys.exit(0)
PYEOF
status=$?

if [[ $status -eq 1 ]]; then
  cat /tmp/check-corpus-cwe-coverage.err >&2
  exit 2
fi

exit 0
