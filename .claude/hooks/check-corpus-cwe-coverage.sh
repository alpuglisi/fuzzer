#!/bin/bash
# Stop hook: mechanically catch the BUG-0029 failure mode (a corpus
# manifest.yaml entry given only a recalled CWE or two, or CWEs merely
# copy-pasted across sibling entries) instead of relying on remembering
# PA-0032. Every entry needs >= 2 CWEs in `cwe_unique:` that are not
# claimed as unique by any other entry this hook checks (a CWE relevant to
# more than one entry belongs in `cwe_shared:` instead and does not count
# toward the floor). See docs/bugs/BUG-0029-*.md.

input=$(cat)

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
    sys.exit(0)

manifests = sys.argv[1].split("\n") if len(sys.argv) > 1 else []
problems = []

# Track which entry first claimed each CWE as "unique" so a repeat across
# entries (even across different manifest files) is caught, not just
# within one file.
unique_claims = {}  # cwe_id -> (path, file)

all_entries = []  # (path, file, cwe_unique, cwe_shared)

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
        fname = entry.get("file", "<unnamed>")
        cwe_unique = entry.get("cwe_unique")
        cwe_shared = entry.get("cwe_shared") or []
        legacy_cwe = entry.get("cwe")

        if cwe_unique is None:
            if legacy_cwe is not None:
                # Pre-migration entry using the old flat `cwe:` field.
                problems.append(
                    f"{path}: {fname} still uses the old flat `cwe:` field -- "
                    f"migrate to `cwe_unique:`/`cwe_shared:` per PA-0032's "
                    f"updated standard (>= 2 CWEs unique to this entry, not "
                    f"shared with any other touched entry)."
                )
            continue

        all_entries.append((path, fname, cwe_unique, cwe_shared))

        if len(cwe_unique) < 2:
            problems.append(
                f"{path}: {fname} has only {len(cwe_unique)} cwe_unique "
                f"entr{'y' if len(cwe_unique) == 1 else 'ies'} (need >= 2). "
                f"CWEs shared with other entries go in cwe_shared instead "
                f"and do not count toward this floor."
            )

        for cwe_id in cwe_unique:
            if cwe_id in unique_claims:
                other_path, other_fname = unique_claims[cwe_id]
                if (other_path, other_fname) != (path, fname):
                    problems.append(
                        f"{cwe_id} is claimed as cwe_unique by both "
                        f"{other_path}:{other_fname} and {path}:{fname} -- "
                        f"a CWE relevant to more than one entry belongs in "
                        f"cwe_shared on both, not cwe_unique on either."
                    )
            else:
                unique_claims[cwe_id] = (path, fname)

if problems:
    print(
        "docs/research/corpus-examples/*/manifest.yaml entries touched by this "
        "turn don't meet the >= 2 unique CWEs per entry standard:",
        file=sys.stderr,
    )
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "Research the MITRE CWE index (https://cwe.mitre.org/data/index.html) for "
        "CWEs genuinely specific to each entry's own code, per PA-0032 / "
        "docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md Step 6.",
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
