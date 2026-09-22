#!/bin/bash
# Stop hook: mechanically catch the BUG-0030 failure mode (a corpus
# manifest.yaml entry given only a recalled CWE or two, or CWEs merely
# copy-pasted across sibling entries) instead of relying on remembering
# PA-0033. Every entry needs >= 2 CWEs in `cwe_unique:` that are not
# claimed as unique by any other entry this hook checks (a CWE relevant to
# more than one entry belongs in `cwe_shared:` instead and does not count
# toward the floor). See docs/bugs/BUG-0030-*.md.

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
else
  # No upstream tracking branch yet (a freshly created local branch): fall
  # back to the merge-base with the repo's default branch, so a manifest
  # edit already committed this turn (working tree clean, nothing in `git
  # diff`/`git diff --cached`/untracked) is still caught rather than
  # silently skipped -- a committed-but-unchecked edit on an unpushed
  # branch is the same authoring gap this hook exists to catch.
  default_branch=$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null)
  default_branch=${default_branch#origin/}
  for candidate in "$default_branch" main master; do
    [[ -n "$candidate" ]] || continue
    if git rev-parse -q --verify "origin/$candidate" >/dev/null 2>&1; then
      merge_base=$(git merge-base HEAD "origin/$candidate" 2>/dev/null)
      if [[ -n "$merge_base" ]]; then
        upstream="$merge_base"
        break
      fi
    fi
  done
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
                    f"migrate to `cwe_unique:`/`cwe_shared:` per PA-0033's "
                    f"updated standard (>= 2 CWEs unique to this entry, not "
                    f"shared with any other touched entry)."
                )
            else:
                # Neither the new nor the old field is present at all -- the
                # exact BUG-0030 failure mode this hook exists to catch (an
                # under-annotated entry slipping through unflagged). Do not
                # silently drop it from `problems` just because it predates
                # even the legacy `cwe:` field.
                problems.append(
                    f"{path}: {fname} has no `cwe_unique:` (or legacy `cwe:`) "
                    f"field at all -- needs >= 2 CWEs unique to this entry per "
                    f"PA-0033's standard."
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

import os
import glob

# Second mechanical floor (PA-0033): "at least 5 vulnerable/idiomatic pairs
# per class" is its own explicit quantitative instruction and needs its own
# check, not just a restatement in a planning doc. Group by cell directory
# (docs/research/corpus-examples/<cell>/), aggregate every manifest.yaml
# under that cell (not just the ones touched this turn, since a cell can
# span multiple language subdirs and only some may be touched), and
# require >= 5 `role: vulnerable` entries per touched cell.
touched_cells = set()
for path in manifests:
    path = path.strip()
    if not path:
        continue
    parts = path.split("/")
    # docs/research/corpus-examples/<cell>/<lang>/manifest.yaml
    try:
        idx = parts.index("corpus-examples")
        touched_cells.add("/".join(parts[: idx + 2]))
    except (ValueError, IndexError):
        continue

for cell_dir in sorted(touched_cells):
    vulnerable_count = 0
    idiomatic_count = 0
    unpaired_vulnerable = []
    for manifest_path in glob.glob(os.path.join(cell_dir, "*", "manifest.yaml")):
        try:
            with open(manifest_path) as f:
                entries = yaml.safe_load(f) or []
        except (FileNotFoundError, yaml.YAMLError):
            continue
        if not isinstance(entries, list):
            continue
        files_in_manifest = {
            e.get("file") for e in entries if isinstance(e, dict) and e.get("file")
        }
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            role = entry.get("role")
            if role == "vulnerable":
                vulnerable_count += 1
                # A pair, not just a floor count: an orphaned vulnerable
                # entry with no idiomatic counterpart is exactly the
                # unpaired-corpus state the "vulnerable/idiomatic pairs"
                # floor is meant to prevent -- checked via `derived_from`
                # (the field a manufactured pair's vulnerable twin sets to
                # name its idiomatic anchor) pointing at a real idiomatic
                # entry in the same manifest.
                derived_from = entry.get("derived_from")
                if derived_from and derived_from not in files_in_manifest:
                    unpaired_vulnerable.append((manifest_path, entry.get("file", "<unnamed>")))
            elif role == "idiomatic":
                idiomatic_count += 1
    if vulnerable_count < 5 or idiomatic_count < 5:
        problems.append(
            f"{cell_dir} has {vulnerable_count} `role: vulnerable` and "
            f"{idiomatic_count} `role: idiomatic` entries across its "
            f"manifest.yaml files (need >= 5 of EACH -- 5 orphaned "
            f"vulnerable entries with no idiomatic counterparts does not "
            f"satisfy the 'vulnerable/idiomatic pairs' floor, per direct "
            f"instruction)."
        )
    for manifest_path, fname in unpaired_vulnerable:
        problems.append(
            f"{manifest_path}: {fname}'s `derived_from` names a file not "
            f"present in the same manifest -- this vulnerable entry has no "
            f"real idiomatic counterpart to pair with."
        )

if problems:
    print(
        "docs/research/corpus-examples/*/manifest.yaml entries touched by this "
        "turn don't meet the >= 2 unique CWEs per entry standard and/or the "
        ">= 5 pairs per class standard:",
        file=sys.stderr,
    )
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "Research the MITRE CWE index (https://cwe.mitre.org/data/index.html) for "
        "CWEs genuinely specific to each entry's own code, per PA-0033 / "
        "docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md Step 6. For the "
        "pairs-per-class floor, add more vulnerable/idiomatic pairs to the cell.",
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
