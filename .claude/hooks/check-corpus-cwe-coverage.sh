#!/bin/bash
# Stop hook for the vulnerability corpus (BUG-0030; PA-0033 replaced by BUG-0157).
# Every touched docs/research/corpus-examples/*/manifest.yaml entry needs at least
# one well-formed CWE mapping, and every touched cell keeps the owner-requested
# floor of >= 5 vulnerable and >= 5 idiomatic entries, with real pairs. The former
# ">= 2 CWEs unique to each entry" quota is removed: it measured label uniqueness,
# not mapping accuracy (docs/quality/LEAN_QC_PROPOSAL_REV3.md, PA-0033).

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

python3 - "$changed_manifests" <<'PYEOF' 2>"${TMPDIR:-/tmp}/check-corpus-cwe-coverage.$$.err"
import sys

try:
    import yaml
except ImportError:
    # Not a silent pass (L10: no vacuous guard): manifests changed and cannot be read.
    print("PyYAML is not importable by `python3`, so the touched corpus manifests could "
          "not be checked. Install it (pip install PyYAML) or run the check by hand.",
          file=sys.stderr)
    sys.exit(1)

manifests = sys.argv[1].split("\n") if len(sys.argv) > 1 else []
problems = []

# BUG-0157 / PA-0033 (replaced): an entry needs at least one well-formed CWE
# mapping, across `cwe_unique:`, `cwe_shared:` and the legacy `cwe:`. There is no
# per-entry quota of CWEs unique to it: independent examples may correctly share one
# root weakness (MITRE CWE root-cause mapping guidance), and a uniqueness quota made
# acceptance depend on which other files were touched. Accuracy of the mapping is a
# review question; the hook checks only what it can: presence and form.
import re

CWE_ID = re.compile(r"^CWE-[1-9][0-9]*$")

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
        cwes = []
        for key in ("cwe_unique", "cwe_shared", "cwe"):
            value = entry.get(key) or []
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, list):
                problems.append(f"{path}: {fname}: `{key}:` is not a list")
                continue
            listed = [str(v).strip() for v in value]
            dupes = sorted({c for c in listed if listed.count(c) > 1})
            if dupes:
                problems.append(f"{path}: {fname}: `{key}:` lists {dupes} twice")
            cwes += listed
        if not cwes:
            problems.append(
                f"{path}: {fname} has no CWE mapping (`cwe_unique:`, `cwe_shared:` or "
                f"`cwe:`) -- map the precise underlying weakness."
            )
        bad = [c for c in cwes if not CWE_ID.match(c)]
        if bad:
            problems.append(f"{path}: {fname}: malformed CWE id(s) {bad} (expected CWE-<n>)")

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
        "turn lack a well-formed CWE mapping and/or the >= 5 pairs per class floor:",
        file=sys.stderr,
    )
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "Map each entry to the precise underlying weakness in the MITRE CWE index "
        "(https://cwe.mitre.org/data/index.html); more substantiated CWEs are better "
        "(docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md Step 6), and entries "
        "may share one. For the pairs-per-class floor, add vulnerable/idiomatic pairs.",
        file=sys.stderr,
    )
    sys.exit(1)

sys.exit(0)
PYEOF
status=$?

err_file="${TMPDIR:-/tmp}/check-corpus-cwe-coverage.$$.err"
if [[ $status -eq 1 ]]; then
  cat "$err_file" >&2
  rm -f "$err_file"
  exit 2
fi
rm -f "$err_file"

exit 0
