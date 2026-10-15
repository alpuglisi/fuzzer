#!/usr/bin/env python3
"""Stop hook: the change record is declared, and a defect carries its ERROR_LOG entry.

Replaces ``check-error-log-bookkeeping.sh`` (BUG-0018/PA-0019/PA-0020; corrected by
BUG-0157). The old hook guessed at incidents from words in the diff ("fail",
"timeout", "broken" ...): it blocked a README line saying "The timeout setting is 15
seconds." and was satisfied by any edit to ``ERROR_LOG.md``. This hook checks what the
change *declares* instead (``docs/QUALITY_POLICY.md`` §7):

1. every not-yet-pushed commit carries a ``Change-Type:`` trailer (defect, feature,
   safety, process, docs, refactor, test) and a ``Risk:`` trailer (low, medium, high);
2. a commit declared ``Change-Type: defect`` comes with an ``ERROR_LOG.md`` change in
   the same unpushed range or working tree;
3. a new or changed bug report (``docs/bugs/BUG-*.md``) or spike write-up
   (``docs/spikes/*.md``) comes with an ``ERROR_LOG.md`` change.

Exit 2 asks the session to continue and fix it; it fires once per stop cycle
(``stop_hook_active``). Standard library only; never blocks outside a git checkout.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

CHANGE_TYPES = ("defect", "feature", "safety", "process", "docs", "refactor", "test")
RISKS = ("low", "medium", "high")
ERROR_LOG = "ERROR_LOG.md"
RECORD_PATHS = re.compile(r"^docs/(bugs/BUG-[^/]+|spikes/[^/]+)\.md$")
SEP = "\x1f"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True, timeout=30).stdout


def upstream_base(repo: Path) -> str | None:
    """The pushed point to compare with: origin/<branch>, else the merge-base with the
    remote default branch (a fresh local branch)."""
    branch = git(repo, "branch", "--show-current").strip()
    if branch:
        try:
            git(repo, "rev-parse", "-q", "--verify", f"origin/{branch}")
            return f"origin/{branch}"
        except subprocess.CalledProcessError:
            pass
    try:
        default = git(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD").strip()
    except subprocess.CalledProcessError:
        default = ""
    for cand in filter(None, (default.removeprefix("origin/"), "main", "master")):
        try:
            return git(repo, "merge-base", "HEAD", f"origin/{cand}").strip() or None
        except subprocess.CalledProcessError:
            continue
    return None


def unpushed_commits(repo: Path, base: str | None) -> list[dict]:
    if not base:
        return []
    fmt = SEP.join(["%H", "%s", "%(trailers:key=Change-Type,valueonly,separator=%x2C)",
                    "%(trailers:key=Risk,valueonly,separator=%x2C)"]) + "%x1e"
    out = git(repo, "log", f"--format={fmt}", f"{base}..HEAD")
    commits = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, subject, ctype, risk = (rec.split(SEP) + ["", "", "", ""])[:4]
        commits.append({"sha": sha, "subject": subject,
                        "types": [t.strip().lower() for t in ctype.split(",") if t.strip()],
                        "risk": [r.strip().lower() for r in risk.split(",") if r.strip()]})
    return commits


def touched_files(repo: Path, base: str | None) -> set[str]:
    files: set[str] = set()
    for args in (("diff", "--name-only"), ("diff", "--cached", "--name-only"),
                 ("ls-files", "--others", "--exclude-standard")):
        files.update(git(repo, *args).splitlines())
    if base:
        files.update(git(repo, "diff", "--name-only", f"{base}...HEAD").splitlines())
    return {f for f in files if f}


def problems(repo: Path) -> list[str]:
    if not (repo / ERROR_LOG).exists():
        return []
    base = upstream_base(repo)
    commits = unpushed_commits(repo, base)
    files = touched_files(repo, base)
    out: list[str] = []
    for c in commits:
        bad_type = [t for t in c["types"] if t not in CHANGE_TYPES]
        if not c["types"] or bad_type:
            out.append(f"{c['sha'][:10]} \"{c['subject']}\": needs a `Change-Type:` trailer, "
                       f"one of {', '.join(CHANGE_TYPES)}"
                       + (f" (got {', '.join(bad_type)})" if bad_type else ""))
        if len(c["risk"]) != 1 or c["risk"][0] not in RISKS:
            out.append(f"{c['sha'][:10]} \"{c['subject']}\": needs one `Risk:` trailer, "
                       f"one of {', '.join(RISKS)}")
    logged = ERROR_LOG in files
    if not logged:
        defects = [c for c in commits if "defect" in c["types"]]
        for c in defects:
            out.append(f"{c['sha'][:10]} is declared `Change-Type: defect` but {ERROR_LOG} "
                       "has no entry in this change (reproduction, correction, regression "
                       "check, scope)")
        records = sorted(f for f in files if RECORD_PATHS.match(f))
        if records:
            out.append(f"bug/spike record(s) changed without an {ERROR_LOG} entry: "
                       + ", ".join(records))
    return out


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    if payload.get("stop_hook_active"):
        return 0
    try:
        repo = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").strip())
        found = problems(repo)
    except (OSError, subprocess.SubprocessError):
        return 0  # not a checkout, or git is unavailable: nothing to check
    if not found:
        return 0
    print("Bookkeeping (docs/QUALITY_POLICY.md §7):", file=sys.stderr)
    for p in found:
        print(f"  - {p}", file=sys.stderr)
    print("Trailers count only in the message's final paragraph (the block with "
          "Co-Authored-By). Add them to the unpushed commits (for the last one: `git commit "
          "--amend --trailer 'Change-Type: ...' --trailer 'Risk: ...'`), or add the "
          "ERROR_LOG.md entry. Pushed history is never rewritten.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
