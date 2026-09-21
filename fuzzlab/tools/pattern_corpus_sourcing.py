"""T-LAB0.8 mechanical OSV/GHSA pull + candidate-list tooling.

Docs: ``docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md`` (Revision 2),
``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.8.

**Scope, deliberately narrow** (the sourcing plan's step 6 is explicit: "human,
on cluster representatives only"). This module implements steps 1-5 of that
plan's pipeline — pull, index, scope, rank, cluster — and stops there. It
**never** authors a pattern card, **never** writes to ``lab/patterns/cards/``,
and **never** touches ``lab/patterns/provenance.yaml``. Its output is a
structured candidate list (clustered representatives + up to two alternates
per cluster) for a human to read next and decide, per the plan's step 6/7,
which candidates become real cards. Authoring a card's ``root_cause`` text
from a candidate is separate, human-supervised work this module does not do.

**Pull mechanism** (per Revision 2 §2, correcting Revision 1's API-based
approach): a ``git clone``/``git pull`` of ``github/advisory-database``, not
the OSV or GHSA APIs — the OSV REST API has no CWE filter (it answers "what
affects this package," not "what advisories match this weakness"), and
unauthenticated GHSA GraphQL is rate-limited to 0 requests/hour (measured by
the plan's own research pass). A real clone is ~3.3 GB and takes several
minutes (per the plan) and is not exercised by this module's own test suite
by default — see :func:`probe_reachable` and the module-level note in
``tests/test_pattern_corpus_sourcing.py`` about the live, opt-in smoke test.

**Clustering** (step 5 of the plan) is a lightweight, dependency-free
token-overlap (Jaccard) heuristic over each candidate's prose — a deliberate
stand-in for the plan's eventual embedding-based clustering. Swapping in a
real sentence-embedding model later is a change to :func:`cluster_by_shape`
alone, not to this pipeline's shape or its callers.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import yaml

DEFAULT_REMOTE = "https://github.com/github/advisory-database"
DEFAULT_CACHE_DIR = Path(".cache/advisory-database")
DEFAULT_CROSSWALK_PATH = Path("lab/patterns/sourcing/crosswalk.yaml")
DEFAULT_OUTPUT_DIR = Path("lab/patterns/refresh")
DEFAULT_REFRESH_LOG = Path("lab/patterns/REFRESH_LOG.md")

# Stopwords stripped before shape-clustering — deliberately generic
# vulnerability-report vocabulary that would otherwise dominate every
# advisory's token set and defeat clustering by shape.
_STOPWORDS = frozenset(
    """a an the of to in on for and or with without via is are was were be
    been being this that these those it its as at by from into can could
    may might allow allows allowed attacker attackers vulnerability
    vulnerabilities issue issues affected version versions prior before
    after due through user users application""".split()
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class SourcingError(ValueError):
    """Raised for a malformed advisory file, an invalid crosswalk config, an
    invalid checkout, or a git command failure."""


# ---------------------------------------------------------------------------
# Git sync (injectable runner; real default shells out)
# ---------------------------------------------------------------------------

GitRunner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def default_git_runner(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    """The real runner: shells out via ``subprocess.run`` under a hard
    timeout. Tests inject a fake runner instead — see
    ``tests/test_pattern_corpus_sourcing.py``."""
    return subprocess.run(argv, capture_output=True, text=True, timeout=600)


def probe_reachable(
    remote_url: str = DEFAULT_REMOTE,
    *,
    runner: GitRunner = default_git_runner,
) -> bool:
    """Cheap reachability probe (``git ls-remote --heads``, no clone). Check
    this before assuming a real :func:`sync_advisory_database` call can
    succeed in a given environment — this project's outbound access goes
    through a proxy and reachability is not guaranteed everywhere it runs."""
    try:
        result = runner(["git", "ls-remote", "--heads", remote_url])
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def sync_advisory_database(
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    remote_url: str = DEFAULT_REMOTE,
    *,
    runner: GitRunner = default_git_runner,
) -> str:
    """Clone (first run) or pull (subsequent runs) ``github/advisory-database``
    into ``cache_dir``. Returns the checked-out commit SHA.

    Idempotent: running this twice in a row against an already-current clone
    is a fast no-op ``git pull`` that returns the same SHA. ``cache_dir`` is
    a local build cache, never committed (see ``.gitignore``'s ``.cache/``
    entry) — the real corpus this project commits is the small, hand-curated
    ``lab/patterns/cards/*.yaml``, not this multi-gigabyte upstream mirror.
    """
    cache_dir = Path(cache_dir)
    if (cache_dir / ".git").is_dir():
        result = runner(["git", "-C", str(cache_dir), "pull", "--ff-only"])
    else:
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        result = runner(["git", "clone", remote_url, str(cache_dir)])
    if result.returncode != 0:
        raise SourcingError(f"git sync of {remote_url} into {cache_dir} failed: {result.stderr.strip()}")
    return _read_local_head(cache_dir, runner=runner)


def _read_local_head(cache_dir: str | Path, *, runner: GitRunner) -> str:
    result = runner(["git", "-C", str(cache_dir), "rev-parse", "HEAD"])
    if result.returncode != 0:
        raise SourcingError(f"git rev-parse HEAD failed in {cache_dir}: {result.stderr.strip()}")
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Index: parse OSV-format advisory JSON files
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    details: str
    published: str  # ISO 8601, as stored in the advisory
    modified: str
    cwe_ids: tuple[str, ...]
    ecosystems: tuple[str, ...]
    severity: str | None
    source_path: str

    @property
    def prose(self) -> str:
        return f"{self.summary}\n{self.details}"


def parse_advisory_file(path: Path) -> Advisory | None:
    """Parse one OSV-format advisory JSON file (schema verified directly
    against a real ``github/advisory-database`` checkout during development
    — ``id``/``summary``/``details``/``published``/``modified``/
    ``affected[].package.ecosystem``/``database_specific.cwe_ids`` all match).

    Returns ``None`` (never raises) for a file that is not
    ``github_reviewed`` — the plan's own measurement found ~90% of
    community-reviewed-only advisories unusable (median 321 characters, no
    structured prose), so this pipeline intentionally only indexes the
    reviewed subset.
    """
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourcingError(f"{path}: could not parse advisory JSON: {exc}") from exc

    db = data.get("database_specific") or {}
    if not db.get("github_reviewed", False):
        return None

    ecosystems = tuple(
        sorted({a["package"]["ecosystem"] for a in data.get("affected", []) if "package" in a})
    )
    return Advisory(
        id=data["id"],
        summary=data.get("summary", ""),
        details=data.get("details", ""),
        published=data.get("published", ""),
        modified=data.get("modified", ""),
        cwe_ids=tuple(db.get("cwe_ids", ())),
        ecosystems=ecosystems,
        severity=db.get("severity"),
        source_path=str(path),
    )


def iter_advisories(repo_dir: str | Path) -> Iterable[Advisory]:
    """Yield every ``github_reviewed`` advisory under a
    ``github/advisory-database`` checkout (or a directory shaped like one —
    tests use a small synthetic tree, never the real corpus)."""
    repo_dir = Path(repo_dir)
    base = repo_dir / "advisories" / "github-reviewed"
    if not base.is_dir():
        raise SourcingError(
            f"{base} not found — {repo_dir} does not look like a github/advisory-database checkout"
        )
    for path in sorted(base.rglob("GHSA-*.json")):
        advisory = parse_advisory_file(path)
        if advisory is not None:
            yield advisory


# ---------------------------------------------------------------------------
# Scope: CWE/keyword crosswalk + ecosystem + currency window
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ClassRule:
    id: str
    cwes: tuple[str, ...]
    keyword_gated_cwes: dict[str, tuple[str, ...]]
    target_count: int


@dataclasses.dataclass(frozen=True)
class Crosswalk:
    classes: tuple[ClassRule, ...]
    ecosystems: tuple[str, ...]
    currency_window_months: int

    @property
    def precedence(self) -> tuple[str, ...]:
        """Multi-CWE resolution order: declaration order in the config file
        (docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md §5's "most-specific class
        first" rule) — not a separate field to keep in sync by hand."""
        return tuple(c.id for c in self.classes)

    def matches(self, advisory: Advisory) -> list[str]:
        """Every class id this advisory matches, in crosswalk declaration
        order. A ``keyword_gated_cwes`` entry (e.g. SSTI's CWE-94) only
        counts when the advisory's prose also contains one of the gating
        keywords — CWE-94 alone is far too broad (any code injection)."""
        hits = []
        prose_lower = advisory.prose.lower()
        for rule in self.classes:
            if any(cwe in rule.cwes for cwe in advisory.cwe_ids):
                hits.append(rule.id)
                continue
            for cwe, keywords in rule.keyword_gated_cwes.items():
                if cwe in advisory.cwe_ids and any(kw in prose_lower for kw in keywords):
                    hits.append(rule.id)
                    break
        return hits


def load_crosswalk(path: str | Path = DEFAULT_CROSSWALK_PATH) -> Crosswalk:
    path = Path(path)
    if not path.is_file():
        raise SourcingError(f"crosswalk config not found at {path!r}")
    data = yaml.safe_load(path.read_text("utf-8"))
    classes = tuple(
        ClassRule(
            id=c["id"],
            cwes=tuple(c.get("cwes", ())),
            keyword_gated_cwes={k: tuple(v) for k, v in (c.get("keyword_gated_cwes") or {}).items()},
            target_count=c.get("target_count", 0),
        )
        for c in data["classes"]
    )
    if not classes:
        raise SourcingError(f"{path}: crosswalk config has no classes")
    return Crosswalk(
        classes=classes,
        ecosystems=tuple(data.get("ecosystems", ())),
        currency_window_months=data.get("currency_window_months", 24),
    )


@dataclasses.dataclass(frozen=True)
class ScopedCandidate:
    advisory: Advisory
    class_id: str
    other_matches: tuple[str, ...]

    def prose_score(self) -> int:
        """Rank signal (plan step 4): prose length plus a bonus for a
        structured-heading shape (markdown headings or bolded lead-ins),
        which the plan found correlates with a usable, citable advisory."""
        text = self.advisory.prose
        score = len(text)
        if re.search(r"(^|\n)#{1,6}\s|\*\*[^\n*]+\*\*:", text):
            score += 500
        return score


def _within_currency_window(advisory: Advisory, as_of: date, window_months: int) -> bool:
    try:
        published = datetime.fromisoformat(advisory.published.replace("Z", "+00:00")).date()
    except ValueError:
        return False
    months_old = (as_of.year - published.year) * 12 + (as_of.month - published.month)
    return 0 <= months_old <= window_months


def scope(
    advisories: Iterable[Advisory],
    crosswalk: Crosswalk,
    *,
    as_of: date | None = None,
) -> list[ScopedCandidate]:
    """Filter to the currency window, target ecosystems, and the CWE/keyword
    crosswalk (plan step 3). A multi-CWE advisory keeps every class it
    matched in ``other_matches`` — a losing match is recorded, never
    silently dropped."""
    as_of = as_of or date.today()
    out: list[ScopedCandidate] = []
    for advisory in advisories:
        if crosswalk.ecosystems and not (set(advisory.ecosystems) & set(crosswalk.ecosystems)):
            continue
        if not _within_currency_window(advisory, as_of, crosswalk.currency_window_months):
            continue
        hits = crosswalk.matches(advisory)
        if not hits:
            continue
        primary = next((c for c in crosswalk.precedence if c in hits), hits[0])
        others = tuple(h for h in hits if h != primary)
        out.append(ScopedCandidate(advisory=advisory, class_id=primary, other_matches=others))
    return out


def rank(candidates: Sequence[ScopedCandidate]) -> list[ScopedCandidate]:
    """Sort by prose score descending (plan step 4); ties broken by
    advisory ID for determinism."""
    return sorted(candidates, key=lambda c: (-c.prose_score(), c.advisory.id))


# ---------------------------------------------------------------------------
# Cluster: lightweight, dependency-free shape clustering (plan step 5)
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> frozenset[str]:
    tokens = _TOKEN_RE.findall(text.lower())
    return frozenset(t for t in tokens if t not in _STOPWORDS and len(t) > 2)


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


@dataclasses.dataclass(frozen=True)
class Cluster:
    class_id: str
    representative: ScopedCandidate
    alternates: tuple[ScopedCandidate, ...]


def cluster_by_shape(
    candidates: Sequence[ScopedCandidate],
    *,
    similarity_threshold: float = 0.25,
    max_alternates: int = 2,
) -> list[Cluster]:
    """Greedy single-linkage clustering over token-overlap (Jaccard)
    similarity of each candidate's prose, per class. Deterministic: within a
    class, candidates are ranked first (by :func:`rank`) so cluster
    formation order — and therefore which candidate becomes each cluster's
    representative — never depends on input ordering or on Python's
    (per-process-randomized) hash/set iteration order.

    This is the plan's "look at 10-20 per class instead of reading hundreds
    in sequence" step: keeps one representative (highest-ranked in the
    cluster) plus up to ``max_alternates`` others, per class.
    """
    by_class: dict[str, list[ScopedCandidate]] = defaultdict(list)
    for c in candidates:
        by_class[c.class_id].append(c)

    clusters: list[Cluster] = []
    for class_id in sorted(by_class):
        ranked = rank(by_class[class_id])
        groups: list[list[ScopedCandidate]] = []
        group_tokens: list[frozenset[str]] = []
        for cand in ranked:
            tokens = _tokenize(cand.advisory.prose)
            placed = False
            for i, rep_tokens in enumerate(group_tokens):
                if _jaccard(tokens, rep_tokens) >= similarity_threshold:
                    groups[i].append(cand)
                    placed = True
                    break
            if not placed:
                groups.append([cand])
                group_tokens.append(tokens)
        for group in groups:
            clusters.append(
                Cluster(class_id=class_id, representative=group[0], alternates=tuple(group[1 : 1 + max_alternates]))
            )
    return clusters


# ---------------------------------------------------------------------------
# Emit: a structured candidate list for human triage (never a card)
# ---------------------------------------------------------------------------


def _candidate_to_dict(c: ScopedCandidate) -> dict[str, Any]:
    a = c.advisory
    return {
        "id": a.id,
        "class_id": c.class_id,
        "other_matches": list(c.other_matches),
        "summary": a.summary,
        "details": a.details,
        "published": a.published,
        "cwe_ids": list(a.cwe_ids),
        "ecosystems": list(a.ecosystems),
        "severity": a.severity,
        "source_path": a.source_path,
    }


def clusters_to_candidate_list(clusters: Sequence[Cluster]) -> dict[str, Any]:
    """Serialize clusters into the structured candidate list this module's
    whole job is to produce for a human to read next — never a card, never
    a ``provenance.yaml`` entry, never written under ``lab/patterns/cards/``."""
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cl in sorted(clusters, key=lambda c: (c.class_id, c.representative.advisory.id)):
        by_class[cl.class_id].append(
            {
                "representative": _candidate_to_dict(cl.representative),
                "alternates": [_candidate_to_dict(alt) for alt in cl.alternates],
            }
        )
    return {"classes": dict(sorted(by_class.items()))}


def quarter_label(d: date) -> str:
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


def _render_report(label: str, sha: str, crosswalk: Crosswalk, candidate_list: dict[str, Any]) -> str:
    target_by_class = {c.id: c.target_count for c in crosswalk.classes}
    lines = [
        f"# Pattern-corpus sourcing refresh — {label}",
        "",
        f"Advisory-database commit: `{sha}`",
        "",
        "Mechanical output only — candidate clusters for human triage "
        "(docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md step 6). No card was "
        "authored, and nothing here has been validated or added to "
        "lab/patterns/cards/ or provenance.yaml by this run.",
        "",
    ]
    classes = candidate_list["classes"]
    for class_id in sorted(classes):
        entries = classes[class_id]
        target = target_by_class.get(class_id, "?")
        lines.append(f"## {class_id} — {len(entries)} cluster(s) (target: {target} cards)")
        for entry in entries:
            rep = entry["representative"]
            lines.append(f"- {rep['id']}: {rep['summary']} ({len(entry['alternates'])} alternate(s))")
        lines.append("")
    if not classes:
        lines.append("No new distinct shapes this run — a successful, expected outcome, not a gap.")
    return "\n".join(lines) + "\n"


_REFRESH_LOG_HEADER = (
    "# Pattern-corpus sourcing refresh log\n\n"
    "Append-only (per CLAUDE.md's logging conventions). One line per refresh "
    "run: date, quarter label, the github/advisory-database commit SHA "
    "indexed, and candidate cluster counts by class. See "
    "docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md step 8.\n\n"
)


def _append_refresh_log(path: str | Path, *, sha: str, label: str, candidate_list: dict[str, Any]) -> bool:
    """Append one line, unless this exact commit SHA was already logged
    (idempotent: re-running against an unchanged clone is a no-op here).
    Returns whether a line was appended."""
    path = Path(path)
    existing = path.read_text("utf-8") if path.exists() else _REFRESH_LOG_HEADER
    if f"`{sha}`" in existing:
        return False
    counts = {cls: len(entries) for cls, entries in candidate_list["classes"].items()}
    counts_str = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no candidates"
    line = f"- {date.today().isoformat()} ({label}): sha `{sha}` — {counts_str}\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(existing + line)
    return True


def run_refresh(
    *,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    remote_url: str = DEFAULT_REMOTE,
    crosswalk_path: str | Path = DEFAULT_CROSSWALK_PATH,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    refresh_log_path: str | Path = DEFAULT_REFRESH_LOG,
    as_of: date | None = None,
    runner: GitRunner = default_git_runner,
    sync: bool = True,
) -> dict[str, Any]:
    """Run the full mechanical pipeline: pull -> index -> scope -> rank ->
    cluster -> emit.

    Idempotent: re-running against an unchanged clone (same HEAD SHA)
    overwrites this quarter's candidate-list/report files with identical
    content (a pure function of the indexed advisories + crosswalk + as_of)
    and does not append a duplicate ``REFRESH_LOG.md`` line.

    ``sync=False`` skips the git pull and indexes whatever is already in
    ``cache_dir`` — used by the offline test suite (and by a caller who
    already synced separately), so the network step and the pure
    index/scope/rank/cluster pipeline stay independently testable.
    """
    as_of = as_of or date.today()
    crosswalk = load_crosswalk(crosswalk_path)

    if sync:
        sha = sync_advisory_database(cache_dir, remote_url, runner=runner)
    else:
        sha = _read_local_head(cache_dir, runner=runner) if (Path(cache_dir) / ".git").is_dir() else "unknown"

    advisories = list(iter_advisories(cache_dir))
    candidates = scope(advisories, crosswalk, as_of=as_of)
    clusters = cluster_by_shape(candidates)
    candidate_list = clusters_to_candidate_list(clusters)

    label = quarter_label(as_of)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = output_dir / f"{label}-candidates.json"
    report_path = output_dir / f"{label}.md"

    candidates_path.write_text(json.dumps(candidate_list, indent=2, sort_keys=True) + "\n")
    report_path.write_text(_render_report(label, sha, crosswalk, candidate_list))

    appended = _append_refresh_log(refresh_log_path, sha=sha, label=label, candidate_list=candidate_list)

    return {
        "sha": sha,
        "label": label,
        "candidates_path": str(candidates_path),
        "report_path": str(report_path),
        "refresh_log_appended": appended,
        "candidate_list": candidate_list,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli_probe(args: argparse.Namespace) -> int:
    ok = probe_reachable(args.remote)
    print("reachable" if ok else "unreachable")
    return 0 if ok else 1


def _cli_refresh(args: argparse.Namespace) -> int:
    result = run_refresh(
        cache_dir=args.cache_dir,
        remote_url=args.remote,
        crosswalk_path=args.crosswalk,
        output_dir=args.output_dir,
        refresh_log_path=args.refresh_log,
        sync=not args.no_sync,
    )
    summary = {k: v for k, v in result.items() if k != "candidate_list"}
    print(json.dumps(summary, indent=2))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pattern-corpus-sourcing",
        description=(
            "T-LAB0.8 mechanical OSV/GHSA pull + candidate-list tooling. "
            "Produces a candidate list for human triage; never authors a "
            "card and never touches lab/patterns/cards/ or provenance.yaml."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    probe_p = sub.add_parser("probe", help="check whether github/advisory-database is reachable (no clone)")
    probe_p.add_argument("--remote", default=DEFAULT_REMOTE)
    probe_p.set_defaults(func=_cli_probe)

    refresh_p = sub.add_parser(
        "refresh", help="pull + index + scope + rank + cluster -> a candidate list for human triage"
    )
    refresh_p.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    refresh_p.add_argument("--remote", default=DEFAULT_REMOTE)
    refresh_p.add_argument("--crosswalk", default=str(DEFAULT_CROSSWALK_PATH))
    refresh_p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    refresh_p.add_argument("--refresh-log", default=str(DEFAULT_REFRESH_LOG))
    refresh_p.add_argument(
        "--no-sync",
        action="store_true",
        help="skip the git pull; index whatever is already in --cache-dir (offline reruns/testing)",
    )
    refresh_p.set_defaults(func=_cli_refresh)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
