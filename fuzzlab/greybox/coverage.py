"""Per-request line coverage: the injected source, app-filtering, and the frontier.

`CoverageSource` is the seam: given a request's correlation id, return the set of
source lines that request executed (`{file: {lines}}`). The live implementation reads
the instrumented lab's pcov side channel (on-host, T3.1); tests use
`InMemoryCoverageSource`. `app_lines` filters a raw coverage map down to application
files (a signal that includes framework/vendor boilerplate every request runs is not
causal). `CoverageFrontier` tracks the union of app lines seen so far in a run, so a
request's **novelty** (new lines it reached) can drive the reward (T3.3).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Protocol, runtime_checkable

# Path fragments that mark a file as NOT application code. Extend per-lab as needed.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "/vendor/", "/node_modules/", "/usr/", "/tmp/",
    "coverage_shim", "auto_prepend", "auto_append", "cov.php",
)

# The correlation id the tools send as X-Fzl-Cov and the lab's cov.php shim uses to
# name the side-channel file. Sanitize identically on both sides so a request's id
# maps to exactly one file (and no id can traverse out of the side-channel directory).
_CID_SANITIZE = re.compile(r"[^A-Za-z0-9_.-]")


def sanitize_cid(cid: str) -> str:
    """Filesystem-safe correlation id, matching the lab shim's `preg_replace`."""
    return _CID_SANITIZE.sub("", cid or "")


@runtime_checkable
class CoverageSource(Protocol):
    """Return executed lines for a request, as ``{file: {line, ...}}``."""

    def lines_for(self, request_id: str) -> Mapping[str, Iterable[int]]:
        ...


class InMemoryCoverageSource:
    """Test/offline fake: canned coverage keyed by request id."""

    def __init__(self, by_request: Mapping[str, Mapping[str, Iterable[int]]] | None = None):
        self._by_request = {
            rid: {f: set(lines) for f, lines in cov.items()}
            for rid, cov in (by_request or {}).items()
        }

    def set(self, request_id: str, coverage: Mapping[str, Iterable[int]]) -> None:
        self._by_request[request_id] = {f: set(lines) for f, lines in coverage.items()}

    def lines_for(self, request_id: str) -> dict[str, set[int]]:
        return {f: set(lines) for f, lines in self._by_request.get(request_id, {}).items()}


def _coverage_from_payload(data: object) -> dict[str, set[int]]:
    """Extract a ``{file: {lines}}`` map from the shim's JSON payload.

    Accepts either the structured shim file ``{"files": {path: [lines]}, ...}`` or a
    bare ``{path: [lines]}`` map, so the reader tolerates a shim that writes only
    coverage. Non-list line values are ignored rather than raising.
    """
    if isinstance(data, Mapping) and "files" in data:
        data = data["files"]
    out: dict[str, set[int]] = {}
    if isinstance(data, Mapping):
        for path, lines in data.items():
            if isinstance(lines, (list, tuple, set)):
                out[str(path)] = {int(n) for n in lines}
    return out


class FileCoverageSource:
    """Live source: reads the lab shim's per-request pcov side channel (T3.1/T3.2).

    ``cov.php`` writes one JSON file per request into ``directory``, named by the
    sanitized ``X-Fzl-Cov`` correlation id. This reads that file back for a given id.
    Missing/half-written/undecodable files return ``{}`` (no coverage) rather than
    raising — a request the shim did not instrument simply has no novelty, which the
    reward layer already treats as "reached no new code".
    """

    def __init__(self, directory: str | Path = "/tmp/fzl-cov"):
        self._dir = Path(directory)

    def _path(self, request_id: str) -> Path:
        return self._dir / sanitize_cid(request_id)

    def lines_for(self, request_id: str) -> dict[str, set[int]]:
        path = self._path(request_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return _coverage_from_payload(data)


def app_lines(coverage: Mapping[str, Iterable[int]], *,
              excludes: Iterable[str] = DEFAULT_EXCLUDES,
              include_prefixes: Iterable[str] | None = None) -> dict[str, set[int]]:
    """Filter a raw coverage map to application files.

    Drops any file whose path contains one of ``excludes``. When
    ``include_prefixes`` is given, keeps only files starting with one of them
    (e.g. the app's document root); otherwise keeps everything not excluded.
    """
    excludes = tuple(excludes)
    prefixes = tuple(include_prefixes) if include_prefixes else None
    out: dict[str, set[int]] = {}
    for path, lines in coverage.items():
        if any(frag in path for frag in excludes):
            continue
        if prefixes is not None and not any(path.startswith(p) for p in prefixes):
            continue
        line_set = {int(n) for n in lines}
        if line_set:
            out[path] = line_set
    return out


class CoverageFrontier:
    """The union of application lines seen so far in a run."""

    def __init__(self) -> None:
        self._seen: dict[str, set[int]] = {}

    def novelty(self, coverage: Mapping[str, Iterable[int]]) -> int:
        """New lines in ``coverage`` not yet in the frontier (does not mutate)."""
        total = 0
        for path, lines in coverage.items():
            total += len({int(n) for n in lines} - self._seen.get(path, set()))
        return total

    def add(self, coverage: Mapping[str, Iterable[int]]) -> int:
        """Add ``coverage`` to the frontier; return how many lines were newly added."""
        added = 0
        for path, lines in coverage.items():
            seen = self._seen.setdefault(path, set())
            new = {int(n) for n in lines} - seen
            seen |= new
            added += len(new)
        return added

    def observe(self, coverage: Mapping[str, Iterable[int]]) -> int:
        """One step: measure novelty, then fold it in. Returns the novel-line count."""
        novel = self.novelty(coverage)
        self.add(coverage)
        return novel

    @property
    def size(self) -> int:
        return sum(len(v) for v in self._seen.values())


def encode_coverage(coverage: Mapping[str, Iterable[int]], *,
                    novel: int | None = None) -> str:
    """Compact JSON for the ``attempt.coverage`` column (deterministic ordering)."""
    files = {path: sorted({int(n) for n in lines}) for path, lines in coverage.items()}
    payload: dict[str, object] = {
        "files": files,
        "n_lines": sum(len(v) for v in files.values()),
    }
    if novel is not None:
        payload["n_novel"] = int(novel)
    return json.dumps(payload, sort_keys=True)


def decode_coverage(blob: str | None) -> dict[str, object]:
    """Inverse of `encode_coverage`; ``{}`` for empty/missing."""
    if not blob:
        return {}
    return json.loads(blob)
