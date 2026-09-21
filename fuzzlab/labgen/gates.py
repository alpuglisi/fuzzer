"""Build gates: regenerate-and-diff (T-LAB0.5) and the name-leak scanner
(T-LAB0.6).

Both are meant to be wired as pytest tests (see
``tests/test_labgen_gates.py``), the same way this repo already treats
reproducibility/schema checks as part of the test suite rather than a
separate ad hoc script.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from .denylist import VULN_CLASS_DENYLIST
from .schema import Manifest
from .subseed import render_cell_stub
from .verdict import SafetyMatrix


class RegenerateDiffError(AssertionError):
    """Raised when two generator runs from the same manifest+seed disagree
    (violates NFR-LAB-reproducible)."""


class Leak(NamedTuple):
    context: str
    text: str
    matched_term: str


def generate_source_tree(manifest: Manifest, matrix: SafetyMatrix, root_seed: str) -> dict[str, bytes]:
    """Deterministically render every cell in ``manifest``, keyed by a
    stable relative path. This is the Phase-0 scaffold generator
    (``fuzzlab.labgen.subseed.render_cell_stub``) — not the real per-stack
    emitter (T-LAB0.4).
    """
    return {f"{cell.cell_id}.json": render_cell_stub(cell, matrix, root_seed) for cell in manifest.cells}


def regenerate_and_diff(manifest: Manifest, matrix: SafetyMatrix, root_seed: str) -> None:
    """Run the generator twice from the same ``manifest`` + ``root_seed`` and
    assert byte-identical output (NFR-LAB-reproducible). Raises
    :class:`RegenerateDiffError` naming the first differing file on failure.
    """
    first = generate_source_tree(manifest, matrix, root_seed)
    second = generate_source_tree(manifest, matrix, root_seed)
    if first.keys() != second.keys():
        raise RegenerateDiffError(
            f"file set differs between two runs of the same manifest+seed: "
            f"{sorted(first.keys())} vs {sorted(second.keys())}"
        )
    for path in sorted(first):
        if first[path] != second[path]:
            raise RegenerateDiffError(
                f"{path}: output differs between two generator runs from the same manifest+seed "
                f"(before sha256={_sha256(first[path])}, after sha256={_sha256(second[path])})"
            )


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


_LETTER_RE = "[A-Za-z]"


def _term_pattern(term: str) -> re.Pattern[str]:
    # A match is rejected if a letter immediately precedes or follows it —
    # rejects "maxssl" for the term "xss" (bounded by the letters 'a'/'l')
    # while still accepting "xss_payload"/"test-xss"/"xss1" (bounded by
    # underscore/hyphen/digit/string edge, none of which are letters).
    escaped = re.escape(term)
    return re.compile(rf"(?<!{_LETTER_RE}){escaped}(?!{_LETTER_RE})", re.IGNORECASE)


def scan_name_leaks(
    strings: Iterable[tuple[str, str]],
    denylist: Sequence[str] = VULN_CLASS_DENYLIST,
) -> list[Leak]:
    """Scan ``(context_label, text)`` pairs — a URL, filename, or parameter
    name — for a vulnerability-class name (NFR-LAB-no-leak).

    Matching rejects a hit when a letter directly borders it on either side
    (so ``xss`` does not fire inside ``maxssl``) but still catches
    delimiter-separated leaks like ``xss_payload`` or ``test-sqli``.
    Returns an empty list when clean.
    """
    patterns = [(term, _term_pattern(term)) for term in denylist]
    leaks: list[Leak] = []
    for label, text in strings:
        for term, pattern in patterns:
            if pattern.search(text):
                leaks.append(Leak(context=label, text=text, matched_term=term))
    return leaks


def scan_generated_tree_for_name_leaks(
    tree: dict[str, bytes],
    denylist: Sequence[str] = VULN_CLASS_DENYLIST,
) -> list[Leak]:
    """Apply :func:`scan_name_leaks` across a generated tree's file paths and
    (best-effort) each file's embedded route path, as a stand-in for
    filename/URL/param-name scanning of a real emitted app."""
    pairs: list[tuple[str, str]] = []
    for path, content in tree.items():
        pairs.append((f"path:{path}", path))
        try:
            obj = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        route = obj.get("route") if isinstance(obj, dict) else None
        if isinstance(route, dict) and "path" in route:
            pairs.append((f"route:{path}", str(route["path"])))
    return scan_name_leaks(pairs, denylist)
