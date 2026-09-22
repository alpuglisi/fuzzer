"""Semantics validator for mutations (Phase 8 T8.1, NFR-MUT-semantics).

A mutation must preserve meaning; this validator refutes ones that don't. Two checks:

* **AST equivalence** (SQL, via `sqlglot`) — parse both payloads and compare their
  syntax trees. Best-effort: payloads are often fragments that don't parse, and the
  native build may be unavailable (the tests skip-guard it, like `cryptography`), so it
  falls back to the canonical check.
* **Canonical equivalence** — normalize away the surface variation the operators
  introduce (single URL-decode, strip SQL inline comments, collapse whitespace,
  lowercase) and require the canonical forms to match. This proves the surface operators
  (encoding/whitespace/comment/case) preserve meaning and rejects anything that drifted.

Vetted-equivalent operators (tautology swaps) are meaning-preserving *by construction*
from a human-vetted table; the canonicalizer can't prove tautology equivalence, so those
are trusted via provenance (`preserves(..., trusted=True)`) rather than re-derived.
"""

from __future__ import annotations

import re
import urllib.parse

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"--")
_SQL_LIKE_CLASSES = ("sql-injection", "command-injection")


def _comment_provenance_differs(a: str, b: str) -> bool:
    """True if a `--` line comment appears in one string but not the other.

    `sqlglot` discards *every* comment style (`--` and `/* */`) as lexer trivia
    when it builds a syntax tree, so AST equivalence cannot distinguish a vetted
    `/* */` insertion (the one comment-insertion operator this validator is
    meant to accept) from an arbitrary, unvetted `--` comment append — which in
    a real query can truncate everything after it. `canonicalize()` only
    normalizes `/* */`, by design, so a `--` difference it still sees must never
    be laundered through the AST path.
    """
    return bool(_LINE_COMMENT.search(a)) != bool(_LINE_COMMENT.search(b))


def canonicalize(payload: str, vuln_class: str = "sql-injection") -> str:
    """Normalize away meaning-preserving surface variation for comparison."""
    s = urllib.parse.unquote(payload)                 # single URL-decode
    if vuln_class in _SQL_LIKE_CLASSES:
        s = _SQL_COMMENT.sub(" ", s)                  # /**/ -> space
    return _WS.sub(" ", s).strip().lower()


def sqlglot_available() -> bool:
    """True only if `sqlglot` imports and actually parses (native builds can panic)."""
    try:
        import sqlglot
        sqlglot.parse_one("SELECT 1")
        return True
    except BaseException:                             # noqa: BLE001 - broken native build
        return False


class SemanticsValidator:
    def __init__(self, use_ast: bool = True):
        self.use_ast = use_ast and sqlglot_available()

    def _ast_equiv(self, a: str, b: str) -> bool | None:
        """True/False if both parse as SQL; None if either can't be decided."""
        try:
            import sqlglot
            pa, pb = sqlglot.parse_one(a), sqlglot.parse_one(b)
            if pa is None or pb is None:
                return None
            return pa == pb
        except BaseException:                         # noqa: BLE001 - fragment/parse issue
            return None

    def preserves(self, original: str, mutated: str, vuln_class: str = "sql-injection",
                  *, trusted: bool = False) -> bool:
        """Does ``mutated`` mean the same as ``original``?

        ``trusted=True`` accepts a vetted-equivalent transform by provenance (used for
        the vetted-equivalence operators). Otherwise, canonical equivalence is the
        authoritative proof for the surface operators (it defines exactly what surface
        variation is recognized as safe); AST equivalence can only *widen* acceptance
        beyond it for a genuinely unparseable-by-canonicalize difference, and never for
        one that turns on comment provenance (`_comment_provenance_differs`), since AST
        comparison is comment-blind and would otherwise rubber-stamp an unvetted comment
        injection as meaning-preserving.
        """
        if mutated == original:
            return True
        if trusted:
            return True
        if canonicalize(original, vuln_class) == canonicalize(mutated, vuln_class):
            return True
        if _comment_provenance_differs(original, mutated):
            return False
        if self.use_ast and vuln_class == "sql-injection":
            verdict = self._ast_equiv(original, mutated)
            if verdict is not None:
                return verdict                        # decisive AST comparison
        return False
