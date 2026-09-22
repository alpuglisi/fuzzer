"""Typed, semantics-preserving mutation operators (Phase 8 T8.1, FR-MUT-1).

Each operator transforms a payload into one or more variants **without changing its
meaning** — the surface changes (encoding, whitespace, comments, case) that defeat naive
signature filters while the server still decodes/parses to the same thing. Operators are
deterministic and declare which vulnerability classes they apply to.

Two flavors:
* **surface** operators (encoding/whitespace/comment/case) — provably meaning-preserving,
  checked by `SemanticsValidator` via canonicalization / AST equivalence;
* **vetted-equivalent** operators — substitutions drawn from a human-vetted
  equivalence table (e.g. ``1=1`` ↔ ``2>1``), meaning-preserving *by construction*
  (the canonicalizer can't prove tautology equivalence, so these are trusted via
  provenance, not re-derived).

Anything meaning-changing is out of scope: the engine only emits these, and the
validator rejects a surface variant whose canonical form drifted.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

ANY = "*"


@dataclass(frozen=True)
class MutationOperator:
    """A named, meaning-preserving transform. ``apply`` returns 0+ distinct variants."""

    id: str
    kind: str                              # encoding|whitespace|comment|case|equivalent
    classes: tuple[str, ...]               # vuln classes it applies to, or (ANY,)
    _fn: Callable[[str], list[str]] = field(repr=False, default=None)
    surface: bool = True                   # False = vetted-equivalent (trusted)

    def applies(self, vuln_class: str | None) -> bool:
        return vuln_class is None or ANY in self.classes or vuln_class in self.classes

    def apply(self, payload: str) -> list[str]:
        """Distinct, order-preserving variants (never the input unchanged)."""
        out, seen = [], {payload}
        for v in self._fn(payload):
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out


# --- surface transforms ------------------------------------------------------
def _url_encode(payload: str) -> list[str]:
    # Full single percent-encoding — the server decodes once to the original.
    return [urllib.parse.quote(payload, safe="")]


# --- advanced evasion operators (WAF-bypass encoding tricks; still provably
# meaning-preserving — SemanticsValidator.canonicalize() fully URL-decodes and
# NFKC-normalizes, so both round-trip back to the original) ------------------
def _double_url_encode(payload: str) -> list[str]:
    # Percent-encode twice: many WAFs decode once before pattern-matching, while
    # some backends (or an intermediate proxy) decode recursively.
    once = urllib.parse.quote(payload, safe="")
    return [urllib.parse.quote(once, safe="")]


def _unicode_fullwidth(payload: str) -> list[str]:
    # Substitute each ASCII punctuation/letter/digit char (0x21-0x7E) with its
    # Unicode "fullwidth form" (U+FF01-FF5E, offset +0xFEE0). Some WAF signatures
    # match ASCII only, while a backend that NFKC-normalizes (or a database engine
    # that folds Unicode compatibility forms) still sees the original character.
    out = "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in payload)
    return [out] if out != payload else []


_WS = re.compile(r" +")

def _whitespace(payload: str) -> list[str]:
    if " " not in payload:
        return []
    # Meaning-preserving whitespace alternates that evade a naive ``\s`` signature.
    return [_WS.sub(alt, payload) for alt in ("%09", "%0a", "/**/")]


_BETWEEN_WORDS = re.compile(r"(?<=\w) +(?=\w)")

def _inline_comment(payload: str) -> list[str]:
    # Insert SQL inline comments at word boundaries: "union select" -> "union/**/select".
    return [_BETWEEN_WORDS.sub("/**/", payload)]


def _case_toggle(payload: str) -> list[str]:
    upper = payload.upper()
    alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    return [upper, alt]


# --- vetted-equivalent transforms (trusted by construction) ------------------
# Each pair is a human-vetted, meaning-preserving SQL rewrite. Applied only when the
# left side is present; the validator accepts these via provenance, not canonicalization.
_SQL_EQUIVALENCES: tuple[tuple[str, str], ...] = (
    ("1=1", "2>1"),
    ("1=1", "'a'='a'"),
    (" or ", " || "),          # boolean OR ↔ logical-or operator (MySQL)
    ("=", " like "),           # equality ↔ LIKE with no wildcard
)


def _sql_equivalent(payload: str) -> list[str]:
    out = []
    low = payload.lower()
    for left, right in _SQL_EQUIVALENCES:
        idx = low.find(left.lower())
        if idx != -1:
            out.append(payload[:idx] + right + payload[idx + len(left):])
    return out


_ALL: tuple[MutationOperator, ...] = (
    MutationOperator("url-encode", "encoding", (ANY,), _url_encode),
    MutationOperator("ws-alt", "whitespace", ("sql-injection", "command-injection"),
                     _whitespace),
    MutationOperator("sql-comment", "comment", ("sql-injection",), _inline_comment),
    MutationOperator("case-toggle", "case", ("sql-injection", "xss"), _case_toggle),
    MutationOperator("sql-equivalent", "equivalent", ("sql-injection",),
                     _sql_equivalent, surface=False),
    MutationOperator("double-url-encode", "encoding", (ANY,), _double_url_encode),
    MutationOperator("unicode-fullwidth", "encoding", (ANY,), _unicode_fullwidth),
)


def default_operators(vuln_class: str | None = None) -> list[MutationOperator]:
    """All operators, or those that apply to ``vuln_class``."""
    return [op for op in _ALL if op.applies(vuln_class)]


def apply_chain(payload: str, operators: list[MutationOperator]) -> str:
    """Apply operators in sequence (first variant of each), for a deterministic chain."""
    cur = payload
    for op in operators:
        variants = op.apply(cur)
        if variants:
            cur = variants[0]
    return cur
