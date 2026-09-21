"""DOM-skeleton MinHash template dedup (Phase 2 T2.6).

Near-duplicate pages (same structure, different data — e.g. product #1 vs #99)
should be audited once. We hash the DOM *skeleton* (tag structure only, no text or
attributes) into a MinHash signature and cluster pages whose signatures are similar.

Pure-Python MinHash (deterministic, no external dependency): a family of hash
permutations over shingles of the tag sequence; signature similarity approximates
Jaccard similarity of the skeletons.
"""

from __future__ import annotations

import hashlib

from bs4 import BeautifulSoup

_PRIME = (1 << 61) - 1


def dom_skeleton(html: str) -> list[str]:
    """The ordered tag names of a page (structure only; text/attrs discarded)."""
    soup = BeautifulSoup(html or "", "html.parser")
    return [tag.name for tag in soup.find_all(True)]


def _shingles(tokens: list[str], k: int) -> list[str]:
    if len(tokens) < k:
        return [" ".join(tokens)] if tokens else []
    return [" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)]


def _hash(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8).digest(), "big")


def _perm_params(num_perm: int) -> list[tuple[int, int]]:
    # Deterministic (a odd/nonzero, b) pairs; quality is fine for template clustering.
    return [(2 * i + 1, i * i + 7) for i in range(num_perm)]


def minhash(html: str, num_perm: int = 64, k: int = 3) -> tuple[int, ...]:
    shingles = _shingles(dom_skeleton(html), k)
    if not shingles:
        return tuple([0] * num_perm)
    hashes = [_hash(s) for s in shingles]
    return tuple(min((a * h + b) % _PRIME for h in hashes) for a, b in _perm_params(num_perm))


def similarity(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


class TemplateClusterer:
    """Assigns a stable `template_cluster_id` to each page by skeleton similarity."""

    def __init__(self, threshold: float = 0.7, num_perm: int = 64, k: int = 3):
        self.threshold = threshold
        self.num_perm = num_perm
        self.k = k
        self._clusters: list[tuple[str, tuple[int, ...]]] = []

    def cluster_id(self, html: str) -> str:
        sig = minhash(html, self.num_perm, self.k)
        for cid, csig in self._clusters:
            if similarity(sig, csig) >= self.threshold:
                return cid
        cid = f"T{len(self._clusters) + 1:04d}"
        self._clusters.append((cid, sig))
        return cid

    @property
    def cluster_count(self) -> int:
        return len(self._clusters)
