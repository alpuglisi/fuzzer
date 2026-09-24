"""Manufactured third variant for auth-session/python CWE-330/CWE-338
(Use of Insufficiently Random Values / Cryptographically Weak PRNG) --
distinct from this cell's natural pair (vulnerable-2.py/idiomatic-2.py,
DOAJ's real ``random.randint``-based login code). This one targets a
different token purpose and a different framework idiom: a Django-style
custom auth backend's "remember me" cookie token, built by hashing a
``random.random()`` draw instead of drawing directly from a CSPRNG.

Manufactured per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
mechanics".
"""
from __future__ import annotations

import hashlib
import random


def generate_remember_me_token(user_id: int) -> str:
    """BUG: ``random`` is CPython's Mersenne Twister (MT19937), not a
    CSPRNG -- its internal state is recoverable from a handful of
    observed outputs. Hashing a low-entropy ``random.random()`` draw with
    SHA-256 does not add real entropy; it only obscures a still-
    predictable input."""
    raw = f"{user_id}-{random.random()}"
    return hashlib.sha256(raw.encode()).hexdigest()
