"""Idiomatic counterpart to vulnerable-4-altered.py (auth-session/python,
CWE-330/CWE-338). Differs only in the token-generation mechanism: the
``secrets`` module (a CSPRNG, backed by ``os.urandom``) replaces the
``random.random()``+SHA-256 construction, drawing entropy directly
instead of hashing a predictable seed.
"""
from __future__ import annotations

import secrets


def generate_remember_me_token(user_id: int) -> str:
    return secrets.token_hex(32)
