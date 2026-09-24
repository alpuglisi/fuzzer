"""Idiomatic counterpart to vulnerable-3-altered.py (auth-session/python,
CWE-347). Differs only in the verification mechanism: the caller pins
the one algorithm this verifier will ever accept (HS256) before looking
at the token at all, so a token's own ``alg`` claim (including
``"none"``) can never select a weaker or absent check.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

EXPECTED_ALG = "HS256"  # pinned by the caller, not read from the token


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def make_token(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def verify_token(token: str, secret: bytes) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    if header.get("alg") != EXPECTED_ALG:
        raise ValueError(
            f"rejected: expected alg {EXPECTED_ALG}, token claims {header.get('alg')!r}"
        )
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected, sig):
        raise ValueError("invalid signature")
    return json.loads(_b64url_decode(payload_b64))
