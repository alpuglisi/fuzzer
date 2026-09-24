"""Manufactured third variant for auth-session/python CWE-347 (Improper
Verification of Cryptographic Signature) -- distinct from this cell's
natural pair (vulnerable-1.py/idiomatic-1.py, PyJWT's real PyJWK
algorithm-inference bug). This one is a hand-rolled JWT verifier where
the token's own header ``alg`` claim directly selects the verification
branch, including an ``alg: none`` branch that performs no cryptographic
check at all -- the same class of bug as php/vulnerable-3-altered.php,
in a different language stack, per this cell's own assignment ("same
class, different stack").

Manufactured per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
mechanics". Self-contained (stdlib ``hmac``/``hashlib`` only) so it can
be exercised without any external JWT package.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def make_token(payload: dict, alg: str, secret: bytes) -> str:
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = b"" if alg == "none" else hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def verify_token(token: str, secret: bytes) -> dict:
    """BUG: dispatches verification based on the token's own claimed
    ``alg``, including trusting ``"none"`` as a legitimate, signature-free
    choice -- an attacker who rewrites a token's header to
    ``{"alg": "none"}`` and strips the signature segment sails straight
    through."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    signing_input = f"{header_b64}.{payload_b64}".encode()

    alg = header.get("alg")
    if alg == "none":
        pass  # no verification performed at all
    elif alg == "HS256":
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, sig):
            raise ValueError("invalid signature")
    else:
        raise ValueError(f"unsupported alg {alg!r}")
    return json.loads(_b64url_decode(payload_b64))
