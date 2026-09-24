# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 10 of 10). Genuinely distinct
# third variant from idiomatic-hmac-compare-digest-3.py/
# vulnerable-hmac-naive-equality-3.py (constant-time compare_digest() vs a
# naive `==`): both files in THIS pair use hmac.compare_digest() correctly
# for the comparison itself. The mechanism difference here is what bytes the
# signature is computed OVER -- the actual raw request body received, versus
# a re-serialized reconstruction of the parsed JSON, a real, well-documented
# webhook-verification pitfall (Stripe/GitHub's own webhook docs both
# explicitly warn to verify against the raw body, never a re-serialized
# copy of the parsed payload).
import hashlib
import hmac
import json


def verify_and_parse(raw_body: bytes, signature_header: str, webhook_secret: str) -> dict:
    # IDIOMATIC: the signature is computed over `raw_body` -- the exact
    # bytes the sender transmitted and signed -- BEFORE any JSON parsing
    # happens. Only after the signature is confirmed valid against those
    # exact bytes is the body parsed and returned.
    expected = hmac.new(webhook_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise ValueError("Invalid webhook signature")
    return json.loads(raw_body)
