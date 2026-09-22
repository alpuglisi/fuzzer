# Manufactured vulnerable variant, derived from
# idiomatic-hmac-compare-digest-3.py. Naive `==` string comparison
# instead of hmac.compare_digest() -- Python string equality short-
# circuits on the first mismatched byte, a well-documented real timing
# side-channel that lets an attacker recover a valid signature one byte
# at a time via repeated requests and response-time measurement.
import hashlib
import hmac


def verify_webhook_signature(payload: bytes, signature_header: str, webhook_secret: str) -> bool:
    expected = hmac.new(webhook_secret.encode(), payload, hashlib.sha256).hexdigest()
    return expected == signature_header
