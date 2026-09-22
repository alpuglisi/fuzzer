# Manufactured, representative of safe HMAC webhook-signature
# verification: hmac.compare_digest() performs a constant-time
# comparison, which Python's own hmac module documentation explicitly
# recommends specifically to avoid timing attacks on signature checks.
import hashlib
import hmac


def verify_webhook_signature(payload: bytes, signature_header: str, webhook_secret: str) -> bool:
    expected = hmac.new(webhook_secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
