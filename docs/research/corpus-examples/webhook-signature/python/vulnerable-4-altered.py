# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 10 of 10). Derived from
# idiomatic-4-altered.py's real verify_and_parse() structure. Minimal-pair
# discipline: identical function signature, identical hmac.compare_digest()
# comparison call. The ONLY mechanism difference: this file parses the body
# to JSON FIRST, then computes the expected signature over
# `json.dumps(payload)` -- a re-serialized reconstruction of the parsed
# data -- instead of over the raw bytes actually received and signed.
import hashlib
import hmac
import json


def verify_and_parse(raw_body: bytes, signature_header: str, webhook_secret: str) -> dict:
    # VULNERABLE: the body is parsed to a Python dict first, and the
    # signature is verified against `json.dumps(payload)` -- a freshly
    # re-serialized copy of the parsed data -- rather than against
    # `raw_body` itself. JSON permits many distinct byte sequences that all
    # parse to the same dict (different key order, whitespace, duplicate
    # keys where the last one wins, numeric vs. string representations of
    # the same value); this check only proves the payload's PARSED FORM
    # matches whatever bytes originally produced a valid signature, not
    # that these specific transmitted bytes are the ones the sender signed.
    payload = json.loads(raw_body)
    expected = hmac.new(webhook_secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise ValueError("Invalid webhook signature")
    return payload
