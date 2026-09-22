# Manufactured vulnerable variant, derived from
# idiomatic-oembed-unfurl-4.py. No scheme/IP check, redirects followed.
import requests


def unfurl_link(message_url: str) -> dict:
    # No scheme allowlist, no resolved-IP check, and allow_redirects
    # defaults to True in requests -- a pasted link can redirect through
    # a public URL to an internal one and still be fetched.
    response = requests.get(message_url, timeout=3)
    return response.json()
