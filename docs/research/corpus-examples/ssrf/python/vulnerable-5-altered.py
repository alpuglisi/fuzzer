# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 5 of 10). Derived from
# idiomatic-5-altered.py's real webhook-test structure. Minimal-pair
# discipline: identical scheme check, identical requests.post() call shape.
# The ONLY mechanism difference is the resolution/validation step: this file
# uses socket.gethostbyname() (IPv4-only, single result) instead of
# socket.getaddrinfo() (every resolved address, all families).
import ipaddress
import socket
from urllib.parse import urlparse

import requests

ALLOWED_SCHEMES = {"https"}


def test_webhook_url(webhook_url: str) -> dict:
    parsed = urlparse(webhook_url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only https webhook URLs can be tested")

    # VULNERABLE: gethostbyname() only ever inspects ONE resolved IPv4
    # address. A hostname whose DNS records include a private/loopback
    # IPv6 (AAAA) address alongside a public IPv4 (A) address passes this
    # check on the public A record, but requests/urllib3's own connection
    # logic (via getaddrinfo internally) may still connect over the
    # unchecked AAAA record depending on the host's address-family
    # preference -- the address actually verified is not guaranteed to be
    # the address actually connected to.
    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip_obj = ipaddress.ip_address(resolved_ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError("Refusing to test a webhook URL resolving to a non-public address")

    response = requests.post(webhook_url, json={"type": "test"}, timeout=3, allow_redirects=False)
    return {"status_code": response.status_code}
