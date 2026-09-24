# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 5 of 10). Genuinely distinct third
# variant from idiomatic-oembed-unfurl-4.py/vulnerable-oembed-unfurl-4.py
# (a chat-link-unfurl feature): a SaaS "test this outgoing webhook URL"
# settings feature, using a different real Python idiom -- socket.getaddrinfo()
# (which returns every resolved address, IPv4 AND IPv6) checked in full,
# rather than socket.gethostbyname() (IPv4-only, single result).
import ipaddress
import socket
from urllib.parse import urlparse

import requests

ALLOWED_SCHEMES = {"https"}


def test_webhook_url(webhook_url: str) -> dict:
    parsed = urlparse(webhook_url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only https webhook URLs can be tested")

    # getaddrinfo() returns every address family the hostname resolves to
    # (A and AAAA records both), not just the first IPv4 result --
    # socket.gethostbyname() only ever returns an IPv4 address and raises
    # on an IPv6-only host, so a hostname with a mix of public IPv4 and
    # private/loopback IPv6 records would pass a gethostbyname()-only check
    # while still being reachable over the unchecked address family.
    addr_infos = socket.getaddrinfo(parsed.hostname, None)
    for family, _, _, _, sockaddr in addr_infos:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise ValueError("Refusing to test a webhook URL resolving to a non-public address")

    response = requests.post(webhook_url, json={"type": "test"}, timeout=3, allow_redirects=False)
    return {"status_code": response.status_code}
