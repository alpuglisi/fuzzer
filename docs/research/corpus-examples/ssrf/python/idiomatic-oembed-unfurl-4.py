# Manufactured, representative of a chat-app "link unfurl" feature
# (Slack/Discord-style: fetch oEmbed metadata for a link a user pasted
# into a message, common in social/UGC and SaaS-collaboration platforms).
import ipaddress
import socket
from urllib.parse import urlparse

import requests

ALLOWED_SCHEMES = {"https"}


def unfurl_link(message_url: str) -> dict:
    parsed = urlparse(message_url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only https links can be unfurled")

    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip_obj = ipaddress.ip_address(resolved_ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError("Refusing to unfurl a link resolving to a private address")

    response = requests.get(message_url, timeout=3, allow_redirects=False)
    return response.json()
