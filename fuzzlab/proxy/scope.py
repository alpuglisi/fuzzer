"""Scope engine (FR-PROXY-5, NFR-PROXY-safe).

Only in-scope traffic is intercepted, edited, or recorded. The proxy is a
security-sensitive component pointed at a lab, so scope is **default-deny**: a host is
out of scope unless an include rule matches, and any matching exclude rule overrides
includes. This keeps the proxy from ever touching a host the user did not name.

Matching is on host (with an optional path regex). Host rules support a leading ``.``
for subdomain suffix matching (``.lab.local`` matches ``a.lab.local`` and
``lab.local``); ``*`` matches any host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fuzzlab.proxy.authority import split_authority


@dataclass(frozen=True)
class ScopeRule:
    host: str = "*"
    path_regex: str | None = None
    exclude: bool = False

    def __post_init__(self):
        # validated when created (BUG-0085): a bad regex used to raise per request
        if self.path_regex is not None:
            try:
                re.compile(self.path_regex)
            except re.error as exc:
                raise ValueError(f"invalid scope path regex: {exc}") from exc

    def matches(self, host: str, path: str = "/") -> bool:
        if not _host_matches(self.host, host):
            return False
        if self.path_regex is not None and re.search(self.path_regex, path) is None:
            return False
        return True


class Scope:
    """An ordered set of include/exclude rules; default-deny."""

    def __init__(self, rules: list[ScopeRule] | None = None):
        self.rules: list[ScopeRule] = list(rules or [])

    def include(self, host: str, path_regex: str | None = None) -> "Scope":
        self.rules.append(ScopeRule(host=host, path_regex=path_regex, exclude=False))
        return self

    def exclude(self, host: str, path_regex: str | None = None) -> "Scope":
        self.rules.append(ScopeRule(host=host, path_regex=path_regex, exclude=True))
        return self

    def in_scope(self, host: str, path: str = "/") -> bool:
        host = _normalize_host(host)
        included = False
        for rule in self.rules:
            if rule.matches(host, path):
                if rule.exclude:
                    return False          # an explicit exclude always wins
                included = True
        return included

    @classmethod
    def for_host(cls, host: str) -> "Scope":
        """A one-host scope — the common lab case (e.g. ``127.0.0.1:8080``)."""
        return cls([ScopeRule(host=_normalize_host(host))])


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower()


def _host_matches(pattern: str, host: str) -> bool:
    """Both sides are parsed as authorities (`split_authority`, IPv6-safe, BUG-0086): the
    hosts must match, and a pattern's port, when it has one, must equal the host's. A
    port-less pattern matches any port."""
    pattern = _normalize_host(pattern)
    if pattern in ("", "*"):
        return True
    p_host, p_port = split_authority(pattern)
    h_host, h_port = split_authority(host)
    if p_port is not None and p_port != h_port:
        return False
    # A leading dot means "this domain or any subdomain of it".
    if p_host.startswith("."):
        return h_host == p_host[1:] or h_host.endswith(p_host)
    return h_host == p_host
