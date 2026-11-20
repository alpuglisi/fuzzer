"""Filter-bypass variants of an existing confirmation (CC-FUZZ-0632, FR-FUZZ-632),
measured on SasanLabs OWASP VulnerableApp 2.2.115 (CC-LAB-0350) before it was written.

**Open redirect past a prefix filter.** An app that refuses a target starting with
``http``, ``https``, ``www`` or ``//`` (VulnerableApp Http3xxStatusCodeBasedInjection
LEVEL_2..5), or that prefixes its own origin with no ``/`` after it (LEVEL_6), still
redirects off-site: a browser reads ``\\`` as ``/`` after a special scheme and drops
tabs and newlines (the WHATWG URL parser), and reads ``http://own@host/`` as a login to
``host``. Measured in Chromium 157 (``page.on("request")``): ``/\\host/cb`` and
``\\/host/cb`` leave the origin at LEVEL_2..5, ``//host/cb`` at LEVEL_2, ``@host/cb`` at
LEVEL_6; none at LEVEL_7 (``scheme://own/`` + the value) or LEVEL_8 (an allowlist).
`OpenRedirectStrategy`'s plain canary (``https://host/cb``) lands at none of LEVEL_2..6.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from fuzzlab.oracle.probe import Verdict
from fuzzlab.oracle.strategies import OpenRedirectStrategy, _one_trailing_dot_off, _token

#: The special schemes a browser reads ``\\`` after as ``/`` (the ones a redirect lands on).
_SPECIAL = ("http", "https")
#: What WHATWG removes from anywhere in a URL (ASCII tab or newline) and trims from its
#: ends (C0 control or space).
_TAB_NEWLINE = "\t\n\r"
_C0_SPACE = "".join(chr(c) for c in range(0x21))


def browser_resolve(page_url: str, target: str) -> str:
    """``target`` (a ``Location`` value) resolved against ``page_url`` as a browser reads
    it, for the rules a redirect filter is bypassed with: C0 and space trimmed, tab and
    newline removed, and -- when the result's scheme is special (the target's own, or
    the page's for a relative target) -- every ``\\`` before the query read as ``/``.
    Anything else is `urljoin`'s reading."""
    t = (target or "").strip(_C0_SPACE)
    t = "".join(ch for ch in t if ch not in _TAB_NEWLINE)
    head, sep, tail = t.partition("?")
    frag_head, fsep, ftail = head.partition("#")
    scheme = frag_head.split(":", 1)[0].lower() if ":" in frag_head.split("/", 1)[0] \
        else urlsplit(page_url).scheme.lower()
    if scheme in _SPECIAL:
        frag_head = frag_head.replace("\\", "/")
    return urljoin(page_url, frag_head + fsep + ftail + sep + tail)


class OpenRedirectFilterBypassStrategy(OpenRedirectStrategy):
    """M9, after `OpenRedirectStrategy` (FR-FUZZ-632): when the plain canary did not land,
    the canary in the spellings a prefix filter misses and a browser still follows off-site
    -- scheme-relative ``//``, backslashed ``/\\``, and ``@`` after an app-prefixed origin
    -- each judged by where a browser lands (`browser_resolve`), never by a prefix test.
    At most three probes; the plain canary is `OpenRedirectStrategy`'s and is not re-sent."""
    mechanism = "redirect-target-control-filter-bypass"

    #: (spelling, template): ``{h}`` is the canary host.
    VARIANTS = (("scheme-relative", "//{h}/cb"),
                ("backslash", "/\\{h}/cb"),
                ("userinfo", "@{h}/cb"))

    @staticmethod
    def _lands_on(target, page_url, host) -> bool:
        try:
            parts = urlsplit(browser_resolve(page_url, target))
        except ValueError:
            return False
        return (parts.scheme.lower() in _SPECIAL
                and _one_trailing_dot_off(parts.hostname or "") == host
                and parts.path in ("/cb", "/cb/"))

    def confirm(self, candidate, sender):
        for spelling, template in self.VARIANTS:
            host = f"oracle{_token()}.example"
            value = template.format(h=host)
            hit = self._probe(sender, candidate, value, host)
            if hit is not None:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {**hit, "variant": spelling, "probe": value})
        return None
