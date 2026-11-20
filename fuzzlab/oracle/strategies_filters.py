"""Filter-bypass variants of an existing confirmation (CC-FUZZ-0632, FR-FUZZ-632).
Black-box: the probes are generic spellings of one canary, and the judgement is how a
browser reads the redirect target; nothing names a lab's paths, parameters or values.

**Open redirect past a prefix filter.** An app that refuses a target starting with
``http``, ``https``, ``www`` or ``//``, or that prefixes its own origin with no ``/``
after it, can still redirect off-site, because a browser drops tabs and newlines, reads
``\\`` as ``/`` after a special scheme, and reads ``http://own@host/`` as a login to
``host``. Evidence (CC-FUZZ-0632):

* the spellings are a public corpus's: PayloadsAllTheThings, Open Redirect ("//"
  to bypass "http", "\\/\\/" to bypass "//", the "@" character);
* `browser_resolve` agrees with Chromium 157 on 10 of 10 ``Location`` shapes served by a
  synthetic loopback server independent of any lab
  (`tests/test_oracle_strategies_filters.py::test_browser_resolve_agrees_with_chromium`);
* on a lab: SasanLabs VulnerableApp 2.2.115's five filtered redirect levels confirm,
  its own-origin and allowlisted levels do not (CC-LAB-0350).
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
