"""Hybrid-crawl decision: does a page need a headless browser? (Phase 2 T2.7).

Fetch cheaply over HTTP first; escalate to Playwright only for client-rendered
pages (empty shells, SPA roots, noscript-gated content). Conservative — escalate on
any real doubt — so JS-only surface is never missed to save a browser launch.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

_SPA_ROOTS = (("div", {"id": "root"}), ("div", {"id": "app"}),
              ("div", {"id": "__next"}), ("div", {"id": "__nuxt"}))


def needs_browser(html: str) -> bool:
    """True if the static HTML looks client-rendered (should escalate to a browser)."""
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(strip=True)
    scripts = soup.find_all("script")
    script_len = sum(len(s.get_text() or "") for s in scripts) + \
        sum(len(s.get("src") or "") for s in scripts)

    # An empty SPA mount point => the content is built client-side.
    for name, attrs in _SPA_ROOTS:
        el = soup.find(name, attrs=attrs)
        if el is not None and not el.get_text(strip=True):
            return True

    # <noscript> that asks the user to enable JavaScript.
    noscript = soup.find("noscript")
    if noscript:
        ns_text = (noscript.get_text() or "").lower()
        if "enable" in ns_text and ("javascript" in ns_text or "js" in ns_text):
            return True

    # Empty shell: little visible text but scripts present.
    if len(text) < 200 and scripts:
        return True

    # Overwhelmingly script vs content.
    if script_len > 3 * max(len(text), 1):
        return True

    return False
