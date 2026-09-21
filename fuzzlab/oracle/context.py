"""Sink-context typing for reflected input (Phase 2 T2.4).

Classifies *where* a reflected marker lands in a response — the sink context —
which tells the reflected-XSS mechanism (M5) whether a break-out would execute and
which break-out to use. Also checks whether a context-breaking fragment survived
unescaped.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

# Attributes whose value is a URL (a reflected marker here is a URL-attribute sink).
_URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster",
              "background", "cite", "longdesc"}

CONTEXTS = ("html", "html-attribute", "url-attribute", "js", "none")


def type_reflection(html: str, marker: str) -> str:
    """Return the sink context of ``marker`` in ``html``: one of ``CONTEXTS``."""
    if not html or marker not in html:
        return "none"
    soup = BeautifulSoup(html, "html.parser")

    for script in soup.find_all("script"):
        if marker in (script.get_text() or ""):
            return "js"

    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            values = value if isinstance(value, list) else [value]
            for val in values:
                if isinstance(val, str) and marker in val:
                    return "url-attribute" if attr.lower() in _URL_ATTRS else "html-attribute"

    if marker in soup.get_text():
        return "html"
    return "html"   # present but unclassified (e.g. raw between tags)


def is_unescaped(html: str, fragment: str) -> bool:
    """True if ``fragment`` appears literally (its special chars were not encoded)."""
    return bool(fragment) and fragment in html


def breakout_for(context: str, token: str) -> tuple[str, str] | None:
    """Return ``(fragment_to_send, signature_to_find)`` for a context break-out.

    The fragment is what we inject; the signature is what must appear *unescaped* in
    the response to prove the break-out survived (i.e. the sink did not encode it).
    """
    if context == "html":
        return f"<{token}>", f"<{token}>"                 # a new tag
    if context == "html-attribute":
        return f'"><{token}>', f"<{token}>"               # close attr+tag, new tag
    if context == "url-attribute":
        return f"javascript:{token}", f"javascript:{token}"
    if context == "js":
        return f"';{token};//", f";{token};"              # break out of a JS string
    return None
