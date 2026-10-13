"""Sink-context typing for reflected input (Phase 2 T2.4).

Classifies *where* a reflected marker lands in a response — the sink context —
which tells the reflected-XSS mechanism (M5) whether a break-out would execute and
which break-out to use. Also checks whether a context-breaking fragment survived
unescaped.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote

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


# --- structural reflected-XSS confirmation (BUG-0083, FR-FUZZ-15, PA-0084) ------------
#
# A substring of the break-out fragment appearing "unescaped" somewhere is not proof:
# `javascript:TOK` mid-URL, `';TOK;//` inside a double-quoted JS string, or `<TOK>`
# inside a <textarea> are all inert. Confirmation is judged on the parsed response by
# the effect the break-out would have: an element exists outside any inert element, an
# attribute was injected, or the token sits in JavaScript **code** state.

#: Elements whose content the browser does not parse as markup (or never renders).
INERT_ELEMENTS = frozenset({"textarea", "title", "script", "style", "xmp", "noscript",
                            "iframe", "noembed", "noframes", "plaintext", "template"})
#: Attributes whose value runs a ``javascript:`` URL, by element (``*`` = any element).
_EXEC_ATTRS = {"href": {"a", "area"}, "action": {"form"},
               "formaction": {"button", "input"}, "src": {"iframe", "frame", "embed"},
               "data": {"object"}}
UNSURE = "unsure"
_REGEX_PREV = set("(,=:[!&|?{};+-*%<>~^") | {""}


def js_states(src: str) -> list[str]:
    """The lexical state at each character of JavaScript ``src``: ``code``, a quote
    character (``'`` ``"`` `` ` ``), ``comment`` or ``regex``. Returns ``[UNSURE] *
    len(src)`` when the lexer cannot be sure (a string or regex literal left open at the
    end): the caller then gives no verdict (fail closed, PA-0025)."""
    out: list[str] = []
    state, i, n = "code", 0, len(src)
    prev = ""                                  # last non-space code character
    while i < n:
        c = src[i]
        if state == "code":
            if c in "'\"`":
                out.append("code")
                state = c
            elif src.startswith("//", i):
                j = src.find("\n", i)
                j = n if j == -1 else j
                out.extend(["comment"] * (j - i))
                i = j
                continue
            elif src.startswith("/*", i):
                j = src.find("*/", i + 2)
                if j == -1:
                    return [UNSURE] * n
                out.extend(["comment"] * (j + 2 - i))
                i = j + 2
                continue
            elif c == "/" and prev in _REGEX_PREV:
                j, in_class = i + 1, False       # a regex literal: skip to its end
                while j < n and src[j] != "\n":
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    elif src[j] == "/" and not in_class:
                        break
                    j += 1
                if j >= n or src[j] != "/":
                    return [UNSURE] * n
                out.extend(["regex"] * (j + 1 - i))
                i = j + 1
                prev = "/"
                continue
            else:
                out.append("code")
                if not c.isspace():
                    prev = c
        else:                                   # inside a string literal
            out.append(state)
            if c == "\\" and i + 1 < n:
                out.append(state)
                i += 2
                continue
            if c == state:
                state, prev = "code", c
            elif c == "\n" and state != "`":
                return [UNSURE] * n             # an unterminated string
        i += 1
    if state != "code":
        return [UNSURE] * n
    return out


def _js_state_at(src: str, needle: str) -> str | None:
    i = src.find(needle)
    return None if i < 0 else js_states(src)[i]


def js_token_in_code(src: str, token: str) -> bool:
    """True when ``token`` occurs in ``src`` in **code** state (never when unsure)."""
    states = None
    start = 0
    while True:
        i = src.find(token, start)
        if i < 0:
            return False
        states = states or js_states(src)
        if states[i] == "code":
            return True
        start = i + 1


def _js_breakout(state: str | None, token: str) -> str | None:
    if state == "code":
        return f";{token};//"
    if state in ("'", '"', "`"):
        return f"{state};{token};//"
    return None                                 # comment / regex / unsure / absent


def _is_exec_attr(tag: str, attr: str) -> bool:
    return tag in _EXEC_ATTRS.get(attr.lower(), set())


def _js_url_body(value: str) -> str | None:
    """The JavaScript of a ``javascript:`` URL value (whitespace/controls stripped,
    percent-decoded as the browser does), or None."""
    v = value.lstrip("".join(chr(c) for c in range(0x21)))
    if not v.lower().startswith("javascript:"):
        return None
    return unquote(v[len("javascript:"):])


def _raw_attr_quote(html: str, marker: str) -> str | None:
    """The quote delimiting the attribute value that holds ``marker`` in the raw HTML
    (BeautifulSoup does not keep it): ``"``, ``'``, or ``""`` for unquoted."""
    start = 0
    while True:
        i = html.find(marker, start)
        if i < 0:
            return None
        lt, gt = html.rfind("<", 0, i), html.rfind(">", 0, i)
        if lt > gt:                               # inside a tag
            eq = html.rfind("=", lt, i)
            if eq != -1:
                j = eq + 1
                while j < i and html[j] in " \t\n\r\f":
                    j += 1
                return html[j] if html[j] in "\"'" else ""
        start = i + 1


@dataclass(frozen=True)
class Reflection:
    """Where a marker landed: ``context`` is ``script`` / ``attribute`` / ``html``."""
    context: str
    js_state: str | None = None                   # script / js-url: state at the marker
    attr_exec: bool = False                       # a javascript:-running attribute
    attr_at_start: bool = False                   # the marker starts the attribute value
    quote: str | None = None                      # attribute quoting in the raw text
    inert_parent: str | None = None               # html: the innermost inert ancestor


def locate_reflection(html: str, marker: str) -> Reflection | None:
    """Type the first reflection of ``marker`` (script, then attribute, then text)."""
    if not html or marker not in html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        text = script.get_text() or ""
        if marker in text:
            return Reflection("script", js_state=_js_state_at(text, marker))
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            for val in (value if isinstance(value, list) else [value]):
                if isinstance(val, str) and marker in val:
                    exec_attr = _is_exec_attr(tag.name, attr)
                    js = _js_url_body(val) if exec_attr else None
                    return Reflection(
                        "attribute", attr_exec=exec_attr,
                        js_state=_js_state_at(js, marker) if js is not None else None,
                        attr_at_start=val.lstrip().startswith(marker),
                        quote=_raw_attr_quote(html, marker))
    for text in soup.find_all(string=lambda s: s is not None and marker in s):
        inert = next((p.name for p in text.parents if p.name in INERT_ELEMENTS), None)
        return Reflection("html", inert_parent=inert)
    return Reflection("html")


def element_injected(html: str, name: str) -> bool:
    """True when an element ``name`` exists with no inert ancestor."""
    soup = BeautifulSoup(html, "html.parser")
    return any(not any(p.name in INERT_ELEMENTS for p in el.parents if p.name)
               for el in soup.find_all(name.lower()))


def attribute_injected(html: str, name: str) -> bool:
    """True when some element carries an attribute named ``name``."""
    soup = BeautifulSoup(html, "html.parser")
    return any(name.lower() in (a.lower() for a in tag.attrs)
               for tag in soup.find_all(True)
               if not any(p.name in INERT_ELEMENTS for p in tag.parents if p.name))


def js_executes(html: str, token: str) -> bool:
    """True when ``token`` is in JavaScript code state in a ``<script>`` or in an
    executing ``javascript:`` URL."""
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        if js_token_in_code(script.get_text() or "", token):
            return True
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if not _is_exec_attr(tag.name, attr):
                continue
            for val in (value if isinstance(value, list) else [value]):
                js = _js_url_body(val) if isinstance(val, str) else None
                if js is not None and js_token_in_code(js, token):
                    return True
    return False


def xss_breakouts(ref: Reflection, token: str):
    """``(kind, fragment, check)`` tries for a reflection, at most 3, most specific
    first; ``check(html)`` judges the second response structurally."""
    tries = []
    if ref.context == "script":
        frag = _js_breakout(ref.js_state, token)
        if frag:
            tries.append(("js", frag, lambda h: js_executes(h, token)))
    elif ref.context == "attribute":
        if ref.attr_exec and ref.js_state is not None:
            frag = _js_breakout(ref.js_state, token)
            if frag:
                tries.append(("js-url", frag, lambda h: js_executes(h, token)))
        if ref.attr_exec and ref.attr_at_start:
            tries.append(("url-scheme", f"javascript:{token}",
                          lambda h: js_executes(h, token)))
        if ref.quote is not None:
            q = ref.quote
            # unquoted: a value first, since whitespace right after '=' is skipped
            frag = f"{q} {token}=1 x={q}" if q else f"x {token}=1"
            tries.append(("attribute-injection", frag,
                          lambda h: attribute_injected(h, token)))
    else:
        close = f"</{ref.inert_parent}>" if ref.inert_parent else ""
        tries.append(("element", f"{close}<{token}>",
                      lambda h: element_injected(h, token)))
    return tries[:3]
