"""Sink-context typing for reflected input (Phase 2 T2.4).

Classifies *where* a reflected marker lands in a response — the sink context —
which tells the reflected-XSS mechanism (M5) whether a break-out would execute and
which break-out to use, and judges a break-out by its **structural** effect on the
parsed response (BUG-0083), never by a substring surviving somewhere.
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
        if marker in (script.get_text() or "") and script_executes(script):
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


# --- structural reflected-XSS confirmation (BUG-0083, FR-FUZZ-39, PA-0084) ------------
#
# A substring of the break-out fragment appearing "unescaped" somewhere is not proof:
# `javascript:TOK` mid-URL, `';TOK;//` inside a double-quoted JS string, or `<TOK>`
# inside a <textarea> are all inert. Confirmation is judged on the parsed response by
# the effect the break-out would have: an element exists outside any inert element, an
# attribute was injected, or the token sits in JavaScript **code** state.
#
# "Inside <script>" is not "JavaScript" (BUG-0093, PA-0094): a JSON / ld+json / template
# data block, an import map, a `nomodule` classic script, the inline body of a script
# with `src`, and any script under an inert ancestor (`<template>`, ...) never run. The
# container's executability is part of the structure: `script_executes`.

#: Elements whose content the browser does not parse as markup (or never renders).
INERT_ELEMENTS = frozenset({"textarea", "title", "script", "style", "xmp", "noscript",
                            "iframe", "noembed", "noframes", "plaintext", "template"})
#: Attributes whose value runs a ``javascript:`` URL, by element (``*`` = any element).
_EXEC_ATTRS = {"href": {"a", "area"}, "action": {"form"},
               "formaction": {"button", "input"}, "src": {"iframe", "frame", "embed"},
               "data": {"object"}}
UNSURE = "unsure"
#: JavaScript MIME type essences (HTML standard, "JavaScript MIME type"): a script's
#: type string must equal one of these, ASCII case-insensitively, to run as classic JS.
JS_MIME_TYPES = frozenset({
    "application/ecmascript", "application/javascript", "application/x-ecmascript",
    "application/x-javascript", "text/ecmascript", "text/javascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript",
    "text/livescript", "text/x-ecmascript", "text/x-javascript"})
_ASCII_WS = " \t\n\f\r"
#: Keywords after which a ``/`` begins a regex literal (an expression is expected).
REGEX_KEYWORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete",
                            "void", "throw", "case", "do", "else", "yield", "await",
                            "default"})
#: Keywords whose ``( … )`` is a statement head: a ``/`` after its ``)`` is a regex.
_STATEMENT_PARENS = frozenset({"if", "while", "for", "with"})
_IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


def js_states(src: str) -> list[str]:
    """The lexical state at each character of JavaScript ``src``: ``code``, a quote
    character (``'`` ``"`` `` ` ``), ``comment`` or ``regex``. Returns ``[UNSURE] *
    len(src)`` when the lexer cannot be sure (a string or regex literal left open at the
    end, or a ``/`` whose meaning the grammar leaves open): the caller then gives no
    verdict (fail closed, PA-0025).

    Regex versus division is decided from the previous **token**, not one character
    (BUG-0102, PA-0103): a regex follows an operator or punctuator, a keyword in
    `REGEX_KEYWORDS`, or the ``)`` closing an ``if`` / ``while`` / ``for`` / ``with``
    head; a division follows an identifier (``this`` / ``null`` / ``true`` … included),
    a number, a string, a regex, ``]``, any other ``)`` and postfix ``++`` / ``--``. A
    ``/`` right after ``}`` (a block or an object literal) is ambiguous: UNSURE."""
    out: list[str] = []
    state, i, n = "code", 0, len(src)
    last: tuple = ("start",)                   # the previous significant token
    parens: list[tuple] = []                   # the token before each open '('
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
            elif c == "/":
                kind = _slash_kind(last)
                if kind == UNSURE:
                    return [UNSURE] * n
                if kind == "regex":
                    j, in_class = i + 1, False   # a regex literal: skip to its end
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
                    last = ("operand",)
                    continue
                out.append("code")              # division
                last = ("punct", "/")
            elif c in _IDENT:
                j = i
                while j < n and src[j] in _IDENT:
                    j += 1
                word = src[i:j]
                out.extend(["code"] * (j - i))
                last = ("operand",) if word[0].isdigit() else ("word", word)
                i = j
                continue
            elif src.startswith("++", i) or src.startswith("--", i):
                out.extend(["code", "code"])
                # postfix after an operand ends an expression; prefix starts one
                last = ("operand",) if last[0] in ("word", "operand", "close") \
                    else ("punct", c)
                i += 2
                continue
            else:
                out.append("code")
                if c == "(":
                    parens.append(last)
                    last = ("punct", "(")
                elif c == ")":
                    opener = parens.pop() if parens else ("start",)
                    head = opener[0] == "word" and opener[1] in _STATEMENT_PARENS
                    last = ("punct", ")") if head else ("close",)
                elif c == "]":
                    last = ("close",)
                elif c == "}":
                    last = ("brace",)
                elif not c.isspace():
                    last = ("punct", c)
        else:                                   # inside a string literal
            out.append(state)
            if c == "\\" and i + 1 < n:
                out.append(state)
                i += 2
                continue
            if c == state:
                state, last = "code", ("operand",)
            elif c == "\n" and state != "`":
                return [UNSURE] * n             # an unterminated string
        i += 1
    if state != "code":
        return [UNSURE] * n
    return out


def _slash_kind(last: tuple) -> str:
    """``regex``, ``division`` or `UNSURE` for a ``/`` after token ``last``."""
    kind = last[0]
    if kind in ("start", "punct"):
        return "regex"
    if kind == "word":
        return "regex" if last[1] in REGEX_KEYWORDS else "division"
    if kind in ("operand", "close"):
        return "division"
    return UNSURE                               # "brace": block end or object literal


def _attr(tag, name: str) -> str | None:
    value = tag.attrs.get(name)
    if isinstance(value, list):                   # a multi-valued attribute in bs4
        value = " ".join(value)
    return value


def _has_inert_ancestor(tag) -> bool:
    return any(p.name in INERT_ELEMENTS for p in tag.parents if p.name)


def script_executes(tag) -> bool:
    """Whether a ``<script>`` element's **inline** body runs, per the HTML standard's
    "prepare the script element" type rules (BUG-0093):

    - the type string: ``type`` when present (empty → JavaScript; otherwise ASCII
      whitespace stripped), else ``"text/" + language`` when ``language`` is present
      and non-empty, else JavaScript;
    - it runs as a classic script when the type string is a JavaScript MIME type
      essence match (exact, case-insensitive: ``text/javascript;charset=utf-8`` is a
      data block), and as a module when it is ``module``; anything else (JSON,
      ``importmap``, ``text/template``) is a data block and never runs;
    - a classic script with ``nomodule`` does not run; with ``src`` the inline body is
      never run (even ``src=""``); under an inert ancestor (``<template>``,
      ``<noscript>``, ...) nothing runs.
    """
    if tag.name != "script" or "src" in tag.attrs or _has_inert_ancestor(tag):
        return False
    stype = _attr(tag, "type")
    if stype is None:
        language = _attr(tag, "language")
        kind = "classic" if not language else \
            ("classic" if f"text/{language}".lower() in JS_MIME_TYPES else None)
    elif stype == "":
        kind = "classic"
    else:
        stype = stype.strip(_ASCII_WS).lower()
        kind = "classic" if stype in JS_MIME_TYPES else \
            ("module" if stype == "module" else None)
    if kind is None:
        return False
    return not (kind == "classic" and "nomodule" in tag.attrs)


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
    """Type the first reflection of ``marker`` (executing script, then attribute, then
    text). A marker in a script that never runs (`script_executes`) is text inside a
    raw-text element: ``html`` with ``inert_parent="script"``, whose only try is the
    ``</script>`` element break-out (BUG-0093)."""
    if not html or marker not in html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        text = script.get_text() or ""
        if marker in text and script_executes(script):
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
    """True when ``token`` is in JavaScript code state in an executing ``<script>``
    (`script_executes`) or in an executing ``javascript:`` URL on an element with no
    inert ancestor."""
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        if script_executes(script) and js_token_in_code(script.get_text() or "", token):
            return True
    for tag in soup.find_all(True):
        if _has_inert_ancestor(tag):
            continue
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
