"""Sink-context typing for reflected input (Phase 2 T2.4).

Classifies *where* a reflected marker lands in a response — the sink context —
which tells the reflected-XSS mechanism (M5) whether a break-out would execute and
which break-out to use -- in every context the marker lands in, not only the first
(BUG-0154) -- and judges a break-out by its **structural** effect on the
parsed response (BUG-0083), never by a substring surviving somewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import unescape as _unescape
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
    """A fallback only (`_attr_quote` reads the attribute's own start tag): the quote
    before the nearest ``=`` left of the first raw occurrence of ``marker`` inside
    something tag-like. It misreads a value holding an ``=`` before the marker
    (``href="/s?q=MARK"`` reads as unquoted, BUG-0155), so it is used only when the
    parser gave no source position for the tag."""
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


def _start_tag_attrs(html: str, pos: int) -> list[tuple[str, str | None, str]]:
    """``(name, quote, raw value)`` of each attribute of the start tag at ``html[pos]``
    (a ``<``), lexed by the HTML tokenizer's attribute states: a name runs to
    whitespace, ``/``, ``>`` or ``=`` (its first character may be ``=``); a value is
    double-quoted, single-quoted (to the matching quote, ``>`` included) or unquoted
    (to whitespace or ``>``). ``quote`` is ``"``, ``'``, ``""`` for unquoted, or None
    for an attribute with no value. Names are lower-cased, as the parser stores them."""
    n, out = len(html), []
    i = pos + 1
    while i < n and html[i] not in _ASCII_WS and html[i] not in "/>":
        i += 1                                    # the tag name
    while i < n:
        while i < n and (html[i] in _ASCII_WS or html[i] == "/"):
            i += 1
        if i >= n or html[i] == ">":
            break
        start, i = i, i + 1
        while i < n and html[i] not in _ASCII_WS and html[i] not in "/>=":
            i += 1
        name = html[start:i].lower()
        while i < n and html[i] in _ASCII_WS:
            i += 1
        if i >= n or html[i] != "=":
            out.append((name, None, ""))
            continue
        i += 1
        while i < n and html[i] in _ASCII_WS:
            i += 1
        if i < n and html[i] in "\"'":
            q = html[i]
            end = html.find(q, i + 1)
            end = n if end == -1 else end
            out.append((name, q, html[i + 1:end]))
            i = end + 1
        else:
            end = i
            while end < n and html[end] not in _ASCII_WS and html[end] != ">":
                end += 1
            out.append((name, "", html[i:end]))
            i = end
    return out


def _line_starts(html: str) -> list[int]:
    """The offset of each line's first character, as `html.parser` counts lines
    (``\\n`` only), for a tag's ``sourceline`` / ``sourcepos``."""
    starts = [0]
    i = html.find("\n")
    while i != -1:
        starts.append(i + 1)
        i = html.find("\n", i + 1)
    return starts


def _attr_quote(html: str, tag, attr: str, marker: str, line_starts) -> str | None:
    """The quote of attribute ``attr`` of ``tag`` (the one holding ``marker``), read
    from the tag's own start tag in the raw text (BUG-0155): the parser keeps the
    tag's source position but not its quoting. The last same-named attribute holding
    the marker wins, as the parser keeps the last duplicate. With no source position
    (another parser), the old nearest-``=`` reading is the fallback."""
    line, col = getattr(tag, "sourceline", None), getattr(tag, "sourcepos", None)
    if line is not None and col is not None and 0 < line <= len(line_starts()):
        pos = line_starts()[line - 1] + col
        if html.startswith("<", pos):
            found = [q for name, q, raw in _start_tag_attrs(html, pos)
                     if name == attr.lower() and marker in _unescape(raw)]
            if found:
                return found[-1]
    return _raw_attr_quote(html, marker)


@dataclass(frozen=True)
class Reflection:
    """Where a marker landed: ``context`` is ``script`` / ``attribute`` / ``html``."""
    context: str
    js_state: str | None = None                   # script / js-url: state at the marker
    attr_exec: bool = False                       # a javascript:-running attribute
    attr_at_start: bool = False                   # the marker starts the attribute value
    quote: str | None = None                      # attribute quoting in the raw text
    inert_parent: str | None = None               # html: the innermost inert ancestor


def _js_states_of(src: str, marker: str) -> list[str]:
    """The lexer state at each occurrence of ``marker`` in ``src``, in order."""
    out, states, i = [], None, src.find(marker)
    while i != -1:
        states = states or js_states(src)
        out.append(states[i])
        i = src.find(marker, i + 1)
    return out


def locate_reflections(html: str, marker: str) -> list[Reflection]:
    """Every distinct context ``marker`` is reflected in (BUG-0154), in a fixed order:
    executing scripts (by the lexer state at each occurrence), then attribute values
    (with their executability, position and raw quote), then text (with its innermost
    inert parent), each group in document order; equal contexts appear once. An
    empty list means no reflection. A page that shows a value escaped in one place
    and raw in another (an edit form's ``<input value>`` beside a ``<p>``) is typed in
    both, so the raw place's break-out is tried too.

    A marker in a script that never runs (`script_executes`) is text inside a
    raw-text element: ``html`` with ``inert_parent="script"``, whose only try is the
    ``</script>`` element break-out (BUG-0093). The text of an executing script is its
    script context only. A marker the parser shows nowhere (e.g. inside a tag name) is
    typed ``html``, as before."""
    if not html or marker not in html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    found: list[Reflection] = []

    def add(ref: Reflection) -> None:
        if ref not in found:
            found.append(ref)

    running = set()
    for script in soup.find_all("script"):
        text = script.get_text() or ""
        if marker in text and script_executes(script):
            running.add(id(script))
            for state in _js_states_of(text, marker):
                add(Reflection("script", js_state=state))
    starts: list[int] | None = None

    def line_starts() -> list[int]:
        nonlocal starts
        starts = starts if starts is not None else _line_starts(html)
        return starts
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            for val in (value if isinstance(value, list) else [value]):
                if not (isinstance(val, str) and marker in val):
                    continue
                exec_attr = _is_exec_attr(tag.name, attr)
                js = _js_url_body(val) if exec_attr else None
                quote = _attr_quote(html, tag, attr, marker, line_starts)
                states = (_js_states_of(js, marker) if js is not None else []) or [None]
                for state in states:
                    add(Reflection("attribute", attr_exec=exec_attr, js_state=state,
                                   attr_at_start=val.lstrip().startswith(marker),
                                   quote=quote))
    for text in soup.find_all(string=lambda s: s is not None and marker in s):
        if id(text.parent) in running:
            continue
        inert = next((p.name for p in text.parents if p.name in INERT_ELEMENTS), None)
        add(Reflection("html", inert_parent=inert))
    return found or [Reflection("html")]


def locate_reflection(html: str, marker: str) -> Reflection | None:
    """The first of `locate_reflections` (executing script, then attribute, then
    text), or None when ``marker`` is not reflected. Kept for callers that type one
    reflection; a confirmer tries them all (BUG-0154)."""
    found = locate_reflections(html, marker)
    return found[0] if found else None


def _in_form_control(node) -> bool:
    """Is ``node`` (a string) inside a ``<textarea>`` or a selected ``<option>``?"""
    return any(p.name == "textarea" or (p.name == "option" and p.has_attr("selected"))
               for p in node.parents if p.name)


def split_form_control_values(html: str) -> tuple[list[str], list[str]]:
    """``(form-control values, everything else)`` of the parsed page (BUG-0133).

    A form shows a stored value back for editing in an ``<input>``'s ``value``
    attribute, a ``<textarea>``'s content or a selected ``<option>``'s text and
    ``value``: those are the first list. Every other string (text, comments, script
    and style content) and every other attribute value is the second. Values are as
    the parser decodes them."""
    soup = BeautifulSoup(html or "", "html.parser")
    controls: list[str] = []
    rest: list[str] = []
    for string in soup.find_all(string=True):
        (controls if _in_form_control(string) else rest).append(str(string))
    for tag in soup.find_all(True):
        selected_option = tag.name == "option" and tag.has_attr("selected")
        for attr, value in tag.attrs.items():
            value = " ".join(value) if isinstance(value, list) else value
            if not isinstance(value, str):
                continue
            edit = attr.lower() == "value" and (tag.name == "input" or selected_option)
            (controls if edit else rest).append(value)
    return controls, rest


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
    """``(kind, fragment, check)`` tries for **one** reflection, at most 3, most
    specific first; ``check(html)`` judges the second response structurally. A page
    reflecting in several contexts gets each context's tries (`locate_reflections`;
    the confirmer caps the total, FR-FUZZ-54)."""
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
