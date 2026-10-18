"""Every URL a document links, by the rules of the format it is in (pure; no network).

A crawler that reads only ``<a href>`` misses most of how the web links resources. This
module reads what the specifications define, never one site's markup:

* **HTML** (`html_urls`): every URL-valued attribute of the HTML Living Standard and of
  its obsolete-but-parsed predecessors (`URL_ATTRIBUTES`: ``href``, ``src``,
  ``srcset``, ``action``, ``formaction``, ``data``, ``poster``, ``cite``,
  ``background``, ``manifest``, ``ping``, ``codebase``/``archive``, ``longdesc``,
  SVG ``href``/``xlink:href`` ...), ``<base href>`` resolution, a ``refresh``
  ``<meta>``, the DOCTYPE's system identifier, CSS in ``style`` attributes and
  ``<style>`` blocks, and markup inside IE conditional comments
  (``<!--[if ...]> ... <![endif]-->``), which browsers of that era parsed.
* **CSS** (`css_urls`): ``url(...)`` and ``@import``.
* **HTTP headers** (`header_urls`): ``Location``, ``Content-Location``, ``Refresh``
  and every ``Link`` target.
* **Known files** (`robots_urls`, `sitemap_urls`): a ``robots.txt``'s ``Allow`` /
  ``Disallow`` paths (wildcard rules skipped) and ``Sitemap`` lines (RFC 9309); a
  sitemap's ``<loc>`` entries (sitemaps.org). `KNOWN_FILES` names where they live.

Every result is absolute (resolved against the document's URL or its ``<base>``),
de-duplicated in document order, without its fragment. Non-fetchable schemes
(``javascript:``, ``data:``, ``mailto:``, ``tel:``, ``blob:``, ``about:``) are dropped.
Scope and destructive-URL decisions belong to the caller.

**Never a link: a submission target or a script string (BUG-0503).** Whatever this
module returns, a crawler fetches with GET. A form's ``action``, a ``formaction`` and a
``ping`` (a POST beacon) are where a *write* goes, and a string literal in a script
carries no evidence of the method the script uses it with (``fetch(url, {method:
'POST'})``). Neither is returned: forms reach the target only through the crawlers'
gated submission paths, and what a script requests is what the browser was seen to
request.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Iterable, Mapping
from urllib.parse import urldefrag, urljoin, urlsplit

#: element -> its URL-valued attributes. ``*`` applies to every element.
URL_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "*": ("background",),
    "a": ("href", "xlink:href"),       # SVG's <a> too; never ``ping`` (BUG-0503)
    "area": ("href",),
    "link": ("href",),
    "base": ("href",),
    "img": ("src", "srcset", "longdesc", "lowsrc", "dynsrc"),
    "iframe": ("src", "longdesc"),
    "frame": ("src", "longdesc"),
    "embed": ("src", "code", "pluginspage"),
    "script": ("src", "href", "xlink:href"),   # SVG's <script> too
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src", "srcset"),
    "track": ("src",),
    "input": ("src", "usemap"),         # never ``formaction``/``action`` (BUG-0503)
    "object": ("data", "codebase", "archive", "classid"),
    "applet": ("code", "codebase", "archive", "object"),
    "param": ("value",),           # only when it parses as a URL (`_param_url`)
    "blockquote": ("cite",),
    "q": ("cite",),
    "del": ("cite",),
    "ins": ("cite",),
    "html": ("manifest",),
    "head": ("profile",),
    "command": ("icon",),
    "menuitem": ("icon",),
    "image": ("href", "xlink:href"),       # SVG
    "use": ("href", "xlink:href"),
    "feimage": ("href", "xlink:href"),
    "textpath": ("href", "xlink:href"),
    "pattern": ("href", "xlink:href"),
    "lineargradient": ("href", "xlink:href"),
    "radialgradient": ("href", "xlink:href"),
    "mpath": ("href", "xlink:href"),
}
#: Attributes holding several URLs separated by white space.
SPACE_LISTS = frozenset({"archive"})
#: Attributes in the ``srcset`` syntax (comma-separated ``URL descriptor``).
SRCSETS = frozenset({"srcset"})
#: Schemes a crawler cannot request.
UNFETCHABLE = frozenset({"javascript", "data", "mailto", "tel", "blob", "about", "vbscript",
                         "file"})

_CSS_URL = re.compile(r"""url\(\s*(['"]?)([^'")\s]+)\1\s*\)""", re.I)
_CSS_IMPORT = re.compile(r"""@import\s+(['"])([^'"]+)\1""", re.I)
_REFRESH = re.compile(r"""^\s*\d*\.?\d*\s*[;,]?\s*(?:url\s*=\s*)?(['"]?)(.+?)\1\s*$""", re.I)
_DOCTYPE_SYSTEM = re.compile(r"""(?:SYSTEM|PUBLIC\s+(['"]).*?\1)\s+(['"])([^'"]+)\2""",
                             re.I | re.S)
_LINK_TARGET = re.compile(r"<([^>]*)>")
_JS_URLISH = re.compile(r"^(?:https?://[^\s<>]+|/[A-Za-z0-9_\-.~/%]*[A-Za-z0-9_\-~/%]"
                        r"(?:\?[^\s<>]*)?|[A-Za-z0-9_\-.~%]+(?:/[A-Za-z0-9_\-.~%]+)*"
                        r"\.[A-Za-z0-9]{1,6}(?:\?[^\s<>]*)?)$")
_COND_COMMENT = re.compile(r"^\s*\[if\b[^\]]*\]>(.*?)<!\[endif\]\s*$", re.I | re.S)


def _absolute(raw: str | None, base: str) -> str | None:
    if raw is None:
        return None
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    scheme = urlsplit(raw).scheme.lower()
    if scheme in UNFETCHABLE:
        return None
    try:
        url = urldefrag(urljoin(base, raw))[0]
    except ValueError:                       # a malformed authority
        return None
    return url if urlsplit(url).scheme in ("http", "https") else None


def _ordered(urls: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(u for u in urls if u))


def css_urls(css: str, base_url: str) -> list[str]:
    """``url(...)`` and ``@import`` targets of a stylesheet, absolute."""
    found = [m.group(2) for m in _CSS_URL.finditer(css or "")]
    found += [m.group(2) for m in _CSS_IMPORT.finditer(css or "")]
    return _ordered(_absolute(u, base_url) for u in found)


def refresh_url(value: str | None, base_url: str) -> str | None:
    """The target of a ``Refresh`` header or ``<meta http-equiv=refresh>`` content."""
    m = _REFRESH.match(value or "")
    if not m or not re.search(r"[;,]|url\s*=", value or "", re.I):
        return None
    return _absolute(m.group(2), base_url)


def header_urls(headers: Mapping[str, str], base_url: str) -> list[str]:
    """``Location``, ``Content-Location``, ``Refresh`` and every ``Link`` target."""
    low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out = [_absolute(low.get("location"), base_url),
           _absolute(low.get("content-location"), base_url),
           refresh_url(low.get("refresh"), base_url)]
    out += [_absolute(m.group(1), base_url)
            for m in _LINK_TARGET.finditer(low.get("link", ""))]
    return _ordered(out)


#: Well-known locations every origin may serve (a crawler seeds them).
KNOWN_FILES = ("/robots.txt", "/sitemap.xml")
_ROBOTS_LINE = re.compile(r"^\s*(allow|disallow|sitemap)\s*:\s*(\S+)", re.I)
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def robots_urls(text: str, base_url: str) -> list[str]:
    """``Allow`` / ``Disallow`` paths and ``Sitemap`` URLs of a robots.txt. A rule with a
    wildcard (``*``) or an end anchor (``$``) is a pattern, not a path: skipped."""
    out = []
    for line in (text or "").splitlines():
        m = _ROBOTS_LINE.match(line.split("#", 1)[0])
        if m and not any(c in m.group(2) for c in "*$"):
            out.append(_absolute(m.group(2), base_url))
    return _ordered(out)


def sitemap_urls(xml: str, base_url: str) -> list[str]:
    """The ``<loc>`` entries of a sitemap or sitemap index."""
    return _ordered(_absolute(m.group(1), base_url) for m in _SITEMAP_LOC.finditer(xml or ""))


def _srcset(value: str) -> list[str]:
    return [part.strip().split()[0] for part in (value or "").split(",") if part.strip()]


class _Collector(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.raw: list[tuple[str, str]] = []   # (kind, value), resolved at the end
        self._in: str | None = None          # inside a <style> block
        self._text: list[str] = []

    # <base href> applies to the URLs after it and before it alike (HTML resolves
    # against the document base); collected raw, resolved at the end
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = [(k.lower(), v) for k, v in attrs if v is not None]
        names = URL_ATTRIBUTES.get(tag, ()) + URL_ATTRIBUTES["*"]
        values = dict(attrs)
        if tag == "base" and values.get("href"):
            self.base = urljoin(self.base, values["href"])
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            self.raw.append(("refresh", values.get("content")))
        for name, value in attrs:
            if name == "style":
                self.raw += [("url", u) for u in
                             (m.group(2) for m in _CSS_URL.finditer(value))]
            if name not in names:
                continue
            if tag == "param" and not _JS_URLISH.match(value.strip()):
                continue
            if name in SRCSETS:
                self.raw += [("url", u) for u in _srcset(value)]
            elif name in SPACE_LISTS:
                self.raw += [("url", u) for u in value.split()]
            else:
                self.raw.append(("url", value))
        if tag == "style":
            self._in, self._text = tag, []

    handle_startendtag = handle_starttag

    def handle_endtag(self, tag):
        if self._in and tag.lower() == self._in:
            self.raw.append((self._in, "".join(self._text)))
            self._in, self._text = None, []

    def handle_data(self, data):
        if self._in:
            self._text.append(data)

    def handle_decl(self, decl):
        m = _DOCTYPE_SYSTEM.search(decl)
        if decl.lower().startswith("doctype") and m:
            self.raw.append(("url", m.group(3)))

    def handle_comment(self, data):
        m = _COND_COMMENT.match(data)
        if m:
            self.raw.append(("html", m.group(1)))


def html_urls(html: str, base_url: str) -> list[str]:
    """Every URL an HTML document links (see the module doc), absolute, in order."""
    c = _Collector(base_url)
    try:
        c.feed(html or "")
        c.close()
    except (AssertionError, ValueError):     # markup the parser gives up on
        pass
    out: list[str | None] = []
    for kind, value in c.raw:
        if kind == "url":
            out.append(_absolute(value, c.base))
        elif kind == "refresh":
            out.append(refresh_url(value, c.base))
        elif kind == "style":
            out += css_urls(value, c.base)
        elif kind == "html":
            out += html_urls(value, c.base)
    return _ordered(out)


def response_urls(url: str, content_type: str | None, body: str | None,
                  headers: Mapping[str, str] | None = None) -> list[str]:
    """What one response links: its headers' targets, plus its body's by its media
    type (HTML, CSS), a robots.txt's rules or a sitemap's entries; anything else
    (a script included: BUG-0503) headers only."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    out = header_urls(headers or {}, url)
    path = urlsplit(url).path.lower()
    if body and path.endswith("/robots.txt"):
        return _ordered(out + robots_urls(body, url))
    if body and ("<urlset" in body[:2000] or "<sitemapindex" in body[:2000]):
        return _ordered(out + sitemap_urls(body, url))
    if body:
        if media in ("text/html", "application/xhtml+xml"):
            out += html_urls(body, url)
        elif media == "text/css":
            out += css_urls(body, url)
    return _ordered(out)
