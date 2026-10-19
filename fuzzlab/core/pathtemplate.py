"""Path parameters from crawled URLs (FR-CORE-503, FR-AUD-26).

A crawl sees concrete URLs (``/ticket/680f…``, ``/live/username/mr.robot``); a path
point is a template with one placeholder segment (``/ticket/{id}``, FR-FUZZ-57). This
module turns a run's URLs into such templates, from two kinds of evidence:

* **shape** -- a segment that looks like an object id (all digits, a UUID, a hex string
  of at least 8 characters with a digit and a letter, or `looks_like_identifier`) is a
  parameter even when seen once; it is named ``id``;
* **variation** -- among URLs of one origin with the same number of segments that agree
  on every segment but one, a position (never the first) holding at least two distinct
  values is a parameter; it is named after the fixed segment before it
  (``/live/username/{username}``).

A static asset (its last segment has an `ASSET_EXTENSIONS` extension) never yields a
template, and a segment naming a file (`FILE_EXTENSIONS`: ``index.php``) is never a
value. Each template carries one
placeholder: a URL with two parameters gives two templates, the other segment kept
concrete as crawled, so a probe of one never sends a literal ``{…}`` for the other.
The example is the first crawled value. Pure: no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from fuzzlab.core.redaction import looks_like_identifier
from fuzzlab.core.urls import canonical_origin, path_placeholder

#: Last-segment extensions of static assets: never a template.
ASSET_EXTENSIONS = frozenset({
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "bmp", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav", "pdf",
    "zip", "gz", "txt", "xml", "json", "wasm"})
#: ... and of server pages: a segment ending in one names a file, not a value.
FILE_EXTENSIONS = ASSET_EXTENSIONS | frozenset({
    "php", "html", "htm", "asp", "aspx", "jsp", "cgi", "do", "action", "pl", "py", "rb"})
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}$", re.I)
_DIGITS = re.compile(r"^\d{1,20}$")
_NAME = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class PathTemplate:
    origin: str
    #: The path with its one placeholder segment (``/live/{id}/messages``).
    path: str
    param: str
    #: The value the crawl saw in that segment (decoded).
    example: str


def id_shaped(segment: str) -> bool:
    """A segment that looks like an object id: digits, a UUID, a mixed hex string of 8+
    characters, or an identifier-like token (`looks_like_identifier`)."""
    return bool(_DIGITS.match(segment) or _UUID.match(segment) or _HEX.match(segment)
                or looks_like_identifier(segment))


def _segments(url: str):
    """``(origin, decoded segments)`` of a crawlable URL, or None for an asset, a URL
    with no usable origin, or the root."""
    origin = canonical_origin(url)
    if origin is None:
        return None
    segs = [unquote(s) for s in urlsplit(url).path.split("/")[1:]]
    if segs and segs[-1] == "":
        segs = segs[:-1]                       # a trailing slash is not a segment
    if not segs or any(s == "" for s in segs):
        return None
    last = segs[-1]
    if "." in last and last.rsplit(".", 1)[1].lower() in ASSET_EXTENSIONS:
        return None
    return origin, segs


def _name_for(segs: list[str], i: int, shaped: bool) -> str:
    if shaped:
        return "id"
    before = _NAME.sub("_", segs[i - 1].lower()).strip("_") if i > 0 else ""
    return before or "segment"


def _usable(segment: str) -> bool:
    """A segment that can be a parameter value: no placeholder braces, and not a file
    name (``index.php``, ``thumb.png``; ``mr.robot`` is a value)."""
    if "{" in segment or "}" in segment:
        return False
    return not ("." in segment and segment.rsplit(".", 1)[1].lower() in FILE_EXTENSIONS)


def path_templates(urls) -> list[PathTemplate]:
    """The path templates a run's URLs show (module docstring), in first-seen order,
    one per (origin, template path)."""
    from urllib.parse import quote
    parsed = []
    for url in dict.fromkeys(urls):
        got = _segments(url)
        if got is not None:
            parsed.append(got)
    found: dict[tuple[str, str], PathTemplate] = {}

    def add(origin: str, segs: list[str], i: int, shaped: bool) -> None:
        path = "/" + "/".join(path_placeholder(_name_for(segs, i, shaped)) if j == i
                              else quote(s, safe="@:!$&'()*+,;=-._~")
                              for j, s in enumerate(segs))
        found.setdefault((origin, path), PathTemplate(origin, path,
                                                      _name_for(segs, i, shaped), segs[i]))

    for origin, segs in parsed:                                 # shape
        for i, seg in enumerate(segs):
            if _usable(seg) and id_shaped(seg):
                add(origin, segs, i, True)
    groups: dict[tuple, list[list[str]]] = {}                   # variation
    for origin, segs in parsed:
        for i in range(1, len(segs)):
            key = (origin, len(segs), i, tuple(segs[:i] + segs[i + 1:]))
            groups.setdefault(key, []).append(segs)
    for (origin, _n, i, _rest), members in groups.items():
        values = {m[i] for m in members}
        if len(values) < 2 or not all(_usable(v) for v in values):
            continue
        for m in members:
            add(origin, m, i, id_shaped(m[i]))
    return list(found.values())
