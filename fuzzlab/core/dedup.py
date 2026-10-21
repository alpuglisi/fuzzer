"""DOM-skeleton MinHash template clustering (Phase 2 T2.6) and point folding.

Near-duplicate pages (same structure, different data — e.g. product #1 vs #99) share a
template. We hash the DOM *skeleton* (tag structure only, no text or attributes) into a
MinHash signature and cluster pages whose signatures are similar.

A shared template is never, on its own, a reason to drop an injection point
(BUG-0547, FR-FUZZ-68): the skeleton holds no form action, input name, handler or
authorisation rule. `fold_points` drops a point only when an earlier point on a page of
the same template sends the same request and makes the same observation
(`wire_request_key`), and reports how many it folded and on what key.

Pure-Python MinHash (deterministic, no external dependency): a family of hash
permutations over shingles of the tag sequence; signature similarity approximates
Jaccard similarity of the skeletons.
"""

from __future__ import annotations

import dataclasses
import hashlib

from bs4 import BeautifulSoup

_PRIME = (1 << 61) - 1


def dom_skeleton(html: str) -> list[str]:
    """The ordered tag names of a page (structure only; text/attrs discarded)."""
    soup = BeautifulSoup(html or "", "html.parser")
    return [tag.name for tag in soup.find_all(True)]


def _shingles(tokens: list[str], k: int) -> list[str]:
    if len(tokens) < k:
        return [" ".join(tokens)] if tokens else []
    return [" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)]


def _hash(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8).digest(), "big")


def _perm_params(num_perm: int) -> list[tuple[int, int]]:
    # Deterministic (a odd/nonzero, b) pairs; quality is fine for template clustering.
    return [(2 * i + 1, i * i + 7) for i in range(num_perm)]


def minhash(html: str, num_perm: int = 64, k: int = 3) -> tuple[int, ...]:
    return _skeleton_signature(dom_skeleton(html), num_perm, k)


def _skeleton_signature(skeleton: list[str], num_perm: int, k: int) -> tuple[int, ...]:
    shingles = _shingles(skeleton, k)
    if not shingles:
        return tuple([0] * num_perm)
    hashes = [_hash(s) for s in shingles]
    return tuple(min((a * h + b) % _PRIME for h in hashes) for a, b in _perm_params(num_perm))


def similarity(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


class TemplateClusterer:
    """Assigns a stable `template_cluster_id` to each page by skeleton similarity."""

    def __init__(self, threshold: float = 0.7, num_perm: int = 64, k: int = 3):
        self.threshold = threshold
        self.num_perm = num_perm
        self.k = k
        self._clusters: list[tuple[str, tuple[int, ...]]] = []

    def cluster_id(self, html: str) -> str:
        return self._assign(minhash(html, self.num_perm, self.k))

    def known_cluster_id(self, html: str | None) -> str | None:
        """`cluster_id`, or None when the page is unknown: no HTML, or HTML with no tag
        structure to compare. An unknown page is never in a template with another
        (BUG-0547: every absent page used to be one empty template)."""
        if html is None:
            return None
        skeleton = dom_skeleton(html)
        if not skeleton:
            return None
        return self._assign(_skeleton_signature(skeleton, self.num_perm, self.k))

    def _assign(self, sig: tuple[int, ...]) -> str:
        for cid, csig in self._clusters:
            if similarity(sig, csig) >= self.threshold:
                return cid
        cid = f"T{len(self._clusters) + 1:04d}"
        self._clusters.append((cid, sig))
        return cid

    @property
    def cluster_count(self) -> int:
        return len(self._clusters)


# --- folding injection points (BUG-0547, FR-FUZZ-68) ----------------------------------
#: What `fold_points` folds on, reported with its count: the page's template plus
#: `wire_request_key`. Bumped whenever either changes (v2: the key holds SP-57's
#: request-context identity as a member, AU-REQID78).
FOLD_KEY = "template+wire-request-v2"

#: The value a standalone query point's own slot holds in its key (never sent).
_SLOT = "fuzzlab-injected-slot"


def wire_request_key(point) -> tuple:
    """Which request an injection point sends and what it observes, as a hashable key
    (BUG-0547, FR-FUZZ-68): every field of the point's dataclass, by name, exactly as
    given -- a field added later joins the key on its own.

    One field is taken as sent rather than as given: the URL of a **standalone query
    point** (``location == "query"``, no sibling entries, no stored-XSS store step) has
    its injected slot placed by the one query placement (SP-42, `place_query_param`: the
    first occurrence, in place), because every sender overwrites that value -- so
    ``/item?id=1`` and ``/item?id=2`` probing ``id`` are one request. Nothing else is
    normalised: another query part, a fragment, an encoding, the method's case, a form
    default or a sibling's value (the oracle sends a form's default and the value a
    crawl saw: `_restore_value`, the cross-account check) all keep two points apart.

    It refines the request-context identity (SP-57, `core.reqctx.point_key`), which is a
    member of the key: a fold never joins two request contexts, and every field beyond
    the context (an audit label, a field added later) keeps two points apart too. A URL
    the identity cannot parse has no context member (``None``) and is keyed as given."""
    from fuzzlab.core.urls import place_query_param
    if not dataclasses.is_dataclass(point) or isinstance(point, type):
        raise TypeError(f"an injection point dataclass, not {type(point).__name__}")
    url = point.url
    if getattr(point, "location", None) == "query" and \
            not getattr(point, "base_entries", None) and not getattr(point, "store_url", None):
        try:
            url = place_query_param(url, point.param, _SLOT)
        except ValueError:                   # unparseable (`urlsplit`): kept as given
            url = point.url
    from fuzzlab.core.reqctx import point_key
    try:
        context = point_key(point)
    except ValueError:                       # unparseable (`urlsplit`): no context
        context = None
    return (("url", url),) + tuple(
        (f.name, _frozen(getattr(point, f.name)))
        for f in dataclasses.fields(point) if f.name != "url") + (("context", context),)


def _frozen(value):
    """``value`` as a hashable equal to the frozen form of every equal value; an
    unhashable value of another kind is unequal to everything (never folded)."""
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_frozen(v) for v in value)
    if isinstance(value, dict):
        return ("dict",) + tuple(sorted(((repr(k), _frozen(v)) for k, v in value.items()),
                                        key=lambda kv: kv[0]))
    try:
        hash(value)
    except TypeError:
        return object()
    return value


@dataclasses.dataclass(frozen=True)
class Folded:
    """What `fold_points` kept, and its report."""
    points: list
    folded: int            # points dropped as the same request as an earlier kept one
    unknown_pages: int     # points whose page HTML was absent or had no structure
    key: str = FOLD_KEY


def fold_points(points: list, pages_html: dict[str, str],
                clusterer: TemplateClusterer | None = None) -> Folded:
    """``points`` without those that are the same attack surface as an earlier one
    (BUG-0547, FR-FUZZ-68), in their order.

    A point is folded only when an earlier kept point is on a page of the same DOM
    template **and** has the same `wire_request_key`. A shared template alone never
    folds two points (another endpoint, parameter, location, method, sibling set,
    content type, sink, store step: each is kept). A page whose HTML is absent or has no
    tag structure is unknown: its points fold only with an identical point on the same
    URL, never with another page's."""
    clusterer = TemplateClusterer() if clusterer is None else clusterer
    template: dict[str, tuple] = {}
    seen: set[tuple] = set()
    kept: list = []
    unknown = 0
    for point in points:
        if point.url not in template:
            cid = clusterer.known_cluster_id(pages_html.get(point.url))
            template[point.url] = ("template", cid) if cid is not None else \
                ("unknown-page", point.url)
        page = template[point.url]
        if page[0] == "unknown-page":
            unknown += 1
        key = (page, wire_request_key(point))
        if key in seen:
            continue
        seen.add(key)
        kept.append(point)
    return Folded(points=kept, folded=len(points) - len(kept), unknown_pages=unknown)
