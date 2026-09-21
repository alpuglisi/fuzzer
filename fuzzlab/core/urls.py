"""URL normalization used wherever a result URL is stored for cross-referencing.

Result URLs (findings, pages, endpoints, parameters) are stored in **path form**
so they line up with the ground-truth contract (which is written in paths) and can
be matched by the harness. This is the single place that convention lives — writers
must not store URLs verbatim ad hoc (see PA-0003 / BUG-0003).
"""

from __future__ import annotations

from urllib.parse import urlparse


def to_path(url: str) -> str:
    """Return a URL's path with a leading slash (``/product.php``); ``/`` if empty."""
    path = urlparse(url).path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path
