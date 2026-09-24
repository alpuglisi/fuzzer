"""Regression tests for the crawler's link-following scope (BUG-0050).

The crawler used to hardcode `hostname in {localhost, 127.0.0.1}` as the only
followable hosts, so pointed at any authorized *external* host it silently
dropped every discovered link and followed none. Scope is now the start URL's
own host: same-host links are followed, off-host links (third-party domains,
other subdomains) are not, and loopback aliases still count as one host so the
lab keeps working. These tests pin that decision.
"""

import tempfile
import os

import pytest

from fuzzlab.tools.spider import LocalSpider


def _spider(start):
    db = tempfile.mktemp(suffix=".db")
    sp = LocalSpider(start, db_name=db, engine="requests")
    return sp, db


def _cleanup(sp, db):
    try:
        sp.storage.close()
    except Exception:
        pass
    if os.path.exists(db):
        os.unlink(db)


@pytest.mark.parametrize("link,expected", [
    ("https://shop.example.org/catalog/item?id=1", True),   # same host, deeper path
    ("https://shop.example.org/login", True),               # same host, other path
    ("http://shop.example.org:8443/x", True),               # same host, other scheme/port
    ("https://www.shop.example.org/x", True),               # www normalises to the apex
    ("https://cdn.example.org/a.js", False),                # different subdomain
    ("https://other.com/x", False),                         # third-party domain
    ("mailto:a@b.com", False),                              # no host at all
])
def test_external_start_follows_only_same_host(link, expected):
    sp, db = _spider("https://shop.example.org/catalog")
    try:
        assert sp._scope_host == "shop.example.org"
        assert sp._in_scope(link) is expected
    finally:
        _cleanup(sp, db)


def test_external_host_was_the_bug_all_links_would_have_been_dropped():
    # The core of BUG-0050: for an external start, at least one real same-host
    # link must now be in scope (the old localhost-only guard returned False for
    # every one of these, so a real target yielded zero followed links).
    sp, db = _spider("https://target.example.net/")
    try:
        assert sp._in_scope("https://target.example.net/page2") is True
    finally:
        _cleanup(sp, db)


@pytest.mark.parametrize("link,expected", [
    ("http://localhost:8080/x", True),      # loopback alias of the start host
    ("http://127.0.0.1:9999/y", True),      # same, different port
    ("http://[::1]/z", True),               # ipv6 loopback
    ("https://example.com/", False),        # off to the open web
])
def test_loopback_start_treats_aliases_as_one_host(link, expected):
    sp, db = _spider("http://127.0.0.1:8080/")
    try:
        assert sp._in_scope(link) is expected
    finally:
        _cleanup(sp, db)
