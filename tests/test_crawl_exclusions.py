"""Operator URL exclusions (FR-CRAWL-675, FR-CORE-662, FR-LAB-410; CC-CRAWL-0674).

Some GET routes change a target's state for everything after them and no generic rule
can tell them apart (lane CRAWLSAFE kept such words out of SP-09 under the black-box
rule). The operator -- or a bundled lab's fixture -- names them with ``--exclude`` /
``--exclude-lab``, and neither crawler ever loads a match. Invented routes, loopback."""

from __future__ import annotations

import pytest

from fuzzlab.core.urls import MAX_EXCLUSIONS, compile_exclusions, exclusion_reason
from fuzzlab.lab_fixtures.exclusions import UnknownLab, crawl_exclusions, exclusions_for
from fuzzlab.lab_fixtures.external import LAB_META
from fuzzlab.tools import spider as sp
from tests.test_spider_frontier import _page, _Site, _stats


def test_an_exclusion_matches_the_path_and_query_only():
    ex = compile_exclusions([r"^/mode/", r"reset=1"])
    assert exclusion_reason("http://h/mode/hard", ex) == r"^/mode/"
    assert exclusion_reason("http://h/a?x=2&reset=1", ex) == "reset=1"
    assert exclusion_reason("http://mode.h/other", ex) is None       # never the host
    assert exclusion_reason("http://h/a", ()) is None


@pytest.mark.parametrize("bad", [["("], [""], ["a" * 513], ["x"] * (MAX_EXCLUSIONS + 1)])
def test_a_bad_exclusion_list_is_refused(bad):
    with pytest.raises(ValueError):
        compile_exclusions(bad)


def test_every_lab_fixture_exclusion_compiles_and_the_cli_merges_them():
    for name, meta in LAB_META.items():
        compile_exclusions(meta.crawl_exclude)
    assert crawl_exclusions("dvga") == LAB_META["dvga"].crawl_exclude
    with pytest.raises(UnknownLab):
        crawl_exclusions("no-such-lab")
    args = type("A", (), {"exclude": ["^/x"], "exclude_lab": "dvga"})()
    assert exclusions_for(args) == ("^/x", *crawl_exclusions("dvga"))


def test_the_crawl_cli_refuses_a_bad_pattern_before_anything(capsys):
    with pytest.raises(SystemExit):
        sp.parse_args(["--exclude", "("])
    assert "not a regular expression" in capsys.readouterr().err


def test_a_crawl_never_loads_an_excluded_url(tmp_path):
    site = _Site({"/": lambda h, n: _page("/mode/hard", "/about"),
                  "/mode/hard": lambda h, n: _page(), "/about": lambda h, n: _page()})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(site.base, max_depth=2, db_name=db, engine="requests",
                       exclude=[r"^/mode/"]).crawl()
    finally:
        site.close()
    assert site.gets("/mode/hard") == 0 and site.gets("/about") == 1
    assert _stats(db)["loads_refused[excluded]"] >= 1


def test_the_explorer_scope_refuses_an_excluded_url():
    from fuzzlab.disco.explore import Explorer, ExploreOptions
    ex = Explorer("http://127.0.0.1:9/", scope_urls=["http://127.0.0.1:9/"],
                  proxy="127.0.0.1:1", options=ExploreOptions(exclude=(r"^/mode/",)))
    assert ex._in_scope("http://127.0.0.1:9/about")
    assert not ex._in_scope("http://127.0.0.1:9/mode/hard")
    with pytest.raises(ValueError):
        Explorer("http://127.0.0.1:9/", scope_urls=["http://127.0.0.1:9/"],
                 proxy="127.0.0.1:1", options=ExploreOptions(exclude=("(",)))
