"""`core.linkextract`: the URLs a document links, by the rules of its format.

Cases come from the HTML Living Standard (and the obsolete features it still parses),
CSS and HTTP -- one construct per test, never a particular site's markup."""

from __future__ import annotations

import pytest

from fuzzlab.core import linkextract as lx

B = "http://h.test/dir/page.html"


@pytest.mark.parametrize("markup,expected", [
    ('<a href="a.html">x</a>', "http://h.test/dir/a.html"),
    ('<area href="/map.html">', "http://h.test/map.html"),
    ('<link rel="stylesheet" href="s.css">', "http://h.test/dir/s.css"),
    ('<img src="i.png">', "http://h.test/dir/i.png"),
    ('<iframe src="f.html"></iframe>', "http://h.test/dir/f.html"),
    ('<frameset><frame src="fr.html"></frameset>', "http://h.test/dir/fr.html"),
    ('<embed src="e.swf">', "http://h.test/dir/e.swf"),
    ('<script src="j.js"></script>', "http://h.test/dir/j.js"),
    ('<video poster="p.jpg"><source src="v.mp4"></video>', "http://h.test/dir/p.jpg"),
    ('<video><track src="t.vtt"></video>', "http://h.test/dir/t.vtt"),
    ('<audio src="a.mp3"></audio>', "http://h.test/dir/a.mp3"),
    ('<object data="o.swf"></object>', "http://h.test/dir/o.swf"),
    ('<applet code="Ap.class" codebase="/cb/"></applet>', "http://h.test/cb/"),
    ('<form><input type="image" src="btn.png"></form>', "http://h.test/dir/btn.png"),
    ('<blockquote cite="/quote"></blockquote>', "http://h.test/quote"),
    ('<body background="bg.gif"></body>', "http://h.test/dir/bg.gif"),
    ('<table background="t.gif"></table>', "http://h.test/dir/t.gif"),
    ('<html manifest="app.appcache"></html>', "http://h.test/dir/app.appcache"),
    ('<head profile="/profile"></head>', "http://h.test/profile"),
    ('<svg><image href="s.svg"/></svg>', "http://h.test/dir/s.svg"),
    ('<svg><a xlink:href="/x.html"><text>x</text></a></svg>', "http://h.test/x.html"),
    ('<div style="background: url(\'d.png\')"></div>', "http://h.test/dir/d.png"),
    ('<style>@import "imp.css"; p{background:url(w.png)}</style>',
     "http://h.test/dir/imp.css"),
    ('<meta http-equiv="refresh" content="0; url=/next">', "http://h.test/next"),
])
def test_each_url_valued_construct_is_read(markup, expected):
    urls = lx.html_urls(markup, B)
    assert expected in urls, urls


def test_srcset_and_archive_lists_give_every_url():
    urls = lx.html_urls('<img srcset="a.png 1x, b.png 2x">'
                        '<object archive="a.jar b.jar"></object>', B)
    for u in ("a.png", "b.png", "a.jar", "b.jar"):
        assert f"http://h.test/dir/{u}" in urls


def test_the_document_base_applies_and_fragments_and_schemes_are_dropped():
    urls = lx.html_urls('<base href="http://h.test/other/"><a href="r.html#top">'
                        '<a href="#only"><a href="javascript:void(0)"><a href="mailto:x@y">'
                        '<img src="data:image/png;base64,AAAA">', B)
    # the base is a URL the document names, and the link resolves against it
    assert urls == ["http://h.test/other/", "http://h.test/other/r.html"]


def test_the_doctype_system_identifier_and_conditional_comments():
    urls = lx.html_urls('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "/dtd/x.dtd">'
                        '<!--[if IE]><link href="ie.css"><![endif]--><!-- <a href="no"> -->',
                        B)
    assert "http://h.test/dtd/x.dtd" in urls and "http://h.test/dir/ie.css" in urls
    assert "http://h.test/dir/no" not in urls           # a plain comment is not markup


@pytest.mark.parametrize("markup", [
    '<form action="/submit" method="post"></form>',
    '<form><button formaction="/b">x</button><input type="submit" formaction="/i"></form>',
    '<isindex action="/idx">',
    '<a ping="/p1 /p2">x</a><area ping="/p3">',
    '<script>fetch("/api/after-close", {method: "POST"}); var j = "img/logo.png";</script>',
])
def test_a_submission_target_or_a_script_string_is_never_a_link(markup):
    """BUG-0503: a crawler GETs whatever this returns; a form's action, a formaction, a
    ping (a POST beacon) and a script's string literals are write targets or of unknown
    method, so none is returned -- from markup, or from a script response."""
    assert lx.html_urls(markup, B) == []
    assert lx.response_urls(B, "text/html", markup, {}) == []
    assert not hasattr(lx, "js_urls")


def test_a_script_response_links_only_through_its_headers():
    assert lx.response_urls(B, "application/javascript", 'u="/j/a.json"',
                            {"Link": "</l>"}) == ["http://h.test/l"]


def test_headers_location_content_location_refresh_and_every_link():
    urls = lx.header_urls({"Location": "/moved", "Content-Location": "c.html",
                           "Refresh": "5; url=/later",
                           "Link": '</a.css>; rel=preload, <http://h.test/b>; rel=next'}, B)
    assert urls == ["http://h.test/moved", "http://h.test/dir/c.html",
                    "http://h.test/later", "http://h.test/a.css", "http://h.test/b"]


def test_a_refresh_without_a_url_is_not_one():
    assert lx.refresh_url("5", B) is None
    assert lx.refresh_url("0;URL='q.html'", B) == "http://h.test/dir/q.html"


def test_css_urls_and_response_dispatch_by_media_type():
    css = '@import url("x.css"); @font-face { src: url(f.woff2) format("woff2"); }'
    assert lx.css_urls(css, B) == ["http://h.test/dir/x.css", "http://h.test/dir/f.woff2"]
    assert lx.response_urls(B, "text/css; charset=utf-8", css, {}) == \
        ["http://h.test/dir/x.css", "http://h.test/dir/f.woff2"]
    assert lx.response_urls(B, "image/png", "\x89PNG", {"Link": "</l>"}) == ["http://h.test/l"]


def test_broken_markup_never_raises():
    assert isinstance(lx.html_urls("<a href='x'<<<<img src=\x00>", B), list)
    assert lx.html_urls("", B) == [] and lx.css_urls("", B) == [] 


def test_robots_rules_and_sitemaps():
    robots = ("User-agent: *\nDisallow: /private/\nAllow: /public/page.html # ok\n"
              "Disallow: /*.pdf$\nSitemap: http://h.test/sm.xml\n")
    assert lx.robots_urls(robots, "http://h.test/robots.txt") == [
        "http://h.test/private/", "http://h.test/public/page.html", "http://h.test/sm.xml"]
    sm = '<?xml version="1.0"?><urlset><url><loc> http://h.test/a </loc></url>' \
         '<url><loc>http://h.test/b</loc></url></urlset>'
    assert lx.sitemap_urls(sm, B) == ["http://h.test/a", "http://h.test/b"]
    assert lx.response_urls("http://h.test/robots.txt", "text/plain", robots, {})[0] == \
        "http://h.test/private/"
    assert lx.response_urls("http://h.test/sitemap.xml", "application/xml", sm, {}) == \
        ["http://h.test/a", "http://h.test/b"]
    assert lx.KNOWN_FILES == ("/robots.txt", "/sitemap.xml")


SUB = "http://h.test/app/"


def test_a_base_under_a_subpath_keeps_its_path():
    """PA-0300: every function that takes a base resolves a relative URL under the
    app's sub-path and an absolute path at the origin -- never doubled or dropped."""
    assert lx._absolute("x.html", SUB) == "http://h.test/app/x.html"
    assert lx._absolute("/x.html", SUB) == "http://h.test/x.html"
    c = lx._Collector(SUB)
    assert c.base == SUB
    assert lx.html_urls('<a href="p.html"><img src="i/a.png">', SUB) == \
        ["http://h.test/app/p.html", "http://h.test/app/i/a.png"]
    assert lx.css_urls("p{background:url(b.gif)}", SUB) == ["http://h.test/app/b.gif"]
    assert lx.refresh_url("0; url=n.html", SUB) == "http://h.test/app/n.html"
    assert lx.header_urls({"Location": "moved"}, SUB) == ["http://h.test/app/moved"]
    assert lx.robots_urls("Disallow: private/\n", SUB) == ["http://h.test/app/private/"]
    assert lx.sitemap_urls("<urlset><loc>s.html</loc></urlset>", SUB) == \
        ["http://h.test/app/s.html"]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0559's PA-0002 sweep for super-linear patterns over a value the target writes "
    "(PA-0559(14)); pre-existing at 7393c90, owner CRAWL (SP-39): core/linkextract.py::_REFRESH "
    "tries a lazy group against a trailing \\s*$ at every length, quadratic in a "
    "whitespace run of a Refresh header's or a meta refresh's content"))
def test_a_refresh_value_with_a_long_whitespace_run_is_read_in_linear_time():
    """A refresh value is target-written (a ``Refresh`` header, a ``<meta http-equiv>``'s
    content). Measured at 7393c90: ``'x' + ' ' * n + 'y'`` takes 0.27 s at n = 8 000 and
    four times that at twice n, so 80 000 characters take about 27 s. Run in a child
    with a 5 s bound: a linear reader takes milliseconds."""
    import subprocess
    import sys
    from pathlib import Path
    code = ("from fuzzlab.core.linkextract import refresh_url\n"
            "refresh_url('x' + ' ' * 80000 + 'y', 'http://h.test/')\n")
    try:
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=5,
                              cwd=str(Path(__file__).resolve().parents[1]))
    except subprocess.TimeoutExpired:
        done = None
    if done is not None and done.returncode != 0:
        pytest.fail(f"the child failed: {done.stderr[-400:]!r}")
    assert done is not None, "refresh_url is super-linear in a whitespace run"
