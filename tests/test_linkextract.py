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
    ('<form action="/submit"></form>', "http://h.test/submit"),
    ('<form><button formaction="/b">x</button></form>', "http://h.test/b"),
    ('<form><input type="image" src="btn.png"></form>', "http://h.test/dir/btn.png"),
    ('<isindex action="/idx">', "http://h.test/idx"),
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


def test_srcset_ping_and_archive_lists_give_every_url():
    urls = lx.html_urls('<img srcset="a.png 1x, b.png 2x"><a href="x" ping="/p1 /p2">'
                        '</a><object archive="a.jar b.jar"></object>', B)
    for u in ("a.png", "b.png", "a.jar", "b.jar"):
        assert f"http://h.test/dir/{u}" in urls
    assert "http://h.test/p1" in urls and "http://h.test/p2" in urls


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


def test_inline_script_strings_that_are_paths():
    urls = lx.html_urls('<script>var a = "/api/items"; fetch(\'img/logo.png\');'
                        'var w = "hello world"; var t = `x/${id}`; var s = "word";</script>', B)
    assert urls == ["http://h.test/api/items", "http://h.test/dir/img/logo.png"]


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
    assert lx.response_urls(B, "application/javascript", 'u="/j/a.json"', {}) == \
        ["http://h.test/j/a.json"]


def test_broken_markup_never_raises():
    assert isinstance(lx.html_urls("<a href='x'<<<<img src=\x00>", B), list)
    assert lx.html_urls("", B) == [] and lx.css_urls("", B) == [] and lx.js_urls("", B) == []


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
