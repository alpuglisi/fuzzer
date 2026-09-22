"""Unit coverage for the pure URL-building helpers in `browserexec.py`.

`PlaywrightBrowserExecutor.run()` itself needs a real browser and is
exercised on-host only (per its own docstring); these two helpers are pure
and were previously untested (this module had zero test coverage).
"""
from fuzzlab.tools.browserexec import _with_fragment, _with_query


def test_with_query_appends_to_a_bare_url():
    assert _with_query("http://x/page", "id", "1' or '1'='1") == \
        "http://x/page?id=1%27+or+%271%27%3D%271"


def test_with_query_appends_to_an_existing_query_string():
    url = _with_query("http://x/page?a=1", "b", "2")
    assert url == "http://x/page?a=1&b=2"


def test_with_fragment_replaces_any_existing_fragment():
    url = _with_fragment("http://x/page?a=1#old", "xss", "<img onerror=1>")
    assert url.startswith("http://x/page?a=1#")
    assert "old" not in url
    assert "xss=" in url


def test_with_query_and_fragment_preserve_scheme_and_host():
    for fn in (_with_query, _with_fragment):
        url = fn("https://h.example:8080/p", "k", "v")
        assert url.startswith("https://h.example:8080/p")
