"""PathTraversalClasspathResourceStrategy / SsrfFileSchemeStrategy (CC-FUZZ-0630,
FR-FUZZ-630/631): JVM read sinks, each with its "always shows the marker" and "reflects
the request" false-positive fixtures (PA-0090(2), BUG-0117's control rule). The live
confirmation on VulnerableApp is `tests/test_external_labs_live.py` territory (gated by
FUZZLAB_LIVE_EXTERNAL_LABS=1); these fakes reproduce the measured answers."""

from __future__ import annotations

import posixpath

from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies_jvm import (CLASSPATH_DEPTHS, CLASSPATH_FILES, FILE_URLS,
                                           PathTraversalClasspathResourceStrategy,
                                           SsrfFileSchemeStrategy)

#: What VulnerableApp's resource read answers for its classpath root's properties file
#: (measured: lines joined with no separator).
PROPERTIES = ("server.port=9090server.servlet.context-path=/VulnerableApp"
              "spring.datasource.admin.url=jdbc:h2:mem:testdb")
PASSWD = "root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"


def _pt():
    return Candidate(url="http://h/PathTraversal/LEVEL_1", param="fileName",
                     category="path-traversal")


def _ssrf():
    return Candidate(url="http://h/SSRF/LEVEL_1", param="fileurl", category="ssrf")


class _Sender:
    def __init__(self, answer):
        self.answer, self.sent = answer, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None):
        self.sent.append(value)
        return Probe(200, self.answer(value))


def _classpath_read(base="/scripts/PathTraversal/", files=None):
    """A `getResourceAsStream(base + value)`: `..` resolves inside the classpath only."""
    files = {"/application.properties": PROPERTIES,
             "/scripts/PathTraversal/UserInfo.json": "[]"} if files is None else files

    def answer(value):
        path = posixpath.normpath(base + value)
        if path.startswith("/..") or path.startswith("//"):
            return '{"content":null,"isValid":false}'
        body = files.get(path)
        return ('{"content":null,"isValid":false}' if body is None
                else '{"content":"%s","isValid":true}' % body)
    return answer


def test_a_classpath_confined_read_is_confirmed_at_its_depth():
    sender = _Sender(_classpath_read())
    v = PathTraversalClasspathResourceStrategy().confirm(_pt(), sender)
    assert v and v.confirmed and v.vuln_class == "path_traversal"
    assert v.evidence == {"payload": "../../application.properties",
                          "file": "application.properties", "depth": 2}
    assert sender.sent[-1] == "application.properties"           # the control, last


def test_the_os_file_strategy_misses_what_the_classpath_one_finds():
    """The measured gap: /etc/passwd is above the classpath root."""
    sender = _Sender(_classpath_read())
    assert S.PathTraversalFsPathReadStrategy().confirm(_pt(), sender) is None


def test_a_file_served_without_traversal_is_not_attributable():
    """FP fixture: a handler that serves application.properties for any value."""
    sender = _Sender(lambda v: PROPERTIES)
    assert PathTraversalClasspathResourceStrategy().confirm(_pt(), sender) is None


def test_a_page_reflecting_the_payload_is_not_confirmed():
    """FP fixture: the value echoed back carries no file content."""
    sender = _Sender(lambda v: f'{{"error":"no such file: {v}"}}')
    assert PathTraversalClasspathResourceStrategy().confirm(_pt(), sender) is None
    assert len(sender.sent) == len(CLASSPATH_FILES) * len(CLASSPATH_DEPTHS)   # bounded


def test_a_confined_read_answers_nothing_outside_its_directory():
    """A secure level: only names inside the base directory resolve."""
    def answer(value):
        return ('{"content":"[]","isValid":true}' if value == "UserInfo.json"
                else '{"content":null,"isValid":false}')
    assert PathTraversalClasspathResourceStrategy().confirm(_pt(), _Sender(answer)) is None


def test_a_servlet_descriptor_is_reached_too():
    xml = ('<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee" version="5.0">'
           '<servlet/></web-app>')
    sender = _Sender(_classpath_read(base="/WEB-INF/classes/static/",
                                     files={"/WEB-INF/web.xml": xml}))
    v = PathTraversalClasspathResourceStrategy().confirm(_pt(), sender)
    assert v and v.evidence["file"] == "WEB-INF/web.xml" and v.evidence["depth"] == 3


def test_the_properties_marker_needs_a_spring_key_and_an_equals_sign():
    marker = CLASSPATH_FILES[0][1]
    assert marker.search(PROPERTIES)
    for text in ("our server port is 9090", "spring.datasource", "myserver.port=1",
                 "see spring.profiles.active in the docs"):
        assert not marker.search(text), text


def _url_fetcher(value):
    """`new URL(value).openStream()`: a file: URL reads the file; a bare path is no URL."""
    if value in FILE_URLS:
        return '{"content":"%s","isValid":true}' % PASSWD
    return '{"content":null,"isValid":false}'


def test_a_file_scheme_fetch_is_confirmed_in_band():
    sender = _Sender(_url_fetcher)
    v = SsrfFileSchemeStrategy().confirm(_ssrf(), sender)
    assert v and v.confirmed and v.vuln_class == "ssrf"
    assert v.evidence == {"payload": "file:///etc/passwd"}
    assert sender.sent == ["file:///etc/passwd", "/etc/passwd"]


def test_a_refused_file_scheme_is_no_finding():
    """A secure level: file: refused (VulnerableApp LEVEL_2..5, measured)."""
    sender = _Sender(lambda v: '{"content":null,"isValid":false}')
    assert SsrfFileSchemeStrategy().confirm(_ssrf(), sender) is None
    assert sender.sent == list(FILE_URLS)


def test_a_page_always_showing_passwd_text_is_not_an_ssrf():
    """FP fixture: the marker without any file: URL (the bare-path control)."""
    assert SsrfFileSchemeStrategy().confirm(_ssrf(), _Sender(lambda v: PASSWD)) is None


def test_a_page_reflecting_the_url_is_not_an_ssrf():
    """FP fixture (PA-0090(2)): the URL echoed back is not the file's content."""
    assert SsrfFileSchemeStrategy().confirm(
        _ssrf(), _Sender(lambda v: f"fetching {v} failed")) is None


def test_both_are_default_strategies_after_their_categorys_own():
    names = [type(s).__name__ for s in S.default_strategies()]
    assert names.index("PathTraversalClasspathResourceStrategy") > \
        names.index("PathTraversalFsPathReadStrategy")
    assert names.index("SsrfFileSchemeStrategy") > names.index("SsrfOobStrategy")
    by_name = {type(s).__name__: s for s in S.default_strategies()}
    assert by_name["PathTraversalClasspathResourceStrategy"].vuln_class == "path_traversal"
    assert by_name["SsrfFileSchemeStrategy"].vuln_class == "ssrf"
