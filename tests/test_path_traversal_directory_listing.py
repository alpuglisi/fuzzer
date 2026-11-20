"""FR-FUZZ-640/641 (CC-FUZZ-0640, CC-FUZZ-0641, BUG-0641): `PathTraversalFsPathReadStrategy`'s
directory-listing phase. A sink that lists a directory (bWAPP's
``directory_traversal_2.php``, measured live 2026-11-20) never shows file content, so the
``/etc/passwd`` phase cannot confirm it. The answer must be 2xx and show at least
`LISTING_MIN_ENTRIES` non-English ``/etc`` file names, each a *whole listing item* (a line,
a JSON string, an HTML text node), that a compared control does not show; the control is
the same value naming a random sibling of ``etc`` (same separators, same depth).

BUG-0641: the first version matched words (``group``, ``profile``, ``issue``) anywhere and
compared with a separator-free control, so prose, or an error page an app shows for any
path-shaped value, confirmed. The fixtures below copy the measured answers of four
independent listing implementations (2026-11-20): Python ``os.listdir`` joined by lines,
Node ``fs.readdirSync`` as JSON, Python's ``http.server`` and nginx 1.27's autoindex, plus
bWAPP's PHP table. Each test drives the real strategy through the real
`Oracle.confirm_outcome` with a scripted target."""
from __future__ import annotations

import json

import pytest

from fuzzlab.oracle import Oracle
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import (_LISTING_PAYLOADS, _TRAVERSAL_PAYLOADS,
                                       LISTING_MIN_ENTRIES, PathTraversalFsPathReadStrategy,
                                       _etc_entries)

HOST = "http://127.0.0.1:9"
NAMES = ("ImageMagick-6", "X11", "adduser.conf", "alternatives", "fstab", "login.defs",
         "os-release", "passwd", "passwd-", "resolv.conf", "group", "hosts", "profile")
#: The measured shapes (2026-11-20), trimmed to a few entries each.
BWAPP = "".join(f'<tr><td><a href="../../../../etc/{n}" target="_blank">{n}</a></td></tr>'
                for n in NAMES)
LINES = "\n".join(NAMES)                                          # os.listdir
NODE_JSON = json.dumps(list(NAMES))                               # fs.readdirSync
HTTP_SERVER = ("<h1>Directory listing for /</h1><hr><ul>" + "".join(
    f'<li><a href="{n}">{n}{"@" if n == "os-release" else "/" if n[0].isupper() else ""}'
    f'</a></li>' for n in NAMES) + "</ul>")
NGINX = ('<h1>Index of /files/etc/</h1><hr><pre><a href="../">../</a>\n' + "".join(
    f'<a href="{n}">{n}</a>{" " * 30}16-Nov-2026 18:50{" " * 16}3333\n' for n in NAMES)
    + "</pre>")
NOT_FOUND = "<p>This directory doesn't exist!</p>"
PROSE = "<p>Welcome to the group! Edit your profile. Report an issue. Shells and hosts.</p>"
ERROR_PAGE = ("<h1>Internal Server Error</h1><pre>an environment issue in group profile: "
              "cannot read passwd, fstab, os-release or login.defs</pre>")


class Script:
    def __init__(self, answer):
        self.answer, self.sent = answer, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        self.sent.append(value)
        return self.answer(value)


def _run(answer):
    sender = Script(answer)
    verdict, unsure = Oracle(strategies=[PathTraversalFsPathReadStrategy()]).confirm_outcome(
        Candidate(f"{HOST}/list", "directory", category="path-traversal"), sender)
    return verdict, unsure, sender.sent


def _lister(body):
    def answer(value):
        if value.rstrip("/").endswith("/etc") and "passwd" not in value:
            return Probe(200, body, 0.0)
        return Probe(200, NOT_FOUND, 0.0)
    return answer


def _confirmed(verdict):
    return verdict is not None and verdict.confirmed


@pytest.mark.parametrize("body", [BWAPP, LINES, NODE_JSON, HTTP_SERVER, NGINX],
                         ids=["bwapp-php", "os.listdir", "node-readdir", "http.server",
                              "nginx-autoindex"])
def test_each_measured_listing_shape_confirms_against_a_sibling_control(body):
    verdict, unsure, sent = _run(_lister(body))
    assert _confirmed(verdict) and unsure is None
    assert verdict.vuln_class == "path_traversal"
    assert verdict.evidence["variant"] == "directory-listing"
    assert verdict.evidence["payload"] == "../../../../../../../../etc"
    assert {"passwd", "fstab", "os-release", "login.defs"} <= set(verdict.evidence["listing"])
    control = sent[-1]
    assert control == verdict.evidence["control"]
    assert control.startswith("../../../../../../../../zq") and "etc" not in control


def test_prose_naming_etc_files_is_not_a_listing():
    """The reviewer's case: four words that were /etc names (in 684fab9's set), in a
    sentence, answered to the listing payloads and to nothing else."""
    verdict, _unsure, sent = _run(lambda value: Probe(
        200, PROSE if value in _LISTING_PAYLOADS else NOT_FOUND, 0.0))
    assert not _confirmed(verdict)
    assert not any("zq" in v for v in sent)           # no control without a listing


def test_an_error_page_for_every_path_shaped_value_is_not_confirmed():
    """An app that answers any value holding a separator with an error page: the sibling
    control (same separators) gets the same page, so nothing is fresh."""
    def answer(value):
        if "/" in value:
            return Probe(200, LINES if value.endswith("etc") else LINES, 0.0)
        return Probe(200, NOT_FOUND, 0.0)
    verdict, _unsure, _sent = _run(answer)
    assert not _confirmed(verdict)
    verdict, _unsure, _sent = _run(lambda value: Probe(
        200, ERROR_PAGE if "/" in value else NOT_FOUND, 0.0))
    assert not _confirmed(verdict)


def test_a_non_2xx_listing_is_not_confirmed():
    def answer(value):
        if value.endswith("etc"):
            return Probe(500, LINES, 0.0)
        return Probe(200, NOT_FOUND, 0.0)
    verdict, _unsure, _sent = _run(answer)
    assert not _confirmed(verdict)


def test_fewer_than_the_minimum_entries_is_not_a_listing():
    few = "\n".join(["passwd", "fstab", "os-release"][:LISTING_MIN_ENTRIES - 1])
    verdict, _unsure, sent = _run(lambda value: Probe(200, NOT_FOUND if "zq" in value
                                                      else few, 0.0))
    assert not _confirmed(verdict)
    assert not any("zq" in v for v in sent)


def test_the_listing_phase_costs_two_requests_when_nothing_lists():
    verdict, _unsure, sent = _run(lambda value: Probe(200, NOT_FOUND, 0.0))
    assert not _confirmed(verdict)
    assert sent == list(_TRAVERSAL_PAYLOADS) + list(_LISTING_PAYLOADS)


def test_the_file_phase_still_wins_first():
    passwd = "root:x:0:0:root:/root:/bin/bash\n"
    verdict, _unsure, sent = _run(lambda value: Probe(200, NOT_FOUND if value == "passwd"
                                                      else passwd, 0.0))
    assert verdict.confirmed and "variant" not in verdict.evidence
    assert sent == ["../../../../../../../../etc/passwd", "passwd"]


@pytest.mark.parametrize("control", [Probe(429, "Too Many Requests", 0.0),
                                     Probe(503, "busy", 0.0),
                                     Probe(302, "", 0.0, headers={"Location": "/login"})])
def test_a_control_that_is_not_the_applications_answer_never_confirms(control):
    def answer(value):
        return control if "zq" in value else _lister(LINES)(value)
    verdict, unsure, _sent = _run(answer)
    assert not _confirmed(verdict)
    assert unsure is not None                         # inconclusive, never a negative


@pytest.mark.parametrize("text, names", [
    (LINES, {"passwd", "fstab", "os-release", "login.defs", "resolv.conf", "adduser.conf"}),
    (PROSE, set()),                                   # words in a sentence
    (ERROR_PAGE, set()),                              # names inside a message
    ("/etc/passwd\n../etc/fstab", set()),             # an echoed path is not an item
    ("passwd.bak\npasswd-\nfstab~", set()),           # other files' names
    ('["passwd", "fstab"]', {"passwd", "fstab"}),     # a JSON array's strings
    ('<a href="x">os-release@</a><a>ld.so.conf.d/</a>', {"os-release"}),   # http.server
    ("group\nprofile\nissue\nhosts", set()),          # English words never count
])
def test_entries_are_whole_listing_items_of_non_english_names(text, names):
    assert _etc_entries(text) == names
