"""FR-FUZZ-640 (CC-FUZZ-0640): `PathTraversalFsPathReadStrategy`'s directory-listing
phase. A sink that lists a directory (bWAPP's ``directory_traversal_2.php``, measured
live 2026-11-20: ``../../../../etc`` and ``/etc`` list ``/etc``, an unknown name answers
"This directory doesn't exist!", a file name an ``opendir`` warning) never shows file
content, so the ``/etc/passwd`` phase cannot confirm it. The listing must show at least
`LISTING_MIN_ENTRIES` well-known ``/etc`` names that a compared control naming ``etc``
with no separator does not show.

Each test drives the real strategy through the real `Oracle.confirm_outcome` with a
scripted target (the listing page's shape copied from the measured bWAPP answer)."""
from __future__ import annotations

import pytest

from fuzzlab.oracle import Oracle
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import (LISTING_MIN_ENTRIES, PathTraversalFsPathReadStrategy,
                                       _etc_entries)

HOST = "http://127.0.0.1:9"
#: The measured listing's shape: one ``<a>`` per entry in a table (bWAPP).
ETC_LISTING = "".join(f'<tr><td><a href="../../../../etc/{n}" target="_blank">{n}</a></td>'
                      f'</tr>' for n in ("rc2.d", "passwd", "group", "hosts", "hostname",
                                         "shells", "os-release", "motd", "profile.d"))
NOT_FOUND = "<p>This directory doesn't exist!</p>"
DOCS = "<p>Directory Traversal - Directories</p><a>bWAPP_intro.pdf</a>"


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
        Candidate(f"{HOST}/bWAPP/directory_traversal_2.php", "directory",
                  category="path-traversal"), sender)
    return verdict, unsure, sender.sent


def _lister(control_body=NOT_FOUND):
    def answer(value):
        if value == "etc":
            return Probe(200, control_body, 0.0)
        if value.rstrip("/").endswith("etc"):
            return Probe(200, DOCS + ETC_LISTING, 0.0)
        if "passwd" in value:                         # the file phase: opendir warning
            return Probe(200, f"<b>Warning</b>: opendir({value}): failed to open dir: "
                              f"Not a directory", 0.0)
        return Probe(200, NOT_FOUND, 0.0)
    return answer


def test_a_directory_listing_of_etc_absent_from_the_control_confirms():
    verdict, unsure, sent = _run(_lister())
    assert verdict is not None and verdict.confirmed and unsure is None
    assert verdict.vuln_class == "path_traversal"
    assert verdict.evidence["variant"] == "directory-listing"
    assert verdict.evidence["payload"] == "../../../../../../../../etc"
    assert {"passwd", "group", "hosts", "hostname"} <= set(verdict.evidence["listing"])
    assert sent[-1] == "etc"                          # the control, after the match


def test_a_page_that_always_shows_the_names_is_not_confirmed():
    verdict, _unsure, _sent = _run(_lister(control_body=DOCS + ETC_LISTING))
    assert verdict is None or not verdict.confirmed


def test_fewer_than_the_minimum_entries_is_not_a_listing():
    few = "".join(f"<a>{n}</a>" for n in ("passwd", "group", "hosts")[:LISTING_MIN_ENTRIES - 1])

    def answer(value):
        return Probe(200, NOT_FOUND if value == "etc" else few, 0.0)
    verdict, _unsure, sent = _run(answer)
    assert verdict is None or not verdict.confirmed
    assert "etc" not in sent                          # no control without a match


def test_the_listing_phase_costs_two_requests_when_nothing_lists():
    verdict, _unsure, sent = _run(lambda value: Probe(200, NOT_FOUND, 0.0))
    assert verdict is None or not verdict.confirmed
    from fuzzlab.oracle.strategies import _LISTING_PAYLOADS, _TRAVERSAL_PAYLOADS
    assert sent == list(_TRAVERSAL_PAYLOADS) + list(_LISTING_PAYLOADS)


def test_the_file_phase_still_wins_first():
    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    def answer(value):
        return Probe(200, NOT_FOUND if value == "passwd" else passwd, 0.0)
    verdict, _unsure, sent = _run(answer)
    assert verdict.confirmed and "variant" not in verdict.evidence
    assert sent == ["../../../../../../../../etc/passwd", "passwd"]


@pytest.mark.parametrize("control", [Probe(429, "Too Many Requests", 0.0),
                                     Probe(503, "busy", 0.0),
                                     Probe(302, "", 0.0, headers={"Location": "/login"})])
def test_a_control_that_is_not_the_applications_answer_never_confirms(control):
    def answer(value):
        if value == "etc":
            return control
        return _lister()(value)
    verdict, unsure, _sent = _run(answer)
    assert verdict is None or not verdict.confirmed
    assert unsure is not None                         # inconclusive, never a negative


@pytest.mark.parametrize("text, names", [
    ("<a>passwd</a> <a>group</a>", {"passwd", "group"}),
    ("/etc/passwd and ../etc/hosts", set()),          # an echoed path is not a listing
    ("passwd.bak shadow- profile.d hosts.allow", set()),   # other files' names
    ("resolv.conf\nos-release\tld.so.cache", {"resolv.conf", "os-release", "ld.so.cache"}),
])
def test_entries_are_matched_as_whole_names(text, names):
    assert _etc_entries(text) == names
