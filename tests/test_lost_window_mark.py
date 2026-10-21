"""Every consumer of a disco capture's answers reads the lost-window mark (PA-0552(4)).

FR-CRAWL-41 marks the action ids whose answers fell in a known-lost window (a
``session`` line in ``actions.jsonl``); `disco.capture.lost_action_ids` is its one
reader (SP-71). BUG-0552's review (B2) found two consumers that took such answers as
evidence and were neither fixed nor pinned, although the lane's own sweep had listed the
consumers: the sweep read prose, not the call graph. This guard reads the call graph:
every function of `fuzzlab/` that reads a capture's records (`read_capture`,
`CaptureTail`) also reads the mark, or is listed here with why it does not -- a pin (a
strict xfail naming its owner, PA-0531(4)) or "not evidence". The list is compared
exactly: a new reader and a stale entry both fail. Proven on synthetic offenders
(PA-0034(2))."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.package_guard

#: The owner module: it defines the readers (and the mark's reader) themselves.
OWNER = "fuzzlab/disco/capture.py"
#: The calls that read a capture's records, and the call that reads the mark.
READERS = frozenset({"read_capture", "CaptureTail"})
MARK = "lost_action_ids"

#: Readers of a capture's records that do not read the mark, each with why.
NOT_READING_THE_MARK = {
    "fuzzlab/disco/cli.py::_synth":
        "pinned: tests/test_disco_session_loss.py::"
        "test_an_answer_in_a_lost_window_is_never_in_the_inventory "
        "(owner: disco synth, CRAWL, FR-CRAWL-20)",
    "fuzzlab/tools/store_adapter.py::import_disco":
        "pinned: tests/test_disco_session_loss.py::"
        "test_import_disco_never_takes_a_lost_windows_answer_as_evidence "
        "(owner: store_adapter.import_disco, AUD, FR-AUD-23)",
    "fuzzlab/disco/livetrace.py::LiveTrace.__init__":
        "the live trace (FR-CRAWL-30, FR-AUD-28/29): what was exchanged, never "
        "evidence; its events equal the import's",
    "fuzzlab/disco/livetrace.py::LiveTrace.finish":
        "the live trace's final pass (`observe_disco`): as above",
}


def unmarked_readers(source: str, rel: str) -> list[str]:
    """``<rel>::<qualified name>`` of each function in ``source`` that calls a capture
    reader (`READERS`, by name or attribute) and never calls `MARK` in its body."""
    found: list[str] = []

    def visit(node, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                called = set()
                for sub in ast.walk(child):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        called.add(f.id if isinstance(f, ast.Name) else
                                   getattr(f, "attr", None))
                if called & READERS and MARK not in called:
                    found.append(f"{rel}::{name}")
                visit(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")
            else:
                visit(child, prefix)

    visit(ast.parse(source, filename=rel), "")
    return found


def test_every_capture_reader_reads_the_lost_window_mark():
    found = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel != OWNER:
            found += unmarked_readers(path.read_text(encoding="utf-8"), rel)
    assert sorted(found) == sorted(NOT_READING_THE_MARK), (
        "a reader of a capture's answers must read FR-CRAWL-41's mark "
        "(disco.capture.lost_action_ids) or be listed with its pin")


def test_the_capture_reader_guard_catches_synthetic_offenders():
    """A reader by name, by attribute, in a method and in a nested function is found;
    one that reads the mark is not."""
    rel = "fuzzlab/rogue.py"
    src = ("from fuzzlab.disco import capture\n"
           "from fuzzlab.disco.capture import lost_action_ids, read_capture\n"
           "def reads(run):\n"
           "    return read_capture(run / 'capture.jsonl').records\n"
           "def marked(run):\n"
           "    lost = lost_action_ids(run)\n"
           "    return [r for r in read_capture(run).records\n"
           "            if r.action_id not in lost]\n"
           "class T:\n"
           "    def tail(self, p):\n"
           "        return capture.CaptureTail(p)\n"
           "def outer(run):\n"
           "    def inner():\n"
           "        return capture.read_capture(run)\n"
           "    return inner\n")
    assert unmarked_readers(src, rel) == [
        f"{rel}::reads", f"{rel}::T.tail", f"{rel}::outer", f"{rel}::outer.inner"]
